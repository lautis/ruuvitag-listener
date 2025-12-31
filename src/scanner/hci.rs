//! Raw HCI socket backend for RuuviTag scanning.
//!
//! This backend uses raw Linux HCI sockets to scan for BLE advertisements
//! without requiring the BlueZ daemon. It requires CAP_NET_RAW and
//! CAP_NET_ADMIN capabilities or root privileges.

use super::{
    DecodeError, MEASUREMENT_CHANNEL_BUFFER_SIZE, MeasurementResult, RUUVI_MANUFACTURER_ID,
    ScanError, decode_ruuvi_data,
};
use crate::mac_address::MacAddress;
use libc::{AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, c_int, c_void, sockaddr, socklen_t};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

// HCI protocol constants
const BTPROTO_HCI: c_int = 1;
const HCI_FILTER: c_int = 2;

// HCI packet types
const HCI_EVENT_PKT: u8 = 0x04;

// HCI events
const EVT_LE_META_EVENT: u8 = 0x3E;

// LE Meta event sub-events
const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;

// HCI commands
const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;

// Scan types
const LE_SCAN_PASSIVE: u8 = 0x00;

// Own address type
const LE_PUBLIC_ADDRESS: u8 = 0x00;

// Filter policy
const FILTER_POLICY_ACCEPT_ALL: u8 = 0x00;

// AD types
const AD_TYPE_MANUFACTURER_DATA: u8 = 0xFF;

/// HCI socket address structure
#[repr(C)]
struct SockaddrHci {
    hci_family: u16,
    hci_dev: u16,
    hci_channel: u16,
}

/// HCI filter structure for raw sockets
#[repr(C)]
struct HciFilter {
    type_mask: u32,
    event_mask: [u32; 2],
    opcode: u16,
}

impl HciFilter {
    fn new() -> Self {
        Self {
            type_mask: 0,
            event_mask: [0, 0],
            opcode: 0,
        }
    }

    fn set_ptype(&mut self, ptype: u8) {
        self.type_mask |= 1 << (ptype as u32);
    }

    fn set_event(&mut self, event: u8) {
        let bit = event as usize;
        self.event_mask[bit / 32] |= 1 << (bit % 32);
    }
}

/// LE Set Scan Parameters command
#[repr(C, packed)]
struct LeSetScanParametersCmd {
    scan_type: u8,
    interval: u16,
    window: u16,
    own_address_type: u8,
    filter_policy: u8,
}

/// LE Set Scan Enable command
#[repr(C, packed)]
struct LeSetScanEnableCmd {
    enable: u8,
    filter_dup: u8,
}

/// Create an HCI command packet
fn hci_command_packet(ogf: u16, ocf: u16, params: &[u8]) -> Vec<u8> {
    let opcode = (ogf << 10) | ocf;
    let mut packet = Vec::with_capacity(4 + params.len());
    packet.push(0x01); // HCI command packet type
    packet.push((opcode & 0xFF) as u8);
    packet.push((opcode >> 8) as u8);
    packet.push(params.len() as u8);
    packet.extend_from_slice(params);
    packet
}

/// Open a raw HCI socket
fn open_hci_socket() -> Result<OwnedFd, ScanError> {
    // Create a raw Bluetooth HCI socket using libc directly
    // since nix doesn't support BTPROTO_HCI
    // SOCK_NONBLOCK is required for AsyncFd to work properly
    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH,
            SOCK_RAW | SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            BTPROTO_HCI,
        )
    };

    if fd < 0 {
        return Err(ScanError::Bluetooth(format!(
            "Failed to create HCI socket: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Bind HCI socket to a device
fn bind_hci_socket(fd: &OwnedFd, dev_id: u16) -> Result<(), ScanError> {
    let addr = SockaddrHci {
        hci_family: AF_BLUETOOTH as u16,
        hci_dev: dev_id,
        hci_channel: 0, // HCI_CHANNEL_RAW
    };

    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const SockaddrHci as *const sockaddr,
            mem::size_of::<SockaddrHci>() as socklen_t,
        )
    };

    if ret < 0 {
        return Err(ScanError::Bluetooth(format!(
            "Failed to bind HCI socket: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Set HCI socket filter
fn set_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    let mut filter = HciFilter::new();
    filter.set_ptype(HCI_EVENT_PKT);
    filter.set_event(EVT_LE_META_EVENT);

    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            0, // SOL_HCI
            HCI_FILTER,
            &filter as *const HciFilter as *const c_void,
            mem::size_of::<HciFilter>() as socklen_t,
        )
    };

    if ret < 0 {
        return Err(ScanError::Bluetooth(format!(
            "Failed to set HCI filter: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Send an HCI command
fn send_hci_command(fd: &OwnedFd, packet: &[u8]) -> Result<(), ScanError> {
    let ret = unsafe {
        libc::write(
            fd.as_raw_fd(),
            packet.as_ptr() as *const c_void,
            packet.len(),
        )
    };

    if ret < 0 {
        return Err(ScanError::Bluetooth(format!(
            "Failed to send HCI command: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Configure LE scanning parameters
fn configure_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
    // Set scan parameters: passive scan, 10ms interval, 10ms window
    let params = LeSetScanParametersCmd {
        scan_type: LE_SCAN_PASSIVE,
        interval: 0x0010, // 10ms in 0.625ms units
        window: 0x0010,   // 10ms in 0.625ms units
        own_address_type: LE_PUBLIC_ADDRESS,
        filter_policy: FILTER_POLICY_ACCEPT_ALL,
    };

    let params_bytes = unsafe {
        std::slice::from_raw_parts(
            &params as *const LeSetScanParametersCmd as *const u8,
            mem::size_of::<LeSetScanParametersCmd>(),
        )
    };

    let packet = hci_command_packet(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, params_bytes);
    send_hci_command(fd, &packet)?;

    // Enable scanning
    let enable = LeSetScanEnableCmd {
        enable: 0x01,
        filter_dup: 0x00, // Don't filter duplicates
    };

    let enable_bytes = unsafe {
        std::slice::from_raw_parts(
            &enable as *const LeSetScanEnableCmd as *const u8,
            mem::size_of::<LeSetScanEnableCmd>(),
        )
    };

    let packet = hci_command_packet(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, enable_bytes);
    send_hci_command(fd, &packet)?;

    Ok(())
}

/// Parse LE advertising report and extract RuuviTag data
fn parse_advertising_report(data: &[u8], verbose: bool) -> Option<MeasurementResult> {
    // Minimum size for an advertising report
    if data.len() < 12 {
        return if verbose {
            Some(Err(DecodeError::InvalidData(
                "Advertising report too short".into(),
            )))
        } else {
            None
        };
    }

    // Skip HCI header (1 byte packet type + 1 byte event code + 1 byte param len + 1 byte subevent)
    let report = &data[4..];

    if report.is_empty() {
        return None;
    }

    // Number of reports
    let num_reports = report[0] as usize;
    if num_reports == 0 {
        return None;
    }

    // Parse first report (we process one at a time)
    // Skip: num_reports(1) + event_type(1) + addr_type(1)
    if report.len() < 9 {
        return None;
    }

    // Extract address (6 bytes, in reverse order)
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&report[3..9]);
    addr.reverse(); // HCI uses little-endian address

    // Data length
    if report.len() < 10 {
        return None;
    }
    let data_len = report[9] as usize;

    if report.len() < 10 + data_len {
        return None;
    }

    let ad_data = &report[10..10 + data_len];

    // Parse AD structures to find manufacturer data
    let mut offset = 0;
    while offset + 2 <= ad_data.len() {
        let len = ad_data[offset] as usize;
        if len == 0 || offset + 1 + len > ad_data.len() {
            break;
        }

        let ad_type = ad_data[offset + 1];

        if ad_type == AD_TYPE_MANUFACTURER_DATA && len >= 3 {
            // Extract manufacturer ID (little-endian)
            let mfg_id = u16::from_le_bytes([ad_data[offset + 2], ad_data[offset + 3]]);

            if mfg_id == RUUVI_MANUFACTURER_ID {
                // Found RuuviTag data
                let ruuvi_data = &ad_data[offset + 4..offset + 1 + len];
                let mac = MacAddress(addr);

                return Some(decode_ruuvi_data(mac, ruuvi_data));
            }
        }

        offset += 1 + len;
    }

    None
}

/// Start scanning for RuuviTag devices using raw HCI sockets.
///
/// This function opens a raw HCI socket, configures LE scanning, and
/// processes advertising reports. Discovered measurements are sent through the
/// returned channel. Runs indefinitely until interrupted.
///
/// # Arguments
/// * `verbose` - If true, decode errors are sent as Err values; otherwise they're silently dropped.
///
/// # Returns
/// A receiver for measurements (or decode errors if verbose).
///
/// # Requirements
/// - CAP_NET_RAW and CAP_NET_ADMIN capabilities or root privileges
/// - An available HCI device (typically hci0)
pub async fn start_scan(verbose: bool) -> Result<mpsc::Receiver<MeasurementResult>, ScanError> {
    // Open and configure HCI socket for receiving events
    let fd = open_hci_socket()?;
    bind_hci_socket(&fd, 0)?; // Bind to hci0 to receive advertising events
    set_hci_filter(&fd)?;

    // We need a separate socket for sending commands (bound to specific device)
    let cmd_fd = open_hci_socket()?;
    bind_hci_socket(&cmd_fd, 0)?; // Bind to hci0
    configure_le_scan(&cmd_fd)?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);

    // Wrap in AsyncFd for async I/O
    let async_fd = AsyncFd::new(fd)
        .map_err(|e| ScanError::Bluetooth(format!("Failed to create async fd: {}", e)))?;

    // Spawn a task to read and process HCI events
    tokio::spawn(async move {
        let _cmd_fd = cmd_fd; // Keep command socket alive
        let mut buf = [0u8; 258]; // Max HCI event size

        loop {
            // Wait for the socket to be readable
            let mut guard = match async_fd.readable().await {
                Ok(guard) => guard,
                Err(_) => break,
            };

            // Drain all available packets before waiting again
            loop {
                let n = match guard.try_io(|inner| {
                    let ret = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut c_void,
                            buf.len(),
                        )
                    };
                    if ret < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ret as usize)
                    }
                }) {
                    Ok(Ok(n)) if n > 0 => n,
                    Ok(Ok(_)) => break,  // EOF or empty read
                    Ok(Err(_)) => break, // Read error
                    Err(_) => break,     // WouldBlock - no more data
                };

                // Check if this is an LE advertising report
                if n >= 4 && buf[0] == HCI_EVENT_PKT && buf[1] == EVT_LE_META_EVENT {
                    let subevent = buf[3];
                    if subevent == EVT_LE_ADVERTISING_REPORT
                        && let Some(result) = parse_advertising_report(&buf[..n], verbose)
                    {
                        match &result {
                            Ok(_) => {
                                let _ = tx.send(result).await;
                            }
                            Err(_) if verbose => {
                                let _ = tx.send(result).await;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    });

    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hci_filter_setup() {
        let mut filter = HciFilter::new();
        filter.set_ptype(HCI_EVENT_PKT);
        filter.set_event(EVT_LE_META_EVENT);

        // Verify filter is set correctly
        // HCI_EVENT_PKT (0x04) sets bit 4 in type_mask
        assert_eq!(filter.type_mask, 1 << HCI_EVENT_PKT);
        // EVT_LE_META_EVENT (0x3E = 62) sets bit 30 in event_mask[1]
        assert_eq!(filter.event_mask[1], 1 << (EVT_LE_META_EVENT % 32));
    }

    #[test]
    fn test_hci_command_packet() {
        let packet = hci_command_packet(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, &[0x01, 0x00]);

        assert_eq!(packet[0], 0x01); // Command packet type
        assert_eq!(packet.len(), 6); // Header + 2 params
    }
}
