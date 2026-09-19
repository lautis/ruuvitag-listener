//! Raw HCI socket FFI layer: socket/command/scan packet structures, socket
//! setup, filtering, and HCI command I/O.

use super::*;
use crate::scanner::ScanError;
use libc::{AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, c_int, c_void, sockaddr, socklen_t};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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

/// LE Set Extended Scan Parameters command (Bluetooth 5.x).
///
/// This variant carries one parameter block per scanning PHY. We only ever
/// scan on the LE 1M PHY (`scanning_phys == LE_1M_PHY`), so exactly one
/// `{scan_type, interval, window}` block follows the PHY bitmask.
#[repr(C, packed)]
struct LeSetExtendedScanParametersCmd {
    own_address_type: u8,
    filter_policy: u8,
    scanning_phys: u8,
    scan_type: u8,
    interval: u16,
    window: u16,
}

/// LE Set Extended Scan Enable command (Bluetooth 5.x).
#[repr(C, packed)]
struct LeSetExtendedScanEnableCmd {
    enable: u8,
    filter_dup: u8,
    duration: u16,
    period: u16,
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
pub(crate) fn open_hci_socket() -> Result<OwnedFd, ScanError> {
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
pub(crate) fn bind_hci_socket(fd: &OwnedFd, dev_id: u16) -> Result<(), ScanError> {
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

/// Set HCI socket filter for kernel-level packet filtering.
///
/// This is the first layer of kernel-level filtering. It configures the HCI
/// subsystem to only deliver LE Meta Events to userspace, dropping:
/// - HCI command packets
/// - ACL data packets
/// - SCO audio packets
/// - All other HCI events (connection, disconnection, encryption, etc.)
///
/// This significantly reduces CPU wakeups since the kernel discards irrelevant
/// packets before any userspace context switch or memory copy occurs.
///
/// Note: HCI_FILTER cannot filter by LE subevent type, so we still receive
/// all LE Meta Events (connection complete, advertising reports, etc.).
/// The BPF filter (set_bpf_ruuvi_filter) provides finer-grained filtering.
pub(crate) fn set_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    let mut filter = HciFilter::new();
    filter.set_ptype(HCI_EVENT_PKT); // Only HCI event packets (0x04)
    filter.set_event(EVT_LE_META_EVENT); // Only LE Meta Events (0x3E)
    apply_hci_filter(fd, &filter)
}

/// Set an HCI filter that only lets Command Complete events through.
///
/// The command socket needs this so we can read back the controller's response
/// to setup commands (feature query, scan enable). A freshly opened HCI raw
/// socket has an all-zero filter that drops *every* packet, so without this the
/// command responses would never reach userspace.
pub(crate) fn set_command_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    let mut filter = HciFilter::new();
    filter.set_ptype(HCI_EVENT_PKT);
    filter.set_event(EVT_CMD_COMPLETE);
    apply_hci_filter(fd, &filter)
}

/// Apply an [`HciFilter`] to a socket via `setsockopt(SOL_HCI, HCI_FILTER)`.
fn apply_hci_filter(fd: &OwnedFd, filter: &HciFilter) -> Result<(), ScanError> {
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            0, // SOL_HCI
            HCI_FILTER,
            filter as *const HciFilter as *const c_void,
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

/// Wait for the Command Complete event matching `expected_opcode`.
///
/// The command socket is non-blocking, so we `poll(2)` for readiness and read
/// events until the one for our command arrives (or we time out). Unrelated
/// Command Complete events from other openers of the controller are skipped.
fn read_command_complete(fd: &OwnedFd, expected_opcode: u16) -> Result<Vec<u8>, ScanError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(COMMAND_TIMEOUT_MS);
    let mut buf = [0u8; 258];

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(ScanError::Bluetooth(
                "Timed out waiting for HCI command response".into(),
            ));
        }

        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as c_int) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ScanError::Bluetooth(format!("poll failed: {err}")));
        }
        if ret == 0 {
            return Err(ScanError::Bluetooth(
                "Timed out waiting for HCI command response".into(),
            ));
        }

        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ScanError::Bluetooth(format!("read failed: {err}")));
        }

        let n = n as usize;
        // Command Complete: [0]=pkt type, [1]=event, [2]=plen, [3]=num cmds,
        // [4..6]=opcode (LE), [6..]=return params (status first).
        if n >= 6 && buf[0] == HCI_EVENT_PKT && buf[1] == EVT_CMD_COMPLETE {
            let opcode = u16::from_le_bytes([buf[4], buf[5]]);
            if opcode == expected_opcode {
                return Ok(buf[..n].to_vec());
            }
        }
    }
}

/// Dispatch an HCI command and return its Command Complete status and event.
///
/// Unlike [`send_hci_command_checked`], this does not treat a non-zero status
/// as an error, so callers can decide which status codes are acceptable.
fn send_hci_command_with_status(
    fd: &OwnedFd,
    ogf: u16,
    ocf: u16,
    params: &[u8],
) -> Result<(u8, Vec<u8>), ScanError> {
    let packet = hci_command_packet(ogf, ocf, params);
    send_hci_command(fd, &packet)?;

    let event = read_command_complete(fd, (ogf << 10) | ocf)?;

    // Status is the first return parameter, at byte 6.
    let status = *event
        .get(6)
        .ok_or_else(|| ScanError::Bluetooth("Truncated HCI Command Complete event".to_string()))?;
    Ok((status, event))
}

/// Send an HCI command and verify its Command Complete status is success.
///
/// Returns the full Command Complete event so callers can read additional
/// return parameters. Surfacing a non-zero status here turns what used to be a
/// silent "no events ever arrive" failure into an explicit error.
fn send_hci_command_checked(
    fd: &OwnedFd,
    ogf: u16,
    ocf: u16,
    params: &[u8],
) -> Result<Vec<u8>, ScanError> {
    let opcode = (ogf << 10) | ocf;
    let (status, event) = send_hci_command_with_status(fd, ogf, ocf, params)?;
    if status != 0 {
        return Err(ScanError::Bluetooth(format!(
            "HCI command {opcode:#06x} failed with status {status:#04x}"
        )));
    }
    Ok(event)
}

/// Query whether the controller supports LE Extended Advertising.
///
/// Reads the LE features bitmap and checks the Extended Advertising bit. A
/// Bluetooth 5 controller (e.g. Intel AX210) reports advertisements via
/// Extended Advertising Reports once extended scanning is enabled, so we must
/// drive it with the extended scan commands instead of the legacy ones.
fn controller_supports_extended_scan(fd: &OwnedFd) -> Result<bool, ScanError> {
    let event =
        send_hci_command_checked(fd, OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES, &[])?;

    // Return params after status (byte 6) are the 8-byte LE features bitmap.
    let features_start = 7;
    match event.get(features_start + LE_FEATURE_EXTENDED_ADVERTISING_BYTE) {
        Some(byte) => Ok(byte & LE_FEATURE_EXTENDED_ADVERTISING_BIT != 0),
        None => Ok(false),
    }
}

/// Configure LE scanning, preferring extended scanning when the controller
/// supports it.
pub(crate) fn configure_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
    if controller_supports_extended_scan(fd)? {
        configure_extended_le_scan(fd)
    } else {
        configure_legacy_le_scan(fd)
    }
}

/// Disable LE scanning on the controller, matching the mode used to start it.
///
/// The controller's feature set determines which disable command it accepts
/// (legacy vs extended). Both disable paths tolerate "Command Disallowed" for
/// an already-disabled scan.
pub(crate) fn disable_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
    if controller_supports_extended_scan(fd)? {
        set_extended_scan_enable(fd, false)
    } else {
        set_legacy_scan_enable(fd, false)
    }
}

/// Configure legacy (Bluetooth 4.x) LE scanning parameters.
fn configure_legacy_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
    // Setting scan parameters is rejected with "Command Disallowed" while
    // scanning is already active (e.g. bluetoothd is running a discovery), so
    // disable scanning first. Disabling an already-disabled scan is a no-op
    // that some controllers reject with "Command Disallowed"; that status is
    // tolerated on the disable path.
    set_legacy_scan_enable(fd, false)?;

    // Set scan parameters: passive scan, 200ms interval, 200ms window
    // Using longer intervals reduces CPU usage significantly while still
    // catching RuuviTag broadcasts (which occur every ~1 second)
    let params = LeSetScanParametersCmd {
        scan_type: LE_SCAN_PASSIVE,
        interval: 0x0140, // 200ms in 0.625ms units (0x140 = 320 * 0.625ms)
        window: 0x0140,   // 200ms in 0.625ms units (0x140 = 320 * 0.625ms)
        own_address_type: LE_PUBLIC_ADDRESS,
        filter_policy: FILTER_POLICY_ACCEPT_ALL,
    };

    let params_bytes = unsafe {
        std::slice::from_raw_parts(
            &params as *const LeSetScanParametersCmd as *const u8,
            mem::size_of::<LeSetScanParametersCmd>(),
        )
    };

    send_hci_command_checked(fd, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, params_bytes)?;

    set_legacy_scan_enable(fd, true)?;

    Ok(())
}

/// Enable or disable legacy LE scanning.
fn set_legacy_scan_enable(fd: &OwnedFd, enable: bool) -> Result<(), ScanError> {
    let cmd = LeSetScanEnableCmd {
        enable: enable as u8,
        filter_dup: 0x00, // Don't filter duplicates
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &cmd as *const LeSetScanEnableCmd as *const u8,
            mem::size_of::<LeSetScanEnableCmd>(),
        )
    };

    send_scan_enable(fd, OCF_LE_SET_SCAN_ENABLE, bytes, enable)
}

/// Whether a returned status is acceptable for an LE scan enable/disable
/// command.
///
/// Disabling an already-disabled scan is a no-op that some controllers reject
/// with `Command Disallowed` (e.g. Broadcom BCM43455), so that status is
/// tolerated when disabling.
fn scan_enable_status_ok(enable: bool, status: u8) -> bool {
    status == 0 || (!enable && status == HCI_ERR_COMMAND_DISALLOWED)
}

/// Send an LE scan enable/disable command, tolerating `Command Disallowed`
/// when disabling an already-disabled scan.
fn send_scan_enable(fd: &OwnedFd, ocf: u16, params: &[u8], enable: bool) -> Result<(), ScanError> {
    let opcode = (OGF_LE_CTL << 10) | ocf;
    let (status, _event) = send_hci_command_with_status(fd, OGF_LE_CTL, ocf, params)?;
    if !scan_enable_status_ok(enable, status) {
        return Err(ScanError::Bluetooth(format!(
            "HCI command {opcode:#06x} failed with status {status:#04x}"
        )));
    }
    Ok(())
}

/// Configure extended (Bluetooth 5.x) LE scanning parameters.
///
/// Mirrors the legacy configuration (passive scan, 200ms interval/window on the
/// LE 1M PHY) using the extended scan commands. Controllers that have been put
/// into extended mode only report advertisements via Extended Advertising
/// Reports, so the legacy `LE Set Scan Enable` command would be rejected.
fn configure_extended_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
    // Setting scan parameters is rejected with "Command Disallowed" while
    // scanning is already active (e.g. bluetoothd is running a discovery), so
    // disable scanning first. Disabling an already-disabled scan is a no-op
    // that some controllers reject with "Command Disallowed"; that status is
    // tolerated on the disable path.
    set_extended_scan_enable(fd, false)?;

    let params = LeSetExtendedScanParametersCmd {
        own_address_type: LE_PUBLIC_ADDRESS,
        filter_policy: FILTER_POLICY_ACCEPT_ALL,
        scanning_phys: LE_1M_PHY,
        scan_type: LE_SCAN_PASSIVE,
        interval: 0x0140, // 200ms in 0.625ms units
        window: 0x0140,   // 200ms in 0.625ms units
    };

    let params_bytes = unsafe {
        std::slice::from_raw_parts(
            &params as *const LeSetExtendedScanParametersCmd as *const u8,
            mem::size_of::<LeSetExtendedScanParametersCmd>(),
        )
    };

    send_hci_command_checked(
        fd,
        OGF_LE_CTL,
        OCF_LE_SET_EXTENDED_SCAN_PARAMETERS,
        params_bytes,
    )?;

    set_extended_scan_enable(fd, true)?;

    Ok(())
}

/// Enable or disable extended LE scanning (continuous: duration = period = 0).
fn set_extended_scan_enable(fd: &OwnedFd, enable: bool) -> Result<(), ScanError> {
    let cmd = LeSetExtendedScanEnableCmd {
        enable: enable as u8,
        filter_dup: 0x00, // Don't filter duplicates
        duration: 0x0000,
        period: 0x0000,
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &cmd as *const LeSetExtendedScanEnableCmd as *const u8,
            mem::size_of::<LeSetExtendedScanEnableCmd>(),
        )
    };

    send_scan_enable(fd, OCF_LE_SET_EXTENDED_SCAN_ENABLE, bytes, enable)
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

    #[test]
    fn test_scan_enable_status_ok() {
        // Success is always acceptable.
        assert!(scan_enable_status_ok(true, 0x00));
        assert!(scan_enable_status_ok(false, 0x00));
        // Disabling an already-disabled scan may be rejected with Command Disallowed.
        assert!(scan_enable_status_ok(false, HCI_ERR_COMMAND_DISALLOWED));
        // Enabling must always succeed.
        assert!(!scan_enable_status_ok(true, HCI_ERR_COMMAND_DISALLOWED));
        // Other errors are never tolerated.
        assert!(!scan_enable_status_ok(false, 0x0f));
    }
}
