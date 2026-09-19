//! Raw HCI socket backend for RuuviTag scanning.
//!
//! This backend uses raw Linux HCI sockets to scan for BLE advertisements
//! without requiring the BlueZ daemon. It requires CAP_NET_RAW and
//! CAP_NET_ADMIN capabilities or root privileges.

use super::{
    DecodeError, MEASUREMENT_CHANNEL_BUFFER_SIZE, MeasurementResult, RSSI_UNAVAILABLE,
    RUUVI_MANUFACTURER_ID, ScanError, ScanSession, decode_ruuvi_data, with_rssi,
};
use crate::mac_address::MacAddress;
use libc::{
    AF_BLUETOOTH, SO_ATTACH_FILTER, SOCK_CLOEXEC, SOCK_RAW, SOL_SOCKET, c_int, c_void, sockaddr,
    socklen_t,
};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// HCI protocol constants
const BTPROTO_HCI: c_int = 1;
const HCI_FILTER: c_int = 2;

// HCI packet types
const HCI_EVENT_PKT: u8 = 0x04;

// HCI events
const EVT_LE_META_EVENT: u8 = 0x3E;
const EVT_CMD_COMPLETE: u8 = 0x0E;

// LE Meta event sub-events
const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
const EVT_LE_EXTENDED_ADVERTISING_REPORT: u8 = 0x0D;

// HCI commands
const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = 0x0003;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
const OCF_LE_SET_EXTENDED_SCAN_PARAMETERS: u16 = 0x0041;
const OCF_LE_SET_EXTENDED_SCAN_ENABLE: u16 = 0x0042;

// HCI error codes
const HCI_ERR_COMMAND_DISALLOWED: u8 = 0x0c;

// LE feature bits (from LE Read Local Supported Features)
// Bit 12 (byte 1, bit 4) = LE Extended Advertising
const LE_FEATURE_EXTENDED_ADVERTISING_BYTE: usize = 1;
const LE_FEATURE_EXTENDED_ADVERTISING_BIT: u8 = 1 << 4;

// Scanning PHYs bitmask for extended scan (bit 0 = LE 1M PHY)
const LE_1M_PHY: u8 = 0x01;

// How long to wait for an HCI command's Command Complete event
const COMMAND_TIMEOUT_MS: u64 = 1000;

// Scan types
const LE_SCAN_PASSIVE: u8 = 0x00;

// Own address type
const LE_PUBLIC_ADDRESS: u8 = 0x00;

// Filter policy
const FILTER_POLICY_ACCEPT_ALL: u8 = 0x00;

// AD types
const AD_TYPE_MANUFACTURER_DATA: u8 = 0xFF;

// Ruuvi manufacturer ID as little-endian bytes for quick matching
const RUUVI_MANUFACTURER_ID_LE: [u8; 2] = [
    (RUUVI_MANUFACTURER_ID & 0xFF) as u8,
    (RUUVI_MANUFACTURER_ID >> 8) as u8,
];

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_H: u16 = 0x08; // Half-word (16-bit)
const BPF_B: u16 = 0x10; // Byte
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// BPF instruction structure (classic BPF, not eBPF)
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8, // Jump if true
    jf: u8, // Jump if false
    k: u32, // Constant/offset
}

/// BPF program structure
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

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

/// Sysfs directory where the kernel exposes registered HCI controllers.
const HCI_SYSFS_CLASS: &str = "/sys/class/bluetooth";

/// Parse an adapter name such as "hci1" (or a bare index "1") into a device id.
///
/// The kernel names controllers strictly "hci<dev_id>", so the id can be
/// derived from the name without querying the kernel.
fn parse_adapter_name(name: &str) -> Option<u16> {
    name.strip_prefix("hci").unwrap_or(name).parse().ok()
}

/// List adapter names (e.g. "hci0") currently registered with the kernel.
///
/// Returns `None` when sysfs is unavailable; callers then proceed without
/// validation and any real problem surfaces at `bind`.
fn list_adapters() -> Option<Vec<String>> {
    list_adapters_in(Path::new(HCI_SYSFS_CLASS)).ok()
}

/// List adapter names found in a sysfs Bluetooth class directory, sorted by device id.
fn list_adapters_in(dir: &Path) -> io::Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| parse_adapter_name(name).is_some())
        .collect();
    names.sort_by_key(|name| parse_adapter_name(name).unwrap_or(u16::MAX));
    Ok(names)
}

/// Resolve a user-supplied adapter name to an HCI device id.
///
/// The sysfs listing is only consulted to validate the name and produce a
/// helpful error; when sysfs is unavailable the parsed device id is used
/// as-is.
fn resolve_adapter(name: &str) -> Result<u16, ScanError> {
    let dev_id = parse_adapter_name(name).ok_or_else(|| {
        ScanError::Bluetooth(format!(
            "Invalid Bluetooth adapter '{}': expected a name like hci0",
            name
        ))
    })?;
    let available = list_adapters();
    if let Some(available) = available.as_deref() {
        let canonical = format!("hci{}", dev_id);
        if !available.iter().any(|candidate| candidate == &canonical) {
            return Err(ScanError::adapter_not_found(name, Some(available)));
        }
    }
    Ok(dev_id)
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
fn set_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
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
fn set_command_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
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

/// Set up a BPF filter to match Ruuvi manufacturer ID at the kernel level.
///
/// This is the second layer of kernel-level filtering, complementing HCI_FILTER.
/// While HCI_FILTER drops non-LE-Meta-Event packets, this BPF filter provides
/// finer-grained filtering to drop:
/// - Non-advertising LE Meta Events (connection complete, etc.)
/// - Advertisements from non-Ruuvi devices (Tile trackers, smartwatches, etc.)
///
/// The filter checks:
/// 1. Packet type is HCI_EVENT_PKT (0x04)
/// 2. Event code is EVT_LE_META_EVENT (0x3E)
/// 3. Subevent is EVT_LE_ADVERTISING_REPORT (0x02)
/// 4. Packet contains Ruuvi manufacturer ID (0x9904) at common positions
///
/// Combined filtering layers:
/// ```text
/// All HCI packets
///   └─[HCI_FILTER]─► Only LE Meta Events
///       └─[BPF filter]─► Only Ruuvi advertising reports
///           └─[Application]─► Parse and decode
/// ```
fn set_bpf_ruuvi_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    // Ruuvi manufacturer ID as big-endian 16-bit value for BPF comparison
    // BPF loads 16-bit values in network byte order (big-endian)
    const RUUVI_ID_BE: u32 = 0x9904;

    // Build BPF program that checks for Ruuvi manufacturer ID
    // Classic BPF doesn't support loops, so we check multiple fixed offsets
    // where manufacturer data typically appears in advertising reports.
    //
    // HCI LE Advertising Report structure:
    // [0]: Packet type (0x04)
    // [1]: Event code (0x3E)
    // [2]: Parameter length
    // [3]: Subevent code (0x02)
    // [4]: Num reports
    // [5]: Event type
    // [6]: Address type
    // [7-12]: Address (6 bytes)
    // [13]: Data length
    // [14+]: Advertising data (AD structures)
    //
    // AD structure: [length][type][data...]
    // Manufacturer data (type 0xFF): [length][0xFF][mfg_id_lo][mfg_id_hi][data...]

    // Manufacturer data starts at offset 14 in a legacy report but at offset 29
    // in an extended report (the per-report header is larger). We scan a single
    // wide range that covers both layouts.
    const FIRST_OFFSET: u32 = 14;
    const LAST_OFFSET: u32 = 60;
    let num_offsets = (LAST_OFFSET - FIRST_OFFSET + 1) as usize;

    let mut filter = Vec::with_capacity(num_offsets * 2 + 16);

    // [0,1] Check packet type == HCI_EVENT_PKT (0x04)
    filter.push(SockFilter {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 0, // Will be patched to jump to reject
        k: HCI_EVENT_PKT as u32,
    });

    // [2,3] Check event code == EVT_LE_META_EVENT (0x3E)
    filter.push(SockFilter {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 1,
    });
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 0, // Will be patched
        k: EVT_LE_META_EVENT as u32,
    });

    // [4] Load subevent code, then accept either the legacy or the extended
    // advertising report subevent.
    filter.push(SockFilter {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 3,
    });
    // [5] subevent == EVT_LE_ADVERTISING_REPORT (0x02): jump to mfg-id checks
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0, // Will be patched to jump to checks_start
        jf: 0, // Fall through to the extended check below
        k: EVT_LE_ADVERTISING_REPORT as u32,
    });
    // [6] subevent == EVT_LE_EXTENDED_ADVERTISING_REPORT (0x0D): otherwise reject
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0, // Will be patched to jump to checks_start
        jf: 0, // Will be patched to jump to reject
        k: EVT_LE_EXTENDED_ADVERTISING_REPORT as u32,
    });

    let checks_start = filter.len();

    // Check for the Ruuvi manufacturer ID at each candidate offset.
    for offset in FIRST_OFFSET..=LAST_OFFSET {
        // Load 16-bit value at this offset
        filter.push(SockFilter {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        });
        // Jump to accept if it matches Ruuvi ID
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0, // Will be patched to jump to accept
            jf: 0, // Continue to next check
            k: RUUVI_ID_BE,
        });
    }

    // Reject: return 0 (drop packet)
    let reject_idx = filter.len();
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // Accept: return max packet size
    let accept_idx = filter.len();
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: 0xFFFF,
    });

    // Patch jump targets. A BPF jump offset is relative to the instruction
    // *after* the jump, so the offset to reach `target` from index `i` is
    // `target - i - 1`.
    // Packet-type and event-code checks reject on mismatch.
    filter[1].jf = (reject_idx - 1 - 1) as u8;
    filter[3].jf = (reject_idx - 3 - 1) as u8;
    // Subevent dispatch: both report types branch to the mfg-id checks; a
    // non-advertising LE Meta Event is rejected.
    filter[5].jt = (checks_start - 5 - 1) as u8;
    filter[6].jt = (checks_start - 6 - 1) as u8;
    filter[6].jf = (reject_idx - 6 - 1) as u8;

    // Manufacturer ID checks jump to accept on success
    for i in 0..num_offsets {
        let check_idx = checks_start + i * 2 + 1; // The JEQ instruction
        filter[check_idx].jt = (accept_idx - check_idx - 1) as u8;
    }

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const SockFprog as *const c_void,
            mem::size_of::<SockFprog>() as socklen_t,
        )
    };

    if ret < 0 {
        return Err(ScanError::Bluetooth(format!(
            "Failed to set BPF filter: {}",
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
fn configure_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
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
fn disable_le_scan(fd: &OwnedFd) -> Result<(), ScanError> {
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

/// Quick check if a packet might contain Ruuvi manufacturer data.
///
/// This performs a fast scan for the Ruuvi manufacturer ID bytes (0x99 0x04 in LE)
/// to avoid expensive parsing of non-Ruuvi advertisements.
#[inline]
fn might_be_ruuvi(data: &[u8]) -> bool {
    data.windows(2).any(|w| w == RUUVI_MANUFACTURER_ID_LE)
}

/// Parse a legacy LE Advertising Report (subevent 0x02) and extract RuuviTag data.
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

    // Legacy per-report header:
    //   num_reports(1) event_type(1) addr_type(1) address(6) data_len(1) data(..) rssi(1)
    // Extract address (6 bytes, in reverse order)
    if report.len() < 10 {
        return None;
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&report[3..9]);
    addr.reverse(); // HCI uses little-endian address

    let data_len = report[9] as usize;
    if report.len() < 10 + data_len {
        return None;
    }

    // The RSSI byte follows the advertising data; a truncated report means
    // the controller did not include it.
    let rssi = report
        .get(10 + data_len)
        .copied()
        .unwrap_or(RSSI_UNAVAILABLE as u8) as i8;

    parse_ruuvi_from_ad_data(&report[10..10 + data_len], addr, rssi)
}

/// Parse an LE Extended Advertising Report (subevent 0x0D) and extract RuuviTag data.
///
/// Bluetooth 5 controllers report advertisements with this event once extended
/// scanning is enabled. Its per-report header is larger than the legacy one and
/// carries PHY/SID/TX-power fields before the advertising data.
fn parse_extended_advertising_report(data: &[u8], _verbose: bool) -> Option<MeasurementResult> {
    // Skip HCI header (pkt type + event code + param len + subevent)
    let report = data.get(4..)?;

    // Number of reports
    let num_reports = *report.first()?;
    if num_reports == 0 {
        return None;
    }

    // Extended per-report header (relative to `report`):
    //   [0]      num_reports
    //   [1..3]   event_type (2)
    //   [3]      address_type
    //   [4..10]  address (6)
    //   [10]     primary_phy
    //   [11]     secondary_phy
    //   [12]     advertising_sid
    //   [13]     tx_power
    //   [14]     rssi
    //   [15..17] periodic_advertising_interval (2)
    //   [17]     direct_address_type
    //   [18..24] direct_address (6)
    //   [24]     data_length
    //   [25..]   data
    if report.len() < 25 {
        return None;
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&report[4..10]);
    addr.reverse(); // HCI uses little-endian address

    let data_len = report[24] as usize;
    if report.len() < 25 + data_len {
        return None;
    }
    let rssi = report[14] as i8; // RSSI byte in the extended per-report header

    parse_ruuvi_from_ad_data(&report[25..25 + data_len], addr, rssi)
}

/// Walk the AD structures of an advertisement and decode any RuuviTag
/// manufacturer data found.
///
/// `rssi` is the signal strength (dBm) reported by the controller for this
/// advertisement; the HCI "not available" sentinel is handled by
/// [`super::with_rssi`].
fn parse_ruuvi_from_ad_data(ad_data: &[u8], addr: [u8; 6], rssi: i8) -> Option<MeasurementResult> {
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
                return Some(match decode_ruuvi_data(MacAddress(addr), ruuvi_data) {
                    Ok(measurement) => Ok(with_rssi(measurement, rssi)),
                    Err(e) => Err(e),
                });
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
/// # Kernel-Level Filtering
///
/// To minimize CPU usage, two layers of kernel-level filtering are applied:
/// 1. **HCI_FILTER** - Drops all non-LE-Meta-Event packets (commands, ACL, etc.)
/// 2. **BPF filter** - Drops non-Ruuvi advertisements (Tile, smartwatches, etc.)
///
/// This ensures the application only wakes up for actual RuuviTag broadcasts,
/// not for the many other BLE devices that may be in the environment.
///
/// # Arguments
/// * `verbose` - If true, decode errors are sent as Err values; otherwise they're silently dropped.
/// * `adapter` - Kernel adapter name (e.g. "hci1"), or `None` for `hci0`.
///
/// # Returns
/// A scan session whose `measurements` receiver yields measurements (or decode
/// errors if verbose). Stopping the session (`ScanSession::stop`) makes the
/// backend send the LE Scan disable command, which is required on Linux to
/// actually end the adapter's scan.
///
/// # Requirements
/// - CAP_NET_RAW and CAP_NET_ADMIN capabilities or root privileges
/// - An available HCI device (typically hci0)
pub async fn start_scan(verbose: bool, adapter: Option<String>) -> Result<ScanSession, ScanError> {
    let dev_id = match adapter {
        Some(name) => resolve_adapter(&name)?,
        None => 0, // default to hci0, as before
    };

    // Open and configure HCI socket for receiving events
    let fd = open_hci_socket()?;
    bind_hci_socket(&fd, dev_id)?;
    set_hci_filter(&fd)?;
    set_bpf_ruuvi_filter(&fd)?; // Kernel-level filtering for Ruuvi packets

    // We need a separate socket for sending commands (bound to specific device).
    // It needs a filter that lets Command Complete events through so we can read
    // back command results and detect Bluetooth 5 extended-advertising support.
    let cmd_fd = open_hci_socket()?;
    bind_hci_socket(&cmd_fd, dev_id)?;
    set_command_hci_filter(&cmd_fd)?;
    configure_le_scan(&cmd_fd)?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();

    // Wrap in AsyncFd for async I/O
    let async_fd = AsyncFd::new(fd)
        .map_err(|e| ScanError::Bluetooth(format!("Failed to create async fd: {}", e)))?;

    // Spawn a task to read and process HCI events. The task owns the command
    // socket so it can disable the adapter's LE scan on shutdown — closing the
    // raw HCI socket alone does not stop scanning on Linux.
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 258]; // Max HCI event size

        loop {
            tokio::select! {
                // Graceful shutdown requested by the scan session.
                _ = task_cancel.cancelled() => break,
                // Wait for the socket to be readable
                result = async_fd.readable() => {
                    let mut guard = match result {
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

                        // Check if this is an LE advertising report that might be from a
                        // RuuviTag. Controllers emit legacy reports (0x02) or, in
                        // extended/Bluetooth 5 mode, extended reports (0x0D).
                        if n >= 4 && buf[0] == HCI_EVENT_PKT && buf[1] == EVT_LE_META_EVENT {
                            let subevent = buf[3];
                            // Quick check for Ruuvi manufacturer ID before expensive parsing
                            let result = if !might_be_ruuvi(&buf[..n]) {
                                None
                            } else if subevent == EVT_LE_ADVERTISING_REPORT {
                                parse_advertising_report(&buf[..n], verbose)
                            } else if subevent == EVT_LE_EXTENDED_ADVERTISING_REPORT {
                                parse_extended_advertising_report(&buf[..n], verbose)
                            } else {
                                None
                            };

                            if let Some(result) = result {
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
            }
        }

        // Tell the controller to stop scanning. Without this the adapter keeps
        // scanning after the process exits, wasting power and interfering with
        // other connections.
        if let Err(e) = disable_le_scan(&cmd_fd) {
            eprintln!("failed to disable LE scan: {e}");
        }
    });

    Ok(ScanSession::managed(rx, cancel, task))
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

    #[test]
    fn test_might_be_ruuvi_positive() {
        // Packet containing Ruuvi manufacturer ID (0x0499 in little-endian = 0x99 0x04)
        let packet = [0x04, 0x3E, 0x1A, 0x02, 0x01, 0x00, 0x99, 0x04, 0x05, 0x12];
        assert!(might_be_ruuvi(&packet));
    }

    #[test]
    fn test_might_be_ruuvi_negative() {
        // Packet without Ruuvi manufacturer ID
        let packet = [0x04, 0x3E, 0x1A, 0x02, 0x01, 0x00, 0xAA, 0xBB, 0x05, 0x12];
        assert!(!might_be_ruuvi(&packet));
    }

    #[test]
    fn test_might_be_ruuvi_empty() {
        assert!(!might_be_ruuvi(&[]));
        assert!(!might_be_ruuvi(&[0x99])); // Only one byte, can't match 2-byte pattern
    }

    /// Build a minimal RuuviTag RAWv2 (data format 5) manufacturer payload.
    fn ruuvi_rawv2_payload() -> Vec<u8> {
        // 0x9904 manufacturer id + 24 bytes of format-5 data
        let mut data = vec![0x99, 0x04];
        data.push(0x05); // data format 5
        data.extend(std::iter::repeat_n(0x00, 23));
        data
    }

    #[test]
    fn test_parse_extended_advertising_report() {
        let payload = ruuvi_rawv2_payload();
        // AD structure: [len][type=0xFF][payload...]
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);

        // HCI header + extended report header + data
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_EXTENDED_ADVERTISING_REPORT,
        ];
        pkt.push(0x01); // num_reports
        pkt.extend_from_slice(&[0x00, 0x00]); // event_type
        pkt.push(0x00); // address_type
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // address (LE)
        pkt.extend_from_slice(&[0x01, 0x01, 0x00, 0x7F, 0xC3]); // primary/secondary phy, sid, tx_power, rssi
        pkt.extend_from_slice(&[0x00, 0x00]); // periodic interval
        pkt.push(0x00); // direct_address_type
        pkt.extend_from_slice(&[0x00; 6]); // direct_address
        pkt.push(ad.len() as u8); // data_length
        pkt.extend_from_slice(&ad);

        assert!(might_be_ruuvi(&pkt));
        let result = parse_extended_advertising_report(&pkt, false);
        assert!(result.is_some(), "expected a RuuviTag measurement");
        let measurement = result.unwrap().expect("payload should decode");
        // Address is little-endian on the wire, so it reverses on decode.
        assert_eq!(
            measurement.mac,
            MacAddress([0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        );
        // RSSI 0xC3 = -61 dBm, from the extended per-report header.
        assert_eq!(measurement.rssi, Some(-61));
    }

    #[test]
    fn test_parse_legacy_advertising_report_with_rssi() {
        let payload = ruuvi_rawv2_payload();
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);

        // HCI header + legacy report header, data, and a trailing RSSI byte.
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_ADVERTISING_REPORT,
        ];
        pkt.push(0x01); // num_reports
        pkt.push(0x00); // event_type
        pkt.push(0x00); // address_type
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // address (LE)
        pkt.push(ad.len() as u8); // data_len
        pkt.extend_from_slice(&ad);
        pkt.push(0xB0); // RSSI = -80 dBm

        assert!(might_be_ruuvi(&pkt));
        let result = parse_advertising_report(&pkt, false);
        let measurement = result.unwrap().expect("payload should decode");
        assert_eq!(measurement.rssi, Some(-80));
    }

    #[test]
    fn test_parse_report_maps_rssi_sentinel_to_none() {
        let payload = ruuvi_rawv2_payload();
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);

        // Legacy report whose RSSI byte is the 127 "not available" sentinel.
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_ADVERTISING_REPORT,
        ];
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        pkt.push(ad.len() as u8);
        pkt.extend_from_slice(&ad);
        pkt.push(RSSI_UNAVAILABLE as u8);

        let result = parse_advertising_report(&pkt, false);
        let measurement = result.unwrap().expect("payload should decode");
        assert_eq!(measurement.rssi, None);
    }

    #[test]
    fn test_parse_adapter_name() {
        assert_eq!(parse_adapter_name("hci0"), Some(0));
        assert_eq!(parse_adapter_name("hci1"), Some(1));
        assert_eq!(parse_adapter_name("1"), Some(1));
        assert_eq!(parse_adapter_name("hci"), None);
        assert_eq!(parse_adapter_name("hciX"), None);
        assert_eq!(parse_adapter_name(""), None);
        assert_eq!(parse_adapter_name("hci99999"), None);
    }

    #[test]
    fn test_resolve_adapter_rejects_invalid_name() {
        match resolve_adapter("not-an-adapter") {
            Err(ScanError::Bluetooth(message)) => {
                assert!(message.contains("not-an-adapter"));
                assert!(message.contains("expected a name like hci0"));
            }
            other => panic!("expected Bluetooth error, got {:?}", other),
        }
    }

    #[test]
    fn test_list_adapters_in_sorts_by_device_id() {
        let dir = std::env::temp_dir().join(format!("ruuvitag-hci-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("hci10")).unwrap();
        std::fs::create_dir_all(dir.join("hci2")).unwrap();
        std::fs::create_dir_all(dir.join("not-hci")).unwrap();

        let adapters = list_adapters_in(&dir).unwrap();
        assert_eq!(adapters, vec!["hci2".to_string(), "hci10".to_string()]);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
