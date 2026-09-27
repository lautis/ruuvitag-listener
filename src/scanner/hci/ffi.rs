//! Raw HCI socket FFI layer: socket/command/scan packet structures, socket
//! setup, filtering, and HCI command I/O.

use super::*;
use crate::scanner::ScanError;
use libc::{AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, c_int, c_void, sockaddr, socklen_t};
use std::io;
use std::mem;
use std::ops::Deref;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// HCI socket protocols and options
const BTPROTO_HCI: c_int = 1;
const HCI_FILTER: c_int = 2;

// HCI commands
const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = 0x0003;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
const OCF_LE_READ_SCAN_ENABLE: u16 = 0x000D;
const OCF_LE_SET_EXTENDED_SCAN_PARAMETERS: u16 = 0x0041;
const OCF_LE_SET_EXTENDED_SCAN_ENABLE: u16 = 0x0042;

// HCI error codes
const HCI_ERR_UNKNOWN_COMMAND: u8 = 0x01;
const HCI_ERR_COMMAND_DISALLOWED: u8 = 0x0c;

// LE feature bits (from LE Read Local Supported Features)
// Bit 12 (byte 1, bit 4) = LE Extended Advertising
const LE_FEATURE_EXTENDED_ADVERTISING_BYTE: usize = 1;
const LE_FEATURE_EXTENDED_ADVERTISING_BIT: u8 = 1 << 4;

// Scanning PHYs bitmask for extended scan (bit 0 = LE 1M PHY)
const LE_1M_PHY: u8 = 0x01;

// Scan types, own address type, filter policy
const LE_SCAN_PASSIVE: u8 = 0x00;
const LE_PUBLIC_ADDRESS: u8 = 0x00;
const FILTER_POLICY_ACCEPT_ALL: u8 = 0x00;

// The events the command socket must receive to read back command results
const EVT_CMD_COMPLETE: u8 = 0x0E;
const EVT_CMD_STATUS: u8 = 0x0F;

// How long to wait for a command's reply (Command Complete or a failing
// Command Status)
const COMMAND_TIMEOUT_MS: u64 = 1000;

/// LE scan interval and window: 200 ms in 0.625 ms units (0x140 = 320 ticks).
const SCAN_200MS: u16 = 0x0140;

// LE_Scan_Enable value (byte 7 of an LE Read Scan Enable response) that means
// the controller is actively scanning.
const HCI_SCAN_ENABLED: u8 = 0x01;

// Filter_Duplicates value (byte 8 of the same response) that means the
// controller discards repeated advertisements from an address it has already
// reported.
const HCI_FILTER_DUPLICATES: u8 = 0x01;

/// Owned raw HCI socket bound to one controller.
pub(crate) struct HciSocket {
    fd: OwnedFd,
}

impl HciSocket {
    /// Open a raw HCI socket and bind it to the given controller.
    pub(crate) fn open(dev_id: u16) -> Result<Self, ScanError> {
        let fd = open_hci_socket()?;
        bind_hci_socket(&fd, dev_id)?;
        Ok(Self { fd })
    }

    /// Restrict kernel-delivered packets to LE Meta Events.
    pub(crate) fn set_event_filter(&self) -> Result<(), ScanError> {
        set_hci_filter(&self.fd)
    }

    /// Restrict kernel-delivered packets to command replies: Command
    /// Complete and Command Status events.
    pub(crate) fn set_command_filter(&self) -> Result<(), ScanError> {
        set_command_hci_filter(&self.fd)
    }

    /// Dispatch a command and return its status and reply event.
    ///
    /// A rejection arrives as a Command Status rather than a Command Complete,
    /// and is the final word, so the status comes back the same way with no
    /// event. [`Self::command_checked`] rejects a non-zero status instead.
    fn command(&self, ogf: u16, ocf: u16, params: &[u8]) -> Result<(u8, Vec<u8>), ScanError> {
        let packet = hci_command_packet(ogf, ocf, params);
        send_hci_command(&self.fd, &packet)?;

        match read_command_reply(&self.fd, hci_opcode(ogf, ocf))? {
            CommandReply::Complete(event) => {
                // Status is the first return parameter, at byte 6.
                let status = *event.get(6).ok_or_else(|| {
                    ScanError::Bluetooth("Truncated HCI Command Complete event".to_string())
                })?;
                Ok((status, event))
            }
            CommandReply::Failed(status) => Ok((status, Vec::new())),
        }
    }

    /// Send a command and fail on a non-zero status, returning the Command
    /// Complete event for any return parameters.
    fn command_checked(&self, ogf: u16, ocf: u16, params: &[u8]) -> Result<Vec<u8>, ScanError> {
        let opcode = hci_opcode(ogf, ocf);
        let (status, event) = self.command(ogf, ocf, params)?;
        if status != 0 {
            return Err(command_status_error(opcode, status));
        }
        Ok(event)
    }
}

impl AsRawFd for HciSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Deref for HciSocket {
    type Target = OwnedFd;

    fn deref(&self) -> &OwnedFd {
        &self.fd
    }
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

/// Compose an HCI opcode from an OGF and OCF.
fn hci_opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | ocf
}

/// Create an HCI command packet
fn hci_command_packet(ogf: u16, ocf: u16, params: &[u8]) -> Vec<u8> {
    let opcode = hci_opcode(ogf, ocf);
    let mut packet = Vec::with_capacity(4 + params.len());
    packet.push(0x01); // HCI command packet type
    packet.push((opcode & 0xFF) as u8);
    packet.push((opcode >> 8) as u8);
    packet.push(params.len() as u8);
    packet.extend_from_slice(params);
    packet
}

/// Build a `ScanError::Bluetooth` from the latest OS error for `action`.
fn ffi_err(action: &str) -> ScanError {
    ScanError::Bluetooth(format!("{action}: {}", io::Error::last_os_error()))
}

/// Build the error for a command the controller rejected with `status`.
fn command_status_error(opcode: u16, status: u8) -> ScanError {
    ScanError::Bluetooth(format!(
        "HCI command {opcode:#06x} failed with status {status:#04x}"
    ))
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
        return Err(ffi_err("Failed to create HCI socket"));
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
        return Err(ffi_err("Failed to bind HCI socket"));
    }

    Ok(())
}

/// Keep the event socket to LE Meta Events, so the kernel drops everything
/// else before userspace wakes for it. HCI_FILTER cannot select LE subevents,
/// so the BPF filter in `bpf` narrows it down to Ruuvi advertisements.
fn set_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    let mut filter = HciFilter::new();
    filter.set_ptype(HCI_EVENT_PKT);
    filter.set_event(EVT_LE_META_EVENT);
    apply_hci_filter(fd, &filter)
}

/// Event packets only, and among those the two events a command's reply can
/// arrive as: a controller that rejects a command outright may answer with
/// either (an Intel AX210 rejects `LE Read Scan Enable` with a Command
/// Status).
fn command_reply_filter() -> HciFilter {
    let mut filter = HciFilter::new();
    filter.set_ptype(HCI_EVENT_PKT);
    filter.set_event(EVT_CMD_COMPLETE);
    filter.set_event(EVT_CMD_STATUS);
    filter
}

/// Apply the command reply filter. A freshly opened HCI raw socket drops
/// every packet, so without a filter the replies never reach userspace.
fn set_command_hci_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    apply_hci_filter(fd, &command_reply_filter())
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
        return Err(ffi_err("Failed to set HCI filter"));
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
        return Err(ffi_err("Failed to send HCI command"));
    }

    Ok(())
}

/// Read up to `buf.len()` bytes from `fd` into `buf`.
pub(crate) fn read_packet(fd: &impl AsRawFd, buf: &mut [u8]) -> io::Result<usize> {
    // Safety: `read` is given a writable buffer of the correct length.
    let ret = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, buf.len()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// A controller's reply to a command sent on the command socket.
#[derive(Debug, PartialEq)]
enum CommandReply {
    /// The Command Complete event for the command, carrying its status and
    /// return parameters.
    Complete(Vec<u8>),
    /// A Command Status carrying a failure for the command, as the HCI
    /// status it reported. No Command Complete follows a failing status,
    /// so this is the controller's final word on the command.
    Failed(u8),
}

/// Classify a received packet against the command being waited on.
///
/// Returns `None` for packets to skip while waiting: replies to other
/// commands, anything that is not an event packet, and a Command Status with
/// status zero — that one only acknowledges the command.
fn parse_command_reply(buf: &[u8], expected_opcode: u16) -> Option<CommandReply> {
    if buf.first() != Some(&HCI_EVENT_PKT) {
        return None;
    }
    match buf.get(1) {
        // Command Complete: [1]=event, [2]=plen, [3]=num cmds, [4..6]=opcode
        // (LE), [6..]=return params (status first).
        Some(&EVT_CMD_COMPLETE)
            if buf.len() >= 6 && u16::from_le_bytes([buf[4], buf[5]]) == expected_opcode =>
        {
            Some(CommandReply::Complete(buf.to_vec()))
        }
        // Command Status: [1]=event, [2]=plen, [3]=num cmds, [4]=status,
        // [5..7]=opcode (LE).
        Some(&EVT_CMD_STATUS)
            if buf.len() >= 7
                && u16::from_le_bytes([buf[5], buf[6]]) == expected_opcode
                && buf[4] != 0 =>
        {
            Some(CommandReply::Failed(buf[4]))
        }
        _ => None,
    }
}

/// Wait for the controller's reply to the command with `expected_opcode`.
///
/// The socket is non-blocking, so we `poll(2)` and read until the reply
/// arrives or the deadline passes; mismatching events are skipped.
fn read_command_reply(fd: &OwnedFd, expected_opcode: u16) -> Result<CommandReply, ScanError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(COMMAND_TIMEOUT_MS);
    let mut buf = [0u8; HCI_EVENT_BUF_SIZE];

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
        if let Some(reply) = parse_command_reply(&buf[..n], expected_opcode) {
            return Ok(reply);
        }
    }
}

/// Query whether the controller supports LE Extended Advertising.
fn controller_supports_extended_scan(fd: &HciSocket) -> Result<bool, ScanError> {
    let event = fd.command_checked(OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES, &[])?;

    // Return params after status (byte 6) are the 8-byte LE features bitmap.
    let features_start = 7;
    match event.get(features_start + LE_FEATURE_EXTENDED_ADVERTISING_BYTE) {
        Some(byte) => Ok(byte & LE_FEATURE_EXTENDED_ADVERTISING_BIT != 0),
        None => Ok(false),
    }
}

/// The controller's LE scan state, as reported by `LE Read Scan Enable` — the
/// only scan configuration the spec lets us read back, which is why both
/// fields are kept: whether a scan is running decides ownership, and the
/// duplicate policy is what to restore on the way out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanState {
    /// Whether the controller is actively scanning.
    pub(crate) enabled: bool,
    /// Whether the controller discards duplicate advertisements.
    pub(crate) filter_duplicates: bool,
}

/// Parse an `LE Read Scan Enable` Command Complete response.
///
/// The caller has already checked the status byte (6); byte 7 is
/// LE_Scan_Enable and byte 8 Filter_Duplicates. A response too short to hold
/// a field reads as off for that field.
fn scan_state(event: &[u8]) -> ScanState {
    ScanState {
        enabled: event.get(7).copied() == Some(HCI_SCAN_ENABLED),
        filter_duplicates: event.get(8).copied() == Some(HCI_FILTER_DUPLICATES),
    }
}

/// The outcome of asking a controller for its LE scan state.
#[derive(Debug)]
pub(crate) enum ScanStateOutcome {
    /// The controller reported its state.
    Known(ScanState),
    /// The controller does not implement `LE Read Scan Enable`, so it cannot
    /// say whether a scan was already running. Some firmwares (e.g. Intel
    /// AX210) report this instead of a state.
    Unreported,
    /// The query failed (e.g. a timeout), so the state is unknown.
    Failed(ScanError),
}

/// Read the controller's current LE scan state.
///
/// The answer is global — it says nothing about who started the scan — which
/// is what lets the caller tell its own scan from someone else's. A controller
/// that does not implement the command reports [`ScanStateOutcome::Unreported`].
pub(crate) fn le_scan_state(fd: &HciSocket) -> ScanStateOutcome {
    scan_state_outcome(fd.command(OGF_LE_CTL, OCF_LE_READ_SCAN_ENABLE, &[]))
}

/// Translate the reply to `LE Read Scan Enable` into an outcome.
fn scan_state_outcome(reply: Result<(u8, Vec<u8>), ScanError>) -> ScanStateOutcome {
    match reply {
        Ok((0, event)) => ScanStateOutcome::Known(scan_state(&event)),
        // Either reply shape can carry the status. Only "Unknown HCI Command"
        // means unimplemented; "Unsupported Feature or Parameter" (0x11) lands
        // in `Failed`, which exit treats the same way.
        Ok((HCI_ERR_UNKNOWN_COMMAND, _)) => ScanStateOutcome::Unreported,
        Ok((status, _)) => ScanStateOutcome::Failed(command_status_error(
            hci_opcode(OGF_LE_CTL, OCF_LE_READ_SCAN_ENABLE),
            status,
        )),
        Err(e) => ScanStateOutcome::Failed(e),
    }
}

/// Which LE scan command family to use: legacy (Bluetooth 4.x) vs extended
/// (Bluetooth 5.x). Extended controllers only report advertisements via
/// Extended Advertising Reports, so they must be driven with the extended
/// commands.
#[derive(Clone, Copy)]
pub(crate) enum ScanMode {
    Legacy,
    Extended,
}

impl ScanMode {
    /// Choose the mode for this controller from its LE feature query.
    fn for_controller(fd: &HciSocket) -> Result<Self, ScanError> {
        if controller_supports_extended_scan(fd)? {
            Ok(Self::Extended)
        } else {
            Ok(Self::Legacy)
        }
    }

    /// OCF of the matching LE Set Scan Parameters command.
    fn set_params_ocf(self) -> u16 {
        match self {
            Self::Legacy => OCF_LE_SET_SCAN_PARAMETERS,
            Self::Extended => OCF_LE_SET_EXTENDED_SCAN_PARAMETERS,
        }
    }

    /// OCF of the matching LE Set Scan Enable command.
    fn enable_ocf(self) -> u16 {
        match self {
            Self::Legacy => OCF_LE_SET_SCAN_ENABLE,
            Self::Extended => OCF_LE_SET_EXTENDED_SCAN_ENABLE,
        }
    }

    /// Wire bytes for LE Set Scan Parameters: passive scan, 200ms interval,
    /// 200ms window, public address, accept-all policy. The extended variant
    /// carries one scan parameter block per scanning PHY; we only ever scan
    /// on the LE 1M PHY (`scanning_phys == LE_1M_PHY`), so exactly one
    /// `{scan_type, interval, window}` block follows the PHY bitmask.
    fn set_params_bytes(self) -> Vec<u8> {
        // Interval and window are identical: 200 ms (0x0140) in 0.625 ms units.
        let (lo, hi) = (SCAN_200MS as u8, (SCAN_200MS >> 8) as u8);
        match self {
            // scan_type, interval, window, own_addr_type, filter_policy
            Self::Legacy => vec![
                LE_SCAN_PASSIVE,
                lo,
                hi,
                lo,
                hi,
                LE_PUBLIC_ADDRESS,
                FILTER_POLICY_ACCEPT_ALL,
            ],
            // own_addr_type, filter_policy, scanning_phys, scan_type, interval, window
            Self::Extended => vec![
                LE_PUBLIC_ADDRESS,
                FILTER_POLICY_ACCEPT_ALL,
                LE_1M_PHY,
                LE_SCAN_PASSIVE,
                lo,
                hi,
                lo,
                hi,
            ],
        }
    }

    /// Wire bytes for LE Set Scan Enable; the extended variant adds the
    /// duration/period fields (both zero for continuous scanning).
    fn enable_bytes(self, enable: bool, filter_duplicates: bool) -> Vec<u8> {
        // enable, filter_dup
        let mut bytes = vec![enable as u8, filter_duplicates as u8];
        if matches!(self, Self::Extended) {
            bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // duration, period
        }
        bytes
    }
}

/// Disable, set the scan parameters, enable.
///
/// The disable comes first: a controller rejects `LE Set Scan Parameters` with
/// "Command Disallowed" while a scan is active. Attaching to a pre-existing
/// scan replaces its parameters, of which only the duplicate policy is
/// restored afterwards (see [`restore_le_scan_duplicates`]).
fn configure_scan(fd: &HciSocket, mode: ScanMode) -> Result<(), ScanError> {
    set_scan_enable_with_duplicates(fd, mode, false, false)?;
    let params = mode.set_params_bytes();
    fd.command_checked(OGF_LE_CTL, mode.set_params_ocf(), &params)?;
    set_scan_enable_with_duplicates(fd, mode, true, false)?;
    Ok(())
}

/// Enable or disable LE scanning, tolerating "Command Disallowed" when
/// disabling an already-disabled scan (see [`scan_enable_status_ok`]).
///
/// `filter_duplicates` is the controller-side dedup policy. This listener asks
/// for `false` on every path except restoring someone else's: RuuviTags
/// re-broadcast much the same payload, so deduplication would discard
/// measurements it still wants to see.
fn set_scan_enable_with_duplicates(
    fd: &HciSocket,
    mode: ScanMode,
    enable: bool,
    filter_duplicates: bool,
) -> Result<(), ScanError> {
    let opcode = hci_opcode(OGF_LE_CTL, mode.enable_ocf());
    let bytes = mode.enable_bytes(enable, filter_duplicates);
    let (status, _event) = fd.command(OGF_LE_CTL, mode.enable_ocf(), &bytes)?;
    if !scan_enable_status_ok(enable, status) {
        return Err(command_status_error(opcode, status));
    }
    Ok(())
}

/// Configure LE scanning, preferring extended scanning when the controller
/// supports it, and report the mode used so shutdown can speak the same
/// command family without re-querying the controller's features.
pub(crate) fn configure_le_scan(fd: &HciSocket) -> Result<ScanMode, ScanError> {
    let mode = ScanMode::for_controller(fd)?;
    configure_scan(fd, mode)?;
    Ok(mode)
}

/// Disable LE scanning on the controller, matching the mode used to start it.
///
/// The controller's feature set determines which disable command it accepts
/// (legacy vs extended).
pub(crate) fn disable_le_scan(fd: &HciSocket, mode: ScanMode) -> Result<(), ScanError> {
    set_scan_enable_with_duplicates(fd, mode, false, false)
}

/// Put back the duplicate policy of a scan this process attached to.
///
/// `Filter_Duplicates` is a parameter of LE Set Scan Enable, so restoring it
/// takes one command and leaves everything else as it is — and it is the only
/// part of the previous configuration that can be restored, the spec offering
/// no way to read the rest back.
///
/// The state is re-read first, because restoring means sending `LE Set Scan
/// Enable`, which re-enables scanning as a side effect: a scan whose owner has
/// since stopped it would be restarted for nobody. The scan is also cycled
/// rather than re-enabled in place, since a redundant enable is rejected with
/// "Command Disallowed" (see [`scan_enable_status_ok`]) — the cost is a
/// one-command gap at exit.
///
/// Returns the non-fatal warning to report, if any.
pub(crate) fn restore_le_scan_duplicates(
    fd: &HciSocket,
    mode: ScanMode,
    filter_duplicates: bool,
) -> Result<Option<String>, ScanError> {
    let scan_running = match le_scan_state(fd) {
        ScanStateOutcome::Known(state) => state.enabled,
        // Unreachable: a policy to restore was read at startup, so the
        // controller reports its state. Nothing safe to restore if it stops.
        ScanStateOutcome::Unreported => {
            return Ok(Some(
                "cannot re-read the LE scan state; not restoring its duplicate policy".to_string(),
            ));
        }
        ScanStateOutcome::Failed(e) => return Err(e),
    };
    if !scan_running {
        return Ok(Some(
            "LE scan stopped while we ran; not restoring its duplicate policy".to_string(),
        ));
    }
    set_scan_enable_with_duplicates(fd, mode, false, false)?;
    set_scan_enable_with_duplicates(fd, mode, true, filter_duplicates)?;
    Ok(None)
}

/// Whether a returned status is acceptable for an LE scan enable/disable:
/// disabling an already-disabled scan is a no-op that some controllers reject
/// with `Command Disallowed` (e.g. Broadcom BCM43455).
fn scan_enable_status_ok(enable: bool, status: u8) -> bool {
    status == 0 || (!enable && status == HCI_ERR_COMMAND_DISALLOWED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hci_filter_setup() {
        let mut filter = HciFilter::new();
        filter.set_ptype(HCI_EVENT_PKT);
        filter.set_event(EVT_LE_META_EVENT);

        assert_eq!(filter.type_mask, 1 << HCI_EVENT_PKT);
        assert_eq!(filter.event_mask[1], 1 << (EVT_LE_META_EVENT % 32));
    }

    #[test]
    fn test_hci_command_packet() {
        // opcode 0x200C (OGF_LE_CTL << 10 | OCF_LE_SET_SCAN_ENABLE), 2 params
        let packet = hci_command_packet(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, &[0x01, 0x00]);
        assert_eq!(packet, vec![0x01, 0x0C, 0x20, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_scan_enable_status_ok() {
        assert!(scan_enable_status_ok(true, 0x00));
        assert!(scan_enable_status_ok(false, 0x00));
        // Disabling an already-disabled scan may be rejected.
        assert!(scan_enable_status_ok(false, HCI_ERR_COMMAND_DISALLOWED));
        assert!(!scan_enable_status_ok(true, HCI_ERR_COMMAND_DISALLOWED));
        assert!(!scan_enable_status_ok(false, 0x0f));
    }

    #[test]
    fn test_scan_mode_wire_bytes_and_ocfs() {
        // Legacy LE Set Scan Parameters: scan_type=passive, 200ms interval and
        // window, public address, accept-all filter policy (7 bytes).
        assert_eq!(
            ScanMode::Legacy.set_params_bytes(),
            vec![0x00, 0x40, 0x01, 0x40, 0x01, 0x00, 0x00]
        );
        // Extended adds one PHY block (scanning_phys = LE 1M) (8 bytes).
        assert_eq!(
            ScanMode::Extended.set_params_bytes(),
            vec![0x00, 0x00, 0x01, 0x00, 0x40, 0x01, 0x40, 0x01]
        );

        // Legacy LE Set Scan Enable is 2 bytes; the extended variant adds the
        // duration/period fields (both zero for continuous scanning).
        assert_eq!(ScanMode::Legacy.enable_bytes(true, false), vec![0x01, 0x00]);
        assert_eq!(
            ScanMode::Legacy.enable_bytes(false, false),
            vec![0x00, 0x00]
        );
        assert_eq!(
            ScanMode::Extended.enable_bytes(true, false),
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            ScanMode::Extended.enable_bytes(false, false),
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        // Filter_Duplicates is the second byte, in both command variants.
        assert_eq!(ScanMode::Legacy.enable_bytes(true, true), vec![0x01, 0x01]);
        assert_eq!(
            ScanMode::Extended.enable_bytes(true, true),
            vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x00]
        );

        assert_eq!(
            ScanMode::Legacy.set_params_ocf(),
            OCF_LE_SET_SCAN_PARAMETERS
        );
        assert_eq!(
            ScanMode::Extended.set_params_ocf(),
            OCF_LE_SET_EXTENDED_SCAN_PARAMETERS
        );
        assert_eq!(ScanMode::Legacy.enable_ocf(), OCF_LE_SET_SCAN_ENABLE);
        assert_eq!(
            ScanMode::Extended.enable_ocf(),
            OCF_LE_SET_EXTENDED_SCAN_ENABLE
        );
    }

    #[test]
    fn test_scan_state_parses_command_complete() {
        // Command Complete for LE Read Scan Enable (opcode 0x200d): status at
        // byte 6, LE_Scan_Enable at byte 7, Filter_Duplicates at byte 8.
        let disabled = [0x04u8, 0x0E, 0x06, 0x01, 0x0D, 0x20, 0x00, 0x00, 0x00];
        assert_eq!(
            scan_state(&disabled),
            ScanState {
                enabled: false,
                filter_duplicates: false
            }
        );

        let enabled = [0x04u8, 0x0E, 0x06, 0x01, 0x0D, 0x20, 0x00, 0x01, 0x00];
        assert_eq!(
            scan_state(&enabled),
            ScanState {
                enabled: true,
                filter_duplicates: false
            }
        );

        let filtering = [0x04u8, 0x0E, 0x06, 0x01, 0x0D, 0x20, 0x00, 0x01, 0x01];
        assert_eq!(
            scan_state(&filtering),
            ScanState {
                enabled: true,
                filter_duplicates: true
            }
        );

        // A truncated event reads as an idle controller with no filtering.
        assert_eq!(scan_state(&[0x04, 0x0E]), ScanState::default());
    }

    /// Both reply events have to pass: without the Command Status bit a
    /// rejection never reaches userspace and every query for one times out.
    #[test]
    fn test_command_filter_passes_both_reply_events() {
        let filter = command_reply_filter();
        assert_eq!(filter.type_mask, 1 << HCI_EVENT_PKT);
        assert_eq!(
            filter.event_mask[0],
            (1 << (EVT_CMD_COMPLETE % 32)) | (1 << (EVT_CMD_STATUS % 32))
        );
    }

    /// Replies are matched by event kind and opcode; everything else is
    /// skipped while waiting.
    #[test]
    fn test_parse_command_reply_matches_only_its_command() {
        // Command Complete for LE Read Scan Enable (0x200d).
        let complete = [0x04, 0x0E, 0x06, 0x01, 0x0D, 0x20, 0x00, 0x01, 0x00];
        assert_eq!(
            parse_command_reply(&complete, 0x200d),
            Some(CommandReply::Complete(complete.to_vec()))
        );

        // Command Complete for another command belongs to its wait, not ours.
        assert_eq!(
            parse_command_reply(&[0x04, 0x0E, 0x0C, 0x01, 0x03, 0x20, 0x00], 0x200d),
            None
        );

        // A Command Status with a failure is the final word — the shape an
        // Intel AX210 rejects this command in.
        assert_eq!(
            parse_command_reply(&[0x04, 0x0F, 0x04, 0x0C, 0x01, 0x0D, 0x20], 0x200d),
            Some(CommandReply::Failed(0x01))
        );

        // Status zero only acknowledges the command; its real reply follows.
        assert_eq!(
            parse_command_reply(&[0x04, 0x0F, 0x04, 0x0C, 0x00, 0x0D, 0x20], 0x200d),
            None
        );

        // Command Status for another command.
        assert_eq!(
            parse_command_reply(&[0x04, 0x0F, 0x04, 0x01, 0x0C, 0x03, 0x20], 0x200d),
            None
        );

        // A Command Complete short of its status byte still identifies its
        // command, so the caller reports the truncation instead of the wait
        // timing out on a reply already in hand.
        assert_eq!(
            parse_command_reply(&[0x04, 0x0E, 0x01, 0x01, 0x0D, 0x20], 0x200d),
            Some(CommandReply::Complete(vec![
                0x04, 0x0E, 0x01, 0x01, 0x0D, 0x20
            ]))
        );

        // Truncated and non-event packets are not replies.
        assert_eq!(
            parse_command_reply(&[0x04, 0x0E, 0x02, 0x01, 0x0D], 0x200d),
            None
        );
        assert_eq!(
            parse_command_reply(&[0x04, 0x0F, 0x04, 0x0C, 0x01, 0x0D], 0x200d),
            None
        );
        assert_eq!(
            parse_command_reply(&[0x01, 0x0F, 0x04, 0x0C, 0x01, 0x0D, 0x20], 0x200d),
            None
        );
    }

    /// Reply shapes map to the outcome they mean.
    #[test]
    fn test_scan_state_outcome_translations() {
        let reported = Ok((
            0x00,
            vec![0x04, 0x0E, 0x06, 0x01, 0x0D, 0x20, 0x00, 0x01, 0x01],
        ));
        assert!(matches!(
            scan_state_outcome(reported),
            ScanStateOutcome::Known(ScanState {
                enabled: true,
                filter_duplicates: true
            })
        ));

        // "Unknown HCI Command" as a Command Status, which carries no event.
        assert!(matches!(
            scan_state_outcome(Ok((HCI_ERR_UNKNOWN_COMMAND, Vec::new()))),
            ScanStateOutcome::Unreported
        ));

        // The same status in a Command Complete says the same thing.
        assert!(matches!(
            scan_state_outcome(Ok((
                HCI_ERR_UNKNOWN_COMMAND,
                vec![0x04, 0x0E, 0x04, 0x01, 0x0D, 0x20, 0x01]
            ))),
            ScanStateOutcome::Unreported
        ));

        // Any other status is a failure.
        match scan_state_outcome(Ok((HCI_ERR_COMMAND_DISALLOWED, Vec::new()))) {
            ScanStateOutcome::Failed(ScanError::Bluetooth(message)) => {
                assert!(message.contains("0x200d"), "names the command: {message}");
                assert!(message.contains("0x0c"), "names the status: {message}");
            }
            other => panic!("expected a failed query, got {other:?}"),
        }

        // A transport error (e.g. a timeout) is a failure too.
        assert!(matches!(
            scan_state_outcome(Err(ScanError::Bluetooth("timed out".into()))),
            ScanStateOutcome::Failed(_)
        ));
    }
}
