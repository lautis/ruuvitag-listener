//! HCI scanner entry point: adapter resolution, `start_scan`, and the
//! event read loop.

use super::bpf::set_bpf_ruuvi_filter;
use super::ffi::{
    HciSocket, configure_le_scan, disable_le_scan, read_packet, set_command_hci_filter,
    set_hci_filter,
};
use super::parse::parse_event;
use super::*;
use crate::scanner::{
    MEASUREMENT_CHANNEL_BUFFER_SIZE, MeasurementResult, ScanError, ScanExitBehavior, ScanSession,
};
use std::io;
use std::path::Path;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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

/// Forward every HCI event currently readable on `guard` to `tx`.
///
/// Returns `false` when the receive loop should end: a read error or a
/// departed consumer. An empty socket buffer just ends the drain.
async fn drain_events(
    guard: &mut AsyncFdReadyGuard<'_, HciSocket>,
    buf: &mut [u8; HCI_EVENT_BUF_SIZE],
    tx: &mpsc::Sender<MeasurementResult>,
    warn_tx: &mpsc::UnboundedSender<String>,
    verbose: bool,
) -> bool {
    loop {
        let n = match guard.try_io(|inner| read_packet(inner, buf)) {
            Ok(Ok(0)) | Err(_) => return true, // EOF or no more buffered data
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                let _ = warn_tx.send(format!("failed to read HCI event: {e}"));
                return false;
            }
        };

        // Parse any Ruuvi advertising report in this event; parse_event drops
        // everything that is not one (non-LE-Meta-Events, non-Ruuvi payloads,
        // unknown subevents).
        if let Some(result) = parse_event(&buf[..n], verbose)
            && (result.is_ok() || verbose)
            && tx.send(result).await.is_err()
        {
            return false; // consumer gone, stop scanning
        }
    }
}

/// Start scanning for RuuviTag devices using raw HCI sockets.
///
/// Opens event and command sockets, applies kernel filtering (see module
/// docs), and spawns the receive loop. Requires CAP_NET_RAW/CAP_NET_ADMIN or
/// root and an available HCI device.
///
/// `verbose` sends decode errors as `Err` values, otherwise they are dropped.
/// `adapter` selects the controller (`None` means `hci0`). `scan_exit`
/// selects whether `ScanSession::stop` disables the controller scan.
pub async fn start_scan(
    verbose: bool,
    adapter: Option<String>,
    scan_exit: ScanExitBehavior,
) -> Result<ScanSession, ScanError> {
    let dev_id = match adapter {
        Some(name) => resolve_adapter(&name)?,
        None => 0, // default to hci0, as before
    };

    // Open and configure HCI socket for receiving events
    let event_socket = HciSocket::open(dev_id)?;
    set_hci_filter(&event_socket)?;
    set_bpf_ruuvi_filter(&event_socket)?; // Kernel-level filtering for Ruuvi packets

    // We need a separate socket for sending commands (bound to specific device).
    // It needs a filter that lets Command Complete events through so we can read
    // back command results and detect Bluetooth 5 extended-advertising support.
    let cmd_socket = HciSocket::open(dev_id)?;
    set_command_hci_filter(&cmd_socket)?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);
    let (warn_tx, warn_rx) = mpsc::unbounded_channel::<String>();

    let mode = configure_le_scan(&cmd_socket)?;

    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();

    // Wrap in AsyncFd for async I/O
    let async_fd = AsyncFd::new(event_socket)
        .map_err(|e| ScanError::Bluetooth(format!("Failed to create async fd: {}", e)))?;

    // Spawn a task to read and process HCI events. The task owns the command
    // socket so it can disable the adapter's LE scan on shutdown (closing the
    // raw HCI socket alone does not stop scanning on Linux).
    let task = tokio::spawn(async move {
        let mut buf = [0u8; HCI_EVENT_BUF_SIZE]; // Max HCI event size

        'receive: loop {
            tokio::select! {
                // Graceful shutdown requested by the scan session.
                _ = task_cancel.cancelled() => break,
                // Wait for the socket to be readable
                result = async_fd.readable() => {
                    let mut guard = match result {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };

                    // Drain all available packets before waiting again.
                    if !drain_events(&mut guard, &mut buf, &tx, &warn_tx, verbose).await {
                        break 'receive;
                    }
                }
            }
        }

        // Failures are reported, not propagated: the scan is already over and
        // there is nothing left to abort.
        let report = match scan_exit {
            ScanExitBehavior::Always => disable_le_scan(&cmd_socket, mode)
                .err()
                .map(|e| format!("failed to finish the LE scan on hci{dev_id}: {e}")),
            ScanExitBehavior::Never => None,
        };
        if let Some(report) = report {
            let _ = warn_tx.send(report);
        }
    });

    Ok(ScanSession::managed(rx, warn_rx, cancel, task))
}

#[cfg(test)]
mod tests {
    use super::*;

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
