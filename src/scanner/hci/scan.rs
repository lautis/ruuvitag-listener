//! HCI scanner entry point: adapter resolution, `start_scan`, and the
//! event read loop.

use super::bpf::set_bpf_ruuvi_filter;
use super::ffi::{HciSocket, configure_le_scan, disable_le_scan, read_packet};
use super::parse::{might_be_ruuvi, parse_advertising_report, parse_extended_advertising_report};
use super::*;
use crate::scanner::{MEASUREMENT_CHANNEL_BUFFER_SIZE, ScanError, ScanSession};
use std::io;
use std::path::Path;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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
    let event_socket = HciSocket::open(dev_id)?;
    event_socket.set_event_filter()?;
    set_bpf_ruuvi_filter(&event_socket)?; // Kernel-level filtering for Ruuvi packets

    // We need a separate socket for sending commands (bound to specific device).
    // It needs a filter that lets Command Complete events through so we can read
    // back command results and detect Bluetooth 5 extended-advertising support.
    let cmd_socket = HciSocket::open(dev_id)?;
    cmd_socket.set_command_filter()?;
    configure_le_scan(&cmd_socket)?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();

    // Wrap in AsyncFd for async I/O
    let async_fd = AsyncFd::new(event_socket)
        .map_err(|e| ScanError::Bluetooth(format!("Failed to create async fd: {}", e)))?;

    // Spawn a task to read and process HCI events. The task owns the command
    // socket so it can disable the adapter's LE scan on shutdown — closing the
    // raw HCI socket alone does not stop scanning on Linux.
    let task = tokio::spawn(async move {
        let mut buf = [0u8; HCI_EVENT_BUF_SIZE]; // Max HCI event size

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
                        let n = match guard.try_io(|inner| read_packet(inner, &mut buf)) {
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
        if let Err(e) = disable_le_scan(&cmd_socket) {
            eprintln!("failed to disable LE scan: {e}");
        }
    });

    Ok(ScanSession::managed(rx, cancel, task))
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
