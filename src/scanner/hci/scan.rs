//! HCI scanner entry point: adapter resolution, `start_scan`, and the
//! event read loop.

use super::bpf::set_bpf_ruuvi_filter;
use super::ffi::{
    HciSocket, ScanStateOutcome, configure_le_scan, disable_le_scan, le_scan_state, read_packet,
    restore_le_scan_duplicates,
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
/// The sysfs listing only fills in a helpful error when the name is wrong;
/// when sysfs is unavailable the parsed id is used as-is.
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
/// Returns `false` when the receive loop should end for good: a read error, or
/// a consumer that has gone away. An empty read only means nothing is buffered
/// right now.
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

/// What this process does with the adapter's LE scan when the session ends.
///
/// Settles [`ScanExitBehavior`] against the controller state the backend
/// already had to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanShutdown {
    /// Send `LE Set Scan Enable (disable)` so the adapter stops scanning.
    Stop,
    /// Leave the adapter scanning, first putting back a `Filter_Duplicates`
    /// policy when the scan we attached to had one; see
    /// [`restore_le_scan_duplicates`].
    LeaveRunning {
        /// The policy to put back, or `None` to send nothing and leave the
        /// controller's setting alone.
        filter_duplicates: Option<bool>,
    },
}

/// Fold a non-fatal warning into the fatal error that pre-empted it.
///
/// Setup warnings go to the session's warnings channel, but a failure during
/// setup means there is no session to carry them.
fn with_warning(error: ScanError, warning: Option<String>) -> ScanError {
    let Some(warning) = warning else {
        return error;
    };
    match error {
        // Splice into the existing message rather than nesting, so the
        // `Bluetooth error:` prefix is not repeated.
        ScanError::Bluetooth(message) => ScanError::Bluetooth(format!("{warning}; {message}")),
        other => ScanError::Bluetooth(format!("{warning}; {other}")),
    }
}

impl ScanExitBehavior {
    /// Settle what shutdown does with the scan, and what the user is told at
    /// startup, from what the controller reported about the start state.
    ///
    /// Must run before this process configures its own scan: attaching to a
    /// pre-existing scan replaces its parameters. The scan at exit is ours to
    /// stop when the controller reported none running. A state that could not be
    /// read leaves ownership undecidable, so the scan is left running — only
    /// `always` stops it then, as it does anyway.
    ///
    /// Warnings state the outcome, not the cause: only `owned-only` turns on the
    /// state, so only it warns about not reading it. A failed query points at a
    /// controller or driver problem and is reported under every behavior.
    fn shutdown_plan(self, outcome: &ScanStateOutcome) -> (ScanShutdown, Option<String>) {
        // A scan to leave running, with the duplicate policy to put back
        // first, or `None` to leave the controller's setting alone.
        let leave =
            |filter_duplicates: Option<bool>| ScanShutdown::LeaveRunning { filter_duplicates };

        match (self, outcome) {
            // `always` stops the scan whoever started it, so what the
            // controller reported changes nothing.
            (Self::Always, ScanStateOutcome::Known(_) | ScanStateOutcome::Unreported) => {
                (ScanShutdown::Stop, None)
            }
            (Self::Always, ScanStateOutcome::Failed(e)) => (
                ScanShutdown::Stop,
                Some(format!("failed to query LE scan state: {e}")),
            ),

            // Nobody was scanning, so the scan at exit is ours to stop.
            (Self::OwnedOnly, ScanStateOutcome::Known(state)) if !state.enabled => {
                (ScanShutdown::Stop, None)
            }
            // A foreign scan, left to its owner with its policy put back. Only
            // one that was filtering duplicates has a policy, and an idle
            // controller can report a stale one — the two fields are read
            // independently — hence the `enabled`.
            (Self::OwnedOnly | Self::Never, ScanStateOutcome::Known(state)) => (
                leave((state.enabled && state.filter_duplicates).then_some(true)),
                None,
            ),

            // Unreadable: the scan may belong to another process, so it is left
            // running. `owned-only` says so; `never` has nothing to add.
            (Self::OwnedOnly, ScanStateOutcome::Unreported) => (
                leave(None),
                Some(
                    "could not determine whether the adapter was already scanning; \
                     leaving the scan running on exit"
                        .to_string(),
                ),
            ),
            (Self::Never, ScanStateOutcome::Unreported) => (leave(None), None),
            (Self::OwnedOnly, ScanStateOutcome::Failed(e)) => (
                leave(None),
                Some(format!(
                    "failed to query LE scan state: {e}; \
                     leaving the scan running on exit"
                )),
            ),
            (Self::Never, ScanStateOutcome::Failed(e)) => (
                leave(None),
                Some(format!("failed to query LE scan state: {e}")),
            ),
        }
    }
}

/// Start scanning for RuuviTag devices using raw HCI sockets, and keep
/// scanning until the returned session is stopped.
///
/// The event socket is filtered in the kernel twice over — HCI_FILTER keeps it
/// to LE Meta Events, a BPF program to Ruuvi advertisements — so userspace
/// wakes only for RuuviTag broadcasts.
///
/// # Returns
/// A scan session whose `measurements` receiver yields measurements (or decode
/// errors if verbose). Stopping it (`ScanSession::stop`) disables the adapter's
/// scan when [`ScanExitBehavior::OwnedOnly`] and the controller reported no
/// scan running, or unconditionally when the behavior is
/// [`ScanExitBehavior::Always`]. A scan left to its original owner keeps
/// running, and so does one whose start state could not be read: every
/// behavior but `always` leaves it alone.
///
/// # Requirements
/// - CAP_NET_RAW and CAP_NET_ADMIN capabilities or root privileges
/// - An available HCI device (typically hci0)
pub async fn start_scan(
    verbose: bool,
    adapter: Option<String>,
    scan_exit: ScanExitBehavior,
) -> Result<ScanSession, ScanError> {
    let dev_id = match adapter {
        Some(name) => resolve_adapter(&name)?,
        None => 0, // default to hci0, as before
    };

    let event_socket = HciSocket::open(dev_id)?;
    event_socket.set_event_filter()?;
    set_bpf_ruuvi_filter(&event_socket)?;

    // A second socket for the commands: the event socket's filter would drop
    // their replies.
    let cmd_socket = HciSocket::open(dev_id)?;
    cmd_socket.set_command_filter()?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);
    let (warn_tx, warn_rx) = mpsc::unbounded_channel::<String>();

    // The warning is held back until the scan is configured: if that fails
    // there is no session to carry it, so it rides along on the error instead.
    let outcome = le_scan_state(&cmd_socket);
    let (shutdown, state_warning) = scan_exit.shutdown_plan(&outcome);
    let mode = match configure_le_scan(&cmd_socket) {
        Ok(mode) => mode,
        Err(e) => return Err(with_warning(e, state_warning)),
    };
    if let Some(warning) = state_warning {
        let _ = warn_tx.send(warning);
    }

    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();

    let async_fd = AsyncFd::new(event_socket)
        .map_err(|e| ScanError::Bluetooth(format!("Failed to create async fd: {}", e)))?;

    // The task owns the command socket: closing the raw socket does not stop
    // scanning on Linux, so the disable has to be sent.
    let task = tokio::spawn(async move {
        let mut buf = [0u8; HCI_EVENT_BUF_SIZE];

        'receive: loop {
            tokio::select! {
                _ = task_cancel.cancelled() => break,
                result = async_fd.readable() => {
                    let mut guard = match result {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };

                    if !drain_events(&mut guard, &mut buf, &tx, &warn_tx, verbose).await {
                        break 'receive;
                    }
                }
            }
        }

        // Put the controller back as we found it. Failures are reported, not
        // propagated: the scan is already over and there is nothing to abort.
        let finished = match shutdown {
            ScanShutdown::Stop => disable_le_scan(&cmd_socket, mode).map(|()| None),
            // Already the policy we want to leave: our own scan, or a foreign
            // one that matched ours.
            ScanShutdown::LeaveRunning {
                filter_duplicates: None,
            } => Ok(None),
            ScanShutdown::LeaveRunning {
                filter_duplicates: Some(policy),
            } => restore_le_scan_duplicates(&cmd_socket, mode, policy),
        };
        let report = match finished {
            Ok(Some(warning)) => Some(warning),
            Ok(None) => None,
            Err(e) => Some(format!("failed to finish the LE scan on hci{dev_id}: {e}")),
        };
        if let Some(report) = report {
            let _ = warn_tx.send(report);
        }
    });

    Ok(ScanSession::managed(rx, warn_rx, cancel, task))
}

#[cfg(test)]
mod tests {
    use super::super::ffi::ScanState;
    use super::*;

    /// The warning for a start state the controller cannot report. Pinned in
    /// full because the README's troubleshooting entry quotes it.
    const UNREADABLE_WARNING: &str = "could not determine whether the adapter was already scanning; \
                                     leaving the scan running on exit";

    /// A prior scan state: off, scanning, or scanning with duplicate
    /// filtering on.
    fn prior(enabled: bool, filter_duplicates: bool) -> ScanState {
        ScanState {
            enabled,
            filter_duplicates,
        }
    }

    /// The `Some(policy)` to restore before leaving the scan running.
    fn leave(filter_duplicates: Option<bool>) -> ScanShutdown {
        ScanShutdown::LeaveRunning { filter_duplicates }
    }

    /// The whole behavior x scan-state matrix in one table: what shutdown does
    /// with the scan, and what the user is told at startup about it.
    #[test]
    fn test_shutdown_plan_matrix() {
        // Columns: idle, idle with a stale policy, foreign without dedup,
        // foreign with dedup. `scan_state` reads the two fields independently,
        // so a controller can report a policy while reporting the scan off.
        let states = [
            prior(false, false),
            prior(false, true),
            prior(true, false),
            prior(true, true),
        ];
        let reported = [
            (
                ScanExitBehavior::OwnedOnly,
                [
                    ScanShutdown::Stop,
                    ScanShutdown::Stop,
                    leave(None),
                    leave(Some(true)),
                ],
            ),
            (
                ScanExitBehavior::Never,
                [leave(None), leave(None), leave(None), leave(Some(true))],
            ),
            // `always` stops the scan whoever started it.
            (ScanExitBehavior::Always, [ScanShutdown::Stop; 4]),
        ];
        for (behavior, expected) in reported {
            for (state, expected) in states.into_iter().zip(expected) {
                let (action, warning) = behavior.shutdown_plan(&ScanStateOutcome::Known(state));
                assert_eq!(action, expected, "{behavior:?} with a reported {state:?}");
                assert_eq!(warning, None, "{behavior:?} with a reported {state:?}");
            }
        }

        // A start state that could not be read is no one's to stop on the
        // evidence available: the scan is left running whoever may own it, and
        // only `always` stops it.
        let failed = || ScanStateOutcome::Failed(ScanError::Bluetooth("timed out".into()));
        let cases = [
            (
                ScanExitBehavior::OwnedOnly,
                ScanStateOutcome::Unreported,
                leave(None),
            ),
            (
                ScanExitBehavior::Never,
                ScanStateOutcome::Unreported,
                leave(None),
            ),
            (
                ScanExitBehavior::Always,
                ScanStateOutcome::Unreported,
                ScanShutdown::Stop,
            ),
            (ScanExitBehavior::OwnedOnly, failed(), leave(None)),
            (ScanExitBehavior::Never, failed(), leave(None)),
            (ScanExitBehavior::Always, failed(), ScanShutdown::Stop),
        ];
        for (behavior, outcome, expected) in cases {
            let (action, warning) = behavior.shutdown_plan(&outcome);
            let cell = format!("{behavior:?} with {outcome:?}");
            assert_eq!(action, expected, "{cell}");

            // A warning is owed when `owned-only` exit depends on the state,
            // and for a failed query under any behavior — a controller or
            // driver problem.
            let failure = matches!(outcome, ScanStateOutcome::Failed(_));
            let owned_only = behavior == ScanExitBehavior::OwnedOnly;
            assert_eq!(warning.is_some(), failure || owned_only, "{cell}");

            if failure {
                let text = warning.as_deref().unwrap_or_default();
                assert!(text.contains("failed to query LE scan state"), "{cell}");
                assert!(text.contains("timed out"), "{cell} omits the error");
            } else if owned_only {
                // Pinned verbatim: the README quotes this message.
                assert_eq!(warning.as_deref(), Some(UNREADABLE_WARNING), "{cell}");
            }

            // The outcome is spelled out where leaving the scan running is
            // `owned-only`'s doing; the others leave it be anyway.
            let text = warning.as_deref().unwrap_or_default();
            assert_eq!(
                text.contains("leaving the scan running on exit"),
                owned_only,
                "{cell}"
            );
        }
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

    #[test]
    fn test_with_warning_keeps_both_messages_without_repeating_the_prefix() {
        let error = || ScanError::Bluetooth("HCI command 0x200c failed".to_string());

        // The warning rides along in front of the error it explains. `ScanError`
        // renders its own prefix, so nesting the error in the message instead
        // of splicing would double it.
        let rendered =
            with_warning(error(), Some("failed to query LE scan state".to_string())).to_string();
        assert_eq!(
            rendered,
            "Bluetooth error: failed to query LE scan state; HCI command 0x200c failed"
        );
        assert_eq!(rendered.matches("Bluetooth error:").count(), 1);

        // No warning leaves the error exactly as it was.
        assert_eq!(with_warning(error(), None).to_string(), error().to_string());
    }
}
