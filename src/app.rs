//! Core application runner (business logic) for `ruuvitag-listener`.
//!
//! This module is intentionally decoupled from CLI parsing and process exit codes
//! so it can be tested deterministically.

use crate::alias::{Alias, AliasMap};
use crate::mac_address::MacAddress;
use crate::measurement::{Format, Measurement};
use crate::output::OutputFormatter;
use crate::output::csv::CsvFormatter;
use crate::output::influxdb::InfluxDbFormatter;
use crate::output::jsonl::JsonLinesFormatter;
use crate::scanner::{Backend, ScanConfig, ScanError, ScanExitBehavior, ScanSession};
use crate::throttle::Throttle;
use clap::{Parser, ValueEnum};
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::io::Write;
use std::time::Duration;
use thiserror::Error;

/// Output format for measurements.
#[derive(ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// InfluxDB line protocol (default).
    #[default]
    #[value(name = "influxdb")]
    InfluxDb,
    /// JSON Lines: one JSON object per line.
    Jsonl,
    /// CSV with a header row.
    Csv,
}

/// Configuration for the core run loop.
#[derive(Parser, Debug, Clone)]
#[command(author, about, version)]
pub struct Options {
    /// The name of the measurement in InfluxDB line protocol.
    #[arg(long, default_value = "ruuvi_measurement")]
    pub influxdb_measurement: String,

    /// Output format for measurements.
    #[arg(long, default_value = "influxdb", value_enum)]
    pub format: OutputFormat,

    /// Specify human-readable alias for RuuviTag id.
    /// Format: --alias DE:AD:BE:EF:00:00=Sauna
    #[arg(long = "alias", value_parser = crate::alias::parse_alias, value_name = "ALIAS")]
    pub aliases: Vec<Alias>,

    /// Only emit measurements from devices that have an alias defined.
    #[arg(long)]
    pub only_aliased: bool,

    /// Verbose output, print parse errors for unrecognized data
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Throttle events per tag to at most one per interval.
    /// Accepts duration with suffix: 3s, 1m, 500ms, 2h.
    /// Without suffix, value is interpreted as seconds.
    #[arg(long, value_parser = crate::throttle::parse_duration)]
    pub throttle: Option<Duration>,

    /// Bluetooth scanner backend to use
    #[arg(long, default_value_t, value_enum)]
    pub backend: Backend,

    /// Bluetooth adapter to use, e.g. hci0
    #[arg(long, value_name = "ADAPTER")]
    pub adapter: Option<String>,

    /// What the HCI backend does with the adapter's LE scan on exit
    #[arg(long, default_value_t, value_enum)]
    pub hci_scan_exit_behavior: ScanExitBehavior,
}

impl Default for Options {
    /// The configuration the CLI produces when no flag is given: one
    /// `Default` instead of a repeated field-by-field literal at every call
    /// site, in tests and in embedders.
    fn default() -> Self {
        Self {
            influxdb_measurement: "ruuvi_measurement".to_string(),
            format: OutputFormat::default(),
            aliases: Vec::new(),
            only_aliased: false,
            verbose: false,
            throttle: None,
            backend: Backend::default(),
            adapter: None,
            hci_scan_exit_behavior: ScanExitBehavior::default(),
        }
    }
}

/// Errors returned by the core run loop.
#[derive(Error, Debug)]
pub enum RunError {
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Scanner abstraction to enable deterministic unit tests without Bluetooth hardware.
pub trait Scanner: Send + Sync {
    fn start_scan(
        &self,
        config: ScanConfig,
    ) -> impl Future<Output = Result<ScanSession, ScanError>> + Send;
}

/// Real scanner implementation that delegates to the compiled-in backends.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealScanner;

impl Scanner for RealScanner {
    async fn start_scan(&self, config: ScanConfig) -> Result<ScanSession, ScanError> {
        crate::scanner::start_scan(config).await
    }
}

/// "E1 supersedes V6": once a device has emitted E1, drop its V6 frames.
///
/// Data format 6 exists only for Bluetooth 4 compatibility and is a strict
/// subset of E1. Once a device has produced an E1 advertisement, its V6 frames
/// carry no additional data, so they are dropped. E1 frames record the device
/// as an E1 emitter; V3 and V5 are unrelated lineages and are never suppressed.
///
/// The device set grows for the whole run and is never pruned. That is fine:
/// the set of RuuviTags in BLE range is finite and tiny, and unlike
/// [`Throttle`]'s interval-keyed timers there is no staleness to reclaim —
/// membership means "this device speaks E1", which never expires.
#[derive(Debug, Default)]
struct SupersedePolicy {
    /// Devices seen emitting E1.
    e1_devices: HashSet<MacAddress>,
}

impl SupersedePolicy {
    /// Returns `true` if the measurement should be dropped. E1 frames are
    /// recorded as a side effect, even when a later policy drops them.
    fn is_redundant(&mut self, measurement: &Measurement) -> bool {
        match measurement.format {
            Format::E1 => {
                self.e1_devices.insert(measurement.mac);
                false
            }
            Format::V6 => self.e1_devices.contains(&measurement.mac),
            Format::V5 | Format::V3 => false,
        }
    }
}

/// The per-measurement processing policies of the run loop, applied in order.
///
/// The run loop stays "recv → `handle` → write"; every policy state lives here
/// so each one is testable without a [`Scanner`] fake.
struct Pipeline {
    /// Drop V6 frames from devices that have emitted E1.
    supersede: SupersedePolicy,
    /// At most one emitted measurement per device per interval.
    throttle: Option<Throttle>,
    /// Device names; unknown devices fall back to their MAC string.
    aliases: AliasMap,
    /// Drop measurements from devices without an alias.
    only_aliased: bool,
    formatter: Box<dyn OutputFormatter>,
}

impl Pipeline {
    fn new(options: &Options, formatter: Box<dyn OutputFormatter>) -> Self {
        Self {
            supersede: SupersedePolicy::default(),
            throttle: options.throttle.map(Throttle::new),
            aliases: crate::alias::to_map(&options.aliases),
            only_aliased: options.only_aliased,
            formatter,
        }
    }

    /// Run one measurement through the policies and format it.
    ///
    /// Returns the ready-to-write line without its trailing newline, or `None`
    /// when a policy drops the measurement.
    ///
    /// Supersede must run before the throttle: an E1 the throttle drops still
    /// has to register the device, and a redundant V6 must not take a throttle
    /// slot. The only-aliased filter is order-independent, since the alias set
    /// is fixed for the run.
    fn handle(&mut self, measurement: Measurement) -> Option<String> {
        if self.supersede.is_redundant(&measurement) {
            return None;
        }
        let should_emit = self
            .throttle
            .as_mut()
            .is_none_or(|t| t.should_emit(measurement.mac));
        if !should_emit {
            return None;
        }
        if self.only_aliased && !crate::alias::has_alias(&measurement.mac, &self.aliases) {
            return None;
        }
        let name = crate::alias::resolve_name(&measurement.mac, &self.aliases);
        Some(self.formatter.format(&measurement, &name))
    }
}

fn report_warning(err: &mut dyn Write, warning: String) -> io::Result<()> {
    writeln!(err, "{warning}")
}

fn drain_shutdown_warnings(
    warnings: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    err: &mut dyn Write,
) -> io::Result<()> {
    while let Ok(warning) = warnings.try_recv() {
        report_warning(err, warning)?;
    }
    Ok(())
}

/// Run the core processing loop, writing formatted output to `out` and verbose errors to `err`.
///
/// - On successful measurements, it optionally applies throttling, formats them, and writes a line to `out`.
/// - On decode errors, it writes the error to `err` only when `options.verbose` is true.
/// - When `stop` resolves (e.g. SIGINT/SIGTERM in the binary), the loop ends
///   and the scan is stopped gracefully so the backend can do its configured
///   shutdown cleanup (the HCI backend disables the adapter's LE scan only
///   with [`ScanExitBehavior::Always`]) before the process exits.
pub async fn run_with_io(
    options: Options,
    scanner: &impl Scanner,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stop: impl Future<Output = ()> + Send,
) -> Result<(), RunError> {
    // Cloned rather than moved: `options` is still borrowed below (and its
    // remaining fields feed the ScanConfig).
    let formatter: Box<dyn OutputFormatter> = match options.format {
        OutputFormat::InfluxDb => {
            Box::new(InfluxDbFormatter::new(options.influxdb_measurement.clone()))
        }
        OutputFormat::Jsonl => Box::new(JsonLinesFormatter::new()),
        OutputFormat::Csv => Box::new(CsvFormatter::new()),
    };
    if let Some(header) = formatter.header() {
        writeln!(out, "{header}")?;
    }

    let mut pipeline = Pipeline::new(&options, formatter);

    let mut session = scanner
        .start_scan(ScanConfig {
            backend: options.backend,
            verbose: options.verbose,
            adapter: options.adapter,
            scan_exit: options.hci_scan_exit_behavior,
        })
        .await?;

    tokio::pin!(stop);

    // A closed warnings channel is always ready, so the branch has to be
    // disabled once it reports closure. Otherwise the loop spins on it for as
    // long as the scan runs, which is every run of a backend that has no
    // warnings to send.
    let mut warnings_open = true;

    loop {
        tokio::select! {
            result = session.measurements.recv() => match result {
                Some(result) => match result {
                    Ok(measurement) => {
                        if let Some(line) = pipeline.handle(measurement) {
                            writeln!(out, "{line}")?;
                        }
                    }
                    Err(decode_err) => {
                        if options.verbose {
                            writeln!(err, "{decode_err}")?;
                        }
                    }
                },
                // All senders dropped: the scan ended on its own.
                None => break,
            },
            warning = session.warnings.recv(), if warnings_open => match warning {
                Some(warning) => report_warning(err, warning)?,
                // The backend will send no more warnings, but the scan itself
                // may still be running, so keep looping on the other arms.
                None => warnings_open = false,
            },
            () = &mut stop => break,
        }
    }

    // Graceful shutdown: ask the backend to stop scanning and wait for it to
    // finish (the HCI backend disables the adapter's LE scan here — unless
    // --hci-scan-exit-behavior says to leave a scan running; the BlueZ backend
    // ends the discovery session).
    session.stop().await;

    // The loop stopped listening during shutdown, so surface warnings the
    // backend emitted while it was stopping (e.g. a failed LE scan disable).
    drain_shutdown_warnings(&mut session.warnings, err)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac_address::MacAddress;
    use crate::scanner::{DecodeError, MeasurementResult};
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[derive(Debug, Default)]
    struct ConfigCapturingScanner {
        seen: Mutex<Option<ScanConfig>>,
    }

    impl Scanner for ConfigCapturingScanner {
        async fn start_scan(&self, config: ScanConfig) -> Result<ScanSession, ScanError> {
            *self.seen.lock().unwrap() = Some(config);
            // No measurements, and the sender is dropped straight away so
            // the run loop ends on its own.
            let (tx, rx) = mpsc::channel::<MeasurementResult>(1);
            drop(tx);
            Ok(ScanSession::unmanaged(rx))
        }
    }

    #[derive(Debug)]
    struct FakeScanner {
        results: Mutex<Vec<MeasurementResult>>,
    }

    impl FakeScanner {
        fn new(results: Vec<MeasurementResult>) -> Self {
            Self {
                results: Mutex::new(results),
            }
        }
    }

    impl Scanner for FakeScanner {
        async fn start_scan(&self, _config: ScanConfig) -> Result<ScanSession, ScanError> {
            let results = self.results.lock().unwrap().clone();
            let (tx, rx) = mpsc::channel::<MeasurementResult>(results.len().max(1));
            tokio::spawn(async move {
                for r in results {
                    let _ = tx.send(r).await;
                }
                // drop tx to close channel
            });
            Ok(ScanSession::unmanaged(rx))
        }
    }

    fn measurement(mac: MacAddress, timestamp: SystemTime) -> Measurement {
        measurement_with_format(mac, timestamp, Format::V5)
    }

    fn measurement_with_format(
        mac: MacAddress,
        timestamp: SystemTime,
        format: Format,
    ) -> Measurement {
        Measurement {
            mac,
            format,
            timestamp,
            temperature: Some(25.5),
            humidity: Some(60.0),
            pressure: Some(101_325.0),
            battery: Some(3.0),
            tx_power: Some(4),
            rssi: None,
            movement_counter: Some(10),
            measurement_sequence: Some(100),
            acceleration: None,
            pm1_0: None,
            pm2_5: None,
            pm4_0: None,
            pm10_0: None,
            co2: None,
            voc_index: None,
            nox_index: None,
            luminosity: None,
        }
    }

    async fn run_test(
        options: Options,
        scanner: &impl Scanner,
        stop: impl Future<Output = ()> + Send,
    ) -> (String, String) {
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        run_with_io(options, scanner, &mut out, &mut err, stop)
            .await
            .unwrap();
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn default_options_match_the_no_flag_command_line() {
        // Tests and embedders build `Options::default()` instead of spelling
        // out every field; that is only honest while it equals what the CLI
        // produces with no flags. A new `#[arg(default_value...)]` must show
        // up here.
        let parsed = Options::try_parse_from(["ruuvitag-listener"]).expect("no flags is valid");
        let default = Options::default();
        assert_eq!(parsed.influxdb_measurement, default.influxdb_measurement);
        assert_eq!(parsed.format, default.format);
        assert_eq!(parsed.aliases.len(), default.aliases.len());
        assert_eq!(parsed.only_aliased, default.only_aliased);
        assert_eq!(parsed.verbose, default.verbose);
        assert_eq!(parsed.throttle, default.throttle);
        assert_eq!(parsed.backend, default.backend);
        assert_eq!(parsed.adapter, default.adapter);
        assert_eq!(
            parsed.hci_scan_exit_behavior,
            default.hci_scan_exit_behavior
        );
    }

    #[test]
    fn hci_scan_exit_behavior_flag_name_is_stable() {
        // The flag name is derived from the field name, so renaming the field
        // would silently rename a user-facing option. Pin it here.
        let parse = |args: &[&str]| {
            Options::try_parse_from(args)
                .expect("valid arguments")
                .hci_scan_exit_behavior
        };

        assert_eq!(parse(&["ruuvitag-listener"]), ScanExitBehavior::Never);
        for (flag, expected) in [
            ("always", ScanExitBehavior::Always),
            ("never", ScanExitBehavior::Never),
        ] {
            assert_eq!(
                parse(&["ruuvitag-listener", "--hci-scan-exit-behavior", flag]),
                expected,
                "--hci-scan-exit-behavior {flag}"
            );
        }

        assert!(
            Options::try_parse_from(["ruuvitag-listener", "--hci-scan-exit-behavior", "sometimes"])
                .is_err(),
            "unknown values are rejected"
        );
    }

    #[tokio::test]
    // Names a specific Backend variant, so it only builds where that variant does.
    #[cfg(feature = "hci")]
    async fn run_passes_options_to_the_scanner() {
        // The options below only mean something if run_with_io hands them to
        // the scanner; the other Scanner fakes ignore their ScanConfig, so
        // without this the whole wiring could be dropped and stay green.
        let options = Options {
            verbose: true,
            backend: Backend::Hci,
            adapter: Some("hci1".to_string()),
            hci_scan_exit_behavior: ScanExitBehavior::Never,
            ..Default::default()
        };

        let scanner = ConfigCapturingScanner::default();
        run_test(options, &scanner, std::future::ready(())).await;

        let seen = scanner.seen.lock().unwrap().clone();
        let seen = seen.expect("the scanner was started");
        assert_eq!(seen.backend, Backend::Hci);
        assert!(seen.verbose);
        assert_eq!(seen.adapter.as_deref(), Some("hci1"));
        assert_eq!(seen.scan_exit, ScanExitBehavior::Never);
    }

    #[tokio::test]
    async fn run_ends_cleanly_when_stop_resolves() {
        // A scanner that never closes the channel: the run loop can only end
        // via the stop signal.
        let scanner = NoWarningScanner {
            hold: Mutex::new(None),
        };
        // A stop signal that is already resolved: the loop must break
        // immediately and `run_with_io` must return cleanly.
        let (out, err) = run_test(Options::default(), &scanner, std::future::ready(())).await;

        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn run_writes_measurements_to_out() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let m = measurement(mac, timestamp);

        let scanner = FakeScanner::new(vec![Ok(m)]);

        let (out, err) = run_test(Options::default(), &scanner, std::future::pending()).await;

        assert!(err.is_empty());

        assert!(out.contains("ruuvi_measurement,"));
        assert!(out.contains("mac=AA:BB:CC:DD:EE:FF"));
        assert!(out.contains("temperature=25.5"));
        assert!(out.ends_with('\n'));
    }

    #[tokio::test]
    async fn run_applies_throttle() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let m1 = measurement(mac, timestamp);
        let m2 = measurement(mac, timestamp);

        let scanner = FakeScanner::new(vec![Ok(m1), Ok(m2)]);
        let options = Options {
            throttle: Some(Duration::from_secs(3600)),
            ..Default::default()
        };

        let (out, _) = run_test(options, &scanner, std::future::pending()).await;

        // only first should pass (no waiting in test, so second is within interval)
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn supersede_policy_drops_v6_only_after_e1_seen_for_same_device() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let other = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let ts = SystemTime::UNIX_EPOCH;
        let mut supersede = SupersedePolicy::default();

        // V6 before any E1 is kept.
        assert!(!supersede.is_redundant(&measurement_with_format(mac, ts, Format::V6)));

        // E1 is always kept and registers the device.
        assert!(!supersede.is_redundant(&measurement_with_format(mac, ts, Format::E1)));

        // V6 from that device is now redundant.
        assert!(supersede.is_redundant(&measurement_with_format(mac, ts, Format::V6)));

        // V6 from a different device is unaffected.
        assert!(!supersede.is_redundant(&measurement_with_format(other, ts, Format::V6)));

        // V5 is never suppressed.
        assert!(!supersede.is_redundant(&measurement_with_format(mac, ts, Format::V5)));

        // V3 is never suppressed either.
        assert!(!supersede.is_redundant(&measurement_with_format(mac, ts, Format::V3)));
    }

    /// A pipeline with JSONL output: exact lines are easy to assert on.
    fn jsonl_pipeline(options: &Options) -> Pipeline {
        Pipeline::new(options, Box::new(JsonLinesFormatter::new()))
    }

    #[test]
    fn pipeline_resolves_the_alias_name_or_falls_back_to_the_mac() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let other = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let options = Options {
            aliases: vec![Alias {
                address: mac,
                name: "Sauna".to_string(),
            }],
            ..Default::default()
        };
        let mut pipeline = jsonl_pipeline(&options);

        let line = pipeline
            .handle(measurement(mac, ts))
            .expect("aliased measurement is emitted");
        assert!(line.contains("\"name\":\"Sauna\""), "{line}");

        let line = pipeline
            .handle(measurement(other, ts))
            .expect("unaliased measurement is emitted without --only-aliased");
        assert!(line.contains("\"name\":\"11:22:33:44:55:66\""), "{line}");
    }

    #[test]
    fn pipeline_only_aliased_drops_unaliased_devices() {
        let aliased = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let unaliased = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let options = Options {
            aliases: vec![Alias {
                address: aliased,
                name: "Sauna".to_string(),
            }],
            only_aliased: true,
            ..Default::default()
        };
        let mut pipeline = jsonl_pipeline(&options);

        assert!(pipeline.handle(measurement(aliased, ts)).is_some());
        assert!(pipeline.handle(measurement(unaliased, ts)).is_none());
    }

    #[test]
    fn pipeline_throttle_allows_the_first_measurement_per_device() {
        let a = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let b = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let options = Options {
            throttle: Some(Duration::from_secs(3600)),
            ..Default::default()
        };
        let mut pipeline = jsonl_pipeline(&options);

        // First event per device passes, the repeat inside the interval does
        // not, and the other device has its own slot.
        assert!(pipeline.handle(measurement(a, ts)).is_some());
        assert!(pipeline.handle(measurement(a, ts)).is_none());
        assert!(pipeline.handle(measurement(b, ts)).is_some());
    }

    /// Push one measurement of the given format through a pipeline.
    fn push(pipeline: &mut Pipeline, mac: MacAddress, format: Format) -> Option<String> {
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        pipeline.handle(measurement_with_format(mac, ts, format))
    }

    #[test]
    fn pipeline_drops_v6_superseded_by_e1_and_keeps_the_other_formats() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut pipeline = jsonl_pipeline(&Options::default());

        assert!(push(&mut pipeline, mac, Format::V6).is_some());
        assert!(push(&mut pipeline, mac, Format::E1).is_some());
        assert!(push(&mut pipeline, mac, Format::V6).is_none());
        assert!(push(&mut pipeline, mac, Format::V5).is_some());
        assert!(push(&mut pipeline, mac, Format::V3).is_some());
    }

    #[test]
    fn throttled_e1_still_registers_the_device_for_supersede() {
        // The supersede pass runs before the throttle, so an E1 the throttle
        // drops still marks the device as an E1 emitter. If registration
        // happened only for frames that get emitted, the final V6 would come
        // back to life once the throttle interval had passed.
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let options = Options {
            throttle: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        let mut pipeline = jsonl_pipeline(&options);

        // The V6 takes the device's throttle slot.
        assert!(push(&mut pipeline, mac, Format::V6).is_some());
        // The E1 lands inside the interval: dropped, but it registers.
        assert!(push(&mut pipeline, mac, Format::E1).is_none());
        std::thread::sleep(Duration::from_millis(250));
        // Past the interval the throttle would let a V6 through; only the
        // registration from the dropped E1 keeps it out.
        assert!(push(&mut pipeline, mac, Format::V6).is_none());
    }

    #[test]
    fn superseded_v6_does_not_take_a_throttle_slot() {
        // The other half of the ordering: a redundant V6 is dropped before the
        // throttle sees it, so it cannot refresh the device's timer. If it
        // did, the follow-up E1 would land inside the refreshed interval and
        // be dropped.
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let options = Options {
            throttle: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        let mut pipeline = jsonl_pipeline(&options);

        assert!(push(&mut pipeline, mac, Format::E1).is_some());
        std::thread::sleep(Duration::from_millis(250));
        assert!(push(&mut pipeline, mac, Format::V6).is_none());
        // Immediately after the dropped V6: the timer still dates from the
        // E1, so the interval has long passed.
        assert!(push(&mut pipeline, mac, Format::E1).is_some());
    }

    #[tokio::test]
    async fn run_drops_v6_after_e1_from_same_device() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1);

        // Order: V6 (kept), E1 (kept), V6 (dropped).
        let scanner = FakeScanner::new(vec![
            Ok(measurement_with_format(mac, ts, Format::V6)),
            Ok(measurement_with_format(mac, ts, Format::E1)),
            Ok(measurement_with_format(mac, ts, Format::V6)),
        ]);

        let (out, _) = run_test(Options::default(), &scanner, std::future::pending()).await;

        assert_eq!(out.lines().count(), 2);
    }

    #[tokio::test]
    async fn run_only_aliased_emits_only_devices_with_alias() {
        let aliased = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let unaliased = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1);

        let scanner = FakeScanner::new(vec![
            Ok(measurement(aliased, ts)),
            Ok(measurement(unaliased, ts)),
        ]);
        let options = Options {
            aliases: vec![Alias {
                address: aliased,
                name: "Sauna".to_string(),
            }],
            only_aliased: true,
            ..Default::default()
        };

        let (out, _) = run_test(options, &scanner, std::future::pending()).await;

        assert!(out.contains("name=Sauna"));
        assert!(!out.contains("11:22:33:44:55:66"));
        assert_eq!(out.lines().count(), 1);
    }

    #[tokio::test]
    async fn run_prints_decode_errors_only_when_verbose() {
        let scanner = FakeScanner::new(vec![Err(DecodeError::InvalidData(
            "bad packet".to_string(),
        ))]);

        let base = Options::default();

        // non-verbose: nothing written
        let (out, err) = run_test(base.clone(), &scanner, std::future::pending()).await;
        assert!(out.is_empty());
        assert!(err.is_empty());

        // verbose: error is written to err
        let mut verbose = base;
        verbose.verbose = true;
        let (out, err) = run_test(verbose, &scanner, std::future::pending()).await;

        assert!(out.is_empty());
        assert!(err.contains("Invalid data: bad packet"));
    }

    #[tokio::test]
    async fn run_csv_writes_header_then_rows() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let m = measurement(mac, timestamp);

        let scanner = FakeScanner::new(vec![Ok(m)]);
        let options = Options {
            format: OutputFormat::Csv,
            ..Default::default()
        };

        let (out, _) = run_test(options, &scanner, std::future::pending()).await;

        let mut lines = out.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("mac,name,timestamp,format,"));
        let row = lines.next().unwrap();
        assert!(row.starts_with("AA:BB:CC:DD:EE:FF,AA:BB:CC:DD:EE:FF,"));
        assert_eq!(lines.count(), 0);
    }

    #[tokio::test]
    async fn run_jsonl_writes_json_objects() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let m = measurement(mac, timestamp);

        let scanner = FakeScanner::new(vec![Ok(m)]);
        let options = Options {
            format: OutputFormat::Jsonl,
            ..Default::default()
        };

        let (out, _) = run_test(options, &scanner, std::future::pending()).await;

        let line = out.trim_end();
        assert!(line.starts_with("{\"mac\":\"AA:BB:CC:DD:EE:FF\""));
        assert!(line.contains("\"format\":\"v5\""));
        assert!(line.contains("\"temperature\":25.5"));
        assert!(line.ends_with('}'));
    }

    /// A backend that reports `warning` either at startup or while shutting
    /// down, selected by `on_stop`.
    ///
    /// Mirrors a real backend: the measurement channel stays open for the whole
    /// session, so the run loop has something live to wait on.
    struct WarningScanner {
        warning: &'static str,
        on_stop: bool,
    }

    impl Scanner for WarningScanner {
        async fn start_scan(&self, _config: ScanConfig) -> Result<ScanSession, ScanError> {
            let (tx, rx) = mpsc::channel::<MeasurementResult>(1);
            let (warn_tx, warn_rx) = mpsc::unbounded_channel::<String>();
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let warning = self.warning;
            let on_stop = self.on_stop;
            let task = tokio::spawn(async move {
                if !on_stop {
                    let _ = warn_tx.send(warning.to_string());
                    task_cancel.cancelled().await;
                } else {
                    // Reported only while shutting down, i.e. after the run
                    // loop has stopped listening for warnings.
                    task_cancel.cancelled().await;
                    let _ = warn_tx.send(warning.to_string());
                }
                drop(tx);
            });
            Ok(ScanSession::managed(rx, warn_rx, cancel, task))
        }
    }

    #[tokio::test]
    async fn backend_warning_reaches_the_error_writer() {
        let scanner = WarningScanner {
            warning: "example backend warning: timed out",
            on_stop: false,
        };
        let options = Options {
            format: OutputFormat::Jsonl,
            ..Default::default()
        };

        let (_, err) = run_test(
            options,
            &scanner,
            tokio::time::sleep(Duration::from_millis(50)),
        )
        .await;

        assert!(
            err.contains("example backend warning: timed out"),
            "warning missing from err: {err:?}"
        );
    }

    #[tokio::test]
    async fn warning_reported_during_shutdown_is_still_surfaced() {
        // `stop` resolves straight away, so the run loop leaves before the
        // backend task gets a chance to report anything. Only the drain after
        // `session.stop()` can catch this warning.
        let scanner = WarningScanner {
            warning: "failed to finish the LE scan on hci0: command failed",
            on_stop: true,
        };
        let options = Options {
            format: OutputFormat::Jsonl,
            ..Default::default()
        };

        let (_, err) = run_test(options, &scanner, std::future::ready(())).await;

        assert!(
            err.contains("failed to finish the LE scan on hci0: command failed"),
            "shutdown warning missing from err: {err:?}"
        );
    }

    /// A backend with no warnings to report closes the channel at startup,
    /// which is what the BlueZ backend does.
    struct NoWarningScanner {
        hold: Mutex<Option<mpsc::Sender<MeasurementResult>>>,
    }

    impl Scanner for NoWarningScanner {
        async fn start_scan(&self, _config: ScanConfig) -> Result<ScanSession, ScanError> {
            let (tx, rx) = mpsc::channel::<MeasurementResult>(1);
            // Keep the scan alive for the whole test; `unmanaged` drops the
            // warnings sender, so its channel is closed from the start.
            *self.hold.lock().unwrap() = Some(tx);
            Ok(ScanSession::unmanaged(rx))
        }
    }

    /// CPU time burned by this process so far.
    ///
    /// Gated on the `hci` feature because that is what pulls in `libc`; the
    /// test itself is about `run_with_io` and needs no Bluetooth support.
    #[cfg(feature = "hci")]
    fn cpu_time() -> Duration {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }

    /// A closed warnings channel is permanently ready, so an unguarded
    /// `select!` arm would spin on it and burn a core for the whole scan. This
    /// is the shape every backend with nothing to warn about produces.
    #[cfg(feature = "hci")]
    #[tokio::test]
    async fn closed_warnings_channel_does_not_spin() {
        let scanner = NoWarningScanner {
            hold: Mutex::new(None),
        };
        let window = Duration::from_millis(200);
        let options = Options {
            format: OutputFormat::Jsonl,
            ..Default::default()
        };

        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        let cpu_before = cpu_time();
        let wall = tokio::time::Instant::now();
        run_with_io(
            options,
            &scanner,
            &mut out,
            &mut err,
            tokio::time::sleep(window),
        )
        .await
        .unwrap();
        let burned = cpu_time() - cpu_before;
        let elapsed = wall.elapsed();

        // An idling loop costs microseconds; a spinning one costs roughly the
        // whole window. Half the window separates the two with room to spare on
        // a loaded machine.
        assert!(
            burned * 2 < elapsed,
            "run loop burned {burned:?} of CPU in {elapsed:?} with a closed warnings channel"
        );
    }
}
