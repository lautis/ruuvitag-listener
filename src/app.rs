//! Core application runner (business logic) for `ruuvitag-listener`.
//!
//! This module is intentionally decoupled from CLI parsing and process exit codes
//! so it can be tested deterministically.

use crate::alias::{Alias, AliasMap};
use crate::measurement::Measurement;
use crate::output::OutputFormatter;
use crate::output::influxdb::InfluxDbFormatter;
use crate::scanner::{Backend, MeasurementResult, ScanError};
use crate::throttle::Throttle;
use clap::Parser;
use std::future::Future;
use std::io;
use std::io::Write;
use std::pin::Pin;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;

/// Configuration for the core run loop.
#[derive(Parser, Debug, Clone)]
#[command(author, about, version)]
pub struct Options {
    /// The name of the measurement in InfluxDB line protocol.
    #[arg(long, default_value = "ruuvi_measurement")]
    pub influxdb_measurement: String,

    /// Specify human-readable alias for RuuviTag id.
    /// Format: --alias DE:AD:BE:EF:00:00=Sauna
    #[arg(long = "alias", value_parser = crate::alias::parse_alias, value_name = "ALIAS")]
    pub aliases: Vec<Alias>,

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
        backend: Backend,
        verbose: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<mpsc::Receiver<MeasurementResult>, ScanError>> + Send + '_>,
    >;
}

/// Real scanner implementation that delegates to the compiled-in backends.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealScanner;

impl Scanner for RealScanner {
    fn start_scan(
        &self,
        backend: Backend,
        verbose: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<mpsc::Receiver<MeasurementResult>, ScanError>> + Send + '_>,
    > {
        Box::pin(async move { crate::scanner::start_scan(backend, verbose).await })
    }
}

fn write_measurement(
    formatter: &dyn OutputFormatter,
    measurement: &Measurement,
    name: &str,
    out: &mut dyn Write,
) -> io::Result<()> {
    let line = formatter.format(measurement, name);
    writeln!(out, "{line}")
}

/// Run the core processing loop, writing formatted output to `out` and verbose errors to `err`.
///
/// - On successful measurements, it optionally applies throttling, formats them, and writes a line to `out`.
/// - On decode errors, it writes the error to `err` only when `options.verbose` is true.
pub async fn run_with_io(
    options: Options,
    scanner: &dyn Scanner,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), RunError> {
    let aliases: AliasMap = crate::alias::to_map(&options.aliases);
    let formatter = InfluxDbFormatter::new(options.influxdb_measurement);

    // Create throttle if interval is specified
    let mut throttle = options.throttle.map(Throttle::new);

    let mut measurements = scanner.start_scan(options.backend, options.verbose).await?;

    while let Some(result) = measurements.recv().await {
        match result {
            Ok(measurement) => {
                let should_emit = throttle
                    .as_mut()
                    .is_none_or(|t: &mut Throttle| t.should_emit(measurement.mac));

                if should_emit {
                    let name = crate::alias::resolve_name(&measurement.mac, &aliases);
                    write_measurement(&formatter, &measurement, &name, out)?;
                }
            }
            Err(decode_err) => {
                if options.verbose {
                    writeln!(err, "{decode_err}")?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac_address::MacAddress;
    use crate::scanner::DecodeError;
    use std::sync::Mutex;
    use std::time::SystemTime;

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
        fn start_scan(
            &self,
            _backend: Backend,
            _verbose: bool,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<mpsc::Receiver<MeasurementResult>, ScanError>>
                    + Send
                    + '_,
            >,
        > {
            let results = self.results.lock().unwrap().clone();
            Box::pin(async move {
                let (tx, rx) = mpsc::channel::<MeasurementResult>(results.len().max(1));
                tokio::spawn(async move {
                    for r in results {
                        let _ = tx.send(r).await;
                    }
                    // drop tx to close channel
                });
                Ok(rx)
            })
        }
    }

    fn measurement(mac: MacAddress, timestamp: SystemTime) -> Measurement {
        Measurement {
            mac,
            timestamp,
            temperature: Some(25.5),
            humidity: Some(60.0),
            pressure: Some(101_325.0),
            battery: Some(3.0),
            tx_power: Some(4),
            movement_counter: Some(10),
            measurement_sequence: Some(100),
            acceleration: None,
            pm2_5: None,
            co2: None,
            voc_index: None,
            nox_index: None,
            luminosity: None,
        }
    }

    #[tokio::test]
    async fn run_writes_measurements_to_out() {
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let m = measurement(mac, timestamp);

        let scanner = FakeScanner::new(vec![Ok(m)]);
        let options = Options {
            influxdb_measurement: "ruuvi_measurement".to_string(),
            aliases: vec![],
            verbose: false,
            throttle: None,
            backend: Backend::Bluer,
        };

        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        run_with_io(options, &scanner, &mut out, &mut err)
            .await
            .unwrap();

        assert!(err.is_empty());

        let out = String::from_utf8(out).unwrap();
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
            influxdb_measurement: "ruuvi_measurement".to_string(),
            aliases: vec![],
            verbose: false,
            throttle: Some(Duration::from_secs(3600)),
            backend: Backend::Bluer,
        };

        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        run_with_io(options, &scanner, &mut out, &mut err)
            .await
            .unwrap();

        let out = String::from_utf8(out).unwrap();
        // only first should pass (no waiting in test, so second is within interval)
        assert_eq!(out.lines().count(), 1);
    }

    #[tokio::test]
    async fn run_prints_decode_errors_only_when_verbose() {
        let scanner = FakeScanner::new(vec![Err(DecodeError::InvalidData(
            "bad packet".to_string(),
        ))]);

        let base = Options {
            influxdb_measurement: "ruuvi_measurement".to_string(),
            aliases: vec![],
            verbose: false,
            throttle: None,
            backend: Backend::Bluer,
        };

        // non-verbose: nothing written
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        run_with_io(base.clone(), &scanner, &mut out, &mut err)
            .await
            .unwrap();
        assert!(out.is_empty());
        assert!(err.is_empty());

        // verbose: error is written to err
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        let mut verbose = base;
        verbose.verbose = true;
        run_with_io(verbose, &scanner, &mut out, &mut err)
            .await
            .unwrap();

        assert!(out.is_empty());
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("Invalid data: bad packet"));
    }
}
