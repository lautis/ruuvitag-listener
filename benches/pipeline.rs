//! Integration benchmark for the RuuviTag processing pipeline.
//!
//! Benchmarks the full application loop using the same patterns as the
//! integration tests in app.rs - with a FakeScanner feeding measurements
//! through run_with_io.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ruuvitag_listener::app::{Options, Scanner, run_with_io};
use ruuvitag_listener::{Backend, MacAddress, MeasurementResult, ScanError, decode_ruuvi_data};
use std::future::Future;
use std::pin::Pin;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Example V5 payload (RuuviTag standard format)
fn v5_payload() -> Vec<u8> {
    vec![
        0x05, // Format 5
        0x12, 0xFC, // Temperature: 24.30°C
        0x53, 0x94, // Humidity: 53.49%
        0xC3, 0x7C, // Pressure: 100044 Pa
        0x00, 0x04, // Acceleration X: 4 mG
        0xFF, 0xFC, // Acceleration Y: -4 mG
        0x04, 0x0C, // Acceleration Z: 1036 mG
        0xAC, 0x36, // Battery: 2977 mV, TX Power: 4 dBm
        0x42, // Movement counter: 66
        0x00, 0xCD, // Sequence: 205
        0xCB, 0xB8, 0x33, 0x4C, 0x88, 0x4F, // MAC address
    ]
}

/// Example V6 payload (Ruuvi Air Quality Sensor)
fn v6_payload() -> Vec<u8> {
    vec![
        0x06, 0x17, 0x0C, 0x56, 0x68, 0xC7, 0x9E, 0x00, 0x70, 0x00, 0xC9, 0x05, 0x01, 0xD9, 0xFF,
        0xCD, 0x00, 0x4C, 0x88, 0x4F,
    ]
}

const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

/// A fake scanner that yields pre-decoded measurements, similar to the one in app.rs tests.
struct FakeScanner {
    results: Vec<MeasurementResult>,
}

impl FakeScanner {
    fn new(results: Vec<MeasurementResult>) -> Self {
        Self { results }
    }

    /// Create a scanner that decodes raw payloads into measurements
    fn from_raw_payloads(payloads: Vec<Vec<u8>>) -> Self {
        let results = payloads
            .into_iter()
            .map(|data| decode_ruuvi_data(TEST_MAC, &data))
            .collect();
        Self::new(results)
    }
}

impl Scanner for FakeScanner {
    fn start_scan(
        &self,
        _backend: Backend,
        _verbose: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<mpsc::Receiver<MeasurementResult>, ScanError>> + Send + '_>,
    > {
        let results = self.results.clone();
        Box::pin(async move {
            let (tx, rx) = mpsc::channel::<MeasurementResult>(results.len().max(1));
            tokio::spawn(async move {
                for r in results {
                    let _ = tx.send(r).await;
                }
            });
            Ok(rx)
        })
    }
}

fn default_options() -> Options {
    Options {
        influxdb_measurement: "ruuvi_measurement".to_string(),
        aliases: vec![],
        verbose: false,
        throttle: None,
        backend: Backend::Bluer,
    }
}

/// Benchmark the full application pipeline: scanner -> decode -> throttle -> format -> write
fn bench_app_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("app_pipeline");
    let rt = Runtime::new().unwrap();

    // Single V5 measurement through the full pipeline
    let v5_data = v5_payload();
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_v5", |b| {
        b.iter(|| {
            let scanner = FakeScanner::from_raw_payloads(vec![v5_data.clone()]);
            let options = default_options();
            let mut out = Vec::<u8>::with_capacity(512);
            let mut err = Vec::<u8>::new();

            rt.block_on(async {
                run_with_io(options, &scanner, &mut out, &mut err)
                    .await
                    .unwrap();
            });

            black_box(out)
        })
    });

    // Single V6 measurement
    let v6_data = v6_payload();
    group.bench_function("single_v6", |b| {
        b.iter(|| {
            let scanner = FakeScanner::from_raw_payloads(vec![v6_data.clone()]);
            let options = default_options();
            let mut out = Vec::<u8>::with_capacity(512);
            let mut err = Vec::<u8>::new();

            rt.block_on(async {
                run_with_io(options, &scanner, &mut out, &mut err)
                    .await
                    .unwrap();
            });

            black_box(out)
        })
    });

    group.finish();
}

/// Benchmark batch processing through the full pipeline
fn bench_batch_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_pipeline");
    let rt = Runtime::new().unwrap();

    let v5_data = v5_payload();

    for batch_size in [1, 10, 100] {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                let payloads: Vec<Vec<u8>> = (0..size).map(|_| v5_data.clone()).collect();

                b.iter(|| {
                    let scanner = FakeScanner::from_raw_payloads(payloads.clone());
                    let options = default_options();
                    let mut out = Vec::<u8>::with_capacity(512 * size);
                    let mut err = Vec::<u8>::new();

                    rt.block_on(async {
                        run_with_io(options, &scanner, &mut out, &mut err)
                            .await
                            .unwrap();
                    });

                    black_box(out)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark with throttling enabled (realistic scenario where most measurements are dropped)
fn bench_throttled_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("throttled_pipeline");
    let rt = Runtime::new().unwrap();

    let v5_data = v5_payload();

    // 100 measurements from the same MAC, but throttle is set to 1 hour
    // so only the first one should be emitted
    let payloads: Vec<Vec<u8>> = (0..100).map(|_| v5_data.clone()).collect();

    group.throughput(Throughput::Elements(100));
    group.bench_function("100_same_mac_throttled", |b| {
        b.iter(|| {
            let scanner = FakeScanner::from_raw_payloads(payloads.clone());
            let mut options = default_options();
            options.throttle = Some(std::time::Duration::from_secs(3600));

            let mut out = Vec::<u8>::with_capacity(512);
            let mut err = Vec::<u8>::new();

            rt.block_on(async {
                run_with_io(options, &scanner, &mut out, &mut err)
                    .await
                    .unwrap();
            });

            // Verify only 1 line was output (the rest were throttled)
            debug_assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);

            black_box(out)
        })
    });

    group.finish();
}

/// Benchmark with multiple different devices (no throttling effect)
fn bench_multi_device_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_device_pipeline");
    let rt = Runtime::new().unwrap();

    // Pre-decode measurements from different MAC addresses
    let v5_data = v5_payload();
    let measurements: Vec<MeasurementResult> = (0..10u8)
        .map(|i| {
            let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, i]);
            decode_ruuvi_data(mac, &v5_data)
        })
        .collect();

    group.throughput(Throughput::Elements(10));
    group.bench_function("10_different_devices", |b| {
        b.iter(|| {
            let scanner = FakeScanner::new(measurements.clone());
            let options = default_options();
            let mut out = Vec::<u8>::with_capacity(512 * 10);
            let mut err = Vec::<u8>::new();

            rt.block_on(async {
                run_with_io(options, &scanner, &mut out, &mut err)
                    .await
                    .unwrap();
            });

            black_box(out)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_app_pipeline,
    bench_batch_pipeline,
    bench_throttled_pipeline,
    bench_multi_device_pipeline,
);
criterion_main!(benches);
