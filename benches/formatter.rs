//! Benchmark suite for the output formatters.
//!
//! Isolates formatter performance from async runtime overhead to enable
//! precise measurement and optimization of the formatting logic.
//!
//! The InfluxDB formatter is the one that was measured first, because it is
//! the default output. JSON Lines and CSV carry an RFC 3339 timestamp and a
//! per-string escaping scan that the InfluxDB path does not have, so they get
//! their own groups with the same fixtures to keep the formats comparable.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ruuvitag_listener::{
    AliasMap, CsvFormatter, Format, InfluxDbFormatter, JsonLinesFormatter, MacAddress, Measurement,
    OutputFormatter, resolve_name,
};
use std::collections::HashMap;
use std::hint::black_box;
use std::time::SystemTime;

const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

/// Device name that forces the escaping slow path in every formatter.
///
/// The comma and the space trigger RFC 4180 quoting in CSV and tag escaping in
/// InfluxDB, the double quote triggers JSON escaping and doubled quotes in CSV,
/// and `ö` forces multi-byte UTF-8 handling on top. A MAC string never needs
/// escaping, so the plain cases never touch those branches.
const HOSTILE_NAME: &str = "Sauna, \"VIP\" ö";

/// V5-style measurement (standard RuuviTag with acceleration)
fn v5_measurement() -> Measurement {
    Measurement {
        mac: TEST_MAC,
        format: Format::V5,
        timestamp: SystemTime::UNIX_EPOCH,
        temperature: Some(24.30),
        humidity: Some(53.49),
        pressure: Some(100044.0),
        battery: Some(2.977),
        tx_power: Some(4),
        rssi: Some(-60),
        movement_counter: Some(66),
        measurement_sequence: Some(205),
        acceleration: Some((0.004, -0.004, 1.036)),
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

/// V6-style measurement (Ruuvi Air Quality Monitor)
fn v6_measurement() -> Measurement {
    Measurement {
        mac: TEST_MAC,
        format: Format::V6,
        timestamp: SystemTime::UNIX_EPOCH,
        temperature: Some(23.12),
        humidity: Some(55.68),
        pressure: Some(100798.0),
        battery: None,
        tx_power: None,
        rssi: None,
        movement_counter: None,
        measurement_sequence: Some(1),
        acceleration: None,
        pm1_0: Some(9.8),
        pm2_5: Some(11.2),
        pm4_0: Some(12.5),
        pm10_0: Some(13.1),
        co2: Some(473.0),
        voc_index: Some(100.0),
        nox_index: Some(1.0),
        luminosity: Some(25.5),
    }
}

/// V5 measurement with every optional field cleared.
///
/// What survives is the part of a line that is paid whether or not the sensor
/// reported anything: mac, name, format and the timestamp. JSON Lines drops
/// absent fields, so this is a short line; CSV still writes an empty column for
/// each one, so its sparse line is not as cheap. Comparing this against the
/// dense cases separates the fixed per-line cost from the per-field cost, which
/// is the number needed before touching the timestamp formatting.
fn sparse_measurement() -> Measurement {
    let mut m = v5_measurement();
    m.temperature = None;
    m.humidity = None;
    m.pressure = None;
    m.battery = None;
    m.tx_power = None;
    m.rssi = None;
    m.movement_counter = None;
    m.measurement_sequence = None;
    m.acceleration = None;
    m.pm1_0 = None;
    m.pm2_5 = None;
    m.pm4_0 = None;
    m.pm10_0 = None;
    m.co2 = None;
    m.voc_index = None;
    m.nox_index = None;
    m.luminosity = None;
    m
}

/// Benchmark formatter with different measurement types
fn bench_format_measurement_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("format_measurement_type");
    let formatter = InfluxDbFormatter::new("ruuvi_measurement".to_string());
    let name = TEST_MAC.to_string();

    group.throughput(Throughput::Elements(1));

    let v5 = v5_measurement();
    group.bench_function("v5", |b| {
        b.iter(|| {
            let output = formatter.format(black_box(&v5), black_box(&name));
            black_box(output)
        })
    });

    let v6 = v6_measurement();
    group.bench_function("v6", |b| {
        b.iter(|| {
            let output = formatter.format(black_box(&v6), black_box(&name));
            black_box(output)
        })
    });

    group.finish();
}

/// Register the shared per-format cases under `group_name`.
///
/// The InfluxDB group predates these cases and keeps its own body so that its
/// baseline IDs never move. JSON Lines and CSV run through here so that the
/// three formats are measured on the same input by construction, rather than
/// by two sets of benchmarks that happen to look alike.
fn bench_format_cases<F: OutputFormatter>(c: &mut Criterion, group_name: &str, formatter: F) {
    let mut group = c.benchmark_group(group_name);

    group.throughput(Throughput::Elements(1));

    // Same MAC-derived name as the InfluxDB group, so a hostile name measured
    // against this is a measurement of escaping and not of the alias.
    let name = TEST_MAC.to_string();

    let v5 = v5_measurement();
    group.bench_function("v5", |b| {
        b.iter(|| {
            let output = formatter.format(black_box(&v5), black_box(&name));
            black_box(output)
        })
    });

    let v6 = v6_measurement();
    group.bench_function("v6", |b| {
        b.iter(|| {
            let output = formatter.format(black_box(&v6), black_box(&name));
            black_box(output)
        })
    });

    // Same measurement, empty field set: the fixed cost of emitting a line.
    let sparse = sparse_measurement();
    group.bench_function("sparse_v5", |b| {
        b.iter(|| {
            let output = formatter.format(black_box(&sparse), black_box(&name));
            black_box(output)
        })
    });

    // `v5` again, only the name differs. Aliases are user input, so a name
    // that needs escaping is a supported case, not a hypothetical one. The gap
    // against `v5` is the scan plus the slow-path write.
    group.bench_function("v5_hostile_name", |b| {
        b.iter(|| {
            let output = formatter.format(black_box(&v5), black_box(HOSTILE_NAME));
            black_box(output)
        })
    });

    group.finish();
}

/// Benchmark JSON Lines formatting
fn bench_format_measurement_types_jsonl(c: &mut Criterion) {
    bench_format_cases(
        c,
        "format_measurement_type_jsonl",
        JsonLinesFormatter::new(),
    );
}

/// Benchmark CSV formatting
fn bench_format_measurement_types_csv(c: &mut Criterion) {
    bench_format_cases(c, "format_measurement_type_csv", CsvFormatter::new());
}

/// Benchmark alias resolution (now separate from formatting)
fn bench_alias_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("alias_resolution");

    group.throughput(Throughput::Elements(1));

    // No aliases - falls back to MAC string
    let empty_aliases: AliasMap = HashMap::new();
    group.bench_function("no_alias", |b| {
        b.iter(|| {
            let name = resolve_name(black_box(&TEST_MAC), black_box(&empty_aliases));
            black_box(name)
        })
    });

    // With alias for this MAC
    let mut aliases: AliasMap = HashMap::new();
    aliases.insert(TEST_MAC, "Living_Room".to_string());
    group.bench_function("with_alias", |b| {
        b.iter(|| {
            let name = resolve_name(black_box(&TEST_MAC), black_box(&aliases));
            black_box(name)
        })
    });

    // With many aliases (but not for this MAC - tests lookup miss)
    let mut many_aliases: AliasMap = HashMap::new();
    for i in 0..100u8 {
        let mac = MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, i]);
        many_aliases.insert(mac, format!("Device_{}", i));
    }
    group.bench_function("miss_in_100", |b| {
        b.iter(|| {
            let name = resolve_name(black_box(&TEST_MAC), black_box(&many_aliases));
            black_box(name)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_format_measurement_types,
    bench_format_measurement_types_jsonl,
    bench_format_measurement_types_csv,
    bench_alias_resolution
);
criterion_main!(benches);
