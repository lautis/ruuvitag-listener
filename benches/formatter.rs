//! Benchmark suite specifically for the InfluxDB formatter.
//!
//! Isolates formatter performance from async runtime overhead to enable
//! precise measurement and optimization of the formatting logic.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use ruuvitag_listener::{
    AliasMap, InfluxDbFormatter, MacAddress, Measurement, OutputFormatter, resolve_name,
};
use std::collections::HashMap;
use std::time::SystemTime;

const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

/// V5-style measurement (standard RuuviTag with acceleration)
fn v5_measurement() -> Measurement {
    Measurement {
        mac: TEST_MAC,
        timestamp: SystemTime::UNIX_EPOCH,
        temperature: Some(24.30),
        humidity: Some(53.49),
        pressure: Some(100044.0),
        battery: Some(2.977),
        tx_power: Some(4),
        movement_counter: Some(66),
        measurement_sequence: Some(205),
        acceleration: Some((0.004, -0.004, 1.036)),
        pm2_5: None,
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
        timestamp: SystemTime::UNIX_EPOCH,
        temperature: Some(23.12),
        humidity: Some(55.68),
        pressure: Some(100798.0),
        battery: None,
        tx_power: None,
        movement_counter: None,
        measurement_sequence: Some(1),
        acceleration: None,
        pm2_5: Some(11.2),
        co2: Some(473.0),
        voc_index: Some(100.0),
        nox_index: Some(1.0),
        luminosity: Some(25.5),
    }
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
    bench_alias_resolution
);
criterion_main!(benches);
