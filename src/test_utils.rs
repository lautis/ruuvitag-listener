use crate::mac_address::MacAddress;
use crate::measurement::{Format, Measurement};
use std::time::{Duration, SystemTime};

/// A stable MAC address for unit tests.
pub const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

/// The timestamp of the full measurement fixture: 2019-01-05T09:47:35.691300729Z.
pub fn test_timestamp() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_546_681_655) + Duration::from_nanos(691_300_729)
}

/// Build a `Measurement` with all optional fields set to `None`.
///
/// Tests can override just the fields they care about.
pub fn base_measurement(mac: MacAddress, timestamp: SystemTime) -> Measurement {
    Measurement {
        mac,
        format: Format::V5,
        timestamp,
        temperature: None,
        humidity: None,
        pressure: None,
        battery: None,
        tx_power: None,
        rssi: None,
        movement_counter: None,
        measurement_sequence: None,
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

/// A measurement with a value in every field of the output schema.
///
/// The values are ordinary-looking on purpose: the exact-output tests stay
/// readable, and the odd-looking ones live in [`full_measurement_extremes`].
/// A test in `measurement::fields` fails when the schema grows a field this
/// fixture does not fill, so adding a `FIELDS` entry means adding a value here.
pub fn full_measurement() -> Measurement {
    let mut m = base_measurement(TEST_MAC, test_timestamp());
    m.temperature = Some(19.63);
    m.humidity = Some(19.5);
    m.pressure = Some(101481.0);
    m.battery = Some(3.007);
    m.tx_power = Some(-4);
    m.rssi = Some(-63);
    m.movement_counter = Some(42);
    m.measurement_sequence = Some(1234);
    m.acceleration = Some((-0.055, -0.032, 0.998));
    m.pm1_0 = Some(5.5);
    m.pm2_5 = Some(12.5);
    m.pm4_0 = Some(8.2);
    m.pm10_0 = Some(15.1);
    m.co2 = Some(420.0);
    m.voc_index = Some(123.0);
    m.nox_index = Some(45.0);
    m.luminosity = Some(10.0);
    m
}

/// [`full_measurement`] with the three integer fields at the edges of their
/// storage types: `tx_power` = `i8::MIN` (-128), `rssi` = `i8::MAX` (127),
/// `movement_counter` = `u32::MAX` (4294967295).
///
/// InfluxDB line protocol marks integers with a trailing `i`, so an exact-line
/// test needs values that render as integers at both sign and width extremes
/// (and would be visibly wrong as `f64`). Every other value matches
/// [`full_measurement`], so the two fixtures produce the same line except for
/// those three columns.
pub fn full_measurement_extremes() -> Measurement {
    let mut m = full_measurement();
    m.tx_power = Some(i8::MIN);
    m.rssi = Some(i8::MAX);
    m.movement_counter = Some(u32::MAX);
    m
}
