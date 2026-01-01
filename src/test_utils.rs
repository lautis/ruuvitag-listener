use crate::mac_address::MacAddress;
use crate::measurement::Measurement;
use std::time::SystemTime;

/// A stable MAC address for unit tests.
pub const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

/// Build a `Measurement` with all optional fields set to `None`.
///
/// Tests can override just the fields they care about.
pub fn base_measurement(mac: MacAddress, timestamp: SystemTime) -> Measurement {
    Measurement {
        mac,
        timestamp,
        temperature: None,
        humidity: None,
        pressure: None,
        battery: None,
        tx_power: None,
        movement_counter: None,
        measurement_sequence: None,
        acceleration: None,
        pm2_5: None,
        co2: None,
        voc_index: None,
        nox_index: None,
        luminosity: None,
    }
}
