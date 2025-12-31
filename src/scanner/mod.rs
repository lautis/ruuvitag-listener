//! BLE scanner abstraction for RuuviTag devices.
//!
//! This module provides a trait-based abstraction over different Bluetooth
//! scanning backends, with shared decoding logic for RuuviTag sensor data.

#[cfg(feature = "bluer")]
pub mod bluer;

#[cfg(feature = "hci")]
pub mod hci;

use crate::mac_address::MacAddress;
use crate::measurement::Measurement;
use ruuvi_decoders::{v5, v6};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Error types for decoding RuuviTag data.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// Unsupported RuuviTag data format (e.g., V2, V3, V4 when only V5 is supported)
    UnsupportedFormat(String),
    /// Invalid or corrupted data that cannot be decoded
    InvalidData(String),
    /// Decoder library returned an error
    DecoderError(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnsupportedFormat(msg) => write!(f, "Unsupported format: {}", msg),
            DecodeError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            DecodeError::DecoderError(msg) => write!(f, "Decoder error: {}", msg),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Convenience alias for decoded measurements or decode errors.
pub type MeasurementResult = Result<Measurement, DecodeError>;

/// Error type for scanner operations.
#[derive(Debug)]
pub enum ScanError {
    /// Bluetooth/adapter related error
    Bluetooth(String),
    /// Data decoding error
    Decode(DecodeError),
    /// Backend not available (not compiled in)
    #[allow(dead_code)]
    BackendNotAvailable(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Bluetooth(e) => write!(f, "Bluetooth error: {}", e),
            ScanError::Decode(e) => write!(f, "Decode error: {}", e),
            ScanError::BackendNotAvailable(name) => {
                write!(f, "Backend '{}' not available (not compiled in)", name)
            }
        }
    }
}

impl From<DecodeError> for ScanError {
    fn from(err: DecodeError) -> Self {
        ScanError::Decode(err)
    }
}

impl std::error::Error for ScanError {}

/// Ruuvi Innovations manufacturer ID (little-endian bytes for pattern matching).
///
/// Bluetooth LE advertisements use little-endian byte order for manufacturer IDs.
/// This is the byte representation of 0x0499 used for filtering advertisements.
/// See: https://github.com/ruuvi/ruuvi-sensor-protocols
#[cfg(feature = "bluer")]
pub const RUUVI_MANUFACTURER_ID_BYTES: [u8; 2] = [0x99, 0x04];

/// Ruuvi Innovations manufacturer ID for data lookup.
///
/// This is the big-endian representation (0x0499) used when looking up
/// manufacturer-specific data from device advertisements.
#[cfg(any(feature = "bluer", feature = "hci"))]
pub const RUUVI_MANUFACTURER_ID: u16 = 0x0499;

/// Bluetooth manufacturer-specific data type (AD type 0xFF)
#[cfg(feature = "bluer")]
pub const MANUFACTURER_DATA_TYPE: u8 = 0xff;

/// Channel buffer size for measurement results.
pub const MEASUREMENT_CHANNEL_BUFFER_SIZE: usize = 100;

/// Available scanner backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// BlueZ D-Bus backend (requires bluetoothd daemon)
    #[default]
    Bluer,
    /// Raw HCI socket backend (direct kernel access, no daemon required)
    Hci,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Bluer => write!(f, "bluer"),
            Backend::Hci => write!(f, "hci"),
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bluer" | "bluez" => Ok(Backend::Bluer),
            "hci" | "raw" => Ok(Backend::Hci),
            _ => Err(format!("Unknown backend: {}", s)),
        }
    }
}

/// Decode manufacturer data from a RuuviTag into a Measurement.
///
/// This function converts raw manufacturer data bytes into a structured `Measurement`
/// with all values in standard SI units. Supports RuuviTag V5 and V6 formats.
///
/// # Arguments
/// * `mac` - The MAC address of the device
/// * `data` - The manufacturer-specific data bytes (without the company ID prefix)
///
/// # Returns
/// A Result containing the decoded Measurement or a DecodeError.
///
/// # Unit Conversions
/// - Battery voltage: millivolts → Volts (divide by 1000)
/// - Acceleration: milli-g → g (divide by 1000)
pub fn decode_ruuvi_data(mac: MacAddress, data: &[u8]) -> Result<Measurement, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::InvalidData("Empty data".into()));
    }

    match data[0] {
        5 => decode_v5_measurement(mac, data),
        6 => decode_v6_measurement(mac, data),
        _ => Err(DecodeError::UnsupportedFormat(format!(
            "RuuviTag data format {} (only V5 and V6 supported)",
            data[0]
        ))),
    }
}

fn decode_v5_measurement(mac: MacAddress, data: &[u8]) -> Result<Measurement, DecodeError> {
    match v5::decode(data) {
        Ok(tag) => {
            let battery_potential = tag.battery_voltage.map(|v| f64::from(v) / 1000.0);

            let acceleration = match (tag.acceleration_x, tag.acceleration_y, tag.acceleration_z) {
                (Some(x), Some(y), Some(z)) => Some((
                    f64::from(x) / 1000.0,
                    f64::from(y) / 1000.0,
                    f64::from(z) / 1000.0,
                )),
                _ => None,
            };

            Ok(Measurement {
                mac,
                timestamp: SystemTime::now(),
                temperature: tag.temperature,
                humidity: tag.humidity,
                pressure: tag.pressure,
                battery: battery_potential,
                tx_power: tag.tx_power,
                movement_counter: tag.movement_counter.map(u32::from),
                measurement_sequence: tag.measurement_sequence.map(u32::from),
                acceleration,
                pm2_5: None,
                co2: None,
                voc_index: None,
                nox_index: None,
                luminosity: None,
            })
        }
        Err(e) => Err(DecodeError::DecoderError(format!(
            "Failed to decode RuuviTag data: {e:?}"
        ))),
    }
}

fn decode_v6_measurement(mac: MacAddress, data: &[u8]) -> Result<Measurement, DecodeError> {
    match v6::decode(data) {
        Ok(tag) => Ok(Measurement {
            mac,
            timestamp: SystemTime::now(),
            temperature: tag.temperature,
            humidity: tag.humidity,
            // Decoder returns hPa; store as Pa to stay consistent with v5 handling.
            pressure: tag.pressure.map(|hpa| hpa * 100.0),
            battery: None,
            tx_power: None,
            movement_counter: None,
            measurement_sequence: tag.measurement_sequence.map(u32::from),
            acceleration: None,
            pm2_5: tag.pm2_5,
            co2: tag.co2.map(f64::from),
            voc_index: tag.voc_index.map(f64::from),
            nox_index: tag.nox_index.map(f64::from),
            luminosity: tag.luminosity,
        }),
        Err(e) => Err(DecodeError::DecoderError(format!(
            "Failed to decode RuuviTag data: {e:?}"
        ))),
    }
}

/// Start scanning for RuuviTag devices using the specified backend.
///
/// This is the main entry point for creating a scanner. It dispatches to the
/// appropriate backend implementation based on the `backend` parameter.
///
/// # Arguments
/// * `backend` - The scanner backend to use
/// * `verbose` - If true, decode errors are sent as Err values; otherwise they're silently dropped.
///
/// # Returns
/// A receiver for measurements (or decode errors if verbose).
///
/// # Errors
/// Returns `ScanError::BackendNotAvailable` if the requested backend was not compiled in.
pub async fn start_scan(
    backend: Backend,
    verbose: bool,
) -> Result<mpsc::Receiver<MeasurementResult>, ScanError> {
    match backend {
        Backend::Bluer => {
            #[cfg(feature = "bluer")]
            {
                bluer::start_scan(verbose).await
            }
            #[cfg(not(feature = "bluer"))]
            {
                let _ = verbose;
                Err(ScanError::BackendNotAvailable("bluer".into()))
            }
        }
        Backend::Hci => {
            #[cfg(feature = "hci")]
            {
                hci::start_scan(verbose).await
            }
            #[cfg(not(feature = "hci"))]
            {
                let _ = verbose;
                Err(ScanError::BackendNotAvailable("hci".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    #[test]
    fn test_decode_ruuvi_data_v5() {
        // Example V5 data (without manufacturer ID prefix)
        // This is a valid V5 payload
        let data: Vec<u8> = vec![
            0x05, // Format 5
            0x12, 0xFC, // Temperature: 24.30°C (0x12FC = 4860, 4860 * 0.005 = 24.30)
            0x53, 0x94, // Humidity: 53.49% (0x5394 = 21396, 21396 * 0.0025 = 53.49)
            0xC3, 0x7C, // Pressure: 100044 Pa (0xC37C = 50044, 50044 + 50000 = 100044)
            0x00, 0x04, // Acceleration X: 4 mG
            0xFF, 0xFC, // Acceleration Y: -4 mG
            0x04, 0x0C, // Acceleration Z: 1036 mG
            0xAC, 0x36, // Battery: 2977 mV, TX Power: 4 dBm
            0x42, // Movement counter: 66
            0x00, 0xCD, // Sequence: 205
            0xCB, 0xB8, 0x33, 0x4C, 0x88, 0x4F, // MAC address (ignored in decode)
        ];

        let result = decode_ruuvi_data(TEST_MAC, &data);
        assert!(result.is_ok());

        let measurement = result.unwrap();
        assert_eq!(measurement.mac, TEST_MAC);
        assert!(measurement.timestamp.elapsed().is_ok()); // Verify timestamp is set
        assert!(measurement.temperature.is_some());
        assert!(measurement.humidity.is_some());
        assert!(measurement.pressure.is_some());
        assert!(measurement.battery.is_some());
        assert!(measurement.movement_counter.is_some());
        assert_eq!(measurement.movement_counter, Some(66));
        assert!(measurement.acceleration.is_some());
        // Acceleration should be converted from mG to g
        let (x, _y, z) = measurement.acceleration.unwrap();
        assert!((x - 0.004).abs() < 0.001);
        assert!((z - 1.036).abs() < 0.001);
        assert!(measurement.pm2_5.is_none());
        assert!(measurement.co2.is_none());
        assert!(measurement.voc_index.is_none());
        assert!(measurement.nox_index.is_none());
        assert!(measurement.luminosity.is_none());
    }

    #[test]
    fn test_decode_ruuvi_data_invalid() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x02]; // Invalid/too short data
        let result = decode_ruuvi_data(TEST_MAC, &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_ruuvi_data_v6() {
        // Example V6 payload (includes format byte and compact MAC)
        let data: Vec<u8> = vec![
            0x06, 0x17, 0x0C, 0x56, 0x68, 0xC7, 0x9E, 0x00, 0x70, 0x00, 0xC9, 0x05, 0x01, 0xD9,
            0xFF, 0xCD, 0x00, 0x4C, 0x88, 0x4F,
        ];

        let result = decode_ruuvi_data(TEST_MAC, &data);
        assert!(result.is_ok());

        let measurement = result.unwrap();
        assert_eq!(measurement.mac, TEST_MAC);
        assert!(measurement.temperature.is_some());
        assert!(measurement.humidity.is_some());
        assert!(measurement.pressure.is_some());
        assert!(measurement.pm2_5.is_some());
        assert!(measurement.co2.is_some());
        assert!(measurement.voc_index.is_some());
        assert!(measurement.nox_index.is_some());
        assert!(measurement.luminosity.is_some());
        assert!(measurement.acceleration.is_none());
        assert!(measurement.battery.is_none());
        assert!(measurement.tx_power.is_none());
    }

    #[test]
    fn test_decode_error_display() {
        let err = DecodeError::InvalidData("test error".to_string());
        assert_eq!(format!("{}", err), "Invalid data: test error");

        let err2 = DecodeError::UnsupportedFormat("V2".to_string());
        assert_eq!(format!("{}", err2), "Unsupported format: V2");

        let err3 = DecodeError::DecoderError("parse failed".to_string());
        assert_eq!(format!("{}", err3), "Decoder error: parse failed");
    }

    #[test]
    fn test_scan_error_display() {
        let decode_err = DecodeError::InvalidData("test error".to_string());
        let err = ScanError::Decode(decode_err);
        assert_eq!(format!("{}", err), "Decode error: Invalid data: test error");
    }

    #[test]
    fn test_backend_from_str() {
        assert_eq!(Backend::from_str("bluer").unwrap(), Backend::Bluer);
        assert_eq!(Backend::from_str("bluez").unwrap(), Backend::Bluer);
        assert_eq!(Backend::from_str("hci").unwrap(), Backend::Hci);
        assert_eq!(Backend::from_str("raw").unwrap(), Backend::Hci);
        assert!(Backend::from_str("invalid").is_err());
    }

    #[test]
    fn test_backend_display() {
        assert_eq!(format!("{}", Backend::Bluer), "bluer");
        assert_eq!(format!("{}", Backend::Hci), "hci");
    }
}
