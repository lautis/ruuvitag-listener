//! BLE scanner for RuuviTag devices using bluer.
//!
//! This module provides functionality to scan for RuuviTag BLE advertisements
//! and decode their sensor data.

use crate::measurement::Measurement;
use bluer::monitor::{Monitor, MonitorEvent, Pattern};
use bluer::{Adapter, Address, Session};
use futures::StreamExt;
use ruuvi_decoders::{RuuviData, decode};
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

/// Ruuvi Innovations manufacturer ID (little-endian bytes for pattern matching).
///
/// Bluetooth LE advertisements use little-endian byte order for manufacturer IDs.
/// This is the byte representation of 0x0499 used for filtering advertisements.
/// See: https://github.com/ruuvi/ruuvi-sensor-protocols
const RUUVI_MANUFACTURER_ID_BYTES: [u8; 2] = [0x99, 0x04];

/// Ruuvi Innovations manufacturer ID for data lookup.
///
/// This is the big-endian representation (0x0499) used when looking up
/// manufacturer-specific data from device advertisements.
const RUUVI_MANUFACTURER_ID: u16 = 0x0499;

/// Bluetooth manufacturer-specific data type (AD type 0xFF)
const MANUFACTURER_DATA_TYPE: u8 = 0xff;

/// Channel buffer size for measurement results.
const MEASUREMENT_CHANNEL_BUFFER_SIZE: usize = 100;

/// Error type for scanner operations.
#[derive(Debug)]
pub enum ScanError {
    Bluetooth(bluer::Error),
    Decode(DecodeError),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Bluetooth(e) => write!(f, "Bluetooth error: {}", e),
            ScanError::Decode(e) => write!(f, "Decode error: {}", e),
        }
    }
}

impl From<DecodeError> for ScanError {
    fn from(err: DecodeError) -> Self {
        ScanError::Decode(err)
    }
}

impl std::error::Error for ScanError {}

impl From<bluer::Error> for ScanError {
    fn from(err: bluer::Error) -> Self {
        ScanError::Bluetooth(err)
    }
}

/// Format a Bluetooth address as a MAC address string.
fn format_address(addr: Address) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr.0[0], addr.0[1], addr.0[2], addr.0[3], addr.0[4], addr.0[5]
    )
}

/// Decode manufacturer data from a RuuviTag into a Measurement.
///
/// This function converts raw manufacturer data bytes into a structured `Measurement`
/// with all values in standard SI units. Currently only supports RuuviTag V5 format.
///
/// # Arguments
/// * `mac` - The MAC address of the device (formatted as "AA:BB:CC:DD:EE:FF")
/// * `data` - The manufacturer-specific data bytes (without the company ID prefix)
///
/// # Returns
/// A Result containing the decoded Measurement or a DecodeError.
///
/// # Unit Conversions
/// - Battery voltage: millivolts → Volts (divide by 1000)
/// - Acceleration: milli-g → g (divide by 1000)
pub fn decode_ruuvi_data(mac: String, data: &[u8]) -> Result<Measurement, DecodeError> {
    let hex_payload: String = data.iter().map(|b| format!("{:02x}", b)).collect();

    match decode(&hex_payload) {
        Ok(RuuviData::V5(tag)) => {
            // Convert battery potential from millivolts to Volts
            let battery_potential = tag.battery_voltage.map(|v| f64::from(v) / 1000.0);

            // Convert acceleration from milli-g (i16) to g (f64)
            // All three components must be present to include acceleration
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
            })
        }
        Ok(other_format) => Err(DecodeError::UnsupportedFormat(format!(
            "RuuviTag data format {:?} (only V5 supported)",
            other_format
        ))),
        Err(e) => Err(DecodeError::DecoderError(format!(
            "Failed to decode RuuviTag data: {e:?}"
        ))),
    }
}

/// Start scanning for RuuviTag devices.
///
/// This function initializes the Bluetooth adapter and starts a passive scan
/// for RuuviTag advertisements. Discovered measurements are sent through the
/// returned channel. Runs indefinitely until interrupted.
///
/// # Arguments
/// * `verbose` - If true, decode errors are sent as Err values; otherwise they're silently dropped.
///
/// # Returns
/// A receiver for measurements (or decode errors if verbose).
pub async fn start_scan(verbose: bool) -> Result<mpsc::Receiver<MeasurementResult>, ScanError> {
    let session = Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);

    // Create a pattern to filter for Ruuvi manufacturer data
    let pattern = Pattern {
        data_type: MANUFACTURER_DATA_TYPE,
        start_position: 0,
        content: RUUVI_MANUFACTURER_ID_BYTES.to_vec(),
    };

    let monitor_manager = adapter.monitor().await?;
    let mut monitor_handle = monitor_manager
        .register(Monitor {
            patterns: Some(vec![pattern]),
            ..Default::default()
        })
        .await?;

    // Spawn a task that owns all Bluetooth state and runs the event loop
    tokio::spawn(async move {
        // Keep all Bluetooth state alive by moving it into this task
        let _session = session;
        let _monitor_manager = monitor_manager;

        while let Some(event) = monitor_handle.next().await {
            if let MonitorEvent::DeviceFound(device_id) = event {
                if let Err(e) = process_device(&adapter, device_id.device, &tx, verbose).await {
                    if verbose {
                        let err = match e {
                            ScanError::Bluetooth(e) => {
                                DecodeError::InvalidData(format!("Bluetooth error: {e}"))
                            }
                            ScanError::Decode(e) => e,
                        };
                        let _ = tx.send(Err(err)).await;
                    }
                }
            }
        }
    });

    Ok(rx)
}

/// Process a discovered Bluetooth device and extract RuuviTag measurements.
///
/// This function attempts to read manufacturer data from the device and decode it
/// as a RuuviTag measurement. Results are sent through the provided channel.
async fn process_device(
    adapter: &Adapter,
    address: Address,
    tx: &mpsc::Sender<MeasurementResult>,
    verbose: bool,
) -> Result<(), ScanError> {
    let device = adapter.device(address)?;
    let mac = format_address(address);

    // Try to get manufacturer-specific data from the device
    let manufacturer_data = match device.manufacturer_data().await? {
        Some(data) => data,
        None => return Ok(()), // No manufacturer data available
    };

    // Extract RuuviTag data if present
    let ruuvi_data = match manufacturer_data.get(&RUUVI_MANUFACTURER_ID) {
        Some(data) => data,
        None => return Ok(()), // Not a RuuviTag device
    };

    // Decode and send the measurement
    match decode_ruuvi_data(mac, ruuvi_data) {
        Ok(measurement) => {
            let _ = tx.send(Ok(measurement)).await;
        }
        Err(e) if verbose => {
            let _ = tx.send(Err(e)).await;
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_address() {
        let addr = Address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(format_address(addr), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_format_address_with_zeros() {
        let addr = Address([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(format_address(addr), "00:01:02:03:04:05");
    }

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

        let result = decode_ruuvi_data("AA:BB:CC:DD:EE:FF".to_string(), &data);
        assert!(result.is_ok());

        let measurement = result.unwrap();
        assert_eq!(measurement.mac, "AA:BB:CC:DD:EE:FF");
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
    }

    #[test]
    fn test_decode_ruuvi_data_invalid() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x02]; // Invalid/too short data
        let result = decode_ruuvi_data("AA:BB:CC:DD:EE:FF".to_string(), &data);
        assert!(result.is_err());
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
}
