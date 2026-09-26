//! BLE scanner abstraction for RuuviTag devices.
//!
//! This module provides a trait-based abstraction over different Bluetooth
//! scanning backends, with shared decoding logic for RuuviTag sensor data.

#[cfg(feature = "bluer")]
pub mod bluer;

#[cfg(feature = "hci")]
pub mod hci;

use crate::mac_address::MacAddress;
use crate::measurement::{Format, Measurement};
use ruuvi_sensor_protocol::{
    Acceleration, AccelerationVector, BatteryPotential, CarbonDioxide, Humidity, Luminosity,
    MeasurementSequenceNumber, MovementCounter, NitrogenOxides, ParticulateMatter, Pressure,
    SensorValues, Temperature, TransmitterPower, VolatileOrganicCompounds,
};
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A running BLE scan: the measurement stream plus graceful-stop plumbing.
///
/// `start_scan` returns one of these. The backend owns the adapter state
/// (raw HCI sockets or the BlueZ discovery session) inside a spawned task;
/// [`ScanSession::stop`](Self::stop) asks that task to stop scanning and
/// waits for it to complete any cleanup (e.g. disabling the adapter's LE
/// scan) before returning.
///
/// Dropping a session without calling `stop` lets the backend task run until
/// the process exits, in which case the OS reclaims the sockets. For the HCI
/// backend this leaves the adapter scanning, so prefer an explicit `stop`.
pub struct ScanSession {
    /// Receiver for measurements (or decode errors when verbose).
    pub measurements: mpsc::Receiver<MeasurementResult>,
    /// Non-fatal backend warnings (e.g. a failed LE scan disable), written to
    /// the process's error stream by the run loop. Control-plane messages are
    /// rare, so the channel is unbounded: they can neither block the scan nor
    /// be dropped. Closes when the backend task finishes.
    pub warnings: mpsc::UnboundedReceiver<String>,
    /// Cancellation signal used to ask the backend task to stop scanning
    /// gracefully. `cancel()` is idempotent, so calling [`Self::stop`] more
    /// than once is harmless.
    cancel: CancellationToken,
    /// Join handle for the backend task.
    task: Option<JoinHandle<()>>,
}

impl ScanSession {
    /// Wrap a scan managed by a backend task.
    ///
    /// `cancel` requests the task to stop scanning; the task is expected to
    /// disable the adapter's scan (and do any other cleanup) before finishing.
    /// Backend tasks report non-fatal problems through `warnings`.
    pub fn managed(
        measurements: mpsc::Receiver<MeasurementResult>,
        warnings: mpsc::UnboundedReceiver<String>,
        cancel: CancellationToken,
        task: JoinHandle<()>,
    ) -> Self {
        Self {
            measurements,
            warnings,
            cancel,
            task: Some(task),
        }
    }

    /// Wrap a bare receiver with no managed scan (used in tests).
    pub fn unmanaged(measurements: mpsc::Receiver<MeasurementResult>) -> Self {
        let (_, warnings) = mpsc::unbounded_channel();
        Self {
            measurements,
            warnings,
            cancel: CancellationToken::new(),
            task: None,
        }
    }

    /// Ask the backend to stop scanning and wait until its cleanup completes.
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// Error types for decoding RuuviTag data.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// Unsupported RuuviTag data format (e.g., V2 or V4, which are not supported)
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    /// Invalid or corrupted data that cannot be decoded
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// Decoder library returned an error
    #[error("Decoder error: {0}")]
    DecoderError(String),
}

/// Convenience alias for decoded measurements or decode errors.
pub type MeasurementResult = Result<Measurement, DecodeError>;

/// Error type for scanner operations.
#[derive(Error, Debug)]
pub enum ScanError {
    /// Bluetooth/adapter related error
    #[error("Bluetooth error: {0}")]
    Bluetooth(String),
    /// Data decoding error
    #[error("Decode error: {0}")]
    Decode(#[from] DecodeError),
    /// Backend not available (not compiled in)
    #[allow(dead_code)]
    #[error("Backend '{0}' not available (not compiled in)")]
    BackendNotAvailable(String),
}

impl ScanError {
    /// Build an error for a requested Bluetooth adapter that does not exist.
    ///
    /// `available` is the list of adapter names reported to the user; pass
    /// `None` when the available adapters could not be enumerated.
    pub(crate) fn adapter_not_found(name: &str, available: Option<&[String]>) -> Self {
        let mut message = format!("Bluetooth adapter '{}' not found", name);
        if let Some(available) = available.filter(|available| !available.is_empty()) {
            message.push_str("; available adapters: ");
            message.push_str(&available.join(", "));
        }
        ScanError::Bluetooth(message)
    }
}

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

/// HCI "RSSI not available" sentinel value.
///
/// Legacy and extended LE Advertising Reports use 127 to signal that the
/// controller did not report a signal strength. The sentinel is mapped to
/// `None` by [`with_rssi`] so it never appears in the output.
const RSSI_UNAVAILABLE: i8 = 127;

/// Attach an RSSI reading in dBm (from the radio advertisement, not the Ruuvi
/// payload) to a decoded measurement.
///
/// The HCI "not available" sentinel (127) is mapped to `None` so those packets
/// are indistinguishable from backends that never report RSSI.
pub(crate) fn with_rssi(mut measurement: Measurement, rssi: i8) -> Measurement {
    if rssi != RSSI_UNAVAILABLE {
        measurement.rssi = Some(rssi);
    }
    measurement
}

/// Bluetooth manufacturer-specific data type (AD type 0xFF)
#[cfg(feature = "bluer")]
pub const MANUFACTURER_DATA_TYPE: u8 = 0xff;

/// Channel buffer size for measurement results.
pub const MEASUREMENT_CHANNEL_BUFFER_SIZE: usize = 100;

/// Available scanner backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    /// BlueZ D-Bus backend (requires bluetoothd daemon)
    #[cfg(feature = "bluer")]
    Bluer,
    /// Raw HCI socket backend (direct kernel access, no daemon required)
    #[cfg(feature = "hci")]
    Hci,
}

impl Default for Backend {
    fn default() -> Self {
        #[cfg(feature = "bluer")]
        return Backend::Bluer;
        #[cfg(all(feature = "hci", not(feature = "bluer")))]
        return Backend::Hci;
        #[cfg(not(any(feature = "bluer", feature = "hci")))]
        compile_error!("At least one backend feature must be enabled");
    }
}

/// What the HCI backend does with the adapter's LE scan on shutdown.
///
/// The controller's scan state is global: a scan left running keeps the radio
/// awake for everyone, and disabling it stops whatever process started it. A
/// scan this process leaves running also gets its duplicate-filtering policy
/// put back, so its owner does not silently inherit ours.
/// The BlueZ backend is unaffected — it ends its discovery session either way.
#[derive(clap::ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ScanExitBehavior {
    /// Stop the scan on exit only if this process started it (default). A scan
    /// that was already running is left to its original owner, with the
    /// duplicate-filtering policy it had.
    #[default]
    OwnedOnly,
    /// Always stop the scan on exit, even if another process started it. The
    /// pre-0.9 behavior; use when this process owns the adapter.
    Always,
    /// Never stop the scan on exit, not even one this process started. The
    /// adapter keeps scanning after the listener exits, with the duplicate
    /// policy of whichever scan is running.
    Never,
}

/// Everything a backend needs to start a scan.
///
/// One grouped argument instead of a positional per option, so adding an
/// option does not widen the signature of [`crate::app::Scanner::start_scan`]
/// and every backend entry point.
#[derive(Debug, Default, Clone)]
pub struct ScanConfig {
    /// Which backend to scan with.
    pub backend: Backend,
    /// Whether decode errors are forwarded to the consumer as `Err` values
    /// instead of being dropped.
    pub verbose: bool,
    /// Kernel adapter name (e.g. "hci1"), or `None` for the backend default.
    pub adapter: Option<String>,
    /// What the HCI backend does with the adapter's LE scan on shutdown.
    pub scan_exit: ScanExitBehavior,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "bluer")]
            Backend::Bluer => write!(f, "bluer"),
            #[cfg(feature = "hci")]
            Backend::Hci => write!(f, "hci"),
            #[cfg(not(any(feature = "bluer", feature = "hci")))]
            _ => unreachable!("Backend enum has no variants when no backend features are enabled"),
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "bluer")]
            "bluer" | "bluez" => Ok(Backend::Bluer),
            #[cfg(feature = "hci")]
            "hci" | "raw" => Ok(Backend::Hci),
            _ => Err(format!("Unknown backend: {}", s)),
        }
    }
}

/// Decode manufacturer data from a RuuviTag into a Measurement.
///
/// This function converts raw manufacturer data bytes into a structured `Measurement`
/// with all values in standard SI units. Supports RuuviTag data formats V3, V5, V6 and E1.
///
/// # Arguments
/// * `mac` - The MAC address of the device
/// * `data` - The manufacturer-specific data bytes (without the company ID prefix)
///
/// # Returns
/// A Result containing the decoded Measurement or a DecodeError.
///
/// # Unit Conversions
/// - Temperature: milli-celsius → Celsius (divide by 1000)
/// - Humidity: parts per million → percent (divide by 10000)
/// - Battery voltage: millivolts → Volts (divide by 1000)
/// - Acceleration: milli-g → g (divide by 1000)
/// - Particulate matter: nanograms per cubic meter → micrograms per cubic meter (divide by 1000)
/// - Luminosity: millilux → lux (divide by 1000)
pub fn decode_ruuvi_data(mac: MacAddress, data: &[u8]) -> Result<Measurement, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::InvalidData("Empty data".into()));
    }

    let format = match data[0] {
        3 => Format::V3,
        5 => Format::V5,
        6 => Format::V6,
        0xE1 => Format::E1,
        other => {
            return Err(DecodeError::UnsupportedFormat(format!(
                "RuuviTag data format {other} (only V3, V5, V6 and E1 supported)"
            )));
        }
    };

    let values = SensorValues::from_manufacturer_specific_data(RUUVI_MANUFACTURER_ID, data)
        .map_err(|e| DecodeError::DecoderError(e.to_string()))?;

    let acceleration =
        values
            .acceleration_vector_as_milli_g()
            .map(|AccelerationVector(x, y, z)| {
                (
                    f64::from(x) / 1000.0,
                    f64::from(y) / 1000.0,
                    f64::from(z) / 1000.0,
                )
            });

    Ok(Measurement {
        mac,
        format,
        timestamp: SystemTime::now(),
        temperature: values
            .temperature_as_millicelsius()
            .map(|milli_celsius| f64::from(milli_celsius) / 1000.0),
        humidity: values
            .humidity_as_ppm()
            .map(|ppm| f64::from(ppm) / 10_000.0),
        pressure: values.pressure_as_pascals().map(f64::from),
        battery: values
            .battery_potential_as_millivolts()
            .map(|millivolts| f64::from(millivolts) / 1000.0),
        tx_power: values.tx_power_as_dbm(),
        rssi: None, // Set by the scanner backend from the radio advertisement.
        movement_counter: values.movement_counter(),
        measurement_sequence: values.measurement_sequence_number(),
        acceleration,
        pm1_0: values
            .pm1_0_as_nanograms_per_cubic_meter()
            .map(|ng_m3| f64::from(ng_m3) / 1000.0),
        pm2_5: values
            .pm2_5_as_nanograms_per_cubic_meter()
            .map(|ng_m3| f64::from(ng_m3) / 1000.0),
        pm4_0: values
            .pm4_0_as_nanograms_per_cubic_meter()
            .map(|ng_m3| f64::from(ng_m3) / 1000.0),
        pm10_0: values
            .pm10_0_as_nanograms_per_cubic_meter()
            .map(|ng_m3| f64::from(ng_m3) / 1000.0),
        co2: values.carbon_dioxide_as_ppm().map(f64::from),
        voc_index: values.voc_index().map(f64::from),
        nox_index: values.nox_index().map(f64::from),
        luminosity: values
            .luminosity_as_millilux()
            .map(|millilux| f64::from(millilux) / 1000.0),
    })
}

/// Start scanning for RuuviTag devices using the specified backend.
///
/// This is the main entry point for creating a scanner. It dispatches to the
/// appropriate backend implementation based on the backend in `config`.
///
/// # Arguments
/// * `config` - Scan parameters: backend, verbose flag, adapter name (or
///   `None` for the backend default) and HCI scan-exit behavior.
///
/// # Returns
/// A scan session whose `measurements` receiver yields measurements (or decode
/// errors if verbose). The session can be stopped with
/// [`ScanSession::stop`], which lets the backend disable the adapter's scan
/// according to the configured [`ScanExitBehavior`].
pub async fn start_scan(config: ScanConfig) -> Result<ScanSession, ScanError> {
    let ScanConfig {
        backend,
        verbose,
        adapter,
        scan_exit,
    } = config;
    match backend {
        #[cfg(feature = "bluer")]
        Backend::Bluer => {
            // The BlueZ backend ends its discovery session on shutdown, so
            // the scan-exit behavior does not apply to it.
            let _ = scan_exit;
            bluer::start_scan(verbose, adapter).await
        }
        #[cfg(feature = "hci")]
        Backend::Hci => hci::start_scan(verbose, adapter, scan_exit).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TEST_MAC;
    use std::str::FromStr;

    /// Assert that an Option<f64> is present and close to the expected value.
    fn assert_close(actual: Option<f64>, expected: f64) {
        let actual = actual.expect("expected a value");
        assert!(
            (actual - expected).abs() < 1e-9,
            "expected {expected}, got {actual}"
        );
    }

    fn v5_payload() -> Vec<u8> {
        // Example V5 data (without manufacturer ID prefix)
        // This is a valid V5 payload
        vec![
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
        ]
    }

    fn v3_payload() -> Vec<u8> {
        // Example V3 (RAWv1) payload without the manufacturer ID prefix,
        // from the ruuvi-sensor-protocol crate documentation.
        vec![
            0x03, // Format 3
            0x17, // Humidity: 11.5% (0x17 = 23, 23 * 0.5 = 11.5)
            0x01, 0x45, // Temperature: 1.69°C (sign bit 0, 1°C + 69 * 0.01°C)
            0x35, 0x58, // Pressure: 63656 Pa (0x3558 = 13656, 13656 + 50000 = 63656)
            0x03, 0xE8, // Acceleration X: 1000 mG
            0x04, 0xE7, // Acceleration Y: 1255 mG
            0x05, 0xE6, // Acceleration Z: 1510 mG
            0x08, 0x86, // Battery: 2182 mV
        ]
    }

    fn v6_payload() -> Vec<u8> {
        // Example V6 payload (includes format byte and compact MAC)
        vec![
            0x06, 0x17, 0x0C, 0x56, 0x68, 0xC7, 0x9E, 0x00, 0x70, 0x00, 0xC9, 0x05, 0x01, 0xD9,
            0xFF, 0xCD, 0x00, 0x4C, 0x88, 0x4F,
        ]
    }

    #[test]
    fn test_decode_ruuvi_data_v5() {
        let measurement = decode_ruuvi_data(TEST_MAC, &v5_payload()).unwrap();
        assert_eq!(measurement.mac, TEST_MAC);
        assert_eq!(measurement.format, Format::V5);
        assert!(measurement.timestamp.elapsed().is_ok()); // Verify timestamp is set
        // Values as per the Ruuvi data format 5 specification.
        assert_close(measurement.temperature, 24.3);
        assert_close(measurement.humidity, 53.49);
        assert_close(measurement.pressure, 100_044.0);
        assert_close(measurement.battery, 2.977);
        assert_eq!(measurement.tx_power, Some(4));
        assert_eq!(measurement.movement_counter, Some(66));
        assert_eq!(measurement.measurement_sequence, Some(205));
        // Acceleration should be converted from mG to g
        assert_eq!(measurement.acceleration, Some((0.004, -0.004, 1.036)));
        assert!(measurement.pm1_0.is_none());
        assert!(measurement.pm2_5.is_none());
        assert!(measurement.pm4_0.is_none());
        assert!(measurement.pm10_0.is_none());
        assert!(measurement.co2.is_none());
        assert!(measurement.voc_index.is_none());
        assert!(measurement.nox_index.is_none());
        assert!(measurement.luminosity.is_none());
    }

    #[test]
    fn test_decode_ruuvi_data_v3() {
        let measurement = decode_ruuvi_data(TEST_MAC, &v3_payload()).unwrap();
        assert_eq!(measurement.mac, TEST_MAC);
        assert_eq!(measurement.format, Format::V3);
        assert_close(measurement.temperature, 1.69);
        assert_close(measurement.humidity, 11.5);
        assert_close(measurement.pressure, 63_656.0);
        assert_close(measurement.battery, 2.182);
        // Acceleration should be converted from mG to g
        assert_eq!(measurement.acceleration, Some((1.0, 1.255, 1.51)));
        // Fields not present in V3 advertisements.
        assert_eq!(measurement.tx_power, None);
        assert_eq!(measurement.movement_counter, None);
        assert_eq!(measurement.measurement_sequence, None);
        assert!(measurement.pm1_0.is_none());
        assert!(measurement.pm2_5.is_none());
        assert!(measurement.pm4_0.is_none());
        assert!(measurement.pm10_0.is_none());
        assert!(measurement.co2.is_none());
        assert!(measurement.voc_index.is_none());
        assert!(measurement.nox_index.is_none());
        assert!(measurement.luminosity.is_none());
    }

    fn e1_payload() -> Vec<u8> {
        // Known-good E1 (Ruuvi Air) payload,
        // without the 9904 manufacturer prefix. 40 bytes (34 data + 6 MAC).
        vec![
            0xE1, 0x17, 0x0C, 0x56, 0x68, 0xC7, 0x9E, 0x00, 0x65, 0x00, 0x70, 0x04, 0xBD, 0x11,
            0xCA, 0x00, 0xC9, 0x0A, 0x02, 0x13, 0xE0, 0xAC, 0x00, 0x00, 0x00, 0xDE, 0xCD, 0xEE,
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCB, 0xB8, 0x33, 0x4C, 0x88, 0x4F,
        ]
    }

    #[test]
    fn test_decode_ruuvi_data_e1() {
        let measurement = decode_ruuvi_data(TEST_MAC, &e1_payload()).unwrap();
        assert_eq!(measurement.mac, TEST_MAC);
        assert_eq!(measurement.format, Format::E1);
        assert_close(measurement.temperature, 29.5);
        assert_close(measurement.humidity, 55.3);
        assert_close(measurement.pressure, 101_102.0);
        // E1 carries the full particulate-matter range that V6 lacks.
        assert_close(measurement.pm1_0, 10.1);
        assert_close(measurement.pm2_5, 11.2);
        assert_close(measurement.pm4_0, 121.3);
        assert_close(measurement.pm10_0, 455.4);
        assert_close(measurement.co2, 201.0);
        assert_close(measurement.voc_index, 10.0);
        assert_close(measurement.nox_index, 2.0);
        assert_close(measurement.luminosity, 13_027.0);
        assert_eq!(measurement.measurement_sequence, Some(14_601_710));
        // Fields not present in E1 advertisements.
        assert!(measurement.battery.is_none());
        assert!(measurement.tx_power.is_none());
        assert!(measurement.movement_counter.is_none());
        assert!(measurement.acceleration.is_none());
    }

    #[test]
    fn test_decode_ruuvi_data_invalid() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x02]; // Invalid/too short data
        assert!(decode_ruuvi_data(TEST_MAC, &data).is_err());
    }

    #[test]
    fn test_decode_ruuvi_data_v6() {
        let measurement = decode_ruuvi_data(TEST_MAC, &v6_payload()).unwrap();
        assert_eq!(measurement.mac, TEST_MAC);
        assert_eq!(measurement.format, Format::V6);
        assert_close(measurement.temperature, 29.5);
        assert_close(measurement.humidity, 55.3);
        assert_close(measurement.pressure, 101_102.0);
        assert_close(measurement.pm2_5, 11.2);
        assert_close(measurement.co2, 201.0);
        assert_close(measurement.voc_index, 5.0);
        assert_close(measurement.nox_index, 1.0);
        // Luminosity is a logarithmic lookup (millilux → lux)
        assert_close(measurement.luminosity, 13_026.67);
        assert_eq!(measurement.measurement_sequence, Some(205));
        assert_eq!(measurement.movement_counter, None);
        assert_eq!(measurement.battery, None);
        assert_eq!(measurement.tx_power, None);
        assert!(measurement.acceleration.is_none());
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
    fn test_scan_exit_behavior_value_names() {
        use clap::ValueEnum;
        let names: Vec<String> = ScanExitBehavior::value_variants()
            .iter()
            .map(|v| {
                v.to_possible_value()
                    .expect("every variant has a name")
                    .get_name()
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec!["owned-only", "always", "never"]);
        assert_eq!(
            ScanExitBehavior::default(),
            ScanExitBehavior::OwnedOnly,
            "owned-only is the documented default"
        );
        assert_eq!(
            <ScanExitBehavior as ValueEnum>::from_str("always", false).unwrap(),
            ScanExitBehavior::Always
        );
        assert!(<ScanExitBehavior as ValueEnum>::from_str("maybe", false).is_err());
    }

    // Backend variants are feature-gated, so each assertion pair is gated with
    // the variant it names; otherwise these tests fail to compile in
    // single-backend builds.
    #[test]
    #[cfg(feature = "bluer")]
    fn test_backend_from_str_bluer() {
        assert_eq!(Backend::from_str("bluer").unwrap(), Backend::Bluer);
        assert_eq!(Backend::from_str("bluez").unwrap(), Backend::Bluer);
    }

    #[test]
    #[cfg(feature = "hci")]
    fn test_backend_from_str_hci() {
        assert_eq!(Backend::from_str("hci").unwrap(), Backend::Hci);
        assert_eq!(Backend::from_str("raw").unwrap(), Backend::Hci);
    }

    #[test]
    fn test_backend_from_str_rejects_unknown() {
        assert!(Backend::from_str("invalid").is_err());
    }

    #[test]
    #[cfg(feature = "bluer")]
    fn test_backend_display_bluer() {
        assert_eq!(format!("{}", Backend::Bluer), "bluer");
    }

    #[test]
    #[cfg(feature = "hci")]
    fn test_backend_display_hci() {
        assert_eq!(format!("{}", Backend::Hci), "hci");
    }
}
