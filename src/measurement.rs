//! RuuviTag measurement data structure.

use crate::mac_address::MacAddress;

/// A measurement from a RuuviTag sensor.
///
/// All values are in standard SI units:
/// - Temperature in Celsius
/// - Humidity in percent (0-100)
/// - Pressure in Pascals
/// - Battery voltage in Volts
/// - TX power in dBm
/// - Acceleration in g (standard gravity)
/// - PM2.5 in micrograms per cubic meter (ug/m3)
/// - CO2 in parts per million (ppm)
/// - VOC/NOx indexes are unitless scores
/// - Luminosity in lux
#[derive(Debug, Clone, PartialEq)]
pub struct Measurement {
    /// MAC address of the RuuviTag (stored as efficient 6-byte array)
    pub mac: MacAddress,
    /// Timestamp when the measurement was taken
    pub timestamp: std::time::SystemTime,
    /// Temperature in Celsius
    pub temperature: Option<f64>,
    /// Relative humidity in percent (0-100)
    pub humidity: Option<f64>,
    /// Atmospheric pressure in Pascals
    pub pressure: Option<f64>,
    /// Battery voltage in Volts
    pub battery: Option<f64>,
    /// TX power in dBm
    pub tx_power: Option<i8>,
    /// Movement counter
    pub movement_counter: Option<u32>,
    /// Measurement sequence number
    pub measurement_sequence: Option<u32>,
    /// Acceleration vector (x, y, z) in g
    pub acceleration: Option<(f64, f64, f64)>,
    /// Particulate matter (PM2.5) concentration in ug/m3
    pub pm2_5: Option<f64>,
    /// Carbon dioxide concentration in ppm
    pub co2: Option<f64>,
    /// Volatile organic compound index
    pub voc_index: Option<f64>,
    /// Nitrogen oxides index
    pub nox_index: Option<f64>,
    /// Ambient luminosity in lux
    pub luminosity: Option<f64>,
}
