/// A measurement from a RuuviTag sensor.
///
/// All values are in standard SI units:
/// - Temperature in Celsius
/// - Humidity in percent (0-100)
/// - Pressure in Pascals
/// - Battery voltage in Volts
/// - TX power in dBm
/// - Acceleration in g (standard gravity)
#[derive(Debug, Clone, PartialEq)]
pub struct Measurement {
    /// MAC address of the RuuviTag
    pub mac: String,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_with_values() {
        let timestamp = std::time::SystemTime::now();
        let m = Measurement {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            timestamp,
            temperature: Some(25.5),
            humidity: Some(60.0),
            pressure: Some(101325.0),
            battery: Some(3.0),
            tx_power: Some(4),
            movement_counter: Some(10),
            measurement_sequence: Some(100),
            acceleration: Some((0.0, 0.0, 1.0)),
        };

        assert_eq!(m.timestamp, timestamp);
        assert_eq!(m.temperature, Some(25.5));
        assert_eq!(m.humidity, Some(60.0));
        assert_eq!(m.pressure, Some(101325.0));
        assert_eq!(m.battery, Some(3.0));
        assert_eq!(m.tx_power, Some(4));
        assert_eq!(m.movement_counter, Some(10));
        assert_eq!(m.measurement_sequence, Some(100));
        assert_eq!(m.acceleration, Some((0.0, 0.0, 1.0)));
    }

    #[test]
    fn test_measurement_clone() {
        let m1 = Measurement {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            temperature: Some(25.5),
            humidity: None,
            pressure: None,
            battery: None,
            tx_power: None,
            movement_counter: None,
            measurement_sequence: None,
            acceleration: None,
            timestamp: std::time::SystemTime::now(),
        };
        let m2 = m1.clone();
        assert_eq!(m1, m2);
    }
}
