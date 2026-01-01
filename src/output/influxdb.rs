//! InfluxDB line protocol output formatter.

use crate::alias::AliasMap;
use crate::measurement::Measurement;
use crate::output::OutputFormatter;
use std::fmt::Write;
use std::time::SystemTime;

#[cfg(test)]
use std::time::Duration;

/// InfluxDB line protocol formatter.
///
/// Formats measurements according to the InfluxDB line protocol specification.
/// Supports configurable measurement name and MAC address aliases.
///
/// Uses efficient `Address` keys for alias lookup (O(1) HashMap vs O(log n) BTreeMap),
/// and only formats addresses to strings during output generation.
pub struct InfluxDbFormatter {
    /// The measurement name in InfluxDB
    measurement_name: String,
    /// Aliases for MAC addresses (Address -> human-readable name)
    aliases: AliasMap,
}

impl InfluxDbFormatter {
    /// Convert pressure from Pascals to kilopascals.
    #[inline]
    fn pressure_kpa(pascals: f64) -> f64 {
        pascals / 1000.0
    }

    /// Create a new InfluxDB formatter.
    ///
    /// # Arguments
    /// * `measurement_name` - The measurement name to use in the line protocol
    /// * `aliases` - A map from MAC addresses to human-readable names
    pub fn new(measurement_name: String, aliases: AliasMap) -> Self {
        Self {
            measurement_name,
            aliases,
        }
    }

    /// Write tags directly to the buffer (no intermediate BTreeMap).
    ///
    /// Tags are written in a fixed order: mac, name.
    /// InfluxDB accepts tags in any order, so we don't need to sort.
    ///
    /// Note: `write!` to a `String` is infallible (only fails on OOM which panics anyway),
    /// so we use `let _ = ...` to explicitly ignore the Result.
    #[inline]
    fn write_tags(&self, buf: &mut String, m: &Measurement) {
        // Write mac tag
        let _ = write!(buf, ",mac={}", m.mac);

        // Write name tag (alias or MAC address)
        buf.push_str(",name=");
        if let Some(alias) = self.aliases.get(&m.mac) {
            buf.push_str(alias);
        } else {
            let _ = write!(buf, "{}", m.mac);
        }
    }

    /// Write fields directly to the buffer (no intermediate BTreeMap).
    ///
    /// Only writes fields that have values. Uses a macro to avoid code duplication.
    #[inline]
    fn write_fields(&self, buf: &mut String, m: &Measurement) {
        let mut first = true;

        // Macro to write a field if present, handling the comma separator.
        macro_rules! write_field {
            ($name:literal, $val:expr) => {
                if let Some(v) = $val {
                    if first {
                        first = false;
                    } else {
                        buf.push(',');
                    }
                    let _ = write!(buf, "{}={}", $name, v);
                }
            };
        }

        write_field!("temperature", m.temperature);
        write_field!("humidity", m.humidity);
        write_field!("pressure", m.pressure.map(Self::pressure_kpa));
        write_field!("battery_potential", m.battery);
        write_field!("tx_power", m.tx_power.map(f64::from));
        write_field!("movement_counter", m.movement_counter.map(f64::from));
        write_field!(
            "measurement_sequence_number",
            m.measurement_sequence.map(f64::from)
        );
        write_field!("pm2_5", m.pm2_5);
        write_field!("co2", m.co2);
        write_field!("voc_index", m.voc_index);
        write_field!("nox_index", m.nox_index);
        write_field!("luminosity", m.luminosity);

        // Handle acceleration tuple specially
        if let Some((x, y, z)) = m.acceleration {
            if first {
                first = false;
            } else {
                buf.push(',');
            }
            let _ = write!(
                buf,
                "acceleration_x={},acceleration_y={},acceleration_z={}",
                x, y, z
            );
        }
        let _ = first; // suppress unused warning
    }

    /// Write timestamp as nanoseconds since Unix epoch.
    ///
    /// If the timestamp is before Unix epoch (which shouldn't happen for sensor data),
    /// writes 0 as a safe fallback rather than panicking.
    #[inline]
    fn write_timestamp(buf: &mut String, timestamp: SystemTime) {
        let nanos = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let _ = write!(buf, " {}", nanos);
    }
}

impl OutputFormatter for InfluxDbFormatter {
    /// Format a measurement to InfluxDB line protocol.
    ///
    /// This implementation writes directly to a pre-sized buffer, avoiding
    /// intermediate allocations from BTreeMap and String clones.
    fn format(&self, m: &Measurement) -> String {
        // Pre-allocate buffer: measurement name + tags (~50 bytes) + fields (~200 bytes max)
        // + timestamp (~20 bytes) = ~270 bytes typical, 300 with headroom
        let mut buf = String::with_capacity(300);

        // Write measurement name (borrowed, no clone)
        buf.push_str(&self.measurement_name);

        // Write tags directly
        self.write_tags(&mut buf, m);

        // Space separator between tags and fields
        buf.push(' ');

        // Write fields directly
        self.write_fields(&mut buf, m);

        // Write timestamp
        Self::write_timestamp(&mut buf, m.timestamp);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TEST_MAC, base_measurement};
    use std::collections::HashMap;

    fn assert_contains_all(haystack: &str, needles: &[&str]) {
        for needle in needles {
            assert!(
                haystack.contains(needle),
                "expected output to contain {needle:?}\noutput: {haystack}"
            );
        }
    }

    #[test]
    fn test_influxdb_formatter_basic() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), HashMap::new());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.temperature = Some(25.5);
        measurement.humidity = Some(60.0);
        measurement.pressure = Some(101325.0);
        measurement.battery = Some(3.0);
        measurement.tx_power = Some(4);
        measurement.movement_counter = Some(10);
        measurement.measurement_sequence = Some(100);
        measurement.acceleration = Some((0.01, -0.02, 1.0));
        measurement.pm2_5 = Some(12.5);
        measurement.co2 = Some(420.0);
        measurement.voc_index = Some(123.0);
        measurement.nox_index = Some(45.0);
        measurement.luminosity = Some(10.0);

        let result = formatter.format(&measurement);

        // Check that the result contains expected parts
        assert!(result.starts_with("ruuvi,"));
        assert_contains_all(
            &result,
            &[
                "mac=AA:BB:CC:DD:EE:FF",
                "temperature=25.5",
                "humidity=60",      // 60%
                "pressure=101.325", // Pa -> kPa
                "battery_potential=3",
                "tx_power=4",
                "movement_counter=10",
                "measurement_sequence_number=100",
                "acceleration_x=0.01",
                "acceleration_y=-0.02",
                "acceleration_z=1",
                "pm2_5=12.5",
                "co2=420",
                "voc_index=123",
                "nox_index=45",
                "luminosity=10",
            ],
        );
        assert!(result.ends_with("1000000000000000000"));
    }

    #[test]
    fn test_influxdb_formatter_with_alias() {
        let mut aliases = HashMap::new();
        aliases.insert(TEST_MAC, "Sauna".to_string());

        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), aliases);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.temperature = Some(80.0);

        let result = formatter.format(&measurement);

        assert_contains_all(&result, &["name=Sauna", "mac=AA:BB:CC:DD:EE:FF"]);
    }

    #[test]
    fn test_influxdb_formatter_partial_data() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), HashMap::new());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.temperature = Some(25.5);

        let result = formatter.format(&measurement);

        assert!(result.contains("temperature=25.5"));
        assert!(!result.contains("humidity="));
        assert!(!result.contains("pressure="));
    }
}
