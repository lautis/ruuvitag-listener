//! InfluxDB line protocol output formatter.

use crate::measurement::Measurement;
use crate::output::OutputFormatter;
use std::fmt::Write;
use std::time::SystemTime;

#[cfg(test)]
use std::time::Duration;

/// InfluxDB line protocol formatter.
///
/// Formats measurements according to the InfluxDB line protocol specification.
/// The device name (alias or MAC) is provided by the caller via the `format` method.
pub struct InfluxDbFormatter {
    /// The measurement name in InfluxDB
    measurement_name: String,
    /// Whether the measurement name needs escaping (precomputed at initialization)
    needs_measurement_escape: bool,
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
    pub fn new(measurement_name: String) -> Self {
        let needs_escape = Self::needs_measurement_escape(&measurement_name);
        Self {
            measurement_name,
            needs_measurement_escape: needs_escape,
        }
    }

    /// Check if a measurement name needs escaping (fast path).
    ///
    /// Returns true if the string contains commas or spaces.
    #[inline]
    fn needs_measurement_escape(s: &str) -> bool {
        s.bytes().any(|b| b == b',' || b == b' ')
    }

    /// Check if a tag value needs escaping (fast path).
    ///
    /// Returns true if the string contains commas, equals signs, or spaces.
    #[inline]
    fn needs_tag_escape(s: &str) -> bool {
        s.bytes().any(|b| b == b',' || b == b'=' || b == b' ')
    }

    /// Write measurement name to buffer, escaping if needed.
    ///
    /// Escapes commas and spaces with backslashes.
    /// Measurement names must escape: `,` → `\,`, ` ` → `\ `
    ///
    /// # Arguments
    /// * `buf` - The buffer to write to
    /// * `s` - The measurement name string
    /// * `needs_escape` - Whether escaping is needed (precomputed)
    #[inline]
    fn write_measurement_name(buf: &mut String, s: &str, needs_escape: bool) {
        if needs_escape {
            // Slow path: escape special characters
            for ch in s.chars() {
                match ch {
                    ',' => buf.push_str("\\,"),
                    ' ' => buf.push_str("\\ "),
                    _ => buf.push(ch),
                }
            }
        } else {
            // Fast path: no escaping needed, write directly
            buf.push_str(s);
        }
    }

    /// Write tag value to buffer, escaping if needed.
    ///
    /// Escapes commas, equals signs, and spaces with backslashes.
    /// Tag values must escape: `,` → `\,`, `=` → `\=`, ` ` → `\ `
    #[inline]
    fn write_tag_value(buf: &mut String, s: &str) {
        if Self::needs_tag_escape(s) {
            // Slow path: escape special characters
            for ch in s.chars() {
                match ch {
                    ',' => buf.push_str("\\,"),
                    '=' => buf.push_str("\\="),
                    ' ' => buf.push_str("\\ "),
                    _ => buf.push(ch),
                }
            }
        } else {
            // Fast path: no escaping needed, write directly
            buf.push_str(s);
        }
    }

    /// Write tags directly to the buffer (no intermediate BTreeMap).
    ///
    /// Tags are written in a fixed order: mac, name.
    /// InfluxDB accepts tags in any order, so we don't need to sort.
    ///
    /// Tag values are escaped according to InfluxDB line protocol rules.
    ///
    /// Note: `write!` to a `String` is infallible (only fails on OOM which panics anyway),
    /// so we use `let _ = ...` to explicitly ignore the Result.
    #[inline]
    fn write_tags(buf: &mut String, m: &Measurement, name: &str) {
        // Write mac tag (MAC addresses are safe - format is AA:BB:CC:DD:EE:FF)
        let _ = write!(buf, ",mac={}", m.mac);

        // Write name tag (resolved by caller) - escape special characters if needed
        buf.push_str(",name=");
        Self::write_tag_value(buf, name);
    }

    /// Write fields directly to the buffer (no intermediate BTreeMap).
    ///
    /// Only writes fields that have values. Uses a macro to avoid code duplication.
    #[inline]
    fn write_fields(buf: &mut String, m: &Measurement) {
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
    fn format(&self, m: &Measurement, name: &str) -> String {
        // Pre-allocate buffer: measurement name + tags (~50 bytes) + fields (~200 bytes max)
        // + timestamp (~20 bytes) = ~270 bytes typical, 300 with headroom
        let mut buf = String::with_capacity(300);

        // Write measurement name (escaped according to InfluxDB rules if needed)
        // Use precomputed escape flag to avoid checking on every format call
        Self::write_measurement_name(
            &mut buf,
            &self.measurement_name,
            self.needs_measurement_escape,
        );

        // Write tags directly
        Self::write_tags(&mut buf, m, name);

        // Space separator between tags and fields
        buf.push(' ');

        // Write fields directly
        Self::write_fields(&mut buf, m);

        // Write timestamp
        Self::write_timestamp(&mut buf, m.timestamp);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TEST_MAC, base_measurement};

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
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
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

        let result = formatter.format(&measurement, "AA:BB:CC:DD:EE:FF");

        // Check that the result contains expected parts
        assert!(result.starts_with("ruuvi,"));
        assert_contains_all(
            &result,
            &[
                "mac=AA:BB:CC:DD:EE:FF",
                "name=AA:BB:CC:DD:EE:FF",
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
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.temperature = Some(80.0);

        // Name is now passed by caller (alias resolved at app layer)
        let result = formatter.format(&measurement, "Sauna");

        assert_contains_all(&result, &["name=Sauna", "mac=AA:BB:CC:DD:EE:FF"]);
    }

    #[test]
    fn test_influxdb_formatter_partial_data() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.temperature = Some(25.5);

        let result = formatter.format(&measurement, "AA:BB:CC:DD:EE:FF");

        assert!(result.contains("temperature=25.5"));
        assert!(!result.contains("humidity="));
        assert!(!result.contains("pressure="));
    }

    #[test]
    fn test_measurement_name_with_space() {
        let formatter = InfluxDbFormatter::new("ruuvi tag".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Device");

        // InfluxDB requires spaces in measurement names to be escaped as \
        assert!(result.starts_with("ruuvi\\ tag"));
    }

    #[test]
    fn test_measurement_name_with_comma() {
        let formatter = InfluxDbFormatter::new("ruuvi,tag".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Device");

        // InfluxDB requires commas in measurement names to be escaped as \,
        assert!(result.starts_with("ruuvi\\,tag"));
    }

    #[test]
    fn test_device_name_with_space() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Living Room");

        // InfluxDB requires spaces in tag values to be escaped as \
        assert!(result.contains("name=Living\\ Room"));
    }

    #[test]
    fn test_device_name_with_comma() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Kitchen, Upstairs");

        // InfluxDB requires commas and spaces in tag values to be escaped
        // "Kitchen, Upstairs" becomes "Kitchen\\,\\ Upstairs"
        assert!(result.contains("name=Kitchen\\,\\ Upstairs"));
    }

    #[test]
    fn test_device_name_with_equals() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "tag=value");

        // InfluxDB requires equals signs in tag values to be escaped as \=
        assert!(result.contains("name=tag\\=value"));
    }

    #[test]
    fn test_empty_measurement_name() {
        let formatter = InfluxDbFormatter::new("".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Device");

        // Empty measurement name should still produce valid line protocol
        // (starts with comma from tags)
        assert!(result.starts_with(","));
    }

    #[test]
    fn test_empty_device_name() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "");

        // Empty device name should still produce valid line protocol
        assert!(result.contains("name="));
    }

    #[test]
    fn test_device_name_with_multiple_special_chars() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Room 1, Floor=2");

        // Should escape all special characters: space, comma, equals
        // "Room 1, Floor=2" becomes "Room\\ 1\\,\\ Floor\\=2"
        assert!(result.contains("name=Room\\ 1\\,\\ Floor\\=2"));
    }

    #[test]
    fn test_measurement_name_with_multiple_special_chars() {
        let formatter = InfluxDbFormatter::new("ruuvi tag, v2".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Device");

        // Should escape spaces and commas in measurement name
        // "ruuvi tag, v2" becomes "ruuvi\\ tag\\,\\ v2" (space after comma is also escaped)
        assert!(result.starts_with("ruuvi\\ tag\\,\\ v2"));
    }
}
