//! InfluxDB line protocol output formatter.

use crate::measurement::{Measurement, fields};
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
    /// Only writes fields that have values, taking names and order from the
    /// measurement field schema. The acceleration components are written
    /// after the scalar fields: line protocol field order is not semantic and
    /// this is the line layout this formatter has always emitted.
    #[inline]
    fn write_fields(buf: &mut String, m: &Measurement) {
        let mut first = true;
        for spec in fields::FIELDS
            .iter()
            .filter(|spec| !spec.vector)
            .chain(fields::FIELDS.iter().filter(|spec| spec.vector))
        {
            if let Some(v) = (spec.get)(m) {
                if first {
                    first = false;
                } else {
                    buf.push(',');
                }
                let _ = write!(buf, "{}={}", spec.name, v);
            }
        }
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
        measurement.rssi = Some(-63);
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
                "rssi=-63",
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

    fn full_measurement() -> Measurement {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_546_681_655_691_300_729);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.temperature = Some(19.63);
        measurement.humidity = Some(19.5);
        measurement.pressure = Some(101481.0);
        measurement.battery = Some(3.007);
        measurement.tx_power = Some(-128);
        measurement.rssi = Some(127);
        measurement.movement_counter = Some(4294967295);
        measurement.measurement_sequence = Some(1234);
        measurement.acceleration = Some((-0.055, -0.032, 0.998));
        measurement.pm1_0 = Some(5.5);
        measurement.pm2_5 = Some(12.5);
        measurement.pm4_0 = Some(8.2);
        measurement.pm10_0 = Some(15.1);
        measurement.co2 = Some(420.0);
        measurement.voc_index = Some(123.0);
        measurement.nox_index = Some(45.0);
        measurement.luminosity = Some(10.0);
        measurement
    }

    // Exact lines pin what the assertions above skim over: field order,
    // separators, and the rendering of every value (including pm1_0, pm4_0
    // and pm10_0).

    #[test]
    fn test_influxdb_formatter_exact_line() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let result = formatter.format(&full_measurement(), "Sauna");

        assert_eq!(
            result,
            "ruuvi,mac=AA:BB:CC:DD:EE:FF,name=Sauna temperature=19.63,humidity=19.5,\
             pressure=101.481,battery_potential=3.007,tx_power=-128,rssi=127,\
             movement_counter=4294967295,measurement_sequence_number=1234,pm1_0=5.5,\
             pm2_5=12.5,pm4_0=8.2,pm10_0=15.1,co2=420,voc_index=123,nox_index=45,\
             luminosity=10,acceleration_x=-0.055,acceleration_y=-0.032,acceleration_z=0.998\
             \x201546681655691300729"
        );
    }

    #[test]
    fn test_influxdb_formatter_exact_line_acceleration_only() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_546_681_655_691_300_729);
        let mut measurement = base_measurement(TEST_MAC, timestamp);
        measurement.acceleration = Some((0.01, -0.02, 1.0));

        assert_eq!(
            formatter.format(&measurement, "Sauna"),
            "ruuvi,mac=AA:BB:CC:DD:EE:FF,name=Sauna acceleration_x=0.01,acceleration_y=-0.02,\
             acceleration_z=1\x201546681655691300729"
        );
    }

    #[test]
    fn test_influxdb_formatter_exact_line_without_fields() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_546_681_655_691_300_729);
        let measurement = base_measurement(TEST_MAC, timestamp);

        // An empty field set leaves the space separator and the space before
        // the timestamp back to back. Pinned as-is.
        assert_eq!(
            formatter.format(&measurement, "Sauna"),
            "ruuvi,mac=AA:BB:CC:DD:EE:FF,name=Sauna\x20\x201546681655691300729"
        );
    }
}
