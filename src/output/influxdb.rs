//! InfluxDB line protocol output formatter.

use crate::measurement::Measurement;
use crate::measurement::fields::for_each_field;
use crate::output::OutputFormatter;
use std::fmt;
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

    /// Write one present field, comma separated.
    #[inline]
    fn write_field(buf: &mut String, first: &mut bool, name: &str, v: impl fmt::Display) {
        if *first {
            *first = false;
        } else {
            buf.push(',');
        }
        let _ = write!(buf, "{}={}", name, v);
    }

    /// Write fields directly to the buffer (no intermediate BTreeMap).
    ///
    /// Only writes fields that have values, taking names and order from the
    /// measurement field schema. The acceleration components are written
    /// after the scalar fields: line protocol field order is not semantic and
    /// this is the line layout this formatter has always emitted. The schema
    /// list is walked twice, once for each kind, so the components still come
    /// out last without a second hand-kept list.
    #[inline]
    fn write_fields(buf: &mut String, m: &Measurement) {
        let mut first = true;
        macro_rules! scalar_field {
            ($name:literal, scalar, $get:expr) => {
                if let Some(v) = ($get)(m) {
                    Self::write_field(buf, &mut first, $name, v);
                }
            };
            ($name:literal, vector, $get:expr) => {};
        }
        macro_rules! vector_field {
            ($name:literal, scalar, $get:expr) => {};
            ($name:literal, vector, $get:expr) => {
                if let Some(v) = ($get)(m) {
                    Self::write_field(buf, &mut first, $name, v);
                }
            };
        }
        for_each_field!(scalar_field);
        for_each_field!(vector_field);
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
    use crate::test_utils::{
        TEST_MAC, base_measurement, full_measurement_extremes, test_timestamp,
    };

    #[test]
    fn writes_empty_measurement_name() {
        let formatter = InfluxDbFormatter::new("".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Device");

        // Empty measurement name should still produce valid line protocol
        // (starts with comma from tags)
        assert!(result.starts_with(","));
    }

    #[test]
    fn writes_empty_tag_value() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "");

        // Empty device name should still produce valid line protocol
        assert!(result.contains("name="));
    }

    #[test]
    fn escapes_tag_value_special_characters() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Room 1, Floor=2");

        // Should escape all special characters: space, comma, equals
        // "Room 1, Floor=2" becomes "Room\\ 1\\,\\ Floor\\=2"
        assert!(result.contains("name=Room\\ 1\\,\\ Floor\\=2"));
    }

    #[test]
    fn escapes_measurement_name_special_characters() {
        let formatter = InfluxDbFormatter::new("ruuvi tag, v2".to_string());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = base_measurement(TEST_MAC, timestamp);

        let result = formatter.format(&measurement, "Device");

        // Should escape spaces and commas in measurement name
        // "ruuvi tag, v2" becomes "ruuvi\\ tag\\,\\ v2" (space after comma is also escaped)
        assert!(result.starts_with("ruuvi\\ tag\\,\\ v2"));
    }

    // Exact lines pin what the assertions above skim over: field order,
    // separators, and the rendering of every value (including pm1_0, pm4_0
    // and pm10_0).

    #[test]
    fn writes_exact_line_with_all_fields() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let result = formatter.format(&full_measurement_extremes(), "Sauna");

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
    fn writes_exact_line_with_acceleration_only() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let mut measurement = base_measurement(TEST_MAC, test_timestamp());
        measurement.acceleration = Some((0.01, -0.02, 1.0));

        assert_eq!(
            formatter.format(&measurement, "Sauna"),
            "ruuvi,mac=AA:BB:CC:DD:EE:FF,name=Sauna acceleration_x=0.01,acceleration_y=-0.02,\
             acceleration_z=1\x201546681655691300729"
        );
    }

    #[test]
    fn writes_exact_line_without_fields() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string());
        let measurement = base_measurement(TEST_MAC, test_timestamp());

        // An empty field set leaves the space separator and the space before
        // the timestamp back to back. Pinned as-is.
        assert_eq!(
            formatter.format(&measurement, "Sauna"),
            "ruuvi,mac=AA:BB:CC:DD:EE:FF,name=Sauna\x20\x201546681655691300729"
        );
    }
}
