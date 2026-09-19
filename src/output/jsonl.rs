//! JSON Lines output formatter.

use crate::measurement::Measurement;
use crate::output::{OutputFormatter, format_timestamp_rfc3339};
use std::fmt::Write;

/// JSON Lines formatter.
///
/// Emits one JSON object per line, omitting fields that are absent from the
/// decoded measurement. The device name (alias or MAC) is provided by the
/// caller via the `format` method.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonLinesFormatter;

impl JsonLinesFormatter {
    /// Create a new JSON Lines formatter.
    pub fn new() -> Self {
        Self
    }

    /// Check if a string needs JSON escaping (fast path).
    ///
    /// Returns true if the string contains quotes, backslashes, or control
    /// characters.
    #[inline]
    fn needs_escape(s: &str) -> bool {
        s.bytes().any(|b| b < 0x20 || b == b'"' || b == b'\\')
    }

    /// Write a string as a JSON string literal, escaping when needed.
    ///
    /// MAC addresses (the common case) take the fast path unchanged.
    #[inline]
    fn write_string(buf: &mut String, s: &str) {
        buf.push('"');
        if Self::needs_escape(s) {
            // Slow path: escape special characters
            for ch in s.chars() {
                match ch {
                    '"' => buf.push_str("\\\""),
                    '\\' => buf.push_str("\\\\"),
                    '\n' => buf.push_str("\\n"),
                    '\r' => buf.push_str("\\r"),
                    '\t' => buf.push_str("\\t"),
                    '\u{08}' => buf.push_str("\\b"),
                    '\u{0C}' => buf.push_str("\\f"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(buf, "\\u{:04x}", c as u32);
                    }
                    c => buf.push(c),
                }
            }
        } else {
            // Fast path: no escaping needed, write directly
            buf.push_str(s);
        }
        buf.push('"');
    }

    /// Write measurement fields, omitting absent values.
    ///
    /// Field names and units match the InfluxDB line protocol output.
    #[inline]
    fn write_fields(buf: &mut String, m: &Measurement) {
        // MAC, name, format, and timestamp always precede the fields, so every
        // present field is written with a leading comma.
        macro_rules! write_field {
            ($key:literal, $val:expr) => {
                if let Some(v) = $val {
                    buf.push(',');
                    let _ = write!(buf, "{}:{}", $key, v);
                }
            };
        }

        write_field!("\"temperature\"", m.temperature);
        write_field!("\"humidity\"", m.humidity);
        write_field!("\"pressure\"", m.pressure.map(|p| p / 1000.0));
        write_field!("\"battery_potential\"", m.battery);
        write_field!("\"tx_power\"", m.tx_power);
        write_field!("\"rssi\"", m.rssi);
        write_field!("\"movement_counter\"", m.movement_counter);
        write_field!("\"measurement_sequence_number\"", m.measurement_sequence);
        if let Some((x, y, z)) = m.acceleration {
            let _ = write!(
                buf,
                ",\"acceleration_x\":{},\"acceleration_y\":{},\"acceleration_z\":{}",
                x, y, z
            );
        }
        write_field!("\"pm1_0\"", m.pm1_0);
        write_field!("\"pm2_5\"", m.pm2_5);
        write_field!("\"pm4_0\"", m.pm4_0);
        write_field!("\"pm10_0\"", m.pm10_0);
        write_field!("\"co2\"", m.co2);
        write_field!("\"voc_index\"", m.voc_index);
        write_field!("\"nox_index\"", m.nox_index);
        write_field!("\"luminosity\"", m.luminosity);
    }
}

impl OutputFormatter for JsonLinesFormatter {
    /// Format a measurement as a single-line JSON object.
    fn format(&self, m: &Measurement, name: &str) -> String {
        // MAC, name, format, and timestamp are always present; measurement
        // fields are appended only when present.
        let mut buf = String::with_capacity(160);
        buf.push_str("{\"mac\":");
        Self::write_string(&mut buf, &m.mac.to_string());
        buf.push_str(",\"name\":");
        Self::write_string(&mut buf, name);
        let _ = write!(buf, ",\"format\":\"{}\"", m.format.as_str());
        let _ = write!(
            buf,
            ",\"timestamp\":\"{}\"",
            format_timestamp_rfc3339(m.timestamp)
        );
        Self::write_fields(&mut buf, m);
        buf.push('}');
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TEST_MAC, base_measurement};
    use std::time::Duration;

    fn test_timestamp() -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH
            + Duration::from_secs(1_546_681_655)
            + Duration::from_nanos(691_300_729)
    }

    fn full_v5_measurement() -> Measurement {
        let mut m = base_measurement(TEST_MAC, test_timestamp());
        m.temperature = Some(19.63);
        m.humidity = Some(19.5);
        m.pressure = Some(101481.0);
        m.battery = Some(3.007);
        m.tx_power = Some(-4);
        m.rssi = Some(-63);
        m.movement_counter = Some(42);
        m.measurement_sequence = Some(1234);
        m.acceleration = Some((-0.055, -0.032, 0.998));
        m.pm1_0 = Some(5.5);
        m.pm2_5 = Some(12.5);
        m.pm4_0 = Some(8.2);
        m.pm10_0 = Some(15.1);
        m.co2 = Some(420.0);
        m.voc_index = Some(123.0);
        m.nox_index = Some(45.0);
        m.luminosity = Some(10.0);
        m
    }

    #[test]
    fn test_jsonl_formatter_basic() {
        let formatter = JsonLinesFormatter::new();
        let m = full_v5_measurement();
        let line = formatter.format(&m, &TEST_MAC.to_string());

        assert_eq!(
            line,
            "{\"mac\":\"AA:BB:CC:DD:EE:FF\",\"name\":\"AA:BB:CC:DD:EE:FF\",\"format\":\"v5\",\
             \"timestamp\":\"2019-01-05T09:47:35.691300729Z\",\"temperature\":19.63,\
             \"humidity\":19.5,\"pressure\":101.481,\"battery_potential\":3.007,\"tx_power\":-4,\
             \"rssi\":-63,\"movement_counter\":42,\"measurement_sequence_number\":1234,\
             \"acceleration_x\":-0.055,\"acceleration_y\":-0.032,\"acceleration_z\":0.998,\
             \"pm1_0\":5.5,\"pm2_5\":12.5,\"pm4_0\":8.2,\"pm10_0\":15.1,\"co2\":420,\
             \"voc_index\":123,\"nox_index\":45,\"luminosity\":10}"
        );
    }

    #[test]
    fn test_jsonl_formatter_omits_absent_fields() {
        let formatter = JsonLinesFormatter::new();
        let mut m = base_measurement(TEST_MAC, test_timestamp());
        m.temperature = Some(25.5);
        let line = formatter.format(&m, "Indoor");

        assert_eq!(
            line,
            "{\"mac\":\"AA:BB:CC:DD:EE:FF\",\"name\":\"Indoor\",\"format\":\"v5\",\
             \"timestamp\":\"2019-01-05T09:47:35.691300729Z\",\"temperature\":25.5}"
        );
    }

    #[test]
    fn test_jsonl_formatter_e1() {
        let formatter = JsonLinesFormatter::new();
        let mut m = base_measurement(TEST_MAC, test_timestamp());
        m.format = crate::Format::E1;
        m.pm2_5 = Some(12.5);
        m.co2 = Some(420.0);
        let line = formatter.format(&m, &TEST_MAC.to_string());

        assert!(line.contains("\"format\":\"e1\""));
        assert!(line.contains("\"pm2_5\":12.5"));
        assert!(line.contains("\"co2\":420"));
        assert!(!line.contains("humidity"));
    }

    #[test]
    fn test_jsonl_formatter_escapes_name() {
        let formatter = JsonLinesFormatter::new();
        let m = base_measurement(TEST_MAC, test_timestamp());
        let name = "Ali\"as\\name\n\t\u{1}";
        let line = formatter.format(&m, name);

        assert!(line.contains(r#""name":"Ali\"as\\name\n\t\u0001""#));
    }

    #[test]
    fn test_jsonl_formatter_utf8_name_preserved() {
        let formatter = JsonLinesFormatter::new();
        let m = base_measurement(TEST_MAC, test_timestamp());
        let line = formatter.format(&m, "Sauna ☀");

        assert!(line.contains("\"name\":\"Sauna ☀\""));
    }
}
