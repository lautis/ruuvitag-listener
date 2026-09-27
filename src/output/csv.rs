//! CSV output formatter.

use crate::measurement::Measurement;
use crate::measurement::fields::for_each_field;
use crate::output::{OutputFormatter, format_timestamp_rfc3339};
use std::fmt::Write;

/// Fixed columns preceding the schema fields. The rest of the header row is
/// derived from the measurement field schema.
const COLUMN_PREFIX: &str = "mac,name,timestamp,format";

/// CSV formatter.
///
/// Emits a header row once (via `header`) followed by one row per measurement.
/// Values absent from the decoded measurement are written as empty fields.
/// The device name (alias or MAC) is provided by the caller via the `format`
/// method.
#[derive(Debug, Default, Clone, Copy)]
pub struct CsvFormatter;

impl CsvFormatter {
    /// Create a new CSV formatter.
    pub fn new() -> Self {
        Self
    }

    /// Write a string as a CSV field, quoting when needed.
    ///
    /// Fields containing commas, quotes, or line breaks are wrapped in double
    /// quotes with embedded quotes doubled (RFC 4180).
    #[inline]
    fn write_field(buf: &mut String, s: &str) {
        let needs_quote = s.bytes().any(|b| matches!(b, b',' | b'"' | b'\n' | b'\r'));
        if needs_quote {
            buf.push('"');
            for ch in s.chars() {
                if ch == '"' {
                    buf.push('"');
                }
                buf.push(ch);
            }
            buf.push('"');
        } else {
            buf.push_str(s);
        }
    }

    /// Write measurement values in schema order, leaving absent values empty.
    #[inline]
    fn write_values(buf: &mut String, m: &Measurement) {
        macro_rules! value {
            ($name:literal, $kind:ident, $get:expr) => {
                buf.push(',');
                if let Some(v) = ($get)(m) {
                    let _ = write!(buf, "{v}");
                }
            };
        }
        for_each_field!(value);
    }
}

impl OutputFormatter for CsvFormatter {
    /// Format a measurement as a CSV row.
    fn format(&self, m: &Measurement, name: &str) -> String {
        let mut buf = String::with_capacity(160);
        let _ = write!(buf, "{}", m.mac);
        buf.push(',');
        Self::write_field(&mut buf, name);
        let _ = write!(
            buf,
            ",{},{}",
            format_timestamp_rfc3339(m.timestamp),
            m.format.as_str()
        );
        Self::write_values(&mut buf, m);
        buf
    }

    fn header(&self) -> Option<String> {
        let mut header = String::from(COLUMN_PREFIX);
        macro_rules! column {
            ($name:literal, $kind:ident, $get:expr) => {
                header.push(',');
                header.push_str($name);
            };
        }
        for_each_field!(column);
        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TEST_MAC, base_measurement, full_measurement, test_timestamp};

    #[test]
    fn test_csv_header_lists_all_columns() {
        let formatter = CsvFormatter::new();
        let header = formatter.header().unwrap();
        let columns: Vec<&str> = header.split(',').collect();

        assert_eq!(
            columns,
            vec![
                "mac",
                "name",
                "timestamp",
                "format",
                "temperature",
                "humidity",
                "pressure",
                "battery_potential",
                "tx_power",
                "rssi",
                "movement_counter",
                "measurement_sequence_number",
                "acceleration_x",
                "acceleration_y",
                "acceleration_z",
                "pm1_0",
                "pm2_5",
                "pm4_0",
                "pm10_0",
                "co2",
                "voc_index",
                "nox_index",
                "luminosity",
            ]
        );
    }

    #[test]
    fn test_csv_formatter_basic() {
        let formatter = CsvFormatter::new();
        let m = full_measurement();
        let row = formatter.format(&m, &TEST_MAC.to_string());
        let fields: Vec<&str> = row.split(',').collect();

        assert_eq!(
            fields,
            vec![
                "AA:BB:CC:DD:EE:FF",
                "AA:BB:CC:DD:EE:FF",
                "2019-01-05T09:47:35.691300729Z",
                "v5",
                "19.63",
                "19.5",
                "101.481",
                "3.007",
                "-4",
                "-63",
                "42",
                "1234",
                "-0.055",
                "-0.032",
                "0.998",
                "5.5",
                "12.5",
                "8.2",
                "15.1",
                "420",
                "123",
                "45",
                "10",
            ]
        );
    }

    #[test]
    fn test_csv_formatter_partial_data() {
        let formatter = CsvFormatter::new();
        let mut m = base_measurement(TEST_MAC, test_timestamp());
        m.temperature = Some(25.5);
        let row = formatter.format(&m, "Indoor");
        let fields: Vec<&str> = row.split(',').collect();

        assert_eq!(fields.len(), 23);
        assert_eq!(fields[0], "AA:BB:CC:DD:EE:FF");
        assert_eq!(fields[1], "Indoor");
        assert_eq!(fields[4], "25.5");
        // All measurement fields except temperature are empty.
        assert!(fields[5..].iter().all(|f| f.is_empty()));
    }

    #[test]
    fn test_csv_formatter_quotes_name_with_comma() {
        let formatter = CsvFormatter::new();
        let m = base_measurement(TEST_MAC, test_timestamp());
        let row = formatter.format(&m, "Indoor, A");

        assert!(row.contains(",\"Indoor, A\","));
    }

    #[test]
    fn test_csv_formatter_doubles_quotes_in_name() {
        let formatter = CsvFormatter::new();
        let m = base_measurement(TEST_MAC, test_timestamp());
        let row = formatter.format(&m, "He said \"hi\"");

        assert!(row.contains(",\"He said \"\"hi\"\"\","));
    }

    #[test]
    fn test_csv_formatter_quotes_name_with_line_break() {
        let formatter = CsvFormatter::new();
        let m = base_measurement(TEST_MAC, test_timestamp());
        let row = formatter.format(&m, "Sauna\nSuite");

        assert!(row.contains(",\"Sauna\nSuite\","));
    }
}
