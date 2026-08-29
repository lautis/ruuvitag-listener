//! CSV output formatter.

use crate::measurement::Measurement;
use crate::output::{OutputFormatter, format_timestamp_rfc3339};
use std::fmt::Write;

/// Column names. Field names and units match the InfluxDB line protocol
/// output and the JSON Lines field names.
const HEADER: &str = "mac,name,timestamp,format,temperature,humidity,pressure,battery_potential,\
tx_power,movement_counter,measurement_sequence_number,acceleration_x,acceleration_y,\
acceleration_z,pm1_0,pm2_5,pm4_0,pm10_0,co2,voc_index,nox_index,luminosity";

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

    /// Write measurement values, leaving absent values empty.
    #[inline]
    fn write_values(buf: &mut String, m: &Measurement) {
        macro_rules! write_value {
            ($val:expr) => {
                buf.push(',');
                if let Some(v) = $val {
                    let _ = write!(buf, "{}", v);
                }
            };
        }

        write_value!(m.temperature);
        write_value!(m.humidity);
        write_value!(m.pressure.map(|p| p / 1000.0));
        write_value!(m.battery);
        write_value!(m.tx_power);
        write_value!(m.movement_counter);
        write_value!(m.measurement_sequence);
        if let Some((x, y, z)) = m.acceleration {
            write_value!(Some(x));
            write_value!(Some(y));
            write_value!(Some(z));
        } else {
            write_value!(None::<f64>);
            write_value!(None::<f64>);
            write_value!(None::<f64>);
        }
        write_value!(m.pm1_0);
        write_value!(m.pm2_5);
        write_value!(m.pm4_0);
        write_value!(m.pm10_0);
        write_value!(m.co2);
        write_value!(m.voc_index);
        write_value!(m.nox_index);
        write_value!(m.luminosity);
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
        Some(HEADER.to_string())
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
        let m = full_v5_measurement();
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

        assert_eq!(fields.len(), 22);
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
