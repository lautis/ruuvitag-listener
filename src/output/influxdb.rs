//! InfluxDB line protocol output formatter.

use crate::measurement::Measurement;
use crate::output::OutputFormatter;
use std::collections::BTreeMap;
use std::fmt;
#[cfg(test)]
use std::time::Duration;
use std::time::SystemTime;

/// Field values for InfluxDB line protocol
#[derive(Debug, PartialEq)]
pub enum FieldValue {
    Float(f64),
    #[allow(dead_code)] // Used in tests
    String(String),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FieldValue::Float(num) => write!(f, "{num}"),
            FieldValue::String(s) => write!(f, "\"{s}\""),
        }
    }
}

/// Data point in InfluxDB line protocol
#[derive(Debug)]
pub struct DataPoint {
    pub measurement: String,
    pub tag_set: BTreeMap<String, String>,
    pub field_set: BTreeMap<String, FieldValue>,
    pub timestamp: Option<SystemTime>,
}

fn fmt_tags(data_point: &DataPoint, fmt: &mut fmt::Formatter) -> fmt::Result {
    for (key, value) in data_point.tag_set.iter() {
        write!(fmt, ",{}={}", key, value)?;
    }
    Ok(())
}

fn fmt_fields(data_point: &DataPoint, fmt: &mut fmt::Formatter) -> fmt::Result {
    let mut first = true;
    for (key, value) in data_point.field_set.iter() {
        if first {
            first = false;
        } else {
            write!(fmt, ",")?;
        }
        write!(fmt, "{}={}", key, value)?;
    }
    Ok(())
}

fn fmt_timestamp(data_point: &DataPoint, fmt: &mut fmt::Formatter) -> fmt::Result {
    if let Some(time) = data_point.timestamp {
        let nanos = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();
        write!(fmt, " {}", nanos)?;
    }
    Ok(())
}

impl fmt::Display for DataPoint {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.measurement)?;
        fmt_tags(self, fmt)?;
        write!(fmt, " ")?;
        fmt_fields(self, fmt)?;
        fmt_timestamp(self, fmt)
    }
}

/// InfluxDB line protocol formatter.
///
/// Formats measurements according to the InfluxDB line protocol specification.
/// Supports configurable measurement name and MAC address aliases.
pub struct InfluxDbFormatter {
    /// The measurement name in InfluxDB
    measurement_name: String,
    /// Aliases for MAC addresses (MAC -> human-readable name)
    aliases: BTreeMap<String, String>,
}

impl InfluxDbFormatter {
    /// Convert humidity from percent (0-100) to fraction (0-1).
    #[inline]
    fn humidity_fraction(percent: f64) -> f64 {
        percent / 100.0
    }

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
    pub fn new(measurement_name: String, aliases: BTreeMap<String, String>) -> Self {
        Self {
            measurement_name,
            aliases,
        }
    }

    /// Build the tag set for InfluxDB line protocol.
    ///
    /// Tags include the MAC address and a human-readable name (if an alias exists).
    fn tag_set(&self, measurement: &Measurement) -> BTreeMap<String, String> {
        let mut tags = BTreeMap::new();
        let address = &measurement.mac;
        tags.insert("mac".to_string(), address.clone());

        // Use alias if available, otherwise fall back to MAC address
        let name = self.aliases.get(address).unwrap_or(address);
        tags.insert("name".to_string(), name.clone());

        tags
    }

    /// Build the field set for InfluxDB line protocol.
    ///
    /// Only includes fields that have values (None fields are omitted).
    /// Performs unit conversions as needed (humidity to fraction, pressure to kPa).
    fn field_set(&self, m: &Measurement) -> BTreeMap<String, FieldValue> {
        let mut fields = BTreeMap::new();

        macro_rules! add {
            ($name:literal, $val:expr) => {
                if let Some(v) = $val {
                    fields.insert($name.into(), FieldValue::Float(v));
                }
            };
        }

        add!("temperature", m.temperature);
        add!("humidity", m.humidity.map(Self::humidity_fraction));
        add!("pressure", m.pressure.map(Self::pressure_kpa));
        add!("battery_potential", m.battery);
        add!("tx_power", m.tx_power.map(f64::from));
        add!("movement_counter", m.movement_counter.map(f64::from));
        add!(
            "measurement_sequence_number",
            m.measurement_sequence.map(f64::from)
        );

        if let Some((x, y, z)) = m.acceleration {
            fields.insert("acceleration_x".into(), FieldValue::Float(x));
            fields.insert("acceleration_y".into(), FieldValue::Float(y));
            fields.insert("acceleration_z".into(), FieldValue::Float(z));
        }

        fields
    }

    fn to_data_point(&self, measurement: &Measurement) -> DataPoint {
        DataPoint {
            measurement: self.measurement_name.clone(),
            tag_set: self.tag_set(measurement),
            field_set: self.field_set(measurement),
            timestamp: Some(measurement.timestamp),
        }
    }
}

impl OutputFormatter for InfluxDbFormatter {
    fn format(&self, measurement: &Measurement) -> String {
        format!("{}", self.to_data_point(measurement))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_value_display() {
        assert_eq!(format!("{}", FieldValue::Float(3.14)), "3.14");
        assert_eq!(
            format!("{}", FieldValue::String("test".to_string())),
            "\"test\""
        );
    }

    #[test]
    fn test_data_point_format() {
        let mut tags = BTreeMap::new();
        tags.insert("name".to_string(), "test".to_string());
        tags.insert("test".to_string(), "true".to_string());

        let mut fields = BTreeMap::new();
        fields.insert("temperature".to_string(), FieldValue::Float(32.0));
        fields.insert("humidity".to_string(), FieldValue::Float(0.2));

        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);

        let data_point = DataPoint {
            measurement: "test".to_string(),
            tag_set: tags,
            field_set: fields,
            timestamp: Some(time),
        };
        let result = format!("{}", data_point);

        assert_eq!(
            result,
            "test,name=test,test=true humidity=0.2,temperature=32 1000000000000000000"
        );
    }

    #[test]
    fn test_data_point_without_timestamp() {
        let tags = BTreeMap::new();
        let mut fields = BTreeMap::new();
        fields.insert(
            "value".to_string(),
            FieldValue::String("string,value".to_string()),
        );

        let data_point = DataPoint {
            measurement: "test".to_string(),
            tag_set: tags,
            field_set: fields,
            timestamp: None,
        };
        let result = format!("{}", data_point);
        assert_eq!(result, "test value=\"string,value\"");
    }

    #[test]
    fn test_influxdb_formatter_basic() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), BTreeMap::new());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = Measurement {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            timestamp,
            temperature: Some(25.5),
            humidity: Some(60.0),
            pressure: Some(101325.0),
            battery: Some(3.0),
            tx_power: Some(4),
            movement_counter: Some(10),
            measurement_sequence: Some(100),
            acceleration: Some((0.01, -0.02, 1.0)),
        };

        let result = formatter.format(&measurement);

        // Check that the result contains expected parts
        assert!(result.starts_with("ruuvi,"));
        assert!(result.contains("mac=AA:BB:CC:DD:EE:FF"));
        assert!(result.contains("temperature=25.5"));
        assert!(result.contains("humidity=0.6")); // 60% -> 0.6
        assert!(result.contains("pressure=101.325")); // Pa -> kPa
        assert!(result.contains("battery_potential=3"));
        assert!(result.contains("tx_power=4"));
        assert!(result.contains("movement_counter=10"));
        assert!(result.contains("measurement_sequence_number=100"));
        assert!(result.contains("acceleration_x=0.01"));
        assert!(result.contains("acceleration_y=-0.02"));
        assert!(result.contains("acceleration_z=1"));
        assert!(result.ends_with("1000000000000000000"));
    }

    #[test]
    fn test_influxdb_formatter_with_alias() {
        let mut aliases = BTreeMap::new();
        aliases.insert("AA:BB:CC:DD:EE:FF".to_string(), "Sauna".to_string());

        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), aliases);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = Measurement {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            timestamp,
            temperature: Some(80.0),
            humidity: None,
            pressure: None,
            battery: None,
            tx_power: None,
            movement_counter: None,
            measurement_sequence: None,
            acceleration: None,
        };

        let result = formatter.format(&measurement);

        assert!(result.contains("name=Sauna"));
        assert!(result.contains("mac=AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_influxdb_formatter_partial_data() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), BTreeMap::new());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = Measurement {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            timestamp,
            temperature: Some(25.5),
            humidity: None,
            pressure: None,
            battery: None,
            tx_power: None,
            movement_counter: None,
            measurement_sequence: None,
            acceleration: None,
        };

        let result = formatter.format(&measurement);

        assert!(result.contains("temperature=25.5"));
        assert!(!result.contains("humidity="));
        assert!(!result.contains("pressure="));
    }
}
