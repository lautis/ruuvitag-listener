//! InfluxDB line protocol output formatter.

use crate::alias::AliasMap;
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

    /// Build the tag set for InfluxDB line protocol.
    ///
    /// Tags include the MAC address and a human-readable name (if an alias exists).
    /// Address is formatted to string only here, at the output boundary.
    fn tag_set(&self, measurement: &Measurement) -> BTreeMap<String, String> {
        let mut tags = BTreeMap::new();
        let address = measurement.mac;
        let address_str = address.to_string();

        tags.insert("mac".to_string(), address_str.clone());

        // Use alias if available, otherwise fall back to MAC address string
        let name = self.aliases.get(&address).cloned().unwrap_or(address_str);
        tags.insert("name".to_string(), name);

        tags
    }

    /// Build the field set for InfluxDB line protocol.
    ///
    /// Only includes fields that have values (None fields are omitted).
    /// Performs unit conversions as needed (pressure to kPa).
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
        add!("humidity", m.humidity);
        add!("pressure", m.pressure.map(Self::pressure_kpa));
        add!("battery_potential", m.battery);
        add!("tx_power", m.tx_power.map(f64::from));
        add!("movement_counter", m.movement_counter.map(f64::from));
        add!(
            "measurement_sequence_number",
            m.measurement_sequence.map(f64::from)
        );
        add!("pm2_5", m.pm2_5);
        add!("co2", m.co2);
        add!("voc_index", m.voc_index);
        add!("nox_index", m.nox_index);
        add!("luminosity", m.luminosity);

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
    use crate::mac_address::MacAddress;
    use std::collections::HashMap;

    const TEST_MAC: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    #[test]
    fn test_field_value_display() {
        assert_eq!(format!("{}", FieldValue::Float(2.5)), "2.5");
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
        fields.insert("humidity".to_string(), FieldValue::Float(20.0));

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
            "test,name=test,test=true humidity=20,temperature=32 1000000000000000000"
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
        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), HashMap::new());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = Measurement {
            mac: TEST_MAC,
            timestamp,
            temperature: Some(25.5),
            humidity: Some(60.0),
            pressure: Some(101325.0),
            battery: Some(3.0),
            tx_power: Some(4),
            movement_counter: Some(10),
            measurement_sequence: Some(100),
            acceleration: Some((0.01, -0.02, 1.0)),
            pm2_5: Some(12.5),
            co2: Some(420.0),
            voc_index: Some(123.0),
            nox_index: Some(45.0),
            luminosity: Some(10.0),
        };

        let result = formatter.format(&measurement);

        // Check that the result contains expected parts
        assert!(result.starts_with("ruuvi,"));
        assert!(result.contains("mac=AA:BB:CC:DD:EE:FF"));
        assert!(result.contains("temperature=25.5"));
        assert!(result.contains("humidity=60")); // 60%
        assert!(result.contains("pressure=101.325")); // Pa -> kPa
        assert!(result.contains("battery_potential=3"));
        assert!(result.contains("tx_power=4"));
        assert!(result.contains("movement_counter=10"));
        assert!(result.contains("measurement_sequence_number=100"));
        assert!(result.contains("acceleration_x=0.01"));
        assert!(result.contains("acceleration_y=-0.02"));
        assert!(result.contains("acceleration_z=1"));
        assert!(result.contains("pm2_5=12.5"));
        assert!(result.contains("co2=420"));
        assert!(result.contains("voc_index=123"));
        assert!(result.contains("nox_index=45"));
        assert!(result.contains("luminosity=10"));
        assert!(result.ends_with("1000000000000000000"));
    }

    #[test]
    fn test_influxdb_formatter_with_alias() {
        let mut aliases = HashMap::new();
        aliases.insert(TEST_MAC, "Sauna".to_string());

        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), aliases);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = Measurement {
            mac: TEST_MAC,
            timestamp,
            temperature: Some(80.0),
            humidity: None,
            pressure: None,
            battery: None,
            tx_power: None,
            movement_counter: None,
            measurement_sequence: None,
            acceleration: None,
            pm2_5: None,
            co2: None,
            voc_index: None,
            nox_index: None,
            luminosity: None,
        };

        let result = formatter.format(&measurement);

        assert!(result.contains("name=Sauna"));
        assert!(result.contains("mac=AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_influxdb_formatter_partial_data() {
        let formatter = InfluxDbFormatter::new("ruuvi".to_string(), HashMap::new());
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000);
        let measurement = Measurement {
            mac: TEST_MAC,
            timestamp,
            temperature: Some(25.5),
            humidity: None,
            pressure: None,
            battery: None,
            tx_power: None,
            movement_counter: None,
            measurement_sequence: None,
            acceleration: None,
            pm2_5: None,
            co2: None,
            voc_index: None,
            nox_index: None,
            luminosity: None,
        };

        let result = formatter.format(&measurement);

        assert!(result.contains("temperature=25.5"));
        assert!(!result.contains("humidity="));
        assert!(!result.contains("pressure="));
    }
}
