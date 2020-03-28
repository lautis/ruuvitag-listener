use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};

/// Field values for InfluxDB line protocol
#[derive(Debug)]
pub enum FieldValue {
    IntegerValue(i64),
    FloatValue(f64),
    StringValue(String),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            FieldValue::IntegerValue(num) => format!("{}", num),
            FieldValue::FloatValue(num) => format!("{}", num),
            FieldValue::StringValue(str) => format!("\"{}\"", str),
        };
        write!(fmt, "{}", value)
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
    if data_point.tag_set.is_empty() {
        Ok(())
    } else {
        for (key, value) in data_point.tag_set.iter() {
            write!(fmt, ",{}={}", key, value)?;
        }
        Ok(())
    }
}

fn fmt_fields(data_point: &DataPoint, fmt: &mut fmt::Formatter) -> fmt::Result {
    if data_point.field_set.is_empty() {
        Ok(())
    } else {
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
}

fn duration_as_nanos(duration: Duration) -> String {
    format!(
        "{}",
        u128::from(duration.as_secs()) * 1_000_000_000 + u128::from(duration.subsec_nanos())
    )
}

fn fmt_timestamp(data_point: &DataPoint, fmt: &mut fmt::Formatter) -> fmt::Result {
    match data_point.timestamp {
        Some(time) => {
            let duration = time
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards");
            write!(fmt, " {}", duration_as_nanos(duration))
        }
        None => Ok(()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_data_point() {
        let mut tags = BTreeMap::new();
        tags.insert("name".to_string(), "test".to_string());
        tags.insert("test".to_string(), "true".to_string());
        let mut fields = BTreeMap::new();
        fields.insert("temperature".to_string(), FieldValue::IntegerValue(32));
        fields.insert("humidity".to_string(), FieldValue::FloatValue(0.2));
        let time = SystemTime::now();

        let data_point = DataPoint {
            measurement: "test".to_string(),
            tag_set: tags,
            field_set: fields,
            timestamp: Some(time),
        };
        let result = format!("{}", data_point);

        assert_eq!(
            result,
            format!(
                "test,name=test,test=true humidity=0.2,temperature=32 {}",
                duration_as_nanos(time.duration_since(SystemTime::UNIX_EPOCH).unwrap())
            )
        );
    }

    #[test]
    fn escape_string() {
        let tags = BTreeMap::new();
        let mut fields = BTreeMap::new();
        fields.insert(
            "value".to_string(),
            FieldValue::StringValue("string,value".to_string()),
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
}
