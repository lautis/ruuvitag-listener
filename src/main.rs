extern crate rumble;
extern crate ruuvi_sensor_protocol;

use std::collections::BTreeMap;
use std::io::Write;
use std::time::SystemTime;

pub mod ruuvi;
use ruuvi::{on_measurement, Measurement};

pub mod influxdb;
use influxdb::{DataPoint, FieldValue};

fn tag_set(measurement: &Measurement) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    tags.insert("name".to_string(), measurement.address.to_string());
    tags
}

macro_rules! add_value {
    ( $fields: ident, $value: expr, $field: expr, $scale: expr ) => {{
        if let Some(value) = $value {
            $fields.insert(
                $field.to_string(),
                FieldValue::FloatValue(f64::from(value) / $scale),
            );
        }
    }};
}

fn field_set(measurement: &Measurement) -> BTreeMap<String, FieldValue> {
    let mut fields = BTreeMap::new();
    add_value!(
        fields,
        measurement.sensor_values.temperature,
        "temperature",
        1000.0
    );
    add_value!(
        fields,
        measurement.sensor_values.humidity,
        "humidity",
        10000.0
    );
    add_value!(
        fields,
        measurement.sensor_values.pressure,
        "pressure",
        1000.0
    );
    add_value!(
        fields,
        measurement.sensor_values.battery_potential,
        "battery_potential",
        1000.0
    );
    fields
}

fn to_data_point(measurement: &Measurement) -> DataPoint {
    DataPoint {
        measurement: "ruuvi_measurement".to_string(),
        tag_set: tag_set(&measurement),
        field_set: field_set(&measurement),
        timestamp: Some(SystemTime::now()),
    }
}

fn main() {
    on_measurement(Box::new(move |measurement| {
        match writeln!(std::io::stdout(), "{}", to_data_point(&measurement)) {
            Ok(_) => (),
            Err(error) => {
                eprintln!("error: {}", error);
                ::std::process::exit(1);
            }
        }
    }));
}
