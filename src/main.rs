extern crate rumble;
extern crate ruuvi_sensor_protocol;
extern crate structopt;

use std::collections::BTreeMap;
use std::io::Write;
use std::time::SystemTime;
use structopt::StructOpt;

pub mod ruuvi;
use ruuvi::{on_measurement, Measurement};

pub mod influxdb;
use influxdb::{DataPoint, FieldValue};

use std::alloc::System;

#[global_allocator]
static GLOBAL: System = System;

fn tag_set(measurement: &Measurement) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    tags.insert("name".to_string(), measurement.address.to_string());
    tags
}

macro_rules! to_float {
    ( $value: expr, $scale: expr ) => {{
        FieldValue::FloatValue(f64::from($value) / $scale)
    }};
}

macro_rules! add_value {
    ( $fields: ident, $value: expr, $field: expr, $scale: expr ) => {{
        if let Some(value) = $value {
            $fields.insert($field.to_string(), to_float!(value, $scale));
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

    if let Some(ref acceleration) = measurement.sensor_values.acceleration {
        fields.insert(
            "acceleration_x".to_string(),
            to_float!(acceleration.0, 1000.0),
        );
        fields.insert(
            "acceleration_y".to_string(),
            to_float!(acceleration.1, 1000.0),
        );
        fields.insert(
            "acceleration_z".to_string(),
            to_float!(acceleration.2, 1000.0),
        );
    }

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

fn listen() {
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

#[derive(Debug, StructOpt)]
#[structopt()]
struct Opt {}

fn main() {
    Opt::from_args();
    listen()
}
