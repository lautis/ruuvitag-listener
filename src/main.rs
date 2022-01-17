extern crate btleplug;
extern crate ruuvi_sensor_protocol;
extern crate clap;

use std::collections::BTreeMap;
use std::io::Write;
use std::panic::{self, PanicInfo};
use std::time::SystemTime;
use clap::Parser;

use crate::ruuvi_sensor_protocol::{
    Acceleration, BatteryPotential, Humidity, MeasurementSequenceNumber, MovementCounter, Pressure,
    Temperature, TransmitterPower,
};
pub mod ruuvi;
use ruuvi::{on_measurement, Measurement};

pub mod influxdb;
use influxdb::{DataPoint, FieldValue};

use btleplug::Error::PermissionDenied;

fn tag_set(
    aliases: &BTreeMap<String, String>,
    measurement: &Measurement,
) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    let address = measurement.address.to_string();
    tags.insert("mac".to_string(), address.to_string());
    tags.insert(
        "name".to_string(),
        aliases.get(&address).unwrap_or(&address).to_string(),
    );
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
        measurement.sensor_values.temperature_as_millicelsius(),
        "temperature",
        1000.0
    );
    add_value!(
        fields,
        measurement.sensor_values.humidity_as_ppm(),
        "humidity",
        10000.0
    );
    add_value!(
        fields,
        measurement.sensor_values.pressure_as_pascals(),
        "pressure",
        1000.0
    );
    add_value!(
        fields,
        measurement.sensor_values.battery_potential_as_millivolts(),
        "battery_potential",
        1000.0
    );

    add_value!(
        fields,
        measurement.sensor_values.tx_power_as_dbm(),
        "tx_power",
        1.0
    );

    add_value!(
        fields,
        measurement.sensor_values.movement_counter(),
        "movement_counter",
        1.0
    );

    add_value!(
        fields,
        measurement.sensor_values.measurement_sequence_number(),
        "measurement_sequence_number",
        1.0
    );

    if let Some(ref acceleration) = measurement.sensor_values.acceleration_vector_as_milli_g() {
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

fn to_data_point(
    aliases: &BTreeMap<String, String>,
    name: String,
    measurement: &Measurement,
) -> DataPoint {
    DataPoint {
        measurement: name,
        tag_set: tag_set(aliases, &measurement),
        field_set: field_set(&measurement),
        timestamp: Some(SystemTime::now()),
    }
}

#[derive(Debug)]
pub struct Alias {
    pub address: String,
    pub name: String,
}

fn parse_alias(src: &str) -> Result<Alias, String> {
    let index = src.find('=');
    match index {
        Some(i) => {
            let (address, name) = src.split_at(i);
            Ok(Alias {
                address: address.to_string(),
                name: name.get(1..).unwrap_or("").to_string(),
            })
        }
        None => Err("invalid alias".to_string()),
    }
}

fn alias_map(aliases: &[Alias]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for alias in aliases.iter() {
        map.insert(alias.address.to_string(), alias.name.to_string());
    }
    map
}

#[derive(Parser, Debug)]
#[clap(author, about, rename_all = "kebab-case")]
struct Options {
    #[clap(long, default_value = "ruuvi_measurement")]
    /// The name of the measurement in InfluxDB line protocol.
    influxdb_measurement: String,
    #[clap(long, parse(try_from_str = parse_alias))]
    /// Specify human-readable alias for RuuviTag id. For example --alias DE:AD:BE:EF:00:00=Sauna.
    alias: Vec<Alias>,
    /// Verbose output, print parse errors for unrecognized data
    #[clap(short = 'v', long = "verbose")]
    verbose: bool,
}

fn print_result(aliases: &BTreeMap<String, String>, name: &str, measurement: Measurement) {
    match writeln!(
        std::io::stdout(),
        "{}",
        to_data_point(&aliases, name.to_string(), &measurement)
    ) {
        Ok(_) => (),
        Err(error) => {
            eprintln!("error: {}", error);
            ::std::process::exit(1);
        }
    }
}

fn listen(options: Options) -> Result<(), btleplug::Error> {
    let name = options.influxdb_measurement;
    let aliases = alias_map(&options.alias);
    let verbose = options.verbose;
    on_measurement(Box::new(move |result| match result {
        Ok(measurement) => print_result(&aliases, &name, measurement),
        Err(error) => {
            if verbose {
                eprintln!("{}", error)
            }
        }
    }))
}

fn main() {
    panic::set_hook(Box::new(move |info: &PanicInfo| {
        eprintln!("Panic! {}", info);
        std::process::exit(0x2);
    }));
    let options = Options::parse();
    match listen(options) {
        Ok(_) => std::process::exit(0x0),
        Err(why) => {
            match why {
                PermissionDenied => println!("error: Permission Denied. Have you run setcap?"),
                _ => eprintln!("error: {}", why),
            }
            std::process::exit(0x1);
        }
    }
}
