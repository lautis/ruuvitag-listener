//! The measurement field schema.
//!
//! Field names, output order, presence and unit conversions live here and
//! nowhere else. Adding, renaming or reordering an output field is done in
//! [`FIELDS`] only: the CSV header is derived from these names and every
//! formatter iterates the table, encoding nothing but its own syntax.

use super::Measurement;
use std::fmt;

/// A field value as rendered by the output formatters.
///
/// Rendering goes through [`Display`](fmt::Display) in every format, so an
/// integer prints the same whether a formatter used to write it as `f64`
/// (InfluxDB) or as `i8`/`u32` (JSON, CSV).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Field {
    /// A floating point value.
    F64(f64),
    /// An integer value (tx power, RSSI, counters).
    I64(i64),
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Field::F64(v) => write!(f, "{v}"),
            Field::I64(v) => write!(f, "{v}"),
        }
    }
}

/// One column of the measurement schema.
pub(crate) struct FieldSpec {
    /// Column name: the InfluxDB field key, the JSON key, and the CSV header
    /// cell.
    pub(crate) name: &'static str,
    /// Extract the value from a measurement, applying the schema's unit
    /// conversions.
    pub(crate) get: fn(&Measurement) -> Option<Field>,
    /// The column is a component of the acceleration vector: one logical
    /// field written as three columns. The InfluxDB formatter writes these
    /// last to preserve its historical line layout (line protocol field order
    /// is not semantic); the other formats write them in place.
    pub(crate) vector: bool,
}

/// A scalar column.
const fn scalar(name: &'static str, get: fn(&Measurement) -> Option<Field>) -> FieldSpec {
    FieldSpec {
        name,
        get,
        vector: false,
    }
}

/// A component of the acceleration vector (see [`FieldSpec::vector`]).
const fn vector(name: &'static str, get: fn(&Measurement) -> Option<Field>) -> FieldSpec {
    FieldSpec {
        name,
        get,
        vector: true,
    }
}

/// The measurement field schema in output order.
pub(crate) const FIELDS: &[FieldSpec] = &[
    scalar("temperature", |m| m.temperature.map(Field::F64)),
    scalar("humidity", |m| m.humidity.map(Field::F64)),
    // Pressure is stored in Pascals and written in kilopascals. This is the
    // one conversion; it used to be copy-pasted in every formatter.
    scalar("pressure", |m| m.pressure.map(|p| Field::F64(p / 1000.0))),
    scalar("battery_potential", |m| m.battery.map(Field::F64)),
    scalar("tx_power", |m| m.tx_power.map(|v| Field::I64(i64::from(v)))),
    scalar("rssi", |m| m.rssi.map(|v| Field::I64(i64::from(v)))),
    scalar("movement_counter", |m| {
        m.movement_counter.map(|v| Field::I64(i64::from(v)))
    }),
    scalar("measurement_sequence_number", |m| {
        m.measurement_sequence.map(|v| Field::I64(i64::from(v)))
    }),
    // The acceleration vector: one logical field, three columns.
    vector("acceleration_x", |m| {
        m.acceleration.map(|(x, _, _)| Field::F64(x))
    }),
    vector("acceleration_y", |m| {
        m.acceleration.map(|(_, y, _)| Field::F64(y))
    }),
    vector("acceleration_z", |m| {
        m.acceleration.map(|(_, _, z)| Field::F64(z))
    }),
    scalar("pm1_0", |m| m.pm1_0.map(Field::F64)),
    scalar("pm2_5", |m| m.pm2_5.map(Field::F64)),
    scalar("pm4_0", |m| m.pm4_0.map(Field::F64)),
    scalar("pm10_0", |m| m.pm10_0.map(Field::F64)),
    scalar("co2", |m| m.co2.map(Field::F64)),
    scalar("voc_index", |m| m.voc_index.map(Field::F64)),
    scalar("nox_index", |m| m.nox_index.map(Field::F64)),
    scalar("luminosity", |m| m.luminosity.map(Field::F64)),
];
