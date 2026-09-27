//! The measurement field schema.
//!
//! Field names, output order, presence and unit conversions live here and
//! nowhere else. The schema is written once, in [`for_each_field`], and
//! expanded at each use site: the CSV header emits the names, the formatters
//! emit straight-line per-field code, and the drift guard below emits one
//! assertion per field. It is deliberately not a table of function pointers --
//! that turned every field into an indirect call the optimizer cannot inline,
//! worth double digits on the formatting hot path.

/// Every measurement field, in output order, written exactly once.
///
/// Expands to one `$mac!($name, $kind, $get)` per field, in statement
/// position, where:
///
/// * `$name` is the column name: the InfluxDB field key, the JSON key and the
///   CSV header cell,
/// * `$kind` is `scalar` or `vector`. A `vector` field is one component of the
///   acceleration vector, which the InfluxDB formatter writes last to preserve
///   its historical line layout (line protocol field order is not semantic);
///   the other formats write it in place. Callers with no opinion on the kind
///   match it as any identifier,
/// * `$get` is `|m: &Measurement| Option<T>`, extracting the value from a
///   measurement with the schema's unit conversions applied.
///
/// The per-field arguments are tokens, not values, so a caller that only wants
/// the names never compiles the extraction. A caller that uses `$get` needs
/// [`Measurement`](crate::measurement::Measurement) in scope.
// The list is laid out one field per line by hand: rustfmt would wrap the
// method chains mid-expression and the schema stops reading as a table.
#[rustfmt::skip]
macro_rules! for_each_field {
    ($mac:ident) => {
        $mac!("temperature", scalar, |m: &Measurement| m.temperature);
        $mac!("humidity", scalar, |m: &Measurement| m.humidity);
        // Pressure is stored in Pascals and written in kilopascals. This is
        // the one conversion; it used to be copy-pasted in every formatter.
        $mac!(
            "pressure",
            scalar,
            |m: &Measurement| m.pressure.map(|p| p / 1000.0)
        );
        $mac!("battery_potential", scalar, |m: &Measurement| m.battery);
        $mac!("tx_power", scalar, |m: &Measurement| m.tx_power.map(i64::from));
        $mac!("rssi", scalar, |m: &Measurement| m.rssi.map(i64::from));
        $mac!(
            "movement_counter",
            scalar,
            |m: &Measurement| m.movement_counter.map(i64::from)
        );
        $mac!(
            "measurement_sequence_number",
            scalar,
            |m: &Measurement| m.measurement_sequence.map(i64::from)
        );
        // The acceleration vector: one logical field, three columns.
        $mac!(
            "acceleration_x",
            vector,
            |m: &Measurement| m.acceleration.map(|(x, _, _)| x)
        );
        $mac!(
            "acceleration_y",
            vector,
            |m: &Measurement| m.acceleration.map(|(_, y, _)| y)
        );
        $mac!(
            "acceleration_z",
            vector,
            |m: &Measurement| m.acceleration.map(|(_, _, z)| z)
        );
        $mac!("pm1_0", scalar, |m: &Measurement| m.pm1_0);
        $mac!("pm2_5", scalar, |m: &Measurement| m.pm2_5);
        $mac!("pm4_0", scalar, |m: &Measurement| m.pm4_0);
        $mac!("pm10_0", scalar, |m: &Measurement| m.pm10_0);
        $mac!("co2", scalar, |m: &Measurement| m.co2);
        $mac!("voc_index", scalar, |m: &Measurement| m.voc_index);
        $mac!("nox_index", scalar, |m: &Measurement| m.nox_index);
        $mac!("luminosity", scalar, |m: &Measurement| m.luminosity);
    };
}

/// The one list of measurement fields, expanded by its caller. Re-exported
/// because a `macro_rules!` macro is otherwise only visible in the module that
/// defines it, and every formatter needs the schema.
pub(crate) use for_each_field;

#[cfg(test)]
mod tests {
    use crate::measurement::Measurement;
    use crate::test_utils::full_measurement;

    /// The shared test fixture is what makes the formatters' exact-output
    /// assertions cover every field, so a new schema entry without a matching
    /// fixture value has to fail here rather than quietly drop out of those
    /// assertions.
    #[test]
    fn full_measurement_populates_every_schema_field() {
        let m = full_measurement();
        macro_rules! populated {
            ($name:literal, $kind:ident, $get:expr) => {
                assert!(
                    ($get)(&m).is_some(),
                    "the shared test fixture leaves `{}` empty, so the exact-output \
                     tests do not cover it",
                    $name
                );
            };
        }
        for_each_field!(populated);
    }
}
