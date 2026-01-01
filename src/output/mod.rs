//! Output formatters for RuuviTag measurements.
//!
//! This module provides a trait for formatting measurements and implementations
//! for various output formats. Currently supports InfluxDB line protocol, with
//! extensibility for future formats like JSON and CSV.

pub mod influxdb;

use crate::measurement::Measurement;

/// Trait for formatting measurements into output strings.
///
/// Implementations of this trait convert a `Measurement` into a formatted string
/// suitable for a specific output format (e.g., InfluxDB line protocol, JSON, CSV).
///
/// The `name` parameter is the resolved device name (either an alias or the MAC address),
/// determined by the caller. This keeps formatters simple and free of alias handling logic.
pub trait OutputFormatter: Send + Sync {
    /// Format a measurement.
    ///
    /// # Arguments
    /// * `measurement` - The measurement data to format (includes timestamp)
    /// * `name` - The resolved device name (alias or MAC address)
    ///
    /// # Returns
    /// A formatted string representation of the measurement
    fn format(&self, measurement: &Measurement, name: &str) -> String;
}
