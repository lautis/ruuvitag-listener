//! Output formatters for RuuviTag measurements.
//!
//! This module provides a trait for formatting measurements and implementations
//! for various output formats: InfluxDB line protocol, JSON Lines, and CSV.

pub mod csv;
pub mod influxdb;
pub mod jsonl;

use std::time::{Duration, SystemTime};

use crate::measurement::Measurement;
use jiff::{Timestamp, tz::TimeZone};

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

    /// Optional one-line header written once before the first measurement.
    ///
    /// Formats with a fixed schema (e.g. CSV) return the header row. The default
    /// implementation returns `None`, meaning no header is written.
    fn header(&self) -> Option<String> {
        None
    }
}

/// Format a timestamp as RFC 3339 with fixed nanosecond precision in UTC.
///
/// A fixed-width subsecond part keeps lines lexicographically sortable and
/// preserves the nanosecond precision of the InfluxDB line protocol output.
/// Timestamps before the Unix epoch (system clock set before 1970-01-01) are
/// clamped to the epoch, matching the InfluxDB formatter.
pub(crate) fn format_timestamp_rfc3339(timestamp: SystemTime) -> String {
    let dur = timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    // Conversion fails only for clocks beyond jiff's ±9999 year range;
    // clamp those to the epoch as well.
    let ts = Timestamp::from_nanosecond(dur.as_nanos() as i128).unwrap_or(Timestamp::UNIX_EPOCH);
    let dt = ts.to_zoned(TimeZone::UTC).datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.subsec_nanosecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_epoch() {
        assert_eq!(
            format_timestamp_rfc3339(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00.000000000Z"
        );
    }

    #[test]
    fn clamps_pre_epoch_to_epoch() {
        let t = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(
            format_timestamp_rfc3339(t),
            "1970-01-01T00:00:00.000000000Z"
        );
    }

    #[test]
    fn formats_known_timestamp_with_nanoseconds() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_546_681_655_691_300_729);
        assert_eq!(
            format_timestamp_rfc3339(t),
            "2019-01-05T09:47:35.691300729Z"
        );
    }

    #[test]
    fn rolls_over_day_boundary() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(86_400) - Duration::from_nanos(1);
        assert_eq!(
            format_timestamp_rfc3339(t),
            "1970-01-01T23:59:59.999999999Z"
        );
    }
}
