//! `ruuvitag-listener` library.
//!
//! The binary (`src/main.rs`) is responsible for CLI parsing and process exit codes.
//! The core “business logic” lives in [`crate::app`] where it can be tested
//! deterministically with injected scanner + injected output streams.

pub mod alias;
pub mod app;
pub mod mac_address;
pub mod measurement;
pub mod output;
pub mod scanner;
pub mod throttle;

// Re-export commonly used types at the crate root
pub use alias::{Alias, AliasMap, parse_alias, to_map};
pub use mac_address::MacAddress;
pub use measurement::Measurement;
pub use output::OutputFormatter;
pub use output::influxdb::InfluxDbFormatter;
pub use scanner::{Backend, DecodeError, MeasurementResult, ScanError, decode_ruuvi_data};
pub use throttle::{Throttle, parse_duration};
