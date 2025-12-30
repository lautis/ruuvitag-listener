use clap::Parser;
use std::io::Write;
use std::panic::{self, PanicHookInfo};

mod alias;
mod measurement;
mod output;
mod scanner;

use alias::{Alias, parse_alias};
use measurement::Measurement;
use output::OutputFormatter;
use output::influxdb::InfluxDbFormatter;

/// Exit codes for the application
const EXIT_SUCCESS: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_PANIC: i32 = 2;

#[derive(Parser, Debug)]
#[command(author, about, version)]
struct Options {
    /// The name of the measurement in InfluxDB line protocol.
    #[arg(long, default_value = "ruuvi_measurement")]
    influxdb_measurement: String,

    /// Specify human-readable alias for RuuviTag id.
    /// Format: --alias DE:AD:BE:EF:00:00=Sauna
    #[arg(long, value_parser = parse_alias)]
    alias: Vec<Alias>,

    /// Verbose output, print parse errors for unrecognized data
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

/// Print a formatted measurement to stdout.
///
/// # Arguments
/// * `formatter` - The formatter to use for converting the measurement to a string
/// * `measurement` - The measurement data to format and print
///
/// # Errors
/// Returns an `io::Error` if writing to stdout fails
fn print_measurement(
    formatter: &dyn OutputFormatter,
    measurement: &Measurement,
) -> std::io::Result<()> {
    let output = formatter.format(measurement);
    writeln!(std::io::stdout(), "{}", output)
}

/// Main application entry point that sets up scanning and output formatting.
///
/// This function:
/// 1. Converts CLI aliases into a lookup map
/// 2. Creates an InfluxDB formatter with the specified measurement name
/// 3. Starts the BLE scanner
/// 4. Processes measurements and outputs them to stdout until interrupted
///
/// # Arguments
/// * `options` - Command-line options parsed from user input
///
/// # Errors
/// Returns `ScanError` if Bluetooth initialization fails
async fn run(options: Options) -> Result<(), scanner::ScanError> {
    let aliases = alias::to_map(&options.alias);
    let formatter = InfluxDbFormatter::new(options.influxdb_measurement.clone(), aliases);

    let mut measurements = scanner::start_scan(options.verbose).await?;

    while let Some(result) = measurements.recv().await {
        match result {
            Ok(measurement) => {
                if let Err(error) = print_measurement(&formatter, &measurement) {
                    eprintln!("error: {}", error);
                    std::process::exit(EXIT_ERROR);
                }
            }
            Err(error) => {
                if options.verbose {
                    eprintln!("{}", error);
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    // Set up panic hook to ensure clean exit codes for process managers
    // (e.g., systemd, Telegraf execd) that monitor exit status
    panic::set_hook(Box::new(move |info: &PanicHookInfo| {
        eprintln!("Panic! {}", info);
        std::process::exit(EXIT_PANIC);
    }));

    let options = Options::parse();

    match run(options).await {
        Ok(_) => std::process::exit(EXIT_SUCCESS),
        Err(why) => {
            eprintln!("error: {}", why);
            std::process::exit(EXIT_ERROR);
        }
    }
}
