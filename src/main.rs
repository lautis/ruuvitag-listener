use clap::Parser;
use std::panic::{self, PanicHookInfo};

use ruuvitag_listener::app::{Options, RealScanner, RunError, run_with_io};

/// Exit codes for the application
const EXIT_SUCCESS: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_PANIC: i32 = 2;

/// Main application entry point that sets up scanning and output formatting.
///
/// This function:
/// 1. Converts CLI aliases into a lookup map
/// 2. Creates an InfluxDB formatter with the specified measurement name
/// 3. Optionally creates a throttle to limit event frequency per tag
/// 4. Starts the BLE scanner
/// 5. Processes measurements and outputs them to stdout until interrupted
///
/// # Arguments
/// * `options` - Command-line options parsed from user input
///
/// # Errors
/// Returns `ScanError` if Bluetooth initialization fails
async fn run(run_options: Options) -> Result<(), RunError> {
    let scanner = RealScanner;
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    run_with_io(run_options, &scanner, &mut out, &mut err).await
}

#[tokio::main(flavor = "current_thread")]
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
