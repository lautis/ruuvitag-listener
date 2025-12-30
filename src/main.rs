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

fn print_measurement(formatter: &dyn OutputFormatter, measurement: &Measurement) -> io::Result<()> {
    let output = formatter.format(measurement);
    writeln!(std::io::stdout(), "{}", output)
}

async fn run(options: Options) -> Result<(), scanner::ScanError> {
    let aliases = alias::to_map(&options.alias);
    let formatter = InfluxDbFormatter::new(options.influxdb_measurement.clone(), aliases);

    let mut measurements = scanner::start_scan(options.verbose).await?;

    while let Some(result) = measurements.recv().await {
        match result {
            Ok(measurement) => {
                if let Err(error) = print_measurement(&formatter, &measurement) {
                    eprintln!("error: {}", error);
                    std::process::exit(1);
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
    panic::set_hook(Box::new(move |info: &PanicHookInfo| {
        eprintln!("Panic! {}", info);
        std::process::exit(0x2);
    }));

    let options = Options::parse();

    match run(options).await {
        Ok(_) => std::process::exit(0x0),
        Err(why) => {
            eprintln!("error: {}", why);
            std::process::exit(0x1);
        }
    }
}
