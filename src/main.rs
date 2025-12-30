use clap::Parser;
use std::io::Write;
use std::panic::{self, PanicHookInfo};

mod measurement;
mod output;
mod scanner;

use measurement::Measurement;
use output::OutputFormatter;
use output::influxdb::InfluxDbFormatter;

/// A parsed alias mapping a MAC address to a human-readable name.
#[derive(Debug, Clone)]
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
        None => Err("invalid alias: expected format MAC=NAME".to_string()),
    }
}

fn alias_map(aliases: &[Alias]) -> BTreeMap<String, String> {
    aliases
        .iter()
        .map(|a| (a.address.clone(), a.name.clone()))
        .collect()
}

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
    let aliases = alias_map(&options.alias);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alias_valid() {
        let result = parse_alias("AA:BB:CC:DD:EE:FF=Kitchen");
        assert!(result.is_ok());
        let alias = result.unwrap();
        assert_eq!(alias.address, "AA:BB:CC:DD:EE:FF");
        assert_eq!(alias.name, "Kitchen");
    }

    #[test]
    fn test_parse_alias_with_spaces() {
        let result = parse_alias("AA:BB:CC:DD:EE:FF=Living Room");
        assert!(result.is_ok());
        let alias = result.unwrap();
        assert_eq!(alias.name, "Living Room");
    }

    #[test]
    fn test_parse_alias_invalid() {
        let result = parse_alias("no-equals-sign");
        assert!(result.is_err());
    }

    #[test]
    fn test_alias_map() {
        let aliases = vec![
            Alias {
                address: "AA:BB:CC:DD:EE:FF".to_string(),
                name: "Kitchen".to_string(),
            },
            Alias {
                address: "11:22:33:44:55:66".to_string(),
                name: "Bedroom".to_string(),
            },
        ];
        let map = alias_map(&aliases);
        assert_eq!(map.get("AA:BB:CC:DD:EE:FF"), Some(&"Kitchen".to_string()));
        assert_eq!(map.get("11:22:33:44:55:66"), Some(&"Bedroom".to_string()));
        assert_eq!(map.get("00:00:00:00:00:00"), None);
    }
}
