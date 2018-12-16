# RuuviTag Listener

A command-line client to legalisten to RuuviTag Bluetooth LE sensor measurements and output using [InfluxDB line protocol](https://docs.influxdata.com/influxdb/v1.7/write_protocols/line_protocol_reference/).

The output could be e.g. piped to [Telegraf Socket Listener](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/socket_listener) with netcat.

## Requirements

* Linux with BlueZ bluetooth stack

## Usage

```sh
cargo install
sudo ruuvitag-listener
```

## TODO

* Pre-built binaries
* Aliases for RuuviTags

## License

MIT
