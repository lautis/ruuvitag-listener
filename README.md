# RuuviTag Listener

A command-line client to listen to [RuuviTag](https://ruuvi.com) Bluetooth LE sensor measurements and output using [InfluxDB line protocol](https://docs.influxdata.com/influxdb/v1.7/write_protocols/line_protocol_reference/).

The output could be e.g. piped to [Telegraf Socket Listener](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/socket_listener) with netcat. For an example setup, check out [examples/telegraf](./examples/telegraf/README.md).

## Requirements

* Linux with BlueZ bluetooth stack

## Usage

```sh
cargo install
sudo setcap 'cap_net_raw,cap_net_admin+eip' `which ruuvitag-listener`
ruuvitag-listener
```

Running `ruuvitag-listener` will output measurements to STDOUT until interrupted.

Example output:

```
ruuvi_measurement,name=F1:FC:AA:80:4E:59 battery_potential=2.977,humidity=20,pressure=102.675,temperature=19.45 1544980428505808227
ruuvi_measurement,name=F7:2A:60:0D:6E:1E battery_potential=3.007,humidity=19.5,pressure=102.623,temperature=19.43 1544980429956859088
ruuvi_measurement,name=F1:FC:AA:80:4E:59 battery_potential=2.977,humidity=20,pressure=102.675,temperature=19.45 1544980430517650108
ruuvi_measurement,name=F7:2A:60:0D:6E:1E battery_potential=3.013,humidity=19.5,pressure=102.624,temperature=19.43 1544980431970919680
ruuvi_measurement,name=F7:2A:60:0D:6E:1E battery_potential=3.013,humidity=19.5,pressure=102.624,temperature=19.43 1544980433981955612
ruuvi_measurement,name=F1:FC:AA:80:4E:59 battery_potential=2.971,humidity=20,pressure=102.675,temperature=19.45 1544980434537007732
ruuvi_measurement,name=F7:2A:60:0D:6E:1E battery_potential=3.007,humidity=19.5,pressure=102.624,temperature=19.43 1544980434984969861
```

## TODO

* Pre-built binaries
* Aliases for RuuviTags

## License

MIT
