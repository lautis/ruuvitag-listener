# Publish Ruuvitag measurements via Telegraf

## Requirements

* [Telegraf](https://www.influxdata.com/time-series-platform/telegraf/)
* Linux with [systemd](https://www.freedesktop.org/wiki/Software/systemd/)
* ruuvitag-listener installed in `$PATH`

## Telegraf configuration

Copy the example configuration from [ruuvitag.conf](./ruuvitag.conf) and use values suitable for your setup.

The example uses [execd input](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/execd/README.md) to run ruuvitag-listener. Using `--alias` arguments, RuuviTag UUIDs can be replaced with more sensible tag names.

To take the in use, configure the output section to use your InfluxDB (or any other Telegraf output).

The alias mapping is at the end of the example configuration. Use your RuuviTag ids in the same format.

```
[[inputs.execd]]
  command = [
    "ruuvitag-listener",
    "--influxdb-measurement", "ruuvi_measurement",
    "--alias", "00:00:DE:AD:BE:EF=Kitchen",
    "--alias", "DE:AD:BE:EF:00:00=Sauna",
  ]
```

### Systemd services

Two services are needed: [ruuvitag-listener.service](./ruuvitag-listener.service) and [ruuvitag-telegraf.service](./ruuvitag-telegraf.services).

Copy these files to ~/.config/systemd/user` directory.

Then enable the services:

```
systemctl --user enable --now ruuvitag-telegraf.service
```

This starts pushing metrics to InfluxDB every 10 seconds.
