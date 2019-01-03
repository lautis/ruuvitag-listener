# Publish Ruuvitag measurements via Telegraf

## Requirements

* [Telegraf](https://www.influxdata.com/time-series-platform/telegraf/)
* Linux with [systemd](https://www.freedesktop.org/wiki/Software/systemd/)
* OpenBSD netcat (package name is usually openbsd-netcat or netcat-openbsd)
* ruuvitag-listener installed in `$PATH`

## Telegraf configuration

Copy the example configuration from [ruuvitag.conf](./ruuvitag.conf) and use values suitable for your setup.

The uses [socket listener](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/socket_listener) to receive events. Using the configuration, the RuuviTag UUIDs can be replaced with more sensible tag names.

To take it in use, configure the output section to use your InfluxDB (or any other Telegraf output).

The RuuviTag id to name mapping is at the end of the file. use your ruuvitag ids in the same format.

```
[[processors.regex.tags]]
  key = "name"
  pattern = "^DE:AD:BE:EF:00:00$"
  replacement = "Sauna"
```

### Systemd services

Two services are needed: [ruuvitag-listener.service](./ruuvitag-listener.service) and [ruuvitag-telegraf.service](./ruuvitag-telegraf.services).

Copy these files to ~/.config/systemd/user` directory.

Then enable the services:

```
systemctl --user enable --now ruuvitag-listener.service
systemctl --user enable --now ruuvitag-telegraf.service
```

This starts pushing metrics to InfluxDB every 10 seconds.
