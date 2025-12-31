# RuuviTag Listener

A command-line client to listen to [RuuviTag](https://ruuvi.com) sensor measurements over Bluetooth LE and output as [InfluxDB line protocol](https://docs.influxdata.com/influxdb/v1.7/write_protocols/line_protocol_reference/).

The listener understands RuuviTag data formats 5 and 6.

The output can be used in e.g. [Telegraf Execd Input](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/execd). For an example setup, check out [examples/telegraf](./examples/telegraf/README.md).

## Requirements

- RuuviTag Bluetooth sensor
- Linux with Bluetooth adapter

## Bluetooth Backends

Two Bluetooth backends are available:

### BlueZ (default)

Uses the BlueZ D-Bus API to communicate with the Bluetooth adapter. This is the default backend.

**Requirements:**
- BlueZ daemon (`bluetoothd`) running
- D-Bus
- Experimental features enabled in BlueZ (see [Troubleshooting](#troubleshooting))

**Usage:**
```sh
ruuvitag-listener --backend bluer
```

### HCI (raw sockets)

Uses raw HCI sockets for direct kernel access, bypassing BlueZ. Useful when BlueZ is unavailable or for minimal deployments.

**Requirements:**
- `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities, or root privileges
- BlueZ daemon might need to be stopped
- HCI device brought up manually

**Setup:**
```sh
# Set capabilities (must be re-run after each rebuild)
sudo setcap 'cap_net_admin,cap_net_raw+ep' ruuvitag-listener

# Stop BlueZ and bring up the device
sudo systemctl stop bluetooth
sudo hciconfig hci0 up

# Run with HCI backend
ruuvitag-listener --backend hci
```

### Building with a single backend

By default, all backends are compiled. To build with only the e.g. HCI backend (smaller binary, no D-Bus dependency):

```sh
cargo build --release --no-default-features --features hci
```

To build with only Bluer backend:

```sh
cargo build --release --no-default-features --features bluer
```

## Installation

Download binary from [releases](https://github.com/lautis/ruuvitag-listener/releases) to your $PATH.

Alternatively, install ruuvitag-listener using any of the following package managers:

| Distribution | Repository  | Instructions                                                 |
| ------------ | ----------- | ------------------------------------------------------------ |
| _Any_        | [Crates.io] | `cargo install ruuvitag-listener --locked`                   |
| Arch Linux   | [AUR]       | `yay -S ruuvitag-listener` or `yay -S ruuvitag-listener-bin` |

[AUR]: https://aur.archlinux.org/packages/ruuvitag-listener
[Crates.io]: https://crates.io/crates/ruuvitag-listener

## Usage

```sh
ruuvitag-listener
```

Running `ruuvitag-listener` will output measurements to STDOUT until interrupted.

Example output:

```
ruuvi_measurement,name=F7:2A:60:0D:6E:1E acceleration_x=-0.055,acceleration_y=-0.032,acceleration_z=0.998,battery_potential=3.007,humidity=19.5,pressure=101.481,temperature=19.63 1546681652675044272
ruuvi_measurement,name=F1:FC:AA:80:4E:59 acceleration_x=0.005,acceleration_y=0.015,acceleration_z=1.036,battery_potential=2.989,humidity=17.5,pressure=101.536,temperature=21.97 1546681653451240083
ruuvi_measurement,name=F1:FC:AA:80:4E:59 acceleration_x=0.002,acceleration_y=0.017,acceleration_z=1.032,battery_potential=2.977,humidity=17.5,pressure=101.536,temperature=21.97 1546681654458923308
ruuvi_measurement,name=F7:2A:60:0D:6E:1E acceleration_x=-0.052,acceleration_y=-0.032,acceleration_z=1,battery_potential=3.013,humidity=19.5,pressure=101.481,temperature=19.63 1546681655691300729
```

You can also define the InfluxDB measurement name or aliases using command line arguments. For example

```sh
ruuvitag-listener --influxdb-measurement=ruuvi --alias F1:FC:AA:80:4E:59=Indoor --alias F7:2A:60:0D:6E:1E=Outdoor
```

```
ruuvi,name=Indoor acceleration_x=0,acceleration_y=0.017,acceleration_z=1.027,battery_potential=2.989,humidity=17.5,pressure=101.54,temperature=21.97 1546681957964524841
ruuvi,name=Outdoor acceleration_x=-0.054,acceleration_y=-0.032,acceleration_z=1.005,battery_potential=3.013,humidity=83.5,pressure=101.487,temperature=-5.63 1546681958085455294
```

All options can be listed with `ruuvitag-listener --help`.

## Troubleshooting

### BlueZ backend: D-Bus errors

If you see errors related to D-Bus when using the BlueZ backend, you probably need to enable experimental features in bluetoothd. Add the following to `/etc/bluetooth/main.conf`:

```
[General]
Experimental = true
```

Then restart bluetoothd:

```sh
sudo systemctl restart bluetooth
```

### HCI backend: Permission denied

If you get "Operation not permitted" errors with the HCI backend, ensure capabilities are set:

```sh
sudo setcap 'cap_net_admin,cap_net_raw+ep' ruuvitag-listener
getcap ruuvitag-listener  # Verify: should show cap_net_admin,cap_net_raw=ep
```

### HCI backend: Network is down

If you get "Network is down" errors, the Bluetooth adapter needs to be brought up:

```sh
sudo systemctl stop bluetooth  # Stop BlueZ first
sudo hciconfig hci0 up         # Bring up the adapter
```

## Development

Use [cargo](https://doc.rust-lang.org/stable/cargo/) to build the project to target/debug directory:

```sh
cargo build
```

Tests can be run with

```sh
cargo test
```

## License

MIT
