# RuuviTag Listener

A command-line client to listen to [RuuviTag](https://ruuvi.com/ruuvitag/) and [Ruuvi Air](https://ruuvi.com/air/) sensor measurements over Bluetooth LE and output as [InfluxDB line protocol](https://docs.influxdata.com/influxdb/v1.7/write_protocols/line_protocol_reference/), JSON Lines, or CSV.

The listener understands RuuviTag data formats 3 (RAWv1), 5 (RAWv2), 6 (compact BLE 4 compatible), and E1 (Ruuvi Air). Once a device has been seen emitting E1, its V6 frames are dropped as redundant since V6 is a strict subset of E1.

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

### Adapter selection

By default, the BlueZ backend uses the system default adapter and the HCI backend uses `hci0`. To scan with a specific adapter, pass its kernel name with `--adapter`:

```sh
ruuvitag-listener --adapter hci1
```

Selecting an adapter that does not exist fails at startup with the list of available adapters.

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

On SIGINT (Ctrl-C) or SIGTERM the process shuts down gracefully: it asks the
scanner backend to stop scanning before exiting. The HCI backend sends the
`LE Set Scan Enable (disable)` command (closing the raw socket alone would
leave the adapter scanning), and the BlueZ backend ends its discovery session,
which makes BlueZ stop discovery on the adapter.

The adapter's scan state is global, so a scan started by another process
(bluetoothctl, bluetoothd discovery, a second listener) does not belong to the
listener. `--hci-scan-exit-behavior` controls what happens to it on exit:

| Behavior     | On exit                                                     |
| ------------ | ----------------------------------------------------------- |
| `owned-only` | Stop the scan only if this process started it (default)    |
| `always`     | Always stop the scan, including one another process started |
| `never`      | Never stop the scan; the adapter keeps scanning after exit  |

```sh
# This process owns the adapter: always leave it idle on exit
ruuvitag-listener --backend hci --hci-scan-exit-behavior always
```

Attaching to an existing scan replaces its parameters regardless of this
setting. On exit, the duplicate-filtering policy is the one parameter put back,
because HCI lets a client read it; the scan interval, window, address type and
filter policy stay as the listener set them, since there is no way to read those
back. Putting the policy back cycles the scan (one disable/enable round trip),
so the other process sees a brief gap. The option applies to the HCI backend
only.

### Upgrading from 0.8

A listener that attached to a scan another process owned used to disable that
scan when it exited. The default is now `--hci-scan-exit-behavior owned-only`,
which leaves it running; pass `always` to restore the old unconditional stop.

`Scanner::start_scan` takes a `ScanConfig` tuple instead of separate `backend`,
`verbose` and `adapter` arguments, so implementations of that trait need
updating.

Example output:

```
ruuvi_measurement,mac=F7:2A:60:0D:6E:1E,name=F7:2A:60:0D:6E:1E acceleration_x=-0.055,acceleration_y=-0.032,acceleration_z=0.998,battery_potential=3.007,humidity=19.5,pressure=101.481,rssi=-61,temperature=19.63 1546681652675044272
ruuvi_measurement,mac=F1:FC:AA:80:4E:59,name=F1:FC:AA:80:4E:59 acceleration_x=0.005,acceleration_y=0.015,acceleration_z=1.036,battery_potential=2.989,humidity=17.5,pressure=101.536,rssi=-54,temperature=21.97 1546681653451240083
ruuvi_measurement,mac=F1:FC:AA:80:4E:59,name=F1:FC:AA:80:4E:59 pm1_0=5.5,pm2_5=12.5,pm4_0=8.2,pm10_0=15.1,co2=420,voc_index=123,nox_index=45,luminosity=10,temperature=21.97 1546681654458923308
ruuvi_measurement,mac=F7:2A:60:0D:6E:1E,name=F7:2A:60:0D:6E:1E acceleration_x=-0.052,acceleration_y=-0.032,acceleration_z=1,battery_potential=3.013,humidity=19.5,pressure=101.481,rssi=-63,temperature=19.63 1546681655691300729
```

You can also define the InfluxDB measurement name or aliases using command line arguments. For example

```sh
ruuvitag-listener --influxdb-measurement=ruuvi --alias F1:FC:AA:80:4E:59=Indoor --alias F7:2A:60:0D:6E:1E=Outdoor
```

```
ruuvi,mac=F1:FC:AA:80:4E:59,name=Indoor acceleration_x=0,acceleration_y=0.017,acceleration_z=1.027,battery_potential=2.989,humidity=17.5,pressure=101.54,rssi=-58,temperature=21.97 1546681957964524841
ruuvi,mac=F7:2A:60:0D:6E:1E,name=Outdoor acceleration_x=-0.054,acceleration_y=-0.032,acceleration_z=1.005,battery_potential=3.013,humidity=83.5,pressure=101.487,rssi=-65,temperature=-5.63 1546681958085455294
```

## Output Formats

The output format is selected with `--format`:

| Format     | Description                                                       |
| ---------- | ----------------------------------------------------------------- |
| `influxdb` | InfluxDB line protocol (default)                                  |
| `jsonl`    | JSON Lines: one JSON object per line                              |
| `csv`      | CSV with a header row; values missing from the frame are left empty |

```sh
ruuvitag-listener --format jsonl
```

```
{"mac":"F1:FC:AA:80:4E:59","name":"Indoor","format":"v5","timestamp":"2019-01-05T09:47:35.691300729Z","temperature":21.97,"humidity":17.5,"pressure":101.536,"battery_potential":2.989,"rssi":-54,"acceleration_x":0.005,"acceleration_y":0.015,"acceleration_z":1.036}
```

JSON Lines omits fields that are absent from the advertisement.

```sh
ruuvitag-listener --format csv > measurements.csv
```

```
mac,name,timestamp,format,temperature,humidity,pressure,battery_potential,tx_power,rssi,movement_counter,measurement_sequence_number,acceleration_x,acceleration_y,acceleration_z,pm1_0,pm2_5,pm4_0,pm10_0,co2,voc_index,nox_index,luminosity
F1:FC:AA:80:4E:59,Indoor,2019-01-05T09:47:35.691300729Z,v5,21.97,17.5,101.536,2.989,,,,0.005,0.015,1.036,,,,,,,,
```

In JSON Lines and CSV output, timestamps are RFC 3339 in UTC and pressure is
reported in kilopascals, matching the InfluxDB line protocol output. The
`--influxdb-measurement` option only applies to `--format influxdb`.

All formats include the received signal strength `rssi` (in dBm) whenever the
Bluetooth adapter reports one; it is omitted from InfluxDB and JSON Lines lines
and left empty in CSV when unavailable.

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
