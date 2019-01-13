use rumble::api::{BDAddr, Central, CentralEvent, Peripheral};
use rumble::bluez::adapter::ConnectedAdapter;
use rumble::bluez::manager::Manager;
use ruuvi_sensor_protocol::{ParseError, SensorValues};
use std::eprintln;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Measurement from RuuviTag sensor
#[derive(Debug)]
pub struct Measurement {
    pub address: BDAddr,
    pub sensor_values: SensorValues,
}

trait ToSensorValue {
    fn to_sensor_value(self: Self) -> Result<SensorValues, ParseError>;
}

impl<T: Peripheral> ToSensorValue for T {
    fn to_sensor_value(self: Self) -> Result<SensorValues, ParseError> {
        match self.properties().manufacturer_data {
            Some(data) => from_manufacturer_data(&data),
            None => Err(ParseError::EmptyValue),
        }
    }
}

fn from_manufacturer_data(data: &[u8]) -> Result<SensorValues, ParseError> {
    let id = u16::from(data[0]) + (u16::from(data[1]) << 8);
    SensorValues::from_manufacturer_specific_data(id, &data[2..])
}

fn on_event_with_address(
    central: &ConnectedAdapter,
    address: BDAddr,
) -> Option<Result<Measurement, ParseError>> {
    match central.peripheral(address) {
        Some(peripheral) => match peripheral.to_sensor_value() {
            Ok(sensor_values) => Some(Ok(Measurement {
                address,
                sensor_values,
            })),
            Err(error) => Some(Err(error)),
        },
        None => {
            eprintln!("Unknown device");
            None
        }
    }
}

fn on_event(
    central: &ConnectedAdapter,
    event: CentralEvent,
) -> Option<Result<Measurement, ParseError>> {
    match event {
        CentralEvent::DeviceDiscovered(address) => on_event_with_address(central, address),
        CentralEvent::DeviceLost(_) => None,
        CentralEvent::DeviceUpdated(address) => on_event_with_address(central, address),
        CentralEvent::DeviceConnected(_) => None,
        CentralEvent::DeviceDisconnected(_) => None,
    }
}

// Stream of RuuviTag measurements that gets passed to the given callback. Blocks and never stops.
pub fn on_measurement(f: Box<Fn(Measurement) + Send>) {
    let manager = Manager::new().unwrap();

    // get bluetooth adapter
    let adapters = manager.adapters().unwrap();
    let mut adapter = adapters.into_iter().nth(0).unwrap();

    // clear out any errant state
    adapter = manager.down(&adapter).unwrap();
    adapter = manager.up(&adapter).unwrap();

    // connect to the adapter
    let central = Arc::new(adapter.connect().unwrap());
    central.active(false);
    central.filter_duplicates(false);

    let closure_central = central.clone();
    let on_event_closure = Box::new(move |event| match on_event(&closure_central, event) {
        Some(Ok(value)) => f(value),
        Some(Err(_)) => {}
        None => {}
    });
    central.on_event(on_event_closure);

    // scan for tags, reset after 60 seconds
    loop {
        central.start_scan().unwrap();
        thread::sleep(Duration::from_secs(60));

        central.stop_scan().unwrap();
    }
}
