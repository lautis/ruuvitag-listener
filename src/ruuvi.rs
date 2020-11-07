use btleplug::api::{BDAddr, Central, CentralEvent, Peripheral};
use btleplug::bluez::adapter::ConnectedAdapter;
use btleplug::bluez::manager::Manager;
use ruuvi_sensor_protocol::{ParseError, SensorValues};
use std::eprintln;
use std::sync::Arc;
use std::time::Duration;

// Measurement from RuuviTag sensor
#[derive(Debug)]
pub struct Measurement {
    pub address: BDAddr,
    pub sensor_values: SensorValues,
}

trait ToSensorValue {
    fn to_sensor_value(self) -> Result<SensorValues, ParseError>;
}

impl<T: Peripheral> ToSensorValue for T {
    fn to_sensor_value(self) -> Result<SensorValues, ParseError> {
        match self.properties().manufacturer_data {
            Some(data) => from_manufacturer_data(&data),
            None => Err(ParseError::EmptyValue),
        }
    }
}

fn from_manufacturer_data(data: &[u8]) -> Result<SensorValues, ParseError> {
    if data.len() > 2 {
        let id = u16::from(data[0]) + (u16::from(data[1]) << 8);
        SensorValues::from_manufacturer_specific_data(id, &data[2..])
    } else {
        Err(ParseError::EmptyValue)
    }
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
pub fn on_measurement(
    f: Box<dyn Fn(Result<Measurement, ParseError>) + Send>,
) -> Result<(), btleplug::Error> {
    let manager = Manager::new()?;

    // get bluetooth adapter
    let adapters = manager.adapters()?;

    let mut adapter = adapters
        .into_iter()
        .next()
        .expect("Bluetooth adapter not available");

    // clear out any errant state
    adapter = manager.down(&adapter)?;
    adapter = manager.up(&adapter)?;

    // connect to the adapter
    let central = Arc::new(adapter.connect()?);
    central.active(false);
    central.filter_duplicates(false);

    let closure_central = central.clone();
    let event_receiver = central.event_receiver().unwrap();

    loop {
        central.start_scan().unwrap();
        while let Ok(event) = event_receiver.recv_timeout(Duration::from_secs(60)) {
            if let Some(result) = on_event(&closure_central, event) {
                f(result)
            }
        }
        central.stop_scan()?;
    }
}
