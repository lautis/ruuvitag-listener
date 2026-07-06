//! BlueZ D-Bus backend for RuuviTag scanning.
//!
//! This backend uses the `bluer` crate to communicate with the BlueZ daemon
//! via D-Bus. It requires the `bluetoothd` daemon to be running.

use super::{
    DecodeError, MEASUREMENT_CHANNEL_BUFFER_SIZE, MeasurementResult, RUUVI_MANUFACTURER_ID,
    ScanError, decode_ruuvi_data,
};
use crate::mac_address::MacAddress;
use bluer::{Adapter, Address, AdapterEvent, DiscoveryFilter, DiscoveryTransport, Session};
use futures::StreamExt;
use tokio::sync::mpsc;

impl From<bluer::Error> for ScanError {
    fn from(err: bluer::Error) -> Self {
        ScanError::Bluetooth(err.to_string())
    }
}

/// Start scanning for RuuviTag devices using the BlueZ D-Bus backend.
///
/// This function initializes the Bluetooth adapter and starts a passive scan
/// for RuuviTag advertisements. Discovered measurements are sent through the
/// returned channel. Runs indefinitely until interrupted.
///
/// # Arguments
/// * `verbose` - If true, decode errors are sent as Err values; otherwise they're silently dropped.
///
/// # Returns
/// A receiver for measurements (or decode errors if verbose).
pub async fn start_scan(verbose: bool) -> Result<mpsc::Receiver<MeasurementResult>, ScanError> {
    let session = Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    // Enable `duplicate_data` so BlueZ emits a PropertiesChanged signal for
    // *every* advertisement, not just the first one or when the payload
    // changes. Without this, BlueZ deduplicates repeated advertisements and we
    // receive only a fraction of the broadcasts a tool like `bluetoothctl`
    // shows. LE-only transport avoids spurious BR/EDR inquiry traffic.
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            duplicate_data: true,
            ..Default::default()
        })
        .await?;

    let (tx, rx) = mpsc::channel(MEASUREMENT_CHANNEL_BUFFER_SIZE);

    // `discover_devices_with_changes` re-emits a `DeviceAdded` event for a
    // device each time its properties change, giving us one notification per
    // advertisement. We filter for RuuviTag manufacturer data in
    // `process_device`.
    let mut events = adapter.discover_devices_with_changes().await?;

    // Spawn a task that owns all Bluetooth state and runs the event loop
    tokio::spawn(async move {
        // Keep the session alive by moving it into this task
        let _session = session;

        while let Some(event) = events.next().await {
            if let AdapterEvent::DeviceAdded(address) = event
                && let Err(e) = process_device(&adapter, address, &tx, verbose).await
                && verbose
            {
                let err = match e {
                    ScanError::Bluetooth(e) => {
                        DecodeError::InvalidData(format!("Bluetooth error: {e}"))
                    }
                    ScanError::Decode(e) => e,
                    ScanError::BackendNotAvailable(e) => {
                        DecodeError::InvalidData(format!("Backend not available: {e}"))
                    }
                };
                let _ = tx.send(Err(err)).await;
            }
        }
    });

    Ok(rx)
}

/// Process a discovered Bluetooth device and extract RuuviTag measurements.
///
/// This function attempts to read manufacturer data from the device and decode it
/// as a RuuviTag measurement. Results are sent through the provided channel.
async fn process_device(
    adapter: &Adapter,
    address: Address,
    tx: &mpsc::Sender<MeasurementResult>,
    verbose: bool,
) -> Result<(), ScanError> {
    let device = adapter.device(address)?;
    let mac: MacAddress = address.into();

    // Try to get manufacturer-specific data from the device
    let manufacturer_data = match device.manufacturer_data().await? {
        Some(data) => data,
        None => return Ok(()), // No manufacturer data available
    };

    // Extract RuuviTag data if present
    let ruuvi_data = match manufacturer_data.get(&RUUVI_MANUFACTURER_ID) {
        Some(data) => data,
        None => return Ok(()), // Not a RuuviTag device
    };

    // Decode and send the measurement
    match decode_ruuvi_data(mac, ruuvi_data) {
        Ok(measurement) => {
            let _ = tx.send(Ok(measurement)).await;
        }
        Err(e) if verbose => {
            let _ = tx.send(Err(e)).await;
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_to_mac_address() {
        let addr = Address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mac: MacAddress = addr.into();
        assert_eq!(mac, MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }
}
