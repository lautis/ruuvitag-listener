//! Raw HCI socket backend for RuuviTag scanning.
//!
//! This backend uses raw Linux HCI sockets to scan for BLE advertisements
//! without requiring the BlueZ daemon. It requires CAP_NET_RAW and
//! CAP_NET_ADMIN capabilities or root privileges.
//!
//! The implementation is organized into [`ffi`], [`bpf`], [`parse`], and
//! [`scan`] submodules.

use crate::scanner::RUUVI_MANUFACTURER_ID;

mod bpf;
mod ffi;
mod parse;
mod scan;

pub use scan::start_scan;

// Constants shared by more than one submodule live here; constants with a
// single consumer live in that consumer's module.

// HCI packet types
const HCI_EVENT_PKT: u8 = 0x04;

// HCI events and LE Meta sub-events
const EVT_LE_META_EVENT: u8 = 0x3E;
const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
const EVT_LE_EXTENDED_ADVERTISING_REPORT: u8 = 0x0D;

/// Maximum size of an HCI event delivered to userspace (HCI_MAX_EVENT_SIZE).
const HCI_EVENT_BUF_SIZE: usize = 258;

// Ruuvi manufacturer ID as little-endian bytes for quick matching
const RUUVI_MANUFACTURER_ID_LE: [u8; 2] = [
    (RUUVI_MANUFACTURER_ID & 0xFF) as u8,
    (RUUVI_MANUFACTURER_ID >> 8) as u8,
];
