//! Raw HCI socket backend for RuuviTag scanning.
//!
//! This backend uses raw Linux HCI sockets to scan for BLE advertisements
//! without requiring the BlueZ daemon. It requires CAP_NET_RAW and
//! CAP_NET_ADMIN capabilities or root privileges.
//!
//! The implementation is organized into [`ffi`], [`bpf`], [`parse`], and
//! [`scan`] submodules.

use crate::scanner::RUUVI_MANUFACTURER_ID;
use libc::c_int;

mod bpf;
mod ffi;
mod parse;
mod scan;

pub use scan::start_scan;

// HCI protocol constants
const BTPROTO_HCI: c_int = 1;
const HCI_FILTER: c_int = 2;

// HCI packet types
const HCI_EVENT_PKT: u8 = 0x04;

// HCI events
const EVT_LE_META_EVENT: u8 = 0x3E;
const EVT_CMD_COMPLETE: u8 = 0x0E;

// LE Meta event sub-events
const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
const EVT_LE_EXTENDED_ADVERTISING_REPORT: u8 = 0x0D;

// HCI commands
const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = 0x0003;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
const OCF_LE_SET_EXTENDED_SCAN_PARAMETERS: u16 = 0x0041;
const OCF_LE_SET_EXTENDED_SCAN_ENABLE: u16 = 0x0042;

// HCI error codes
const HCI_ERR_COMMAND_DISALLOWED: u8 = 0x0c;

// LE feature bits (from LE Read Local Supported Features)
// Bit 12 (byte 1, bit 4) = LE Extended Advertising
const LE_FEATURE_EXTENDED_ADVERTISING_BYTE: usize = 1;
const LE_FEATURE_EXTENDED_ADVERTISING_BIT: u8 = 1 << 4;

// Scanning PHYs bitmask for extended scan (bit 0 = LE 1M PHY)
const LE_1M_PHY: u8 = 0x01;

// How long to wait for an HCI command's Command Complete event
const COMMAND_TIMEOUT_MS: u64 = 1000;

// Scan types
const LE_SCAN_PASSIVE: u8 = 0x00;

// Own address type
const LE_PUBLIC_ADDRESS: u8 = 0x00;

// Filter policy
const FILTER_POLICY_ACCEPT_ALL: u8 = 0x00;

// AD types
const AD_TYPE_MANUFACTURER_DATA: u8 = 0xFF;

// Ruuvi manufacturer ID as little-endian bytes for quick matching
const RUUVI_MANUFACTURER_ID_LE: [u8; 2] = [
    (RUUVI_MANUFACTURER_ID & 0xFF) as u8,
    (RUUVI_MANUFACTURER_ID >> 8) as u8,
];

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_H: u16 = 0x08; // Half-word (16-bit)
const BPF_B: u16 = 0x10; // Byte
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

/// Sysfs directory where the kernel exposes registered HCI controllers.
const HCI_SYSFS_CLASS: &str = "/sys/class/bluetooth";
