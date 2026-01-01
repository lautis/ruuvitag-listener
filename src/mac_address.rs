//! Efficient MAC address type for Bluetooth devices.
//!
//! This module provides a compact 6-byte MAC address representation that is
//! decoupled from any specific Bluetooth library.

use std::fmt;
use std::hash::Hash;
use std::str::FromStr;
use thiserror::Error;

/// A Bluetooth MAC address stored as a compact 6-byte array.
///
/// This type provides efficient storage and hashing for use as HashMap keys,
/// while being independent of any specific Bluetooth library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Errors returned when parsing a MAC address string.
#[derive(Error, Debug, PartialEq)]
pub enum ParseMacError {
    #[error("invalid MAC address: expected 6 parts, got {0}")]
    InvalidLength(usize),
    #[error("invalid MAC address: part {0} has wrong length")]
    InvalidPartLength(usize),
    #[error("invalid MAC address: '{0}' is not valid hex")]
    InvalidHex(String),
}

impl FromStr for MacAddress {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(ParseMacError::InvalidLength(parts.len()));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(ParseMacError::InvalidPartLength(i));
            }
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| ParseMacError::InvalidHex(part.to_string()))?;
        }

        Ok(MacAddress(bytes))
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

#[cfg(feature = "bluer")]
impl From<bluer::Address> for MacAddress {
    fn from(addr: bluer::Address) -> Self {
        Self(addr.0)
    }
}

#[cfg(feature = "bluer")]
impl From<MacAddress> for bluer::Address {
    fn from(addr: MacAddress) -> Self {
        bluer::Address(addr.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        let addr = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(format!("{}", addr), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_display_with_zeros() {
        let addr = MacAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(format!("{}", addr), "00:01:02:03:04:05");
    }

    #[test]
    fn test_from_str() {
        let addr: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(addr.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_from_str_lowercase() {
        let addr: MacAddress = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(addr.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_from_str_invalid() {
        assert!(matches!(
            "invalid".parse::<MacAddress>(),
            Err(ParseMacError::InvalidLength(1))
        ));
        assert!(matches!(
            "AA:BB:CC".parse::<MacAddress>(),
            Err(ParseMacError::InvalidLength(3))
        ));
        assert!(matches!(
            "AA:BB:CC:DD:EE:GG".parse::<MacAddress>(),
            Err(ParseMacError::InvalidHex(_))
        ));
    }

    #[test]
    fn test_hash_equality() {
        use std::collections::HashMap;

        let addr1 = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let addr2 = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let mut map = HashMap::new();
        map.insert(addr1, "test");

        assert_eq!(map.get(&addr2), Some(&"test"));
    }
}
