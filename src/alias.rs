//! MAC address aliasing for RuuviTag devices.
//!
//! This module provides functionality to map MAC addresses to human-readable names,
//! making it easier to identify individual RuuviTag sensors in output.

use bluer::Address;
use std::collections::HashMap;

/// A type alias for MAC-to-name mappings using efficient Address keys.
pub type AliasMap = HashMap<Address, String>;

/// A parsed alias mapping a MAC address to a human-readable name.
#[derive(Debug, Clone)]
pub struct Alias {
    /// The MAC address as an efficient 6-byte array
    pub address: Address,
    /// The human-readable name (e.g., "Sauna")
    pub name: String,
}

/// Parse an alias from a string in the format "MAC=NAME".
///
/// # Arguments
/// * `src` - A string in the format "AA:BB:CC:DD:EE:FF=Name"
///
/// # Returns
/// A Result containing the parsed Alias or an error message.
///
/// # Example
/// ```
/// use ruuvitag_listener::alias::parse_alias;
///
/// let alias = parse_alias("AA:BB:CC:DD:EE:FF=Kitchen").unwrap();
/// assert_eq!(alias.address.to_string(), "AA:BB:CC:DD:EE:FF");
/// assert_eq!(alias.name, "Kitchen");
/// ```
pub fn parse_alias(src: &str) -> Result<Alias, String> {
    let (address_str, name) = src
        .split_once('=')
        .ok_or_else(|| "invalid alias: expected format MAC=NAME".to_string())?;

    let address: Address = address_str
        .parse()
        .map_err(|_| format!("invalid MAC address: {}", address_str))?;

    Ok(Alias {
        address,
        name: name.into(),
    })
}

/// Convert a slice of Alias values into an AliasMap.
///
/// # Arguments
/// * `aliases` - A slice of Alias structs
///
/// # Returns
/// A HashMap mapping MAC addresses to their human-readable names.
pub fn to_map(aliases: &[Alias]) -> AliasMap {
    aliases
        .iter()
        .map(|a| (a.address, a.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alias_valid() {
        let result = parse_alias("AA:BB:CC:DD:EE:FF=Kitchen");
        assert!(result.is_ok());
        let alias = result.unwrap();
        assert_eq!(alias.address, Address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        assert_eq!(alias.name, "Kitchen");
    }

    #[test]
    fn test_parse_alias_with_spaces() {
        let result = parse_alias("AA:BB:CC:DD:EE:FF=Living Room");
        assert!(result.is_ok());
        let alias = result.unwrap();
        assert_eq!(alias.name, "Living Room");
    }

    #[test]
    fn test_parse_alias_invalid_format() {
        let result = parse_alias("no-equals-sign");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_alias_invalid_mac() {
        let result = parse_alias("invalid-mac=Kitchen");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_map() {
        let aliases = vec![
            Alias {
                address: Address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                name: "Kitchen".to_string(),
            },
            Alias {
                address: Address([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                name: "Bedroom".to_string(),
            },
        ];
        let map = to_map(&aliases);
        assert_eq!(
            map.get(&Address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])),
            Some(&"Kitchen".to_string())
        );
        assert_eq!(
            map.get(&Address([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
            Some(&"Bedroom".to_string())
        );
        assert_eq!(
            map.get(&Address([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
            None
        );
    }
}
