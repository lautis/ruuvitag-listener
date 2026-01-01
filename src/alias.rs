//! MAC address aliasing for RuuviTag devices.
//!
//! This module provides functionality to map MAC addresses to human-readable names,
//! making it easier to identify individual RuuviTag sensors in output.

use crate::mac_address::MacAddress;
use std::collections::HashMap;

/// A type alias for MAC-to-name mappings using efficient MacAddress keys.
pub type AliasMap = HashMap<MacAddress, String>;

/// A parsed alias mapping a MAC address to a human-readable name.
#[derive(Debug, Clone)]
pub struct Alias {
    /// The MAC address as an efficient 6-byte array
    pub address: MacAddress,
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

    let address: MacAddress = address_str
        .parse()
        .map_err(|e| format!("invalid MAC address: {}", e))?;

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

/// Resolve a device name from aliases, falling back to the MAC address string.
///
/// # Arguments
/// * `mac` - The MAC address to resolve
/// * `aliases` - The alias map to look up
///
/// # Returns
/// The alias name if found, otherwise the MAC address formatted as a string.
pub fn resolve_name(mac: &MacAddress, aliases: &AliasMap) -> String {
    aliases.get(mac).cloned().unwrap_or_else(|| mac.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TEST_MAC;

    #[test]
    fn parse_alias_valid_cases() {
        let cases = [
            ("AA:BB:CC:DD:EE:FF=Kitchen", TEST_MAC, "Kitchen"),
            ("AA:BB:CC:DD:EE:FF=Living Room", TEST_MAC, "Living Room"),
            ("aa:bb:cc:dd:ee:ff=Kitchen", TEST_MAC, "Kitchen"),
        ];

        for (src, expected_mac, expected_name) in cases {
            let alias = parse_alias(src).unwrap();
            assert_eq!(alias.address, expected_mac);
            assert_eq!(alias.name, expected_name);
        }
    }

    #[test]
    fn parse_alias_invalid_format() {
        assert!(parse_alias("no-equals-sign").is_err());
    }

    #[test]
    fn parse_alias_invalid_mac() {
        assert!(parse_alias("invalid-mac=Kitchen").is_err());
    }

    #[test]
    fn to_map_builds_lookup() {
        let aliases = vec![
            Alias {
                address: TEST_MAC,
                name: "Kitchen".to_string(),
            },
            Alias {
                address: MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                name: "Bedroom".to_string(),
            },
        ];
        let map = to_map(&aliases);
        assert_eq!(map.get(&TEST_MAC), Some(&"Kitchen".to_string()));
        assert_eq!(
            map.get(&MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
            Some(&"Bedroom".to_string())
        );
        assert_eq!(
            map.get(&MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
            None
        );
    }

    #[test]
    fn resolve_name_returns_alias_when_present() {
        let mut aliases = HashMap::new();
        aliases.insert(TEST_MAC, "Sauna".to_string());

        assert_eq!(resolve_name(&TEST_MAC, &aliases), "Sauna");
    }

    #[test]
    fn resolve_name_returns_mac_when_no_alias() {
        let aliases = HashMap::new();

        assert_eq!(resolve_name(&TEST_MAC, &aliases), "AA:BB:CC:DD:EE:FF");
    }
}
