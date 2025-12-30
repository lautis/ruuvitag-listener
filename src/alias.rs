//! MAC address aliasing for RuuviTag devices.
//!
//! This module provides functionality to map MAC addresses to human-readable names,
//! making it easier to identify individual RuuviTag sensors in output.

use std::collections::BTreeMap;

/// A type alias for MAC-to-name mappings.
pub type AliasMap = BTreeMap<String, String>;

/// A parsed alias mapping a MAC address to a human-readable name.
#[derive(Debug, Clone)]
pub struct Alias {
    /// The MAC address (e.g., "AA:BB:CC:DD:EE:FF")
    pub address: String,
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
/// assert_eq!(alias.address, "AA:BB:CC:DD:EE:FF");
/// assert_eq!(alias.name, "Kitchen");
/// ```
pub fn parse_alias(src: &str) -> Result<Alias, String> {
    src.split_once('=')
        .map(|(address, name)| Alias {
            address: address.into(),
            name: name.into(),
        })
        .ok_or_else(|| "invalid alias: expected format MAC=NAME".into())
}

/// Convert a slice of Alias values into an AliasMap.
///
/// # Arguments
/// * `aliases` - A slice of Alias structs
///
/// # Returns
/// A BTreeMap mapping MAC addresses to their human-readable names.
pub fn to_map(aliases: &[Alias]) -> AliasMap {
    aliases
        .iter()
        .map(|a| (a.address.clone(), a.name.clone()))
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
        assert_eq!(alias.address, "AA:BB:CC:DD:EE:FF");
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
    fn test_parse_alias_invalid() {
        let result = parse_alias("no-equals-sign");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_map() {
        let aliases = vec![
            Alias {
                address: "AA:BB:CC:DD:EE:FF".to_string(),
                name: "Kitchen".to_string(),
            },
            Alias {
                address: "11:22:33:44:55:66".to_string(),
                name: "Bedroom".to_string(),
            },
        ];
        let map = to_map(&aliases);
        assert_eq!(map.get("AA:BB:CC:DD:EE:FF"), Some(&"Kitchen".to_string()));
        assert_eq!(map.get("11:22:33:44:55:66"), Some(&"Bedroom".to_string()));
        assert_eq!(map.get("00:00:00:00:00:00"), None);
    }
}
