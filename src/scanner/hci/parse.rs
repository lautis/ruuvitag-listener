//! Pure HCI packet parsing: LE advertising-report parsers and Ruuvi
//! manufacturer-data decoding.

use super::*;
use crate::mac_address::MacAddress;
use crate::scanner::{
    DecodeError, MeasurementResult, RSSI_UNAVAILABLE, RUUVI_MANUFACTURER_ID, decode_ruuvi_data,
    with_rssi,
};

/// Quick check if a packet might contain Ruuvi manufacturer data.
///
/// This performs a fast scan for the Ruuvi manufacturer ID bytes (0x99 0x04 in LE)
/// to avoid expensive parsing of non-Ruuvi advertisements.
#[inline]
pub(crate) fn might_be_ruuvi(data: &[u8]) -> bool {
    data.windows(2).any(|w| w == RUUVI_MANUFACTURER_ID_LE)
}

/// Parse a legacy LE Advertising Report (subevent 0x02) and extract RuuviTag data.
pub(crate) fn parse_advertising_report(data: &[u8], verbose: bool) -> Option<MeasurementResult> {
    // Minimum size for an advertising report
    if data.len() < 12 {
        return if verbose {
            Some(Err(DecodeError::InvalidData(
                "Advertising report too short".into(),
            )))
        } else {
            None
        };
    }

    // Skip HCI header (1 byte packet type + 1 byte event code + 1 byte param len + 1 byte subevent)
    let report = &data[4..];

    if report.is_empty() {
        return None;
    }

    // Number of reports
    let num_reports = report[0] as usize;
    if num_reports == 0 {
        return None;
    }

    // Legacy per-report header:
    //   num_reports(1) event_type(1) addr_type(1) address(6) data_len(1) data(..) rssi(1)
    // Extract address (6 bytes, in reverse order)
    if report.len() < 10 {
        return None;
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&report[3..9]);
    addr.reverse(); // HCI uses little-endian address

    let data_len = report[9] as usize;
    if report.len() < 10 + data_len {
        return None;
    }

    // The RSSI byte follows the advertising data; a truncated report means
    // the controller did not include it.
    let rssi = report
        .get(10 + data_len)
        .copied()
        .unwrap_or(RSSI_UNAVAILABLE as u8) as i8;

    parse_ruuvi_from_ad_data(&report[10..10 + data_len], addr, rssi)
}

/// Parse an LE Extended Advertising Report (subevent 0x0D) and extract RuuviTag data.
///
/// Bluetooth 5 controllers report advertisements with this event once extended
/// scanning is enabled. Its per-report header is larger than the legacy one and
/// carries PHY/SID/TX-power fields before the advertising data.
pub(crate) fn parse_extended_advertising_report(
    data: &[u8],
    _verbose: bool,
) -> Option<MeasurementResult> {
    // Skip HCI header (pkt type + event code + param len + subevent)
    let report = data.get(4..)?;

    // Number of reports
    let num_reports = *report.first()?;
    if num_reports == 0 {
        return None;
    }

    // Extended per-report header (relative to `report`):
    //   [0]      num_reports
    //   [1..3]   event_type (2)
    //   [3]      address_type
    //   [4..10]  address (6)
    //   [10]     primary_phy
    //   [11]     secondary_phy
    //   [12]     advertising_sid
    //   [13]     tx_power
    //   [14]     rssi
    //   [15..17] periodic_advertising_interval (2)
    //   [17]     direct_address_type
    //   [18..24] direct_address (6)
    //   [24]     data_length
    //   [25..]   data
    if report.len() < 25 {
        return None;
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&report[4..10]);
    addr.reverse(); // HCI uses little-endian address

    let data_len = report[24] as usize;
    if report.len() < 25 + data_len {
        return None;
    }
    let rssi = report[14] as i8; // RSSI byte in the extended per-report header

    parse_ruuvi_from_ad_data(&report[25..25 + data_len], addr, rssi)
}

/// Walk the AD structures of an advertisement and decode any RuuviTag
/// manufacturer data found.
///
/// `rssi` is the signal strength (dBm) reported by the controller for this
/// advertisement; the HCI "not available" sentinel is handled by
/// [`crate::scanner::with_rssi`].
fn parse_ruuvi_from_ad_data(ad_data: &[u8], addr: [u8; 6], rssi: i8) -> Option<MeasurementResult> {
    let mut offset = 0;
    while offset + 2 <= ad_data.len() {
        let len = ad_data[offset] as usize;
        if len == 0 || offset + 1 + len > ad_data.len() {
            break;
        }

        let ad_type = ad_data[offset + 1];

        if ad_type == AD_TYPE_MANUFACTURER_DATA && len >= 3 {
            // Extract manufacturer ID (little-endian)
            let mfg_id = u16::from_le_bytes([ad_data[offset + 2], ad_data[offset + 3]]);

            if mfg_id == RUUVI_MANUFACTURER_ID {
                // Found RuuviTag data
                let ruuvi_data = &ad_data[offset + 4..offset + 1 + len];
                return Some(match decode_ruuvi_data(MacAddress(addr), ruuvi_data) {
                    Ok(measurement) => Ok(with_rssi(measurement, rssi)),
                    Err(e) => Err(e),
                });
            }
        }

        offset += 1 + len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_might_be_ruuvi_positive() {
        // Packet containing Ruuvi manufacturer ID (0x0499 in little-endian = 0x99 0x04)
        let packet = [0x04, 0x3E, 0x1A, 0x02, 0x01, 0x00, 0x99, 0x04, 0x05, 0x12];
        assert!(might_be_ruuvi(&packet));
    }

    #[test]
    fn test_might_be_ruuvi_negative() {
        // Packet without Ruuvi manufacturer ID
        let packet = [0x04, 0x3E, 0x1A, 0x02, 0x01, 0x00, 0xAA, 0xBB, 0x05, 0x12];
        assert!(!might_be_ruuvi(&packet));
    }

    #[test]
    fn test_might_be_ruuvi_empty() {
        assert!(!might_be_ruuvi(&[]));
        assert!(!might_be_ruuvi(&[0x99])); // Only one byte, can't match 2-byte pattern
    }

    /// Build a minimal RuuviTag RAWv2 (data format 5) manufacturer payload.
    fn ruuvi_rawv2_payload() -> Vec<u8> {
        // 0x9904 manufacturer id + 24 bytes of format-5 data
        let mut data = vec![0x99, 0x04];
        data.push(0x05); // data format 5
        data.extend(std::iter::repeat_n(0x00, 23));
        data
    }

    #[test]
    fn test_parse_extended_advertising_report() {
        let payload = ruuvi_rawv2_payload();
        // AD structure: [len][type=0xFF][payload...]
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);

        // HCI header + extended report header + data
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_EXTENDED_ADVERTISING_REPORT,
        ];
        pkt.push(0x01); // num_reports
        pkt.extend_from_slice(&[0x00, 0x00]); // event_type
        pkt.push(0x00); // address_type
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // address (LE)
        pkt.extend_from_slice(&[0x01, 0x01, 0x00, 0x7F, 0xC3]); // primary/secondary phy, sid, tx_power, rssi
        pkt.extend_from_slice(&[0x00, 0x00]); // periodic interval
        pkt.push(0x00); // direct_address_type
        pkt.extend_from_slice(&[0x00; 6]); // direct_address
        pkt.push(ad.len() as u8); // data_length
        pkt.extend_from_slice(&ad);

        assert!(might_be_ruuvi(&pkt));
        let result = parse_extended_advertising_report(&pkt, false);
        assert!(result.is_some(), "expected a RuuviTag measurement");
        let measurement = result.unwrap().expect("payload should decode");
        // Address is little-endian on the wire, so it reverses on decode.
        assert_eq!(
            measurement.mac,
            MacAddress([0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        );
        // RSSI 0xC3 = -61 dBm, from the extended per-report header.
        assert_eq!(measurement.rssi, Some(-61));
    }

    #[test]
    fn test_parse_legacy_advertising_report_with_rssi() {
        let payload = ruuvi_rawv2_payload();
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);

        // HCI header + legacy report header, data, and a trailing RSSI byte.
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_ADVERTISING_REPORT,
        ];
        pkt.push(0x01); // num_reports
        pkt.push(0x00); // event_type
        pkt.push(0x00); // address_type
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // address (LE)
        pkt.push(ad.len() as u8); // data_len
        pkt.extend_from_slice(&ad);
        pkt.push(0xB0); // RSSI = -80 dBm

        assert!(might_be_ruuvi(&pkt));
        let result = parse_advertising_report(&pkt, false);
        let measurement = result.unwrap().expect("payload should decode");
        assert_eq!(measurement.rssi, Some(-80));
    }

    #[test]
    fn test_parse_report_maps_rssi_sentinel_to_none() {
        let payload = ruuvi_rawv2_payload();
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);

        // Legacy report whose RSSI byte is the 127 "not available" sentinel.
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_ADVERTISING_REPORT,
        ];
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        pkt.push(ad.len() as u8);
        pkt.extend_from_slice(&ad);
        pkt.push(RSSI_UNAVAILABLE as u8);

        let result = parse_advertising_report(&pkt, false);
        let measurement = result.unwrap().expect("payload should decode");
        assert_eq!(measurement.rssi, None);
    }
}
