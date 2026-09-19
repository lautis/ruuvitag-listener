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

/// The per-report header fields of an advertising report, which differ between
/// the legacy (0x02) and extended (0x0D) formats.
struct ReportLayout {
    /// Offset of the 6-byte address (little-endian on the wire).
    addr: usize,
    /// Offset of the one-byte AD data length.
    data_len: usize,
    /// Where the RSSI byte is read from.
    rssi: Rssi,
}

/// Where the RSSI byte lives in a report.
enum Rssi {
    /// Trailing byte after the AD data; absent means "not available".
    Trailing,
    /// Fixed position inside the per-report header.
    Fixed(usize),
}

// Legacy per-report header: [0]num_reports [1]event_type [2]addr_type
// [3..9]addr [9]data_len [10..]data, RSSI trailing the data.
const LEGACY_REPORT: ReportLayout = ReportLayout {
    addr: 3,
    data_len: 9,
    rssi: Rssi::Trailing,
};

// Extended per-report header: [0]num_reports [1..3]event_type [3]addr_type
// [4..10]addr [10]phy [11]phy [12]sid [13]tx_power [14]rssi [15..17]periodic
// interval [17]direct_addr_type [18..24]direct_addr [24]data_len [25..]data.
const EXTENDED_REPORT: ReportLayout = ReportLayout {
    addr: 4,
    data_len: 24,
    rssi: Rssi::Fixed(14),
};

/// Parse a legacy LE Advertising Report (subevent 0x02) and extract RuuviTag data.
pub(crate) fn parse_advertising_report(data: &[u8], verbose: bool) -> Option<MeasurementResult> {
    parse_report(data, verbose, LEGACY_REPORT)
}

/// Parse an LE Extended Advertising Report (subevent 0x0D) and extract RuuviTag data.
///
/// Bluetooth 5 controllers report advertisements with this event once extended
/// scanning is enabled; its per-report header is larger than the legacy one.
pub(crate) fn parse_extended_advertising_report(
    data: &[u8],
    verbose: bool,
) -> Option<MeasurementResult> {
    parse_report(data, verbose, EXTENDED_REPORT)
}

/// Parse `data` as an advertising report laid out per `layout`, returning a
/// measurement when it decodes as a RuuviTag.
///
/// Truncated reports yield `DecodeError::InvalidData` when `verbose` and are
/// dropped silently otherwise.
fn parse_report(data: &[u8], verbose: bool, layout: ReportLayout) -> Option<MeasurementResult> {
    let report = match data.get(HCI_EVENT_HEADER_LEN..) {
        Some(report) if !report.is_empty() => report,
        _ => return too_short(verbose),
    };
    if report[0] == 0 {
        return None; // num_reports == 0
    }
    // The report must at least cover the address and the data-length byte.
    if report.len() <= layout.data_len {
        return too_short(verbose);
    }

    let mut addr = [0u8; 6];
    addr.copy_from_slice(&report[layout.addr..layout.addr + 6]);
    addr.reverse(); // HCI uses little-endian address

    let data_len = report[layout.data_len] as usize;
    let data_start = layout.data_len + 1;
    if report.len() < data_start + data_len {
        return None; // truncated AD data
    }
    let rssi = match layout.rssi {
        // The RSSI byte follows the advertising data; a report truncated here
        // means the controller did not include it.
        Rssi::Trailing => report
            .get(data_start + data_len)
            .copied()
            .unwrap_or(RSSI_UNAVAILABLE as u8) as i8,
        Rssi::Fixed(off) => report[off] as i8,
    };

    parse_ruuvi_from_ad_data(&report[data_start..data_start + data_len], addr, rssi)
}

/// Build the verbose-mode error for an advertising report too short to parse.
fn too_short(verbose: bool) -> Option<MeasurementResult> {
    if verbose {
        Some(Err(DecodeError::InvalidData(
            "Advertising report too short".into(),
        )))
    } else {
        None
    }
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
    fn test_parse_extended_report_too_short() {
        // HCI header + subevent + a truncated per-report body.
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_EXTENDED_ADVERTISING_REPORT,
        ];
        pkt.push(0x01); // num_reports
        pkt.extend_from_slice(&[0x00; 15]); // truncated per-report body
        assert_eq!(pkt.len(), 20);

        let verbose_result = parse_extended_advertising_report(&pkt, true);
        assert!(matches!(
            verbose_result,
            Some(Err(DecodeError::InvalidData(_)))
        ));
        assert_eq!(
            verbose_result,
            Some(Err(DecodeError::InvalidData(
                "Advertising report too short".into()
            )))
        );

        let silent_result = parse_extended_advertising_report(&pkt, false);
        assert!(silent_result.is_none());
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
