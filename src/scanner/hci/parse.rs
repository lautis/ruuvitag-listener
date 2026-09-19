//! Pure HCI packet parsing: LE Meta Event dispatch and advertising-report
//! decoding into RuuviTag measurements.

use super::*;
use crate::mac_address::MacAddress;
use crate::scanner::{
    DecodeError, MeasurementResult, RSSI_UNAVAILABLE, RUUVI_MANUFACTURER_ID, decode_ruuvi_data,
    with_rssi,
};

/// Size of the fixed HCI event header (packet type, event code, param len, subevent).
const HCI_EVENT_HEADER_LEN: usize = 4;

// AD types
const AD_TYPE_MANUFACTURER_DATA: u8 = 0xFF;

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

/// Dispatch one HCI event: parse it as a legacy or extended advertising
/// report when the packet is an LE Meta Event that might carry Ruuvi data.
pub(crate) fn parse_event(data: &[u8], verbose: bool) -> Option<MeasurementResult> {
    // Fast path: drop anything that is not an LE Meta Event or cannot contain
    // the Ruuvi manufacturer ID before doing any real parsing.
    if data.len() < HCI_EVENT_HEADER_LEN
        || data[0] != HCI_EVENT_PKT
        || data[1] != EVT_LE_META_EVENT
        || !might_be_ruuvi(data)
    {
        return None;
    }
    match data[3] {
        EVT_LE_ADVERTISING_REPORT => parse_advertising_report(data, verbose),
        EVT_LE_EXTENDED_ADVERTISING_REPORT => parse_extended_advertising_report(data, verbose),
        _ => None,
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

    /// Minimal RuuviTag RAWv2 (data format 5) payload carrying `mfg_id`
    /// followed by 24 bytes of format-5 data.
    fn ruuvi_rawv2_payload(mfg_id: [u8; 2]) -> Vec<u8> {
        let mut data = vec![mfg_id[0], mfg_id[1]];
        data.push(0x05); // data format 5
        data.extend(std::iter::repeat_n(0x00, 23));
        data
    }

    /// AD structure for a Ruuvi payload: [len][type=0xFF][payload...].
    fn ruuvi_ad_structure(mfg_id: [u8; 2]) -> Vec<u8> {
        let payload = ruuvi_rawv2_payload(mfg_id);
        let mut ad = vec![(payload.len() + 1) as u8, AD_TYPE_MANUFACTURER_DATA];
        ad.extend_from_slice(&payload);
        ad
    }

    /// The fields a test wants in (or done to) a report; `Default` is a valid
    /// legacy Ruuvi advertising report (0x02). The fields mirror what the
    /// parsers read, so a malformed case reads as named parameters instead of
    /// magic byte offsets into a built packet.
    #[derive(Clone, Copy)]
    struct ReportSpec {
        /// LE Meta subevent, which selects the report layout: the extended
        /// (0x0D) header is built when this is `EVT_LE_EXTENDED_ADVERTISING_REPORT`.
        subevent: u8,
        /// Event code in the HCI header (`EVT_LE_META_EVENT` normally).
        event_code: u8,
        /// `num_reports` in the per-report header.
        num_reports: u8,
        /// AD data length the report claims; `None` sizes it to the real bytes.
        data_len: Option<u8>,
        /// Manufacturer ID carried in the AD structure.
        mfg_id: [u8; 2],
        /// RSSI byte: trailing the data (legacy) or in the header (extended).
        rssi: u8,
    }

    impl Default for ReportSpec {
        fn default() -> Self {
            Self {
                subevent: EVT_LE_ADVERTISING_REPORT,
                event_code: EVT_LE_META_EVENT,
                num_reports: 1,
                data_len: None,
                mfg_id: [0x99, 0x04],
                rssi: 0xB0,
            }
        }
    }

    /// Build a full advertising report per `spec`.
    ///
    /// The format-specific header bytes (a 1-byte `event_type` for legacy, a
    /// 2-byte one plus the extended fields for 0x0D) are the reason the
    /// production parser carries a `ReportLayout`; only the shared prefix and
    /// the AD tail are built once here.
    fn report(spec: ReportSpec) -> Vec<u8> {
        let extended = spec.subevent == EVT_LE_EXTENDED_ADVERTISING_REPORT;
        let ad = ruuvi_ad_structure(spec.mfg_id);
        let data_len = spec.data_len.unwrap_or(ad.len() as u8);
        let mut pkt = vec![HCI_EVENT_PKT, spec.event_code, 0x00, spec.subevent];
        pkt.push(spec.num_reports);
        pkt.push(0x00); // event_type
        if extended {
            pkt.push(0x00); // event_type (2nd byte, LE)
            pkt.push(0x00); // address_type
            pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // address (LE)
            // primary/secondary phy, sid, tx_power, rssi
            pkt.extend_from_slice(&[0x01, 0x01, 0x00, 0x7F, spec.rssi]);
            pkt.extend_from_slice(&[0x00, 0x00]); // periodic interval
            pkt.push(0x00); // direct_address_type
            pkt.extend_from_slice(&[0x00; 6]); // direct_address
        } else {
            pkt.push(0x00); // address_type
            pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // address (LE)
        }
        pkt.push(data_len);
        pkt.extend_from_slice(&ad);
        if !extended {
            pkt.push(spec.rssi); // trailing RSSI byte
        }
        pkt
    }

    /// An LE Meta Event whose per-report body is `body_len` bytes: a nonzero
    /// `num_reports`, the Ruuvi ID (so the dispatch fast path passes) and
    /// zeros — too short to decode, but not empty.
    fn truncated_meta_event(subevent: u8, body_len: usize) -> Vec<u8> {
        assert!(body_len >= 3);
        let mut pkt = vec![HCI_EVENT_PKT, EVT_LE_META_EVENT, 0x00, subevent];
        pkt.push(0x01); // num reports
        pkt.extend_from_slice(&[0x99, 0x04]); // Ruuvi ID
        pkt.extend(std::iter::repeat_n(0x00, body_len - 3));
        pkt
    }

    #[test]
    fn test_parse_extended_advertising_report() {
        let pkt = report(ReportSpec {
            subevent: EVT_LE_EXTENDED_ADVERTISING_REPORT,
            rssi: 0xC3, // -61 dBm
            ..Default::default()
        });
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
    fn test_parse_report_too_short_verbose_error() {
        let pkt = truncated_meta_event(EVT_LE_EXTENDED_ADVERTISING_REPORT, 16);
        assert_eq!(pkt.len(), 20);

        assert_eq!(
            parse_extended_advertising_report(&pkt, true),
            Some(Err(DecodeError::InvalidData(
                "Advertising report too short".into()
            )))
        );
        assert!(parse_extended_advertising_report(&pkt, false).is_none());
    }

    #[test]
    fn test_parse_legacy_advertising_report_with_rssi() {
        let pkt = report(ReportSpec {
            rssi: 0xB0, // -80 dBm
            ..Default::default()
        });
        assert!(might_be_ruuvi(&pkt));
        let measurement = parse_advertising_report(&pkt, false)
            .unwrap()
            .expect("payload should decode");
        assert_eq!(measurement.rssi, Some(-80));
    }

    #[test]
    fn test_parse_report_maps_rssi_sentinel_to_none() {
        // A legacy report whose RSSI byte is the 127 "not available" sentinel.
        let pkt = report(ReportSpec {
            rssi: RSSI_UNAVAILABLE as u8,
            ..Default::default()
        });
        let measurement = parse_advertising_report(&pkt, false)
            .unwrap()
            .expect("payload should decode");
        assert_eq!(measurement.rssi, None);
    }

    #[test]
    fn test_parse_event_decodes_both_report_formats() {
        for pkt in [
            report(ReportSpec::default()),
            report(ReportSpec {
                subevent: EVT_LE_EXTENDED_ADVERTISING_REPORT,
                ..Default::default()
            }),
        ] {
            let measurement = parse_event(&pkt, false)
                .expect("report should dispatch")
                .expect("payload should decode");
            assert_eq!(
                measurement.mac,
                MacAddress([0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
            );
            assert_eq!(measurement.rssi, Some(-80)); // default 0xB0
        }
    }

    #[test]
    fn test_parse_event_rejects_foreign_payloads() {
        // A Ruuvi-shaped report carrying a different manufacturer ID is
        // dropped before the payload is touched.
        let pkt = report(ReportSpec {
            mfg_id: [0x12, 0x34],
            ..Default::default()
        });
        assert!(!might_be_ruuvi(&pkt));
        assert!(parse_event(&pkt, false).is_none());

        // A wrong event code or unknown subevent never reaches the parsers.
        let pkt = report(ReportSpec {
            event_code: 0x05,
            ..Default::default()
        });
        assert!(parse_event(&pkt, false).is_none());

        let pkt = report(ReportSpec {
            subevent: 0x0B,
            ..Default::default()
        });
        assert!(parse_event(&pkt, false).is_none());
    }

    #[test]
    fn test_parse_event_short_buffers_do_not_panic() {
        // The receive loop feeds whatever the kernel delivers, so anything
        // shorter than the HCI header must be dropped, not panic.
        assert!(parse_event(&[], false).is_none());
        assert!(parse_event(&[HCI_EVENT_PKT], false).is_none());
        assert!(parse_event(&[HCI_EVENT_PKT, EVT_LE_META_EVENT], false).is_none());
        assert!(parse_event(&[HCI_EVENT_PKT, EVT_LE_META_EVENT, 0x00], false).is_none());
    }

    #[test]
    fn test_parse_event_zero_reports_is_not_an_error() {
        let pkt = report(ReportSpec {
            num_reports: 0,
            ..Default::default()
        });
        // A controller reporting no advertisements yields nothing to decode,
        // even in verbose mode.
        assert!(parse_event(&pkt, false).is_none());
        assert!(parse_event(&pkt, true).is_none());
    }

    #[test]
    fn test_parse_event_truncated_ad_data_is_silent() {
        // The report is well-formed up to the data-length byte, which then
        // claims more AD data than the packet carries. Unlike a truncated
        // header this is dropped silently, even in verbose mode.
        let pkt = report(ReportSpec {
            data_len: Some(200),
            ..Default::default()
        });
        assert!(parse_event(&pkt, false).is_none());
        assert!(parse_event(&pkt, true).is_none());
    }

    #[test]
    fn test_parse_event_propagates_verbose_error() {
        let pkt = truncated_meta_event(EVT_LE_EXTENDED_ADVERTISING_REPORT, 16);
        assert_eq!(
            parse_event(&pkt, true),
            Some(Err(DecodeError::InvalidData(
                "Advertising report too short".into()
            )))
        );
        assert!(parse_event(&pkt, false).is_none());
    }
}
