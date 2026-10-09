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

/// The per-report fields of an advertising report, which differ between
/// the legacy (0x02) and extended (0x0D) formats.
///
/// Offsets are relative to the start of each per-report section (not the
/// start of the event), so the parser can stride through stacked reports
/// whose AD data lengths vary per report.
#[derive(Clone, Copy)]
struct ReportLayout {
    /// Offset of the 6-byte address (little-endian on the wire).
    addr: usize,
    /// Offset of the one-byte AD data length.
    data_len: usize,
    /// Where the RSSI byte is read from.
    rssi: Rssi,
}

/// Where the RSSI byte lives in a report.
#[derive(Clone, Copy)]
enum Rssi {
    /// Trailing byte after the AD data; absent means "not available".
    Trailing,
    /// Fixed position inside the per-report header.
    Fixed(usize),
}

// Legacy per-report section: [0]event_type [1]addr_type [2..8]addr
// [8]data_len [9..]data, RSSI trailing the data.
const LEGACY_REPORT: ReportLayout = ReportLayout {
    addr: 2,
    data_len: 8,
    rssi: Rssi::Trailing,
};

// Extended per-report section: [0..2]event_type [2]addr_type [3..9]addr
// [9]phy [10]phy [11]sid [12]tx_power [13]rssi [14..16]periodic interval
// [16]direct_addr_type [17..23]direct_addr [23]data_len [24..]data.
const EXTENDED_REPORT: ReportLayout = ReportLayout {
    addr: 3,
    data_len: 23,
    rssi: Rssi::Fixed(13),
};

/// Parse a legacy LE Advertising Report (subevent 0x02) and extract RuuviTag data.
///
/// One HCI event can stack several reports; every report carrying Ruuvi
/// data yields one entry in the returned vector.
pub(crate) fn parse_advertising_report(data: &[u8], verbose: bool) -> Vec<MeasurementResult> {
    parse_report(data, verbose, LEGACY_REPORT)
}

/// Parse an LE Extended Advertising Report (subevent 0x0D) and extract RuuviTag data.
///
/// Bluetooth 5 controllers report advertisements with this event once extended
/// scanning is enabled; its per-report header is larger than the legacy one.
/// Like the legacy parser, all stacked reports are decoded, not just the first.
pub(crate) fn parse_extended_advertising_report(
    data: &[u8],
    verbose: bool,
) -> Vec<MeasurementResult> {
    parse_report(data, verbose, EXTENDED_REPORT)
}

/// Parse `data` as an advertising report laid out per `layout`, decoding
/// every stacked report that carries RuuviTag data.
///
/// Each report has its own AD data length, so the cursor advances per
/// report instead of assuming a fixed stride. Truncated report headers
/// yield `DecodeError::InvalidData` when `verbose` and end the walk
/// silently otherwise. A truncated AD payload cannot be resynchronised
/// (the next report boundary is unknowable), so it ends the walk silently
/// in both modes, preserving the single-report behaviour.
fn parse_report(data: &[u8], verbose: bool, layout: ReportLayout) -> Vec<MeasurementResult> {
    let report = match data.get(HCI_EVENT_HEADER_LEN..) {
        Some(report) if !report.is_empty() => report,
        _ => return too_short(verbose),
    };
    let num_reports = report[0];
    if num_reports == 0 {
        return Vec::new(); // num_reports == 0
    }
    let mut results = Vec::new();
    let mut cursor = 1usize; // past num_reports
    for _ in 0..num_reports {
        // The report must at least cover the address and the data-length byte.
        let data_len_byte = match report.get(cursor + layout.data_len) {
            Some(b) => *b as usize,
            None => {
                if verbose {
                    results.push(Err(DecodeError::InvalidData(
                        "Advertising report too short".into(),
                    )));
                }
                break;
            }
        };
        let mut addr = [0u8; 6];
        match report.get(cursor + layout.addr..cursor + layout.addr + 6) {
            Some(bytes) => addr.copy_from_slice(bytes),
            None => {
                if verbose {
                    results.push(Err(DecodeError::InvalidData(
                        "Advertising report too short".into(),
                    )));
                }
                break;
            }
        }
        addr.reverse(); // HCI uses little-endian address

        let data_len = data_len_byte;
        let data_start = cursor + layout.data_len + 1;
        let ad_data = match data_start
            .checked_add(data_len)
            .and_then(|end| report.get(data_start..end))
        {
            Some(slice) => slice,
            None => break, // truncated AD data: silent in both modes
        };
        let rssi = match layout.rssi {
            // The RSSI byte follows the advertising data; a report truncated here
            // means the controller did not include it.
            Rssi::Trailing => report
                .get(data_start + data_len)
                .copied()
                .unwrap_or(RSSI_UNAVAILABLE as u8) as i8,
            Rssi::Fixed(off) => match report.get(cursor + off) {
                Some(b) => *b as i8,
                None => {
                    if verbose {
                        results.push(Err(DecodeError::InvalidData(
                            "Advertising report too short".into(),
                        )));
                    }
                    break;
                }
            },
        };

        if let Some(result) = parse_ruuvi_from_ad_data(ad_data, addr, rssi) {
            results.push(result);
        }
        cursor = match layout.rssi {
            // Consume the trailing RSSI byte when the controller included it.
            Rssi::Trailing if report.get(data_start + data_len).is_some() => {
                data_start + data_len + 1
            }
            _ => data_start + data_len,
        };
    }
    results
}

/// Build the verbose-mode error for an advertising report too short to parse.
fn too_short(verbose: bool) -> Vec<MeasurementResult> {
    if verbose {
        vec![Err(DecodeError::InvalidData(
            "Advertising report too short".into(),
        ))]
    } else {
        Vec::new()
    }
}

/// Dispatch one HCI event: parse it as a legacy or extended advertising
/// report when the packet is an LE Meta Event that might carry Ruuvi data.
///
/// Returns one entry per decoded Ruuvi report stacked in the event.
pub(crate) fn parse_event(data: &[u8], verbose: bool) -> Vec<MeasurementResult> {
    // Fast path: drop anything that is not an LE Meta Event or cannot contain
    // the Ruuvi manufacturer ID before doing any real parsing.
    if data.len() < HCI_EVENT_HEADER_LEN
        || data[0] != HCI_EVENT_PKT
        || data[1] != EVT_LE_META_EVENT
        || !might_be_ruuvi(data)
    {
        return Vec::new();
    }
    match data[3] {
        EVT_LE_ADVERTISING_REPORT => parse_advertising_report(data, verbose),
        EVT_LE_EXTENDED_ADVERTISING_REPORT => parse_extended_advertising_report(data, verbose),
        _ => Vec::new(),
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
    fn might_be_ruuvi_matches_manufacturer_id() {
        // Packet containing Ruuvi manufacturer ID (0x0499 in little-endian = 0x99 0x04)
        let packet = [0x04, 0x3E, 0x1A, 0x02, 0x01, 0x00, 0x99, 0x04, 0x05, 0x12];
        assert!(might_be_ruuvi(&packet));
    }

    #[test]
    fn might_be_ruuvi_rejects_other_manufacturer_ids() {
        // Packet without Ruuvi manufacturer ID
        let packet = [0x04, 0x3E, 0x1A, 0x02, 0x01, 0x00, 0xAA, 0xBB, 0x05, 0x12];
        assert!(!might_be_ruuvi(&packet));
    }

    #[test]
    fn might_be_ruuvi_rejects_short_buffers() {
        assert!(!might_be_ruuvi(&[]));
        assert!(!might_be_ruuvi(&[0x99])); // Only one byte, can't match 2-byte pattern
    }

    // Default AD content: format 5 with zeroed payload.
    const RUUVI_AD: &[u8] = &[
        27,   // AD length: type byte plus 26 bytes of payload
        0xFF, // AD type: manufacturer data
        0x99, 0x04, // Ruuvi manufacturer ID
        0x05, // data format 5
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Test report parameters; `Default` is a valid legacy Ruuvi report.
    #[derive(Clone, Copy)]
    struct ReportSpec {
        // `0x0D` selects the extended header layout.
        subevent: u8,
        event_code: u8,
        num_reports: u8,
        // Claimed AD length; `None` uses the real length.
        data_len: Option<u8>,
        ad: &'static [u8],
        rssi: u8,
    }

    impl Default for ReportSpec {
        fn default() -> Self {
            Self {
                subevent: EVT_LE_ADVERTISING_REPORT,
                event_code: EVT_LE_META_EVENT,
                num_reports: 1,
                data_len: None,
                ad: RUUVI_AD,
                rssi: 0xB0,
            }
        }
    }

    // Build a full advertising report from `spec`.
    fn report(spec: ReportSpec) -> Vec<u8> {
        let extended = spec.subevent == EVT_LE_EXTENDED_ADVERTISING_REPORT;
        let ad = spec.ad;
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
        pkt.extend_from_slice(ad);
        if !extended {
            pkt.push(spec.rssi); // trailing RSSI byte
        }
        pkt
    }

    // LE Meta event with a `body_len`-byte body holding the Ruuvi ID plus
    // zeros: passes the dispatch fast path but is too short to decode.
    fn truncated_meta_event(subevent: u8, body_len: usize) -> Vec<u8> {
        assert!(body_len >= 3);
        let mut pkt = vec![HCI_EVENT_PKT, EVT_LE_META_EVENT, 0x00, subevent];
        pkt.push(0x01); // num reports
        pkt.extend_from_slice(&[0x99, 0x04]); // Ruuvi ID
        pkt.extend(std::iter::repeat_n(0x00, body_len - 3));
        pkt
    }

    // Check `results` holds exactly one decoded fixture tag (wire bytes 01..06, reversed).
    fn assert_ruuvi_decode(results: Vec<MeasurementResult>, rssi: Option<i8>) {
        assert_eq!(results.len(), 1, "expected exactly one report");
        let measurement = results
            .into_iter()
            .next()
            .expect("expected a report")
            .expect("payload should decode");
        assert_eq!(
            measurement.mac,
            MacAddress([0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        );
        assert_eq!(measurement.rssi, rssi);
    }

    // Check verbose mode reports "too short" for `pkt`.
    fn assert_too_short(parse: fn(&[u8], bool) -> Vec<MeasurementResult>, pkt: &[u8]) {
        assert_eq!(
            parse(pkt, true),
            vec![Err(DecodeError::InvalidData(
                "Advertising report too short".into()
            ))]
        );
    }

    // Check `pkt` is dropped in both verbosity modes.
    fn assert_silent(parse: fn(&[u8], bool) -> Vec<MeasurementResult>, pkt: &[u8]) {
        assert!(parse(pkt, false).is_empty());
        assert!(parse(pkt, true).is_empty());
    }

    // One legacy per-report body (no HCI header, no num_reports byte).
    fn legacy_body(addr_le: [u8; 6], ad: &[u8], rssi: u8) -> Vec<u8> {
        let mut body = vec![0x00, 0x00]; // event_type, address_type
        body.extend_from_slice(&addr_le);
        body.push(ad.len() as u8);
        body.extend_from_slice(ad);
        body.push(rssi); // trailing RSSI byte
        body
    }

    // One extended per-report body (no HCI header, no num_reports byte).
    fn extended_body(addr_le: [u8; 6], ad: &[u8], rssi: u8) -> Vec<u8> {
        let mut body = vec![0x00, 0x00, 0x00]; // event_type (2 bytes), address_type
        body.extend_from_slice(&addr_le);
        // primary/secondary phy, sid, tx_power, rssi
        body.extend_from_slice(&[0x01, 0x01, 0x00, 0x7F, rssi]);
        body.extend_from_slice(&[0x00, 0x00]); // periodic interval
        body.push(0x00); // direct_address_type
        body.extend_from_slice(&[0x00; 6]); // direct_address
        body.push(ad.len() as u8);
        body.extend_from_slice(ad);
        body
    }

    // Assemble stacked-report HCI event from per-report bodies.
    fn stacked_packet(subevent: u8, bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut pkt = vec![
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            subevent,
            bodies.len() as u8,
        ];
        for body in bodies {
            pkt.extend_from_slice(body);
        }
        pkt
    }

    #[test]
    fn parses_extended_advertising_report() {
        let pkt = report(ReportSpec {
            subevent: EVT_LE_EXTENDED_ADVERTISING_REPORT,
            rssi: 0xC3, // -61 dBm
            ..Default::default()
        });
        assert!(might_be_ruuvi(&pkt));
        assert_ruuvi_decode(parse_extended_advertising_report(&pkt, false), Some(-61));
    }

    #[test]
    fn report_too_short_is_verbose_error() {
        // A too-short report yields "Advertising report too short" in verbose
        // mode and nothing otherwise, whether parsed directly or dispatched
        // by parse_event.
        let pkt = truncated_meta_event(EVT_LE_EXTENDED_ADVERTISING_REPORT, 16);
        assert_eq!(pkt.len(), 20);
        assert_too_short(parse_extended_advertising_report, &pkt);
        assert_too_short(parse_event, &pkt);
        assert!(parse_event(&pkt, false).is_empty());
    }

    #[test]
    fn parses_legacy_advertising_report_with_rssi() {
        let pkt = report(ReportSpec {
            rssi: 0xB0, // -80 dBm
            ..Default::default()
        });
        assert_ruuvi_decode(parse_advertising_report(&pkt, false), Some(-80));
    }

    #[test]
    fn maps_rssi_sentinel_to_none() {
        // A legacy report whose RSSI byte is the 127 "not available" sentinel.
        let pkt = report(ReportSpec {
            rssi: RSSI_UNAVAILABLE as u8,
            ..Default::default()
        });
        assert_ruuvi_decode(parse_advertising_report(&pkt, false), None);
    }

    #[test]
    fn decodes_both_report_formats() {
        for pkt in [
            report(ReportSpec::default()),
            report(ReportSpec {
                subevent: EVT_LE_EXTENDED_ADVERTISING_REPORT,
                ..Default::default()
            }),
        ] {
            assert_ruuvi_decode(parse_event(&pkt, false), Some(-80)); // default 0xB0
        }
    }

    #[test]
    fn rejects_foreign_payloads() {
        // A Ruuvi-shaped report carrying a different manufacturer ID is
        // dropped before the payload is touched.
        let pkt = report(ReportSpec {
            ad: &[0x06, 0xFF, 0x12, 0x34, 0x00, 0x00, 0x00],
            ..Default::default()
        });
        assert!(!might_be_ruuvi(&pkt));
        assert!(parse_event(&pkt, false).is_empty());

        // A wrong event code or unknown subevent never reaches the parsers.
        let pkt = report(ReportSpec {
            event_code: 0x05,
            ..Default::default()
        });
        assert!(parse_event(&pkt, false).is_empty());

        let pkt = report(ReportSpec {
            subevent: 0x0B,
            ..Default::default()
        });
        assert!(parse_event(&pkt, false).is_empty());
    }

    #[test]
    fn short_buffers_do_not_panic() {
        // The receive loop feeds whatever the kernel delivers, so anything
        // shorter than the HCI header must be dropped, not panic.
        assert!(parse_event(&[], false).is_empty());
        assert!(parse_event(&[HCI_EVENT_PKT], false).is_empty());
        assert!(parse_event(&[HCI_EVENT_PKT, EVT_LE_META_EVENT], false).is_empty());
        assert!(parse_event(&[HCI_EVENT_PKT, EVT_LE_META_EVENT, 0x00], false).is_empty());
    }

    #[test]
    fn zero_reports_is_not_an_error() {
        // A controller reporting no advertisements yields nothing to decode,
        // even in verbose mode.
        let pkt = report(ReportSpec {
            num_reports: 0,
            ..Default::default()
        });
        assert_silent(parse_event, &pkt);
    }

    #[test]
    fn truncated_ad_data_is_silent() {
        // The report is well-formed up to the data-length byte, which then
        // claims more AD data than the packet carries. Unlike a truncated
        // header this is dropped silently, even in verbose mode.
        let pkt = report(ReportSpec {
            data_len: Some(200),
            ..Default::default()
        });
        assert_silent(parse_event, &pkt);
    }

    #[test]
    fn sub_header_buffer_is_verbose_error() {
        // parse_event never routes sub-header buffers here, but the direct
        // parsers must not panic on them either; verbose reports the error,
        // silent mode drops the event.
        let truncated = [HCI_EVENT_PKT, EVT_LE_META_EVENT];
        assert_too_short(parse_advertising_report, &truncated);
        assert!(parse_advertising_report(&truncated, false).is_empty());

        // A full header without a report body takes the same path.
        let header_only = [
            HCI_EVENT_PKT,
            EVT_LE_META_EVENT,
            0x00,
            EVT_LE_ADVERTISING_REPORT,
        ];
        assert!(!parse_advertising_report(&header_only, true).is_empty());
        assert!(parse_advertising_report(&header_only, false).is_empty());
    }

    #[test]
    fn walks_past_non_ruuvi_ad_entries() {
        // Flags data, a foreign manufacturer entry, then the Ruuvi entry: the
        // AD walk must skip the first two and decode the third.
        let pkt = report(ReportSpec {
            ad: &[
                0x02, 0x01, 0x06, // AD type: Flags
                0x06, 0xFF, 0x12, 0x34, 0x00, 0x00, 0x00, // foreign mfg data
                27, 0xFF, 0x99, 0x04, 0x05, // Ruuvi format-5 entry
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            ..Default::default()
        });
        assert_ruuvi_decode(parse_advertising_report(&pkt, false), Some(-80));
    }

    #[test]
    fn malformed_ad_length_is_silent() {
        // A zero-length AD entry terminates the walk without an error...
        let zero_len = report(ReportSpec {
            ad: &[0x00],
            ..Default::default()
        });
        assert_silent(parse_advertising_report, &zero_len);

        // ...as does one whose claimed length overruns the AD data.
        let overrun = report(ReportSpec {
            ad: &[0x20, 0xFF, 0x01],
            ..Default::default()
        });
        assert_silent(parse_advertising_report, &overrun);
    }

    #[test]
    fn without_ruuvi_entry_is_silent() {
        // Flags and foreign manufacturer data, never a Ruuvi ID: the walk
        // exhausts the AD data and yields nothing.
        let pkt = report(ReportSpec {
            ad: &[0x02, 0x01, 0x06, 0x06, 0xFF, 0x12, 0x34, 0x00, 0x00, 0x00],
            ..Default::default()
        });
        assert_silent(parse_advertising_report, &pkt);
    }

    #[test]
    fn decode_failure_propagates() {
        // The report is well-formed up to the payload, but the data format
        // byte (0x00) is unknown. The decoder error surfaces whether or not
        // verbose is set; suppressing it is the scan loop's job.
        let pkt = report(ReportSpec {
            ad: &[0x04, 0xFF, 0x99, 0x04, 0x00],
            ..Default::default()
        });
        for verbose in [false, true] {
            let results = parse_advertising_report(&pkt, verbose);
            assert_eq!(results.len(), 1, "decode error must surface in both modes");
            assert!(matches!(
                &results[0],
                Err(DecodeError::UnsupportedFormat(_))
            ));
        }
    }

    #[test]
    fn decodes_stacked_legacy_reports() {
        // Two Ruuvi reports with different AD lengths: the cursor must stride
        // per report instead of assuming a fixed step.
        let long_ad: &[u8] = &[
            0x02, 0x01, 0x06, // flags
            27, 0xFF, 0x99, 0x04, 0x05, // Ruuvi format-5 entry
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let pkt = stacked_packet(
            EVT_LE_ADVERTISING_REPORT,
            &[
                legacy_body([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], RUUVI_AD, 0xB0),
                legacy_body([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], long_ad, 0xC3),
            ],
        );
        assert!(might_be_ruuvi(&pkt));
        let results = parse_event(&pkt, false);
        assert_eq!(results.len(), 2, "both stacked reports should decode");
        let first = results[0].as_ref().expect("first should decode");
        assert_eq!(first.mac, MacAddress([0x06, 0x05, 0x04, 0x03, 0x02, 0x01]));
        assert_eq!(first.rssi, Some(-80));
        let second = results[1].as_ref().expect("second should decode");
        assert_eq!(second.mac, MacAddress([0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A]));
        assert_eq!(second.rssi, Some(-61));
    }

    #[test]
    fn decodes_stacked_extended_reports() {
        // Same stacking guarantee for the extended (0x0D) layout.
        let pkt = stacked_packet(
            EVT_LE_EXTENDED_ADVERTISING_REPORT,
            &[
                extended_body([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], RUUVI_AD, 0xB0),
                extended_body([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], RUUVI_AD, 0xC3),
            ],
        );
        assert!(might_be_ruuvi(&pkt));
        let results = parse_event(&pkt, false);
        assert_eq!(results.len(), 2, "both stacked reports should decode");
        let first = results[0].as_ref().expect("first should decode");
        assert_eq!(first.mac, MacAddress([0x06, 0x05, 0x04, 0x03, 0x02, 0x01]));
        assert_eq!(first.rssi, Some(-80));
        let second = results[1].as_ref().expect("second should decode");
        assert_eq!(second.mac, MacAddress([0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A]));
        assert_eq!(second.rssi, Some(-61));
    }

    #[test]
    fn truncated_second_report_header_is_verbose_error() {
        // num_reports claims two, but the second report is cut mid-header.
        let mut pkt = stacked_packet(
            EVT_LE_ADVERTISING_REPORT,
            &[legacy_body(
                [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                RUUVI_AD,
                0xB0,
            )],
        );
        pkt[4] = 2; // num_reports
        pkt.push(0x00); // partial second report header
        // Silent mode keeps the first decode and drops the truncation.
        let quiet = parse_event(&pkt, false);
        assert_eq!(quiet.len(), 1);
        assert!(quiet[0].is_ok());
        // Verbose mode appends the truncation error.
        let loud = parse_event(&pkt, true);
        assert_eq!(loud.len(), 2);
        assert!(loud[0].is_ok());
        assert_eq!(
            loud[1],
            Err(DecodeError::InvalidData(
                "Advertising report too short".into()
            ))
        );
    }
}
