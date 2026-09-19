//! Classic-BPF program construction that filters for Ruuvi manufacturer
//! data at the kernel level.

use super::*;
use crate::scanner::ScanError;
use libc::{SO_ATTACH_FILTER, SOL_SOCKET, c_void, socklen_t};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_H: u16 = 0x08; // Half-word (16-bit)
const BPF_B: u16 = 0x10; // Byte
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// Ruuvi manufacturer ID as big-endian 16-bit value for BPF comparison
// (BPF loads half-words in network byte order / big-endian).
const RUUVI_ID_BE: u32 = u16::from_be_bytes(RUUVI_MANUFACTURER_ID_LE) as u32;

// Candidate offsets where the Ruuvi manufacturer ID can appear in an
// advertising report; see the layout on `ruuvi_bpf_program`.
const FIRST_OFFSET: u32 = 14;
const LAST_OFFSET: u32 = 60;
const NUM_OFFSETS: usize = (LAST_OFFSET - FIRST_OFFSET + 1) as usize;

/// BPF instruction structure (classic BPF, not eBPF)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct SockFilter {
    code: u16,
    jt: u8, // Jump if true
    jf: u8, // Jump if false
    k: u32, // Constant/offset
}

/// BPF program structure
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// A branch target for an emitted [`BpfBuilder::jeq`]: fall through to the
/// next instruction, or jump to a label marking an instruction index.
#[derive(Clone, Copy, PartialEq)]
enum JumpTarget {
    Next,
    Label(usize),
}

/// Builder for classic-BPF programs that defers jump-target resolution
/// until [`BpfBuilder::build`].
struct BpfBuilder {
    ops: Vec<SockFilter>,
    // (instruction index, is_jt, target instruction index) to patch at build()
    patches: Vec<(usize, bool, usize)>,
}

impl BpfBuilder {
    fn with_capacity(n: usize) -> Self {
        Self {
            ops: Vec::with_capacity(n),
            patches: Vec::new(),
        }
    }

    fn load_byte(&mut self, offset: u32) {
        self.ops.push(SockFilter {
            code: BPF_LD | BPF_B | BPF_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        });
    }

    fn load_half(&mut self, offset: u32) {
        self.ops.push(SockFilter {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        });
    }

    fn jeq(&mut self, k: u32, jt: JumpTarget, jf: JumpTarget) {
        let idx = self.ops.len();
        self.ops.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 0,
            k,
        });
        if let JumpTarget::Label(target) = jt {
            self.patches.push((idx, true, target));
        }
        if let JumpTarget::Label(target) = jf {
            self.patches.push((idx, false, target));
        }
    }

    fn ret(&mut self, k: u32) {
        self.ops.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        });
    }

    /// Label marking the position of the NEXT instruction to be emitted.
    fn mark(&mut self) -> usize {
        self.ops.len()
    }

    /// Resolve all jump targets. A BPF jump offset is relative to the
    /// instruction AFTER the jump, so target - idx - 1.
    fn build(mut self) -> Vec<SockFilter> {
        for (idx, is_jt, target) in self.patches {
            let offset = target as i32 - idx as i32 - 1;
            let offset: u8 = u8::try_from(offset).expect("BPF jump offset exceeds u8");
            if is_jt {
                self.ops[idx].jt = offset;
            } else {
                self.ops[idx].jf = offset;
            }
        }
        self.ops
    }
}

/// Set up a BPF filter to match Ruuvi manufacturer ID at the kernel level.
///
/// This is the second layer of kernel-level filtering, complementing HCI_FILTER.
/// While HCI_FILTER drops non-LE-Meta-Event packets, this BPF filter provides
/// finer-grained filtering to drop:
/// - Non-advertising LE Meta Events (connection complete, etc.)
/// - Advertisements from non-Ruuvi devices (Tile trackers, smartwatches, etc.)
///
/// The filter checks:
/// 1. Packet type is HCI_EVENT_PKT (0x04)
/// 2. Event code is EVT_LE_META_EVENT (0x3E)
/// 3. Subevent is EVT_LE_ADVERTISING_REPORT (0x02)
/// 4. Packet contains Ruuvi manufacturer ID (0x9904) at common positions
///
/// Combined filtering layers:
/// ```text
/// All HCI packets
///   └─[HCI_FILTER]─► Only LE Meta Events
///       └─[BPF filter]─► Only Ruuvi advertising reports
///           └─[Application]─► Parse and decode
/// ```
pub(crate) fn set_bpf_ruuvi_filter(fd: &OwnedFd) -> Result<(), ScanError> {
    let filter = ruuvi_bpf_program();

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const SockFprog as *const c_void,
            mem::size_of::<SockFprog>() as socklen_t,
        )
    };

    if ret < 0 {
        return Err(ScanError::Bluetooth(format!(
            "Failed to set BPF filter: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Build the classic-BPF program that matches advertising reports containing
/// the Ruuvi manufacturer ID.
///
/// Classic BPF doesn't support loops, so we check multiple fixed offsets
/// where manufacturer data typically appears in advertising reports.
///
/// HCI LE Advertising Report structure:
/// [0]: Packet type (0x04)
/// [1]: Event code (0x3E)
/// [2]: Parameter length
/// [3]: Subevent code (0x02)
/// [4]: Num reports
/// [5]: Event type
/// [6]: Address type
/// [7-12]: Address (6 bytes)
/// [13]: Data length
/// [14+]: Advertising data (AD structures)
///
/// AD structure: [length][type][data...]
/// Manufacturer data (type 0xFF): [length][0xFF][mfg_id_lo][mfg_id_hi][data...]
///
/// Manufacturer data starts at offset 14 in a legacy report but at offset 29
/// in an extended report (the per-report header is larger). We scan a single
/// wide range that covers both layouts.
fn ruuvi_bpf_program() -> Vec<SockFilter> {
    let mut b = BpfBuilder::with_capacity(NUM_OFFSETS * 2 + 16);

    // All branches jump forward to fixed positions: 7 header instructions,
    // one load_half+jeq pair per offset, then reject and accept. Labels are
    // the instruction indices where those blocks start.
    let checks = 7;
    let reject = checks + NUM_OFFSETS * 2;
    let accept = reject + 1;

    // [0,1] Check packet type == HCI_EVENT_PKT (0x04)
    b.load_byte(0);
    b.jeq(
        HCI_EVENT_PKT as u32,
        JumpTarget::Next,
        JumpTarget::Label(reject),
    );

    // [2,3] Check event code == EVT_LE_META_EVENT (0x3E)
    b.load_byte(1);
    b.jeq(
        EVT_LE_META_EVENT as u32,
        JumpTarget::Next,
        JumpTarget::Label(reject),
    );

    // [4] Load subevent code, then accept either the legacy or the extended
    // advertising report subevent.
    b.load_byte(3);
    // [5] subevent == EVT_LE_ADVERTISING_REPORT (0x02): jump to mfg-id checks
    b.jeq(
        EVT_LE_ADVERTISING_REPORT as u32,
        JumpTarget::Label(checks),
        JumpTarget::Next,
    );
    // [6] subevent == EVT_LE_EXTENDED_ADVERTISING_REPORT (0x0D): otherwise reject
    b.jeq(
        EVT_LE_EXTENDED_ADVERTISING_REPORT as u32,
        JumpTarget::Label(checks),
        JumpTarget::Label(reject),
    );
    debug_assert_eq!(b.mark(), checks);

    // Check for the Ruuvi manufacturer ID at each candidate offset.
    for offset in FIRST_OFFSET..=LAST_OFFSET {
        b.load_half(offset);
        b.jeq(RUUVI_ID_BE, JumpTarget::Label(accept), JumpTarget::Next);
    }

    // Reject: return 0 (drop packet)
    debug_assert_eq!(b.mark(), reject);
    b.ret(0);

    // Accept: return max packet size
    debug_assert_eq!(b.mark(), accept);
    b.ret(0xFFFF);

    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Software classic-BPF interpreter for the instruction subset
    /// [`ruuvi_bpf_program`] emits: absolute byte/half-word loads, `JEQ|K`
    /// jumps, and `RET|K`. Returns the verdict: zero drops the packet,
    /// non-zero keeps it.
    fn run_bpf(prog: &[SockFilter], pkt: &[u8]) -> u32 {
        let mut pc = 0usize;
        let mut a: u32 = 0;
        loop {
            let ins = &prog[pc];
            match ins.code & 0x07 {
                // BPF_RET | BPF_K: verdict is the number of bytes to keep.
                0x06 => return ins.k,
                // BPF_LD | BPF_ABS: A = byte, or half-word big-endian, at k.
                0x00 => {
                    let off = ins.k as usize;
                    a = match ins.code & 0x18 {
                        0x10 => *pkt.get(off).unwrap_or(&0) as u32, // BPF_B
                        0x08 => {
                            // BPF_H: the kernel loads half-words big-endian
                            let hi = *pkt.get(off).unwrap_or(&0);
                            let lo = *pkt.get(off + 1).unwrap_or(&0);
                            u32::from(u16::from_be_bytes([hi, lo]))
                        }
                        size => panic!("unsupported load size {size:#04x}"),
                    };
                }
                // BPF_JMP | BPF_JEQ | BPF_K: take jt when A == k, else jf.
                // The generated program only jumps forward.
                0x05 => {
                    let offset = if a == ins.k { ins.jt } else { ins.jf };
                    pc += 1 + offset as usize;
                    continue;
                }
                class => panic!("unsupported instruction class {class:#02x}"),
            }
            pc += 1;
        }
    }

    /// Ruuvi manufacturer ID as it appears on the wire: bytes 0x99 0x04,
    /// big-endian.
    const RUUVI_ID_WIRE: [u8; 2] = {
        let bytes = RUUVI_ID_BE.to_be_bytes();
        [bytes[2], bytes[3]]
    };

    /// Build an HCI advertising report with a manufacturer ID at `id_off`.
    /// Every other payload byte is zeroed so no other offset can match.
    fn advertising_report(subevent: u8, id_off: usize, id: [u8; 2]) -> Vec<u8> {
        let mut pkt = vec![0u8; 80];
        pkt[0] = HCI_EVENT_PKT;
        pkt[1] = EVT_LE_META_EVENT;
        pkt[2] = (pkt.len() - 4) as u8; // parameter length
        pkt[3] = subevent;
        pkt[4] = 1; // num reports
        pkt[id_off..id_off + 2].copy_from_slice(&id);
        pkt
    }

    /// Whether the Ruuvi filter keeps `pkt` — the test view of `run_bpf`'s
    /// byte-count verdict.
    fn kept(pkt: &[u8]) -> bool {
        run_bpf(&ruuvi_bpf_program(), pkt) != 0
    }

    #[test]
    fn test_filter_accepts_legacy_ruuvi_report() {
        // Legacy report: AD data starts at offset 14, so a real RuuviTag's
        // manufacturer ID (after the AD length and type bytes) sits at 16.
        assert!(kept(&advertising_report(
            EVT_LE_ADVERTISING_REPORT,
            16,
            RUUVI_ID_WIRE
        )));
    }

    #[test]
    fn test_filter_accepts_extended_ruuvi_report() {
        // Extended report: the per-report header is 25 bytes, so AD data
        // starts at offset 29 and the manufacturer ID follows at 31.
        assert!(kept(&advertising_report(
            EVT_LE_EXTENDED_ADVERTISING_REPORT,
            31,
            RUUVI_ID_WIRE
        )));
    }

    #[test]
    fn test_filter_accepts_id_at_every_scanned_offset() {
        for off in FIRST_OFFSET..=LAST_OFFSET {
            assert!(
                kept(&advertising_report(
                    EVT_LE_ADVERTISING_REPORT,
                    off as usize,
                    RUUVI_ID_WIRE
                )),
                "ID at byte {off} dropped"
            );
        }
    }

    #[test]
    fn test_filter_rejects_id_outside_scanned_window() {
        for off in [FIRST_OFFSET - 1, LAST_OFFSET + 1, LAST_OFFSET + 2] {
            assert!(
                !kept(&advertising_report(
                    EVT_LE_ADVERTISING_REPORT,
                    off as usize,
                    RUUVI_ID_WIRE
                )),
                "ID at byte {off} kept"
            );
        }
    }

    #[test]
    fn test_filter_rejects_non_ruuvi_packets() {
        // A valid advertising report carrying a different manufacturer ID at
        // the Ruuvi position is dropped.
        assert!(!kept(&advertising_report(
            EVT_LE_ADVERTISING_REPORT,
            16,
            [0x12, 0x34]
        )));

        // Wrong packet type or event code never reaches the ID checks,
        // regardless of where the ID bytes land.
        let mut pkt = advertising_report(EVT_LE_ADVERTISING_REPORT, 16, RUUVI_ID_WIRE);
        pkt[0] = 0x02;
        assert!(!kept(&pkt));

        let mut pkt = advertising_report(EVT_LE_ADVERTISING_REPORT, 16, RUUVI_ID_WIRE);
        pkt[1] = 0x05;
        assert!(!kept(&pkt));

        // An unknown subevent is never decoded as an advertising report.
        assert!(!kept(&advertising_report(0x0B, 16, RUUVI_ID_WIRE)));
    }

    #[test]
    fn test_bpf_builder_resolves_jump_targets() {
        let mut b = BpfBuilder::with_capacity(4);
        b.load_byte(0);
        // `a` labels the final ret(0xFFFF) at instruction index 3.
        let a = 3;
        b.jeq(5, JumpTarget::Label(a), JumpTarget::Next);
        b.ret(0);
        assert_eq!(b.mark(), a);
        b.ret(0xFFFF);

        let prog = b.build();
        assert_eq!(prog.len(), 4);
        assert_eq!(prog[1].jt, 1); // target(3) - idx(1) - 1
        assert_eq!(prog[1].jf, 0); // JumpTarget::Next falls through
        assert_eq!(prog[1].k, 5);
        assert_eq!(prog[0].code, BPF_LD | BPF_B | BPF_ABS);
        assert_eq!(prog[0].k, 0);
        assert_eq!(prog[2].code, BPF_RET | BPF_K);
        assert_eq!(prog[2].k, 0);
        assert_eq!(prog[3].code, BPF_RET | BPF_K);
        assert_eq!(prog[3].k, 0xFFFF);
    }
}
