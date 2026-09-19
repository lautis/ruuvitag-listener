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

    #[test]
    fn test_ruuvi_bpf_program_matches_previous_output() {
        // Byte-identical to the program produced before the BpfBuilder
        // refactor (captured from the hardcoded jump-patching version).
        const EXPECTED: &[SockFilter] = &[
            SockFilter {
                code: 48,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: 21,
                jt: 0,
                jf: 99,
                k: 4,
            },
            SockFilter {
                code: 48,
                jt: 0,
                jf: 0,
                k: 1,
            },
            SockFilter {
                code: 21,
                jt: 0,
                jf: 97,
                k: 62,
            },
            SockFilter {
                code: 48,
                jt: 0,
                jf: 0,
                k: 3,
            },
            SockFilter {
                code: 21,
                jt: 1,
                jf: 0,
                k: 2,
            },
            SockFilter {
                code: 21,
                jt: 0,
                jf: 94,
                k: 13,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 14,
            },
            SockFilter {
                code: 21,
                jt: 93,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 15,
            },
            SockFilter {
                code: 21,
                jt: 91,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 16,
            },
            SockFilter {
                code: 21,
                jt: 89,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 17,
            },
            SockFilter {
                code: 21,
                jt: 87,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 18,
            },
            SockFilter {
                code: 21,
                jt: 85,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 19,
            },
            SockFilter {
                code: 21,
                jt: 83,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 20,
            },
            SockFilter {
                code: 21,
                jt: 81,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 21,
            },
            SockFilter {
                code: 21,
                jt: 79,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 22,
            },
            SockFilter {
                code: 21,
                jt: 77,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 23,
            },
            SockFilter {
                code: 21,
                jt: 75,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 24,
            },
            SockFilter {
                code: 21,
                jt: 73,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 25,
            },
            SockFilter {
                code: 21,
                jt: 71,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 26,
            },
            SockFilter {
                code: 21,
                jt: 69,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 27,
            },
            SockFilter {
                code: 21,
                jt: 67,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 28,
            },
            SockFilter {
                code: 21,
                jt: 65,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 29,
            },
            SockFilter {
                code: 21,
                jt: 63,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 30,
            },
            SockFilter {
                code: 21,
                jt: 61,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 31,
            },
            SockFilter {
                code: 21,
                jt: 59,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 32,
            },
            SockFilter {
                code: 21,
                jt: 57,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 33,
            },
            SockFilter {
                code: 21,
                jt: 55,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 34,
            },
            SockFilter {
                code: 21,
                jt: 53,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 35,
            },
            SockFilter {
                code: 21,
                jt: 51,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 36,
            },
            SockFilter {
                code: 21,
                jt: 49,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 37,
            },
            SockFilter {
                code: 21,
                jt: 47,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 38,
            },
            SockFilter {
                code: 21,
                jt: 45,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 39,
            },
            SockFilter {
                code: 21,
                jt: 43,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 40,
            },
            SockFilter {
                code: 21,
                jt: 41,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 41,
            },
            SockFilter {
                code: 21,
                jt: 39,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 42,
            },
            SockFilter {
                code: 21,
                jt: 37,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 43,
            },
            SockFilter {
                code: 21,
                jt: 35,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 44,
            },
            SockFilter {
                code: 21,
                jt: 33,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 45,
            },
            SockFilter {
                code: 21,
                jt: 31,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 46,
            },
            SockFilter {
                code: 21,
                jt: 29,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 47,
            },
            SockFilter {
                code: 21,
                jt: 27,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 48,
            },
            SockFilter {
                code: 21,
                jt: 25,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 49,
            },
            SockFilter {
                code: 21,
                jt: 23,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 50,
            },
            SockFilter {
                code: 21,
                jt: 21,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 51,
            },
            SockFilter {
                code: 21,
                jt: 19,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 52,
            },
            SockFilter {
                code: 21,
                jt: 17,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 53,
            },
            SockFilter {
                code: 21,
                jt: 15,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 54,
            },
            SockFilter {
                code: 21,
                jt: 13,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 55,
            },
            SockFilter {
                code: 21,
                jt: 11,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 56,
            },
            SockFilter {
                code: 21,
                jt: 9,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 57,
            },
            SockFilter {
                code: 21,
                jt: 7,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 58,
            },
            SockFilter {
                code: 21,
                jt: 5,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 59,
            },
            SockFilter {
                code: 21,
                jt: 3,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 40,
                jt: 0,
                jf: 0,
                k: 60,
            },
            SockFilter {
                code: 21,
                jt: 1,
                jf: 0,
                k: 39172,
            },
            SockFilter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 65535,
            },
        ];
        assert_eq!(ruuvi_bpf_program(), EXPECTED);
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

    #[test]
    fn test_ruuvi_bpf_program_structure() {
        let prog = ruuvi_bpf_program();
        assert_eq!(prog.len(), NUM_OFFSETS * 2 + 9);
        assert_eq!(prog[0].code, BPF_LD | BPF_B | BPF_ABS);
        assert_eq!(prog[0].k, 0);
        assert_eq!(prog[1].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(prog[1].k, HCI_EVENT_PKT as u32);
        let last = prog.len() - 1;
        assert_eq!(prog[last - 1].code, BPF_RET | BPF_K);
        assert_eq!(prog[last - 1].k, 0); // reject
        assert_eq!(prog[last].code, BPF_RET | BPF_K);
        assert_eq!(prog[last].k, 0xFFFF); // accept
    }
}
