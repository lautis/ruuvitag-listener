//! Classic-BPF program construction that filters for Ruuvi manufacturer
//! data at the kernel level.

use super::*;
use crate::scanner::ScanError;
use libc::{SO_ATTACH_FILTER, SOL_SOCKET, c_void, socklen_t};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};

/// BPF instruction structure (classic BPF, not eBPF)
#[repr(C)]
#[derive(Clone, Copy)]
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
    // Ruuvi manufacturer ID as big-endian 16-bit value for BPF comparison
    // BPF loads 16-bit values in network byte order (big-endian)
    const RUUVI_ID_BE: u32 = 0x9904;

    // Build BPF program that checks for Ruuvi manufacturer ID
    // Classic BPF doesn't support loops, so we check multiple fixed offsets
    // where manufacturer data typically appears in advertising reports.
    //
    // HCI LE Advertising Report structure:
    // [0]: Packet type (0x04)
    // [1]: Event code (0x3E)
    // [2]: Parameter length
    // [3]: Subevent code (0x02)
    // [4]: Num reports
    // [5]: Event type
    // [6]: Address type
    // [7-12]: Address (6 bytes)
    // [13]: Data length
    // [14+]: Advertising data (AD structures)
    //
    // AD structure: [length][type][data...]
    // Manufacturer data (type 0xFF): [length][0xFF][mfg_id_lo][mfg_id_hi][data...]

    // Manufacturer data starts at offset 14 in a legacy report but at offset 29
    // in an extended report (the per-report header is larger). We scan a single
    // wide range that covers both layouts.
    const FIRST_OFFSET: u32 = 14;
    const LAST_OFFSET: u32 = 60;
    let num_offsets = (LAST_OFFSET - FIRST_OFFSET + 1) as usize;

    let mut filter = Vec::with_capacity(num_offsets * 2 + 16);

    // [0,1] Check packet type == HCI_EVENT_PKT (0x04)
    filter.push(SockFilter {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 0, // Will be patched to jump to reject
        k: HCI_EVENT_PKT as u32,
    });

    // [2,3] Check event code == EVT_LE_META_EVENT (0x3E)
    filter.push(SockFilter {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 1,
    });
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 0, // Will be patched
        k: EVT_LE_META_EVENT as u32,
    });

    // [4] Load subevent code, then accept either the legacy or the extended
    // advertising report subevent.
    filter.push(SockFilter {
        code: BPF_LD | BPF_B | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 3,
    });
    // [5] subevent == EVT_LE_ADVERTISING_REPORT (0x02): jump to mfg-id checks
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0, // Will be patched to jump to checks_start
        jf: 0, // Fall through to the extended check below
        k: EVT_LE_ADVERTISING_REPORT as u32,
    });
    // [6] subevent == EVT_LE_EXTENDED_ADVERTISING_REPORT (0x0D): otherwise reject
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0, // Will be patched to jump to checks_start
        jf: 0, // Will be patched to jump to reject
        k: EVT_LE_EXTENDED_ADVERTISING_REPORT as u32,
    });

    let checks_start = filter.len();

    // Check for the Ruuvi manufacturer ID at each candidate offset.
    for offset in FIRST_OFFSET..=LAST_OFFSET {
        // Load 16-bit value at this offset
        filter.push(SockFilter {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        });
        // Jump to accept if it matches Ruuvi ID
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0, // Will be patched to jump to accept
            jf: 0, // Continue to next check
            k: RUUVI_ID_BE,
        });
    }

    // Reject: return 0 (drop packet)
    let reject_idx = filter.len();
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: 0,
    });

    // Accept: return max packet size
    let accept_idx = filter.len();
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: 0xFFFF,
    });

    // Patch jump targets. A BPF jump offset is relative to the instruction
    // *after* the jump, so the offset to reach `target` from index `i` is
    // `target - i - 1`.
    // Packet-type and event-code checks reject on mismatch.
    filter[1].jf = (reject_idx - 1 - 1) as u8;
    filter[3].jf = (reject_idx - 3 - 1) as u8;
    // Subevent dispatch: both report types branch to the mfg-id checks; a
    // non-advertising LE Meta Event is rejected.
    filter[5].jt = (checks_start - 5 - 1) as u8;
    filter[6].jt = (checks_start - 6 - 1) as u8;
    filter[6].jf = (reject_idx - 6 - 1) as u8;

    // Manufacturer ID checks jump to accept on success
    for i in 0..num_offsets {
        let check_idx = checks_start + i * 2 + 1; // The JEQ instruction
        filter[check_idx].jt = (accept_idx - check_idx - 1) as u8;
    }

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
