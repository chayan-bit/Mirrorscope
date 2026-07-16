//! Portable retroactive-watchpoint core (issue #12).
//!
//! Retroactive watchpoints answer "show me *every* write to this location
//! across the whole recorded history" — a query that only exists once you can
//! replay, because nothing logged individual memory writes at record time. The
//! Linux engine arms a hardware watchpoint over a full replay pass and collects
//! every hit; this module holds the parts that need no ptrace at all so they
//! compile and unit-test on every host (including the macOS dev machine):
//!
//! - the [`WatchKind`]/[`WatchHit`] vocabulary,
//! - request [`validate`]ation and the single-granule [`fits_in_granule`]
//!   range check,
//! - the debug-register encoding math for both architectures
//!   ([`x86_dr7`], [`aarch64_control`]).
//!
//! Keeping this arithmetic here — free of any `nix`/`libc` reference — means the
//! load-bearing "how do I tell the CPU to trap on this address" logic is covered
//! by ordinary `cargo test`, exactly as [`crate::checkpoint_select`] does for
//! checkpoint selection. The Linux arming that consumes these values lives in
//! [`crate::watchpoint_hw`].

use unwind::SymbolizedFrame;

/// What kind of access should trip the watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    /// Trap only on writes to the range.
    Write,
    /// Trap on both reads and writes to the range.
    ReadWrite,
}

/// One recorded access to the watched range during a replay pass.
///
/// A hit is reported for every hardware trap; consecutive writes (even of the
/// same value) each produce their own hit, so repeated writes in a loop are
/// never collapsed. `seq` is the *nearest* trace event — the last syscall
/// boundary consumed before the write — since a write between two syscalls has
/// no sequence number of its own.
#[derive(Debug, Clone)]
pub struct WatchHit {
    /// The nearest preceding trace sequence number (`None` before any syscall).
    pub seq: Option<u64>,
    /// The instruction pointer at the trap.
    pub pc: u64,
    /// The bytes at the range before this access, when known (the value from
    /// the previous hit, or the initial pre-scan read).
    pub old_value: Option<Vec<u8>>,
    /// The bytes at the range after this access.
    pub new_value: Vec<u8>,
    /// Symbolized backtrace captured at the trap, innermost frame first.
    pub backtrace: Vec<SymbolizedFrame>,
}

/// Errors validating a watchpoint request.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WatchpointError {
    /// Hardware watchpoints only cover 1, 2, 4, or 8 byte ranges.
    #[error("unsupported watchpoint length {0}: must be 1, 2, 4, or 8 bytes")]
    InvalidLen(u8),
    /// The address is not naturally aligned to its length, so the range would
    /// straddle the 8-byte hardware granule and cannot be encoded.
    #[error("watchpoint address {addr:#x} is not aligned to its {len}-byte length")]
    Misaligned {
        /// The offending address.
        addr: u64,
        /// The requested length.
        len: u8,
    },
}

/// Whether `len` is one of the hardware-supported watchpoint sizes.
pub(crate) fn is_valid_len(len: u8) -> bool {
    matches!(len, 1 | 2 | 4 | 8)
}

/// Whether `[addr, addr+len)` fits inside a single 8-byte aligned granule — the
/// unit a hardware watchpoint can cover. Natural alignment (`addr % len == 0`)
/// with a supported `len` guarantees this, which is what [`validate`] enforces.
pub(crate) fn fits_in_granule(addr: u64, len: u8) -> bool {
    let offset = addr & 0x7;
    offset + u64::from(len) <= 8
}

/// Validate a watchpoint request: a supported length and natural alignment so
/// the range sits within one hardware granule.
pub fn validate(addr: u64, len: u8) -> Result<(), WatchpointError> {
    if !is_valid_len(len) {
        return Err(WatchpointError::InvalidLen(len));
    }
    if addr % u64::from(len) != 0 || !fits_in_granule(addr, len) {
        return Err(WatchpointError::Misaligned { addr, len });
    }
    Ok(())
}

// The encoders below come in an x86-64 and an aarch64 flavour. Both are always
// compiled (and unit-tested) so the arithmetic is checked on every host, but on
// any single target only the matching flavour is called from `watchpoint_hw`,
// so the other is `dead_code` in a non-test build — hence the `allow` on each.

/// The `LEN` field encoding for an x86-64 debug-control register.
#[allow(dead_code)]
fn x86_len_bits(len: u8) -> Result<u64, WatchpointError> {
    match len {
        1 => Ok(0b00),
        2 => Ok(0b01),
        8 => Ok(0b10),
        4 => Ok(0b11),
        other => Err(WatchpointError::InvalidLen(other)),
    }
}

/// The `R/W` field encoding for an x86-64 debug-control register. x86 has no
/// write-plus-not-read data breakpoint, so read/write covers reads.
#[allow(dead_code)]
fn x86_rw_bits(kind: WatchKind) -> u64 {
    match kind {
        WatchKind::Write => 0b01,
        WatchKind::ReadWrite => 0b11,
    }
}

/// Encode `DR7` to arm debug slot 0 (`DR0`) with the given kind and length:
/// local-enable bit `L0`, condition field `R/W0`, and size field `LEN0`.
#[allow(dead_code)]
pub(crate) fn x86_dr7(kind: WatchKind, len: u8) -> Result<u64, WatchpointError> {
    let len_bits = x86_len_bits(len)?;
    let rw = x86_rw_bits(kind);
    Ok(1 | (rw << 16) | (len_bits << 18))
}

/// The `LSC` (load/store control) field for an aarch64 `DBGWCR`.
#[allow(dead_code)]
fn aarch64_lsc(kind: WatchKind) -> u32 {
    match kind {
        WatchKind::Write => 0b10,
        WatchKind::ReadWrite => 0b11,
    }
}

/// The `BAS` (byte-address-select) mask selecting `len` bytes at the address's
/// offset within its 8-byte aligned granule.
#[allow(dead_code)]
fn aarch64_bas(addr: u64, len: u8) -> u32 {
    let offset = (addr & 0x7) as u32;
    (((1u32 << len) - 1) & 0xff) << offset
}

/// Encode an aarch64 hardware watchpoint as `(aligned_address, control)` for
/// the `NT_ARM_HW_WATCH` regset: `DBGWVR` is the 8-byte-aligned base and
/// `DBGWCR` carries enable (`E`), EL0 privilege (`PAC`), the load/store control
/// (`LSC`), and the byte-address-select mask (`BAS`).
#[allow(dead_code)]
pub(crate) fn aarch64_control(
    addr: u64,
    len: u8,
    kind: WatchKind,
) -> Result<(u64, u32), WatchpointError> {
    if !is_valid_len(len) {
        return Err(WatchpointError::InvalidLen(len));
    }
    let aligned = addr & !0x7;
    let e = 1u32;
    let pac = 0b10u32 << 1; // EL0 (unprivileged) watchpoint
    let lsc = aarch64_lsc(kind) << 3;
    let bas = aarch64_bas(addr, len) << 5;
    Ok((aligned, e | pac | lsc | bas))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_supported_lengths_when_aligned() {
        assert!(validate(0x1000, 1).is_ok());
        assert!(validate(0x1000, 2).is_ok());
        assert!(validate(0x1000, 4).is_ok());
        assert!(validate(0x1000, 8).is_ok());
        assert!(validate(0x1004, 4).is_ok());
        assert!(validate(0x1002, 2).is_ok());
    }

    #[test]
    fn validate_rejects_unsupported_lengths() {
        assert_eq!(validate(0x1000, 3), Err(WatchpointError::InvalidLen(3)));
        assert_eq!(validate(0x1000, 0), Err(WatchpointError::InvalidLen(0)));
        assert_eq!(validate(0x1000, 16), Err(WatchpointError::InvalidLen(16)));
    }

    #[test]
    fn validate_rejects_misaligned_addresses() {
        assert_eq!(
            validate(0x1001, 4),
            Err(WatchpointError::Misaligned {
                addr: 0x1001,
                len: 4
            })
        );
        assert_eq!(
            validate(0x1002, 8),
            Err(WatchpointError::Misaligned {
                addr: 0x1002,
                len: 8
            })
        );
    }

    #[test]
    fn fits_in_granule_matches_natural_alignment() {
        assert!(fits_in_granule(0x1000, 8));
        assert!(fits_in_granule(0x1004, 4));
        assert!(!fits_in_granule(0x1005, 4)); // 5 + 4 = 9 > 8
        assert!(!fits_in_granule(0x1001, 8));
    }

    #[test]
    fn x86_dr7_encodes_write_watch_of_eight_bytes() {
        // L0=1, R/W0=01 (write) at bit 16, LEN0=10 (8 bytes) at bit 18.
        let dr7 = x86_dr7(WatchKind::Write, 8).expect("valid");
        assert_eq!(dr7, 1 | (0b01 << 16) | (0b10 << 18));
        assert_eq!(dr7, 0x9_0001);
    }

    #[test]
    fn x86_dr7_encodes_readwrite_watch_of_four_bytes() {
        // R/W0=11 (read/write), LEN0=11 (4 bytes).
        let dr7 = x86_dr7(WatchKind::ReadWrite, 4).expect("valid");
        assert_eq!(dr7, 1 | (0b11 << 16) | (0b11 << 18));
        assert_eq!(dr7, 0xf_0001);
    }

    #[test]
    fn x86_dr7_rejects_bad_length() {
        assert_eq!(
            x86_dr7(WatchKind::Write, 3),
            Err(WatchpointError::InvalidLen(3))
        );
    }

    #[test]
    fn aarch64_control_encodes_aligned_eight_byte_write() {
        let (aligned, ctrl) = aarch64_control(0x4020, 8, WatchKind::Write).expect("valid");
        assert_eq!(aligned, 0x4020);
        // E=1, PAC=10<<1, LSC=10<<3 (store), BAS=0xff<<5.
        assert_eq!(ctrl, 1 | (0b10 << 1) | (0b10 << 3) | (0xff << 5));
        assert_eq!(ctrl, 0x1ff5);
    }

    #[test]
    fn aarch64_control_selects_sub_granule_bytes_via_bas() {
        // 4 bytes at offset 4 of the granule: BAS = 0b1111 shifted to byte 4.
        let (aligned, ctrl) = aarch64_control(0x4024, 4, WatchKind::ReadWrite).expect("valid");
        assert_eq!(aligned, 0x4020);
        let bas = (0xf << 4) << 5;
        assert_eq!(ctrl, 1 | (0b10 << 1) | (0b11 << 3) | bas);
    }

    #[test]
    fn aarch64_control_rejects_bad_length() {
        assert_eq!(
            aarch64_control(0x4020, 5, WatchKind::Write),
            Err(WatchpointError::InvalidLen(5))
        );
    }
}
