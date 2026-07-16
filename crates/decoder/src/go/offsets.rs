//! The resolved memory layout of the Go runtime a [`super::GoroutineDecoder`]
//! reads: where `runtime.allgs` lives and the byte offsets of the `g` struct
//! fields it walks.
//!
//! Two ways to obtain a [`GoLayout`]:
//! 1. **DWARF-derived** ([`super::dwarf`]) — preferred, self-adapts to any Go
//!    version because the offsets come from the binary's own debug info.
//! 2. **Vendored fallback** ([`GStructOffsets::vendored`]) — a Delve-style
//!    per-Go-version offset table for binaries built with DWARF stripped
//!    (`-ldflags=-w`) but the symbol table intact. Only entries that have
//!    been verified against a real toolchain are included; unknown versions
//!    return `None` so the decoder can decline honestly.

use super::version::GoVersion;

/// Where a [`GoLayout`] came from, for diagnostics and the honesty rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutSource {
    /// Offsets read from the binary's DWARF debug info.
    Dwarf,
    /// Offsets taken from the vendored table for the given Go version.
    Vendored(GoVersion),
}

/// Byte offsets of the `runtime.g` fields the decoder reads, with nested
/// struct fields (`stack.*`, `sched.*`) already flattened to absolute offsets
/// from the start of `g`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GStructOffsets {
    /// `g.goid` (int64): the goroutine id.
    pub goid: u64,
    /// `g.atomicstatus` (uint32): the `_Gxxx` run status.
    pub atomicstatus: u64,
    /// `g.waitreason` (uint8): index into the wait-reason table.
    pub waitreason: u64,
    /// `g.stack.lo` (uintptr): low bound of the goroutine stack.
    pub stack_lo: u64,
    /// `g.stack.hi` (uintptr): high bound of the goroutine stack.
    pub stack_hi: u64,
    /// `g.sched.pc` (uintptr): saved resume PC for a parked goroutine.
    pub sched_pc: u64,
    /// `g.sched.sp` (uintptr): saved stack pointer for a parked goroutine.
    pub sched_sp: u64,
    /// `g.gopc` (uintptr): PC of the `go` statement that created this g.
    pub gopc: u64,
    /// `g.startpc` (uintptr): PC of the goroutine's entry function.
    pub startpc: u64,
    /// `g.m` (pointer): the M currently running this g, or null.
    pub m: u64,
    /// `g.parentGoid` (int64): the creator goroutine's id. `None` on Go
    /// versions predating the field (< 1.21).
    pub parent_goid: Option<u64>,
}

impl GStructOffsets {
    /// The vendored offset table for a known Go `version`, or `None` if the
    /// version is not in the table (the decoder then declines rather than
    /// guessing offsets that shift between releases).
    ///
    /// Verified entries (64-bit; struct field offsets are identical on amd64
    /// and arm64):
    /// - **Go 1.24** — from `go1.24.13` DWARF (`readelf --debug-dump=info`).
    #[must_use]
    pub fn vendored(version: GoVersion) -> Option<Self> {
        match (version.major, version.minor) {
            (1, 24) => Some(Self {
                goid: 160,
                atomicstatus: 152,
                waitreason: 184,
                stack_lo: 0,  // g.stack @0 + stack.lo @0
                stack_hi: 8,  // g.stack @0 + stack.hi @8
                sched_pc: 64, // g.sched @56 + gobuf.pc @8
                sched_sp: 56, // g.sched @56 + gobuf.sp @0
                gopc: 288,
                startpc: 304,
                m: 48,
                parent_goid: Some(280),
            }),
            _ => None,
        }
    }
}

/// The vendored `runtime.m.procid` offset for a known Go `version`, used to
/// map a running goroutine to its OS thread when DWARF is stripped. Verified
/// against `go1.24.13` (offset 72). `None` for unknown versions.
#[must_use]
pub fn vendored_m_procid(version: GoVersion) -> Option<u64> {
    match (version.major, version.minor) {
        (1, 24) => Some(72),
        _ => None,
    }
}

/// The fully-resolved layout the decoder needs to walk `runtime.allgs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoLayout {
    /// Pointer width of the target (bytes). 8 for all supported targets.
    pub ptr_size: u8,
    /// SVMA of the `runtime.allgs` slice header (`{data, len, cap}`), as read
    /// from the binary's symbol table / DWARF. Add [`Self::load_bias`] to get
    /// the runtime address.
    pub allgs_addr: u64,
    /// SVMA of `runtime.allglen` (uintptr), used to cross-check the slice
    /// length. `None` if the symbol/variable was not found.
    pub allglen_addr: Option<u64>,
    /// Load bias to add to the static symbol addresses above to get their
    /// runtime (AVMA) location: `0` for a non-PIE (`ET_EXEC`) executable,
    /// `mapping_base - min_vaddr` for a PIE (`ET_DYN`). Pointers *inside* the
    /// process (slice contents, `g`/`m` pointers) are already runtime
    /// addresses and are never biased.
    pub load_bias: u64,
    /// Offsets of the `g` fields.
    pub g: GStructOffsets,
    /// Offset of `procid` within `runtime.m`, used to map a running goroutine
    /// to its OS thread. `None` if it could not be resolved.
    pub m_procid: Option<u64>,
    /// Provenance of these offsets.
    pub source: LayoutSource,
}

impl GoLayout {
    /// The `_Gscan`-masked slice-header field offsets for a 64-bit target:
    /// `data` at 0, `len` at `ptr_size`, `cap` at `2*ptr_size`.
    #[must_use]
    pub fn slice_len_offset(&self) -> u64 {
        u64::from(self.ptr_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_go_124_has_known_offsets() {
        let off = GStructOffsets::vendored(GoVersion::new(1, 24, 0)).expect("1.24 present");
        assert_eq!(off.goid, 160);
        assert_eq!(off.atomicstatus, 152);
        assert_eq!(off.sched_sp, 56);
        assert_eq!(off.sched_pc, 64);
        assert_eq!(off.parent_goid, Some(280));
    }

    #[test]
    fn unknown_version_declines() {
        assert!(GStructOffsets::vendored(GoVersion::new(1, 30, 0)).is_none());
    }

    #[test]
    fn slice_len_offset_follows_ptr_size() {
        let layout = GoLayout {
            ptr_size: 8,
            allgs_addr: 0x1000,
            allglen_addr: None,
            load_bias: 0,
            g: GStructOffsets::vendored(GoVersion::new(1, 24, 0)).expect("1.24"),
            m_procid: Some(72),
            source: LayoutSource::Vendored(GoVersion::new(1, 24, 0)),
        };
        assert_eq!(layout.slice_len_offset(), 8);
    }
}
