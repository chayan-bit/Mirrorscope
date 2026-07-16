//! Static-TLS address arithmetic: turn a stopped thread's thread-pointer plus
//! the `CONTEXT` symbol's TLS-block offset into the variable's runtime address.
//!
//! Tokio is statically linked into the target, so `CONTEXT` lives in the main
//! executable's TLS module (module 1), reached with the local-exec model — a
//! fixed offset from the thread pointer, no DTV indirection. The offset math
//! is ABI-specific:
//!
//! - **aarch64 (variant I)** — the static TLS block sits *above* the thread
//!   pointer, past a two-word thread-control block: `addr = tp +
//!   align_up(TCB_SIZE, align) + tls_offset`, `TCB_SIZE = 2 * ptr`. Verified
//!   against a live aarch64 tokio target (`tp + 16 + 0`).
//! - **x86-64 (variant II)** — the static TLS block sits *below* the thread
//!   pointer: `addr = tp - align_up(block_size, align) + tls_offset`. Provided
//!   for completeness; the flagship path is exercised on aarch64.
//!
//! Kept pure (no ptrace, no arch intrinsics) so it unit-tests on any host.

/// Size of the aarch64 variant-I thread-control block preceding the static TLS
/// block: two pointers.
const AARCH64_TCB_SIZE: u64 = 16;

/// The TLS ABI variant a target uses to place its static TLS block relative to
/// the thread pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVariant {
    /// Variant I (aarch64, and others): static block above `tp`, past a TCB.
    VariantI,
    /// Variant II (x86-64): static block below `tp`.
    VariantII,
}

impl TlsVariant {
    /// The variant used by the host architecture this decoder was built for.
    #[must_use]
    pub fn host() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::VariantII
        } else {
            // aarch64 (the flagship target) and other variant-I ABIs.
            Self::VariantI
        }
    }
}

/// Round `value` up to the next multiple of `align` (a power of two, or 1).
fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align) * align
}

/// The runtime address of a static-TLS variable.
///
/// * `thread_pointer` — the stopped thread's TP register (`TPIDR_EL0` /
///   `fs_base`).
/// * `tls_offset` — the variable's `st_value`: its offset within the module's
///   TLS block, as recorded in the ELF symbol table.
/// * `tls_align` — the alignment of the executable's `PT_TLS` segment.
/// * `block_size` — the total size of the executable's static TLS block
///   (`PT_TLS` `p_memsz`); only used by variant II.
#[must_use]
pub fn static_tls_address(
    variant: TlsVariant,
    thread_pointer: u64,
    tls_offset: u64,
    tls_align: u64,
    block_size: u64,
) -> u64 {
    match variant {
        TlsVariant::VariantI => {
            let tcb = align_up(AARCH64_TCB_SIZE, tls_align.max(1));
            thread_pointer
                .wrapping_add(tcb)
                .wrapping_add(tls_offset)
        }
        TlsVariant::VariantII => {
            let block = align_up(block_size, tls_align.max(1));
            thread_pointer
                .wrapping_sub(block)
                .wrapping_add(tls_offset)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_up_to_power_of_two() {
        assert_eq!(align_up(16, 8), 16);
        assert_eq!(align_up(16, 32), 32);
        assert_eq!(align_up(17, 16), 32);
        assert_eq!(align_up(5, 1), 5);
    }

    #[test]
    fn variant_i_matches_measured_aarch64_tokio_target() {
        // Measured live: tp = 0xffff841bd760, CONTEXT = 0xffff841bd770,
        // st_value = 0, PT_TLS align = 8 → TCB 16, offset +16.
        let addr = static_tls_address(TlsVariant::VariantI, 0xffff_841b_d760, 0, 8, 72);
        assert_eq!(addr, 0xffff_841b_d770);
    }

    #[test]
    fn variant_i_respects_large_tls_alignment() {
        // A 64-byte-aligned TLS segment pushes the block past the 16-byte TCB.
        let addr = static_tls_address(TlsVariant::VariantI, 0x1000, 8, 64, 128);
        assert_eq!(addr, 0x1000 + 64 + 8);
    }

    #[test]
    fn variant_ii_places_block_below_tp() {
        // x86-64: block of 72 bytes, align 16 → 80 below tp, then +offset.
        let addr = static_tls_address(TlsVariant::VariantII, 0x10000, 8, 16, 72);
        assert_eq!(addr, 0x10000 - 80 + 8);
    }

    #[test]
    fn host_variant_is_defined() {
        // Just exercises the cfg branch on whichever host runs the test.
        let _ = TlsVariant::host();
    }
}
