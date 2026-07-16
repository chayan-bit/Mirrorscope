//! The Go goroutine [`crate::SemanticDecoder`] — one of the novelty pillars
//! (`CLAUDE.md`): reconstruct the logical concurrency structure (goroutines)
//! the Go runtime flattened into `runtime.allgs`, and make it time-travelable
//! through the same portable [`crate::model::TaskTree`] every language decoder
//! produces.
//!
//! Pipeline:
//! 1. [`version`] / [`dwarf`] — resolve the runtime [`offsets::GoLayout`] from
//!    the target binary (DWARF preferred, vendored table as fallback).
//! 2. [`gwalk`] — walk `runtime.allgs` over an abstract [`crate::ProcessView`]
//!    into per-goroutine [`gwalk::GoroutineInfo`].
//! 3. [`status`] — map Go run status + wait reasons onto the portable model.
//! 4. [`decoder`] — assemble the [`crate::model::TaskTree`].
//!
//! Recording/replay/DAP never see any of this — they only ever hold a
//! `Box<dyn SemanticDecoder>`.
//!
//! ## Stack-growth relocation (v1 scope)
//! Go grows a goroutine's stack by allocating a new segment and *relocating*
//! the old one, rewriting pointers (`copystack`). That invalidates any cached
//! stack address across such an event. v1 of this decoder therefore only
//! *exposes* each goroutine's current `stack.lo`/`stack.hi` bounds
//! ([`gwalk::GoroutineInfo`]); treating a stack move as a first-class
//! record/replay event belongs to the recording layer (Phase 5, README §8)
//! and is deliberately not faked here.

pub mod dwarf;
pub mod error;
pub mod gwalk;
pub mod offsets;
pub mod status;
pub mod version;

mod decoder;

pub use decoder::GoroutineDecoder;
pub use error::GoDecodeError;
pub use gwalk::GoroutineInfo;
pub use offsets::{GStructOffsets, GoLayout, LayoutSource};
pub use version::GoVersion;

use offsets::vendored_m_procid;

/// Resolve the full [`GoLayout`] for a Go target from its binary image.
///
/// Prefers DWARF-derived offsets (self-adapting per Go version); falls back to
/// the vendored per-version table when DWARF is stripped but the symbol table
/// and an embedded version string remain.
///
/// # Errors
/// - [`GoDecodeError::NotGoBinary`] if the image is not a Go binary.
/// - [`GoDecodeError::AllgsNotFound`] if `runtime.allgs` cannot be located.
/// - [`GoDecodeError::LayoutUnresolved`] if neither DWARF nor the vendored
///   table can supply the `g` offsets.
pub fn load_layout(image: &[u8]) -> Result<GoLayout, GoDecodeError> {
    let file = object::File::parse(image).map_err(|e| GoDecodeError::Object(e.to_string()))?;
    if !dwarf::is_go_object(&file) {
        return Err(GoDecodeError::NotGoBinary);
    }
    drop(file);

    let extract = dwarf::extract(image)?;
    let allgs_addr = extract.allgs_addr.ok_or(GoDecodeError::AllgsNotFound)?;

    let (g, m_procid, source) = match extract.offsets {
        Some((g, m_procid)) => (g, m_procid, LayoutSource::Dwarf),
        None => resolve_vendored(image)?,
    };

    Ok(GoLayout {
        ptr_size: extract.ptr_size,
        allgs_addr,
        allglen_addr: extract.allglen_addr,
        load_bias: 0,
        g,
        m_procid,
        source,
    })
}

/// Fall back to the vendored offset table, keyed by the binary's embedded Go
/// version string.
fn resolve_vendored(image: &[u8]) -> Result<(GStructOffsets, Option<u64>, LayoutSource), GoDecodeError> {
    let version = GoVersion::detect_in_bytes(image).ok_or_else(|| {
        GoDecodeError::LayoutUnresolved("no DWARF offsets and no embedded go version".to_string())
    })?;
    let g = GStructOffsets::vendored(version).ok_or_else(|| {
        GoDecodeError::LayoutUnresolved(format!(
            "no vendored offset table for go{}.{}",
            version.major, version.minor
        ))
    })?;
    Ok((g, vendored_m_procid(version), LayoutSource::Vendored(version)))
}
