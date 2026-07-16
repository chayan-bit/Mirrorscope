//! The async-Rust (Tokio) [`crate::SemanticDecoder`] — the flagship novelty
//! pillar (`CLAUDE.md`, README §5.2): reconstruct the logical async task tree
//! that rustc and Tokio flattened into coroutine state-machine structs, and
//! make it time-travelable through the same portable [`crate::model::TaskTree`]
//! every language decoder produces.
//!
//! Pipeline:
//! 1. [`rustc_version`] — parse the DWARF producer string and gate the
//!    coroutine layout against the validated rustc window (the "living
//!    compatibility DB", isolated here so layout knowledge lives in one place).
//! 2. [`dwarf`] — read every `{async_fn_env#N}` `DW_TAG_variant_part` into an
//!    [`layout::AsyncFnLayout`]: discriminant, per-`.await` variants, source
//!    lines, the `__awaitee` continuation, and inline `join!` children.
//! 3. [`decode`] — over an abstract [`crate::ProcessView`], read a task's
//!    `__state` discriminant, recurse the `__awaitee` chain into an async
//!    backtrace, classify the leaf future, and read Tokio header state bits.
//! 4. [`decoder`] — assemble the [`crate::model::TaskTree`] from a set of
//!    [`roots::TaskRoot`]s.
//!
//! Recording/replay/DAP never see any of this — they only ever hold a
//! `Box<dyn SemanticDecoder>`.
//!
//! ## Scope & honesty (v1)
//! - **Enumeration is a real walk** ([`enumerate`]): the TLS `CONTEXT` →
//!   sharded `OwnedTasks` → vtable→type anchor is implemented for the verified
//!   window (tokio 1.44.x, current-thread scheduler) and declines honestly
//!   otherwise. The [`roots`] seam is retained so explicit roots (e.g. the
//!   layout-regression test) still drive the same decode.
//! - **`select!`** shares the `join!` fan-out mechanism (multiple pending child
//!   futures in the active variant become tree children); which branch will
//!   win is not predicted — all pending branches are shown, honestly.
//! - **Waker causality** is the cheap leaf-type heuristic only ([`state`]);
//!   true causality is a later phase (#21), not faked here.
//! - **rustc versions**: coroutine DWARF hand-verified against **1.85.1**; the
//!   layout DB accepts the stable-scheme window (see [`rustc_version`]).
//! - **tokio versions**: state-bit constants vendored and stable across the
//!   1.x line (verified 1.44/1.52).

pub mod decode;
pub mod dwarf;
pub mod enumerate;
pub mod error;
pub mod layout;
pub mod roots;
pub mod rustc_version;
pub mod state;

mod decoder;

pub use decoder::TokioDecoder;
pub use enumerate::{EnumerateError, EnumerationPlan, TokioVersion};
pub use error::AsyncDecodeError;
pub use layout::{AsyncFnLayout, AsyncLayouts};
pub use roots::TaskRoot;
pub use rustc_version::RustcVersion;

/// Resolve every async fn coroutine layout and the rustc version from a Tokio
/// target's binary image.
///
/// # Errors
/// Propagates [`AsyncDecodeError`] if the image is not a Tokio binary, has no
/// DWARF, was built by an unsupported rustc, or contains no coroutines.
pub fn load_layouts(image: &[u8]) -> Result<(AsyncLayouts, RustcVersion), AsyncDecodeError> {
    let extract = dwarf::extract(image)?;
    Ok((extract.layouts, extract.version))
}
