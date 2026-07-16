//! Failure modes of live Tokio task enumeration.
//!
//! Enumeration is best-effort by design (`CLAUDE.md` honesty rule): a Tokio
//! binary we cannot walk must *decline* so the registry falls back to the
//! native decoder, never surface a guessed task set. Every variant here is
//! therefore mapped to [`crate::error::DecoderError::NotApplicable`] at the
//! decoder boundary rather than propagated as a hard failure.

use super::layout::TokioVersion;

/// Why live task enumeration could not run against a target.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnumerateError {
    /// The target's Tokio version has no vendored internal-layout entry, so
    /// the `OwnedTasks` walk would have to guess private offsets — declined.
    #[error("no vendored Tokio internal layout for tokio {0}; live enumeration declines")]
    UnsupportedTokioVersion(TokioVersion),

    /// The binary embeds no recognizable `tokio-<major>.<minor>.<patch>`
    /// version string, so the vendored layout cannot be keyed.
    #[error("no embedded tokio version string; cannot key the internal layout")]
    TokioVersionUnknown,

    /// The `tokio::runtime::context::CONTEXT` thread-local symbol is absent
    /// from the symbol table (stripped binary), so its TLS offset is unknown.
    #[error("tokio runtime CONTEXT thread-local symbol not found")]
    ContextSymbolMissing,

    /// No thread in the target exposed a thread pointer (the backing
    /// [`crate::ProcessView`] does not implement
    /// [`crate::ProcessView::thread_pointer`], or every read failed), so TLS
    /// cannot be resolved.
    #[error("no thread pointer available; TLS-based enumeration is unavailable")]
    ThreadPointerUnavailable,

    /// The main executable's runtime load address could not be obtained, so
    /// the poll-function address map cannot be de-biased.
    #[error("executable load base unavailable; cannot map poll addresses to types")]
    LoadBaseUnavailable,

    /// A pointer chase read implausible data (e.g. a shard count far past any
    /// real runtime), signaling a misresolved layout — declined rather than
    /// trusted.
    #[error("implausible runtime shape while walking OwnedTasks: {0}")]
    Implausible(String),

    /// No thread carried a live runtime handle, so there is no `OwnedTasks`
    /// list to walk (e.g. the runtime was not entered on any stopped thread).
    #[error("no live Tokio runtime handle on any stopped thread")]
    NoRuntimeHandle,

    /// The binary had no `.debug_info`, so the `poll<T, S>` type map cannot be
    /// built.
    #[error("no DWARF debug info; cannot resolve task future types")]
    NoDebugInfo,

    /// Parsing the object file or its DWARF failed.
    #[error("object/DWARF parse error: {0}")]
    Parse(String),
}
