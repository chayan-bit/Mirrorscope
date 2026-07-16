//! Errors specific to building a [`super::TokioDecoder`] from a binary and
//! resolving its async state-machine layouts. Kept separate from
//! [`crate::DecoderError`] (which the trait methods return) because these
//! arise at *construction* time — parsing the executable and reading the
//! rustc-emitted coroutine DWARF — before any [`crate::ProcessView`] exists.
//! Mirrors [`crate::go::GoDecodeError`].

/// Failure modes for resolving async-Rust coroutine layouts out of a target
/// binary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AsyncDecodeError {
    /// The bytes could not be parsed as an object/ELF file.
    #[error("failed to parse target as an object file: {0}")]
    Object(String),

    /// DWARF parsing failed on an otherwise-valid object file.
    #[error("failed to read DWARF from target: {0}")]
    Dwarf(String),

    /// The binary shows no sign of a Tokio runtime (no `tokio::runtime`
    /// symbols). The Tokio decoder declines rather than guessing.
    #[error("target is not a Tokio binary (no tokio runtime symbols found)")]
    NotTokioBinary,

    /// The binary has no DWARF debug info, so no coroutine state-machine
    /// layouts can be recovered. Unlike the Go decoder, there is no vendored
    /// fallback: async fn env layouts are rustc-version- and
    /// monomorphization-specific and only exist in the binary's own DWARF.
    #[error("target has no DWARF debug info; async layouts require debuginfo=1+")]
    NoDebugInfo,

    /// The DWARF producer string was recognized but its rustc version is
    /// outside the layout DB's validated range, or the producer could not be
    /// parsed at all. Per the honesty rule we decline rather than assume a
    /// coroutine layout that may have shifted between rustc releases.
    #[error("unsupported or unrecognized rustc layout: {0}")]
    UnsupportedLayout(String),

    /// No `async fn` coroutine types were found in the DWARF. Either the
    /// program uses no async fns, or its debuginfo was emitted without the
    /// variant-part representation this decoder relies on.
    #[error("no async fn coroutine types found in DWARF")]
    NoCoroutines,
}
