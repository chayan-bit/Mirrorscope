//! Errors specific to building a [`super::GoroutineDecoder`] from a binary.
//! Kept separate from [`crate::DecoderError`] (which the trait methods return)
//! because these arise at *construction* time — parsing the executable and
//! resolving the runtime layout — before any [`crate::ProcessView`] exists.

/// Failure modes for resolving the Go runtime layout out of a target binary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GoDecodeError {
    /// The bytes could not be parsed as an object/ELF file.
    #[error("failed to parse target as an object file: {0}")]
    Object(String),

    /// DWARF parsing failed on an otherwise-valid object file.
    #[error("failed to read DWARF from target: {0}")]
    Dwarf(String),

    /// The binary is not a Go binary (no `.go.buildinfo`, no `runtime.allgs`).
    #[error("target is not a Go binary")]
    NotGoBinary,

    /// `runtime.allgs` could not be located (fully-stripped binary: no symbol
    /// table and no DWARF variable). Walking goroutines is impossible without
    /// it; v1 does not attempt `pclntab`/moduledata recovery.
    #[error("could not locate runtime.allgs (binary stripped of symbols and DWARF)")]
    AllgsNotFound,

    /// Neither DWARF struct offsets nor a vendored table entry could supply
    /// the `g` layout (unknown Go version with stripped DWARF).
    #[error("could not resolve runtime.g offsets: {0}")]
    LayoutUnresolved(String),
}
