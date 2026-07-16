//! The rustc-version layout DB gate (`CLAUDE.md`: "state-machine layout is
//! unstable across rustc versions → per-rustc-version layout DB pinned via the
//! DWARF producer string, treat as a living compatibility DB").
//!
//! rustc stamps every compilation unit with a `DW_AT_producer` string of the
//! form `clang LLVM (rustc version 1.85.1 (4eb161250 2025-03-15))`. This
//! module parses that string into a [`RustcVersion`] and decides whether the
//! coroutine layout for that version is one this decoder has been validated
//! against. Unknown producers are declined honestly (never guessed at) — the
//! single point where "which rustc emitted this" knowledge lives.

/// A parsed rustc toolchain version recovered from a `DW_AT_producer` string.
/// Only `major.minor` drive layout gating; `patch` is retained for
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustcVersion {
    /// Major version (always `1` for released Rust).
    pub major: u16,
    /// Minor version (e.g. `85`).
    pub minor: u16,
    /// Patch version (e.g. `1`), `0` if absent.
    pub patch: u16,
}

impl RustcVersion {
    /// Construct a version triple.
    #[must_use]
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Extract the rustc version from a `DW_AT_producer` string.
    ///
    /// Handles the canonical `clang LLVM (rustc version 1.85.1 (<hash>
    /// <date>))` form; returns `None` for producers with no
    /// `rustc version <n>.<n>` token (e.g. a C translation unit linked in).
    #[must_use]
    pub fn parse_producer(producer: &str) -> Option<Self> {
        let after = producer.split("rustc version ").nth(1)?;
        let token = after.split([' ', '(', ')']).next()?;
        Self::parse_triple(token)
    }

    /// Parse a bare `1.85.1` / `1.85` version token.
    fn parse_triple(token: &str) -> Option<Self> {
        let mut parts = token.split('.');
        let major = parse_leading_number(parts.next()?)?;
        let minor = parse_leading_number(parts.next()?)?;
        let patch = parts
            .next()
            .and_then(parse_leading_number)
            .unwrap_or_default();
        Some(Self::new(major, minor, patch))
    }
}

/// Parse the leading run of ASCII digits of `s`, ignoring a trailing suffix
/// (e.g. `"0-nightly"` -> `0`). `None` if there is no leading digit.
fn parse_leading_number(s: &str) -> Option<u16> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    s[..end].parse().ok()
}

/// The inclusive rustc `minor`-version window this decoder's coroutine-layout
/// reader has been validated against.
///
/// Validation basis: the coroutine DWARF representation (a
/// `DW_TAG_structure_type` named `{async_fn_env#N}` whose sole child is a
/// `DW_TAG_variant_part` with a `DW_AT_discr` pointing at an artificial
/// `__state` member, and per-suspend `DW_TAG_variant`s carrying
/// `DW_AT_decl_line`) was hand-verified against **rustc 1.85.1** DWARF. The
/// scheme has been stable since generators gained multi-variant layouts
/// (rustc ~1.63) and per-variant line info (~1.46), so the window is opened
/// conservatively from 1.63; the upper bound tracks the latest validated
/// toolchain and is bumped only after re-verifying against it.
pub const SUPPORTED_MINOR: std::ops::RangeInclusive<u16> = 63..=94;

/// Whether [`RustcVersion`] falls within the validated layout window.
///
/// This is the honesty backstop: a binary built by a rustc outside the window
/// is declined ([`super::AsyncDecodeError::UnsupportedLayout`]) rather than
/// decoded with layout assumptions that may not hold.
#[must_use]
pub fn is_supported(version: RustcVersion) -> bool {
    version.major == 1 && SUPPORTED_MINOR.contains(&version.minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_producer() {
        let p = "clang LLVM (rustc version 1.85.1 (4eb161250 2025-03-15))";
        assert_eq!(
            RustcVersion::parse_producer(p),
            Some(RustcVersion::new(1, 85, 1))
        );
    }

    #[test]
    fn parses_major_minor_only_producer() {
        let p = "clang LLVM (rustc version 1.90 (abcdef 2026-01-01))";
        assert_eq!(
            RustcVersion::parse_producer(p),
            Some(RustcVersion::new(1, 90, 0))
        );
    }

    #[test]
    fn parses_nightly_suffix() {
        let p = "clang LLVM (rustc version 1.94.0-nightly (deadbeef 2026-03-02))";
        assert_eq!(
            RustcVersion::parse_producer(p),
            Some(RustcVersion::new(1, 94, 0))
        );
    }

    #[test]
    fn rejects_non_rustc_producer() {
        assert_eq!(RustcVersion::parse_producer("GNU C17 13.2.0"), None);
        assert_eq!(RustcVersion::parse_producer(""), None);
    }

    #[test]
    fn support_window_gates_versions() {
        assert!(is_supported(RustcVersion::new(1, 85, 1)));
        assert!(is_supported(RustcVersion::new(1, 63, 0)));
        assert!(!is_supported(RustcVersion::new(1, 62, 0)));
        assert!(!is_supported(RustcVersion::new(2, 0, 0)));
    }
}
