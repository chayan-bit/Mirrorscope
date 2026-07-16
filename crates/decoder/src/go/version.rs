//! Go toolchain version detection, used only to key the vendored offset
//! table ([`super::offsets`]) when DWARF is unavailable. The DWARF path never
//! needs this — it reads offsets directly from the binary.
//!
//! The `runtime.buildVersion` string (e.g. `"go1.24.13"`) is embedded in the
//! read-only data of every Go binary, even fully stripped ones, so a plain
//! scan for the first `go1.<minor>` token is a robust, dependency-free way to
//! recover `major.minor` for table lookup.

/// A parsed Go toolchain version. Only `major.minor` drive layout selection;
/// `patch` is retained for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoVersion {
    /// Major version (always `1` for released Go).
    pub major: u16,
    /// Minor version (e.g. `24`).
    pub minor: u16,
    /// Patch version (e.g. `13`), `0` if absent.
    pub patch: u16,
}

impl GoVersion {
    /// Construct a version triple.
    #[must_use]
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a `"go1.24.13"` / `"go1.24"` / `"1.24.13"` string into a
    /// [`GoVersion`], returning `None` if it does not start with a
    /// `go`-prefixed or bare `major.minor` number.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("go").unwrap_or(text);
        let mut parts = digits.split('.');
        let major = parse_leading_number(parts.next()?)?;
        let minor = parse_leading_number(parts.next()?)?;
        let patch = parts
            .next()
            .and_then(parse_leading_number)
            .unwrap_or_default();
        Some(Self::new(major, minor, patch))
    }

    /// Scan a binary image's raw bytes for the first embedded
    /// `runtime.buildVersion` token (`go1.<minor>[.<patch>]`) and parse it.
    #[must_use]
    pub fn detect_in_bytes(image: &[u8]) -> Option<Self> {
        const NEEDLE: &[u8] = b"go1.";
        let mut from = 0;
        while let Some(pos) = find_subslice(&image[from..], NEEDLE) {
            let start = from + pos;
            let end = (start + 16).min(image.len());
            let candidate = &image[start..end];
            if let Ok(text) = std::str::from_utf8(candidate) {
                if let Some(version) = Self::parse(text) {
                    // Reject the many `go1.` prefixes that are not a real
                    // version (need at least one digit after the dot, which
                    // `parse` already enforced via the minor component).
                    return Some(version);
                }
            }
            from = start + NEEDLE.len();
        }
        None
    }
}

/// Parse the leading run of ASCII digits of `s` into a `u16`, ignoring any
/// trailing non-digit suffix (e.g. `"24rc1"` -> `24`). `None` if there is no
/// leading digit.
fn parse_leading_number(s: &str) -> Option<u16> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    s[..end].parse().ok()
}

/// First index of `needle` within `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_go_version() {
        assert_eq!(GoVersion::parse("go1.24.13"), Some(GoVersion::new(1, 24, 13)));
    }

    #[test]
    fn parses_major_minor_only() {
        assert_eq!(GoVersion::parse("go1.24"), Some(GoVersion::new(1, 24, 0)));
    }

    #[test]
    fn parses_bare_number() {
        assert_eq!(GoVersion::parse("1.21.0"), Some(GoVersion::new(1, 21, 0)));
    }

    #[test]
    fn rejects_non_version() {
        assert_eq!(GoVersion::parse("golang"), None);
        assert_eq!(GoVersion::parse("gofmt"), None);
    }

    #[test]
    fn detects_embedded_build_version() {
        let image = b"\x00\x00some rodata go1.24.13 padding\x00";
        assert_eq!(
            GoVersion::detect_in_bytes(image),
            Some(GoVersion::new(1, 24, 13))
        );
    }

    #[test]
    fn detect_returns_none_without_marker() {
        assert_eq!(GoVersion::detect_in_bytes(b"no version here"), None);
    }
}
