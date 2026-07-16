//! The vendored, version-gated model of Tokio's *internal* runtime layout —
//! the "living compatibility DB" for tokio, distinct from the rustc coroutine
//! layout DB (`CLAUDE.md`: version-gate tokio-internal layout knowledge in one
//! module with honest `UnsupportedVersion` errors).
//!
//! Unlike the coroutine layout (monomorphization-specific, only in the
//! binary's own DWARF), these are offsets of Tokio's *private* structs
//! (`Context`, `Handle`, `Shared`, `OwnedTasks`, `ShardedList`, `Header`,
//! `Vtable`, `Trailer`). They are stable per tokio minor version but not part
//! of any public API, so they are vendored here per version and any version we
//! have not hand-verified is declined rather than guessed.
//!
//! ## Verified entries
//! - **tokio 1.44.2** (current-thread scheduler) — every offset below was read
//!   from the real `gdb -batch -ex 'ptype /o …'` layout of a debug binary and
//!   confirmed end-to-end by a live `CONTEXT → OwnedTasks → Header` walk on an
//!   aarch64 target. Field offsets are pointer/`usize`-sized throughout, so
//!   they are identical on `aarch64` and `x86-64`.

use std::fmt;

use super::error::EnumerateError;

/// A parsed `tokio-<major>.<minor>.<patch>` version, recovered from a version
/// string embedded in the target binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokioVersion {
    /// Major version (always `1` for released Tokio).
    pub major: u16,
    /// Minor version (e.g. `44`).
    pub minor: u16,
    /// Patch version (e.g. `2`).
    pub patch: u16,
}

impl TokioVersion {
    /// Construct a version triple.
    #[must_use]
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Find the first `tokio-<n>.<n>.<n>` token in a binary's bytes.
    ///
    /// Tokio's source file paths (`.../tokio-1.44.2/src/...`) are retained in
    /// DWARF and in the read-only string data of a debug build, so scanning
    /// the raw image recovers the version without parsing DWARF.
    #[must_use]
    pub fn detect_in_bytes(bytes: &[u8]) -> Option<Self> {
        const NEEDLE: &[u8] = b"tokio-1.";
        let mut from = 0;
        while let Some(rel) = find(&bytes[from..], NEEDLE) {
            let start = from + rel + b"tokio-".len();
            if let Some(v) = parse_triple(&bytes[start..]) {
                return Some(v);
            }
            from += rel + NEEDLE.len();
        }
        None
    }
}

impl fmt::Display for TokioVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse a leading `1.44.2`-style token from the front of `bytes` (ASCII).
fn parse_triple(bytes: &[u8]) -> Option<TokioVersion> {
    let text = std::str::from_utf8(bytes.get(..24.min(bytes.len()))?).ok()?;
    let token: String = text
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some(TokioVersion::new(major, minor, patch))
}

/// Naive substring search (avoids pulling in a dependency for one scan).
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Byte offsets of Tokio's private runtime structures needed to walk from the
/// `CONTEXT` thread-local down to each spawned task's `Header`.
///
/// All offsets are from the start of the named struct; pointer chases in
/// [`super::walk`] compose them. Only the current-thread scheduler is modeled
/// in v1 (the flagship fixture's flavor); a multi-threaded runtime has a
/// different `Shared`/`owned` offset and is declined via the shard-count
/// plausibility check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokioRuntimeLayout {
    /// `Context.current` — the `HandleCell` holding the scheduler handle.
    pub context_current: u64,
    /// Offset from `HandleCell` to the `Option<Handle>` cell value: the
    /// scheduler `Handle` is an `enum` whose current-thread variant is an
    /// `Arc` pointer (null when no runtime is entered).
    pub handle_cell_value: u64,
    /// Offset from an `Arc<T>` pointer to its `ArcInner` data payload (past
    /// the strong+weak `AtomicUsize` counts).
    pub arc_data: u64,
    /// `current_thread::Handle.shared`.
    pub handle_shared: u64,
    /// `current_thread::Shared.owned` — the `OwnedTasks`.
    pub shared_owned: u64,
    /// `OwnedTasks.list` — the `ShardedList`.
    pub owned_list: u64,
    /// `ShardedList.lists` — the boxed slice of per-shard mutex-guarded lists
    /// (a fat pointer: `{data_ptr, len}`).
    pub sharded_lists: u64,
    /// Byte stride between consecutive `Mutex<LinkedList>` shard elements.
    pub shard_stride: u64,
    /// Offset from a shard's `Mutex` to its guarded intrusive `LinkedList`.
    pub mutex_data: u64,
    /// `LinkedList.head` — `Option<NonNull<Header>>` of the first task.
    pub list_head: u64,
    /// `Header.vtable` — pointer to the task's `&'static Vtable`.
    pub header_vtable: u64,
    /// `Vtable.poll` — the monomorphized `raw::poll::<T, S>` function pointer,
    /// whose DWARF subprogram name carries the future type `T`.
    pub vtable_poll: u64,
    /// `Vtable.trailer_offset` — byte offset from `Header` to the task's
    /// `Trailer` (self-describing, so no per-task-type guessing).
    pub vtable_trailer_offset: u64,
    /// Offset from a `Trailer` to the `next` link of its intrusive `owned`
    /// pointers (`Trailer.owned` is at offset 0; `Pointers.next` follows the
    /// `prev` pointer).
    pub trailer_owned_next: u64,
    /// Byte offset from a task's `Header` to its inline future (coroutine)
    /// instance, i.e. `Cell` → `core.stage`'s active `Running` payload.
    pub future_offset: u64,
}

impl TokioRuntimeLayout {
    /// The vendored current-thread-scheduler layout for a known Tokio
    /// `version`, or an [`EnumerateError`] declining an unverified version.
    ///
    /// # Errors
    /// [`EnumerateError::UnsupportedTokioVersion`] for any version without a
    /// hand-verified entry.
    pub fn vendored(version: TokioVersion) -> Result<Self, EnumerateError> {
        match (version.major, version.minor) {
            // Verified against tokio 1.44.2 (see module docs). The 1.4x line
            // shares this task/scheduler layout; the entry is opened for the
            // minor it was verified on and can be widened after re-verifying.
            (1, 44) => Ok(Self {
                context_current: 8,
                handle_cell_value: 8,
                arc_data: 16,
                handle_shared: 0,
                shared_owned: 104,
                owned_list: 0,
                sharded_lists: 0,
                shard_stride: 24,
                mutex_data: 8,
                list_head: 0,
                header_vtable: 16,
                vtable_poll: 0,
                vtable_trailer_offset: 56,
                trailer_owned_next: 8,
                future_offset: 56,
            }),
            _ => Err(EnumerateError::UnsupportedTokioVersion(version)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_embedded_tokio_version() {
        let blob = b"junk\x00/root/.cargo/registry/src/index/tokio-1.44.2/src/lib.rs\x00more";
        assert_eq!(
            TokioVersion::detect_in_bytes(blob),
            Some(TokioVersion::new(1, 44, 2))
        );
    }

    #[test]
    fn returns_none_without_a_version_string() {
        assert_eq!(TokioVersion::detect_in_bytes(b"no version here"), None);
    }

    #[test]
    fn vendored_1_44_has_verified_offsets() {
        let l = TokioRuntimeLayout::vendored(TokioVersion::new(1, 44, 2)).expect("1.44");
        assert_eq!(l.shared_owned, 104);
        assert_eq!(l.vtable_trailer_offset, 56);
        assert_eq!(l.future_offset, 56);
        assert_eq!(l.shard_stride, 24);
    }

    #[test]
    fn unverified_version_declines() {
        let err = TokioRuntimeLayout::vendored(TokioVersion::new(1, 30, 0)).expect_err("declined");
        assert!(matches!(err, EnumerateError::UnsupportedTokioVersion(_)));
    }

    #[test]
    fn version_displays_as_triple() {
        assert_eq!(TokioVersion::new(1, 44, 2).to_string(), "1.44.2");
    }
}
