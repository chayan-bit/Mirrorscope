//! Picks a [`SemanticDecoder`] for a target.
//!
//! The selection seam every language decoder plugs into. A caller that has the
//! target's binary image uses [`select_decoder_for_binary`] to get the richest
//! decoder that applies (today: Go → [`GoroutineDecoder`]); everything else,
//! and callers without the image, fall through to [`NativeThreadsDecoder`].
//! Recording/replay/DAP never learn which one they got — they hold a
//! `Box<dyn SemanticDecoder>`.

use crate::async_rust::TokioDecoder;
use crate::decoder_trait::SemanticDecoder;
use crate::go::GoroutineDecoder;
use crate::native::NativeThreadsDecoder;

/// Select the universal fallback decoder, with no target binary to inspect.
///
/// Returns [`NativeThreadsDecoder`]; use [`select_decoder_for_binary`] when the
/// target executable's bytes are available and a language-specific decoder may
/// apply.
#[must_use]
pub fn select_decoder() -> Box<dyn SemanticDecoder> {
    Box::new(NativeThreadsDecoder::new())
}

/// Select the best decoder for a target given its binary image.
///
/// Detection order (the runtimes are mutually exclusive):
/// 1. **Go** (via `.go.buildinfo` / `runtime.allgs`) → [`GoroutineDecoder`].
/// 2. **Tokio** (via a `tokio::runtime` symbol) with resolvable coroutine
///    DWARF → [`TokioDecoder`]. Note: the returned Tokio decoder resolves the
///    binary's coroutine layouts but has no task roots yet, so its
///    [`SemanticDecoder::decode_tasks`] declines with
///    [`crate::DecoderError::NotApplicable`] until live enumeration is wired in
///    (see [`crate::async_rust::roots`]); a caller may then fall back to
///    [`NativeThreadsDecoder`].
/// 3. Otherwise, and on any resolution failure, [`NativeThreadsDecoder`] —
///    honoring the honesty rule by never returning a decoder that would guess.
#[must_use]
pub fn select_decoder_for_binary(image: &[u8]) -> Box<dyn SemanticDecoder> {
    if let Ok(decoder) = GoroutineDecoder::from_binary(image) {
        return Box::new(decoder);
    }
    if let Ok(decoder) = TokioDecoder::from_binary(image) {
        return Box::new(decoder);
    }
    Box::new(NativeThreadsDecoder::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_native_decoder_without_a_binary() {
        let decoder: Box<dyn SemanticDecoder> = select_decoder();
        drop(decoder);
    }

    #[test]
    fn non_go_bytes_fall_through_to_native() {
        // Random non-object bytes are not a Go binary; must not panic and must
        // yield a usable (native) decoder.
        let decoder = select_decoder_for_binary(b"not an elf file at all");
        drop(decoder);
    }
}
