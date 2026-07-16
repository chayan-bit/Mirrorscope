//! Picks a [`SemanticDecoder`] for a target.
//!
//! The selection seam every language decoder plugs into. A caller that has the
//! target's binary image uses [`select_decoder_for_binary`] to get the richest
//! decoder that applies (today: Go → [`GoroutineDecoder`]); everything else,
//! and callers without the image, fall through to [`NativeThreadsDecoder`].
//! Recording/replay/DAP never learn which one they got — they hold a
//! `Box<dyn SemanticDecoder>`.

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
/// Detects a Go binary (via `.go.buildinfo` / the `runtime.allgs` symbol) and
/// resolves its runtime layout; on success returns a [`GoroutineDecoder`].
/// Any failure — not a Go binary, or a Go binary whose layout cannot be
/// resolved (fully stripped, unknown version) — falls through to
/// [`NativeThreadsDecoder`], honoring the honesty rule by never returning a
/// decoder that would guess.
#[must_use]
pub fn select_decoder_for_binary(image: &[u8]) -> Box<dyn SemanticDecoder> {
    match GoroutineDecoder::from_binary(image) {
        Ok(decoder) => Box::new(decoder),
        Err(_) => Box::new(NativeThreadsDecoder::new()),
    }
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
