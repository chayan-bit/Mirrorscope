//! Picks a [`SemanticDecoder`] for a target.
//!
//! Deliberately trivial today (YAGNI): there is exactly one decoder, so
//! there is nothing to choose between yet. Once language-specific decoders
//! land (#18-#26), this grows into trying each candidate in priority order
//! and falling through on [`crate::error::DecoderError::NotApplicable`],
//! ending with [`NativeThreadsDecoder`] as the universal fallback.

use crate::decoder_trait::SemanticDecoder;
use crate::native::NativeThreadsDecoder;

/// Select the best available decoder for the current target.
///
/// Today this always returns [`NativeThreadsDecoder`]; it exists as the
/// single seam every later decoder plugs into, so callers never need to
/// change when richer decoders are added.
#[must_use]
pub fn select_decoder() -> Box<dyn SemanticDecoder> {
    Box::new(NativeThreadsDecoder::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_native_decoder_today() {
        let decoder: Box<dyn SemanticDecoder> = select_decoder();
        // No language-specific decoder exists yet; this is the one seam
        // that will grow branches later.
        drop(decoder);
    }
}
