//! Layer 3 — the language semantic layer.
//!
//! One `SemanticDecoder` trait; every language (async Rust, Go, C++20
//! coroutines, Swift) is a plugin behind it. The recording, replay, and DAP
//! layers never know which language they serve — this is how Mirrorscope
//! solves the class ("concurrency structure the compiler flattened away"),
//! not one instance of it.
//!
//! - [`model`] — the portable data model (`TaskTree`, `LogicalFrame`,
//!   `WakeCause`, …) every decoder produces.
//! - [`process_view`] — the abstract, read-only view of a paused target a
//!   decoder consumes; kept dependency-free of `replay` so this crate is
//!   fully unit-testable without a real recording.
//! - [`SemanticDecoder`] — the trait itself.
//! - [`native`] — the trivial reference implementation (one task per OS
//!   thread) proving the interface end-to-end.
//! - [`registry`] — picks a decoder for a target.

pub mod error;
pub mod model;
pub mod native;
pub mod process_view;
pub mod registry;

mod decoder_trait;

pub use decoder_trait::SemanticDecoder;
pub use error::DecoderError;
pub use native::NativeThreadsDecoder;
pub use process_view::ProcessView;
pub use registry::select_decoder;
