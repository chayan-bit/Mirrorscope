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
//! - [`go`] — the goroutine decoder: walks `runtime.allgs` into a task tree
//!   using DWARF-derived runtime offsets (the first language plugin).
//! - [`registry`] — picks a decoder for a target.
//! - [`ptrace_view`] (Linux only) — a [`ProcessView`] backed by ptrace
//!   against a real, already-attached-and-stopped process.

pub mod error;
pub mod go;
pub mod model;
pub mod native;
pub mod process_view;
#[cfg(target_os = "linux")]
pub mod ptrace_view;
pub mod registry;

mod decoder_trait;

pub use decoder_trait::SemanticDecoder;
pub use error::DecoderError;
pub use go::{GoDecodeError, GoLayout, GoroutineDecoder};
pub use native::NativeThreadsDecoder;
pub use process_view::ProcessView;
#[cfg(target_os = "linux")]
pub use ptrace_view::{PtraceProcessView, PtraceViewError};
pub use registry::select_decoder;
