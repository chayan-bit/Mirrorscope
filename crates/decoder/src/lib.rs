//! Layer 3 — the language semantic layer.
//!
//! One `SemanticDecoder` trait; every language (async Rust, Go, C++20
//! coroutines, Swift) is a plugin behind it. The recording, replay, and DAP
//! layers never know which language they serve — this is how Mirrorscope
//! solves the class ("concurrency structure the compiler flattened away"),
//! not one instance of it.
//!
//! The trait and the `TaskTree`/`LogicalFrame` model land with issue #17.
