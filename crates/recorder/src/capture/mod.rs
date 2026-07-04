//! Capture backends that record a target's non-determinism into the trace.
//!
//! Phase 1 backend: [`ptrace`] (`PTRACE_SYSCALL`), single-threaded targets,
//! Linux-only but portable across x86-64 and aarch64 — the portable fallback
//! path. eBPF/aya replaces it on BTF kernels in Phase 3 (issue #14).
//!
//! Payload encodings live in [`payload`] and are platform-independent, so
//! traces recorded on Linux can be decoded anywhere.

pub mod payload;

#[cfg(target_os = "linux")]
pub mod ptrace;

#[cfg(target_os = "linux")]
pub use ptrace::{record_command, CaptureError, RecordOutcome};
