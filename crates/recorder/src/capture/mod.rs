//! Capture backends that record a target's non-determinism into the trace.
//!
//! Phase 1 backend: [`ptrace`] (`PTRACE_SYSCALL`), Linux-only but portable
//! across x86-64 and aarch64 — the portable fallback path. eBPF/aya replaces
//! it on BTF kernels in Phase 3 (issue #14).
//!
//! Phase 2 (issue #9) extends the ptrace backend from a single tracee to a
//! whole multi-threaded process under **single-core serialization**: every
//! thread is pinned to one CPU and run one at a time, so the interleaving of
//! instrumented points (syscalls + a periodic preemption timer) has a total
//! order that is recorded ([`EventKind::SchedSwitch`](crate::trace::EventKind),
//! [`ThreadSpawn`](crate::trace::EventKind::ThreadSpawn)) for replay to
//! enforce. See [`sched`] for the determinism model and its honest caveats.
//!
//! Payload encodings live in [`payload`] and are platform-independent, so
//! traces recorded on Linux can be decoded anywhere.

pub mod payload;

#[cfg(target_os = "linux")]
mod affinity;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod sched;
#[cfg(target_os = "linux")]
mod syscall;
#[cfg(target_os = "linux")]
mod timer;

#[cfg(target_os = "linux")]
pub mod ptrace;

#[cfg(target_os = "linux")]
pub use error::{CaptureError, RecordOutcome};
#[cfg(target_os = "linux")]
pub use ptrace::record_command;
