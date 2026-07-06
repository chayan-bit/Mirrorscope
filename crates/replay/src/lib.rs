//! Layer 2 — replay execution engine (issue #6).
//!
//! Re-runs a recorded target forward, feeding it the recorded syscall results
//! from the [`recorder::trace`] log so re-execution is deterministic. The target
//! is spawned under ptrace with a pinned address-space layout; every syscall is
//! verified against the trace (divergence is surfaced, never hidden), and the
//! nondeterministic ones (read/pread64/recvfrom, getrandom, clock_gettime) have
//! their results injected from the recording instead of really executing.
//!
//! Checkpoint restore (issue #5) will later let replay start from the nearest
//! preceding snapshot rather than from process start.
//!
//! Linux-only: this crate compiles to a doc-only shell on other platforms,
//! exactly like the recorder's capture backend.

#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod inject;
#[cfg(target_os = "linux")]
mod regs;
#[cfg(target_os = "linux")]
mod session;

#[cfg(target_os = "linux")]
pub use error::ReplayError;
#[cfg(target_os = "linux")]
pub use regs::Registers;
#[cfg(target_os = "linux")]
pub use session::{ExitOutcome, ReplaySession};
