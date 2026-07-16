//! Layer 2 — replay execution engine (issue #6).
//!
//! Re-runs a recorded target forward, feeding it the recorded syscall results
//! from the [`recorder::trace`] log so re-execution is deterministic. The target
//! is spawned under ptrace with a pinned address-space layout; every syscall is
//! verified against the trace (divergence is surfaced, never hidden), and the
//! nondeterministic ones (read/pread64/recvfrom, getrandom, clock_gettime) have
//! their results injected from the recording instead of really executing.
//!
//! Checkpoint restore (issue #5): the engine periodically takes fork-snapshot
//! checkpoints of the tracee and, on `run_to`/`restore_to`, resumes from the
//! nearest snapshot at-or-before the target seq instead of re-running from
//! process entry. The ptrace fork machinery lives in [`checkpoint`]; the
//! portable "which snapshot" arithmetic lives, unit-tested on every platform,
//! in [`checkpoint_select`].
//!
//! Linux-only: this crate compiles to a doc-only shell on other platforms,
//! exactly like the recorder's capture backend — except the portable
//! [`checkpoint_select`] module, which always compiles so its tests run locally.

// Portable modules; compiled everywhere so `cargo test` exercises them on
// non-Linux hosts. Unused (dead) off Linux, where no ptrace driver consumes
// them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod checkpoint_select;
// Retroactive-watchpoint core: the encoding math + request validation, kept
// ptrace-free so its correctness is unit-tested on the macOS dev host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod watchpoint;
// Schedule-enforcement portable core: the recorded-tid ↔ live-pid remapping
// table + the multi-threaded-trace detector, unit-tested on the macOS host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod schedule;

#[cfg(target_os = "linux")]
mod checkpoint;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod inject;
#[cfg(target_os = "linux")]
mod mt;
#[cfg(target_os = "linux")]
mod regs;
#[cfg(target_os = "linux")]
mod scan;
#[cfg(target_os = "linux")]
mod session;
#[cfg(target_os = "linux")]
mod watchpoint_hw;

// Portable watchpoint vocabulary — usable by any client, on any platform.
pub use watchpoint::{WatchHit, WatchKind, WatchpointError};
// Re-export the symbolized-frame type a `WatchHit` backtrace is built from, so
// consumers need not depend on `unwind` directly.
pub use unwind::SymbolizedFrame;

#[cfg(target_os = "linux")]
pub use checkpoint::CheckpointInfo;
#[cfg(target_os = "linux")]
pub use error::ReplayError;
#[cfg(target_os = "linux")]
pub use regs::Registers;
#[cfg(target_os = "linux")]
pub use scan::WatchpointScan;
#[cfg(target_os = "linux")]
pub use session::{ExitOutcome, ReplaySession};
