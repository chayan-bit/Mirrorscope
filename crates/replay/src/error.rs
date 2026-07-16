//! Errors surfaced by the replay engine.

use recorder::capture::payload::PayloadError;
use recorder::trace::{EventKind, TraceError};

/// Errors while launching or driving a replay.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The trace could not be opened or a record was corrupt.
    #[error("trace error: {0}")]
    Trace(#[from] TraceError),
    /// A syscall payload in the trace could not be decoded.
    #[error("payload decode error: {0}")]
    Payload(#[from] PayloadError),
    /// The trace has no embedded command line, so the target cannot be re-run
    /// (v1 traces, or v2 traces recorded without one).
    #[error("trace has no recorded command line to replay")]
    NoCmdline,
    /// Spawning the target under ptrace failed.
    #[error("failed to spawn replay target: {0}")]
    Spawn(std::io::Error),
    /// A ptrace/wait operation failed.
    #[error("ptrace failure: {0}")]
    Ptrace(#[from] nix::Error),
    /// Reading or writing tracee memory failed.
    #[error("tracee memory access failed at {addr:#x} for {len} bytes: {source}")]
    Memory {
        /// Remote address involved.
        addr: u64,
        /// Byte count involved.
        len: usize,
        /// Underlying errno.
        source: nix::Error,
    },
    /// The replayed syscall stream diverged from the recording: the tracee
    /// issued a different syscall than the trace says it should. Never silently
    /// continued — replay honesty is a core project value.
    #[error("replay diverged at seq {seq}: expected syscall {expected_nr}, found {found_nr}")]
    Diverged {
        /// Sequence number of the record that mismatched.
        seq: u64,
        /// Syscall number the trace recorded.
        expected_nr: u64,
        /// Syscall number the tracee actually issued.
        found_nr: u64,
    },
    /// A record of an unexpected kind appeared where the tracee state demanded
    /// another (e.g. a signal record at a syscall entry stop).
    #[error("unexpected record kind at seq {seq}: expected {expected}, found {found:?}")]
    UnexpectedRecord {
        /// Sequence number of the offending record.
        seq: u64,
        /// The record kind the driver expected.
        expected: &'static str,
        /// The record kind actually found.
        found: EventKind,
    },
    /// The tracee kept executing after the trace ran out of records.
    #[error("trace exhausted before the tracee finished replaying")]
    TraceExhausted,
    /// Creating or restoring a fork-snapshot checkpoint failed: the injected
    /// clone produced an unexpected ptrace stop or no fork event. Fork
    /// snapshots are Phase-1 best-effort; a failure is surfaced, never hidden.
    #[error("checkpoint operation failed{}: {reason}", .seq.map(|s| format!(" at seq {s}")).unwrap_or_default())]
    Checkpoint {
        /// Sequence number involved, when known.
        seq: Option<u64>,
        /// Human-readable cause.
        reason: &'static str,
    },
    /// Draining the replayed target's piped stdout/stderr failed.
    #[error("failed to read replay output: {0}")]
    Output(std::io::Error),
}
