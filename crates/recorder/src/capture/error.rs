//! Error and outcome types shared by the ptrace capture modules.

use crate::trace::TraceError;

/// Errors while recording a target.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Failed to spawn the target command.
    #[error("failed to spawn target: {0}")]
    Spawn(std::io::Error),
    /// A ptrace/wait operation failed.
    #[error("ptrace failure: {0}")]
    Ptrace(#[from] nix::Error),
    /// Pinning a tracee to the single serialization CPU failed.
    #[error("failed to pin tid {tid} to cpu {cpu}: {source}")]
    Affinity {
        /// The thread that could not be pinned.
        tid: i32,
        /// The target CPU index.
        cpu: usize,
        /// Underlying errno.
        source: nix::Error,
    },
    /// Reading captured data out of the tracee failed.
    #[error("failed to read {len} bytes of syscall data from tracee at {addr:#x}: {source}")]
    TraceeRead {
        /// Remote address of the buffer.
        addr: u64,
        /// Bytes the syscall reported writing.
        len: usize,
        /// Underlying errno.
        source: nix::Error,
    },
    /// Writing the trace log failed.
    #[error(transparent)]
    Trace(#[from] TraceError),
}

/// Result of a completed recording.
#[derive(Debug)]
pub struct RecordOutcome {
    /// The leader thread's exit code (`None` if killed by a signal).
    pub exit_code: Option<i32>,
    /// Number of events written to the trace.
    pub events_recorded: u64,
    /// Number of distinct threads/processes followed during the recording
    /// (always ≥ 1: the leader).
    pub threads_followed: u64,
}
