//! Errors surfaced by [`crate::SemanticDecoder`] and [`crate::ProcessView`].
//!
//! Per the divergence-honesty rule in `CLAUDE.md`: a decoder that cannot
//! make sense of a given process must say so explicitly rather than
//! guessing. [`DecoderError::NotApplicable`] is that explicit refusal.

use crate::model::TaskId;
use crate::process_view::ThreadId;

/// Failure modes for decoding logical concurrency structure out of a paused
/// process image.
///
/// Marked `#[non_exhaustive]` so new decoders (goroutines, coroutines, …)
/// can add failure modes without breaking existing `match` arms downstream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecoderError {
    /// This decoder does not understand the target process at all (wrong
    /// language/runtime, missing instrumentation, …). Callers should try
    /// the next candidate decoder rather than treat this as fatal.
    #[error("decoder does not apply to this process: {reason}")]
    NotApplicable {
        /// Human-readable reason the decoder declined.
        reason: String,
    },

    /// A [`TaskId`] was passed that does not exist in the current
    /// [`crate::model::TaskTree`].
    #[error("unknown task {0:?}")]
    UnknownTask(TaskId),

    /// A [`ThreadId`] was passed that the [`crate::ProcessView`] does not
    /// know about.
    #[error("unknown thread {0:?}")]
    UnknownThread(ThreadId),

    /// A memory read against the [`crate::ProcessView`] failed.
    #[error("failed to read {len} byte(s) at address {addr:#x}: {reason}")]
    MemoryReadFailed {
        /// The address the read was attempted at.
        addr: u64,
        /// The number of bytes requested.
        len: usize,
        /// Underlying failure description (e.g. unmapped page, I/O error).
        reason: String,
    },

    /// The set of [`crate::model::TaskNode`]s handed to
    /// [`crate::model::TaskTree::try_from_nodes`] does not form a valid
    /// tree (duplicate ids, dangling parent reference, …).
    #[error("invalid task tree: {reason}")]
    InvalidTaskTree {
        /// Human-readable description of what made the tree invalid.
        reason: String,
    },

    /// A ptrace register read against a real, attached thread failed (e.g.
    /// the thread exited or was never attached). Distinct from
    /// [`Self::UnknownThread`], which means the thread id was never seen at
    /// all.
    #[error("failed to read registers for thread {thread:?}: {reason}")]
    RegisterReadFailed {
        /// The thread the register read targeted.
        thread: ThreadId,
        /// Underlying ptrace failure description.
        reason: String,
    },

    /// Unwinding the physical call stack of a real, attached thread failed.
    #[error("failed to unwind physical frames for thread {thread:?}: {reason}")]
    PhysicalFramesFailed {
        /// The thread the unwind targeted.
        thread: ThreadId,
        /// Underlying unwinder failure description.
        reason: String,
    },
}
