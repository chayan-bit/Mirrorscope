//! `ProcessView`: the abstract, read-only view of a paused target that a
//! [`crate::SemanticDecoder`] operates over.
//!
//! Decoder logic must not depend on the `replay` crate — that dependency
//! would run backwards (replay is Layer 2, decoding is Layer 3) and would
//! make the decoder crate untestable without a real recording. `replay`
//! implements this trait instead (tracked by #8/#27); tests here use a
//! mock.
//!
//! Design choice for how physical stacks reach [`crate::SemanticDecoder::logical_stack`]:
//! `ProcessView` exposes [`ProcessView::physical_frames`] rather than the
//! trait method taking the frames as a parameter. Reasons: (1) a decoder
//! may need physical frames for more than one task while deciding how to
//! decode (e.g. correlating an executor's poll-loop frame across threads),
//! so pushing frame retrieval behind the same view the rest of the method
//! already takes avoids a second, inconsistent way to get the same data;
//! (2) it keeps unwinding (framehop, Layer 5 concern) fully outside the
//! decoder crate, which only ever consumes already-unwound frames.

use crate::error::DecoderError;
use crate::model::SourceLocation;

/// Identifier for one OS thread, as seen by [`ProcessView`].
///
/// Distinct from [`crate::model::TaskId`]: a thread is a physical resource
/// the OS schedules, a task is the logical concept a decoder reconstructs.
/// [`crate::native::NativeThreadsDecoder`] happens to map them 1:1, but
/// richer decoders (many async tasks per thread) do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u64);

impl ThreadId {
    /// Build a `ThreadId` from a raw numeric identifier.
    #[must_use]
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }
}

/// Arch-neutral, minimal register snapshot for one thread.
///
/// Only the two registers every unwinder needs to start walking a stack.
/// General-purpose register access, when a decoder needs it (e.g. to read
/// a value spilled to a register rather than memory), is deliberately out
/// of scope here — add it only when a concrete decoder needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    /// Program counter / instruction pointer.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
}

/// One already-unwound physical stack frame.
///
/// This is the frame shape framehop (or the CI-friendly mock in tests)
/// produces; [`crate::model::LogicalFrame::from_physical`] converts it into
/// the logical-frame shape decoders return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalFrame {
    /// Program counter this frame was executing at.
    pub pc: u64,
    /// Stack pointer at this frame.
    pub sp: u64,
    /// Resolved function/symbol name, when debug info covers this address.
    pub function_name: Option<String>,
    /// Resolved source location, when debug info covers this address.
    pub location: Option<SourceLocation>,
}

/// A read-only view of a paused target process, abstract over how it was
/// obtained (a live ptrace attach, or a replay-restored checkpoint).
///
/// Object-safe by construction (no generics, no `Self: Sized` bounds) so
/// callers can hold a `&dyn ProcessView` without knowing which backend
/// produced it.
pub trait ProcessView {
    /// All thread ids currently live in the target.
    fn thread_ids(&self) -> Vec<ThreadId>;

    /// The register snapshot for `thread`.
    ///
    /// # Errors
    /// Returns [`DecoderError::UnknownThread`] if `thread` is not among
    /// [`Self::thread_ids`].
    fn registers(&self, thread: ThreadId) -> Result<Registers, DecoderError>;

    /// Read `len` bytes of the target's memory at `addr`.
    ///
    /// # Errors
    /// Returns [`DecoderError::MemoryReadFailed`] if the range is not
    /// mapped or the read otherwise fails.
    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, DecoderError>;

    /// The already-unwound physical call stack for `thread`, innermost
    /// frame first.
    ///
    /// # Errors
    /// Returns [`DecoderError::UnknownThread`] if `thread` is not among
    /// [`Self::thread_ids`].
    fn physical_frames(&self, thread: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_id_equality_and_ordering() {
        assert_eq!(ThreadId::new(1), ThreadId(1));
        assert!(ThreadId::new(1) < ThreadId::new(2));
    }

    #[test]
    fn registers_are_copyable_value_type() {
        let regs = Registers { pc: 1, sp: 2 };
        let copy = regs;
        assert_eq!(regs.pc, copy.pc);
    }
}
