//! The `SemanticDecoder` trait itself — one trait, languages are plugins
//! behind it (`CLAUDE.md` "Mental model"). Recording, replay, and DAP never
//! know which implementation they are talking to.

use crate::error::DecoderError;
use crate::model::{LogicalFrame, TaskId, TaskTree, Variable, WakeCause};
use crate::process_view::ProcessView;

/// Reconstructs a language/runtime's logical concurrency structure out of a
/// paused process, given only a [`ProcessView`].
///
/// Implementations: [`crate::native::NativeThreadsDecoder`] (OS threads,
/// the trivial reference case) today; an async-Rust state-machine decoder
/// (#19/#20), a Tokio-tracing decoder (#18), a goroutine decoder (#23), and
/// C++20/Swift coroutine decoders (#25/#26) later.
///
/// Object-safe: every method takes `&self` and `&dyn ProcessView`, and
/// returns owned data, so callers hold `Box<dyn SemanticDecoder>` without
/// knowing the concrete language. See the `trait_object_safety` test in
/// `tests/native_decoder.rs`.
///
/// Every method returns `Result` rather than a best-effort value: per the
/// divergence-honesty rule, a decoder that cannot make sense of a target
/// must say so via [`DecoderError::NotApplicable`] (or a more specific
/// variant), never guess silently.
pub trait SemanticDecoder {
    /// Reconstruct the full logical task tree for the target.
    ///
    /// # Errors
    /// Returns [`DecoderError::NotApplicable`] if this decoder does not
    /// recognize the target's language/runtime at all.
    fn decode_tasks(&self, view: &dyn ProcessView) -> Result<TaskTree, DecoderError>;

    /// The logical stack for one task — innermost frame first. For a
    /// simple thread this is a 1:1 map of the physical stack; for an async
    /// task it may synthesize await-point frames the physical stack does
    /// not contain at all.
    ///
    /// # Errors
    /// Returns [`DecoderError::UnknownTask`] if `task` is not a task this
    /// decoder produced via [`Self::decode_tasks`] on this `view`.
    fn logical_stack(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
    ) -> Result<Vec<LogicalFrame>, DecoderError>;

    /// Why `task` last woke from [`crate::model::TaskState::Blocked`], if
    /// the decoder can determine it. Returns
    /// [`WakeCause::Unknown`] (not an error) when the decoder simply has no
    /// causality information — see #21 for the feature that populates this
    /// richly.
    ///
    /// # Errors
    /// Returns [`DecoderError::UnknownTask`] if `task` is not a task this
    /// decoder produced via [`Self::decode_tasks`] on this `view`.
    fn wake_cause(&self, view: &dyn ProcessView, task: TaskId) -> Result<WakeCause, DecoderError>;

    /// Local variables visible at `frame`, one of `task`'s logical frames
    /// (as returned by [`Self::logical_stack`]).
    ///
    /// # Errors
    /// Returns [`DecoderError::UnknownTask`] if `task` is not a task this
    /// decoder produced via [`Self::decode_tasks`] on this `view`.
    fn locals_at(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
        frame: &LogicalFrame,
    ) -> Result<Vec<Variable>, DecoderError>;
}
