//! The [`DebugBackend`] abstraction the DAP [`crate::server`] dispatches to,
//! plus the portable [`StubBackend`] fallback.
//!
//! The server never talks to the replay engine directly: it holds a
//! `Box<dyn DebugBackend>` and translates each backend answer into DAP
//! responses/events. Two implementations exist:
//!
//! - [`StubBackend`] — the static canned target (this module). Always
//!   available, so the server (and the portable integration tests) work on
//!   every platform, and reverse execution stays a *polite* failure that
//!   points at the replay engine.
//! - `ReplayBackend` — the real record/replay driver
//!   ([`crate::replay_backend`], Linux only), selected when `launch` is given
//!   a `trace` argument.
//!
//! Keeping the seam this narrow is what lets `server.rs` stay portable and
//! language/engine-agnostic — the same rule the rest of Mirrorscope follows.

use serde_json::{json, Value};

use crate::stub::{self, MAIN_THREAD_ID};

/// Message returned when reverse/replay execution is asked of the stub target.
/// Kept mentioning "replay" so clients (and tests) can tell it is a
/// not-yet-wired stub rather than a hard protocol error.
pub(crate) const REVERSE_STUB_MESSAGE: &str =
    "not wired to the replay engine: reverse execution needs a recording (launch with a \"trace\" argument)";

/// How a resumed target came to rest, as the backend reports it to the server.
///
/// The server turns this into the DAP `stopped`/`exited`/`terminated` events;
/// the backend stays free of protocol-framing concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopInfo {
    /// The target is paused and inspectable; `reason` is a DAP stop reason
    /// (`entry`, `step`, `pause`, …) and `thread_id` the stopped thread.
    Stopped {
        /// DAP stop reason string.
        reason: String,
        /// The thread the stop applies to.
        thread_id: u64,
    },
    /// The target ran to completion; `code` is its exit (or `128 + signal`).
    Exited {
        /// Process exit code.
        code: i32,
    },
}

impl StopInfo {
    /// Build a `Stopped` on the single Phase-1 main thread.
    #[must_use]
    pub fn stopped(reason: impl Into<String>) -> Self {
        Self::Stopped {
            reason: reason.into(),
            thread_id: MAIN_THREAD_ID,
        }
    }
}

/// Which flavour of execution control the client asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeKind {
    /// `continue` — run forward to the next stop (or exit).
    Continue,
    /// `reverseContinue` — run backward to the earliest recorded point.
    ReverseContinue,
    /// `stepBack` — move to the previous recorded event.
    StepBack,
    /// `next` — forward one event (step over).
    Next,
    /// `stepIn` — forward one event (step in).
    StepIn,
    /// `stepOut` — forward one event (step out).
    StepOut,
}

/// Errors a backend surfaces to the server, which renders them as a visible
/// DAP `output` event plus a failure response — replay divergence is never
/// hidden (the `CLAUDE.md` honesty rule).
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The current backend does not support this operation (e.g. the stub
    /// asked to reverse-execute). The message points at what would.
    #[error("{0}")]
    NotSupported(String),
    /// The replay engine, decoder, or unwinder failed. Carries the underlying
    /// message verbatim so divergence (`replay diverged at seq …`) reaches
    /// the client unchanged.
    #[error("{0}")]
    Engine(String),
    /// No live tracee to inspect: the target has exited (inspect after a
    /// reverse step) or was never launched with a trace.
    #[error("no live replay tracee: the target has exited or was not launched from a trace")]
    NoTracee,
    /// A request carried missing or malformed arguments.
    #[error("invalid request arguments: {0}")]
    BadArgs(String),
}

/// A debug target the DAP server can drive: launch, inspect, and step through
/// (forward and, for real backends, backward).
///
/// Object-safe (every method takes `&mut self` and owned/`&Value` arguments,
/// returns owned data) so the server holds a `Box<dyn DebugBackend>` without
/// knowing which engine produced it.
pub trait DebugBackend {
    /// Begin a debug session; returns where the target first came to rest.
    ///
    /// # Errors
    /// Fails if the target cannot be started or positioned at its first stop.
    fn launch(&mut self, arguments: &Value) -> Result<StopInfo, BackendError>;

    /// The `threads` response body.
    ///
    /// # Errors
    /// Fails if the live target cannot be enumerated.
    fn threads(&mut self) -> Result<Value, BackendError>;

    /// The `stackTrace` response body for the request `arguments`.
    ///
    /// # Errors
    /// Fails if the stack cannot be unwound/symbolized.
    fn stack_trace(&mut self, arguments: &Value) -> Result<Value, BackendError>;

    /// The `scopes` response body for the request `arguments`.
    ///
    /// # Errors
    /// Fails if the frame's scopes cannot be produced.
    fn scopes(&mut self, arguments: &Value) -> Result<Value, BackendError>;

    /// The `variables` response body for the request `arguments`.
    ///
    /// # Errors
    /// Fails if the referenced variables cannot be read.
    fn variables(&mut self, arguments: &Value) -> Result<Value, BackendError>;

    /// Resume execution in the requested direction/granularity.
    ///
    /// # Errors
    /// Fails on an unsupported direction (stub) or an engine failure.
    fn resume(&mut self, kind: ResumeKind) -> Result<StopInfo, BackendError>;

    /// The `listCheckpoints` custom-request body.
    ///
    /// # Errors
    /// Fails if the checkpoint list cannot be produced.
    fn list_checkpoints(&mut self) -> Result<Value, BackendError>;

    /// The `taskTimeline` custom-request body.
    ///
    /// # Errors
    /// Fails if the task tree cannot be decoded.
    fn task_timeline(&mut self) -> Result<Value, BackendError>;

    /// Jump to the recorded event `seq` (the `jumpToEvent` custom request).
    ///
    /// # Errors
    /// Fails on bad arguments or an engine failure.
    fn jump_to_event(&mut self, arguments: &Value) -> Result<StopInfo, BackendError>;
}

/// The static stub target: one thread, a canned stack, canned locals.
///
/// Serves clients before (or without) a real recording, and keeps the whole
/// server usable on non-Linux hosts. Reverse execution and `jumpToEvent`
/// fail politely, pointing at the replay engine.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubBackend;

impl StubBackend {
    /// Build a stub backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DebugBackend for StubBackend {
    fn launch(&mut self, _arguments: &Value) -> Result<StopInfo, BackendError> {
        Ok(StopInfo::stopped("entry"))
    }

    fn threads(&mut self) -> Result<Value, BackendError> {
        Ok(stub::threads())
    }

    fn stack_trace(&mut self, _arguments: &Value) -> Result<Value, BackendError> {
        Ok(stub::stack_trace())
    }

    fn scopes(&mut self, _arguments: &Value) -> Result<Value, BackendError> {
        Ok(stub::scopes())
    }

    fn variables(&mut self, _arguments: &Value) -> Result<Value, BackendError> {
        Ok(stub::variables())
    }

    fn resume(&mut self, kind: ResumeKind) -> Result<StopInfo, BackendError> {
        match kind {
            ResumeKind::StepBack | ResumeKind::ReverseContinue => {
                Err(BackendError::NotSupported(REVERSE_STUB_MESSAGE.to_owned()))
            }
            // The stub target is static; forward controls simply report a
            // benign stop at the single frame rather than pretend to advance.
            ResumeKind::Continue | ResumeKind::Next | ResumeKind::StepIn | ResumeKind::StepOut => {
                Ok(StopInfo::stopped("step"))
            }
        }
    }

    fn list_checkpoints(&mut self) -> Result<Value, BackendError> {
        Ok(json!({ "checkpoints": [] }))
    }

    fn task_timeline(&mut self) -> Result<Value, BackendError> {
        Ok(json!({ "tasks": [] }))
    }

    fn jump_to_event(&mut self, _arguments: &Value) -> Result<StopInfo, BackendError> {
        Err(BackendError::NotSupported(
            "jumpToEvent needs the replay engine: launch with a \"trace\" argument".to_owned(),
        ))
    }
}
