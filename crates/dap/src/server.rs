//! The DAP request loop: reads framed requests, dispatches to a
//! [`DebugBackend`], and writes framed responses/events. Generic over
//! `Read`/`Write` so tests drive it with in-memory pipes and the CLI runs it
//! over stdio.
//!
//! The server owns no engine logic: it starts on the portable
//! [`StubBackend`] and, when `launch` carries a `trace` argument on Linux,
//! swaps in the real `ReplayBackend`. Every backend answer is translated here
//! into DAP framing — including surfacing backend errors (replay divergence
//! among them) as a visible `output` event plus a failure response, never
//! silently.

use std::io::{BufRead, BufReader, Read, Write};

use serde_json::{json, Value};

use crate::backend::{BackendError, DebugBackend, ResumeKind, StopInfo, StubBackend};
use crate::protocol::{self, Request};
use crate::transport::{read_frame, write_frame, TransportError};

/// A single-session DAP server.
pub struct Server {
    next_seq: u64,
    backend: Box<dyn DebugBackend>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            next_seq: 0,
            backend: Box::new(StubBackend::new()),
        }
    }
}

impl Server {
    /// Create a server for one client session, serving the stub target until a
    /// `launch` with a `trace` argument selects the replay backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve until `disconnect` or client EOF.
    pub fn run<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        self.run_buffered(&mut BufReader::new(reader), writer)
    }

    /// Like [`Server::run`] but for an already-buffered reader (stdio lock).
    pub fn run_buffered<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        while let Some(message) = read_frame(reader)? {
            let request: Request = match serde_json::from_value(message) {
                Ok(request) => request,
                Err(_) => continue, // Not a request envelope; DAP clients only send requests.
            };
            let disconnect = request.command == "disconnect";
            self.dispatch(&request, &mut *writer)?;
            if disconnect {
                break;
            }
        }
        Ok(())
    }

    fn dispatch<W: Write>(
        &mut self,
        request: &Request,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        match request.command.as_str() {
            "initialize" => self.on_initialize(request, writer),
            "launch" | "attach" => self.on_launch(request, writer),
            "configurationDone" | "disconnect" | "setBreakpoints" | "setExceptionBreakpoints" => {
                self.respond_success(request, json!({}), writer)
            }
            "threads" => {
                let body = self.backend.threads();
                self.answer(request, body, writer)
            }
            "stackTrace" => {
                let body = self.backend.stack_trace(&request.arguments);
                self.answer(request, body, writer)
            }
            "scopes" => {
                let body = self.backend.scopes(&request.arguments);
                self.answer(request, body, writer)
            }
            "variables" => {
                let body = self.backend.variables(&request.arguments);
                self.answer(request, body, writer)
            }
            "listCheckpoints" => {
                let body = self.backend.list_checkpoints();
                self.answer(request, body, writer)
            }
            "taskTimeline" => {
                let body = self.backend.task_timeline();
                self.answer(request, body, writer)
            }
            "continue" => self.on_resume(request, ResumeKind::Continue, writer),
            "reverseContinue" => self.on_resume(request, ResumeKind::ReverseContinue, writer),
            "stepBack" => self.on_resume(request, ResumeKind::StepBack, writer),
            "next" => self.on_resume(request, ResumeKind::Next, writer),
            "stepIn" => self.on_resume(request, ResumeKind::StepIn, writer),
            "stepOut" => self.on_resume(request, ResumeKind::StepOut, writer),
            "jumpToEvent" => self.on_jump(request, writer),
            other => {
                let message = format!("unsupported request: {other}");
                self.respond_failure(request, &message, writer)
            }
        }
    }

    fn on_initialize<W: Write>(
        &mut self,
        request: &Request,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        let capabilities = json!({
            "supportsConfigurationDoneRequest": true,
            "supportsStepBack": true,
            "supportsRestartRequest": false,
            "supportsSetVariable": false,
        });
        self.respond_success(request, capabilities, writer)?;
        self.emit_event("initialized", json!({}), writer)
    }

    /// Launch/attach. A `trace` argument selects the replay backend (Linux);
    /// otherwise the stub target is served. The backend's first stop is then
    /// reported as a `stopped`/`exited` event.
    fn on_launch<W: Write>(
        &mut self,
        request: &Request,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        if let Some(trace) = request.arguments.get("trace").and_then(Value::as_str) {
            match select_replay_backend(trace) {
                Ok(Some(backend)) => self.backend = backend,
                Ok(None) => self.emit_output(
                    "replay backend unavailable on this platform; serving the stub target",
                    writer,
                )?,
                Err(message) => {
                    self.emit_output(&message, writer)?;
                    return self.respond_failure(request, &message, writer);
                }
            }
        }
        match self.backend.launch(&request.arguments) {
            Ok(stop) => {
                self.respond_success(request, json!({}), writer)?;
                self.emit_stop(stop, writer)
            }
            Err(error) => self.fail(request, error, writer),
        }
    }

    fn on_resume<W: Write>(
        &mut self,
        request: &Request,
        kind: ResumeKind,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        match self.backend.resume(kind) {
            Ok(stop) => {
                let body = if kind == ResumeKind::Continue {
                    json!({ "allThreadsContinued": true })
                } else {
                    json!({})
                };
                self.respond_success(request, body, writer)?;
                self.emit_stop(stop, writer)
            }
            Err(error) => self.fail(request, error, writer),
        }
    }

    fn on_jump<W: Write>(
        &mut self,
        request: &Request,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        match self.backend.jump_to_event(&request.arguments) {
            Ok(stop) => {
                self.respond_success(request, json!({}), writer)?;
                self.emit_stop(stop, writer)
            }
            Err(error) => self.fail(request, error, writer),
        }
    }

    /// Send a body-carrying response, or surface a backend error visibly.
    fn answer<W: Write>(
        &mut self,
        request: &Request,
        body: Result<Value, BackendError>,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        match body {
            Ok(body) => self.respond_success(request, body, writer),
            Err(error) => self.fail(request, error, writer),
        }
    }

    /// Surface a backend error as a visible `output` event plus a failure
    /// response — replay divergence must never be hidden (`CLAUDE.md`).
    fn fail<W: Write>(
        &mut self,
        request: &Request,
        error: BackendError,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        let message = error.to_string();
        self.emit_output(&message, writer)?;
        self.respond_failure(request, &message, writer)
    }

    /// Translate a [`StopInfo`] into the matching DAP event(s).
    fn emit_stop<W: Write>(
        &mut self,
        stop: StopInfo,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        match stop {
            StopInfo::Stopped { reason, thread_id } => self.emit_event(
                "stopped",
                json!({
                    "reason": reason,
                    "threadId": thread_id,
                    "allThreadsStopped": true,
                }),
                writer,
            ),
            StopInfo::Exited { code } => {
                self.emit_event("exited", json!({ "exitCode": code }), writer)?;
                self.emit_event("terminated", json!({}), writer)
            }
        }
    }

    fn emit_output<W: Write>(
        &mut self,
        message: &str,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        self.emit_event(
            "output",
            json!({ "category": "stderr", "output": format!("{message}\n") }),
            writer,
        )
    }

    fn respond_success<W: Write>(
        &mut self,
        request: &Request,
        body: Value,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        let seq = self.bump_seq();
        write_frame(writer, &protocol::success(seq, request, body))
    }

    fn respond_failure<W: Write>(
        &mut self,
        request: &Request,
        message: &str,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        let seq = self.bump_seq();
        write_frame(writer, &protocol::failure(seq, request, message))
    }

    fn emit_event<W: Write>(
        &mut self,
        name: &str,
        body: Value,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        let seq = self.bump_seq();
        write_frame(writer, &protocol::event(seq, name, body))
    }

    fn bump_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }
}

/// Build the replay backend for `trace`, or report why it cannot be.
///
/// On Linux: `Ok(Some(backend))` on success, `Err(message)` if the trace
/// cannot be opened. On other platforms: `Ok(None)` — the caller keeps the
/// stub so the server stays usable everywhere.
#[cfg(target_os = "linux")]
fn select_replay_backend(trace: &str) -> Result<Option<Box<dyn DebugBackend>>, String> {
    crate::replay_backend::ReplayBackend::open(std::path::Path::new(trace))
        .map(|backend| Some(Box::new(backend) as Box<dyn DebugBackend>))
        .map_err(|error| error.to_string())
}

/// Non-Linux: the replay engine is Linux-only, so keep the stub target.
#[cfg(not(target_os = "linux"))]
fn select_replay_backend(_trace: &str) -> Result<Option<Box<dyn DebugBackend>>, String> {
    Ok(None)
}

/// Serve one DAP session over stdio (what `mirrorscope dap` runs).
pub fn serve_stdio() -> Result<(), TransportError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    Server::new().run_buffered(&mut reader, &mut writer)
}
