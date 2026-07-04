//! The DAP request loop: reads framed requests, dispatches, writes framed
//! responses/events. Generic over `Read`/`Write` so tests drive it with
//! in-memory pipes and the CLI runs it over stdio.

use std::io::{BufRead, BufReader, Read, Write};

use serde_json::{json, Value};

use crate::protocol::{self, Request};
use crate::stub;
use crate::transport::{read_frame, write_frame, TransportError};

/// Reply to `stepBack`/`reverseContinue` until issue #8 wires them up.
const REVERSE_STUB_MESSAGE: &str =
    "not yet wired to the replay engine (Phase 1, issue #8): reverse execution needs a recording";

/// A single-session DAP server.
#[derive(Debug, Default)]
pub struct Server {
    next_seq: u64,
}

impl Server {
    /// Create a server for one client session.
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
            "threads" => self.respond_success(request, stub::threads(), writer),
            "stackTrace" => self.respond_success(request, stub::stack_trace(), writer),
            "scopes" => self.respond_success(request, stub::scopes(), writer),
            "variables" => self.respond_success(request, stub::variables(), writer),
            "stepBack" | "reverseContinue" => {
                self.respond_failure(request, REVERSE_STUB_MESSAGE, writer)
            }
            "listCheckpoints" => {
                self.respond_success(request, json!({ "checkpoints": [] }), writer)
            }
            "taskTimeline" => self.respond_success(request, json!({ "tasks": [] }), writer),
            "jumpToEvent" => self.respond_failure(
                request,
                "jumpToEvent needs the replay engine (issue #6)",
                writer,
            ),
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

    /// Launch/attach against the stub target: succeed, then report an
    /// immediate stop at entry so clients ask for threads/stack.
    fn on_launch<W: Write>(
        &mut self,
        request: &Request,
        writer: &mut W,
    ) -> Result<(), TransportError> {
        self.respond_success(request, json!({}), writer)?;
        let body = json!({
            "reason": "entry",
            "threadId": stub::MAIN_THREAD_ID,
            "allThreadsStopped": true,
        });
        self.emit_event("stopped", body, writer)
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

/// Serve one DAP session over stdio (what `mirrorscope dap` runs).
pub fn serve_stdio() -> Result<(), TransportError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    Server::new().run_buffered(&mut reader, &mut writer)
}
