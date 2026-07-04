//! Minimal typed view of DAP messages: the request envelope we receive and
//! builders for the responses/events we send.

use serde::Deserialize;
use serde_json::{json, Value};

/// An incoming DAP request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Client-assigned sequence number, echoed back as `request_seq`.
    pub seq: u64,
    /// The DAP command name (`initialize`, `threads`, …).
    pub command: String,
    /// Command-specific arguments; `null` when absent.
    #[serde(default)]
    pub arguments: Value,
}

/// Build a successful response with a body.
pub fn success(seq: u64, request: &Request, body: Value) -> Value {
    json!({
        "seq": seq,
        "type": "response",
        "request_seq": request.seq,
        "command": request.command,
        "success": true,
        "body": body,
    })
}

/// Build a failure response with a user-facing message.
pub fn failure(seq: u64, request: &Request, message: &str) -> Value {
    json!({
        "seq": seq,
        "type": "response",
        "request_seq": request.seq,
        "command": request.command,
        "success": false,
        "message": message,
    })
}

/// Build an event message.
pub fn event(seq: u64, name: &str, body: Value) -> Value {
    json!({
        "seq": seq,
        "type": "event",
        "event": name,
        "body": body,
    })
}
