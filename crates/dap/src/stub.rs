//! The static stub target the skeleton serves until the replay engine
//! exists: one thread, a canned stack, canned locals. Enough for a DAP
//! client to attach and render *something* (issue #3's "done when").

use serde_json::{json, Value};

/// Thread id of the single stub thread.
pub const MAIN_THREAD_ID: u64 = 1;

/// `threads` response body.
pub fn threads() -> Value {
    json!({ "threads": [{ "id": MAIN_THREAD_ID, "name": "main" }] })
}

/// `stackTrace` response body: a canned two-frame stack.
pub fn stack_trace() -> Value {
    json!({
        "stackFrames": [
            {
                "id": 1,
                "name": "main (stub target — recording/replay not yet wired)",
                "line": 1,
                "column": 1,
            },
            {
                "id": 2,
                "name": "_start (stub)",
                "line": 0,
                "column": 0,
            },
        ],
        "totalFrames": 2,
    })
}

/// `scopes` response body for any frame.
pub fn scopes() -> Value {
    json!({
        "scopes": [{
            "name": "Locals",
            "variablesReference": 1,
            "expensive": false,
        }],
    })
}

/// `variables` response body for the locals reference.
pub fn variables() -> Value {
    json!({
        "variables": [{
            "name": "mirrorscope",
            "value": "stub target — see issues #4/#6 for real state",
            "variablesReference": 0,
        }],
    })
}
