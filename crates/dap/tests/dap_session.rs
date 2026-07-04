//! Integration tests for the DAP server skeleton (issue #3): a client can
//! initialize, launch, and inspect a (static) stack against the stub target.

use dap::server::Server;
use dap::transport::{read_frame, write_frame};
use serde_json::{json, Value};

/// Encode a batch of requests, run the server over in-memory pipes, and
/// return every message (responses + events) it produced, in order.
fn drive(requests: &[Value]) -> Vec<Value> {
    let mut input = Vec::new();
    for req in requests {
        write_frame(&mut input, req).expect("encode request");
    }

    let mut output = Vec::new();
    let mut server = Server::new();
    server
        .run(&mut input.as_slice(), &mut output)
        .expect("server run");

    let mut cursor = output.as_slice();
    let mut messages = Vec::new();
    while let Some(msg) = read_frame(&mut cursor).expect("decode server output") {
        messages.push(msg);
    }
    messages
}

fn request(seq: u64, command: &str, arguments: Value) -> Value {
    json!({ "seq": seq, "type": "request", "command": command, "arguments": arguments })
}

fn response_for<'a>(messages: &'a [Value], command: &str) -> &'a Value {
    messages
        .iter()
        .find(|m| m["type"] == "response" && m["command"] == command)
        .unwrap_or_else(|| panic!("no response for {command} in {messages:?}"))
}

fn full_session() -> Vec<Value> {
    drive(&[
        request(1, "initialize", json!({ "adapterID": "mirrorscope" })),
        request(2, "launch", json!({ "program": "/bin/true" })),
        request(3, "configurationDone", json!({})),
        request(4, "threads", json!({})),
        request(5, "stackTrace", json!({ "threadId": 1 })),
        request(6, "scopes", json!({ "frameId": 1 })),
        request(7, "variables", json!({ "variablesReference": 1 })),
        request(8, "stepBack", json!({ "threadId": 1 })),
        request(9, "reverseContinue", json!({ "threadId": 1 })),
        request(10, "listCheckpoints", json!({})),
        request(11, "taskTimeline", json!({})),
        request(12, "disconnect", json!({})),
    ])
}

#[test]
fn initialize_advertises_time_travel_capabilities() {
    let messages = full_session();
    let init = response_for(&messages, "initialize");
    assert_eq!(init["success"], true);
    assert_eq!(init["request_seq"], 1);
    assert_eq!(init["body"]["supportsStepBack"], true);
    assert_eq!(init["body"]["supportsConfigurationDoneRequest"], true);
}

#[test]
fn initialized_event_follows_initialize_response() {
    let messages = full_session();
    let init_pos = messages
        .iter()
        .position(|m| m["type"] == "response" && m["command"] == "initialize")
        .expect("initialize response");
    let event_pos = messages
        .iter()
        .position(|m| m["type"] == "event" && m["event"] == "initialized")
        .expect("initialized event");
    assert!(event_pos > init_pos);
}

#[test]
fn launch_stops_at_entry() {
    let messages = full_session();
    assert_eq!(response_for(&messages, "launch")["success"], true);
    let stopped = messages
        .iter()
        .find(|m| m["type"] == "event" && m["event"] == "stopped")
        .expect("stopped event");
    assert_eq!(stopped["body"]["reason"], "entry");
    assert_eq!(stopped["body"]["threadId"], 1);
}

#[test]
fn threads_and_stack_trace_show_the_stub_target() {
    let messages = full_session();

    let threads = &response_for(&messages, "threads")["body"]["threads"];
    assert_eq!(threads.as_array().expect("threads array").len(), 1);
    assert_eq!(threads[0]["id"], 1);

    let frames = &response_for(&messages, "stackTrace")["body"]["stackFrames"];
    let frames = frames.as_array().expect("frames array");
    assert!(!frames.is_empty());
    assert!(frames[0]["name"].is_string());
    assert!(frames[0]["line"].is_u64());
}

#[test]
fn scopes_and_variables_resolve_against_the_stub() {
    let messages = full_session();

    let scopes = &response_for(&messages, "scopes")["body"]["scopes"];
    let scopes = scopes.as_array().expect("scopes array");
    assert!(!scopes.is_empty());
    let var_ref = scopes[0]["variablesReference"].as_u64().expect("var ref");
    assert!(var_ref > 0);

    let variables = &response_for(&messages, "variables")["body"]["variables"];
    assert!(!variables.as_array().expect("variables array").is_empty());
}

#[test]
fn reverse_requests_are_stubbed_not_missing() {
    let messages = full_session();
    for command in ["stepBack", "reverseContinue"] {
        let resp = response_for(&messages, command);
        assert_eq!(resp["success"], false, "{command} must be a polite stub");
        assert!(
            resp["message"]
                .as_str()
                .expect("message")
                .contains("replay"),
            "{command} should point at the replay engine"
        );
    }
}

#[test]
fn vendor_requests_are_registered_placeholders() {
    let messages = full_session();
    let checkpoints = response_for(&messages, "listCheckpoints");
    assert_eq!(checkpoints["success"], true);
    assert_eq!(checkpoints["body"]["checkpoints"], json!([]));

    let timeline = response_for(&messages, "taskTimeline");
    assert_eq!(timeline["success"], true);
    assert_eq!(timeline["body"]["tasks"], json!([]));
}

#[test]
fn unknown_requests_fail_gracefully_and_server_keeps_running() {
    let messages = drive(&[
        request(1, "initialize", json!({})),
        request(2, "definitelyNotARequest", json!({})),
        request(3, "threads", json!({})),
        request(4, "disconnect", json!({})),
    ]);
    let unknown = response_for(&messages, "definitelyNotARequest");
    assert_eq!(unknown["success"], false);
    // The server must survive the unknown request and answer the next one.
    assert_eq!(response_for(&messages, "threads")["success"], true);
}

#[test]
fn responses_echo_request_seq_and_use_monotonic_server_seq() {
    let messages = full_session();
    let seqs: Vec<u64> = messages
        .iter()
        .map(|m| m["seq"].as_u64().expect("seq"))
        .collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "server seq must be monotonic");
    assert_eq!(response_for(&messages, "disconnect")["request_seq"], 12);
}
