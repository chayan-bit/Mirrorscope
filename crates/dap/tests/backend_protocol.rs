//! Portable, protocol-level tests for the execution-control and custom
//! requests the backend seam added (issue #8), exercised against the stub
//! backend so they run on every platform. Linux replay behavior is covered by
//! `replay_backend.rs`.

use dap::server::Server;
use dap::transport::{read_frame, write_frame};
use serde_json::{json, Value};

/// Drive the server over in-memory pipes and return every message it emitted.
fn drive(requests: &[Value]) -> Vec<Value> {
    let mut input = Vec::new();
    for req in requests {
        write_frame(&mut input, req).expect("encode request");
    }
    let mut output = Vec::new();
    Server::new()
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

fn events_named<'a>(messages: &'a [Value], event: &str) -> Vec<&'a Value> {
    messages
        .iter()
        .filter(|m| m["type"] == "event" && m["event"] == event)
        .collect()
}

fn session(extra: &[Value]) -> Vec<Value> {
    let mut requests = vec![
        request(1, "initialize", json!({})),
        request(2, "launch", json!({ "program": "/bin/true" })),
    ];
    requests.extend_from_slice(extra);
    requests.push(request(99, "disconnect", json!({})));
    drive(&requests)
}

#[test]
fn continue_responds_and_emits_a_stop() {
    let messages = session(&[request(3, "continue", json!({ "threadId": 1 }))]);
    let resp = response_for(&messages, "continue");
    assert_eq!(resp["success"], true);
    assert_eq!(resp["body"]["allThreadsContinued"], true);
    // A stop event must follow (launch also emits one, so expect at least two).
    assert!(events_named(&messages, "stopped").len() >= 2);
}

#[test]
fn forward_steps_succeed_and_stop_on_the_stub() {
    for command in ["next", "stepIn", "stepOut"] {
        let messages = session(&[request(3, command, json!({ "threadId": 1 }))]);
        let resp = response_for(&messages, command);
        assert_eq!(resp["success"], true, "{command} must succeed on the stub");
        let stopped = events_named(&messages, "stopped");
        assert_eq!(
            stopped.last().expect("a stop event")["body"]["reason"],
            "step",
            "{command} should report a step stop"
        );
    }
}

#[test]
fn reverse_and_jump_fail_politely_pointing_at_replay() {
    let messages = session(&[
        request(3, "stepBack", json!({ "threadId": 1 })),
        request(4, "reverseContinue", json!({ "threadId": 1 })),
        request(5, "jumpToEvent", json!({ "seq": 10 })),
    ]);
    for command in ["stepBack", "reverseContinue", "jumpToEvent"] {
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
fn backend_errors_surface_as_a_visible_output_event() {
    // A failing reverse request on the stub must also emit an output event so
    // the client sees the reason, not just a bare failure response.
    let messages = session(&[request(3, "stepBack", json!({ "threadId": 1 }))]);
    let outputs = events_named(&messages, "output");
    assert!(
        outputs.iter().any(|e| e["body"]["output"]
            .as_str()
            .unwrap_or("")
            .contains("replay")),
        "a failing backend op must emit a visible output event mentioning replay"
    );
}

#[test]
fn list_checkpoints_and_task_timeline_return_real_shapes() {
    let messages = session(&[
        request(3, "listCheckpoints", json!({})),
        request(4, "taskTimeline", json!({})),
    ]);
    assert!(response_for(&messages, "listCheckpoints")["body"]["checkpoints"].is_array());
    assert!(response_for(&messages, "taskTimeline")["body"]["tasks"].is_array());
}
