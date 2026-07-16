//! Linux-only end-to-end test (issue #8): record a tiny target, then drive the
//! DAP server programmatically against the real replay engine and assert the
//! full inspect + time-travel loop produces sane responses.
//!
//! Runs only on Linux CI / in Docker (the whole engine is ptrace-gated). It
//! records `head -c N <file>` (many `read` syscalls → many event boundaries,
//! no compiler needed), exactly as the replay crate's own checkpoint tests do.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use dap::server::Server;
use dap::transport::{read_frame, write_frame};
use recorder::capture::record_command;
use recorder::trace::{EventKind, TraceReader};
use serde_json::{json, Value};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mirrorscope-dap-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Record `head -c 1MiB <big file>` so the trace holds many `read`/`write`
/// syscalls — hence many event boundaries to step between.
fn record_read_heavy(dir: &Path) -> PathBuf {
    let data_path = dir.join("data.txt");
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&data_path, &payload).expect("write source file");

    let trace_path = dir.join("read.mscope");
    let data_arg = data_path.to_str().expect("utf-8 path").to_owned();
    let outcome = record_command(
        "head",
        &["-c".to_owned(), "1048576".to_owned(), data_arg],
        &trace_path,
    )
    .expect("recording must succeed");
    assert_eq!(outcome.exit_code, Some(0), "recorded target must exit 0");
    trace_path
}

/// Ascending seq of every `SyscallExit` record in a trace.
fn exit_seqs(trace_path: &Path) -> Vec<u64> {
    let file = fs::File::open(trace_path).expect("open trace");
    let reader = TraceReader::open(BufReader::new(file)).expect("valid header");
    reader
        .map(|r| r.expect("intact record"))
        .filter(|r| r.event.kind == EventKind::SyscallExit)
        .map(|r| r.seq)
        .collect()
}

fn request(seq: u64, command: &str, arguments: Value) -> Value {
    json!({ "seq": seq, "type": "request", "command": command, "arguments": arguments })
}

/// Feed the whole request batch to the server (driving real replay per
/// request) and return every message it emitted, in order.
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

fn response_for<'a>(messages: &'a [Value], command: &str) -> &'a Value {
    messages
        .iter()
        .find(|m| m["type"] == "response" && m["command"] == command)
        .unwrap_or_else(|| panic!("no response for {command} in {messages:#?}"))
}

fn stopped_events(messages: &[Value]) -> Vec<&Value> {
    messages
        .iter()
        .filter(|m| m["type"] == "event" && m["event"] == "stopped")
        .collect()
}

#[test]
fn drives_the_full_replay_inspect_and_time_travel_loop() {
    let dir = temp_dir("e2e");
    let trace_path = record_read_heavy(&dir);
    let seqs = exit_seqs(&trace_path);
    assert!(seqs.len() >= 4, "need several events to step between");
    let jump_target = seqs[seqs.len() / 2];
    let trace_arg = trace_path.to_str().expect("utf-8 path").to_owned();

    let messages = drive(&[
        request(1, "initialize", json!({ "adapterID": "mirrorscope" })),
        request(2, "launch", json!({ "trace": trace_arg })),
        request(3, "threads", json!({})),
        request(4, "stackTrace", json!({ "threadId": 1 })),
        request(5, "scopes", json!({ "frameId": 1 })),
        request(6, "variables", json!({ "variablesReference": 1000 })),
        request(7, "taskTimeline", json!({})),
        request(8, "jumpToEvent", json!({ "seq": jump_target })),
        request(9, "stepBack", json!({ "threadId": 1 })),
        request(10, "reverseContinue", json!({ "threadId": 1 })),
        request(11, "listCheckpoints", json!({})),
        request(12, "continue", json!({ "threadId": 1 })),
        request(13, "disconnect", json!({})),
    ]);

    // launch selected the replay backend and stopped at entry.
    assert_eq!(response_for(&messages, "launch")["success"], true);
    let stops = stopped_events(&messages);
    assert_eq!(
        stops.first().expect("a launch stop")["body"]["reason"],
        "entry"
    );

    // threads: the single replayed thread, decoded from the live tracee.
    let threads = &response_for(&messages, "threads")["body"]["threads"];
    let threads = threads.as_array().expect("threads array");
    assert_eq!(threads.len(), 1, "the read-heavy target is single-threaded");
    assert_eq!(threads[0]["id"], 1);

    // stackTrace: real symbolized frames off the stopped tracee.
    let frames = &response_for(&messages, "stackTrace")["body"]["stackFrames"];
    let frames = frames.as_array().expect("frames array");
    assert!(!frames.is_empty(), "a stopped tracee must unwind ≥1 frame");
    assert!(frames[0]["name"].is_string());

    // scopes/variables: a registers scope with real register values.
    let scopes = &response_for(&messages, "scopes")["body"]["scopes"];
    assert_eq!(scopes[0]["name"], "Registers");
    let vars = &response_for(&messages, "variables")["body"]["variables"];
    let vars = vars.as_array().expect("variables array");
    assert!(
        vars.iter().any(|v| v["name"] == "pc"),
        "registers scope must expose pc"
    );

    // taskTimeline: the decoder's task tree serialized (one thread task).
    let tasks = &response_for(&messages, "taskTimeline")["body"]["tasks"];
    assert!(!tasks.as_array().expect("tasks array").is_empty());

    // Time travel: jumpToEvent, stepBack, reverseContinue all succeed + stop.
    for command in ["jumpToEvent", "stepBack", "reverseContinue"] {
        assert_eq!(
            response_for(&messages, command)["success"],
            true,
            "{command} must succeed against the real engine"
        );
    }

    // listCheckpoints: the real (checkpointing-disabled → empty) list.
    let checkpoints = &response_for(&messages, "listCheckpoints")["body"]["checkpoints"];
    assert!(checkpoints.is_array());

    // continue runs to completion → exited + terminated.
    assert_eq!(response_for(&messages, "continue")["success"], true);
    assert!(
        messages
            .iter()
            .any(|m| m["type"] == "event" && m["event"] == "exited"),
        "continue to end must emit an exited event"
    );
    assert!(
        messages
            .iter()
            .any(|m| m["type"] == "event" && m["event"] == "terminated"),
        "continue to end must emit a terminated event"
    );

    fs::remove_dir_all(&dir).ok();
}
