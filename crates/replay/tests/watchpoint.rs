//! Linux-only integration test for retroactive watchpoints (issue #12).
//!
//! Records the `watchpoint_writer` fixture (which prints the address of a global
//! and then writes it five times), learns the address from a probe replay, and
//! scans the recorded history for writes to that address. The load-bearing
//! assertion: a hardware watchpoint armed during replay catches *exactly* the
//! writes the fixture performed — the "every write to X across history" query
//! that only replay makes possible — each with a plausible pc and a backtrace
//! that names the writing function.
//!
//! Runs only on Linux (the engine is ptrace-gated); the portable encoding and
//! validation math is unit-tested in the `watchpoint` module on every host.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};

use recorder::capture::record_command;
use replay::{ReplaySession, WatchpointScan};

/// The fixture writes its global this many times; see `src/bin/watchpoint_writer.rs`.
const EXPECTED_WRITES: usize = 5;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mirrorscope-watchpoint-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Record the fixture binary into a fresh trace and return its path.
fn record_fixture(dir: &Path) -> PathBuf {
    let fixture = env!("CARGO_BIN_EXE_watchpoint_writer");
    let trace_path = dir.join("writer.mscope");
    let outcome = record_command(fixture, &[], &trace_path).expect("recording must succeed");
    assert_eq!(outcome.exit_code, Some(0), "recorded fixture must exit 0");
    trace_path
}

/// Replay the trace once to read the global's address off the fixture's stdout.
/// Both this probe and the later scan replay under `ADDR_NO_RANDOMIZE`, so the
/// address is identical in both runs.
fn probe_target_address(trace_path: &Path) -> u64 {
    let mut session = ReplaySession::launch(trace_path).expect("launch probe replay");
    session.run_to_end().expect("probe replay to completion");
    let stdout = session.read_stdout().expect("read probe stdout");
    let text = String::from_utf8(stdout).expect("fixture prints utf-8");
    text.trim()
        .parse::<u64>()
        .expect("fixture prints the target address as a decimal u64")
}

#[test]
fn finds_every_write_to_a_global_across_history() {
    let dir = temp_dir("writes");
    let trace_path = record_fixture(&dir);
    let addr = probe_target_address(&trace_path);
    assert_ne!(addr, 0, "the global must have a real address");

    let hits = WatchpointScan::new(&trace_path, addr, 8)
        .run()
        .expect("watchpoint scan must succeed");

    assert_eq!(
        hits.len(),
        EXPECTED_WRITES,
        "the scan must report exactly the fixture's writes, got {hits:?}"
    );

    // Every hit must carry a plausible pc and a backtrace naming the writer.
    for hit in &hits {
        assert_ne!(hit.pc, 0, "each hit must record a non-zero pc");
        let names: Vec<String> = hit
            .backtrace
            .iter()
            .filter_map(|frame| frame.function.clone())
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.contains("hammer") || n.contains("watchpoint_writer")),
            "a hit's backtrace must name the writing function, got {names:?}"
        );
    }

    // The final observed value must be the fixture's last write (5), and the
    // sequence of new values must be the ascending writes 1..=5.
    let observed: Vec<u64> = hits
        .iter()
        .map(|hit| {
            let bytes: [u8; 8] = hit.new_value.as_slice().try_into().expect("8-byte value");
            u64::from_ne_bytes(bytes)
        })
        .collect();
    assert_eq!(
        observed,
        (1..=EXPECTED_WRITES as u64).collect::<Vec<_>>(),
        "new values across hits must be the fixture's ascending writes"
    );

    // The first hit's old value is the pre-scan read (0); later hits chain the
    // previous new value as their old value.
    assert_eq!(
        hits[0].old_value.as_deref(),
        Some(&0u64.to_ne_bytes()[..]),
        "first hit's old value must be the initial zero"
    );

    fs::remove_dir_all(&dir).ok();
}
