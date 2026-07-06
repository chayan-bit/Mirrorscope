//! Linux-only integration tests for the replay engine (issue #6).
//!
//! The load-bearing test records a program that reads a file, then changes the
//! file on disk and replays: the replayed stdout must equal the ORIGINAL file
//! content, proving the `read()` results came from the trace and not the live
//! filesystem. A second test proves divergence is surfaced, never hidden.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::BufReader;
use std::path::PathBuf;

use recorder::capture::payload::SyscallEnter;
use recorder::capture::record_command;
use recorder::trace::{EventKind, Record, TraceReader, TraceWriter};
use replay::{ExitOutcome, ReplayError, ReplaySession};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mirrorscope-replay-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn replays_recorded_read_results_not_the_live_filesystem() {
    let dir = temp_dir("inject");
    let data_path = dir.join("data.txt");
    let original: &[u8] = b"mirrorscope-replay-original-payload\n";
    fs::write(&data_path, original).expect("write original file");

    let trace_path = dir.join("read.mscope");
    let data_arg = data_path.to_str().expect("utf-8 path").to_owned();
    // `head -c N file` reads the file with read() syscalls (never copy_file_range)
    // and writes the bytes to stdout, so the read results land in the trace.
    let outcome = record_command(
        "head",
        &["-c".to_owned(), "1048576".to_owned(), data_arg],
        &trace_path,
    )
    .expect("recording must succeed");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "recorded target must exit cleanly"
    );

    // Change the file on disk (same length, so fstat/size stay identical). If
    // replay re-read the filesystem it would see this; injection must not.
    let modified = vec![b'X'; original.len()];
    fs::write(&data_path, &modified).expect("overwrite file");
    assert_ne!(modified.as_slice(), original);

    let mut session = ReplaySession::launch(&trace_path).expect("launch replay");
    let exit = session.run_to_end().expect("replay to completion");
    assert_eq!(exit, ExitOutcome::Exited(0), "replayed target must exit 0");

    let stdout = session.read_stdout().expect("read replay stdout");
    assert_eq!(
        stdout, original,
        "replayed stdout must be the ORIGINAL content fed from the trace, \
         not the modified bytes now on disk"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn surfaces_divergence_when_the_trace_disagrees_with_the_tracee() {
    let dir = temp_dir("diverge");
    let trace_path = dir.join("true.mscope");
    record_command("true", &[], &trace_path).expect("recording must succeed");

    // Re-write the trace with the first syscall-enter number tampered so it can
    // never match what the tracee actually issues.
    let file = fs::File::open(&trace_path).expect("open trace");
    let reader = TraceReader::open(BufReader::new(file)).expect("valid header");
    let cmdline = reader
        .cmdline()
        .cloned()
        .expect("v2 trace embeds a cmdline");
    let records: Vec<Record> = reader
        .map(|r| r.expect("intact record"))
        .collect::<Vec<_>>();

    let mut writer = TraceWriter::create_with_cmdline(Vec::new(), &cmdline.program, &cmdline.args)
        .expect("create writer");
    let mut tampered = false;
    for record in &records {
        let mut event = record.event.clone();
        if !tampered && event.kind == EventKind::SyscallEnter {
            let mut enter = SyscallEnter::decode(&event.payload).expect("decode enter");
            enter.nr = 0xdead_beef;
            event.payload = enter.encode();
            tampered = true;
        }
        writer.append(&event).expect("append event");
    }
    assert!(tampered, "trace must contain at least one syscall enter");
    let tampered_path = dir.join("tampered.mscope");
    fs::write(&tampered_path, writer.into_inner()).expect("write tampered trace");

    let mut session = ReplaySession::launch(&tampered_path).expect("launch replay");
    let result = session.run_to_end();
    assert!(
        matches!(result, Err(ReplayError::Diverged { .. })),
        "a tampered syscall number must surface as Diverged, got {result:?}"
    );

    fs::remove_dir_all(&dir).ok();
}
