//! Linux-only integration tests for fork-snapshot checkpointing (issue #5).
//!
//! These exercise the real ptrace fork machinery end to end: recording a
//! read-heavy target, taking checkpoints every N seq units during replay,
//! restoring to the nearest checkpoint at-or-before a target seq, replaying
//! forward again after a restore, and — the load-bearing assertion — that state
//! reached via a checkpoint restore is register-identical to a straight replay.
//!
//! They only run on Linux CI (the whole engine is ptrace-gated); locally on
//! macOS the portable index-selection logic is covered by the unit tests in
//! `checkpoint_select`.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use recorder::capture::record_command;
use recorder::trace::{EventKind, TraceReader};
use replay::{ExitOutcome, ReplaySession};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mirrorscope-checkpoint-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Record `head -c <big> <file>` over a sizeable file so the trace holds many
/// `read`/`write` syscalls (hence many seq boundaries to checkpoint between).
fn record_read_heavy(dir: &Path) -> PathBuf {
    let data_path = dir.join("data.txt");
    // Distinct bytes, large enough to span many read()/write() chunks.
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

/// The seq numbers of every `SyscallExit` record in a trace, ascending.
fn exit_seqs(trace_path: &Path) -> Vec<u64> {
    let file = fs::File::open(trace_path).expect("open trace");
    let reader = TraceReader::open(BufReader::new(file)).expect("valid header");
    reader
        .map(|r| r.expect("intact record"))
        .filter(|r| r.event.kind == EventKind::SyscallExit)
        .map(|r| r.seq)
        .collect()
}

#[test]
fn takes_fork_snapshots_at_the_configured_interval() {
    let dir = temp_dir("interval");
    let trace_path = record_read_heavy(&dir);

    let mut session = ReplaySession::launch(&trace_path).expect("launch replay");
    session.checkpoint_interval(4);
    let exit = session.run_to_end().expect("replay to completion");
    assert_eq!(exit, ExitOutcome::Exited(0), "replayed target must exit 0");

    let seqs: Vec<u64> = session.checkpoints().iter().map(|cp| cp.seq).collect();
    assert!(
        !seqs.is_empty(),
        "a read-heavy target replayed with interval 4 must yield checkpoints"
    );
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "checkpoint seqs must be strictly ascending, got {seqs:?}"
    );
    assert!(
        seqs.windows(2).all(|w| w[1] - w[0] >= 4),
        "consecutive checkpoints must be at least an interval apart, got {seqs:?}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn restores_to_the_nearest_checkpoint_at_or_before_a_seq() {
    let dir = temp_dir("restore");
    let trace_path = record_read_heavy(&dir);
    let seqs = exit_seqs(&trace_path);
    assert!(
        seqs.len() >= 4,
        "need several syscalls to checkpoint between"
    );
    let target = seqs[seqs.len() * 3 / 4];

    let mut session = ReplaySession::launch(&trace_path).expect("launch replay");
    session.checkpoint_interval(3);
    session.run_to_end().expect("build checkpoints and exit");

    let expected = session
        .checkpoints()
        .iter()
        .map(|cp| cp.seq)
        .rfind(|&s| s <= target)
        .expect("a checkpoint must precede a late target");

    session
        .restore_to(target)
        .expect("restore to nearest checkpoint");
    assert_eq!(
        session.current_seq(),
        Some(expected),
        "restore must re-seat the session exactly at the nearest checkpoint"
    );
    assert!(
        session.current_seq().expect("seated") <= target,
        "the restored checkpoint must be at-or-before the target seq"
    );

    // The restored image must be live and replayable forward again.
    let outcome = session
        .run_to(target)
        .expect("replay forward after restore");
    assert!(
        matches!(outcome, ExitOutcome::Running | ExitOutcome::Exited(0)),
        "forward replay after restore must progress, got {outcome:?}"
    );
    assert!(session.current_seq().expect("advanced") >= expected);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn restore_then_replay_matches_straight_replay_registers() {
    let dir = temp_dir("equiv");
    let trace_path = record_read_heavy(&dir);
    let seqs = exit_seqs(&trace_path);
    assert!(
        seqs.len() >= 4,
        "need several syscalls for a meaningful target"
    );
    let target = seqs[seqs.len() * 3 / 4];

    // Ground truth: a straight replay from entry to the target seq.
    let mut straight = ReplaySession::launch(&trace_path).expect("launch straight");
    straight.step_to(target).expect("straight replay to target");
    let straight_seq = straight.current_seq();
    let straight_regs = straight.regs().expect("registers at target");

    // Checkpointed replay: run past the target (building snapshots and exiting),
    // then jump *backward* to the target via a checkpoint restore.
    let mut checked = ReplaySession::launch(&trace_path).expect("launch checkpointed");
    checked.checkpoint_interval(3);
    checked.run_to_end().expect("build checkpoints and exit");
    assert!(
        !checked.checkpoints().is_empty(),
        "checkpointed run must have produced snapshots"
    );
    let outcome = checked.run_to(target).expect("restore + replay to target");
    assert_eq!(
        outcome,
        ExitOutcome::Running,
        "reaching an interior seq must leave the tracee running"
    );

    assert_eq!(
        checked.current_seq(),
        straight_seq,
        "checkpointed replay must stop at the same seq as straight replay"
    );
    assert_eq!(
        checked.regs(),
        Some(straight_regs),
        "state reached via checkpoint restore must be register-identical to a \
         straight replay — otherwise the snapshot diverged"
    );

    fs::remove_dir_all(&dir).ok();
}
