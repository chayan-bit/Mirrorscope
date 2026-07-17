//! Linux-only integration tests for multi-threaded, schedule-enforced replay
//! (issue #10).
//!
//! The load-bearing test records a pthreads target whose threads each `pread`
//! a *distinct* region of a data file, then modifies the data file on disk and
//! replays. Because replay injects the recorded `pread` results, every thread's
//! output must equal its ORIGINAL region — proving (a) replay completes without
//! divergence, (b) per-tid injection routes each recorded result to the right
//! live thread (a mis-routed injection would hand a thread another region's
//! bytes), and (c) the live filesystem is never re-read.
//!
//! A second test proves a tampered schedule (a syscall record re-tagged to the
//! wrong thread) is surfaced as [`ReplayError::ScheduleDiverged`], never
//! silently reordered. A third confirms single-threaded traces still replay via
//! the unchanged single-tracee path.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;

use recorder::capture::record_command;
use recorder::trace::{Event, EventKind, Record, TraceReader, TraceWriter};
use replay::{ExitOutcome, ReplayError, ReplaySession, WatchKind};

const THREADS: usize = 3;
const CHUNK: usize = 64;

/// Each of `THREADS` threads `pread`s its own `CHUNK`-byte region and writes the
/// bytes to a pre-opened per-thread fd, then flags completion in a shared atomic
/// counter and exits with a *raw* `SYS_exit`.
///
/// Deliberately free of any **blocking** syscall, which matters for
/// Mirrorscope's determinism model. The recorder preempts on a timer at
/// *arbitrary* user-space instructions (no perf counters to reproduce the exact
/// point — the whole ARM thesis), and a blocking syscall interrupted by that
/// timer is recorded with kernel-internal `-ERESTARTSYS` restart artifacts.
/// Replay has no such timer, so re-executing a genuinely blocking `futex`/read
/// would deadlock or diverge. So the workers touch no glibc lock (raw `pread`
/// /`write`/`exit`, all fds prepared in single-threaded `main`), and `main`
/// waits by spinning on the counter in user space rather than `pthread_join`
/// (whose `futex_wait` blocks). Every wait is thus resolved by the enforced
/// schedule, never by a blocking kernel call.
const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>

#define N 3
#define CHUNK 64

static volatile int done_count = 0;

struct arg { int id; int datafd; int outfd; };

static void* work(void* p) {
    struct arg* a = (struct arg*)p;
    char buf[CHUNK];
    long n = syscall(SYS_pread64, a->datafd, buf, (long)CHUNK, (long)a->id * CHUNK);
    if (n > 0) syscall(SYS_write, a->outfd, buf, n);
    __atomic_add_fetch(&done_count, 1, __ATOMIC_SEQ_CST);
    syscall(SYS_exit, 0);
    return 0;
}

int main(int argc, char** argv) {
    int datafd = open(argv[1], O_RDONLY);
    struct arg a[N];
    pthread_t t[N];
    for (int i = 0; i < N; i++) {
        char path[1024];
        snprintf(path, sizeof path, "%s/thread_%d.out", argv[2], i);
        a[i].id = i;
        a[i].datafd = datafd;
        a[i].outfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
    for (int i = 0; i < N; i++) pthread_create(&t[i], 0, work, &a[i]);
    while (__atomic_load_n(&done_count, __ATOMIC_SEQ_CST) < N) { /* user-space spin */ }
    return 0;
}
"#;

/// A second pthreads fixture for the `clear_watch` regression below (H1):
/// prints the address of a watched global, spawns two workers that each
/// increment it once and exit, while main spin-waits on their completion
/// counter (the same spin-only, no-blocking-syscall discipline as [`SOURCE`]).
///
/// Deliberately has **no** dependency running the other way (main never
/// signals the workers to proceed): replay only ever switches threads at a
/// syscall/spawn/exit boundary, never mid-instruction, so any handshake where
/// two threads each spin-wait on a memory write only the *other* one can make
/// (worker waits on main, main waits on workers) can never resolve under
/// replay — the workers here don't wait on anything, so no such cycle exists.
/// This gives the test a safe window right after both `ThreadSpawn` records
/// (both workers registered but not yet resumed at all, so neither has
/// written the watched global) in which to arm and then clear the watchpoint
/// — the exact window `clear_watch` must disarm every live thread in, not
/// just the leader.
const WATCH_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#define N 2

static volatile int counter = 0;
static volatile int done_count = 0;

static void* work(void* p) {
    (void)p;
    __atomic_add_fetch(&counter, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&done_count, 1, __ATOMIC_SEQ_CST);
    syscall(SYS_exit, 0);
    return 0;
}

int main(void) {
    printf("%lu\n", (unsigned long)(uintptr_t)&counter);
    fflush(stdout);
    pthread_t t[N];
    for (int i = 0; i < N; i++) pthread_create(&t[i], 0, work, 0);
    while (__atomic_load_n(&done_count, __ATOMIC_SEQ_CST) < N) { /* user-space spin */ }
    return 0;
}
"#;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mirrorscope-mt-replay-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Compile the pthreads target, or `None` if no C compiler is available.
fn compile_target(dir: &Path) -> Option<PathBuf> {
    compile_source(dir, SOURCE, "mt.c", "mt")
}

/// Compile the `clear_watch` regression fixture, or `None` if no C compiler is
/// available.
fn compile_watch_target(dir: &Path) -> Option<PathBuf> {
    compile_source(dir, WATCH_SOURCE, "mt_watch.c", "mt_watch")
}

/// Write `source` to `dir/src_name` and compile it into `dir/bin_name`.
fn compile_source(dir: &Path, source: &str, src_name: &str, bin_name: &str) -> Option<PathBuf> {
    let src = dir.join(src_name);
    fs::write(&src, source).expect("write C source");
    let bin = dir.join(bin_name);
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let ok = Command::new(&cc)
        .arg("-O0")
        .arg("-pthread")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(bin)
}

/// The `CHUNK`-byte region every thread `id` should observe: `CHUNK` copies of a
/// per-thread marker byte, distinct across threads so a mis-routed injection is
/// detectable.
fn expected_region(id: usize) -> Vec<u8> {
    vec![0xA0 + id as u8; CHUNK]
}

/// Build the data file whose region `i` is filled with marker byte `0xA0 + i`.
fn write_data_file(path: &Path) {
    let mut bytes = Vec::with_capacity(THREADS * CHUNK);
    for id in 0..THREADS {
        bytes.extend_from_slice(&expected_region(id));
    }
    fs::write(path, &bytes).expect("write data file");
}

fn read_records(trace_path: &Path) -> (recorder::trace::Cmdline, Vec<Record>) {
    let file = fs::File::open(trace_path).expect("open trace");
    let reader = TraceReader::open(BufReader::new(file)).expect("valid header");
    let cmdline = reader.cmdline().cloned().expect("trace embeds a cmdline");
    let records = reader.map(|r| r.expect("intact record")).collect();
    (cmdline, records)
}

#[test]
fn replays_multithreaded_read_results_per_thread_without_divergence() {
    let dir = temp_dir("inject");
    let Some(bin) = compile_target(&dir) else {
        eprintln!("skipping: no C compiler available to build the pthreads target");
        fs::remove_dir_all(&dir).ok();
        return;
    };

    let data = dir.join("data.bin");
    write_data_file(&data);
    let outdir = dir.join("out");
    fs::create_dir_all(&outdir).expect("create outdir");

    let trace_path = dir.join("mt.mscope");
    let args = vec![
        data.to_str().expect("utf-8").to_owned(),
        outdir.to_str().expect("utf-8").to_owned(),
    ];
    let outcome = record_command(bin.to_str().expect("utf-8"), &args, &trace_path).expect("record");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "recorded target must exit cleanly"
    );
    assert!(
        outcome.threads_followed >= THREADS as u64 + 1,
        "must follow main + {THREADS} workers, got {}",
        outcome.threads_followed
    );
    // Sanity: the recording itself observed each thread's distinct region.
    for id in 0..THREADS {
        let got = fs::read(outdir.join(format!("thread_{id}.out"))).expect("record output");
        assert_eq!(got, expected_region(id), "recording thread {id} region");
    }

    // Corrupt the data file: same length, all 0xFF. If replay re-read the live
    // filesystem instead of injecting from the trace, outputs would be 0xFF.
    fs::write(&data, vec![0xFF; THREADS * CHUNK]).expect("overwrite data file");

    // On divergence the tracee is left ptrace-stopped, so draining its piped
    // output would block; report the error directly instead.
    let mut session = ReplaySession::launch(&trace_path).expect("launch replay");
    let exit = session
        .run_to_end()
        .unwrap_or_else(|err| panic!("multi-threaded replay must not diverge: {err:?}"));
    assert_eq!(exit, ExitOutcome::Exited(0), "replayed target must exit 0");

    for id in 0..THREADS {
        let got = fs::read(outdir.join(format!("thread_{id}.out"))).expect("replay output");
        assert_eq!(
            got,
            expected_region(id),
            "thread {id} must replay its ORIGINAL region (injected from the trace, \
             per-tid), not the 0xFF now on disk"
        );
    }
    // Regions are genuinely distinct across threads (else the test is vacuous).
    assert_ne!(expected_region(0), expected_region(1));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn surfaces_schedule_divergence_when_a_record_is_retagged_to_the_wrong_thread() {
    let dir = temp_dir("diverge");
    let Some(bin) = compile_target(&dir) else {
        eprintln!("skipping: no C compiler available to build the pthreads target");
        fs::remove_dir_all(&dir).ok();
        return;
    };

    let data = dir.join("data.bin");
    write_data_file(&data);
    let outdir = dir.join("out");
    fs::create_dir_all(&outdir).expect("create outdir");
    let trace_path = dir.join("mt.mscope");
    let args = vec![
        data.to_str().expect("utf-8").to_owned(),
        outdir.to_str().expect("utf-8").to_owned(),
    ];
    record_command(bin.to_str().expect("utf-8"), &args, &trace_path).expect("record");

    let (cmdline, records) = read_records(&trace_path);
    // Re-tag the SECOND tid-bearing syscall record to the wrong thread. The
    // first concrete record seeds the leader binding, so tampering a later one
    // forces the enforced expected-tid to disagree — a real schedule reorder.
    let mut writer = TraceWriter::create_with_cmdline(Vec::new(), &cmdline.program, &cmdline.args)
        .expect("writer");
    let mut concrete_seen = 0usize;
    let mut tampered = false;
    for record in &records {
        let mut event = record.event.clone();
        let is_syscall = matches!(event.kind, EventKind::SyscallEnter | EventKind::SyscallExit);
        if is_syscall {
            if let Some(tid) = event.tid {
                concrete_seen += 1;
                if concrete_seen == 2 {
                    event = Event::new_with_tid(
                        event.kind,
                        event.timestamp_ns,
                        tid.wrapping_add(1),
                        event.payload,
                    );
                    tampered = true;
                }
            }
        }
        writer.append(&event).expect("append");
    }
    assert!(
        tampered,
        "trace must contain at least two tid-tagged syscalls"
    );
    let tampered_path = dir.join("tampered.mscope");
    fs::write(&tampered_path, writer.into_inner()).expect("write tampered trace");

    let mut session = ReplaySession::launch(&tampered_path).expect("launch replay");
    let result = session.run_to_end();
    assert!(
        matches!(result, Err(ReplayError::ScheduleDiverged { .. })),
        "a record re-tagged to the wrong thread must surface as ScheduleDiverged, got {result:?}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn single_threaded_trace_still_replays_through_the_unchanged_path() {
    let dir = temp_dir("single");
    let data = dir.join("data.txt");
    let original: &[u8] = b"mirrorscope-single-threaded-replay\n";
    fs::write(&data, original).expect("write data");

    let trace_path = dir.join("head.mscope");
    let arg = data.to_str().expect("utf-8").to_owned();
    record_command(
        "head",
        &["-c".to_owned(), "4096".to_owned(), arg],
        &trace_path,
    )
    .expect("record");

    // Corrupt the file: injection must feed the original bytes, not these.
    fs::write(&data, vec![b'Z'; original.len()]).expect("overwrite");

    let mut session = ReplaySession::launch(&trace_path).expect("launch replay");
    assert_eq!(
        session.run_to_end().expect("replay"),
        ExitOutcome::Exited(0)
    );
    assert_eq!(
        session.read_stdout().expect("stdout"),
        original,
        "single-threaded replay must inject the original bytes as before"
    );

    fs::remove_dir_all(&dir).ok();
}

/// Regression for the `clear_watch` fix (H1): debug registers are per-thread,
/// so `clear_watch` must disarm every live thread symmetrically with `watch`'s
/// arming, not just the leader `self.pid`. Before the fix, a sibling thread's
/// hardware watchpoint stayed armed after `clear_watch`; once
/// `self.watchpoint` is `None` the later stale `SIGTRAP` it raises on its
/// (still-armed) write is no longer recognized by `is_watch_hit` and gets
/// misreported as an ordinary diverging stop.
///
/// Drives replay to the point where both `WATCH_SOURCE` workers have spawned
/// (so `on_thread_spawn` has armed the watchpoint on each of them too) but
/// neither has yet written the watched global, clears the watch there, then
/// lets both workers perform their writes. A pre-fix build fails this test
/// with `ScheduleDiverged` from the sibling's leaked watchpoint trap; the
/// fixed build replays to a clean exit.
#[test]
fn clear_watch_disarms_every_live_thread_not_just_the_leader() {
    let dir = temp_dir("clear-watch");
    let Some(bin) = compile_watch_target(&dir) else {
        eprintln!("skipping: no C compiler available to build the pthreads target");
        fs::remove_dir_all(&dir).ok();
        return;
    };

    let trace_path = dir.join("mtwatch.mscope");
    let outcome = record_command(bin.to_str().expect("utf-8"), &[], &trace_path).expect("record");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "recorded fixture must exit cleanly"
    );

    // Probe replay to learn the watched global's address (stable across runs:
    // both recorder and replay pin the layout with ADDR_NO_RANDOMIZE).
    let mut probe = ReplaySession::launch(&trace_path).expect("launch probe replay");
    probe.run_to_end().expect("probe replay to completion");
    let stdout = probe.read_stdout().expect("read probe stdout");
    let addr: u64 = String::from_utf8(stdout)
        .expect("fixture prints utf-8")
        .trim()
        .parse()
        .expect("fixture prints the watched address as a decimal u64");
    assert_ne!(addr, 0, "the watched global must have a real address");

    // The seq of the last ThreadSpawn record: the earliest point at which both
    // workers are live and (once watched) armed by `on_thread_spawn`.
    let (_cmdline, records) = read_records(&trace_path);
    let last_spawn_seq = records
        .iter()
        .filter(|record| record.event.kind == EventKind::ThreadSpawn)
        .map(|record| record.seq)
        .max()
        .expect("fixture must spawn at least one worker thread");

    let mut session = ReplaySession::launch(&trace_path).expect("launch replay");
    // Arm before any thread has spawned: only the leader is live yet, so this
    // exercises `on_thread_spawn`'s re-arming of each worker as it appears.
    session
        .watch(addr, 4, WatchKind::Write)
        .expect("arm watch on the leader before any worker spawns");
    session
        .step_to(last_spawn_seq)
        .expect("drive past both worker spawns");
    session
        .clear_watch()
        .expect("disarm the watchpoint on every live thread");

    let exit = session.run_to_end().unwrap_or_else(|err| {
        panic!(
            "replay must not diverge after clear_watch: a sibling's stale watchpoint \
             would fire on its counter write and be misreported as a schedule \
             divergence, got {err:?}"
        )
    });
    assert_eq!(
        exit,
        ExitOutcome::Exited(0),
        "replay must reach a clean exit once every live thread's watchpoint is disarmed"
    );

    fs::remove_dir_all(&dir).ok();
}
