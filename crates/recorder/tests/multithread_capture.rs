//! Linux-only integration test for multi-threaded ptrace capture (issue #9).
//!
//! Records a pthreads target and asserts the recorder (a) followed every
//! thread, (b) tagged syscall events with their originating tid, (c) recorded
//! the single-core schedule (`SchedSwitch` + `ThreadSpawn` + `ThreadExit`),
//! and (d) produced a CRC-valid, fully readable v3 trace.
//!
//! The target is compiled with the system C compiler at test time (mirroring
//! how `ptrace_capture.rs` builds its shell targets); the test skips cleanly if
//! no C compiler is available.
#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use recorder::capture::payload::{SchedSwitch, ThreadSpawn};
use recorder::capture::record_command;
use recorder::trace::{EventKind, TraceReader};

const THREAD_COUNT: usize = 4;

const SOURCE: &str = r#"
#include <pthread.h>
#include <unistd.h>
#include <time.h>

static void* work(void* arg) {
    (void)arg;
    struct timespec ts = {0, 1000000};
    for (int i = 0; i < 3; i++) {
        (void)getpid();          /* a reliable per-thread syscall */
        nanosleep(&ts, 0);        /* yields, encouraging interleaving */
    }
    return 0;
}

int main(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, work, 0);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    return 0;
}
"#;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mirrorscope-mt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Compile the pthreads target, returning its path or `None` if no C compiler
/// is available on this host.
fn compile_target(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("mt.c");
    std::fs::write(&src, SOURCE).expect("write C source");
    let bin = dir.join("mt");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let status = Command::new(&cc)
        .arg("-O0")
        .arg("-pthread")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status();
    match status {
        Ok(s) if s.success() => Some(bin),
        _ => None,
    }
}

#[test]
fn follows_all_threads_and_records_the_single_core_schedule() {
    let dir = temp_dir();
    let Some(bin) = compile_target(&dir) else {
        eprintln!("skipping: no C compiler available to build the pthreads target");
        std::fs::remove_dir_all(&dir).ok();
        return;
    };

    let trace_path = dir.join("mt.mscope");
    let outcome = record_command(bin.to_str().expect("utf-8 path"), &[], &trace_path)
        .expect("recording must succeed");
    assert_eq!(outcome.exit_code, Some(0), "target must exit cleanly");
    assert!(
        outcome.threads_followed >= (THREAD_COUNT as u64 + 1),
        "must follow the main thread plus {THREAD_COUNT} workers, got {}",
        outcome.threads_followed
    );

    let file = std::fs::File::open(&trace_path).expect("open trace");
    let reader = TraceReader::open(std::io::BufReader::new(file)).expect("valid trace header");
    assert_eq!(reader.version(), 3, "multi-threaded capture writes v3");

    let mut syscall_tids = BTreeSet::new();
    let mut spawn_children = BTreeSet::new();
    let mut sched_switches = 0u64;
    let mut thread_exits = 0u64;
    let mut untagged_syscalls = 0u64;

    for record in reader {
        let record = record.expect("every record intact (checksum + monotonic seq)");
        match record.event.kind {
            EventKind::SyscallEnter | EventKind::SyscallExit => match record.event.tid {
                Some(tid) => {
                    syscall_tids.insert(tid);
                }
                None => untagged_syscalls += 1,
            },
            EventKind::SchedSwitch => {
                let sw = SchedSwitch::decode(&record.event.payload).expect("decode SchedSwitch");
                assert_eq!(
                    record.event.tid,
                    Some(sw.tid),
                    "SchedSwitch body tid must match its payload tid"
                );
                sched_switches += 1;
            }
            EventKind::ThreadSpawn => {
                let sp = ThreadSpawn::decode(&record.event.payload).expect("decode ThreadSpawn");
                spawn_children.insert(sp.child_tid);
            }
            EventKind::ThreadExit => thread_exits += 1,
            _ => {}
        }
    }

    assert_eq!(untagged_syscalls, 0, "every syscall event must carry a tid");
    assert!(
        syscall_tids.len() >= 2,
        "syscalls from at least two distinct threads must be recorded, got {syscall_tids:?}"
    );
    assert!(
        spawn_children.len() >= THREAD_COUNT,
        "each of the {THREAD_COUNT} worker threads must produce a ThreadSpawn, got {}",
        spawn_children.len()
    );
    assert!(
        sched_switches >= 2,
        "the single-core schedule must record thread switches, got {sched_switches}"
    );
    assert!(
        thread_exits >= THREAD_COUNT as u64,
        "each worker thread must produce a ThreadExit, got {thread_exits}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
