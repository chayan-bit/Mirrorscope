//! Linux-only integration test: exercises [`PtraceProcessView`] and
//! [`NativeThreadsDecoder`] together against a *real*, multi-threaded,
//! ptrace-stopped external process.
//!
//! Mirrors `crates/unwind/tests/remote_unwind.rs`'s re-exec trick (the
//! parent spawns this very test binary a second time, filtered to run only
//! `threaded_child`), but attaches every thread individually rather than
//! relying on `PTRACE_TRACEME`: `PTRACE_TRACEME` only traces the thread
//! that calls it, and the point of this test is enumerating *all* threads
//! of a multi-threaded target the way a real debugger attach would.

#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use decoder::model::TaskKind;
use decoder::process_view::ThreadId;
use decoder::{NativeThreadsDecoder, PtraceProcessView, SemanticDecoder};

/// Env var the parent sets so the re-exec'd child knows to run the
/// multi-thread workload instead of behaving like a normal `cargo test`
/// invocation.
const CHILD_ENV: &str = "MIRRORSCOPE_PTRACE_VIEW_CHILD";

/// How many worker threads `threaded_child` spawns, in addition to main.
const WORKER_COUNT: usize = 2;

/// Entry point for the re-exec'd child process. A no-op under a normal
/// `cargo test` run (the env var is unset); only spawns worker threads and
/// sleeps when driven by [`decodes_a_real_multi_threaded_process`] below.
#[test]
fn threaded_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }

    let workers: Vec<_> = (0..WORKER_COUNT)
        .map(|_| std::thread::spawn(|| std::thread::sleep(Duration::from_secs(5))))
        .collect();
    std::thread::sleep(Duration::from_secs(5));
    for worker in workers {
        let _ = worker.join();
    }
    std::process::exit(0);
}

/// Poll `/proc/<pid>/task` until it lists at least `expected` threads or
/// `timeout` elapses, so the parent does not race the child's thread spawns.
fn wait_for_thread_count(pid: i32, expected: usize, timeout: Duration) -> Vec<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            let tids: Vec<i32> = entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().to_str().and_then(|s| s.parse().ok()))
                .collect();
            if tids.len() >= expected || Instant::now() >= deadline {
                return tids;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `PTRACE_ATTACH` one thread and wait for the resulting stop.
fn attach_thread(tid: i32) -> bool {
    let pid = Pid::from_raw(tid);
    if ptrace::attach(pid).is_err() {
        return false;
    }
    matches!(waitpid(pid, None), Ok(WaitStatus::Stopped(_, _)))
}

/// Detach every attached thread and reap the child, best-effort — this runs
/// after the assertions, so failures here must not mask a real test result.
fn cleanup(child: &mut Child, attached: &[i32]) {
    for tid in attached {
        let _ = ptrace::detach(Pid::from_raw(*tid), None);
    }
    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
    let _ = child.wait();
}

#[test]
fn decodes_a_real_multi_threaded_process() {
    let exe = std::env::current_exe().expect("current test exe");

    let mut command = Command::new(&exe);
    command
        .args(["threaded_child", "--exact", "--nocapture"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = command.spawn().expect("spawn multi-threaded child");
    let pid = child.id() as i32;

    let expected_threads = WORKER_COUNT + 1;
    let tids = wait_for_thread_count(pid, expected_threads, Duration::from_secs(3));
    assert!(
        tids.len() >= expected_threads,
        "expected >= {expected_threads} threads, /proc/{pid}/task listed: {tids:?}"
    );

    let attached: Vec<i32> = tids.into_iter().filter(|tid| attach_thread(*tid)).collect();
    assert!(
        attached.len() >= expected_threads,
        "expected to attach >= {expected_threads} threads, attached: {attached:?}"
    );

    // Deliberately no `?`/early-return here: every fallible step below must
    // run `cleanup` (which reaps `child`) before propagating a failure, and
    // a closure with `?` would let clippy's `zombie_processes` lint (rightly)
    // flag a path that can exit without waiting on the spawned child.
    let view = match PtraceProcessView::for_pid(pid) {
        Ok(view) => view,
        Err(err) => {
            cleanup(&mut child, &attached);
            panic!("build ptrace process view: {err}");
        }
    };
    let decoder = NativeThreadsDecoder::new();
    let tree = match decoder.decode_tasks(&view) {
        Ok(tree) => tree,
        Err(err) => {
            cleanup(&mut child, &attached);
            panic!("decode tasks from real process: {err}");
        }
    };

    assert!(
        tree.len() >= expected_threads,
        "expected >= {expected_threads} tasks, got {}",
        tree.len()
    );

    for &task in tree.flatten_preorder().iter() {
        let node = tree.node(task).expect("node exists for its own id");
        assert_eq!(node.kind, TaskKind::Thread);
        assert!(
            node.name.starts_with("thread "),
            "unexpected task name: {}",
            node.name
        );

        let thread = ThreadId::new(task.raw());
        let name = view.thread_name(thread);
        assert!(
            name.is_some_and(|n| !n.is_empty()),
            "expected a non-empty /proc comm name for thread {thread:?}, got {name:?}"
        );
    }

    cleanup(&mut child, &attached);
}
