//! Linux-only integration test for issue #8 groundwork: unwind and symbolize
//! an *external* process's stack through [`RemoteUnwinder`].
//!
//! The parent spawns this very test binary a second time (`current_exe()`)
//! under `PTRACE_TRACEME`, filtered to run only the `spinner_child` test,
//! which drives a `depth_one -> depth_two -> depth_three -> raise(SIGSTOP)`
//! call chain and stops itself. The parent resumes it past the initial
//! execve trap, waits for that self-inflicted `SIGSTOP`, then reads its
//! registers via `PTRACE_GETREGS(ET)` and unwinds its stack via
//! `process_vm_readv`, mirroring exactly how replay will later drive a DAP
//! `stackTrace` request. This exercises the real remote path end to end,
//! independent of `tests/self_unwind.rs`'s in-process path.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use unwind::RemoteUnwinder;

/// Env var the parent sets so the re-exec'd child knows to run the spinner
/// chain instead of behaving like a normal `cargo test` invocation.
const CHILD_ENV: &str = "MIRRORSCOPE_REMOTE_UNWIND_CHILD";

#[inline(never)]
#[allow(unsafe_code)]
fn stop_here() {
    // SAFETY: raise() with a valid, real-time-unrelated signal number is
    // async-signal-safe and only affects the calling process; no memory is
    // touched here.
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
}

#[inline(never)]
fn depth_three() {
    stop_here();
}

#[inline(never)]
fn depth_two() {
    depth_three();
}

#[inline(never)]
fn depth_one() {
    depth_two();
}

/// Entry point for the re-exec'd child process. A no-op under a normal
/// `cargo test` run (the env var is unset); only does anything when spawned
/// by [`unwinds_and_symbolizes_a_remote_stopped_process`] below.
#[test]
fn spinner_child() {
    if std::env::var_os(CHILD_ENV).is_some() {
        depth_one();
        // Only reached if the parent resumes us past the SIGSTOP instead of
        // killing us; exit cleanly rather than falling into the rest of the
        // test harness.
        std::process::exit(0);
    }
}

/// Index of the first frame whose function name contains `needle`.
fn find(names: &[String], needle: &str) -> Option<usize> {
    names.iter().position(|name| name.contains(needle))
}

#[test]
#[allow(unsafe_code)]
fn unwinds_and_symbolizes_a_remote_stopped_process() {
    let exe = std::env::current_exe().expect("current test exe");

    let mut command = Command::new(&exe);
    command
        .args(["spinner_child", "--exact"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: pre_exec runs post-fork/pre-exec in the child; personality()
    // and traceme() are async-signal-safe single syscalls. Mirrors
    // recorder's spawn_traced: ADDR_NO_RANDOMIZE pins the layout, matching
    // how recorder/replay run real targets, though RemoteUnwinder does not
    // depend on this — it always reads load bases from /proc/<pid>/maps.
    unsafe {
        command.pre_exec(|| {
            if libc::personality(libc::ADDR_NO_RANDOMIZE as _) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            ptrace::traceme().map_err(std::io::Error::from)
        });
    }

    let child = command.spawn().expect("spawn traced spinner child");
    let pid = Pid::from_raw(child.id() as i32);

    // First stop: the SIGTRAP from execve under TRACEME.
    waitpid(pid, None).expect("wait for execve stop");
    ptrace::cont(pid, None).expect("resume child into the spinner chain");

    // Second stop: the child's own SIGSTOP at the bottom of depth_three.
    match waitpid(pid, None).expect("wait for spinner SIGSTOP") {
        WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
        other => {
            let _ = ptrace::kill(pid);
            panic!("expected the spinner to stop itself with SIGSTOP, got {other:?}");
        }
    }

    let result = (|| {
        let mut unwinder = RemoteUnwinder::for_pid(pid.as_raw())?;
        let regs = unwinder.registers()?;
        unwinder.backtrace(&regs)
    })();

    let _ = ptrace::kill(pid);
    let _ = waitpid(pid, None);

    let frames = result.expect("unwind remote stack");
    let names: Vec<String> = frames
        .iter()
        .filter_map(|frame| frame.function.clone())
        .collect();
    let joined = names.join("\n");

    let i3 = find(&names, "depth_three");
    let i2 = find(&names, "depth_two");
    let i1 = find(&names, "depth_one");
    assert!(
        matches!((i3, i2, i1), (Some(a), Some(b), Some(c)) if a < b && b < c),
        "expected depth_three < depth_two < depth_one in remote frame order; got:\n{joined}"
    );
}
