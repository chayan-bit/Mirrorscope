//! Linux-only integration test for issue #8 groundwork: unwind and symbolize
//! an *external* process's stack through [`RemoteUnwinder`].
//!
//! The parent spawns this very test binary a second time (`current_exe()`)
//! under `PTRACE_TRACEME`, which drives a `depth_one -> depth_two ->
//! depth_three -> raise(SIGSTOP)` call chain and stops itself. The parent
//! resumes it past the initial execve trap, waits for that self-inflicted
//! `SIGSTOP`, then reads its registers via `PTRACE_GETREGS(ET)` and unwinds
//! its stack via `process_vm_readv`, mirroring exactly how replay will later
//! drive a DAP `stackTrace` request. This exercises the real remote path end
//! to end, independent of `tests/self_unwind.rs`'s in-process path.
//!
//! This target runs with `harness = false` (see `Cargo.toml`): the standard
//! libtest harness always executes each `#[test]` fn on a spawned worker
//! thread, even with a single test and `RUST_TEST_THREADS=1`. `PTRACE_TRACEME`
//! only traces the thread that calls it — the re-exec'd process's actual main
//! thread, pre-`main` — so a worker-thread `raise(SIGSTOP)` would stop the
//! process (a group-stop) while the parent's `PTRACE_GETREGS` still reads the
//! *traced* main thread, which is parked waiting on the worker rather than
//! sitting in `depth_three`. Running as a plain `fn main()` guarantees the
//! spinner chain executes on the one thread that was actually traced.
//!
//! `harness = false` means this file must supply `fn main()` unconditionally
//! (rustc's synthesized test-harness main is only generated in `harness =
//! true` mode), so the Linux-only body lives in [`linux`] and `main` below is
//! a no-op stub on other platforms — mirroring what the default harness would
//! have done with zero (cfg'd-out) tests.

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;

    use unwind::RemoteUnwinder;

    /// Env var the parent sets so the re-exec'd child knows to run the
    /// spinner chain instead of behaving like a normal invocation.
    const CHILD_ENV: &str = "MIRRORSCOPE_REMOTE_UNWIND_CHILD";

    #[inline(never)]
    #[allow(unsafe_code)]
    fn stop_here() {
        // SAFETY: raise() with a valid, real-time-unrelated signal number is
        // async-signal-safe and only affects the calling process; no memory
        // is touched here.
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

    /// Index of the first frame whose function name contains `needle`.
    fn find(names: &[String], needle: &str) -> Option<usize> {
        names.iter().position(|name| name.contains(needle))
    }

    #[allow(unsafe_code)]
    fn unwinds_and_symbolizes_a_remote_stopped_process() {
        let exe = std::env::current_exe().expect("current test exe");

        let mut command = Command::new(&exe);
        command
            .env(CHILD_ENV, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: pre_exec runs post-fork/pre-exec in the child; personality()
        // and traceme() are async-signal-safe single syscalls. Mirrors
        // recorder's spawn_traced: ADDR_NO_RANDOMIZE pins the layout, matching
        // how recorder/replay run real targets, though RemoteUnwinder does not
        // depend on this — it always reads load bases from /proc/<pid>/maps.
        // personality() is therefore best-effort: some sandboxes (e.g.
        // Docker's default seccomp profile only allow-lists a handful of
        // personality values and rejects ADDR_NO_RANDOMIZE with EPERM) block
        // it even though the caller has no elevated privileges and isn't
        // doing anything unsafe. Failing the whole spawn over a cosmetic
        // ASLR-pinning call would be testing the sandbox's seccomp policy,
        // not this crate's unwinder, so a rejection here is ignored and the
        // child simply keeps ASLR enabled.
        unsafe {
            command.pre_exec(|| {
                let _ = libc::personality(libc::ADDR_NO_RANDOMIZE as _);
                ptrace::traceme().map_err(std::io::Error::from)
            });
        }

        let mut child = command.spawn().expect("spawn traced spinner child");
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

        // Written without `?` (rather than a closure using it) so there is no
        // early-return path between `spawn()` and the unconditional
        // `child.wait()` below for clippy's `zombie_processes` lint to flag.
        let result = match RemoteUnwinder::for_pid(pid.as_raw()) {
            Ok(mut unwinder) => match unwinder.registers() {
                Ok(regs) => unwinder.backtrace(&regs),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };

        // Reap through the `Child` handle (not another raw `waitpid`) so the
        // kernel process table entry is collected via the API clippy's
        // `zombie_processes` lint can see, rather than only via the pid
        // ptrace was tracking — avoids leaving `child` a zombie until this
        // test binary itself exits.
        let _ = ptrace::kill(pid);
        let _ = child.wait();

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

    /// Dispatches to the spinner chain when re-exec'd as the traced child,
    /// otherwise runs the one integration test directly on this process's
    /// actual main thread.
    pub fn main() {
        if std::env::var_os(CHILD_ENV).is_some() {
            depth_one();
            // Only reached if the parent resumes us past the SIGSTOP instead
            // of killing us; exit cleanly rather than falling off the end.
            std::process::exit(0);
        }

        unwinds_and_symbolizes_a_remote_stopped_process();
        println!("test unwinds_and_symbolizes_a_remote_stopped_process ... ok");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
}
