//! Multi-threaded syscall capture via ptrace (issues #4, #9).
//!
//! Spawns the target with `PTRACE_TRACEME`, follows every thread and forked
//! process it creates ([`PTRACE_O_TRACECLONE`]/`FORK`/`VFORK`), and drives the
//! whole set under **single-core serialization** — one thread runs at a time,
//! pinned to one CPU, its interleaving recorded so replay (issue #6) can
//! reproduce it. Syscall entries record the number + raw arguments; exits
//! record the return value plus any kernel-written input data pulled out of the
//! tracee with `process_vm_readv`. See [`super::sched`] for the scheduling
//! model and its honest determinism caveats.
//!
//! [`PTRACE_O_TRACECLONE`]: nix::sys::ptrace::Options::PTRACE_O_TRACECLONE

use std::fs::File;
use std::io::BufWriter;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

use crate::capture::error::{CaptureError, RecordOutcome};
use crate::capture::sched::{trace_options, Scheduler};
use crate::trace::{TraceError, TraceWriter};

/// Record `program args…` into a trace file at `trace_path`.
///
/// Follows all threads/processes the target spawns and records the single-core
/// schedule alongside the syscall stream.
pub fn record_command(
    program: &str,
    args: &[String],
    trace_path: &Path,
) -> Result<RecordOutcome, CaptureError> {
    let file = File::create(trace_path).map_err(TraceError::Io)?;
    let mut writer = TraceWriter::create_with_cmdline(BufWriter::new(file), program, args)?;

    let child = spawn_traced(program, args)?;
    let leader = Pid::from_raw(child.id() as i32);

    // First stop: the SIGTRAP from execve under TRACEME.
    waitpid(leader, None)?;
    ptrace::setoptions(leader, trace_options())?;

    let scheduler = Scheduler::new(&mut writer, leader)?;
    scheduler.run()
}

/// Spawn the target with `PTRACE_TRACEME` set in the child.
fn spawn_traced(program: &str, args: &[String]) -> Result<std::process::Child, CaptureError> {
    let mut command = Command::new(program);
    command.args(args);
    // SAFETY: pre_exec runs post-fork/pre-exec in the child; personality() and
    // traceme() are async-signal-safe (single syscalls) and touch no locks.
    // ADDR_NO_RANDOMIZE pins the address-space layout so record and replay match
    // (checksum divergence detection #11 and retroactive watchpoints #12).
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(|| {
            if libc::personality(libc::ADDR_NO_RANDOMIZE as _) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            ptrace::traceme().map_err(std::io::Error::from)
        });
    }
    command.spawn().map_err(CaptureError::Spawn)
}
