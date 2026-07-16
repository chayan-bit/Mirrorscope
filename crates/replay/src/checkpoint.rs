//! Fork-snapshot checkpoints for the replay engine (issue #5).
//!
//! # Why fork snapshots (and the Phase-1 trade-off)
//!
//! README §8 puts fork checkpointing in Phase 1 and defers CRIU/`userfaultfd`
//! incremental snapshots to later. A fork snapshot is the cheapest correct way
//! to freeze a single-process tracee: injecting a `clone(SIGCHLD)` into the
//! ptrace-stopped tracee makes the kernel create a **copy-on-write** duplicate
//! of its entire address space, which we hold stopped as an immutable image.
//! This is exactly rr's `Task::os_fork_into` technique, minus the multi-task
//! bookkeeping — sound here because the recorder is single-threaded-tracee only.
//!
//! Restore never runs a snapshot directly: it forks *again* from the pristine
//! snapshot, so one checkpoint can seed unlimited restores (repeated
//! reverse-execution) while the original image stays untouched.
//!
//! Trade-offs vs CRIU, stated up front:
//! - snapshots live only in memory (child processes) — nothing is persisted, so
//!   they vanish with the session; that is acceptable for interactive replay.
//! - open-fd / socket / mmap edge cases CRIU handles are out of scope here; a
//!   fork inherits the tracee's fd table, which is enough for the Phase-1
//!   compute-bound targets we replay.
//! - a failure (missing fork event, unexpected stop) is surfaced as
//!   [`ReplayError::Checkpoint`], never silently swallowed — replay honesty.
//!
//! The **selection** arithmetic (which snapshot restores for a target seq) is
//! portable and lives, unit-tested, in [`crate::checkpoint_select`].

use nix::sys::ptrace::{self, Event};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::error::ReplayError;
use crate::regs::{self, Registers};

/// The ptrace options every tracee and every fork snapshot runs under.
///
/// `TRACEFORK | TRACEVFORK | TRACECLONE` make the kernel auto-attach and stop
/// the child of an injected `clone`, so we learn its pid via `PTRACE_EVENT_*`
/// and hold it without a race; `EXITKILL` guarantees no orphaned snapshots
/// survive the tracer; `TRACESYSGOOD` keeps syscall-stops distinguishable.
pub(crate) fn setup_options(pid: Pid) -> Result<(), ReplayError> {
    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACECLONE,
    )?;
    Ok(())
}

/// An immutable fork snapshot plus the replay-cursor bookkeeping needed to
/// resume deterministic re-execution from it.
///
/// The public surface is intentionally just `seq`: clients (DAP `listCheckpoints`)
/// only ever need to know *where* a checkpoint sits. The cursor/register fields
/// are how the engine re-seats itself and are crate-private.
#[derive(Debug, Clone)]
pub struct CheckpointInfo {
    /// Trace sequence number of the boundary this snapshot was taken at.
    pub seq: u64,
    /// Index into the session's record vector to resume consuming from.
    pub(crate) cursor: usize,
    /// The `current_seq` the session should report after restoring here.
    pub(crate) current_seq: Option<u64>,
    /// Normalized syscall registers observed at the snapshot boundary.
    pub(crate) last_regs: Option<Registers>,
    /// The held-stopped copy-on-write child that backs this checkpoint.
    pub(crate) snapshot: Pid,
}

/// Fork `pid` (which must be ptrace-stopped at a clean syscall boundary),
/// returning a fresh held-stopped copy-on-write child. `pid` itself is left
/// byte-for-byte as it was found — registers restored, PC untouched — so the
/// caller's replay is undisturbed.
///
/// The child is returned still stopped with the *same* boundary registers, so
/// it is itself a valid source for a future `fork_snapshot` (that is how one
/// checkpoint seeds many restores).
pub(crate) fn fork_snapshot(pid: Pid) -> Result<Pid, ReplayError> {
    let saved = regs::save_full(pid)?;
    let mut injected = saved;
    regs::prepare_fork(&mut injected);
    regs::restore_full(pid, &injected)?;

    // Single-step the rewound `syscall`/`svc` instruction, now dispatching the
    // injected clone. With TRACE{FORK,CLONE} set the child auto-attaches; the
    // parent reports a fork-family event carrying the child's pid.
    ptrace::step(pid, None)?;
    let child = wait_for_fork_child(pid)?;

    // Reap the child's initial auto-attach stop and leave it held stopped.
    match waitpid(child, None)? {
        WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _) => {}
        _ => {
            return Err(ReplayError::Checkpoint {
                seq: None,
                reason: "fork snapshot child did not stop as expected",
            })
        }
    }

    setup_options(child)?;
    // Restore the parent exactly, and seat the child at the same boundary.
    regs::restore_full(pid, &saved)?;
    regs::restore_full(child, &saved)?;
    Ok(child)
}

/// Await the parent's stop after an injected clone and extract the child pid
/// from the `PTRACE_EVENT_{FORK,VFORK,CLONE}` message.
fn wait_for_fork_child(pid: Pid) -> Result<Pid, ReplayError> {
    match waitpid(pid, None)? {
        WaitStatus::PtraceEvent(_, _, event) if is_fork_event(event) => {
            let raw = ptrace::getevent(pid)?;
            Ok(Pid::from_raw(raw as libc::pid_t))
        }
        _ => Err(ReplayError::Checkpoint {
            seq: None,
            reason: "expected a fork event after the injected clone syscall",
        }),
    }
}

/// Whether a raw `PTRACE_EVENT_*` code is one of the fork-family events an
/// injected `clone(SIGCHLD)` may surface as, depending on kernel version.
fn is_fork_event(event: libc::c_int) -> bool {
    event == Event::PTRACE_EVENT_FORK as libc::c_int
        || event == Event::PTRACE_EVENT_VFORK as libc::c_int
        || event == Event::PTRACE_EVENT_CLONE as libc::c_int
}
