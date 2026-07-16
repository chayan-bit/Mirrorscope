//! Multi-threaded replay with recorded-schedule enforcement (issue #10).
//!
//! This is the replay-side counterpart of the recorder's single-core
//! serialization scheduler ([`recorder::capture::sched`]). Where the recorder
//! ran one thread at a time and wrote a **total order** over instrumented points
//! ([`EventKind::SchedSwitch`] / [`EventKind::ThreadSpawn`] /
//! [`EventKind::ThreadExit`] plus per-tid syscall records), replay walks that
//! order and forces the live tracee set to reproduce it exactly:
//!
//! - **Thread tracking.** The leader is followed with `PTRACE_O_TRACECLONE`
//!   /`FORK`/`VFORK`/`EXEC`; every clone/fork/vfork is caught as a
//!   `PTRACE_EVENT_*`, its child reaped and registered, mirroring the recorder's
//!   `on_spawn`/`register_child`. A followed `exec` (which the recorder records
//!   nothing for) surfaces as `PTRACE_EVENT_EXEC` and is transparently swallowed.
//! - **tid remapping.** Replay tids always differ from the recording, so the
//!   Nth recorded [`ThreadSpawn`] binds the Nth live clone in [`TidMap`]; every
//!   thread-attributed record is routed through it (see [`crate::schedule`]).
//! - **Enforcement.** [`EventKind::SchedSwitch`] is load-bearing: it sets which
//!   recorded tid may run next, and every following concrete record must be
//!   tagged that tid or replay stops with [`ReplayError::ScheduleDiverged`].
//!   Only the one directed thread is ever resumed; all others stay ptrace-stopped
//!   at their last boundary, so the recorded interleaving holds by construction.
//! - **Per-tid injection.** Each thread carries its own pending-syscall slot, so
//!   read/getrandom/clock_gettime results are injected into the right live thread
//!   regardless of how the trace interleaves entries and exits across threads.
//!
//! `clone`/`fork`/`vfork` themselves flow through the ordinary syscall path (the
//! trace records their enter/exit); only the extra [`ThreadSpawn`] event between
//! them needs special handling, and the injected return value is *never* forced,
//! so the live child tid the kernel really returns is preserved.
//!
//! # vfork
//! A `vfork` parent is suspended in-kernel until its child execs/exits. The
//! recorded schedule already reflects that (no parent record appears until the
//! child releases it), so strict record-order replay never resumes such a parent
//! early; the suspended pair is tracked for release symmetry with the recorder.

use std::collections::BTreeMap;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use recorder::capture::payload::{SchedSwitch, SyscallEnter, SyscallExit, ThreadSpawn};
use recorder::trace::{EventKind, Record};

use crate::error::ReplayError;
use crate::inject::{self, injection_addr};
use crate::regs;
use crate::schedule::{TidMap, TidMapError};
use crate::session::{ExitOutcome, ReplaySession};
use crate::watchpoint_hw;

/// Per-thread replay bookkeeping.
#[derive(Debug, Default)]
struct ThreadRt {
    /// A syscall seen at its entry stop, awaiting its exit stop on this thread.
    pending: Option<PendingSys>,
    /// Signal to deliver when this thread is next resumed.
    resume_signal: Option<Signal>,
}

/// A syscall in flight on one thread between its entry and exit stops.
#[derive(Debug, Clone, Copy)]
struct PendingSys {
    /// Whether the syscall was cancelled at entry, so its recorded result is
    /// injected at exit instead of the real syscall running.
    suppressed: bool,
    /// Destination for injected kernel-written bytes when `suppressed`, or
    /// `None` for a return-value-only injection (e.g. `futex`) or a real syscall.
    inject_addr: Option<u64>,
}

/// Decide how a syscall is handled during schedule-enforced replay: `(suppress,
/// inject_addr)`.
///
/// - **Data injection** (`read`/`getrandom`/…): the kernel wrote a result region
///   in the recording; suppress the real syscall and inject those bytes + ret.
/// - **Real execution** (everything else, incl. `write`/`clone`/`futex`): the
///   syscall runs for real so side effects (output, thread creation) happen and
///   synchronization stays consistent with the tracee's own memory. Blocking
///   primitives like `futex(FUTEX_WAIT)` do not deadlock because the enforced
///   record order runs the waking event (e.g. a joinee's exit clears its
///   `clear_child_tid` futex) *before* the waiter's own resume, so the wait
///   finds its condition already satisfied and returns without blocking.
fn classify(nr: u64, args: &[u64; 6]) -> (bool, Option<u64>) {
    match injection_addr(nr, args) {
        Some(addr) => (true, Some(addr)),
        None => (false, None),
    }
}

/// Live thread set + schedule state for an in-flight multi-threaded replay.
#[derive(Debug)]
pub(crate) struct MtState {
    /// The recorded leader's current live pid.
    leader: Pid,
    /// Every followed live thread/process and its per-thread state.
    threads: BTreeMap<Pid, ThreadRt>,
    /// Recorded-tid ↔ live-pid remapping table.
    tidmap: TidMap,
    /// `vfork`'d children awaiting release, keyed by child live pid, valued by
    /// the suspended parent live pid (symmetry with the recorder).
    vfork_suspended: BTreeMap<Pid, Pid>,
    /// The recorded tid the last [`EventKind::SchedSwitch`] handed the CPU to;
    /// every concrete record must be tagged this tid.
    expected_tid: Option<u32>,
}

impl MtState {
    fn new(leader: Pid) -> Self {
        Self {
            leader,
            threads: BTreeMap::new(),
            tidmap: TidMap::new(),
            vfork_suspended: BTreeMap::new(),
            expected_tid: None,
        }
    }

    /// Every live tracee pid currently followed.
    pub(crate) fn live_pids(&self) -> Vec<Pid> {
        self.threads.keys().copied().collect()
    }
}

/// ptrace options every followed thread/process runs under during replay. A
/// superset of the checkpoint options with `TRACEEXEC`, so a followed exec is a
/// distinguishable event rather than an ambiguous `SIGTRAP` (see module docs).
fn mt_trace_options() -> ptrace::Options {
    ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_EXITKILL
        | ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACEEXEC
}

/// Drive a multi-threaded replay forward, enforcing the recorded schedule, until
/// the target seq is reached, the leader exits, or divergence is detected.
pub(crate) fn drive(
    session: &mut ReplaySession,
    stop_at: Option<u64>,
) -> Result<ExitOutcome, ReplayError> {
    ensure_state(session)?;
    loop {
        if let (Some(target), Some(current)) = (stop_at, session.current_seq) {
            if current >= target {
                return Ok(ExitOutcome::Running);
            }
        }
        let Some(record) = session.records.get(session.cursor).cloned() else {
            return Err(ReplayError::TraceExhausted);
        };
        match record.event.kind {
            EventKind::Checkpoint => session.cursor += 1,
            EventKind::SchedSwitch => on_sched_switch(session, &record)?,
            EventKind::SyscallEnter => on_syscall_enter(session, &record)?,
            EventKind::SyscallExit => on_syscall_exit(session, &record)?,
            EventKind::ThreadSpawn => on_thread_spawn(session, &record)?,
            EventKind::ThreadExit => {
                if let Some(outcome) = on_thread_exit(session, &record)? {
                    return Ok(outcome);
                }
            }
            EventKind::Signal => on_signal(session, &record)?,
            other => {
                return Err(ReplayError::UnexpectedRecord {
                    seq: record.seq,
                    expected: "syscall or thread-lifecycle record",
                    found: other,
                })
            }
        }
    }
}

/// Initialize the thread set on first entry: re-apply the follow-everything
/// options to the leader and seat it as the only live thread.
fn ensure_state(session: &mut ReplaySession) -> Result<(), ReplayError> {
    if session.mt.is_some() {
        return Ok(());
    }
    ptrace::setoptions(session.pid, mt_trace_options())?;
    let mut state = MtState::new(session.pid);
    state.threads.insert(session.pid, ThreadRt::default());
    session.mt = Some(state);
    Ok(())
}

fn on_sched_switch(session: &mut ReplaySession, record: &Record) -> Result<(), ReplayError> {
    let switch = SchedSwitch::decode(&record.event.payload)?;
    state(session).expected_tid = Some(switch.tid);
    advance(session, record.seq);
    Ok(())
}

fn on_syscall_enter(session: &mut ReplaySession, record: &Record) -> Result<(), ReplayError> {
    let tid = enforce_tid(session, record)?;
    let live = live_for(session, tid, record.seq)?;
    let sig = take_resume_signal(session, live);
    let status = step_thread(session, live, sig)?;
    let WaitStatus::PtraceSyscall(_) = status else {
        return Err(stop_diverged(
            record.seq,
            tid,
            "a syscall-entry stop",
            status,
        ));
    };
    let regs = regs::read(live)?;
    session.last_regs = Some(regs);
    let enter = SyscallEnter::decode(&record.event.payload)?;
    if enter.nr != regs.nr {
        return Err(ReplayError::Diverged {
            seq: record.seq,
            expected_nr: enter.nr,
            found_nr: regs.nr,
        });
    }
    let (suppress, inject_addr) = classify(regs.nr, &regs.args);
    if suppress {
        regs::suppress_syscall(live)?;
    }
    set_pending(
        session,
        live,
        Some(PendingSys {
            suppressed: suppress,
            inject_addr,
        }),
    );
    advance(session, record.seq);
    Ok(())
}

fn on_syscall_exit(session: &mut ReplaySession, record: &Record) -> Result<(), ReplayError> {
    let tid = enforce_tid(session, record)?;
    let live = live_for(session, tid, record.seq)?;
    let status = step_thread(session, live, None)?;
    let WaitStatus::PtraceSyscall(_) = status else {
        return Err(stop_diverged(
            record.seq,
            tid,
            "a syscall-exit stop",
            status,
        ));
    };
    let regs = regs::read(live)?;
    session.last_regs = Some(regs);
    let exit = SyscallExit::decode(&record.event.payload)?;
    let Some(pending) = take_pending(session, live) else {
        return Err(ReplayError::ScheduleDiverged {
            seq: record.seq,
            detail: format!("syscall-exit for recorded tid {tid} with no matching entry"),
        });
    };
    if pending.suppressed {
        if let Some(addr) = pending.inject_addr {
            inject::write_memory(live, addr, &exit.data)?;
        }
        regs::set_return(live, exit.ret)?;
    }
    advance(session, record.seq);
    Ok(())
}

fn on_thread_spawn(session: &mut ReplaySession, record: &Record) -> Result<(), ReplayError> {
    let tid = enforce_tid(session, record)?;
    let parent = live_for(session, tid, record.seq)?;
    let spawn = ThreadSpawn::decode(&record.event.payload)?;
    let sig = take_resume_signal(session, parent);
    let status = step_thread(session, parent, sig)?;
    let event = match status {
        WaitStatus::PtraceEvent(_, _, event) if is_spawn_event(event) => event,
        other => {
            return Err(stop_diverged(
                record.seq,
                tid,
                "a thread-spawn (clone) event",
                other,
            ))
        }
    };
    let child = Pid::from_raw(ptrace::getevent(parent)? as i32);
    register_child(child, record.seq)?;
    let vforked = event == libc::PTRACE_EVENT_VFORK;
    bind_child(session, record.seq, spawn.child_tid, child, parent, vforked)?;
    if let Some(wp) = session.watchpoint {
        watchpoint_hw::arm(child, wp.addr, wp.len, wp.kind)?;
    }
    advance(session, record.seq);
    Ok(())
}

/// Reap a freshly cloned child's initial stop and apply the follow-everything
/// options, so it is held under our control before the schedule resumes it.
fn register_child(child: Pid, seq: u64) -> Result<(), ReplayError> {
    match waitpid(child, Some(WaitPidFlag::__WALL))? {
        WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _) => {}
        other => {
            return Err(ReplayError::ScheduleDiverged {
                seq,
                detail: format!("cloned child {child} did not stop as expected: {other:?}"),
            })
        }
    }
    ptrace::setoptions(child, mt_trace_options())?;
    Ok(())
}

fn bind_child(
    session: &mut ReplaySession,
    seq: u64,
    child_tid: u32,
    child: Pid,
    parent: Pid,
    vforked: bool,
) -> Result<(), ReplayError> {
    let mt = state(session);
    mt.tidmap
        .bind(child_tid, child.as_raw())
        .map_err(|e| tidmap_diverged(seq, e))?;
    mt.threads.insert(child, ThreadRt::default());
    if vforked {
        mt.vfork_suspended.insert(child, parent);
    }
    Ok(())
}

/// Returns `Some(outcome)` iff the leader exited, ending the replay.
fn on_thread_exit(
    session: &mut ReplaySession,
    record: &Record,
) -> Result<Option<ExitOutcome>, ReplayError> {
    let tid = enforce_tid(session, record)?;
    let live = live_for(session, tid, record.seq)?;
    let sig = take_resume_signal(session, live);
    let status = step_thread(session, live, sig)?;
    let outcome = match status {
        WaitStatus::Exited(_, code) => ExitOutcome::Exited(code),
        WaitStatus::Signaled(_, signal, _) => ExitOutcome::Signaled(signal as i32),
        other => return Err(stop_diverged(record.seq, tid, "a thread exit", other)),
    };
    let is_leader = live == state(session).leader;
    remove_thread(session, tid, live);
    advance(session, record.seq);
    if is_leader {
        session.finished = Some(outcome);
        return Ok(Some(outcome));
    }
    Ok(None)
}

fn on_signal(session: &mut ReplaySession, record: &Record) -> Result<(), ReplayError> {
    let tid = enforce_tid(session, record)?;
    let live = live_for(session, tid, record.seq)?;
    let sig = take_resume_signal(session, live);
    let status = step_thread(session, live, sig)?;
    let WaitStatus::Stopped(_, delivered) = status else {
        return Err(stop_diverged(
            record.seq,
            tid,
            "a signal-delivery stop",
            status,
        ));
    };
    if let Some(thread) = state(session).threads.get_mut(&live) {
        thread.resume_signal = Some(delivered);
    }
    advance(session, record.seq);
    Ok(())
}

/// Resume exactly `live` toward its next instrumented point, transparently
/// swallowing a followed exec (no trace record) and servicing any watchpoint hit
/// (a replay-side observation, also not a trace record) before returning the
/// meaningful stop the schedule expects.
fn step_thread(
    session: &mut ReplaySession,
    live: Pid,
    sig: Option<Signal>,
) -> Result<WaitStatus, ReplayError> {
    let mut sig = sig;
    loop {
        ptrace::syscall(live, sig.take())?;
        let status = waitpid(live, Some(WaitPidFlag::__WALL))?;
        match status {
            WaitStatus::PtraceEvent(_, _, ev) if ev == libc::PTRACE_EVENT_EXEC => continue,
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                if session.is_watch_hit(live)? {
                    session.on_watch_hit(live)?;
                    continue;
                }
                return Ok(status);
            }
            other => return Ok(other),
        }
    }
}

/// Validate the record is tagged the tid the schedule expects next, returning
/// that tid. The first concrete record adopts its tid as the leader; thereafter
/// a [`EventKind::SchedSwitch`] is the only way the expected tid changes, so a
/// mismatch means the recorded schedule was reordered — surfaced, never ignored.
fn enforce_tid(session: &mut ReplaySession, record: &Record) -> Result<u32, ReplayError> {
    let tid = record
        .event
        .tid
        .ok_or_else(|| ReplayError::ScheduleDiverged {
            seq: record.seq,
            detail: "v3 multi-threaded record is missing its tid".to_owned(),
        })?;
    let mt = state(session);
    match mt.expected_tid {
        None => mt.expected_tid = Some(tid),
        Some(expected) if expected == tid => {}
        Some(expected) => {
            return Err(ReplayError::ScheduleDiverged {
                seq: record.seq,
                detail: format!(
                    "schedule says thread {expected} runs next, but the record is tagged tid {tid}"
                ),
            })
        }
    }
    Ok(tid)
}

/// The live pid for a recorded tid, binding the leader on first sight (empty
/// map) and rejecting an otherwise-unknown tid as divergence.
fn live_for(session: &mut ReplaySession, tid: u32, seq: u64) -> Result<Pid, ReplayError> {
    let mt = state(session);
    if let Some(live) = mt.tidmap.live_of(tid) {
        return Ok(Pid::from_raw(live));
    }
    if mt.tidmap.is_empty() {
        let leader = mt.leader;
        mt.tidmap
            .bind(tid, leader.as_raw())
            .map_err(|e| tidmap_diverged(seq, e))?;
        return Ok(leader);
    }
    Err(ReplayError::ScheduleDiverged {
        seq,
        detail: format!("record names unbound tid {tid}"),
    })
}

fn remove_thread(session: &mut ReplaySession, tid: u32, live: Pid) {
    let mt = state(session);
    mt.threads.remove(&live);
    mt.tidmap.unbind_recorded(tid);
    mt.vfork_suspended.remove(&live);
}

fn take_resume_signal(session: &mut ReplaySession, live: Pid) -> Option<Signal> {
    state(session)
        .threads
        .get_mut(&live)
        .and_then(|t| t.resume_signal.take())
}

fn set_pending(session: &mut ReplaySession, live: Pid, pending: Option<PendingSys>) {
    if let Some(thread) = state(session).threads.get_mut(&live) {
        thread.pending = pending;
    }
}

fn take_pending(session: &mut ReplaySession, live: Pid) -> Option<PendingSys> {
    state(session)
        .threads
        .get_mut(&live)
        .and_then(|t| t.pending.take())
}

fn advance(session: &mut ReplaySession, seq: u64) {
    session.current_seq = Some(seq);
    session.cursor += 1;
}

fn state(session: &mut ReplaySession) -> &mut MtState {
    session
        .mt
        .as_mut()
        .expect("multi-threaded replay state is initialized by ensure_state")
}

/// Whether a `PTRACE_EVENT_*` code is a thread/process creation we follow.
fn is_spawn_event(event: i32) -> bool {
    event == libc::PTRACE_EVENT_CLONE
        || event == libc::PTRACE_EVENT_FORK
        || event == libc::PTRACE_EVENT_VFORK
}

fn stop_diverged(seq: u64, tid: u32, expected: &str, got: WaitStatus) -> ReplayError {
    ReplayError::ScheduleDiverged {
        seq,
        detail: format!("thread {tid}: expected {expected}, got {got:?}"),
    }
}

fn tidmap_diverged(seq: u64, err: TidMapError) -> ReplayError {
    ReplayError::ScheduleDiverged {
        seq,
        detail: format!("recorded/live tid mapping conflict: {err:?}"),
    }
}
