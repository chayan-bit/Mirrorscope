//! Single-core serialization scheduler for multi-threaded ptrace capture.
//!
//! # Model (issue #9)
//! rr's single-core trick, adapted to ARM-without-perf-counters (the whole
//! Mirrorscope thesis). Every followed thread is pinned to one CPU
//! ([`crate::capture::affinity`]) and the scheduler runs **exactly one thread
//! at a time**: it resumes a single tracee, blocks until that tracee reaches an
//! *instrumented point* (a syscall stop, a thread lifecycle event, or the
//! periodic preemption timer of [`crate::capture::timer`]), records what
//! happened, then chooses the next thread to run. The result is a **total
//! order** over instrumented points, written to the trace as
//! [`EventKind::SchedSwitch`] / [`EventKind::ThreadSpawn`] /
//! [`EventKind::ThreadExit`] records, every syscall record tagged with its
//! originating tid.
//!
//! # Determinism (conscious trade, not hand-waving)
//! Spans **between** instrumented points are treated as atomic regions. Because
//! no two threads ever run simultaneously, shared memory has a total order for
//! free, so recording is sound even in the presence of data races — but *only*
//! under this single-core serialization. The exact instruction at which the
//! preemption timer interrupts a syscall-free span is **not** reproducible
//! (that would need instruction counting); replay re-derives the schedule from
//! the recorded `SchedSwitch` boundaries and leans on checksum divergence
//! detection (issue #11) as the honesty backstop.
//!
//! # Replay compatibility (follow-up)
//! Enforcing the recorded interleaving on replay is a **separate later task**:
//! the current single-tracee replay engine does not yet understand the v3-only
//! [`SchedSwitch`]/[`ThreadSpawn`]/[`ThreadExit`] kinds. To keep it working
//! meanwhile, a purely single-threaded recording emits **none** of those kinds
//! (see `last_scheduled` seeding and the `threads_followed > 1` gate below), so
//! its trace stays byte-for-byte the shape replay already consumes; only
//! genuinely multi-threaded traces carry the new records.
//!
//! # Fork policy
//! `PTRACE_O_TRACECLONE` follows threads; `PTRACE_O_TRACEFORK` /
//! `PTRACE_O_TRACEVFORK` additionally follow forked child *processes*, pinning
//! them to the same CPU and serializing them alongside the threads. Forked
//! processes have separate address spaces, so single-core serialization still
//! yields a total syscall order, but cross-process shared memory (e.g. SysV
//! shm) is out of scope for the soundness guarantee — documented, not hidden.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::time::Instant;

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::capture::affinity::pin_to_serialization_cpu;
use crate::capture::error::{CaptureError, RecordOutcome};
use crate::capture::payload::{SchedSwitch, ThreadExit, ThreadSpawn};
use crate::capture::syscall::{enter_event, exit_event, read_syscall_regs, SyscallRegs};
use crate::capture::timer::{PreemptionTimer, DEFAULT_QUANTUM};
use crate::trace::{Event, EventKind, TraceWriter};

/// ptrace options applied to the leader and every followed thread/process.
///
/// `PTRACE_O_TRACEEXEC` matters beyond the leader's own initial exec (which
/// happens before this scheduler exists, under a plain `waitpid` in
/// [`crate::capture::ptrace::record_command`]): without it, a *followed*
/// child's own `execve` (e.g. a shell `vfork`-ing then `exec`-ing a command)
/// reports as an ordinary `SIGTRAP` signal-delivery-stop, indistinguishable
/// from a real signal. [`Scheduler::on_stopped`] would then requeue it with
/// `resume_signal = Some(SIGTRAP)` and inject that `SIGTRAP` back into the
/// tracee on its next resume — which, absent a handler, kills it. Setting
/// this option reports the exec as a `PTRACE_EVENT_EXEC` stop instead, which
/// [`Scheduler::handle`] simply requeues with no signal to redeliver.
pub fn trace_options() -> ptrace::Options {
    ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_EXITKILL
        | ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACEEXEC
}

/// Per-thread capture state.
#[derive(Debug, Default)]
struct Thread {
    /// Registers captured at a syscall-entry stop, awaiting the matching exit.
    pending_enter: Option<SyscallRegs>,
    /// Signal to deliver when this thread is next resumed.
    resume_signal: Option<Signal>,
}

/// Drives all threads of a traced process under single-core serialization.
pub struct Scheduler<'w, W: Write> {
    writer: &'w mut TraceWriter<W>,
    timer: PreemptionTimer,
    started: Instant,
    threads: BTreeMap<Pid, Thread>,
    ready: VecDeque<Pid>,
    running: Option<Pid>,
    last_scheduled: Option<Pid>,
    leader: Pid,
    leader_exit: Option<i32>,
    events_recorded: u64,
    threads_followed: u64,
    /// `vfork`'d children awaiting release, keyed by child pid, valued by the
    /// parent pid they unblock on exit. `vfork(2)` suspends the parent in the
    /// kernel (uninterruptible) until this exact child execs or exits, so the
    /// scheduler must never re-continue such a parent before its child has
    /// run — doing so wastes the single running slot on a thread that cannot
    /// produce another event, starving the child forever (see module docs).
    vfork_pending: BTreeMap<Pid, Pid>,
}

impl<'w, W: Write> Scheduler<'w, W> {
    /// Create a scheduler for a `leader` already stopped at its post-exec
    /// SIGTRAP with [`trace_options`] applied. The leader is pinned and queued.
    pub fn new(writer: &'w mut TraceWriter<W>, leader: Pid) -> Result<Self, CaptureError> {
        pin_to_serialization_cpu(leader)?;
        let mut threads = BTreeMap::new();
        threads.insert(leader, Thread::default());
        Ok(Self {
            writer,
            timer: PreemptionTimer::install(DEFAULT_QUANTUM)?,
            started: Instant::now(),
            threads,
            ready: VecDeque::from([leader]),
            running: None,
            // Seed with the leader so a purely single-threaded recording never
            // emits a SchedSwitch (nor any other v3-only kind): its trace stays
            // byte-compatible with what the single-tracee replay engine already
            // understands. New kinds appear only once a second thread exists.
            last_scheduled: Some(leader),
            leader,
            leader_exit: None,
            events_recorded: 0,
            threads_followed: 1,
            vfork_pending: BTreeMap::new(),
        })
    }

    /// Run every thread to completion, recording the interleaving.
    ///
    /// Every wait in this scheduler passes `__WNOTHREAD`: by default Linux's
    /// `waitpid(-1, ...)` reaps children of *any* thread in the calling
    /// process's thread group, not just the caller's own. When multiple
    /// `Scheduler`s run concurrently on different OS threads of one process
    /// (e.g. parallel `cargo test` — each test spawns its own tracee on its
    /// own worker thread), an unscoped wait can steal another thread's
    /// tracee-stop notification. The stealing thread then tries to issue
    /// `PTRACE_*` requests on a pid it never attached — which only the true
    /// tracer thread may do — and fails with `ESRCH`; meanwhile the rightful
    /// thread's own wait never sees the (already-reaped) stop and blocks
    /// forever. `__WNOTHREAD` scopes every wait to this thread's own tracees.
    pub fn run(mut self) -> Result<RecordOutcome, CaptureError> {
        while !self.threads.is_empty() {
            if self.running.is_none() {
                // A momentarily-empty ready queue does not mean the recording
                // is done: e.g. a vfork'd parent is deliberately left off the
                // ready queue until its child releases it (`vfork_pending`),
                // and a freshly-spawned child's first stop may not have been
                // observed by `waitpid` yet. Real completion is `self.threads`
                // truly emptying, which is caught by the loop condition and
                // by the `ECHILD` arm below once no children remain at all.
                self.resume_next()?;
            }
            self.timer.arm()?;
            match waitpid(
                Pid::from_raw(-1),
                Some(WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD),
            ) {
                Ok(status) => {
                    self.timer.disarm()?;
                    self.handle(status)?;
                }
                Err(Errno::EINTR) => {
                    self.timer.disarm()?;
                    if let Some(cur) = self.running {
                        self.preempt(cur)?;
                    }
                }
                Err(Errno::ECHILD) => break,
                Err(e) => return Err(CaptureError::Ptrace(e)),
            }
        }
        Ok(RecordOutcome {
            exit_code: self.leader_exit,
            events_recorded: self.events_recorded,
            threads_followed: self.threads_followed,
        })
    }

    /// Pick the next ready thread and resume it, if any is ready. An empty
    /// ready queue is not necessarily terminal — see the caller in
    /// [`Scheduler::run`].
    fn resume_next(&mut self) -> Result<(), CaptureError> {
        let Some(next) = self.ready.pop_front() else {
            return Ok(());
        };
        self.record_sched_switch(next)?;
        let sig = self
            .threads
            .get_mut(&next)
            .and_then(|t| t.resume_signal.take());
        ptrace::syscall(next, sig)?;
        self.running = Some(next);
        Ok(())
    }

    /// A syscall-free tracee overran its quantum: stop and reap it so the
    /// scheduler can rotate to another thread.
    fn preempt(&mut self, cur: Pid) -> Result<(), CaptureError> {
        kill(cur, Signal::SIGSTOP)?;
        let status = waitpid(cur, Some(WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD))?;
        self.handle(status)
    }

    fn handle(&mut self, status: WaitStatus) -> Result<(), CaptureError> {
        match status {
            WaitStatus::PtraceSyscall(pid) => {
                self.clear_running(pid);
                self.on_syscall(pid)?;
                self.requeue(pid);
            }
            WaitStatus::PtraceEvent(pid, _, event) => {
                self.clear_running(pid);
                if is_spawn_event(event) {
                    let child = self.on_spawn(pid)?;
                    if event == libc::PTRACE_EVENT_VFORK {
                        // Do not requeue: `pid` is suspended in-kernel until
                        // `child` execs or exits. It's released in `on_exit`.
                        self.vfork_pending.insert(child, pid);
                    } else {
                        self.requeue(pid);
                    }
                } else {
                    self.requeue(pid);
                }
            }
            WaitStatus::Stopped(pid, sig) => self.on_stopped(pid, sig)?,
            WaitStatus::Exited(pid, code) => self.on_exit(pid, Some(code))?,
            WaitStatus::Signaled(pid, _, _) => self.on_exit(pid, None)?,
            _ => {}
        }
        Ok(())
    }

    fn on_syscall(&mut self, pid: Pid) -> Result<(), CaptureError> {
        let regs = read_syscall_regs(pid)?;
        let ts = self.now();
        let tid = pid.as_raw() as u32;
        let pending = self
            .threads
            .get_mut(&pid)
            .and_then(|t| t.pending_enter.take());
        match pending {
            None => {
                self.append(enter_event(ts, tid, &regs))?;
                if let Some(t) = self.threads.get_mut(&pid) {
                    t.pending_enter = Some(regs);
                }
            }
            Some(enter) => {
                let event = exit_event(ts, tid, pid, &enter, regs.ret)?;
                self.append(event)?;
            }
        }
        Ok(())
    }

    fn on_spawn(&mut self, parent: Pid) -> Result<Pid, CaptureError> {
        let child = Pid::from_raw(ptrace::getevent(parent)? as i32);
        let ts = self.now();
        let payload = ThreadSpawn {
            parent_tid: parent.as_raw() as u32,
            child_tid: child.as_raw() as u32,
        }
        .encode();
        self.append(Event::new_with_tid(
            EventKind::ThreadSpawn,
            ts,
            parent.as_raw() as u32,
            payload,
        ))?;
        // The child registers itself on its own initial stop (either order is
        // handled), so we don't touch it here — it may not be waited yet.
        Ok(child)
    }

    fn on_stopped(&mut self, pid: Pid, sig: Signal) -> Result<(), CaptureError> {
        if !self.threads.contains_key(&pid) {
            // First sight of a newly followed thread/process: its initial
            // SIGSTOP is swallowed (never delivered, never recorded).
            self.register_child(pid)?;
            self.requeue(pid);
            return Ok(());
        }
        self.clear_running(pid);
        if sig != Signal::SIGSTOP {
            let ts = self.now();
            let payload = (sig as i32).to_le_bytes().to_vec();
            self.append(Event::new_with_tid(
                EventKind::Signal,
                ts,
                pid.as_raw() as u32,
                payload,
            ))?;
            if let Some(t) = self.threads.get_mut(&pid) {
                t.resume_signal = Some(sig);
            }
        }
        self.requeue(pid);
        Ok(())
    }

    fn on_exit(&mut self, pid: Pid, code: Option<i32>) -> Result<(), CaptureError> {
        self.clear_running(pid);
        // Only record a ThreadExit once the recording is genuinely multi-tracee
        // (`threads_followed > 1`); a single-threaded run emits no v3-only kinds
        // so its trace remains replayable by the single-tracee engine.
        if self.threads.remove(&pid).is_some() && self.threads_followed > 1 {
            let ts = self.now();
            let payload = ThreadExit {
                tid: pid.as_raw() as u32,
            }
            .encode();
            self.append(Event::new_with_tid(
                EventKind::ThreadExit,
                ts,
                pid.as_raw() as u32,
                payload,
            ))?;
        }
        self.ready.retain(|&p| p != pid);
        if pid == self.leader {
            self.leader_exit = code;
        }
        // If `pid` was a vfork child, its parent has been sitting suspended
        // in-kernel since the vfork event stop; it's safe (and now necessary)
        // to give it another turn.
        if let Some(parent) = self.vfork_pending.remove(&pid) {
            self.requeue(parent);
        }
        Ok(())
    }

    /// Add a freshly-followed child to the tracked set, pin it, and apply the
    /// trace options so it too reports its syscalls and descendants.
    fn register_child(&mut self, pid: Pid) -> Result<(), CaptureError> {
        pin_to_serialization_cpu(pid)?;
        ptrace::setoptions(pid, trace_options())?;
        self.threads.insert(pid, Thread::default());
        self.threads_followed += 1;
        Ok(())
    }

    fn record_sched_switch(&mut self, next: Pid) -> Result<(), CaptureError> {
        if self.last_scheduled == Some(next) {
            return Ok(());
        }
        self.last_scheduled = Some(next);
        let ts = self.now();
        let tid = next.as_raw() as u32;
        let payload = SchedSwitch { tid }.encode();
        self.append(Event::new_with_tid(
            EventKind::SchedSwitch,
            ts,
            tid,
            payload,
        ))
    }

    fn append(&mut self, event: Event) -> Result<(), CaptureError> {
        self.writer.append(&event)?;
        self.events_recorded += 1;
        Ok(())
    }

    fn requeue(&mut self, pid: Pid) {
        if self.threads.contains_key(&pid) && !self.ready.contains(&pid) {
            self.ready.push_back(pid);
        }
    }

    fn clear_running(&mut self, pid: Pid) {
        if self.running == Some(pid) {
            self.running = None;
        }
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_nanos() as u64
    }
}

/// Whether a `PTRACE_EVENT_*` code is a thread/process creation we follow.
fn is_spawn_event(event: i32) -> bool {
    event == libc::PTRACE_EVENT_CLONE
        || event == libc::PTRACE_EVENT_FORK
        || event == libc::PTRACE_EVENT_VFORK
}
