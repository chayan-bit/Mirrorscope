//! The replay session: spawns the recorded target under ptrace and drives it
//! syscall-stop to syscall-stop, verifying each syscall against the trace and
//! injecting recorded results for the nondeterministic ones.

use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use recorder::capture::payload::{SyscallEnter, SyscallExit};
use recorder::trace::{Cmdline, EventKind, Record, TraceError, TraceReader};
use unwind::{RemoteUnwinder, SymbolizedFrame};

use crate::checkpoint::{self, CheckpointInfo};
use crate::checkpoint_select;
use crate::error::ReplayError;
use crate::inject::{self, injection_addr};
use crate::regs::{self, Registers};
use crate::watchpoint::{self, WatchHit, WatchKind};
use crate::watchpoint_hw;

/// How the replayed tracee left off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitOutcome {
    /// The tracee exited with this status code.
    Exited(i32),
    /// The tracee was terminated by this signal number.
    Signaled(i32),
    /// The tracee is paused at a syscall boundary, not yet finished (returned by
    /// [`ReplaySession::step_to`] once the target sequence number is reached).
    Running,
}

/// A driven replay of a recorded target.
///
/// Fields the multi-threaded driver in [`crate::mt`] reads or updates are
/// `pub(crate)`; single-threaded-only bookkeeping stays private to this module.
pub struct ReplaySession {
    pub(crate) pid: Pid,
    cmdline: Cmdline,
    pub(crate) records: Vec<Record>,
    pub(crate) cursor: usize,
    pub(crate) current_seq: Option<u64>,
    pending: Option<Pending>,
    resume_signal: Option<Signal>,
    pub(crate) last_regs: Option<Registers>,
    pub(crate) finished: Option<ExitOutcome>,
    checkpoint_interval: u64,
    checkpoints: Vec<CheckpointInfo>,
    pub(crate) watchpoint: Option<Watchpoint>,
    pub(crate) watch_hits: Vec<WatchHit>,
    pub(crate) last_value: Option<Vec<u8>>,
    pub(crate) unwinder: Option<RemoteUnwinder>,
    /// Whether the trace carries a recorded single-core thread schedule that
    /// must be enforced (see [`crate::schedule::trace_is_multithreaded`]).
    multithreaded: bool,
    /// Live thread set + tid remapping, present only while a multi-threaded
    /// replay is in flight; rebuilt on every respawn.
    pub(crate) mt: Option<crate::mt::MtState>,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    _child: Child,
}

/// A syscall seen at its entry stop, awaiting its exit stop.
struct Pending {
    /// Destination buffer for injected results, when this syscall is one whose
    /// result must be fed from the trace; `None` for real syscalls.
    inject_addr: Option<u64>,
}

/// The active retroactive-watchpoint request, remembered so the session can
/// re-arm the CPU debug registers after every checkpoint restore or respawn
/// (debug registers are not inherited across `fork`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Watchpoint {
    pub(crate) addr: u64,
    pub(crate) len: u8,
    pub(crate) kind: WatchKind,
}

/// Where a `run_to`/`restore_to` should resume from: a checkpoint index (and
/// its seq), or process entry (`index: None`, `seq: 0`).
struct StartPoint {
    index: Option<usize>,
    seq: u64,
}

impl ReplaySession {
    /// Open `trace_path`, read the embedded command line, and spawn the target
    /// under ptrace (ADDR_NO_RANDOMIZE + TRACEME, TRACESYSGOOD | EXITKILL) with
    /// stdout/stderr piped. Errors if the trace has no recorded command line.
    pub fn launch(trace_path: &Path) -> Result<Self, ReplayError> {
        let file = File::open(trace_path).map_err(TraceError::Io)?;
        let reader = TraceReader::open(BufReader::new(file))?;
        let cmdline = reader.cmdline().cloned().ok_or(ReplayError::NoCmdline)?;
        let records = reader.collect::<Result<Vec<_>, _>>()?;
        let multithreaded = crate::schedule::trace_is_multithreaded(&records);

        let mut child = spawn_traced(&cmdline.program, &cmdline.args)?;
        let pid = Pid::from_raw(child.id() as i32);

        // First stop: the SIGTRAP from execve under TRACEME.
        waitpid(pid, None)?;
        checkpoint::setup_options(pid)?;

        let stdout = child.stdout.take().map(drain_thread);
        let stderr = child.stderr.take().map(drain_thread);

        Ok(Self {
            pid,
            cmdline,
            records,
            cursor: 0,
            current_seq: None,
            pending: None,
            resume_signal: None,
            last_regs: None,
            finished: None,
            checkpoint_interval: 0,
            checkpoints: Vec::new(),
            watchpoint: None,
            watch_hits: Vec::new(),
            last_value: None,
            unwinder: None,
            multithreaded,
            mt: None,
            stdout,
            stderr,
            _child: child,
        })
    }

    /// The current live pid of the main tracee (the recorded leader). The DAP
    /// backend needs this to address the process it is debugging.
    ///
    /// NOTE: this value changes whenever the session respawns from entry or
    /// restores a checkpoint (a fresh forked/spawned process gets a new pid), so
    /// callers must re-read it after any `run_to`/`restore_to`, never cache it.
    pub fn pid(&self) -> i32 {
        self.pid.as_raw()
    }

    /// Take a fork-snapshot checkpoint every `interval` trace-sequence units of
    /// forward progress (`0` disables checkpointing, the default). Checkpoints
    /// are only ever taken at clean syscall boundaries during forward replay.
    pub fn checkpoint_interval(&mut self, interval: u64) {
        self.checkpoint_interval = interval;
    }

    /// The fork-snapshot checkpoints taken so far, ascending by seq. Backs the
    /// DAP `listCheckpoints` request.
    pub fn checkpoints(&self) -> &[CheckpointInfo] {
        &self.checkpoints
    }

    /// Drive replay to `seq`, but first jump to the nearest checkpoint (or, if
    /// none precedes `seq`, respawn from entry) so replay need not always
    /// re-execute from process start — including going *backward* to a seq
    /// already passed. This is the checkpoint-aware sibling of [`Self::step_to`].
    pub fn run_to(&mut self, seq: u64) -> Result<ExitOutcome, ReplayError> {
        let start = self.plan_start(seq);
        if checkpoint_select::should_restart(self.current_seq, start.seq, seq) {
            match start.index {
                Some(index) => self.restore_to_checkpoint(index)?,
                None => self.respawn()?,
            }
        }
        self.drive(Some(seq))
    }

    /// Restore the session to the nearest checkpoint at-or-before `seq` (or to a
    /// fresh process at entry when none precedes it), without driving forward.
    /// After this the session is re-seated at the checkpoint's boundary.
    pub fn restore_to(&mut self, seq: u64) -> Result<(), ReplayError> {
        match self.plan_start(seq).index {
            Some(index) => self.restore_to_checkpoint(index),
            None => self.respawn(),
        }
    }

    /// Choose the restart point for a target seq: the nearest checkpoint
    /// at-or-before it, else process entry (`index: None`, `seq: 0`).
    fn plan_start(&self, target: u64) -> StartPoint {
        let seqs: Vec<u64> = self.checkpoints.iter().map(|cp| cp.seq).collect();
        match checkpoint_select::nearest_at_or_before(&seqs, target) {
            Some(index) => StartPoint {
                index: Some(index),
                seq: self.checkpoints[index].seq,
            },
            None => StartPoint {
                index: None,
                seq: 0,
            },
        }
    }

    /// Drive replay until a record with sequence number `seq` has been consumed
    /// (or the tracee finishes first).
    pub fn step_to(&mut self, seq: u64) -> Result<ExitOutcome, ReplayError> {
        self.drive(Some(seq))
    }

    /// Drive replay until the tracee exits or is killed.
    pub fn run_to_end(&mut self) -> Result<ExitOutcome, ReplayError> {
        self.drive(None)
    }

    /// The sequence number of the last consumed trace record.
    pub fn current_seq(&self) -> Option<u64> {
        self.current_seq
    }

    /// The syscall registers read at the most recent syscall stop.
    pub fn regs(&self) -> Option<Registers> {
        self.last_regs
    }

    /// Read `len` bytes from the replay tracee at `addr`.
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, ReplayError> {
        inject::read_memory(self.pid, addr, len)
    }

    /// Collect everything the replayed target wrote to stdout.
    pub fn read_stdout(&mut self) -> Result<Vec<u8>, ReplayError> {
        join_drain(self.stdout.take())
    }

    /// Collect everything the replayed target wrote to stderr.
    pub fn read_stderr(&mut self) -> Result<Vec<u8>, ReplayError> {
        join_drain(self.stderr.take())
    }

    /// Arm a retroactive watchpoint on `len` bytes (1, 2, 4, or 8) at `addr`.
    ///
    /// Once armed, every access of `kind` to the range during forward replay is
    /// recorded as a [`WatchHit`] (drain them with [`Self::take_watch_hits`]).
    /// The request is validated (supported length, natural alignment) and the
    /// CPU debug registers are armed on the current tracee immediately; the
    /// session re-arms automatically after any checkpoint restore or respawn.
    pub fn watch(&mut self, addr: u64, len: u8, kind: WatchKind) -> Result<(), ReplayError> {
        watchpoint::validate(addr, len)?;
        // Debug registers are per-thread, so a multi-threaded replay must arm
        // every live thread; a single-threaded one has only the leader.
        for live in self.live_threads() {
            watchpoint_hw::arm(live, addr, len, kind)?;
        }
        self.last_value = Some(self.read_memory(addr, usize::from(len))?);
        self.watchpoint = Some(Watchpoint { addr, len, kind });
        Ok(())
    }

    /// Every live tracee pid the session currently drives: the whole followed
    /// thread set during a multi-threaded replay, else just the leader.
    pub(crate) fn live_threads(&self) -> Vec<Pid> {
        match &self.mt {
            Some(mt) => mt.live_pids(),
            None => vec![self.pid],
        }
    }

    /// Disarm the watchpoint and forget the request, leaving any hits collected
    /// so far intact. A no-op if none is armed.
    pub fn clear_watch(&mut self) -> Result<(), ReplayError> {
        if self.watchpoint.take().is_some() && self.finished.is_none() {
            watchpoint_hw::disarm(self.pid)?;
        }
        self.last_value = None;
        Ok(())
    }

    /// Drain every watchpoint hit collected so far, in execution order.
    pub fn take_watch_hits(&mut self) -> Vec<WatchHit> {
        std::mem::take(&mut self.watch_hits)
    }

    fn drive(&mut self, stop_at: Option<u64>) -> Result<ExitOutcome, ReplayError> {
        if let Some(outcome) = self.finished {
            return Ok(outcome);
        }
        // Multi-threaded traces are driven by the schedule-enforcing engine,
        // which understands the v3-only SchedSwitch/ThreadSpawn/ThreadExit kinds
        // and per-tid syscall injection; single-threaded traces keep the
        // original single-tracee loop below, byte-for-byte unchanged.
        if self.multithreaded {
            return crate::mt::drive(self, stop_at);
        }
        loop {
            if let (Some(target), Some(current)) = (stop_at, self.current_seq) {
                if current >= target {
                    return Ok(ExitOutcome::Running);
                }
            }
            ptrace::syscall(self.pid, self.resume_signal.take())?;
            match waitpid(self.pid, None)? {
                WaitStatus::PtraceSyscall(_) => {
                    self.on_syscall_stop()?;
                    self.maybe_checkpoint()?;
                }
                WaitStatus::Stopped(_, signal) => {
                    if signal == Signal::SIGTRAP && self.is_watch_hit(self.pid)? {
                        self.on_watch_hit(self.pid)?;
                    } else {
                        self.on_signal_stop(signal);
                    }
                }
                WaitStatus::Exited(_, code) => return Ok(self.finish(ExitOutcome::Exited(code))),
                WaitStatus::Signaled(_, sig, _) => {
                    return Ok(self.finish(ExitOutcome::Signaled(sig as i32)))
                }
                _ => {}
            }
        }
    }

    /// At a clean syscall boundary (no pending exit), fork a snapshot if the
    /// configured interval says one is due. Never checkpoints mid-syscall, and
    /// the gap test suppresses duplicates when replay re-covers old ground.
    fn maybe_checkpoint(&mut self) -> Result<(), ReplayError> {
        // Fork snapshots duplicate only the *calling* thread's task (fork
        // semantics), so they cannot faithfully snapshot a multi-threaded
        // tracee. Checkpointing is therefore disabled while a schedule is being
        // enforced; a correct multi-threaded snapshot needs CRIU, the deferred
        // Phase-2+ path (issue #5). Backward navigation still works — it
        // respawns from entry and re-drives, which is fully deterministic.
        if self.multithreaded {
            return Ok(());
        }
        if self.pending.is_some() {
            return Ok(());
        }
        let Some(seq) = self.current_seq else {
            return Ok(());
        };
        let last = self.checkpoints.last().map(|cp| cp.seq);
        if !checkpoint_select::is_checkpoint_due(last, seq, self.checkpoint_interval) {
            return Ok(());
        }
        let snapshot = checkpoint::fork_snapshot(self.pid)?;
        self.checkpoints.push(CheckpointInfo {
            seq,
            cursor: self.cursor,
            current_seq: self.current_seq,
            last_regs: self.last_regs,
            snapshot,
        });
        Ok(())
    }

    /// Fork a fresh active tracee from a checkpoint's pristine snapshot and
    /// re-seat the replay cursor at the checkpoint boundary. The snapshot stays
    /// untouched so it can seed further restores (reverse-execution).
    fn restore_to_checkpoint(&mut self, index: usize) -> Result<(), ReplayError> {
        let checkpoint = self.checkpoints[index].clone();
        let fresh = checkpoint::fork_snapshot(checkpoint.snapshot)?;
        self.kill_active();
        self.pid = fresh;
        self.cursor = checkpoint.cursor;
        self.current_seq = checkpoint.current_seq;
        self.last_regs = checkpoint.last_regs;
        self.pending = None;
        self.resume_signal = None;
        self.finished = None;
        self.mt = None;
        self.rearm_watchpoint()?;
        Ok(())
    }

    /// Re-spawn the recorded target from scratch under ptrace and reset the
    /// replay cursor to entry — the fallback when no checkpoint precedes a
    /// target seq. Existing snapshots (independent COW processes) remain valid.
    fn respawn(&mut self) -> Result<(), ReplayError> {
        self.kill_active();
        let mut child = spawn_traced(&self.cmdline.program, &self.cmdline.args)?;
        let pid = Pid::from_raw(child.id() as i32);
        waitpid(pid, None)?;
        checkpoint::setup_options(pid)?;
        self.stdout = child.stdout.take().map(drain_thread);
        self.stderr = child.stderr.take().map(drain_thread);
        self.pid = pid;
        self._child = child;
        self.cursor = 0;
        self.current_seq = None;
        self.pending = None;
        self.resume_signal = None;
        self.last_regs = None;
        self.finished = None;
        self.mt = None;
        self.rearm_watchpoint()?;
        Ok(())
    }

    /// Re-arm the CPU debug registers on the current tracee after a restore or
    /// respawn. Debug registers are not inherited across `fork`, so a freshly
    /// forked snapshot child or a respawned process starts with them clear; a
    /// live watchpoint must be re-installed or writes after the jump go unseen.
    /// The cached remote unwinder is also dropped, as it is bound to the old pid.
    fn rearm_watchpoint(&mut self) -> Result<(), ReplayError> {
        self.unwinder = None;
        if let Some(wp) = self.watchpoint {
            watchpoint_hw::arm(self.pid, wp.addr, wp.len, wp.kind)?;
        }
        Ok(())
    }

    /// Kill and reap the current active tracee. Snapshots are never touched here
    /// — they are cleaned up in [`Drop`].
    fn kill_active(&mut self) {
        if self.finished.is_none() {
            let _ = ptrace::kill(self.pid);
            let _ = waitpid(self.pid, None);
        }
    }

    fn on_syscall_stop(&mut self) -> Result<(), ReplayError> {
        let regs = regs::read(self.pid)?;
        self.last_regs = Some(regs);
        match self.pending.take() {
            None => self.on_entry(&regs),
            Some(pending) => self.on_exit(pending),
        }
    }

    fn on_entry(&mut self, regs: &Registers) -> Result<(), ReplayError> {
        let record = self.next_record()?;
        let enter = match record.event.kind {
            EventKind::SyscallEnter => SyscallEnter::decode(&record.event.payload)?,
            found => {
                return Err(ReplayError::UnexpectedRecord {
                    seq: record.seq,
                    expected: "SyscallEnter",
                    found,
                })
            }
        };
        if enter.nr != regs.nr {
            return Err(ReplayError::Diverged {
                seq: record.seq,
                expected_nr: enter.nr,
                found_nr: regs.nr,
            });
        }
        self.current_seq = Some(record.seq);
        let inject_addr = injection_addr(regs.nr, &regs.args);
        if inject_addr.is_some() {
            regs::suppress_syscall(self.pid)?;
        }
        self.pending = Some(Pending { inject_addr });
        Ok(())
    }

    fn on_exit(&mut self, pending: Pending) -> Result<(), ReplayError> {
        let record = self.next_record()?;
        let exit = match record.event.kind {
            EventKind::SyscallExit => SyscallExit::decode(&record.event.payload)?,
            found => {
                return Err(ReplayError::UnexpectedRecord {
                    seq: record.seq,
                    expected: "SyscallExit",
                    found,
                })
            }
        };
        self.current_seq = Some(record.seq);
        if let Some(addr) = pending.inject_addr {
            inject::write_memory(self.pid, addr, &exit.data)?;
            regs::set_return(self.pid, exit.ret)?;
        }
        Ok(())
    }

    fn on_signal_stop(&mut self, signal: Signal) {
        self.skip_checkpoints();
        if let Some(record) = self.records.get(self.cursor) {
            if record.event.kind == EventKind::Signal {
                self.current_seq = Some(record.seq);
                self.cursor += 1;
            }
        }
        self.resume_signal = Some(signal);
    }

    /// Whether the current `SIGTRAP` stop is a hardware watchpoint hit. Cheap
    /// early-out when no watchpoint is armed, so unrelated `SIGTRAP`s (real
    /// signals, breakpoints) still flow to [`Self::on_signal_stop`].
    pub(crate) fn is_watch_hit(&self, pid: Pid) -> Result<bool, ReplayError> {
        if self.watchpoint.is_none() {
            return Ok(false);
        }
        watchpoint_hw::is_watch_hit(pid)
    }

    /// Service a hardware watchpoint hit: record the pc, backtrace, nearest seq,
    /// and the value at the range, then step over the faulting instruction so
    /// replay continues. The `SIGTRAP` is swallowed (never forwarded), so the
    /// tracee is unaware it was watched.
    pub(crate) fn on_watch_hit(&mut self, pid: Pid) -> Result<(), ReplayError> {
        let Some(wp) = self.watchpoint else {
            return Ok(());
        };
        // Capture pc + backtrace before any step-over so the leaf frame is the
        // writing instruction — on aarch64 the trap precedes the write, and
        // stepping would advance the pc past it.
        let (pc, backtrace) = self.capture_backtrace(pid)?;
        self.step_over_watch(pid)?;
        let new_value = inject::read_memory(pid, wp.addr, usize::from(wp.len))?;
        let old_value = self.last_value.take();
        self.last_value = Some(new_value.clone());
        self.watch_hits.push(WatchHit {
            seq: self.current_seq,
            pc,
            old_value,
            new_value,
            backtrace,
        });
        Ok(())
    }

    /// Unwind and symbolize the current tracee's stack. The remote unwinder is
    /// built lazily and cached per-tracee (dropped on restore/respawn), so a
    /// straight scan reloads DWARF once rather than at every hit.
    fn capture_backtrace(&mut self, pid: Pid) -> Result<(u64, Vec<SymbolizedFrame>), ReplayError> {
        let mut unwinder = match self.unwinder.take() {
            Some(unwinder) => unwinder,
            None => RemoteUnwinder::for_pid(pid.as_raw())?,
        };
        let regs = unwinder.registers()?;
        let frames = unwinder.backtrace(&regs)?;
        self.unwinder = Some(unwinder);
        Ok((regs.pc, frames))
    }

    /// x86-64: a data watchpoint traps *after* the write, so the pc already
    /// points past it — just clear the sticky `DR6` status and let the main
    /// loop resume. No instruction is skipped, so adjacent writes each trap.
    #[cfg(target_arch = "x86_64")]
    fn step_over_watch(&mut self, pid: Pid) -> Result<(), ReplayError> {
        watchpoint_hw::clear_status(pid)
    }

    /// aarch64: a watchpoint traps *before* the access completes, so resuming
    /// would re-trap the same instruction forever. Disarm, single-step over it
    /// (the write lands during the step), then re-arm before the next
    /// instruction runs so no subsequent write is missed.
    #[cfg(target_arch = "aarch64")]
    fn step_over_watch(&mut self, pid: Pid) -> Result<(), ReplayError> {
        let Some(wp) = self.watchpoint else {
            return Ok(());
        };
        watchpoint_hw::disarm(pid)?;
        ptrace::step(pid, None)?;
        match waitpid(pid, Some(WaitPidFlag::__WALL))? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
            _ => {
                return Err(ReplayError::Watchpoint {
                    reason: "unexpected stop while stepping over a watchpoint hit",
                })
            }
        }
        watchpoint_hw::arm(pid, wp.addr, wp.len, wp.kind)
    }

    fn next_record(&mut self) -> Result<Record, ReplayError> {
        self.skip_checkpoints();
        let record = self
            .records
            .get(self.cursor)
            .cloned()
            .ok_or(ReplayError::TraceExhausted)?;
        self.cursor += 1;
        Ok(record)
    }

    fn skip_checkpoints(&mut self) {
        while matches!(
            self.records.get(self.cursor).map(|r| r.event.kind),
            Some(EventKind::Checkpoint)
        ) {
            self.cursor += 1;
        }
    }

    fn finish(&mut self, outcome: ExitOutcome) -> ExitOutcome {
        self.finished = Some(outcome);
        outcome
    }
}

impl Drop for ReplaySession {
    fn drop(&mut self) {
        // Kill and reap every tracee this session owns (EXITKILL only covers
        // tracer *exit*, not an early drop). A multi-threaded tracee dropped
        // mid-replay (e.g. after a divergence) may still hold several stopped
        // worker threads, and a zombie thread-group *leader* is not reapable
        // until its siblings are reaped — so reap each known pid explicitly with
        // the leader last, never a blind `waitpid(-1)` loop (which would spin on
        // a still-stopped snapshot). SIGKILL is unblockable, so all terminate.
        let mut tracees: Vec<Pid> = match &self.mt {
            Some(mt) => mt.live_pids(),
            None => Vec::new(),
        };
        if self.finished.is_none() && !tracees.contains(&self.pid) {
            tracees.push(self.pid);
        }
        // Reap sibling threads before the group leader.
        tracees.sort_by_key(|&pid| pid == self.pid);
        for &pid in &tracees {
            let _ = ptrace::kill(pid);
        }
        for checkpoint in &self.checkpoints {
            let _ = ptrace::kill(checkpoint.snapshot);
        }
        let flags = WaitPidFlag::__WALL;
        for &pid in &tracees {
            let _ = waitpid(pid, Some(flags));
        }
        for checkpoint in &self.checkpoints {
            let _ = waitpid(checkpoint.snapshot, Some(flags));
        }
    }
}

fn spawn_traced(program: &str, args: &[String]) -> Result<Child, ReplayError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: pre_exec runs post-fork/pre-exec in the child; personality() and
    // traceme() are async-signal-safe (single syscalls) and touch no locks.
    // ADDR_NO_RANDOMIZE pins the layout so replay matches the recording.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(|| {
            if libc::personality(libc::ADDR_NO_RANDOMIZE as _) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            ptrace::traceme().map_err(std::io::Error::from)
        });
    }
    command.spawn().map_err(ReplayError::Spawn)
}

fn drain_thread<R: Read + Send + 'static>(mut reader: R) -> JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    })
}

fn join_drain(
    handle: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
) -> Result<Vec<u8>, ReplayError> {
    match handle {
        Some(handle) => handle
            .join()
            .map_err(|_| {
                ReplayError::Output(std::io::Error::other("output reader thread panicked"))
            })?
            .map_err(ReplayError::Output),
        None => Ok(Vec::new()),
    }
}
