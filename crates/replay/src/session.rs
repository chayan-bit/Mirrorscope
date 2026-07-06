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
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use recorder::capture::payload::{SyscallEnter, SyscallExit};
use recorder::trace::{EventKind, Record, TraceError, TraceReader};

use crate::error::ReplayError;
use crate::inject::{self, injection_addr};
use crate::regs::{self, Registers};

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
pub struct ReplaySession {
    pid: Pid,
    records: Vec<Record>,
    cursor: usize,
    current_seq: Option<u64>,
    pending: Option<Pending>,
    resume_signal: Option<Signal>,
    last_regs: Option<Registers>,
    finished: Option<ExitOutcome>,
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

impl ReplaySession {
    /// Open `trace_path`, read the embedded command line, and spawn the target
    /// under ptrace (ADDR_NO_RANDOMIZE + TRACEME, TRACESYSGOOD | EXITKILL) with
    /// stdout/stderr piped. Errors if the trace has no recorded command line.
    pub fn launch(trace_path: &Path) -> Result<Self, ReplayError> {
        let file = File::open(trace_path).map_err(TraceError::Io)?;
        let reader = TraceReader::open(BufReader::new(file))?;
        let cmdline = reader.cmdline().cloned().ok_or(ReplayError::NoCmdline)?;
        let records = reader.collect::<Result<Vec<_>, _>>()?;

        let mut child = spawn_traced(&cmdline.program, &cmdline.args)?;
        let pid = Pid::from_raw(child.id() as i32);

        // First stop: the SIGTRAP from execve under TRACEME.
        waitpid(pid, None)?;
        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL,
        )?;

        let stdout = child.stdout.take().map(drain_thread);
        let stderr = child.stderr.take().map(drain_thread);

        Ok(Self {
            pid,
            records,
            cursor: 0,
            current_seq: None,
            pending: None,
            resume_signal: None,
            last_regs: None,
            finished: None,
            stdout,
            stderr,
            _child: child,
        })
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

    fn drive(&mut self, stop_at: Option<u64>) -> Result<ExitOutcome, ReplayError> {
        if let Some(outcome) = self.finished {
            return Ok(outcome);
        }
        loop {
            if let (Some(target), Some(current)) = (stop_at, self.current_seq) {
                if current >= target {
                    return Ok(ExitOutcome::Running);
                }
            }
            ptrace::syscall(self.pid, self.resume_signal.take())?;
            match waitpid(self.pid, None)? {
                WaitStatus::PtraceSyscall(_) => self.on_syscall_stop()?,
                WaitStatus::Stopped(_, signal) => self.on_signal_stop(signal),
                WaitStatus::Exited(_, code) => return Ok(self.finish(ExitOutcome::Exited(code))),
                WaitStatus::Signaled(_, sig, _) => {
                    return Ok(self.finish(ExitOutcome::Signaled(sig as i32)))
                }
                _ => {}
            }
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
        if self.finished.is_none() {
            let _ = ptrace::kill(self.pid);
            let _ = waitpid(self.pid, None);
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
