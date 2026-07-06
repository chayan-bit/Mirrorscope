//! Single-threaded syscall capture via `PTRACE_SYSCALL` (issue #4).
//!
//! Spawns the target with `PTRACE_TRACEME`, then stops it at every syscall
//! entry and exit. Entries record the syscall number + raw arguments; exits
//! record the return value plus any kernel-written input data (read buffers,
//! `getrandom` bytes, `clock_gettime` results) pulled out of the tracee with
//! `process_vm_readv`. That captured stream is exactly what replay (issue
//! #6) feeds back to make re-execution deterministic.

use std::fs::File;
use std::io::BufWriter;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::trace::{Event, EventKind, TraceError, TraceWriter};

use super::payload::{SyscallEnter, SyscallExit};

/// Errors while recording a target.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Failed to spawn the target command.
    #[error("failed to spawn target: {0}")]
    Spawn(std::io::Error),
    /// A ptrace/wait operation failed.
    #[error("ptrace failure: {0}")]
    Ptrace(#[from] nix::Error),
    /// Reading captured data out of the tracee failed.
    #[error("failed to read {len} bytes of syscall data from tracee at {addr:#x}: {source}")]
    TraceeRead {
        /// Remote address of the buffer.
        addr: u64,
        /// Bytes the syscall reported writing.
        len: usize,
        /// Underlying errno.
        source: nix::Error,
    },
    /// Writing the trace log failed.
    #[error(transparent)]
    Trace(#[from] TraceError),
}

/// Result of a completed recording.
#[derive(Debug)]
pub struct RecordOutcome {
    /// The target's exit code (`None` if killed by a signal).
    pub exit_code: Option<i32>,
    /// Number of events written to the trace.
    pub events_recorded: u64,
}

/// Raw syscall registers, normalized across architectures.
#[derive(Debug, Clone, Copy)]
struct SyscallRegs {
    nr: u64,
    ret: i64,
    args: [u64; 6],
}

/// Record `program args…` into a trace file at `trace_path`.
pub fn record_command(
    program: &str,
    args: &[String],
    trace_path: &Path,
) -> Result<RecordOutcome, CaptureError> {
    let file = File::create(trace_path).map_err(TraceError::Io)?;
    let mut writer = TraceWriter::create_with_cmdline(BufWriter::new(file), program, args)?;

    let child = spawn_traced(program, args)?;
    let pid = Pid::from_raw(child.id() as i32);

    // First stop: the SIGTRAP from execve under TRACEME.
    waitpid(pid, None)?;
    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL,
    )?;

    run_syscall_loop(pid, &mut writer)
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

/// Drive the tracee syscall-stop to syscall-stop until it exits.
fn run_syscall_loop<W: std::io::Write>(
    pid: Pid,
    writer: &mut TraceWriter<W>,
) -> Result<RecordOutcome, CaptureError> {
    let started = Instant::now();
    let mut events_recorded = 0u64;
    let mut pending_enter: Option<SyscallRegs> = None;
    let mut resume_signal: Option<Signal> = None;

    loop {
        ptrace::syscall(pid, resume_signal.take())?;
        match waitpid(pid, None)? {
            WaitStatus::PtraceSyscall(_) => {
                let regs = read_syscall_regs(pid)?;
                let timestamp = started.elapsed().as_nanos() as u64;
                events_recorded += 1;
                match pending_enter.take() {
                    None => {
                        record_enter(writer, timestamp, &regs)?;
                        pending_enter = Some(regs);
                    }
                    Some(enter) => record_exit(writer, timestamp, pid, &enter, regs.ret)?,
                }
            }
            WaitStatus::Stopped(_, signal) => {
                let timestamp = started.elapsed().as_nanos() as u64;
                let event = Event::new(
                    EventKind::Signal,
                    timestamp,
                    (signal as i32).to_le_bytes().into(),
                );
                writer.append(&event)?;
                events_recorded += 1;
                resume_signal = Some(signal);
            }
            WaitStatus::Exited(_, code) => {
                return Ok(RecordOutcome {
                    exit_code: Some(code),
                    events_recorded,
                });
            }
            WaitStatus::Signaled(_, _, _) => {
                return Ok(RecordOutcome {
                    exit_code: None,
                    events_recorded,
                });
            }
            _ => {}
        }
    }
}

fn record_enter<W: std::io::Write>(
    writer: &mut TraceWriter<W>,
    timestamp: u64,
    regs: &SyscallRegs,
) -> Result<(), CaptureError> {
    let payload = SyscallEnter {
        nr: regs.nr,
        args: regs.args,
    }
    .encode();
    writer.append(&Event::new(EventKind::SyscallEnter, timestamp, payload))?;
    Ok(())
}

fn record_exit<W: std::io::Write>(
    writer: &mut TraceWriter<W>,
    timestamp: u64,
    pid: Pid,
    enter: &SyscallRegs,
    ret: i64,
) -> Result<(), CaptureError> {
    let data = match kernel_written_region(enter.nr, &enter.args, ret) {
        Some((addr, len)) => read_tracee_memory(pid, addr, len)?,
        None => Vec::new(),
    };
    let payload = SyscallExit {
        nr: enter.nr,
        ret,
        data,
    }
    .encode();
    writer.append(&Event::new(EventKind::SyscallExit, timestamp, payload))?;
    Ok(())
}

/// For syscalls whose results live in tracee memory (not the return value),
/// return the region the kernel wrote: this is the input stream replay must
/// reproduce. Grown syscall-by-syscall as replay support widens.
fn kernel_written_region(nr: u64, args: &[u64; 6], ret: i64) -> Option<(u64, usize)> {
    const TIMESPEC_LEN: usize = 16;
    match nr as i64 {
        libc::SYS_read | libc::SYS_pread64 | libc::SYS_recvfrom if ret > 0 => {
            Some((args[1], ret as usize))
        }
        libc::SYS_getrandom if ret > 0 => Some((args[0], ret as usize)),
        libc::SYS_clock_gettime if ret == 0 => Some((args[1], TIMESPEC_LEN)),
        _ => None,
    }
}

fn read_tracee_memory(pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>, CaptureError> {
    let mut data = vec![0u8; len];
    let remote = RemoteIoVec {
        base: addr as usize,
        len,
    };
    process_vm_readv(pid, &mut [std::io::IoSliceMut::new(&mut data)], &[remote])
        .map_err(|source| CaptureError::TraceeRead { addr, len, source })?;
    Ok(data)
}

#[cfg(target_arch = "x86_64")]
fn read_syscall_regs(pid: Pid) -> Result<SyscallRegs, CaptureError> {
    let regs = ptrace::getregs(pid)?;
    Ok(SyscallRegs {
        nr: regs.orig_rax,
        ret: regs.rax as i64,
        args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
    })
}

#[cfg(target_arch = "aarch64")]
fn read_syscall_regs(pid: Pid) -> Result<SyscallRegs, CaptureError> {
    let regs = ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid)?;
    Ok(SyscallRegs {
        nr: regs.regs[8],
        ret: regs.regs[0] as i64,
        args: [
            regs.regs[0],
            regs.regs[1],
            regs.regs[2],
            regs.regs[3],
            regs.regs[4],
            regs.regs[5],
        ],
    })
}
