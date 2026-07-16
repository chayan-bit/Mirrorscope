//! Per-thread syscall register reads and trace-event construction.
//!
//! Kept independent of the scheduler so the multi-tracee loop only decides
//! *which* thread runs; this module turns a stopped thread's registers into
//! the tid-tagged [`Event`]s the trace stores.

use nix::sys::ptrace;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;

use crate::capture::error::CaptureError;
use crate::capture::payload::{SyscallEnter, SyscallExit};
use crate::trace::{Event, EventKind};

/// Raw syscall registers, normalized across architectures.
#[derive(Debug, Clone, Copy)]
pub struct SyscallRegs {
    /// Syscall number (architecture-specific).
    pub nr: u64,
    /// Return value (valid at syscall-exit).
    pub ret: i64,
    /// The six raw syscall arguments.
    pub args: [u64; 6],
}

/// Build a tid-tagged [`EventKind::SyscallEnter`] event for `regs`.
pub fn enter_event(timestamp_ns: u64, tid: u32, regs: &SyscallRegs) -> Event {
    let payload = SyscallEnter {
        nr: regs.nr,
        args: regs.args,
    }
    .encode();
    Event::new_with_tid(EventKind::SyscallEnter, timestamp_ns, tid, payload)
}

/// Build a tid-tagged [`EventKind::SyscallExit`] event, reading any
/// kernel-written result region out of the tracee.
pub fn exit_event(
    timestamp_ns: u64,
    tid: u32,
    pid: Pid,
    enter: &SyscallRegs,
    ret: i64,
) -> Result<Event, CaptureError> {
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
    Ok(Event::new_with_tid(
        EventKind::SyscallExit,
        timestamp_ns,
        tid,
        payload,
    ))
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
pub fn read_syscall_regs(pid: Pid) -> Result<SyscallRegs, CaptureError> {
    let regs = ptrace::getregs(pid)?;
    Ok(SyscallRegs {
        nr: regs.orig_rax,
        ret: regs.rax as i64,
        args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
    })
}

#[cfg(target_arch = "aarch64")]
pub fn read_syscall_regs(pid: Pid) -> Result<SyscallRegs, CaptureError> {
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
