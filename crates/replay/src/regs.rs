//! Architecture-normalized syscall register access for the replay tracee.
//!
//! Mirrors the recorder's `SyscallRegs` reading and adds the write paths replay
//! needs: cancelling a syscall at its entry stop and overwriting its return
//! value at its exit stop. x86-64 and aarch64 differ enough (especially in how
//! the syscall number is rewritten) that each has its own implementation.

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::error::ReplayError;

/// Raw syscall registers, normalized across architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    /// Syscall number (`orig_rax` / `x8`).
    pub nr: u64,
    /// Return value register (`rax` / `x0`) as a signed value.
    pub ret: i64,
    /// The six syscall argument registers.
    pub args: [u64; 6],
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn read(pid: Pid) -> Result<Registers, ReplayError> {
    let regs = ptrace::getregs(pid)?;
    Ok(Registers {
        nr: regs.orig_rax,
        ret: regs.rax as i64,
        args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
    })
}

/// Cancel the pending syscall at its entry stop by rewriting the dispatched
/// syscall number to -1, so the kernel returns `-ENOSYS` without running it.
#[cfg(target_arch = "x86_64")]
pub(crate) fn suppress_syscall(pid: Pid) -> Result<(), ReplayError> {
    let mut regs = ptrace::getregs(pid)?;
    regs.orig_rax = u64::MAX; // -1
    ptrace::setregs(pid, regs)?;
    Ok(())
}

/// Overwrite the return-value register at a syscall exit stop.
#[cfg(target_arch = "x86_64")]
pub(crate) fn set_return(pid: Pid, ret: i64) -> Result<(), ReplayError> {
    let mut regs = ptrace::getregs(pid)?;
    regs.rax = ret as u64;
    ptrace::setregs(pid, regs)?;
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn read(pid: Pid) -> Result<Registers, ReplayError> {
    let regs = ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid)?;
    Ok(Registers {
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

/// Cancel the pending syscall at its entry stop. On aarch64 the dispatched
/// syscall number lives in a dedicated regset and setting `x8` has no effect,
/// so it can only be changed via `NT_ARM_SYSTEM_CALL`.
#[cfg(target_arch = "aarch64")]
pub(crate) fn suppress_syscall(pid: Pid) -> Result<(), ReplayError> {
    set_syscall_nr(pid, -1)
}

/// Overwrite the return-value register (`x0`) at a syscall exit stop.
#[cfg(target_arch = "aarch64")]
pub(crate) fn set_return(pid: Pid, ret: i64) -> Result<(), ReplayError> {
    let mut regs = ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid)?;
    regs.regs[0] = ret as u64;
    ptrace::setregset::<ptrace::regset::NT_PRSTATUS>(pid, regs)?;
    Ok(())
}

/// Set the aarch64 dispatched syscall number via `PTRACE_SETREGSET` with the
/// `NT_ARM_SYSTEM_CALL` note type. nix 0.29 does not wrap this regset, so a raw
/// ptrace call is required; the payload is a single `int`.
#[cfg(target_arch = "aarch64")]
fn set_syscall_nr(pid: Pid, nr: libc::c_int) -> Result<(), ReplayError> {
    const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;
    let mut value: libc::c_int = nr;
    let mut iov = libc::iovec {
        iov_base: (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
        iov_len: core::mem::size_of::<libc::c_int>(),
    };
    // SAFETY: a raw PTRACE_SETREGSET on a ptrace-stopped tracee. `addr` selects
    // the NT_ARM_SYSTEM_CALL regset; `data` points at `iov`, itself pointing at
    // a correctly sized `c_int`. Both `value` and `iov` outlive the call, and
    // ptrace only reads `iov_len` bytes from `iov_base`.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid.as_raw(),
            NT_ARM_SYSTEM_CALL as *mut libc::c_void,
            (&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
        )
    };
    if ret != 0 {
        return Err(ReplayError::Ptrace(nix::errno::Errno::last()));
    }
    Ok(())
}
