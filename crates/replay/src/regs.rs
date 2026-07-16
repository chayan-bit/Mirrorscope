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

/// The full architectural register file, saved and restored verbatim around a
/// fork-snapshot injection so the tracee is left byte-for-byte as it was found.
pub(crate) type FullRegs = libc::user_regs_struct;

/// Snapshot every general-purpose register of the stopped tracee.
#[cfg(target_arch = "x86_64")]
pub(crate) fn save_full(pid: Pid) -> Result<FullRegs, ReplayError> {
    Ok(ptrace::getregs(pid)?)
}

/// Restore a previously [`save_full`]ed register file onto the stopped tracee.
#[cfg(target_arch = "x86_64")]
pub(crate) fn restore_full(pid: Pid, regs: &FullRegs) -> Result<(), ReplayError> {
    ptrace::setregs(pid, *regs)?;
    Ok(())
}

/// Rewrite a saved register file so that single-stepping re-executes the
/// preceding `syscall` instruction as `clone(SIGCHLD)` — the fork that mints a
/// copy-on-write snapshot. `rip` is rewound past the 2-byte `syscall` opcode.
#[cfg(target_arch = "x86_64")]
pub(crate) fn prepare_fork(regs: &mut FullRegs) {
    regs.rip = regs.rip.wrapping_sub(2);
    regs.rax = libc::SYS_clone as u64;
    regs.orig_rax = libc::SYS_clone as u64;
    regs.rdi = libc::SIGCHLD as u64; // clone flags: fork-like, no CLONE_VM
    regs.rsi = 0; // child stack (0 → share/COW parent stack, fork semantics)
    regs.rdx = 0;
    regs.r10 = 0;
    regs.r8 = 0;
    regs.r9 = 0;
}

/// Snapshot every general-purpose register of the stopped tracee.
#[cfg(target_arch = "aarch64")]
pub(crate) fn save_full(pid: Pid) -> Result<FullRegs, ReplayError> {
    Ok(ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid)?)
}

/// Restore a previously [`save_full`]ed register file onto the stopped tracee.
#[cfg(target_arch = "aarch64")]
pub(crate) fn restore_full(pid: Pid, regs: &FullRegs) -> Result<(), ReplayError> {
    ptrace::setregset::<ptrace::regset::NT_PRSTATUS>(pid, *regs)?;
    Ok(())
}

/// Rewrite a saved register file so that single-stepping re-executes the
/// preceding `svc #0` instruction as `clone(SIGCHLD)`. `pc` is rewound past the
/// 4-byte `svc` opcode; a freshly re-executed `svc` reads its number from `x8`,
/// so the `NT_ARM_SYSTEM_CALL` override needed for in-flight syscalls is moot.
#[cfg(target_arch = "aarch64")]
pub(crate) fn prepare_fork(regs: &mut FullRegs) {
    regs.pc = regs.pc.wrapping_sub(4);
    regs.regs[8] = libc::SYS_clone as u64;
    regs.regs[0] = libc::SIGCHLD as u64; // clone flags: fork-like, no CLONE_VM
    regs.regs[1] = 0; // child stack (0 → share/COW parent stack)
    regs.regs[2] = 0;
    regs.regs[3] = 0;
    regs.regs[4] = 0;
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
