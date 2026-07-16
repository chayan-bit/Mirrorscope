//! Linux hardware-watchpoint arming for the replay tracee (issue #12).
//!
//! Arms a CPU debug watchpoint on a ptrace-stopped tracee so the next access to
//! the watched range raises `SIGTRAP`, which the replay driver catches as a hit.
//! The two architectures use entirely different mechanisms:
//!
//! - **x86-64**: `PTRACE_POKEUSER` into the `struct user` debug-register slots
//!   (`DR0` holds the address, `DR7` the control word, `DR6` the sticky status).
//! - **aarch64**: `PTRACE_SETREGSET` with the `NT_ARM_HW_WATCH` regset, whose
//!   payload is a `user_hwdebug_state` carrying one `DBGWVR`/`DBGWCR` pair.
//!
//! The encoding math is portable and lives, unit-tested, in
//! [`crate::watchpoint`]; this module is only the raw ptrace plumbing. Debug
//! registers are **not** inherited across `fork`, so the session re-arms after
//! every checkpoint restore or respawn (a fresh tracee starts with them clear).
//!
//! A resume subtlety the caller must honour: on x86-64 a data watchpoint traps
//! *after* the access completes, so the driver simply continues. On aarch64 the
//! trap fires *before* the access, so continuing would re-trap the same
//! instruction forever; the caller must disarm, single-step over it, and re-arm
//! (see [`crate::session`]). Arming failures are surfaced as
//! [`ReplayError::Watchpoint`], never swallowed — a debugger that silently fails
//! to watch is worse than one that stops.

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::error::ReplayError;
use crate::watchpoint::{self, WatchKind};

/// `si_code` value the kernel sets on a `SIGTRAP` raised by a hardware
/// breakpoint or watchpoint (`TRAP_HWBKPT`, asm-generic).
const TRAP_HWBKPT: i32 = 4;

/// Arm debug slot 0 to watch `[addr, addr+len)` for accesses of `kind`.
pub(crate) fn arm(pid: Pid, addr: u64, len: u8, kind: WatchKind) -> Result<(), ReplayError> {
    arm_arch(pid, addr, len, kind)
}

/// Disarm the watchpoint, leaving the tracee's debug registers clear.
pub(crate) fn disarm(pid: Pid) -> Result<(), ReplayError> {
    disarm_arch(pid)
}

/// Whether the current `SIGTRAP` stop is a hardware watchpoint hit. Read via
/// `PTRACE_GETSIGINFO`; a `si_code` of `TRAP_HWBKPT` marks a debug-register trap
/// as opposed to a single-step, breakpoint, or ordinary signal.
pub(crate) fn is_watch_hit(pid: Pid) -> Result<bool, ReplayError> {
    let info = ptrace::getsiginfo(pid)?;
    Ok(info.si_code == TRAP_HWBKPT)
}

fn arm_error(reason: &'static str) -> ReplayError {
    ReplayError::Watchpoint { reason }
}

// ---------------------------------------------------------------------------
// x86-64
// ---------------------------------------------------------------------------

/// Byte offset of `u_debugreg[0]` inside `struct user` on x86-64 Linux. `DR0`
/// is here, `DR6` at `+48`, `DR7` at `+56` (each register is 8 bytes). This
/// layout is ABI-stable and is the same constant gdb and rr hardcode.
#[cfg(target_arch = "x86_64")]
const USER_DEBUGREG_OFFSET: usize = 848;

#[cfg(target_arch = "x86_64")]
const DR0_OFFSET: usize = USER_DEBUGREG_OFFSET;
#[cfg(target_arch = "x86_64")]
const DR6_OFFSET: usize = USER_DEBUGREG_OFFSET + 6 * 8;
#[cfg(target_arch = "x86_64")]
const DR7_OFFSET: usize = USER_DEBUGREG_OFFSET + 7 * 8;

#[cfg(target_arch = "x86_64")]
fn arm_arch(pid: Pid, addr: u64, len: u8, kind: WatchKind) -> Result<(), ReplayError> {
    let dr7 = watchpoint::x86_dr7(kind, len)?;
    poke_user(pid, DR0_OFFSET, addr)?;
    poke_user(pid, DR7_OFFSET, dr7)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn disarm_arch(pid: Pid) -> Result<(), ReplayError> {
    poke_user(pid, DR7_OFFSET, 0)
}

/// Clear the sticky `DR6` status after a hit so a later read never sees a stale
/// hit bit. x86-only; aarch64 has no equivalent sticky status to clear here.
#[cfg(target_arch = "x86_64")]
pub(crate) fn clear_status(pid: Pid) -> Result<(), ReplayError> {
    poke_user(pid, DR6_OFFSET, 0)
}

/// `PTRACE_POKEUSER`: write `data` at `offset` in the tracee's `struct user`.
/// nix 0.29 does not wrap `POKEUSER`, so this is a checked raw ptrace call,
/// mirroring the `NT_ARM_SYSTEM_CALL` raw call in [`crate::regs`].
#[cfg(target_arch = "x86_64")]
fn poke_user(pid: Pid, offset: usize, data: u64) -> Result<(), ReplayError> {
    // SAFETY: a raw PTRACE_POKEUSER on a ptrace-stopped tracee. `addr` is a
    // byte offset into the kernel-owned `struct user`; `data` is a plain
    // integer written by value (POKE* pass data by value, not by pointer).
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid.as_raw(),
            offset as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if ret == -1 {
        return Err(arm_error("PTRACE_POKEUSER on a debug register failed"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// aarch64
// ---------------------------------------------------------------------------

/// One `DBGWVR`/`DBGWCR` pair inside `user_hwdebug_state`.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HwDebugReg {
    addr: u64,
    ctrl: u32,
    pad: u32,
}

/// The `NT_ARM_HW_WATCH` regset payload with a single watchpoint slot. `dbg_info`
/// is read-only info the kernel ignores on write.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HwDebugState {
    dbg_info: u32,
    pad: u32,
    reg: HwDebugReg,
}

/// `PTRACE_GETREGSET`/`PTRACE_SETREGSET` note type for aarch64 watchpoints.
#[cfg(target_arch = "aarch64")]
const NT_ARM_HW_WATCH: libc::c_int = 0x403;

#[cfg(target_arch = "aarch64")]
fn arm_arch(pid: Pid, addr: u64, len: u8, kind: WatchKind) -> Result<(), ReplayError> {
    let (aligned, ctrl) = watchpoint::aarch64_control(addr, len, kind)?;
    let state = HwDebugState {
        reg: HwDebugReg {
            addr: aligned,
            ctrl,
            pad: 0,
        },
        ..HwDebugState::default()
    };
    set_hw_watch(pid, &state)
}

#[cfg(target_arch = "aarch64")]
fn disarm_arch(pid: Pid) -> Result<(), ReplayError> {
    // Enable bit clear (ctrl = 0) disarms the slot.
    set_hw_watch(pid, &HwDebugState::default())
}

/// `PTRACE_SETREGSET(NT_ARM_HW_WATCH)`: install `state` as the tracee's
/// watchpoint registers. nix 0.29 does not wrap this regset, so this is a
/// checked raw ptrace call.
#[cfg(target_arch = "aarch64")]
fn set_hw_watch(pid: Pid, state: &HwDebugState) -> Result<(), ReplayError> {
    let mut iov = libc::iovec {
        iov_base: (state as *const HwDebugState as *mut HwDebugState).cast::<libc::c_void>(),
        iov_len: core::mem::size_of::<HwDebugState>(),
    };
    // SAFETY: a raw PTRACE_SETREGSET on a ptrace-stopped tracee. `addr` selects
    // the NT_ARM_HW_WATCH regset; `data` points at `iov`, itself pointing at a
    // correctly sized `HwDebugState`. Both outlive the call and the kernel only
    // reads `iov_len` bytes; the pointer is used read-only by SETREGSET.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid.as_raw(),
            NT_ARM_HW_WATCH as *mut libc::c_void,
            (&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
        )
    };
    if ret == -1 {
        return Err(arm_error(
            "PTRACE_SETREGSET on the watchpoint regset failed",
        ));
    }
    Ok(())
}
