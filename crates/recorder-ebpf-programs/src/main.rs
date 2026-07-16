//! Kernel-side syscall capture (issue #14): a `raw_tracepoint` pair on
//! `sys_enter`/`sys_exit`, filtered to one target tgid, writing
//! [`RawSyscallEvent`] records into a ring buffer for `recorder-ebpf`
//! (userspace) to drain.
//!
//! Honest scope of this slice: syscall number, the six raw argument words,
//! and the return value. It does **not** yet read the kernel-written memory
//! region behind `read()`/`recvfrom()`/`getrandom()`/`clock_gettime()` the
//! way `recorder::capture::syscall::exit_event` does over ptrace — that needs
//! a second `bpf_probe_read_user` pass keyed off the (arch-specific, and for
//! several of these syscalls, exit-time-only-known) buffer pointer + length,
//! deferred to keep this first slice reviewable. See `README.md` in this
//! crate and `crates/recorder-ebpf/src/lib.rs` for the full gap list against
//! the ptrace path.
#![no_std]
#![no_main]

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel};
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::RawTracePointContext;
use aya_ebpf::EbpfContext;
use recorder_ebpf_common::{RawSyscallEvent, KIND_ENTER, KIND_EXIT, RAW_EVENT_LEN};

/// Read raw tracepoint argument `n`: `bpf_raw_tracepoint_args.args[n]`.
/// `aya-ebpf` 0.1's `RawTracePointContext` doesn't wrap this (that came
/// later, as an unsafe `ctx.arg()` — see aya's `raw_tracepoint_arg` helper),
/// so this reads the same way the C convention does: `ctx.as_ptr()` is a
/// `*mut bpf_raw_tracepoint_args`, whose `args: [u64; N]` field the verifier
/// allows direct (non-`bpf_probe_read`) access to.
///
/// SAFETY: `ctx` came from the kernel's raw_tracepoint invocation; `n` must
/// be within the argument count the specific tracepoint (`sys_enter`/
/// `sys_exit`, both 2 args) actually provides — the verifier does not bounds
/// check this indexing.
#[allow(unsafe_code)]
unsafe fn raw_tracepoint_arg(ctx: &RawTracePointContext, n: usize) -> u64 {
    *(ctx.as_ptr() as *const u64).add(n)
}

/// Single-slot config map: the tgid to capture, written by the userspace
/// loader right after spawning the target (see `crates/recorder-ebpf`'s
/// module docs for the resulting startup-race gap). `0` means "no target
/// configured yet" — every enter/exit is dropped rather than matching tgid 0
/// (the swapper/idle task can't be a userspace target anyway).
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

/// Captured syscall events, drained by `recorder-ebpf`'s userspace loader.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let _ = try_sys_enter(&ctx);
    0
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn sys_exit(ctx: RawTracePointContext) -> i32 {
    let _ = try_sys_exit(&ctx);
    0
}

/// `sys_enter`'s raw tracepoint args: `args[0] = struct pt_regs *regs`,
/// `args[1] = long syscall_nr`. Reading `pt_regs` at all is only needed for
/// the six argument registers; the syscall number is already `args[1]`.
fn try_sys_enter(ctx: &RawTracePointContext) -> Result<(), ()> {
    let Some((tgid, tid)) = matching_target()? else {
        return Ok(());
    };
    // `sys_enter`'s layout (regs ptr, syscall nr) is a stable kernel ABI
    // (include/trace/events/syscalls.h).
    // SAFETY: sys_enter provides exactly these 2 raw tracepoint args.
    #[allow(unsafe_code)]
    let (regs_ptr, nr) = unsafe { (raw_tracepoint_arg(ctx, 0), raw_tracepoint_arg(ctx, 1)) };
    let args = read_syscall_args(regs_ptr)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    emit(&RawSyscallEvent {
        kind: KIND_ENTER,
        tgid,
        tid,
        timestamp_ns,
        nr,
        args,
        ret: 0,
    })
}

/// `sys_exit`'s raw tracepoint args: `args[0] = struct pt_regs *regs`,
/// `args[1] = long ret`. The syscall number isn't re-derived here (the
/// userspace side pairs enter/exit by tid, matching `recorder`'s own
/// convention); `nr` is left `0` and userspace fills it from the paired
/// enter record, same as it must for the ptrace path's exit records.
fn try_sys_exit(ctx: &RawTracePointContext) -> Result<(), ()> {
    let Some((tgid, tid)) = matching_target()? else {
        return Ok(());
    };
    // SAFETY: sys_exit provides exactly 2 raw tracepoint args.
    #[allow(unsafe_code)]
    let ret = unsafe { raw_tracepoint_arg(ctx, 1) } as i64;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    emit(&RawSyscallEvent {
        kind: KIND_EXIT,
        tgid,
        tid,
        timestamp_ns,
        nr: 0,
        args: [0; 6],
        ret,
    })
}

/// Returns `Some((tgid, tid))` of the current task if a target tgid is
/// configured and matches; `None` (not an error) if it doesn't match, so
/// callers can cheaply bail without emitting anything.
fn matching_target() -> Result<Option<(u32, u32)>, ()> {
    let target = TARGET_TGID.get(0).copied().unwrap_or(0);
    if target == 0 {
        return Ok(None);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid != target {
        return Ok(None);
    }
    let tid = pid_tgid as u32;
    Ok(Some((tgid, tid)))
}

fn emit(event: &RawSyscallEvent) -> Result<(), ()> {
    let bytes = event.encode();
    let Some(mut entry) = EVENTS.reserve::<[u8; RAW_EVENT_LEN]>(0) else {
        // Ring buffer full: drop the event. Surfaced to the user as a gap in
        // the trace's tid-paired enter/exit stream, not silently — the
        // userspace collector counts drops (see `recorder-ebpf`).
        return Err(());
    };
    entry.write(bytes);
    entry.submit(0);
    Ok(())
}

/// Read the six syscall argument registers out of the tracee's `pt_regs` at
/// `regs_ptr`. Layout is architecture-specific and selected at *build* time
/// (`--features x86_64` / `--features aarch64`) because the BPF program
/// itself always compiles for the arch-independent `bpfel-unknown-none`
/// target — `cfg(target_arch)` can't distinguish the deployment host here.
#[cfg(feature = "x86_64")]
fn read_syscall_args(regs_ptr: u64) -> Result<[u64; 6], ()> {
    // Kernel `struct pt_regs` (arch/x86/include/asm/ptrace.h), 64-bit build:
    // field order r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,…
    // — the same order `nix::sys::ptrace::getregs` exposes, which is what
    // `recorder::capture::syscall::read_syscall_regs` reads on x86_64.
    const OFF_RDI: usize = 112;
    const OFF_RSI: usize = 104;
    const OFF_RDX: usize = 96;
    const OFF_R10: usize = 56;
    const OFF_R8: usize = 72;
    const OFF_R9: usize = 64;

    let rdi = read_u64_at(regs_ptr, OFF_RDI)?;
    let rsi = read_u64_at(regs_ptr, OFF_RSI)?;
    let rdx = read_u64_at(regs_ptr, OFF_RDX)?;
    let r10 = read_u64_at(regs_ptr, OFF_R10)?;
    let r8 = read_u64_at(regs_ptr, OFF_R8)?;
    let r9 = read_u64_at(regs_ptr, OFF_R9)?;
    Ok([rdi, rsi, rdx, r10, r8, r9])
}

/// Kernel `struct pt_regs` (arch/arm64/include/asm/ptrace.h): `u64
/// regs[31]` is the first field, so `x0..x5` (the six syscall argument
/// registers) sit at byte offset `0..48` with no preceding fields to skip —
/// matching `nix::sys::ptrace::getregset::<NT_PRSTATUS>` regs[0..6] read by
/// `recorder::capture::syscall::read_syscall_regs` on aarch64.
#[cfg(feature = "aarch64")]
fn read_syscall_args(regs_ptr: u64) -> Result<[u64; 6], ()> {
    let mut args = [0u64; 6];
    for (i, arg) in args.iter_mut().enumerate() {
        *arg = read_u64_at(regs_ptr, i * 8)?;
    }
    Ok(args)
}

#[cfg(not(any(feature = "x86_64", feature = "aarch64")))]
fn read_syscall_args(_regs_ptr: u64) -> Result<[u64; 6], ()> {
    compile_error!(
        "recorder-ebpf-programs must be built with --features x86_64 or --features aarch64"
    );
}

#[cfg(any(feature = "x86_64", feature = "aarch64"))]
fn read_u64_at(base: u64, offset: usize) -> Result<u64, ()> {
    // SAFETY: `base` is the `pt_regs` pointer the kernel handed the
    // tracepoint; `bpf_probe_read_kernel` is the verifier-checked helper for
    // reading kernel memory that might not be mapped (the eBPF equivalent of
    // `process_vm_readv` in the ptrace path).
    unsafe { bpf_probe_read_kernel((base as *const u8).add(offset) as *const u64) }.map_err(|_| ())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
