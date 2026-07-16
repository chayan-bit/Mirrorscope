//! Userspace half of the eBPF syscall capture path (issue #14): loads the
//! `recorder-ebpf-programs` object, attaches the `sys_enter`/`sys_exit`
//! raw-tracepoint pair filtered to the target's tgid, and drains the ring
//! buffer into the existing trace format.
//!
//! ## What this does *not* yet capture, vs the ptrace path
//!
//! - **No memory payload capture.** `recorder::capture::syscall::exit_event`
//!   pulls the kernel-written region behind `read()`/`recvfrom()`/
//!   `getrandom()`/`clock_gettime()` out of the tracee with
//!   `process_vm_readv`. The eBPF program does not (see
//!   `crates/recorder-ebpf-programs/src/main.rs` for why: it needs a second
//!   `bpf_probe_read_user` pass keyed off exit-time pointer + length).
//!   Every [`SyscallExit`] payload this backend writes has an empty `data`.
//! - **No serialization.** This backend records observation only; it cannot
//!   pause a thread at a syscall boundary, so it has nothing to say about
//!   the single-core interleaving [`EventKind::SchedSwitch`] captures.
//!   Multi-threaded targets are not yet supported by this backend at all.
//! - **No thread/process following.** One target tgid, no `ThreadSpawn`/
//!   `ThreadExit`/`Fork` events. Matches ptrace's issue #4 baseline, not its
//!   issue #9 multi-threaded extension.
//! - **A startup race.** The tgid filter is configured *after*
//!   [`std::process::Command::spawn`] returns, i.e. after the target has
//!   already started executing — so its first handful of syscalls (usually
//!   dynamic-linker `mmap`/`openat` churn before `main`) can run before the
//!   filter is live and go uncaptured. An earlier version of this backend
//!   tried to close that window by raising `SIGSTOP` in a `pre_exec` hook and
//!   resuming after configuring the filter; that deadlocks `Command::spawn`
//!   itself (its internal exec-error pipe doesn't close until the child
//!   execs or exits, and a `SIGSTOP`'d child does neither), so it's not what
//!   ships here. A real fix needs either a raw `fork`+manual-`execve` (no
//!   `std::process::Command` synchronization to fight) or scoping capture by
//!   cgroup/pid-namespace instead of a post-spawn tgid write.
//!
//! This matches README §4's hybrid design: eBPF replaces ptrace for the
//! "what syscall happened, with what result" observation (2 ptrace stops per
//! syscall → 0), while ptrace remains the tool for anything that needs to
//! *pause* the target (serialization points, sync-primitive uprobes).
//!
//! [`SyscallExit`]: recorder::capture::payload::SyscallExit
//! [`EventKind::SchedSwitch`]: recorder::trace::EventKind::SchedSwitch

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use aya::maps::{Array, RingBuf};
use aya::programs::RawTracePoint;
use aya::Ebpf;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use recorder::capture::payload::{SyscallEnter, SyscallExit};
use recorder::capture::RecordOutcome;
use recorder::trace::{Event, EventKind, TraceError, TraceWriter};
use recorder_ebpf_common::{RawSyscallEvent, KIND_ENTER, KIND_EXIT};

use crate::error::EbpfCaptureError;

/// Record `program args…` into a trace file at `trace_path`, capturing
/// syscalls via the eBPF object at `bpf_object_path` instead of ptrace.
///
/// Single-threaded only (see module docs for the full gap list). Requires
/// root (`CAP_BPF`/`CAP_PERFMON`) and a BTF-enabled kernel.
pub fn record_command(
    program: &str,
    args: &[String],
    trace_path: &Path,
    bpf_object_path: &Path,
) -> Result<RecordOutcome, EbpfCaptureError> {
    let mut bpf = load_and_attach(bpf_object_path)?;

    let events_map = bpf
        .take_map("EVENTS")
        .ok_or(EbpfCaptureError::MissingMap { name: "EVENTS" })?;
    let mut ring_buf = RingBuf::try_from(events_map).map_err(|source| EbpfCaptureError::Map {
        name: "EVENTS",
        source,
    })?;

    // Spawn, then configure the filter immediately: see the module docs'
    // "startup race" gap for why this isn't SIGSTOP-held first.
    let child_pid = spawn(program, args)?;
    configure_target(&mut bpf, child_pid)?;

    let file = File::create(trace_path).map_err(TraceError::Io)?;
    let mut writer = TraceWriter::create_with_cmdline(BufWriter::new(file), program, args)?;
    drain_until_exit(&mut ring_buf, &mut writer, child_pid)
}

fn load_and_attach(bpf_object_path: &Path) -> Result<Ebpf, EbpfCaptureError> {
    let mut bpf =
        Ebpf::load_file(bpf_object_path).map_err(|source| EbpfCaptureError::LoadObject {
            path: bpf_object_path.display().to_string(),
            source: Box::new(source),
        })?;
    attach_raw_tracepoint(&mut bpf, "sys_enter")?;
    attach_raw_tracepoint(&mut bpf, "sys_exit")?;
    Ok(bpf)
}

fn attach_raw_tracepoint(bpf: &mut Ebpf, name: &'static str) -> Result<(), EbpfCaptureError> {
    let program: &mut RawTracePoint = bpf
        .program_mut(name)
        .ok_or(EbpfCaptureError::MissingProgram { name })?
        .try_into()
        .map_err(|source| EbpfCaptureError::Program { name, source })?;
    program
        .load()
        .map_err(|source| EbpfCaptureError::Program { name, source })?;
    program
        .attach(name)
        .map_err(|source| EbpfCaptureError::Program { name, source })?;
    Ok(())
}

/// Spawn the target. No ptrace involved: we're the real parent, so a plain
/// `waitpid` controls it (see [`drain_until_exit`]). See the module docs'
/// "startup race" gap: the tracepoints are already attached at this point
/// (loaded before this is called), but the tgid filter isn't configured
/// until just after this returns, so the target's very first syscalls can
/// run unobserved.
fn spawn(program: &str, args: &[String]) -> Result<Pid, EbpfCaptureError> {
    let mut command = Command::new(program);
    command.args(args);
    let child = command.spawn().map_err(EbpfCaptureError::Spawn)?;
    let pid = Pid::from_raw(child.id() as i32);
    // Don't let `Child`'s Drop reap it out from under our own waitpid calls.
    std::mem::forget(child);
    Ok(pid)
}

fn configure_target(bpf: &mut Ebpf, target: Pid) -> Result<(), EbpfCaptureError> {
    let map = bpf
        .map_mut("TARGET_TGID")
        .ok_or(EbpfCaptureError::MissingMap {
            name: "TARGET_TGID",
        })?;
    let mut tgid_map: Array<_, u32> =
        Array::try_from(map).map_err(|source| EbpfCaptureError::Map {
            name: "TARGET_TGID",
            source,
        })?;
    tgid_map
        .set(0, target.as_raw() as u32, 0)
        .map_err(|source| EbpfCaptureError::Map {
            name: "TARGET_TGID",
            source,
        })?;
    Ok(())
}

/// Poll the ring buffer and the target's exit status until it exits, then
/// drain whatever's left. `recorder-ebpf-programs` doesn't re-derive the
/// syscall number on exit (it isn't in `sys_exit`'s raw tracepoint args), so
/// this pairs each exit with the most recent enter seen for the same tid —
/// mirroring how the two are already correlated by tid in the trace format.
fn drain_until_exit(
    ring_buf: &mut RingBuf<aya::maps::MapData>,
    writer: &mut TraceWriter<BufWriter<File>>,
    target: Pid,
) -> Result<RecordOutcome, EbpfCaptureError> {
    let mut pending_nr: HashMap<u32, u64> = HashMap::new();
    let mut events_recorded = 0u64;
    let mut exit_code = None;

    loop {
        events_recorded += drain_ready(ring_buf, writer, &mut pending_nr)?;
        match waitpid(target, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::StillAlive => std::thread::sleep(Duration::from_micros(200)),
            WaitStatus::Exited(_, code) => {
                exit_code = Some(code);
                break;
            }
            WaitStatus::Signaled(..) => break,
            _ => {}
        }
    }
    // The target may have exited with events still sitting in the ring
    // buffer between our last poll and its exit; drain once more.
    events_recorded += drain_ready(ring_buf, writer, &mut pending_nr)?;

    Ok(RecordOutcome {
        exit_code,
        events_recorded,
        threads_followed: 1,
    })
}

fn drain_ready(
    ring_buf: &mut RingBuf<aya::maps::MapData>,
    writer: &mut TraceWriter<BufWriter<File>>,
    pending_nr: &mut HashMap<u32, u64>,
) -> Result<u64, EbpfCaptureError> {
    let mut written = 0u64;
    while let Some(item) = ring_buf.next() {
        let Some(raw) = RawSyscallEvent::decode(&item) else {
            continue; // Short/corrupt read; skip rather than fail the whole capture.
        };
        let event = match raw.kind {
            KIND_ENTER => {
                pending_nr.insert(raw.tid, raw.nr);
                let payload = SyscallEnter {
                    nr: raw.nr,
                    args: raw.args,
                }
                .encode();
                Event::new_with_tid(EventKind::SyscallEnter, raw.timestamp_ns, raw.tid, payload)
            }
            KIND_EXIT => {
                let nr = pending_nr.remove(&raw.tid).unwrap_or(0);
                let payload = SyscallExit {
                    nr,
                    ret: raw.ret,
                    data: Vec::new(), // Honest gap: see module docs.
                }
                .encode();
                Event::new_with_tid(EventKind::SyscallExit, raw.timestamp_ns, raw.tid, payload)
            }
            _ => continue,
        };
        writer.append(&event)?;
        written += 1;
    }
    Ok(written)
}
