//! [`PtraceProcessView`]: a Linux ptrace-backed [`ProcessView`] over a real,
//! already-attached-and-stopped process.
//!
//! This is the live-process counterpart to the [`ProcessView`] `replay` will
//! implement over a restored checkpoint (tracked by #8/#27): the same
//! [`crate::native::NativeThreadsDecoder`] (and every future language
//! decoder) runs unmodified against either backend. It exists so the decoder
//! crate is exercisable against a real target without waiting on the replay
//! engine, and so a future "attach live, no recording" debugging mode has
//! somewhere to plug in.
//!
//! Attaching to and stopping every thread is the caller's responsibility —
//! mirroring how [`unwind::RemoteUnwinder`] treats the ptrace lifecycle —
//! this type only enumerates and reads an already-stopped target. Threads
//! are enumerated once, at [`PtraceProcessView::for_pid`] time, from
//! `/proc/<pid>/task`; a thread that exits afterward simply fails its next
//! read rather than being pruned from [`ProcessView::thread_ids`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::IoSliceMut;

use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use unwind::RemoteUnwinder;

use crate::error::DecoderError;
use crate::process_view::{PhysicalFrame, ProcessView, Registers, ThreadId};

/// Failure modes specific to constructing a [`PtraceProcessView`].
#[derive(Debug, thiserror::Error)]
pub enum PtraceViewError {
    /// `/proc/<pid>/task` could not be listed (the process does not exist,
    /// or we lack permission).
    #[error("failed to enumerate threads of pid {pid}: {source}")]
    EnumerateThreads {
        /// The process id whose threads could not be listed.
        pid: i32,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Loading module/ELF data for one thread's unwinder failed. Each
    /// thread gets its own [`RemoteUnwinder`] (module loading is per-tid,
    /// see [`for_pid`](PtraceProcessView::for_pid)), so one thread's
    /// modules failing to load does not affect the others.
    #[error("failed to prepare unwinder for thread {tid} of pid {pid}: {source}")]
    Unwinder {
        /// The process id the thread belongs to.
        pid: i32,
        /// The thread id whose unwinder failed to build.
        tid: i32,
        /// Underlying unwind-crate failure.
        source: unwind::RemoteError,
    },
}

/// Per-thread state: a dedicated unwinder (ptrace + module data is scoped to
/// one tid) and the thread's `/proc/<pid>/task/<tid>/comm` name.
///
/// [`RemoteUnwinder::backtrace_now`] takes `&mut self`, but [`ProcessView`]
/// methods take `&self` (an object-safe read-only view shared across
/// callers); the [`RefCell`] bridges that without requiring `unsafe` or a
/// mutex this single-threaded caller does not need.
struct ThreadView {
    unwinder: RefCell<RemoteUnwinder>,
    comm: String,
}

/// A [`ProcessView`] backed by ptrace against a real, already-attached and
/// ptrace-stopped Linux process.
///
/// Construct once per debugging session with [`Self::for_pid`]; every
/// [`ProcessView`] call after that reads fresh state from the live target
/// (registers, memory, and an unwound stack), so callers see the process's
/// current stopped state on every call rather than a stale snapshot.
pub struct PtraceProcessView {
    pid: i32,
    threads: HashMap<ThreadId, ThreadView>,
}

impl std::fmt::Debug for PtraceProcessView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `unwind::RemoteUnwinder` does not implement `Debug`, so this
        // reports the identifying shape (pid, thread count) rather than
        // deriving.
        f.debug_struct("PtraceProcessView")
            .field("pid", &self.pid)
            .field("thread_count", &self.threads.len())
            .finish()
    }
}

impl PtraceProcessView {
    /// Build a view over every thread currently listed in
    /// `/proc/<pid>/task`.
    ///
    /// Every thread must already be ptrace-attached and stopped by the
    /// caller (e.g. `PTRACE_ATTACH` + `waitpid` per tid) before calling
    /// this — see the module docs. A [`unwind::RemoteUnwinder`] is built per
    /// thread rather than shared, because module loading in `unwind` is
    /// scoped to a single tid's `/proc/<tid>/maps` (which, for threads in
    /// one process, all describe the same shared address space, so the
    /// modules loaded are identical — the duplication trades a little
    /// per-thread setup cost for reusing `unwind`'s API unmodified).
    ///
    /// # Errors
    /// Returns [`PtraceViewError::EnumerateThreads`] if `/proc/<pid>/task`
    /// cannot be listed, or [`PtraceViewError::Unwinder`] if any thread's
    /// module data fails to load.
    pub fn for_pid(pid: i32) -> Result<Self, PtraceViewError> {
        let tids =
            task_ids(pid).map_err(|source| PtraceViewError::EnumerateThreads { pid, source })?;

        let mut threads = HashMap::with_capacity(tids.len());
        for tid in tids {
            let unwinder = RemoteUnwinder::for_pid(tid)
                .map_err(|source| PtraceViewError::Unwinder { pid, tid, source })?;
            let comm = read_comm(pid, tid).unwrap_or_default();
            threads.insert(
                ThreadId::new(tid as u64),
                ThreadView {
                    unwinder: RefCell::new(unwinder),
                    comm,
                },
            );
        }

        Ok(Self { pid, threads })
    }

    /// The thread's `/proc/<pid>/task/<tid>/comm` name, if the thread was
    /// present when [`Self::for_pid`] enumerated it.
    ///
    /// Not part of [`ProcessView`] (which stays name-agnostic — decoders
    /// mint their own display names, see
    /// [`crate::native::NativeThreadsDecoder`]); exposed here purely as a
    /// diagnostic for callers/tests that want to sanity-check thread
    /// identity against `/proc`.
    #[must_use]
    pub fn thread_name(&self, thread: ThreadId) -> Option<&str> {
        self.threads.get(&thread).map(|view| view.comm.as_str())
    }

    fn thread_view(&self, thread: ThreadId) -> Result<&ThreadView, DecoderError> {
        self.threads
            .get(&thread)
            .ok_or(DecoderError::UnknownThread(thread))
    }
}

impl ProcessView for PtraceProcessView {
    fn thread_ids(&self) -> Vec<ThreadId> {
        let mut ids: Vec<ThreadId> = self.threads.keys().copied().collect();
        ids.sort();
        ids
    }

    fn registers(&self, thread: ThreadId) -> Result<Registers, DecoderError> {
        let view = self.thread_view(thread)?;
        let regs = view.unwinder.borrow().registers().map_err(|source| {
            DecoderError::RegisterReadFailed {
                thread,
                reason: source.to_string(),
            }
        })?;
        Ok(Registers {
            pc: regs.pc,
            sp: regs.sp,
        })
    }

    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, DecoderError> {
        let mut buf = vec![0u8; len];
        let remote = RemoteIoVec {
            base: addr as usize,
            len,
        };
        process_vm_readv(
            Pid::from_raw(self.pid),
            &mut [IoSliceMut::new(&mut buf)],
            &[remote],
        )
        .map_err(|source| DecoderError::MemoryReadFailed {
            addr,
            len,
            reason: source.to_string(),
        })?;
        Ok(buf)
    }

    fn thread_pointer(&self, thread: ThreadId) -> Result<Option<u64>, DecoderError> {
        // Validate the thread belongs to this view before touching ptrace.
        self.thread_view(thread)?;
        let tid = thread.0 as i32;
        read_thread_pointer(tid).map_err(|reason| DecoderError::RegisterReadFailed {
            thread,
            reason,
        })
    }

    fn executable_base(&self) -> Option<u64> {
        executable_base(self.pid)
    }

    fn physical_frames(&self, thread: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError> {
        let view = self.thread_view(thread)?;
        let leaf_sp = self.registers(thread)?.sp;
        let frames = view
            .unwinder
            .borrow_mut()
            .backtrace_now()
            .map_err(|source| DecoderError::PhysicalFramesFailed {
                thread,
                reason: source.to_string(),
            })?;

        Ok(frames
            .into_iter()
            .enumerate()
            .map(|(index, frame)| PhysicalFrame {
                pc: frame.address,
                // `unwind::RemoteUnwinder` only exposes lookup addresses,
                // not a per-frame stack pointer; the leaf frame's sp is the
                // one register value we do have, everything above it is 0
                // rather than a guessed value (see CLAUDE.md's honesty
                // rule: never show a wrong value silently).
                sp: if index == 0 { leaf_sp } else { 0 },
                function_name: frame.function,
                location: frame.file.map(|path| crate::model::SourceLocation {
                    path,
                    line: frame.line.unwrap_or(0),
                    column: 0,
                }),
            })
            .collect())
    }
}

/// List every thread id under `/proc/<pid>/task`.
fn task_ids(pid: i32) -> std::io::Result<Vec<i32>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        let entry = entry?;
        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            ids.push(tid);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Read and trim `/proc/<pid>/task/<tid>/comm`.
fn read_comm(pid: i32, tid: i32) -> std::io::Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))?;
    Ok(raw.trim_end().to_string())
}

/// The runtime load base of the main executable: the lowest mapped address in
/// `/proc/<pid>/maps` backed by the file `/proc/<pid>/exe` points to.
fn executable_base(pid: i32) -> Option<u64> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let exe = exe.to_str()?;
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    maps.lines()
        .filter(|line| line.ends_with(exe))
        .filter_map(|line| line.split('-').next())
        .filter_map(|hex| u64::from_str_radix(hex, 16).ok())
        .min()
}

/// The ptrace note type for the aarch64 TLS register set (`NT_ARM_TLS`), not
/// exported by `libc`.
#[cfg(target_arch = "aarch64")]
const NT_ARM_TLS: libc::c_int = 0x401;

/// Read a ptrace-stopped thread's thread-pointer register.
///
/// `Ok(Some(tp))` on success, `Ok(None)` on an architecture with no supported
/// reader, `Err(reason)` if the ptrace read failed. The caller must already be
/// this thread's tracer with the thread stopped.
#[allow(unsafe_code)]
#[cfg(target_arch = "aarch64")]
fn read_thread_pointer(tid: i32) -> Result<Option<u64>, String> {
    let mut tp: u64 = 0;
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(tp).cast(),
        iov_len: std::mem::size_of::<u64>(),
    };
    // SAFETY: `iov` points at a live `u64` of matching length; ptrace only
    // writes the TLS register into it. `tid` is a thread this process traces.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            tid,
            NT_ARM_TLS as *mut libc::c_void,
            std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(Some(tp))
}

/// x86-64 thread pointer: `fs_base` from the general register set.
#[allow(unsafe_code)]
#[cfg(target_arch = "x86_64")]
fn read_thread_pointer(tid: i32) -> Result<Option<u64>, String> {
    // SAFETY: `regs` is a correctly-sized, owned `user_regs_struct`; ptrace
    // fills it for the stopped, traced thread `tid`.
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::addr_of_mut!(regs).cast::<libc::c_void>(),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(Some(regs.fs_base))
}

/// Fallback for architectures without a thread-pointer reader.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn read_thread_pointer(_tid: i32) -> Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_ids_lists_the_calling_process_own_threads() {
        let pid = std::process::id() as i32;
        let ids = task_ids(pid).expect("list /proc/self-equivalent task dir");
        assert!(ids.contains(&pid), "main thread tid equals pid: {ids:?}");
    }

    #[test]
    fn read_comm_reads_a_non_empty_name() {
        let pid = std::process::id() as i32;
        let comm = read_comm(pid, pid).expect("read own comm");
        assert!(!comm.is_empty());
    }

    #[test]
    fn for_pid_on_a_nonexistent_pid_errors() {
        let err = PtraceProcessView::for_pid(-1).expect_err("pid -1 has no /proc entry");
        assert!(matches!(err, PtraceViewError::EnumerateThreads { .. }));
    }
}
