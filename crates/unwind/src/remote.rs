//! High-level convenience API for unwinding a stopped external process
//! (issue #8 groundwork: real DAP `stackTrace` during replay).
//!
//! [`RemoteUnwinder::for_pid`] parses `/proc/<pid>/maps`, loads every
//! file-backed module's ELF + CFI/DWARF data, and wraps a
//! [`RemoteMemory`](crate::memory::RemoteMemory) reader over the same pid.
//! [`RemoteUnwinder::backtrace`] then turns a register snapshot into a
//! symbolized frame list.
//!
//! Module load addresses always come from the live `/proc/<pid>/maps`, never
//! from a fixed/assumed base, so this is correct whether or not the target
//! runs under `ADDR_NO_RANDOMIZE` (recorder and replay disable ASLR for their
//! targets, but this module does not depend on that).
//!
//! This crate stays standalone: attaching to and stopping the target is the
//! caller's job (recorder/replay already own that ptrace lifecycle); this
//! type only reads registers and memory from an already-stopped tracee.

use std::path::Path;

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::maps;
use crate::memory::RemoteMemory;
use crate::symbolize::{SymbolizedFrame, Symbolizer};
use crate::unwinder::StackUnwinder;
use crate::{unwind_symbolized, InitialRegs, UnwindError};

/// Errors specific to attaching an unwinder to a remote process.
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    /// Reading `/proc/<pid>/maps` failed.
    #[error("failed to read /proc/{pid}/maps: {source}")]
    Maps {
        /// The process id whose maps could not be read.
        pid: i32,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A ptrace register read failed. The tracee must be ptrace-stopped.
    #[error("ptrace register read failed for pid {pid}: {source}")]
    Ptrace {
        /// The process id the register read targeted.
        pid: i32,
        /// Underlying ptrace errno.
        source: nix::Error,
    },
    /// Loading a module's ELF/CFI/DWARF data, or unwinding, failed.
    #[error(transparent)]
    Unwind(#[from] UnwindError),
}

/// Unwinds and symbolizes stacks of a stopped external process.
///
/// Construct with [`for_pid`](Self::for_pid) once the target is attached and
/// stopped (e.g. via `PTRACE_TRACEME`/`PTRACE_ATTACH` + `waitpid`, as the
/// recorder and replay crates already do); this type never attaches, stops,
/// or resumes the target itself.
pub struct RemoteUnwinder {
    pid: Pid,
    unwinder: StackUnwinder,
    symbolizer: Symbolizer,
    memory: RemoteMemory,
}

impl RemoteUnwinder {
    /// Load every file-backed module mapped into `pid` from `/proc/<pid>/maps`.
    ///
    /// A module whose ELF fails to parse (e.g. a deleted file, an unsupported
    /// format) is skipped rather than failing the whole load, so a partial
    /// backtrace is still possible when one module is unreadable.
    pub fn for_pid(pid: i32) -> Result<Self, RemoteError> {
        let modules = maps::read_process_modules(pid as u32)
            .map_err(|source| RemoteError::Maps { pid, source })?;

        let mut unwinder = StackUnwinder::new();
        let mut symbolizer = Symbolizer::new();
        for module in &modules {
            let path = Path::new(&module.path);
            let _ = unwinder.add_module(path, module.base);
            let _ = symbolizer.add_module(path, module.base);
        }

        Ok(Self {
            pid: Pid::from_raw(pid),
            unwinder,
            symbolizer,
            memory: RemoteMemory::new(pid),
        })
    }

    /// Read the leaf registers of the ptrace-stopped tracee.
    ///
    /// Fails if the target is not currently ptrace-stopped by the calling
    /// process (`ESRCH`/`EPERM` from the kernel).
    pub fn registers(&self) -> Result<InitialRegs, RemoteError> {
        read_registers(self.pid)
    }

    /// Unwind and symbolize from `regs`, reading stack memory from the target.
    pub fn backtrace(&mut self, regs: &InitialRegs) -> Result<Vec<SymbolizedFrame>, RemoteError> {
        let frames =
            unwind_symbolized(&mut self.unwinder, &self.symbolizer, regs, &mut self.memory)?;
        Ok(frames)
    }

    /// Convenience: read the tracee's current registers, then unwind and
    /// symbolize from them.
    pub fn backtrace_now(&mut self) -> Result<Vec<SymbolizedFrame>, RemoteError> {
        let regs = self.registers()?;
        self.backtrace(&regs)
    }
}

/// Build [`InitialRegs`] from `PTRACE_GETREGS`/`PTRACE_GETREGSET(NT_PRSTATUS)`
/// on x86-64: `rip`/`rsp`/`rbp` map directly; `lr` has no x86-64 equivalent.
#[cfg(target_arch = "x86_64")]
fn read_registers(pid: Pid) -> Result<InitialRegs, RemoteError> {
    let regs = ptrace::getregs(pid).map_err(|source| RemoteError::Ptrace {
        pid: pid.as_raw(),
        source,
    })?;
    Ok(InitialRegs {
        pc: regs.rip,
        sp: regs.rsp,
        fp: regs.rbp,
        lr: 0,
    })
}

/// Build [`InitialRegs`] from `PTRACE_GETREGSET(NT_PRSTATUS)` on aarch64:
/// `pc`/`sp` are dedicated fields, `fp` is `x29`, `lr` is `x30`.
#[cfg(target_arch = "aarch64")]
fn read_registers(pid: Pid) -> Result<InitialRegs, RemoteError> {
    let regs = ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid).map_err(|source| {
        RemoteError::Ptrace {
            pid: pid.as_raw(),
            source,
        }
    })?;
    Ok(InitialRegs {
        pc: regs.pc,
        sp: regs.sp,
        fp: regs.regs[29],
        lr: regs.regs[30],
    })
}
