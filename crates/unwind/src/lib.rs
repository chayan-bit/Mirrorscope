//! Layer 5 — native stack unwinding + symbolization.
//!
//! Turns `(module list + registers + memory access)` into a symbolized native
//! stack trace on x86-64 and aarch64 Linux ELF binaries. The heavy lifting is
//! reused, not re-derived: [`framehop`] performs CFI/frame-pointer unwinding
//! (correct on ARM without perf counters) and [`addr2line`] resolves addresses
//! to functions/files/lines over the same object files.
//!
//! This crate is deliberately standalone: it depends on neither the recorder
//! nor the replay crate. It unwinds over an abstract [`MemoryReader`], so the
//! same code path serves the in-process case (tests, via [`SelfMemory`]) and,
//! later, the replayed tracee (issue #8 wires a `process_vm_readv`-based reader
//! and the DAP `stackTrace` request onto this API).
//!
//! # Address vocabulary
//!
//! - **AVMA** — actual virtual memory address: where a byte lives in the target
//!   process right now (what registers hold, what a stack read returns).
//! - **SVMA** — stated virtual memory address: the address as written in the
//!   ELF file (section/DWARF addresses). For ELF, `avma = base_avma + svma`.
//!
//! Callers supply a module's *mapping base* (the load address from
//! `/proc/<pid>/maps`); this crate derives `base_avma` from the ELF program
//! headers so the identity above holds for both PIE and non-PIE binaries.
//!
//! # Example shape
//!
//! ```no_run
//! # #[cfg(target_os = "linux")] {
//! use std::path::Path;
//! use unwind::{StackUnwinder, Symbolizer, SelfMemory, InitialRegs, unwind_symbolized};
//!
//! let mut unwinder = StackUnwinder::new();
//! let mut symbolizer = Symbolizer::new();
//! for module in unwind::maps::read_self_modules().expect("maps") {
//!     let _ = unwinder.add_module(Path::new(&module.path), module.base);
//!     let _ = symbolizer.add_module(Path::new(&module.path), module.base);
//! }
//! let regs = InitialRegs { pc: 0, sp: 0, fp: 0, lr: 0 };
//! let mut mem = SelfMemory::new().expect("self mem");
//! let frames = unwind_symbolized(&mut unwinder, &symbolizer, &regs, &mut mem);
//! # }
//! ```

mod elf;
pub mod maps;
pub mod memory;
pub mod symbolize;
pub mod unwinder;

pub use memory::{MemoryError, MemoryReader};
pub use symbolize::{SymbolizedFrame, Symbolizer};
pub use unwinder::StackUnwinder;

#[cfg(target_os = "linux")]
pub use memory::SelfMemory;

use thiserror::Error;

/// Errors raised while loading a module or unwinding a stack.
#[derive(Debug, Error)]
pub enum UnwindError {
    /// The module file could not be read from disk.
    #[error("failed to read module {path}: {source}")]
    Io {
        /// Path of the module that could not be read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The module was read but is not a well-formed ELF object we can use.
    #[error("malformed or unsupported ELF module: {0}")]
    Elf(String),
    /// The symbolization backend failed to load DWARF/symbol data.
    #[error("symbolization backend failed: {0}")]
    Symbol(String),
}

/// Initial register values at the point unwinding starts.
///
/// The fields cover both supported architectures; the unwinder consumes only
/// the ones its target needs. On x86-64 that is `pc`, `sp`, and `fp` (rbp);
/// on aarch64 it is `pc`, `sp`, `fp` (x29), and `lr` (x30). Populate the
/// unused field with `0`.
#[derive(Debug, Clone, Copy)]
pub struct InitialRegs {
    /// Program counter / instruction pointer (rip / pc) of the leaf frame.
    pub pc: u64,
    /// Stack pointer (rsp / sp) of the leaf frame.
    pub sp: u64,
    /// Frame pointer (rbp / x29) of the leaf frame.
    pub fp: u64,
    /// Link register (x30). Ignored on x86-64; set to `0` there.
    pub lr: u64,
}

/// Unwind and symbolize in one step.
///
/// Runs [`StackUnwinder::unwind`] to obtain frame lookup addresses, then
/// expands each through [`Symbolizer::resolve`] (which fans out inlined
/// functions). The returned vector is innermost frame first.
pub fn unwind_symbolized(
    unwinder: &mut StackUnwinder,
    symbolizer: &Symbolizer,
    regs: &InitialRegs,
    mem: &mut impl MemoryReader,
) -> Result<Vec<SymbolizedFrame>, UnwindError> {
    let addresses = unwinder.unwind(regs, mem)?;
    let mut frames = Vec::new();
    for address in addresses {
        frames.extend(symbolizer.resolve(address));
    }
    Ok(frames)
}
