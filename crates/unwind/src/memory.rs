//! Abstract memory access for unwinding.
//!
//! Unwinding only ever reads 8-byte words from the target's stack, so the
//! reader contract is intentionally tiny. Replay will provide a
//! `process_vm_readv`-backed implementation later; the in-process
//! [`SelfMemory`] here is what the tests unwind against.

use thiserror::Error;

/// Error returned when a target-memory read fails.
#[derive(Debug, Error)]
pub enum MemoryError {
    /// The requested address could not be read from the target.
    #[error("failed to read {len} bytes at {addr:#x}")]
    Read {
        /// Address that could not be read.
        addr: u64,
        /// Number of bytes requested.
        len: usize,
    },
}

/// Random-access reader over a target process's memory.
///
/// Implementations must read the target's *current* memory image at the given
/// actual virtual address (AVMA). For replay this is the restored tracee; for
/// tests it is the current process.
pub trait MemoryReader {
    /// Read a native-endian `u64` located at `addr`.
    fn read_u64(&mut self, addr: u64) -> Result<u64, MemoryError>;
}

/// Reads the current process's own memory via `/proc/self/mem`.
///
/// This is used by tests to unwind the live stack. Reading `/proc/self/mem` is
/// always permitted for one's own process and needs no `unsafe`, unlike raw
/// pointer dereferences.
#[cfg(target_os = "linux")]
pub struct SelfMemory {
    file: std::fs::File,
}

#[cfg(target_os = "linux")]
impl SelfMemory {
    /// Open `/proc/self/mem` for reading.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            file: std::fs::File::open("/proc/self/mem")?,
        })
    }
}

#[cfg(target_os = "linux")]
impl MemoryReader for SelfMemory {
    fn read_u64(&mut self, addr: u64) -> Result<u64, MemoryError> {
        use std::os::unix::fs::FileExt;
        let mut buf = [0u8; 8];
        self.file
            .read_exact_at(&mut buf, addr)
            .map_err(|_| MemoryError::Read { addr, len: 8 })?;
        Ok(u64::from_ne_bytes(buf))
    }
}
