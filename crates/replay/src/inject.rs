//! Syscall-result injection: deciding which syscalls to feed from the trace and
//! moving bytes in and out of the replay tracee's address space.

use std::io::{IoSlice, IoSliceMut};

use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
use nix::unistd::Pid;

use crate::error::ReplayError;

/// For a syscall whose result the kernel wrote into tracee memory (rather than
/// returned in a register), the destination buffer address in *this* tracee.
///
/// Mirrors the recorder's `kernel_written_region` set (read/pread64/recvfrom,
/// getrandom, clock_gettime). At entry we do not yet know the return value, so
/// membership alone decides injection; the recorded length arrives at exit.
pub(crate) fn injection_addr(nr: u64, args: &[u64; 6]) -> Option<u64> {
    match nr as i64 {
        libc::SYS_read | libc::SYS_pread64 | libc::SYS_recvfrom => Some(args[1]),
        libc::SYS_getrandom => Some(args[0]),
        libc::SYS_clock_gettime => Some(args[1]),
        _ => None,
    }
}

/// Write recorded bytes into the tracee's address space at `addr`.
pub(crate) fn write_memory(pid: Pid, addr: u64, data: &[u8]) -> Result<(), ReplayError> {
    if data.is_empty() {
        return Ok(());
    }
    let remote = RemoteIoVec {
        base: addr as usize,
        len: data.len(),
    };
    let written = process_vm_writev(pid, &[IoSlice::new(data)], &[remote]).map_err(|source| {
        ReplayError::Memory {
            addr,
            len: data.len(),
            source,
        }
    })?;
    if written != data.len() {
        return Err(ReplayError::Memory {
            addr,
            len: data.len(),
            source: nix::Error::EFAULT,
        });
    }
    Ok(())
}

/// Read `len` bytes from the tracee's address space at `addr`.
pub(crate) fn read_memory(pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>, ReplayError> {
    let mut data = vec![0u8; len];
    let remote = RemoteIoVec {
        base: addr as usize,
        len,
    };
    process_vm_readv(pid, &mut [IoSliceMut::new(&mut data)], &[remote])
        .map_err(|source| ReplayError::Memory { addr, len, source })?;
    Ok(data)
}
