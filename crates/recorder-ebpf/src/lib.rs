//! Layer 1 (eBPF path, issue #14) — userspace loader for the in-kernel
//! syscall capture programs in `recorder-ebpf-programs`.
//!
//! Moves syscall *observation* in-kernel: a `raw_tracepoint` pair on
//! `sys_enter`/`sys_exit`, filtered by tgid, writes events into a
//! `BPF_MAP_TYPE_RINGBUF` that this crate drains into the same trace format
//! [`recorder::trace`] already writes — so replay, the decoder, and DAP never
//! need to know which backend recorded a trace. Where the ptrace backend
//! costs two `PTRACE_SYSCALL` stops (and a context switch each) per syscall,
//! this backend costs one ring-buffer write per syscall boundary and zero
//! tracer-side stops.
//!
//! This is the userspace half only. The BPF kernel-side programs live in the
//! sibling `recorder-ebpf-programs` crate — deliberately **not** a workspace
//! member (it needs nightly + `bpf-linker`; see its README) — built
//! separately and loaded here at runtime via [`capture::record_command`]'s
//! `bpf_object_path` argument.
//!
//! See [`capture`] module docs for the honest list of what this backend does
//! *not* yet capture relative to `recorder::capture`'s ptrace path.

#![cfg_attr(
    not(target_os = "linux"),
    doc = "\n\nNot available on this platform: eBPF loading needs Linux."
)]

#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod error;

#[cfg(target_os = "linux")]
pub use capture::record_command;
#[cfg(target_os = "linux")]
pub use error::EbpfCaptureError;
