//! Layer 1 — recording.
//!
//! Capture backends (ptrace first, eBPF/aya later) write every source of
//! non-determinism (syscall results, scheduling, signals, sync-primitive
//! ordering) into an append-only trace log, ordered by a monotonic global
//! sequence number. The log format lands with issue #2.
