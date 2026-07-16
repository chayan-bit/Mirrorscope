# recorder-ebpf-programs

Kernel-side half of the eBPF syscall capture path (issue #14: "port syscall
capture ptrace -> eBPF (aya) + ringbuf collector"). Standalone project,
**deliberately excluded** from the main Mirrorscope workspace (see the root
`Cargo.toml`'s `[workspace] exclude`) because it needs a nightly toolchain and
`bpf-linker`, neither of which the rest of the workspace (stable, MSRV 1.85)
should ever require.

## Why excluded, not just feature-gated

`cargo build --workspace` on the main repo must keep working with only a
stable toolchain. The BPF target (`bpfel-unknown-none`) is Tier 3 and needs
`-Z build-std=core`, which needs nightly — see this directory's
`rust-toolchain.toml` and `.cargo/config.toml`, which are scoped to this
directory only and don't affect the workspace root.

## Prerequisites

```sh
rustup toolchain install nightly --component rust-src
cargo +nightly install bpf-linker
```

Use `bpf-linker`'s **default features** (`rust-llvm-*`, via
`aya-rustc-llvm-proxy`), not `--no-default-features --features llvm-N` against
a system LLVM. Verified in Docker (`rust:1.85-slim-bookworm` + a manually
installed nightly, Debian bookworm's newest packaged LLVM is 19): a
system-LLVM build linked *most* of the time but intermittently failed with
`ERROR llvm: Invalid record` — nightly rustc's bundled LLVM version moves
faster than Debian's packaged LLVM, so the bitcode versions drift out of sync.
The default-features build matches whatever LLVM the installed nightly
actually bundles and was reliable across every rebuild in testing.

## Build

The kernel's `struct pt_regs` layout is architecture-specific, and the BPF
program always compiles for the arch-independent `bpfel-unknown-none` ISA —
`cfg(target_arch)` inside the program can't see the *deployment* host's
architecture. Build once per target host arch:

```sh
cd crates/recorder-ebpf-programs
cargo +nightly build --release --features x86_64    # for an x86-64 kernel
cargo +nightly build --release --features aarch64   # for an aarch64 kernel
```

Output: `target/bpfel-unknown-none/release/recorder-ebpf-programs`. Point
`recorder-ebpf`'s userspace loader at it via the `MIRRORSCOPE_EBPF_OBJECT`
env var, or `mirrorscope record --ebpf --ebpf-object <path> -- <cmd>`.

Pinned to `aya-ebpf = "=0.1.1"` / `aya-log-ebpf = "=0.1.0"`: this has to match
`recorder-ebpf`'s userspace loader version (root `Cargo.toml` pins
`aya = "=0.13.1"`, the newest release still under this workspace's MSRV
1.85 — `aya` 0.13.2+/0.14 require rustc 1.87) at the *object-file wire format*
level, not by matching version numbers per se — `aya-ebpf`'s 0.1.x line is
what the 0.13.x `aya` loader line was released alongside.

## What it captures

A `raw_tracepoint` pair on `sys_enter`/`sys_exit`, filtered by tgid (set by
the userspace loader into the `TARGET_TGID` map right after spawning the
target — see `crates/recorder-ebpf/src/capture.rs` module docs for the
resulting startup race and why it isn't SIGSTOP-held first), writing
`recorder_ebpf_common::RawSyscallEvent` records into the `EVENTS` ring
buffer. End-to-end verified in Docker (`--privileged --pid=host`, BTF-enabled
linuxkit kernel): loads, attaches, and captures real `head -c` syscalls into
a trace `recorder::trace::TraceReader` reads back correctly — see
`crates/recorder-ebpf/tests/ebpf_capture.rs`.

**Gap vs the ptrace path** (`crates/recorder/src/capture/syscall.rs`): this
slice does not read the kernel-written memory region behind
`read()`/`recvfrom()`/`getrandom()`/`clock_gettime()` (needs a second
`bpf_probe_read_user` pass keyed off exit-time buffer pointer + length), and
there is no scheduling/serialization story here at all — ptrace remains the
only backend that can pause a thread at a syscall boundary for single-core
serialization (issue #9). The eBPF path is pure observation; see
`crates/recorder-ebpf/src/lib.rs` and the README §4 hybrid-design table for
the full picture.
