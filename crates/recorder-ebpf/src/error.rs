//! Errors from the eBPF capture path.

use recorder::trace::TraceError;

/// Failures while recording a target via the eBPF path.
#[derive(Debug, thiserror::Error)]
pub enum EbpfCaptureError {
    /// Couldn't load the compiled BPF object. Most commonly: the file
    /// doesn't exist (it's built separately — see
    /// `crates/recorder-ebpf-programs/README.md`), or the running kernel
    /// lacks the BTF this program needs (`CONFIG_DEBUG_INFO_BTF`).
    #[error(
        "failed to load eBPF object {path}: {source}\n\
         hint: build it first (crates/recorder-ebpf-programs/README.md), \
         and confirm the kernel exposes BTF (/sys/kernel/btf/vmlinux)"
    )]
    LoadObject {
        /// Path that was passed to the loader.
        path: String,
        /// Underlying aya error (boxed: `aya::EbpfError` is large and this
        /// is the rare error path, not the hot path).
        #[source]
        source: Box<aya::EbpfError>,
    },
    /// A named program wasn't found in the loaded object, or wasn't of the
    /// expected program type.
    #[error("eBPF object is missing expected program {name}")]
    MissingProgram {
        /// The program name (`sys_enter` / `sys_exit`).
        name: &'static str,
    },
    /// Loading or attaching a program into the kernel failed — commonly a
    /// permissions issue (needs `CAP_BPF`/`CAP_PERFMON`, i.e. root) or a
    /// verifier rejection.
    #[error("failed to load/attach eBPF program {name}: {source}\nhint: this needs root (CAP_BPF + CAP_PERFMON)")]
    Program {
        /// The program name.
        name: &'static str,
        /// Underlying aya program error.
        #[source]
        source: aya::programs::ProgramError,
    },
    /// A named map wasn't found in the loaded object.
    #[error("eBPF object is missing expected map {name}")]
    MissingMap {
        /// The map name (`TARGET_TGID` / `EVENTS`).
        name: &'static str,
    },
    /// Reading or writing a BPF map failed.
    #[error("eBPF map {name} access failed: {source}")]
    Map {
        /// The map name.
        name: &'static str,
        /// Underlying aya map error.
        #[source]
        source: aya::maps::MapError,
    },
    /// Failed to spawn the target command.
    #[error("failed to spawn target: {0}")]
    Spawn(std::io::Error),
    /// A `waitpid`/`kill` operation on the (non-ptraced) target failed.
    #[error("process control failure: {0}")]
    Process(#[from] nix::Error),
    /// Writing the trace log failed.
    #[error(transparent)]
    Trace(#[from] TraceError),
}
