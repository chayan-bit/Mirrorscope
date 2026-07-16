//! End-to-end check of the eBPF capture path (issue #14): load the compiled
//! `recorder-ebpf-programs` object, attach it, record a trivial target, and
//! confirm the trace has real `SyscallEnter`/`SyscallExit` records.
//!
//! This needs three things real CI/dev machines won't always have: root
//! (`CAP_BPF`/`CAP_PERFMON`), a BTF-enabled kernel, and the BPF object
//! pre-built (nightly + bpf-linker, deliberately kept out of the normal
//! toolchain — see `crates/recorder-ebpf-programs/README.md`). Rather than
//! fail, this test **skips with an explanation** when any is missing, and
//! only asserts real behavior when all three are present — see the
//! `MIRRORSCOPE_EBPF_TEST_OBJECT` env var below.
#![cfg(target_os = "linux")]

use std::path::PathBuf;

use recorder::trace::{EventKind, TraceReader};

/// Env var pointing at a pre-built `recorder-ebpf-programs` object (see that
/// crate's README for how to build one for the current host arch). Not set
/// by default — this test is opt-in even on Linux, since the object isn't
/// produced by the normal `cargo build`.
const OBJECT_ENV_VAR: &str = "MIRRORSCOPE_EBPF_TEST_OBJECT";

#[test]
fn captures_syscalls_of_a_trivial_target() {
    let Some(object_path) = requested_object_path() else {
        eprintln!(
            "skipping: ${OBJECT_ENV_VAR} not set (no pre-built recorder-ebpf-programs object) \
             — see crates/recorder-ebpf-programs/README.md"
        );
        return;
    };
    if !object_path.exists() {
        eprintln!(
            "skipping: ${OBJECT_ENV_VAR}={} does not exist",
            object_path.display()
        );
        return;
    }
    if !is_root() {
        eprintln!("skipping: eBPF loading needs root (CAP_BPF + CAP_PERFMON)");
        return;
    }
    if !has_btf() {
        eprintln!("skipping: kernel lacks BTF (/sys/kernel/btf/vmlinux not found)");
        return;
    }

    let dir = std::env::temp_dir().join(format!("mscope-ebpf-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let trace_path = dir.join("trace.mscope");

    let outcome = recorder_ebpf::record_command(
        "head",
        &["-c".to_owned(), "16".to_owned(), "/dev/urandom".to_owned()],
        &trace_path,
        &object_path,
    );
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            // A real load/attach failure on a machine that claimed to have
            // root + BTF is worth failing loudly on, not skipping past.
            panic!("eBPF record_command failed despite root + BTF present: {err}");
        }
    };

    assert_eq!(outcome.exit_code, Some(0), "target should have exited 0");
    assert!(
        outcome.events_recorded > 0,
        "expected at least one captured syscall event"
    );

    let file = std::fs::File::open(&trace_path).expect("open trace");
    let reader = TraceReader::open(file).expect("open trace reader");
    let mut enters = 0u64;
    let mut exits = 0u64;
    for record in reader {
        let record = record.expect("valid record");
        match record.event.kind {
            EventKind::SyscallEnter => enters += 1,
            EventKind::SyscallExit => exits += 1,
            _ => {}
        }
    }
    assert!(enters > 0, "expected captured SyscallEnter records");
    assert!(exits > 0, "expected captured SyscallExit records");

    let _ = std::fs::remove_dir_all(&dir);
}

fn requested_object_path() -> Option<PathBuf> {
    std::env::var_os(OBJECT_ENV_VAR).map(PathBuf::from)
}

fn is_root() -> bool {
    // SAFETY: geteuid() takes no arguments and cannot fail.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
    }
}

fn has_btf() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}
