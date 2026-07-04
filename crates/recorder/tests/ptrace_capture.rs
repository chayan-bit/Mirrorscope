//! Linux-only integration test for ptrace syscall capture (issue #4):
//! a target doing nondeterministic reads must leave a deterministic input
//! stream in the trace.
#![cfg(target_os = "linux")]

use recorder::capture::payload::SyscallExit;
use recorder::capture::record_command;
use recorder::trace::{EventKind, TraceReader};

#[test]
fn records_nondeterministic_reads_as_a_deterministic_input_stream() {
    let dir = std::env::temp_dir().join(format!("mirrorscope-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let trace_path = dir.join("urandom.mscope");

    let outcome = record_command(
        "sh",
        &["-c".into(), "head -c 32 /dev/urandom > /dev/null".into()],
        &trace_path,
    )
    .expect("recording must succeed");
    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome.events_recorded > 0);

    let file = std::fs::File::open(&trace_path).expect("open trace");
    let reader = TraceReader::open(std::io::BufReader::new(file)).expect("valid trace header");

    let mut enters = 0u64;
    let mut captured_read_bytes = 0usize;
    for record in reader {
        let record = record.expect("every record intact (checksums + monotonic seq)");
        match record.event.kind {
            EventKind::SyscallEnter => enters += 1,
            EventKind::SyscallExit => {
                let exit = SyscallExit::decode(&record.event.payload).expect("decodable exit");
                if exit.nr as i64 == libc::SYS_read && exit.ret > 0 {
                    assert_eq!(
                        exit.data.len(),
                        exit.ret as usize,
                        "captured data must match the bytes the tracee actually received"
                    );
                    captured_read_bytes += exit.data.len();
                }
            }
            _ => {}
        }
    }

    assert!(enters > 0, "syscall entries must be recorded");
    assert!(
        captured_read_bytes >= 32,
        "the 32 urandom bytes the target consumed must be in the trace, \
         got {captured_read_bytes}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
