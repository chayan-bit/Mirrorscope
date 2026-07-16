//! Mirrorscope CLI: `mirrorscope dap` serves DAP over stdio; `mirrorscope
//! record` captures a target's syscalls (Linux); `mirrorscope replay` re-runs a
//! trace, injecting recorded syscall results (Linux).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("dap") => match dap::server::serve_stdio() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("mirrorscope dap: {err}");
                ExitCode::FAILURE
            }
        },
        Some("record") => run_record(&args[1..]),
        Some("replay") => run_replay(&args[1..]),
        Some("watch") => run_watch(&args[1..]),
        Some("--version") => {
            println!("mirrorscope {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_usage();
            ExitCode::FAILURE
        }
        None => {
            print_usage();
            ExitCode::SUCCESS
        }
    }
}

fn print_usage() {
    eprintln!("usage: mirrorscope <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  dap                                             serve DAP over stdio");
    eprintln!("  record [-o <trace>] [--ebpf [--ebpf-object <path>]] -- <cmd> [args]");
    eprintln!("                                                  record a target (Linux)");
    eprintln!("  replay [-t <trace>] [--to <seq>]                replay a trace (Linux)");
    eprintln!(
        "  watch <trace> --addr <a> --len <n>              every write to an address (Linux)"
    );
    eprintln!("  --version                                       print the version");
}

/// A parsed `record` request.
#[cfg(target_os = "linux")]
struct RecordArgs {
    trace_path: String,
    /// Capture via eBPF (`--ebpf`) instead of the default ptrace backend.
    ebpf: bool,
    /// Path to the compiled `recorder-ebpf-programs` object; only meaningful
    /// with `--ebpf`. Defaults to `$MIRRORSCOPE_EBPF_OBJECT`. Only read when
    /// built with the `ebpf` feature; a build without it still parses (and
    /// rejects at runtime, not parse time) `--ebpf-object` for a clearer
    /// error message than "unknown flag".
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    ebpf_object: Option<String>,
    program: String,
    program_args: Vec<String>,
}

#[cfg(target_os = "linux")]
fn run_record(args: &[String]) -> ExitCode {
    let parsed = match parse_record_args(args) {
        Some(parsed) => parsed,
        None => {
            eprintln!("usage: mirrorscope record [-o <trace>] [--ebpf [--ebpf-object <path>]] -- <cmd> [args…]");
            return ExitCode::FAILURE;
        }
    };
    if parsed.ebpf {
        return run_record_ebpf(&parsed);
    }
    match recorder::capture::record_command(
        &parsed.program,
        &parsed.program_args,
        parsed.trace_path.as_ref(),
    ) {
        Ok(outcome) => {
            eprintln!(
                "recorded {} events to {} (target exit: {:?})",
                outcome.events_recorded, parsed.trace_path, outcome.exit_code
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("mirrorscope record: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn run_record_ebpf(parsed: &RecordArgs) -> ExitCode {
    let object_path = match parsed
        .ebpf_object
        .clone()
        .or_else(|| std::env::var("MIRRORSCOPE_EBPF_OBJECT").ok())
    {
        Some(path) => path,
        None => {
            eprintln!(
                "mirrorscope record --ebpf: no BPF object given (--ebpf-object <path> or \
                 $MIRRORSCOPE_EBPF_OBJECT); build it first — see \
                 crates/recorder-ebpf-programs/README.md"
            );
            return ExitCode::FAILURE;
        }
    };
    match recorder_ebpf::record_command(
        &parsed.program,
        &parsed.program_args,
        parsed.trace_path.as_ref(),
        object_path.as_ref(),
    ) {
        Ok(outcome) => {
            eprintln!(
                "recorded {} events to {} via eBPF (target exit: {:?})",
                outcome.events_recorded, parsed.trace_path, outcome.exit_code
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("mirrorscope record --ebpf: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(target_os = "linux", not(feature = "ebpf")))]
fn run_record_ebpf(_parsed: &RecordArgs) -> ExitCode {
    eprintln!(
        "mirrorscope record --ebpf: this build was compiled without the `ebpf` feature \
         (cargo build --features ebpf -p mirrorscope-cli)"
    );
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn run_record(_args: &[String]) -> ExitCode {
    eprintln!("mirrorscope record: recording requires Linux (ptrace, or eBPF with --ebpf)");
    ExitCode::FAILURE
}

/// Parse `[-o <trace>] [--ebpf [--ebpf-object <path>]] -- <cmd> [args…]`.
#[cfg(target_os = "linux")]
fn parse_record_args(args: &[String]) -> Option<RecordArgs> {
    let separator = args.iter().position(|a| a == "--")?;
    let (options, target) = args.split_at(separator);
    let target = &target[1..];
    let program = target.first()?.clone();
    let program_args = target[1..].to_vec();

    let mut trace_path = "trace.mscope".to_owned();
    let mut ebpf = false;
    let mut ebpf_object = None;
    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "-o" => {
                trace_path = options.get(i + 1)?.clone();
                i += 2;
            }
            "--ebpf" => {
                ebpf = true;
                i += 1;
            }
            "--ebpf-object" => {
                ebpf_object = Some(options.get(i + 1)?.clone());
                i += 2;
            }
            _ => return None,
        }
    }
    Some(RecordArgs {
        trace_path,
        ebpf,
        ebpf_object,
        program,
        program_args,
    })
}

#[cfg(target_os = "linux")]
fn run_replay(args: &[String]) -> ExitCode {
    let (trace_path, to) = match parse_replay_args(args) {
        Some(parts) => parts,
        None => {
            eprintln!("usage: mirrorscope replay [-t <trace>] [--to <seq>]");
            return ExitCode::FAILURE;
        }
    };

    let mut session = match replay::ReplaySession::launch(std::path::Path::new(&trace_path)) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("mirrorscope replay: {err}");
            return ExitCode::FAILURE;
        }
    };

    let outcome = match to {
        Some(seq) => session.step_to(seq),
        None => session.run_to_end(),
    };
    match outcome {
        Ok(outcome) => report_replay(&mut session, outcome),
        Err(err) => {
            eprintln!("mirrorscope replay: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_replay(_args: &[String]) -> ExitCode {
    eprintln!("mirrorscope replay: replay requires Linux (ptrace)");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn report_replay(session: &mut replay::ReplaySession, outcome: replay::ExitOutcome) -> ExitCode {
    match outcome {
        replay::ExitOutcome::Exited(code) => {
            eprintln!("replay finished: target exited with code {code}");
            ExitCode::SUCCESS
        }
        replay::ExitOutcome::Signaled(sig) => {
            eprintln!("replay finished: target killed by signal {sig}");
            ExitCode::SUCCESS
        }
        replay::ExitOutcome::Running => {
            eprintln!("replay stopped at seq {:?}", session.current_seq());
            ExitCode::SUCCESS
        }
    }
}

/// Parse `[-t <trace>] [--to <seq>]`; returns (trace_path, optional target seq).
#[cfg(target_os = "linux")]
fn parse_replay_args(args: &[String]) -> Option<(String, Option<u64>)> {
    let mut trace_path = "trace.mscope".to_owned();
    let mut to = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" => {
                trace_path = args.get(i + 1)?.clone();
                i += 2;
            }
            "--to" => {
                to = Some(args.get(i + 1)?.parse().ok()?);
                i += 2;
            }
            _ => return None,
        }
    }
    Some((trace_path, to))
}

/// A parsed `watch` request.
#[cfg(target_os = "linux")]
struct WatchArgs {
    trace_path: String,
    addr: u64,
    len: u8,
    reads: bool,
}

#[cfg(target_os = "linux")]
fn run_watch(args: &[String]) -> ExitCode {
    let parsed = match parse_watch_args(args) {
        Some(parsed) => parsed,
        None => {
            eprintln!("usage: mirrorscope watch <trace> --addr <addr> --len <1|2|4|8> [--rw]");
            return ExitCode::FAILURE;
        }
    };

    let mut scan = replay::WatchpointScan::new(
        std::path::Path::new(&parsed.trace_path),
        parsed.addr,
        parsed.len,
    );
    if parsed.reads {
        scan = scan.watch_reads();
    }

    match scan.run() {
        Ok(hits) => {
            report_watch(&hits, parsed.addr, parsed.len);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("mirrorscope watch: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_watch(_args: &[String]) -> ExitCode {
    eprintln!("mirrorscope watch: retroactive watchpoints require Linux (ptrace)");
    ExitCode::FAILURE
}

/// Print every watchpoint hit: nearest seq, pc, function, file:line, and value.
#[cfg(target_os = "linux")]
fn report_watch(hits: &[replay::WatchHit], addr: u64, len: u8) {
    eprintln!(
        "{} access(es) to {len} byte(s) at {addr:#x} across history:",
        hits.len()
    );
    for hit in hits {
        let frame = hit.backtrace.first();
        let function = frame
            .and_then(|f| f.function.as_deref())
            .unwrap_or("<unknown>");
        let location = frame
            .and_then(|f| f.file.as_deref().map(|file| (file, f.line)))
            .map(|(file, line)| match line {
                Some(line) => format!("{file}:{line}"),
                None => file.to_owned(),
            })
            .unwrap_or_else(|| "<no source>".to_owned());
        let seq = hit
            .seq
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_owned());
        println!(
            "  seq {seq}  pc {:#018x}  {function}  ({location})  = {}",
            hit.pc,
            format_value(&hit.new_value)
        );
    }
}

/// Render a little-endian byte value as a `0x…` hex integer for display.
#[cfg(target_os = "linux")]
fn format_value(bytes: &[u8]) -> String {
    let mut value: u128 = 0;
    for (i, byte) in bytes.iter().enumerate() {
        value |= u128::from(*byte) << (8 * i);
    }
    format!("{value:#x}")
}

/// Parse `<trace> --addr <addr> --len <n> [--rw]`. `--addr` accepts hex
/// (`0x…`) or decimal; `--len` must be 1, 2, 4, or 8.
#[cfg(target_os = "linux")]
fn parse_watch_args(args: &[String]) -> Option<WatchArgs> {
    let mut trace_path: Option<String> = None;
    let mut addr: Option<u64> = None;
    let mut len: Option<u8> = None;
    let mut reads = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                addr = Some(parse_int(args.get(i + 1)?)?);
                i += 2;
            }
            "--len" => {
                len = Some(args.get(i + 1)?.parse().ok()?);
                i += 2;
            }
            "--rw" => {
                reads = true;
                i += 1;
            }
            flag if flag.starts_with('-') => return None,
            _ => {
                if trace_path.is_some() {
                    return None;
                }
                trace_path = Some(args[i].clone());
                i += 1;
            }
        }
    }
    Some(WatchArgs {
        trace_path: trace_path?,
        addr: addr?,
        len: len?,
        reads,
    })
}

/// Parse an integer given in hex (`0x…`) or decimal.
#[cfg(target_os = "linux")]
fn parse_int(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}
