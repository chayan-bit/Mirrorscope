//! Mirrorscope CLI: `mirrorscope dap` serves DAP over stdio; `mirrorscope
//! record` captures a target's syscalls (Linux); `replay` lands with #6.

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
    eprintln!("  dap                                  serve DAP over stdio");
    eprintln!("  record [-o <trace>] -- <cmd> [args]  record a target (Linux)");
    eprintln!("  --version                            print the version");
    eprintln!();
    eprintln!("`replay` lands with issue #6.");
}

#[cfg(target_os = "linux")]
fn run_record(args: &[String]) -> ExitCode {
    let parsed = parse_record_args(args);
    let (trace_path, program, program_args) = match parsed {
        Some(parts) => parts,
        None => {
            eprintln!("usage: mirrorscope record [-o <trace>] -- <cmd> [args…]");
            return ExitCode::FAILURE;
        }
    };
    match recorder::capture::record_command(&program, &program_args, trace_path.as_ref()) {
        Ok(outcome) => {
            eprintln!(
                "recorded {} events to {trace_path} (target exit: {:?})",
                outcome.events_recorded, outcome.exit_code
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("mirrorscope record: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_record(_args: &[String]) -> ExitCode {
    eprintln!("mirrorscope record: recording requires Linux (ptrace; eBPF in Phase 3)");
    ExitCode::FAILURE
}

/// Parse `[-o <trace>] -- <cmd> [args…]`; returns (trace_path, cmd, args).
#[cfg(target_os = "linux")]
fn parse_record_args(args: &[String]) -> Option<(String, String, Vec<String>)> {
    let separator = args.iter().position(|a| a == "--")?;
    let (options, target) = args.split_at(separator);
    let target = &target[1..];
    let program = target.first()?.clone();
    let program_args = target[1..].to_vec();

    let trace_path = match options {
        [] => "trace.mscope".to_owned(),
        [flag, path] if flag == "-o" => path.clone(),
        _ => return None,
    };
    Some((trace_path, program, program_args))
}
