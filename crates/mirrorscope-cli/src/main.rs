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
    eprintln!("  replay [-t <trace>] [--to <seq>]     replay a trace (Linux)");
    eprintln!("  --version                            print the version");
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
