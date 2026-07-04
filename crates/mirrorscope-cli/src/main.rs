//! Mirrorscope CLI: `mirrorscope dap` serves DAP over stdio; `record` and
//! `replay` land with issues #4 and #6.

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
    eprintln!("  dap        serve the Debug Adapter Protocol over stdio");
    eprintln!("  --version  print the version");
    eprintln!();
    eprintln!("`record` and `replay` land with issues #4 and #6.");
}
