//! Linux-only integration test: [`GoroutineDecoder`] over a *real*, running,
//! ptrace-stopped Go process, via [`PtraceProcessView`].
//!
//! It compiles a small Go program holding goroutines in distinct runtime
//! states (a busy spinner, a channel-receive block, and long sleeps),
//! ptrace-attaches every thread, then asserts the decoder recovers the
//! goroutine tree — goids, states, and wait reasons — by walking
//! `runtime.allgs` with DWARF-derived offsets.
//!
//! Skips gracefully (like the recorder's gcc-dependent tests) when neither a
//! prebuilt fixture (`MIRRORSCOPE_GO_FIXTURE`) nor a `go` toolchain is
//! available — so `cargo test` stays green on a machine without Go, and the
//! real assertions run in CI/Docker where Go is present.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use decoder::go::offsets::LayoutSource;
use decoder::model::{BlockReason, TaskKind, TaskState};
use decoder::{GoroutineDecoder, PtraceProcessView, SemanticDecoder};

/// The Go fixture: goroutines parked in distinct, observable states.
const FIXTURE_SRC: &str = r#"
package main

import (
	"os"
	"runtime"
	"time"
)

func spinForever(ready chan<- struct{}) {
	ready <- struct{}{}
	for {
		runtime.Gosched()
		for i := 0; i < 1000; i++ {
		}
	}
}

func blockOnChannel(ready chan<- struct{}, ch <-chan int) {
	ready <- struct{}{}
	<-ch
}

func blockOnSleep(ready chan<- struct{}) {
	ready <- struct{}{}
	time.Sleep(24 * time.Hour)
}

func main() {
	runtime.GOMAXPROCS(4)
	ready := make(chan struct{})
	never := make(chan int)
	go spinForever(ready)
	<-ready
	go blockOnChannel(ready, never)
	<-ready
	go blockOnSleep(ready)
	<-ready
	_, _ = os.Stdout.WriteString("READY\n")
	_ = os.Stdout.Sync()
	for {
		time.Sleep(time.Second)
	}
}
"#;

/// Locate a fixture binary: an explicit prebuilt one, or compile the embedded
/// source with `go`. Returns `None` (test skips) when neither is available.
fn fixture_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("MIRRORSCOPE_GO_FIXTURE") {
        return Some(PathBuf::from(path));
    }
    if Command::new("go").arg("version").output().is_err() {
        eprintln!("SKIP: no MIRRORSCOPE_GO_FIXTURE and no `go` toolchain");
        return None;
    }
    compile_fixture()
}

/// Compile [`FIXTURE_SRC`] into a non-PIE (`ET_EXEC`) binary so its static
/// `runtime.allgs` symbol address equals its runtime address (v1 does not add
/// a PIE load bias). `CGO_ENABLED=0` selects Go's internal linker, which emits
/// a non-PIE executable.
fn compile_fixture() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("mscope-go-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(dir.join("main.go"), FIXTURE_SRC).ok()?;
    run_in(&dir, &["go", "mod", "init", "fixture"])?;
    let bin = dir.join("fixture");
    let mut cmd = Command::new("go");
    cmd.current_dir(&dir)
        .env("CGO_ENABLED", "0")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(".");
    if !cmd.status().ok()?.success() {
        eprintln!("SKIP: `go build` failed");
        return None;
    }
    Some(bin)
}

fn run_in(dir: &std::path::Path, argv: &[&str]) -> Option<()> {
    let status = Command::new(argv[0])
        .args(&argv[1..])
        .current_dir(dir)
        .status()
        .ok()?;
    status.success().then_some(())
}

/// Spawn the fixture and block until it prints `READY`.
///
/// The returned child is always reaped by the caller's `cleanup` (SIGKILL +
/// `wait`); the panic paths here abort the whole test, so a lingering child is
/// reaped by the OS on process exit. Hence the `zombie_processes` allow.
#[allow(clippy::zombie_processes)]
fn spawn_ready(bin: &std::path::Path) -> Child {
    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn go fixture");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read fixture stdout");
        if n == 0 || Instant::now() > deadline {
            panic!("fixture never signalled READY (got: {line:?})");
        }
        if line.trim() == "READY" {
            return child;
        }
    }
}

/// `PTRACE_ATTACH` + wait for every thread of `pid`, returning the attached
/// tids.
fn attach_all(pid: i32) -> Vec<i32> {
    let tids = tids_of(pid);
    tids.into_iter()
        .filter(|tid| {
            let p = Pid::from_raw(*tid);
            ptrace::attach(p).is_ok() && matches!(waitpid(p, None), Ok(WaitStatus::Stopped(_, _)))
        })
        .collect()
}

fn tids_of(pid: i32) -> Vec<i32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

fn cleanup(child: &mut Child, attached: &[i32]) {
    for tid in attached {
        let _ = ptrace::detach(Pid::from_raw(*tid), None);
    }
    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
    let _ = child.wait();
}

#[test]
fn decodes_goroutines_of_a_real_go_process() {
    let Some(bin) = fixture_binary() else {
        return; // skipped: see stderr
    };
    let image = std::fs::read(&bin).expect("read fixture bytes");
    let decoder = GoroutineDecoder::from_binary(&image).expect("resolve go runtime layout");
    // Default `go build` ships DWARF, so the layout must be DWARF-derived.
    assert_eq!(decoder.layout().source, LayoutSource::Dwarf);

    let mut child = spawn_ready(&bin);
    let pid = child.id() as i32;
    let attached = attach_all(pid);
    assert!(!attached.is_empty(), "attached no threads of pid {pid}");

    // Every fallible step must still run cleanup before panicking.
    let tree = match PtraceProcessView::for_pid(pid).map(|view| decoder.decode_tasks(&view)) {
        Ok(Ok(tree)) => tree,
        other => {
            cleanup(&mut child, &attached);
            panic!("decode goroutines failed: {other:?}");
        }
    };

    let mut channel_blocked = 0;
    let mut timer_blocked = 0;
    let mut non_goroutine = 0;
    for &id in &tree.flatten_preorder() {
        let node = tree.node(id).expect("node for its own id");
        if node.kind != TaskKind::Goroutine {
            non_goroutine += 1;
        }
        match &node.state {
            TaskState::Blocked {
                on: BlockReason::Channel { .. },
            } => channel_blocked += 1,
            TaskState::Blocked {
                on: BlockReason::Timer,
            } => timer_blocked += 1,
            _ => {}
        }
    }

    cleanup(&mut child, &attached);

    assert_eq!(non_goroutine, 0, "every task must be a goroutine");
    assert!(
        tree.len() >= 4,
        "expected >= 4 goroutines (main + 3 spawned), got {}",
        tree.len()
    );
    assert!(
        channel_blocked >= 1,
        "expected a chan-receive-blocked goroutine, found none"
    );
    assert!(
        timer_blocked >= 2,
        "expected >= 2 sleep-blocked goroutines (main idle loop + blockOnSleep), got {timer_blocked}"
    );
}
