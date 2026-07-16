//! Linux-only integration test: [`TokioDecoder`] over a *real*, running,
//! ptrace-stopped async-Rust (Tokio) process.
//!
//! It compiles a small Tokio fixture holding async tasks parked in distinct
//! states — a timer sleep, a channel receive reached through a *nested* async
//! fn, and a `join!` of two sleeps — ptrace-attaches it, then asserts the
//! decoder recovers each task's logical await stack, suspend classification,
//! and `join!` fan-out by reading the rustc coroutine state machines out of
//! process memory with layouts resolved from the binary's own DWARF.
//!
//! ## How the tasks are located (honest test-harness shortcut)
//! Robust live enumeration (TLS `CONTEXT` → sharded `OwnedTasks` → vtable→type)
//! is a deferred production subsystem (see `decoder::async_rust::roots`). So,
//! exactly as the Go test accepts a prebuilt fixture via an env var, this
//! fixture *publishes the heap addresses* of its parked task coroutines on
//! stdout, and the test feeds them as [`TaskRoot`]s. The decoding those roots
//! drive — discriminant read, `__awaitee` recursion, leaf classification,
//! `join!` child discovery — is fully real, over real process memory and real
//! DWARF.
//!
//! Skips gracefully (like the Go/gcc tests) when no `cargo` toolchain is
//! available, so `cargo test` stays green on a machine without one; the real
//! assertions run in Docker/CI where the Rust toolchain is present.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use decoder::async_rust::TaskRoot;
use decoder::model::{BlockReason, SuspendKind, TaskKind, TaskState};
use decoder::{PtraceProcessView, SemanticDecoder, TokioDecoder};

/// The fixture crate name; coroutine DWARF type names are namespaced under it.
const CRATE: &str = "tokfix";

/// `Cargo.toml` for the fixture: a pinned Tokio minor, debuginfo on.
const FIXTURE_TOML: &str = r#"
[package]
name = "tokfix"
version = "0.0.0"
edition = "2021"

[dependencies]
tokio = { version = "~1.44", features = ["rt", "macros", "time", "sync"] }

[profile.dev]
debug = 2

[workspace]
"#;

/// The fixture: build three futures, poll each once inside the runtime so they
/// park at their first `.await`, publish their heap addresses, then keep them
/// alive and park the process for ptrace.
const FIXTURE_SRC: &str = r#"
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

async fn inner_leaf(mut ch: mpsc::Receiver<u32>) {
    let _ = ch.recv().await;
}

async fn nested_parent(ch: mpsc::Receiver<u32>) {
    inner_leaf(ch).await;
}

async fn sleeper(secs: u64) {
    sleep(Duration::from_secs(secs)).await;
}

async fn joiner() {
    tokio::join!(sleeper(3600), sleeper(3601));
}

fn poll_once<F: Future>(f: &mut Pin<Box<F>>) {
    let mut cx = Context::from_waker(Waker::noop());
    let _ = f.as_mut().poll(&mut cx);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (tx, rx) = mpsc::channel::<u32>(4);
    let mut a = Box::pin(nested_parent(rx));
    let mut b = Box::pin(sleeper(100000));
    let mut c = Box::pin(joiner());
    poll_once(&mut a);
    poll_once(&mut b);
    poll_once(&mut c);
    println!("ROOT nested_parent {:p}", &*a);
    println!("ROOT sleeper {:p}", &*b);
    println!("ROOT joiner {:p}", &*c);
    println!("READY");
    // Keep the coroutines alive across the park (their heap addresses stay
    // fixed) and hold the channel sender so the receive never completes.
    let _keep = (a, b, c, tx);
    sleep(Duration::from_secs(100000)).await;
}
"#;

/// The fully-qualified DWARF coroutine type name for an async fn.
fn coro(name: &str) -> String {
    format!("{CRATE}::{name}::{{async_fn_env#0}}")
}

/// Locate the fixture binary: an explicit prebuilt one, or compile the embedded
/// source with `cargo`. Returns `None` (test skips) when neither is available.
fn fixture_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("MIRRORSCOPE_TOKIO_FIXTURE") {
        return Some(PathBuf::from(path));
    }
    if Command::new("cargo").arg("--version").output().is_err() {
        eprintln!("SKIP: no MIRRORSCOPE_TOKIO_FIXTURE and no `cargo` toolchain");
        return None;
    }
    compile_fixture()
}

/// Compile [`FIXTURE_SRC`] into a debug binary in a temp crate.
fn compile_fixture() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("mscope-tokio-fixture-{}", std::process::id()));
    let target = dir.join("target");
    std::fs::create_dir_all(dir.join("src")).ok()?;
    std::fs::write(dir.join("Cargo.toml"), FIXTURE_TOML).ok()?;
    std::fs::write(dir.join("src/main.rs"), FIXTURE_SRC).ok()?;
    // Pin the fixture's own target dir: the outer test run sets
    // CARGO_TARGET_DIR, which a nested `cargo build` would otherwise inherit,
    // putting the binary somewhere unexpected.
    let build = |offline: bool| {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&dir).env("CARGO_TARGET_DIR", &target).arg("build");
        if offline {
            cmd.arg("--offline");
        }
        cmd.status().map(|s| s.success()).unwrap_or(false)
    };
    if !build(true) && !build(false) {
        eprintln!("SKIP: `cargo build` of tokio fixture failed");
        return None;
    }
    Some(target.join("debug/tokfix"))
}

/// One published task root: display name and coroutine heap address.
struct Published {
    name: String,
    addr: u64,
}

/// Spawn the fixture and read its `ROOT`/`READY` lines.
#[allow(clippy::zombie_processes)]
fn spawn_ready(bin: &std::path::Path) -> (Child, Vec<Published>) {
    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tokio fixture");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut published = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read fixture stdout");
        assert!(n != 0, "fixture exited before READY");
        let trimmed = line.trim();
        if trimmed == "READY" {
            return (child, published);
        }
        if let Some(rest) = trimmed.strip_prefix("ROOT ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().expect("root name").to_string();
            let hex = parts.next().expect("root addr");
            let addr = u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("hex addr");
            published.push(Published { name, addr });
        }
    }
}

fn attach_all(pid: i32) -> Vec<i32> {
    tids_of(pid)
        .into_iter()
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

/// Turn the published roots into [`TaskRoot`]s with stable ids.
fn roots_from(published: &[Published]) -> Vec<TaskRoot> {
    published
        .iter()
        .enumerate()
        .map(|(i, p)| TaskRoot::new(i as u64 + 1, p.addr, coro(&p.name)))
        .collect()
}

#[test]
fn decodes_async_tasks_of_a_real_tokio_process() {
    let Some(bin) = fixture_binary() else {
        return; // skipped: see stderr
    };
    let image = std::fs::read(&bin).expect("read fixture bytes");
    let decoder = TokioDecoder::from_binary(&image).expect("resolve tokio coroutine layouts");
    // The fixture's four async fns must all be recovered from DWARF.
    for name in ["nested_parent", "inner_leaf", "sleeper", "joiner"] {
        assert!(
            decoder.layouts().is_coroutine(&coro(name)),
            "missing coroutine layout for {name}; have {} layouts",
            decoder.layouts().len()
        );
    }

    let (mut child, published) = spawn_ready(&bin);
    assert_eq!(published.len(), 3, "expected 3 published roots: {:?}", published_names(&published));
    let decoder = decoder.with_roots(roots_from(&published));

    let pid = child.id() as i32;
    let attached = attach_all(pid);
    assert!(!attached.is_empty(), "attached no threads of pid {pid}");

    // Every fallible step must still run cleanup before panicking.
    let tree = match PtraceProcessView::for_pid(pid).map(|v| decoder.decode_tasks(&v)) {
        Ok(Ok(tree)) => tree,
        other => {
            cleanup(&mut child, &attached);
            panic!("decode tokio tasks failed: {other:?}");
        }
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_decoded(&decoder, &tree, pid);
    }));
    cleanup(&mut child, &attached);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn assert_decoded(decoder: &TokioDecoder, tree: &decoder::model::TaskTree, pid: i32) {
    // 3 roots + join!'s 2 branch children = 5 tasks.
    assert!(tree.len() >= 3, "expected >= 3 tasks, got {}", tree.len());

    let ids = tree.flatten_preorder();
    let mut timer_parked = 0;
    let mut channel_parked = 0;
    let mut nested_multi_frame = false;

    let view = PtraceProcessView::for_pid(pid).expect("rebuild view for stack queries");
    for &id in &ids {
        let node = tree.node(id).expect("node for its own id");
        assert_eq!(node.kind, TaskKind::AsyncTask, "task {id:?} not async");
        match &node.state {
            TaskState::Blocked { on: BlockReason::Timer } => timer_parked += 1,
            TaskState::Blocked { on: BlockReason::Channel { .. } } => channel_parked += 1,
            _ => {}
        }
        if node.name == "nested_parent" {
            let stack = decoder.logical_stack(&view, id).expect("nested logical stack");
            let names: Vec<&str> = stack.iter().map(|f| f.display_name.as_str()).collect();
            assert!(
                names.contains(&"nested_parent") && names.contains(&"inner_leaf"),
                "nested_parent stack must name the nested async fn; got {names:?}"
            );
            // The innermost suspend is a channel receive.
            assert_eq!(
                stack.last().and_then(|f| f.suspend.as_ref()).map(|s| s.kind.clone()),
                Some(SuspendKind::ChannelRecv),
                "nested leaf must be a channel recv; stack {names:?}"
            );
            nested_multi_frame = names.len() >= 2;
        }
    }

    // The join! task fans out to exactly two branch children.
    let joiner_id = ids
        .iter()
        .copied()
        .find(|id| tree.node(*id).map(|n| n.name.as_str()) == Some("joiner"))
        .expect("joiner task present");
    assert_eq!(
        tree.children(joiner_id).len(),
        2,
        "join! task must show 2 children, got {}",
        tree.children(joiner_id).len()
    );

    assert!(nested_multi_frame, "nested_parent must have a multi-frame logical stack");
    assert!(timer_parked >= 1, "expected >= 1 timer-parked task (sleeper)");
    assert!(channel_parked >= 1, "expected >= 1 channel-parked task (nested_parent)");
}

fn published_names(published: &[Published]) -> Vec<&str> {
    published.iter().map(|p| p.name.as_str()).collect()
}
