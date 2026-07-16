//! The real [`DebugBackend`](crate::backend::DebugBackend): drives a recorded
//! trace under the replay engine and answers DAP requests from the live,
//! ptrace-stopped tracee (Linux only, issue #8).
//!
//! # What each request maps onto
//!
//! - `threads` / `taskTimeline` — a [`PtraceProcessView`] over the stopped
//!   tracee fed to the [`NativeThreadsDecoder`](decoder::NativeThreadsDecoder)
//!   via [`select_decoder`], so the DAP layer consumes the same
//!   language-agnostic [`TaskTree`](decoder::model::TaskTree) every future
//!   decoder produces.
//! - `stackTrace` — the decoder's `logical_stack`, which for Phase 1 is the
//!   [`unwind`]-symbolized physical stack of the leaf thread.
//! - `scopes` / `variables` — a *registers* scope (pc/sp/fp/lr). Real
//!   DWARF-based locals are Layer 5 future work; we say so honestly in a note
//!   variable rather than invent values.
//! - execution control — event-stepping at **syscall-exit** granularity, the
//!   trace's natural event unit. `continue` runs to exit; `stepBack` /
//!   `reverseContinue` re-seat via [`ReplaySession::run_to`] (which restores
//!   the nearest checkpoint, or respawns from entry, then replays forward).
//!
//! # The tracee-pid workaround (replay API gap)
//!
//! Unwinding and decoding both need the live tracee pid, but [`ReplaySession`]
//! exposes no `pid()` accessor at this commit, and its pid *changes* whenever a
//! reverse operation respawns the target. We therefore read the pid from
//! `/proc/thread-self/children` on every request. This is only unambiguous
//! while there is exactly one traced child, so this backend deliberately
//! leaves periodic checkpointing **disabled** (fork-snapshots would appear as
//! extra children we cannot tell apart from the active tracee — their pids are
//! `pub(crate)` inside `CheckpointInfo`). A one-line `ReplaySession::pid()`
//! would remove the workaround and let us enable checkpoints for faster
//! reverse stepping; see the crate report.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde_json::{json, Value};

use decoder::model::{TaskId, TaskKind, TaskNode, TaskState};
use decoder::{select_decoder, PtraceProcessView, SemanticDecoder};
use recorder::trace::{EventKind, TraceReader};
use replay::{ExitOutcome, ReplaySession};
use unwind::RemoteUnwinder;

use crate::backend::{BackendError, DebugBackend, ResumeKind, StopInfo};
use crate::stub::MAIN_THREAD_ID;

/// `variablesReference` handed back for the single "Registers" scope. Any other
/// reference resolves to an empty variable list.
const REGISTERS_REF: u64 = 1000;

/// A DAP backend driven by the replay engine over a recorded trace.
pub struct ReplayBackend {
    session: ReplaySession,
    /// Ascending seq of every `SyscallExit` record — the event timeline we
    /// step through. Read once from the trace at construction.
    events: Vec<u64>,
    /// Index into `events` of the current stop; `events.len()` means "at or
    /// past the end" (typically after the target has exited).
    cursor: usize,
    /// Set once the target has run to completion; cleared when a reverse
    /// operation respawns a fresh, live tracee.
    exited: Option<i32>,
}

impl ReplayBackend {
    /// Open `trace_path`, spawn the target under the replay engine, and read
    /// its event timeline. The target is not yet driven — [`DebugBackend::launch`]
    /// positions it at the first event.
    ///
    /// # Errors
    /// Fails if the trace cannot be opened or the target cannot be spawned.
    pub fn open(trace_path: &Path) -> Result<Self, BackendError> {
        let session = ReplaySession::launch(trace_path).map_err(engine)?;
        let events = read_exit_seqs(trace_path)?;
        Ok(Self {
            session,
            events,
            cursor: 0,
            exited: None,
        })
    }

    /// Drive the session to `events[index]`, updating the cursor and exit
    /// state, and describe the resulting stop.
    fn goto(&mut self, index: usize, reason: &str) -> Result<StopInfo, BackendError> {
        let seq = self.events[index];
        let outcome = self.session.run_to(seq).map_err(engine)?;
        self.cursor = index;
        Ok(self.classify(outcome, reason))
    }

    /// Turn an [`ExitOutcome`] into a [`StopInfo`], recording exit state.
    fn classify(&mut self, outcome: ExitOutcome, reason: &str) -> StopInfo {
        match outcome {
            ExitOutcome::Running => {
                self.exited = None;
                StopInfo::Stopped {
                    reason: reason.to_owned(),
                    thread_id: MAIN_THREAD_ID,
                }
            }
            ExitOutcome::Exited(code) => {
                self.exited = Some(code);
                StopInfo::Exited { code }
            }
            ExitOutcome::Signaled(signal) => {
                let code = 128 + signal;
                self.exited = Some(code);
                StopInfo::Exited { code }
            }
        }
    }

    /// Run the target to completion and report its exit.
    fn run_to_end(&mut self) -> Result<StopInfo, BackendError> {
        let outcome = self.session.run_to_end().map_err(engine)?;
        self.cursor = self.events.len();
        Ok(self.classify(outcome, "step"))
    }

    /// The live tracee pid, read from `/proc/thread-self/children`.
    ///
    /// Valid only while exactly one traced child exists (see the module docs
    /// on why checkpointing is disabled). Fails after the target has exited.
    fn tracee_pid(&self) -> Result<i32, BackendError> {
        if self.exited.is_some() {
            return Err(BackendError::NoTracee);
        }
        let raw = std::fs::read_to_string("/proc/thread-self/children")
            .map_err(|source| BackendError::Engine(format!("reading tracee children: {source}")))?;
        let mut pids = raw.split_whitespace().filter_map(|s| s.parse::<i32>().ok());
        let pid = pids.next().ok_or(BackendError::NoTracee)?;
        if pids.next().is_some() {
            return Err(BackendError::Engine(
                "more than one traced child found; the DAP replay backend requires exactly one \
                 (periodic checkpointing is disabled — see replay_backend docs)"
                    .to_owned(),
            ));
        }
        Ok(pid)
    }

    /// Build a decoder + a fresh view over the current stop.
    fn decode(&self) -> Result<(Box<dyn SemanticDecoder>, PtraceProcessView), BackendError> {
        let pid = self.tracee_pid()?;
        let view = PtraceProcessView::for_pid(pid)
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        Ok((select_decoder(), view))
    }
}

impl DebugBackend for ReplayBackend {
    fn launch(&mut self, _arguments: &Value) -> Result<StopInfo, BackendError> {
        if self.events.is_empty() {
            return self.run_to_end();
        }
        self.goto(0, "entry")
    }

    fn threads(&mut self) -> Result<Value, BackendError> {
        let (decoder, view) = self.decode()?;
        let tree = decoder
            .decode_tasks(&view)
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        let threads: Vec<Value> = tree
            .roots()
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let name = tree.node(*id).map_or_else(String::new, |n| n.name.clone());
                json!({ "id": index as u64 + 1, "name": name })
            })
            .collect();
        Ok(json!({ "threads": threads }))
    }

    fn stack_trace(&mut self, _arguments: &Value) -> Result<Value, BackendError> {
        let (decoder, view) = self.decode()?;
        let tree = decoder
            .decode_tasks(&view)
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        let Some(&task) = tree.roots().first() else {
            return Ok(json!({ "stackFrames": [], "totalFrames": 0 }));
        };
        let frames = decoder
            .logical_stack(&view, task)
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        let stack: Vec<Value> = frames
            .iter()
            .enumerate()
            .map(|(index, frame)| logical_frame_to_dap(index, frame))
            .collect();
        Ok(json!({ "stackFrames": stack, "totalFrames": stack.len() }))
    }

    fn scopes(&mut self, _arguments: &Value) -> Result<Value, BackendError> {
        Ok(json!({
            "scopes": [{
                "name": "Registers",
                "variablesReference": REGISTERS_REF,
                "expensive": false,
            }],
        }))
    }

    fn variables(&mut self, arguments: &Value) -> Result<Value, BackendError> {
        let reference = arguments.get("variablesReference").and_then(Value::as_u64);
        if reference != Some(REGISTERS_REF) {
            return Ok(json!({ "variables": [] }));
        }
        let pid = self.tracee_pid()?;
        let unwinder = RemoteUnwinder::for_pid(pid)
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        let regs = unwinder
            .registers()
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        let variables = json!([
            register_var("pc", regs.pc),
            register_var("sp", regs.sp),
            register_var("fp", regs.fp),
            register_var("lr", regs.lr),
            {
                "name": "(locals)",
                "value": "DWARF local-variable evaluation is not yet implemented (Layer 5, \
                          issue-tracked); showing registers only.",
                "variablesReference": 0,
            },
        ]);
        Ok(json!({ "variables": variables }))
    }

    fn resume(&mut self, kind: ResumeKind) -> Result<StopInfo, BackendError> {
        match kind {
            ResumeKind::Continue => self.run_to_end(),
            ResumeKind::ReverseContinue => {
                if self.events.is_empty() {
                    return self.run_to_end();
                }
                self.goto(0, "step")
            }
            ResumeKind::StepBack => {
                if self.events.is_empty() {
                    return Err(BackendError::NotSupported(
                        "no recorded events to step back over".to_owned(),
                    ));
                }
                let target = self.cursor.saturating_sub(1);
                self.goto(target, "step")
            }
            ResumeKind::Next | ResumeKind::StepIn | ResumeKind::StepOut => {
                let next = self.cursor + 1;
                if next >= self.events.len() {
                    self.run_to_end()
                } else {
                    self.goto(next, "step")
                }
            }
        }
    }

    fn list_checkpoints(&mut self) -> Result<Value, BackendError> {
        // Periodic checkpointing is disabled in this backend (see module
        // docs), so this is honestly the real — currently empty — list.
        let checkpoints: Vec<Value> = self
            .session
            .checkpoints()
            .iter()
            .map(|cp| json!({ "seq": cp.seq }))
            .collect();
        Ok(json!({ "checkpoints": checkpoints }))
    }

    fn task_timeline(&mut self) -> Result<Value, BackendError> {
        let (decoder, view) = self.decode()?;
        let tree = decoder
            .decode_tasks(&view)
            .map_err(|source| BackendError::Engine(source.to_string()))?;
        let tasks: Vec<Value> = tree
            .flatten_preorder()
            .iter()
            .filter_map(|id| tree.node(*id).map(|node| serialize_task(*id, node)))
            .collect();
        Ok(json!({ "tasks": tasks }))
    }

    fn jump_to_event(&mut self, arguments: &Value) -> Result<StopInfo, BackendError> {
        let seq = arguments
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                BackendError::BadArgs("jumpToEvent requires a numeric \"seq\"".to_owned())
            })?;
        let outcome = self.session.run_to(seq).map_err(engine)?;
        let reached = self.session.current_seq().unwrap_or(0);
        self.cursor = self
            .events
            .iter()
            .rposition(|&s| s <= reached)
            .map_or(0, |index| index);
        Ok(self.classify(outcome, "step"))
    }
}

/// Read the ascending seq of every `SyscallExit` record in a trace.
fn read_exit_seqs(trace_path: &Path) -> Result<Vec<u64>, BackendError> {
    let file = File::open(trace_path)
        .map_err(|source| BackendError::Engine(format!("opening trace: {source}")))?;
    let reader = TraceReader::open(BufReader::new(file))
        .map_err(|source| BackendError::Engine(source.to_string()))?;
    let mut seqs = Vec::new();
    for record in reader {
        let record = record.map_err(|source| BackendError::Engine(source.to_string()))?;
        if record.event.kind == EventKind::SyscallExit {
            seqs.push(record.seq);
        }
    }
    Ok(seqs)
}

/// Convert an engine error into a [`BackendError::Engine`], preserving its
/// message so divergence surfaces verbatim.
fn engine(error: replay::ReplayError) -> BackendError {
    BackendError::Engine(error.to_string())
}

/// Render a register as a DAP variable.
fn register_var(name: &str, value: u64) -> Value {
    json!({
        "name": name,
        "value": format!("{value:#018x}"),
        "type": "u64",
        "variablesReference": 0,
    })
}

/// Map a decoder [`LogicalFrame`](decoder::model::LogicalFrame) to a DAP stack
/// frame.
fn logical_frame_to_dap(index: usize, frame: &decoder::model::LogicalFrame) -> Value {
    let mut out = json!({
        "id": index as u64 + 1,
        "name": frame.display_name,
        "line": 0,
        "column": 0,
    });
    if let Some(location) = &frame.location {
        out["line"] = json!(location.line);
        out["column"] = json!(location.column);
        out["source"] = json!({
            "name": file_name(&location.path),
            "path": location.path,
        });
    }
    out
}

/// Serialize one task-tree node for the `taskTimeline` response.
fn serialize_task(id: TaskId, node: &TaskNode) -> Value {
    json!({
        "id": id.raw(),
        "name": node.name,
        "kind": task_kind(node.kind),
        "state": task_state(&node.state),
        "parent": node.parent.map(TaskId::raw),
    })
}

/// A stable lowercase label for a [`TaskKind`].
fn task_kind(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::Thread => "thread",
        TaskKind::AsyncTask => "async_task",
        TaskKind::Goroutine => "goroutine",
        TaskKind::Coroutine => "coroutine",
        _ => "unknown",
    }
}

/// A stable lowercase label for a [`TaskState`].
fn task_state(state: &TaskState) -> &'static str {
    match state {
        TaskState::Runnable => "runnable",
        TaskState::Running => "running",
        TaskState::Blocked { .. } => "blocked",
        TaskState::Completed => "completed",
        _ => "unknown",
    }
}

/// The final path component of `path`, for a DAP `source.name`.
fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_owned()
}
