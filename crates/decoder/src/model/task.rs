//! A single node of the logical concurrency tree.
//!
//! One [`TaskNode`] stands in for whatever the source language/runtime
//! flattened away: an OS thread, a spawned async task, a goroutine, or a
//! coroutine frame. `select!`/`join!` fan-out is represented by multiple
//! nodes sharing the same `parent` — see [`super::TaskTree`] for how the
//! tree itself is assembled from a flat list of these.

use super::ids::TaskId;

/// What kind of logical concurrency primitive a [`TaskNode`] represents.
///
/// `#[non_exhaustive]`: the language extension policy in `CLAUDE.md` adds
/// C++20 coroutines and Swift after Go: new variants, not a new trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskKind {
    /// A plain OS thread (the [`crate::native::NativeThreadsDecoder`] case).
    Thread,
    /// A Rust `async fn` / `Future` driven by an executor (Tokio, embassy).
    AsyncTask,
    /// A Go goroutine.
    Goroutine,
    /// A C++20 or Swift coroutine frame.
    Coroutine,
}

/// Why a task is blocked, when [`TaskState::Blocked`] applies.
///
/// Structured rather than a free-text string so DAP layers and the
/// waker-causality feature (#21) can render or filter on it without
/// re-parsing prose. `#[non_exhaustive]` for the same reason as
/// [`TaskKind`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockReason {
    /// Waiting on a channel send/receive.
    Channel {
        /// Optional decoder-supplied detail (e.g. a channel identifier).
        detail: Option<String>,
    },
    /// Waiting to acquire a lock (mutex, `RwLock`, runtime lock, …).
    Lock {
        /// Optional decoder-supplied detail (e.g. the lock's variable name).
        detail: Option<String>,
    },
    /// Waiting on I/O readiness (socket, file descriptor, …).
    Io {
        /// Optional decoder-supplied detail (e.g. a file descriptor number).
        detail: Option<String>,
    },
    /// Waiting for another task to complete (`join!`, `thread::join`).
    Join {
        /// The task being waited on, when known.
        on: Option<TaskId>,
    },
    /// Waiting on a timer or sleep.
    Timer,
    /// Blocked for a reason the decoder cannot further classify.
    Unknown,
}

/// The lifecycle state of a logical task.
///
/// This shape has to be honest about both OS threads (which a debugger
/// only ever observes paused, mid-syscall, or truly running) and async
/// tasks (which spend most of their life neither running nor blocked, but
/// simply not currently scheduled). `#[non_exhaustive]` leaves room for a
/// `Panicked` variant once the async-Rust decoder (#19/#20) needs to
/// distinguish it from `Completed`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskState {
    /// Eligible to run but not currently scheduled on a CPU (an async task
    /// sitting in the executor's ready queue; a runnable-but-not-current
    /// thread).
    Runnable,
    /// Actively executing at the moment the process was paused.
    Running,
    /// Waiting on something external; see [`BlockReason`] for what.
    Blocked {
        /// What the task is waiting on.
        on: BlockReason,
    },
    /// Finished; will never run again.
    Completed,
}

/// One node in a [`super::TaskTree`].
///
/// Deliberately does not store a `children: Vec<TaskId>` field alongside
/// `parent`: keeping only the parent pointer avoids a second, independently
/// mutable copy of the same relationship that could drift out of sync.
/// [`super::TaskTree`] derives the children index once, at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskNode {
    /// This task's stable identifier.
    pub id: TaskId,
    /// Human-readable name for display (thread name, task label, …).
    pub name: String,
    /// What kind of concurrency primitive this node represents.
    pub kind: TaskKind,
    /// Current lifecycle state.
    pub state: TaskState,
    /// The task that spawned this one, or `None` for a root (an OS thread,
    /// or the top-level task of an executor).
    pub parent: Option<TaskId>,
}

impl TaskNode {
    /// Convenience constructor for a root node (no parent).
    #[must_use]
    pub fn root(id: TaskId, name: impl Into<String>, kind: TaskKind, state: TaskState) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            state,
            parent: None,
        }
    }

    /// Convenience constructor for a node spawned by `parent` (e.g. a
    /// `join!`/`select!` branch, or a task spawned from another task).
    #[must_use]
    pub fn child(
        id: TaskId,
        name: impl Into<String>,
        kind: TaskKind,
        state: TaskState,
        parent: TaskId,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            state,
            parent: Some(parent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_constructor_has_no_parent() {
        let node = TaskNode::root(TaskId::new(1), "main", TaskKind::Thread, TaskState::Running);
        assert_eq!(node.parent, None);
        assert_eq!(node.name, "main");
    }

    #[test]
    fn child_constructor_records_parent() {
        let node = TaskNode::child(
            TaskId::new(2),
            "select branch 0",
            TaskKind::AsyncTask,
            TaskState::Runnable,
            TaskId::new(1),
        );
        assert_eq!(node.parent, Some(TaskId::new(1)));
    }

    #[test]
    fn block_reason_join_carries_target_task() {
        let reason = BlockReason::Join {
            on: Some(TaskId::new(7)),
        };
        assert_eq!(
            reason,
            BlockReason::Join {
                on: Some(TaskId::new(7))
            }
        );
    }
}
