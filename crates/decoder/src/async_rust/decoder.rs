//! [`TokioDecoder`]: the [`SemanticDecoder`] that turns a stopped async-Rust
//! (Tokio) process into a [`TaskTree`] of logical async tasks, with
//! await-point logical stacks — the flagship novelty pillar (`CLAUDE.md`).
//!
//! It ties together the DWARF-resolved coroutine [`AsyncLayouts`] and a set of
//! [`TaskRoot`]s (see [`super::roots`]) and re-decodes fresh from the
//! [`ProcessView`] on every call, exactly like the Go and native decoders, so
//! stepping a replay shows each checkpoint's task state rather than a stale
//! snapshot.

use crate::decoder_trait::SemanticDecoder;
use crate::error::DecoderError;
use crate::model::{
    LogicalFrame, TaskId, TaskKind, TaskNode, TaskState, TaskTree, Variable, WakeCause,
};
use crate::process_view::ProcessView;

use super::layout::AsyncLayouts;
use super::rustc_version::RustcVersion;
use super::roots::TaskRoot;
use super::{decode, load_layouts, AsyncDecodeError};

/// Upper bound on total tasks produced, guarding against a cyclic fan-out.
const MAX_TASKS: usize = 1 << 16;

/// Reconstructs the async task tree of a Tokio target by decoding each task's
/// coroutine state machine over a [`ProcessView`], using coroutine layouts
/// resolved once from the target binary's DWARF.
#[derive(Debug, Clone)]
pub struct TokioDecoder {
    layouts: AsyncLayouts,
    version: RustcVersion,
    roots: Vec<TaskRoot>,
}

/// One fully-resolved node produced by the deterministic task walk, reused by
/// every trait method so ids are reproducible across calls.
struct DecodedNode {
    id: TaskId,
    parent: Option<TaskId>,
    base: u64,
    type_name: String,
    state: TaskState,
    wake: WakeCause,
}

impl TokioDecoder {
    /// Build a decoder from already-resolved layouts and roots (for tests, or
    /// when a caller resolved them once).
    #[must_use]
    pub fn from_parts(layouts: AsyncLayouts, version: RustcVersion, roots: Vec<TaskRoot>) -> Self {
        Self {
            layouts,
            version,
            roots,
        }
    }

    /// Build a decoder by resolving coroutine layouts from the target's binary
    /// image. The returned decoder has no task roots yet — attach them with
    /// [`Self::with_roots`] (see [`super::roots`] for why enumeration is a
    /// seam in v1).
    ///
    /// # Errors
    /// Propagates [`AsyncDecodeError`] if the image is not a Tokio binary, has
    /// no DWARF, was built by an unsupported rustc, or contains no coroutines.
    pub fn from_binary(image: &[u8]) -> Result<Self, AsyncDecodeError> {
        let (layouts, version) = load_layouts(image)?;
        Ok(Self {
            layouts,
            version,
            roots: Vec::new(),
        })
    }

    /// Attach the task roots to decode (replaces any existing roots).
    #[must_use]
    pub fn with_roots(mut self, roots: Vec<TaskRoot>) -> Self {
        self.roots = roots;
        self
    }

    /// The resolved coroutine layouts this decoder reads with.
    #[must_use]
    pub fn layouts(&self) -> &AsyncLayouts {
        &self.layouts
    }

    /// The rustc version whose coroutine layout this decoder was validated
    /// against for the target binary.
    #[must_use]
    pub fn version(&self) -> RustcVersion {
        self.version
    }

    /// Deterministically walk every root (and its fan-out children) into a
    /// flat node list. Task ids: roots keep their given ids; fan-out children
    /// are numbered from one past the max root id, in depth-first order, so
    /// the numbering is reproducible across calls on identical memory.
    fn enumerate(&self, view: &dyn ProcessView) -> Result<Vec<DecodedNode>, DecoderError> {
        if self.roots.is_empty() {
            return Err(DecoderError::NotApplicable {
                reason: "no task roots supplied; live task enumeration is a future phase \
                         (see async_rust::roots)"
                    .to_string(),
            });
        }
        let mut next_id = self.roots.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        let mut out = Vec::new();
        for root in &self.roots {
            self.expand(
                view,
                root.base,
                &root.type_name,
                root.header_addr,
                TaskId::new(root.id),
                None,
                &mut next_id,
                &mut out,
            )?;
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn expand(
        &self,
        view: &dyn ProcessView,
        base: u64,
        type_name: &str,
        header_addr: Option<u64>,
        id: TaskId,
        parent: Option<TaskId>,
        next_id: &mut u64,
        out: &mut Vec<DecodedNode>,
    ) -> Result<(), DecoderError> {
        if out.len() >= MAX_TASKS {
            return Err(DecoderError::NotApplicable {
                reason: "task fan-out exceeded MAX_TASKS; layout likely misresolved".to_string(),
            });
        }
        let layout = self.layouts.get(type_name).ok_or_else(|| DecoderError::NotApplicable {
            reason: format!("no coroutine layout for task type {type_name}"),
        })?;
        let state = decode::task_state(view, base, layout, &self.layouts, header_addr)?;
        let wake = decode::wake_cause(view, base, layout, &self.layouts)?;
        out.push(DecodedNode {
            id,
            parent,
            base,
            type_name: type_name.to_string(),
            state,
            wake,
        });

        for (child_base, child_type) in decode::fan_out_children(view, base, layout)? {
            let child_id = TaskId::new(*next_id);
            *next_id += 1;
            self.expand(
                view,
                child_base,
                &child_type,
                None,
                child_id,
                Some(id),
                next_id,
                out,
            )?;
        }
        Ok(())
    }

    fn node_for<'a>(
        &self,
        nodes: &'a [DecodedNode],
        task: TaskId,
    ) -> Result<&'a DecodedNode, DecoderError> {
        nodes
            .iter()
            .find(|n| n.id == task)
            .ok_or(DecoderError::UnknownTask(task))
    }
}

impl SemanticDecoder for TokioDecoder {
    fn decode_tasks(&self, view: &dyn ProcessView) -> Result<TaskTree, DecoderError> {
        let nodes = self.enumerate(view)?;
        let task_nodes = nodes
            .iter()
            .map(|n| TaskNode {
                id: n.id,
                name: short_name(&n.type_name),
                kind: TaskKind::AsyncTask,
                state: n.state.clone(),
                parent: n.parent,
            })
            .collect();
        TaskTree::try_from_nodes(task_nodes)
    }

    fn logical_stack(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
    ) -> Result<Vec<LogicalFrame>, DecoderError> {
        let nodes = self.enumerate(view)?;
        let node = self.node_for(&nodes, task)?;
        decode::logical_stack(view, node.base, &node.type_name, &self.layouts)
    }

    fn wake_cause(&self, view: &dyn ProcessView, task: TaskId) -> Result<WakeCause, DecoderError> {
        let nodes = self.enumerate(view)?;
        Ok(self.node_for(&nodes, task)?.wake.clone())
    }

    fn locals_at(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
        _frame: &LogicalFrame,
    ) -> Result<Vec<Variable>, DecoderError> {
        // Existence check only; typed local evaluation from a variant's live
        // members is a Layer-5 DWARF job (matches the Go/native decoders).
        let nodes = self.enumerate(view)?;
        self.node_for(&nodes, task)?;
        Ok(Vec::new())
    }
}

/// A display name for a task from its coroutine type: the enclosing `async fn`
/// name, e.g. `sleeper` from `probe::sleeper::{async_fn_env#0}`.
fn short_name(type_name: &str) -> String {
    let head = type_name.split("::{async_fn_env").next().unwrap_or(type_name);
    head.rsplit("::").next().unwrap_or(head).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_rust::layout::{AsyncFnLayout, ChildRef, VariantInfo, VariantKind};
    use crate::model::{BlockReason, SourceLocation};
    use crate::process_view::{PhysicalFrame, Registers, ThreadId};
    use std::collections::{BTreeMap, HashMap};

    struct FakeMemory {
        bytes: HashMap<u64, u8>,
    }
    impl FakeMemory {
        fn new() -> Self {
            Self {
                bytes: HashMap::new(),
            }
        }
        fn put_u8(&mut self, addr: u64, v: u8) {
            self.bytes.insert(addr, v);
        }
    }
    impl ProcessView for FakeMemory {
        fn thread_ids(&self) -> Vec<ThreadId> {
            vec![]
        }
        fn registers(&self, _t: ThreadId) -> Result<Registers, DecoderError> {
            Ok(Registers { pc: 0, sp: 0 })
        }
        fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, DecoderError> {
            (0..len as u64)
                .map(|i| {
                    self.bytes.get(&(addr + i)).copied().ok_or(DecoderError::MemoryReadFailed {
                        addr,
                        len,
                        reason: "unmapped".to_string(),
                    })
                })
                .collect()
        }
        fn physical_frames(&self, _t: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError> {
            Ok(vec![])
        }
    }

    fn suspend(kind: VariantKind, awaitee: ChildRef, children: Vec<ChildRef>) -> VariantInfo {
        VariantInfo {
            kind,
            await_location: Some(SourceLocation {
                path: "src/main.rs".to_string(),
                line: 1,
                column: 0,
            }),
            awaitee: Some(awaitee),
            children,
        }
    }

    fn one_suspend_layout(
        name: &str,
        byte_size: u64,
        discr_offset: u64,
        awaitee: ChildRef,
        children: Vec<ChildRef>,
    ) -> AsyncFnLayout {
        let mut variants = BTreeMap::new();
        variants.insert(0, VariantInfo::terminal(VariantKind::Unresumed));
        variants.insert(3, suspend(VariantKind::Suspend(0), awaitee, children));
        AsyncFnLayout {
            type_name: name.to_string(),
            byte_size,
            discr_offset,
            discr_size: 1,
            variants,
        }
    }

    fn layouts() -> AsyncLayouts {
        let mut l = AsyncLayouts::new();
        l.insert(one_suspend_layout(
            "p::sleeper::{async_fn_env#0}",
            128,
            120,
            ChildRef::new(8, "tokio::time::Sleep"),
            vec![],
        ));
        l.insert(one_suspend_layout(
            "p::joiner::{async_fn_env#0}",
            296,
            288,
            ChildRef::new(272, "core::future::poll_fn::PollFn"),
            vec![
                ChildRef::new(0, "p::sleeper::{async_fn_env#0}"),
                ChildRef::new(128, "p::sleeper::{async_fn_env#0}"),
            ],
        ));
        l
    }

    fn decoder(roots: Vec<TaskRoot>) -> TokioDecoder {
        TokioDecoder::from_parts(layouts(), RustcVersion::new(1, 85, 1), roots)
    }

    #[test]
    fn empty_roots_decline() {
        let mem = FakeMemory::new();
        let err = decoder(vec![]).decode_tasks(&mem).expect_err("no roots");
        assert!(matches!(err, DecoderError::NotApplicable { .. }));
    }

    #[test]
    fn decodes_two_root_tasks_with_states() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3); // sleeper parked
        mem.put_u8(0x2000 + 288, 3); // joiner parked
        // joiner's two inline sleepers, both parked:
        mem.put_u8(0x2000 + 120, 3);
        mem.put_u8(0x2000 + 128 + 120, 3);
        let dec = decoder(vec![
            TaskRoot::new(1, 0x1000, "p::sleeper::{async_fn_env#0}"),
            TaskRoot::new(2, 0x2000, "p::joiner::{async_fn_env#0}"),
        ]);
        let tree = dec.decode_tasks(&mem).expect("decode");
        // 2 roots + 2 join children.
        assert_eq!(tree.len(), 4);
        assert_eq!(tree.roots(), &[TaskId::new(1), TaskId::new(2)]);
        // joiner (id 2) fans out to two children.
        assert_eq!(tree.children(TaskId::new(2)).len(), 2);
        // sleeper root is timer-blocked.
        assert_eq!(
            tree.node(TaskId::new(1)).expect("root node").state,
            TaskState::Blocked { on: BlockReason::Timer }
        );
        assert_eq!(tree.node(TaskId::new(1)).expect("root node").name, "sleeper");
    }

    #[test]
    fn logical_stack_and_wake_for_known_task() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        let dec = decoder(vec![TaskRoot::new(1, 0x1000, "p::sleeper::{async_fn_env#0}")]);
        let stack = dec.logical_stack(&mem, TaskId::new(1)).expect("stack");
        assert!(!stack.is_empty());
        assert_eq!(dec.wake_cause(&mem, TaskId::new(1)).expect("wake"), WakeCause::Timer);
    }

    #[test]
    fn unknown_task_errors() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        let dec = decoder(vec![TaskRoot::new(1, 0x1000, "p::sleeper::{async_fn_env#0}")]);
        let err = dec.logical_stack(&mem, TaskId::new(99)).expect_err("no such task");
        assert!(matches!(err, DecoderError::UnknownTask(_)));
    }

    #[test]
    fn locals_validate_task_but_are_empty() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        let dec = decoder(vec![TaskRoot::new(1, 0x1000, "p::sleeper::{async_fn_env#0}")]);
        let stack = dec.logical_stack(&mem, TaskId::new(1)).expect("stack");
        assert!(dec.locals_at(&mem, TaskId::new(1), &stack[0]).expect("known").is_empty());
    }
}
