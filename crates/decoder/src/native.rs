//! `NativeThreadsDecoder`: the trivial reference [`SemanticDecoder`] — every
//! OS thread is one root task, no synthesized frames, no wake causality.
//! Proves the trait's shape works end-to-end before any language-specific
//! decoder exists.

use crate::decoder_trait::SemanticDecoder;
use crate::error::DecoderError;
use crate::model::{
    LogicalFrame, TaskId, TaskKind, TaskNode, TaskState, TaskTree, Variable, WakeCause,
};
use crate::process_view::{ProcessView, ThreadId};

/// Maps each OS thread reported by a [`ProcessView`] onto exactly one root
/// [`crate::model::TaskNode`] of kind [`TaskKind::Thread`], with no
/// children and no synthesized frames.
///
/// Note the deliberate shortcut: this decoder assumes a [`TaskId`]'s raw
/// value equals the corresponding [`ThreadId`]'s raw value, since it is the
/// only decoder for which "one task per thread, same numbering" is exactly
/// correct. Richer decoders must not rely on this — they mint their own
/// [`TaskId`] space independent of thread numbering.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeThreadsDecoder;

impl NativeThreadsDecoder {
    /// Build a new decoder instance. Stateless: every call reads fresh from
    /// the [`ProcessView`] it is given.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn thread_for(&self, task: TaskId) -> ThreadId {
        ThreadId::new(task.raw())
    }
}

impl SemanticDecoder for NativeThreadsDecoder {
    fn decode_tasks(&self, view: &dyn ProcessView) -> Result<TaskTree, DecoderError> {
        let nodes = view
            .thread_ids()
            .into_iter()
            .map(|thread| {
                TaskNode::root(
                    TaskId::new(thread.0),
                    format!("thread {}", thread.0),
                    TaskKind::Thread,
                    TaskState::Running,
                )
            })
            .collect();
        TaskTree::try_from_nodes(nodes)
    }

    fn logical_stack(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
    ) -> Result<Vec<LogicalFrame>, DecoderError> {
        let thread = self.thread_for(task);
        let frames = view
            .physical_frames(thread)
            .map_err(|_| DecoderError::UnknownTask(task))?;
        Ok(frames.iter().map(LogicalFrame::from_physical).collect())
    }

    fn wake_cause(&self, view: &dyn ProcessView, task: TaskId) -> Result<WakeCause, DecoderError> {
        // Existence check only: an OS thread has no wake-causality concept
        // this decoder can extract, so honestly report Unknown rather than
        // guessing.
        let thread = self.thread_for(task);
        if view.registers(thread).is_err() {
            return Err(DecoderError::UnknownTask(task));
        }
        Ok(WakeCause::Unknown)
    }

    fn locals_at(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
        _frame: &LogicalFrame,
    ) -> Result<Vec<Variable>, DecoderError> {
        // Native threads carry no decoder-visible locals beyond what a
        // real DWARF-based variable evaluator (Layer 5, out of this
        // crate's scope) would compute from the physical frame directly.
        let thread = self.thread_for(task);
        if view.registers(thread).is_err() {
            return Err(DecoderError::UnknownTask(task));
        }
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_view::{PhysicalFrame, Registers};

    struct SingleThreadView {
        thread: ThreadId,
        frames: Vec<PhysicalFrame>,
    }

    impl ProcessView for SingleThreadView {
        fn thread_ids(&self) -> Vec<ThreadId> {
            vec![self.thread]
        }

        fn registers(&self, thread: ThreadId) -> Result<Registers, DecoderError> {
            if thread == self.thread {
                Ok(Registers { pc: 0, sp: 0 })
            } else {
                Err(DecoderError::UnknownThread(thread))
            }
        }

        fn read_memory(&self, _addr: u64, len: usize) -> Result<Vec<u8>, DecoderError> {
            Ok(vec![0; len])
        }

        fn physical_frames(&self, thread: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError> {
            if thread == self.thread {
                Ok(self.frames.clone())
            } else {
                Err(DecoderError::UnknownThread(thread))
            }
        }
    }

    fn view() -> SingleThreadView {
        SingleThreadView {
            thread: ThreadId::new(1),
            frames: vec![PhysicalFrame {
                pc: 0x1000,
                sp: 0x7fff,
                function_name: Some("main".to_string()),
                location: None,
            }],
        }
    }

    #[test]
    fn decode_tasks_maps_one_thread_to_one_root_task() {
        let decoder = NativeThreadsDecoder::new();
        let tree = decoder.decode_tasks(&view()).expect("decode succeeds");
        assert_eq!(tree.roots(), &[TaskId::new(1)]);
        let node = tree.node(TaskId::new(1)).expect("node exists");
        assert_eq!(node.kind, TaskKind::Thread);
        assert!(tree.children(TaskId::new(1)).is_empty());
    }

    #[test]
    fn logical_stack_copies_physical_frames_marked_physical() {
        let decoder = NativeThreadsDecoder::new();
        let stack = decoder
            .logical_stack(&view(), TaskId::new(1))
            .expect("stack lookup succeeds");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].display_name, "main");
        assert_eq!(stack[0].origin, crate::model::FrameOrigin::Physical);
    }

    #[test]
    fn logical_stack_unknown_task_errors() {
        let decoder = NativeThreadsDecoder::new();
        let err = decoder
            .logical_stack(&view(), TaskId::new(404))
            .expect_err("task 404 does not exist");
        assert!(matches!(err, DecoderError::UnknownTask(_)));
    }

    #[test]
    fn wake_cause_is_honestly_unknown() {
        let decoder = NativeThreadsDecoder::new();
        let cause = decoder
            .wake_cause(&view(), TaskId::new(1))
            .expect("known task");
        assert_eq!(cause, WakeCause::Unknown);
    }

    #[test]
    fn locals_at_is_empty_for_native_threads() {
        let decoder = NativeThreadsDecoder::new();
        let stack = decoder
            .logical_stack(&view(), TaskId::new(1))
            .expect("stack lookup succeeds");
        let locals = decoder
            .locals_at(&view(), TaskId::new(1), &stack[0])
            .expect("known task");
        assert!(locals.is_empty());
    }
}
