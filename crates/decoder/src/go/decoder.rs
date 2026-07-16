//! [`GoroutineDecoder`]: the [`SemanticDecoder`] that turns a stopped Go
//! process into a [`TaskTree`] of goroutines.

use std::collections::HashSet;

use crate::decoder_trait::SemanticDecoder;
use crate::error::DecoderError;
use crate::model::{
    BlockReason, FrameOrigin, LogicalFrame, SuspendKind, SuspendPoint, TaskId, TaskKind, TaskNode,
    TaskState, TaskTree, Variable, WakeCause,
};
use crate::process_view::{ProcessView, ThreadId};

use super::gwalk::{walk_goroutines, GoroutineInfo};
use super::offsets::GoLayout;
use super::status;
use super::{load_layout, GoDecodeError};

/// Reconstructs the goroutine tree of a Go target by walking `runtime.allgs`
/// over a [`ProcessView`], using a [`GoLayout`] resolved once from the target
/// binary.
///
/// Stateless per call, like [`crate::native::NativeThreadsDecoder`]: every
/// trait method re-reads fresh goroutine state from the view it is given, so a
/// caller stepping a replay sees each checkpoint's goroutines, not a stale
/// snapshot.
#[derive(Debug, Clone)]
pub struct GoroutineDecoder {
    layout: GoLayout,
}

impl GoroutineDecoder {
    /// Build a decoder from an already-resolved layout (e.g. for tests with a
    /// synthetic layout, or when the caller resolved it once and reuses it).
    #[must_use]
    pub fn from_layout(layout: GoLayout) -> Self {
        Self { layout }
    }

    /// Build a decoder by resolving the runtime layout from the target's
    /// binary image (its executable bytes).
    ///
    /// # Errors
    /// Propagates [`GoDecodeError`] if the image is not a Go binary or its
    /// runtime layout cannot be resolved.
    pub fn from_binary(image: &[u8]) -> Result<Self, GoDecodeError> {
        Ok(Self {
            layout: load_layout(image)?,
        })
    }

    /// The resolved layout this decoder reads with (provenance, offsets).
    #[must_use]
    pub fn layout(&self) -> &GoLayout {
        &self.layout
    }

    /// Find the goroutine a [`TaskId`] refers to, re-reading from `view`.
    fn goroutine(&self, view: &dyn ProcessView, task: TaskId) -> Result<GoroutineInfo, DecoderError> {
        walk_goroutines(view, &self.layout)?
            .into_iter()
            .find(|g| g.goid == task.raw() as i64)
            .ok_or(DecoderError::UnknownTask(task))
    }
}

impl SemanticDecoder for GoroutineDecoder {
    fn decode_tasks(&self, view: &dyn ProcessView) -> Result<TaskTree, DecoderError> {
        let goroutines = walk_goroutines(view, &self.layout)?;
        // User goroutines have positive goids; g0/system stacks share goid 0
        // (many per M), so skipping them both avoids duplicate ids and keeps
        // the tree to goroutines a user reasons about. De-dup defensively.
        let live: HashSet<i64> = goroutines
            .iter()
            .map(|g| g.goid)
            .filter(|&goid| goid > 0)
            .collect();

        let mut seen = HashSet::new();
        let mut nodes = Vec::new();
        for g in &goroutines {
            if g.goid <= 0 || !seen.insert(g.goid) {
                continue;
            }
            nodes.push(node_for(g, &live));
        }
        TaskTree::try_from_nodes(nodes)
    }

    fn logical_stack(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
    ) -> Result<Vec<LogicalFrame>, DecoderError> {
        let g = self.goroutine(view, task)?;
        match g.thread {
            // Running/syscall goroutine: its live stack is the OS thread's
            // physical stack (unwound by Layer 5 behind the view).
            Some(thread) => running_stack(view, thread),
            // Parked goroutine: v1 surfaces the logical *start* frame from the
            // saved resume PC. Full unwinding of a parked goroutine's saved
            // stack is future work (needs Layer-5 unwinding over sched.sp).
            None => Ok(vec![parked_start_frame(&g)]),
        }
    }

    fn wake_cause(&self, view: &dyn ProcessView, task: TaskId) -> Result<WakeCause, DecoderError> {
        let g = self.goroutine(view, task)?;
        Ok(match g.state {
            TaskState::Blocked { .. } => status::wake_cause(g.wait_reason),
            _ => WakeCause::Unknown,
        })
    }

    fn locals_at(
        &self,
        view: &dyn ProcessView,
        task: TaskId,
        _frame: &LogicalFrame,
    ) -> Result<Vec<Variable>, DecoderError> {
        // Existence check only; real local evaluation is a Layer-5 DWARF job,
        // out of this crate's scope (matches NativeThreadsDecoder).
        self.goroutine(view, task)?;
        Ok(Vec::new())
    }
}

/// Build a [`TaskNode`] for a goroutine, wiring its parent edge only when the
/// creator goroutine is itself live (else it roots).
fn node_for(g: &GoroutineInfo, live: &HashSet<i64>) -> TaskNode {
    let parent = g
        .parent_goid
        .filter(|p| *p > 0 && *p != g.goid && live.contains(p))
        .map(|p| TaskId::new(p as u64));
    TaskNode {
        id: TaskId::new(g.goid as u64),
        name: format!("goroutine {}", g.goid),
        kind: TaskKind::Goroutine,
        state: g.state.clone(),
        parent,
    }
}

/// The physical stack of the OS thread a running goroutine occupies.
fn running_stack(view: &dyn ProcessView, thread: ThreadId) -> Result<Vec<LogicalFrame>, DecoderError> {
    let frames = view
        .physical_frames(thread)
        .map_err(|_| DecoderError::UnknownThread(thread))?;
    Ok(frames.iter().map(LogicalFrame::from_physical).collect())
}

/// A single synthesized frame at a parked goroutine's saved resume PC,
/// annotated with the suspend point derived from its block reason.
fn parked_start_frame(g: &GoroutineInfo) -> LogicalFrame {
    let suspend = match &g.state {
        TaskState::Blocked { on } => Some(SuspendPoint {
            kind: suspend_kind(on),
            detail: Some(g.wait_reason_str.to_string()),
        }),
        _ => None,
    };
    LogicalFrame {
        display_name: format!("goroutine {} (parked @ {:#x})", g.goid, g.sched_pc),
        location: None,
        suspend,
        origin: FrameOrigin::Synthesized,
    }
}

/// Map a [`BlockReason`] onto the display-oriented [`SuspendKind`].
fn suspend_kind(reason: &BlockReason) -> SuspendKind {
    match reason {
        BlockReason::Channel { .. } => SuspendKind::ChannelRecv,
        BlockReason::Lock { .. } => SuspendKind::Lock,
        BlockReason::Io { .. } => SuspendKind::Io,
        BlockReason::Join { .. } => SuspendKind::Join,
        BlockReason::Timer => SuspendKind::Timer,
        _ => SuspendKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::go::offsets::{GStructOffsets, LayoutSource};
    use crate::go::version::GoVersion;
    use crate::process_view::{PhysicalFrame, Registers};
    use std::collections::BTreeMap;

    struct FakeMemory {
        bytes: BTreeMap<u64, u8>,
        frames: Vec<PhysicalFrame>,
    }

    impl FakeMemory {
        fn put_u64(&mut self, addr: u64, v: u64) {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.bytes.insert(addr + i as u64, *b);
            }
        }
        fn put_u32(&mut self, addr: u64, v: u32) {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.bytes.insert(addr + i as u64, *b);
            }
        }
        fn put_u8(&mut self, addr: u64, v: u8) {
            self.bytes.insert(addr, v);
        }
    }

    impl ProcessView for FakeMemory {
        fn thread_ids(&self) -> Vec<ThreadId> {
            vec![ThreadId::new(4242)]
        }
        fn registers(&self, _t: ThreadId) -> Result<Registers, DecoderError> {
            Ok(Registers { pc: 0, sp: 0 })
        }
        fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, DecoderError> {
            let mut out = Vec::with_capacity(len);
            for i in 0..len as u64 {
                out.push(self.bytes.get(&(addr + i)).copied().ok_or(
                    DecoderError::MemoryReadFailed {
                        addr,
                        len,
                        reason: "unmapped".to_string(),
                    },
                )?);
            }
            Ok(out)
        }
        fn physical_frames(&self, thread: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError> {
            if thread == ThreadId::new(4242) {
                Ok(self.frames.clone())
            } else {
                Err(DecoderError::UnknownThread(thread))
            }
        }
    }

    fn layout() -> GoLayout {
        GoLayout {
            ptr_size: 8,
            allgs_addr: 0x1_0000,
            allglen_addr: None,
            load_bias: 0,
            g: GStructOffsets::vendored(GoVersion::new(1, 24, 0)).expect("1.24"),
            m_procid: Some(72),
            source: LayoutSource::Vendored(GoVersion::new(1, 24, 0)),
        }
    }

    fn write_g(
        mem: &mut FakeMemory,
        layout: &GoLayout,
        gp: u64,
        goid: i64,
        status: u32,
        waitreason: u8,
        parent: i64,
    ) {
        let g = &layout.g;
        mem.put_u64(gp + g.goid, goid as u64);
        mem.put_u32(gp + g.atomicstatus, status);
        mem.put_u8(gp + g.waitreason, waitreason);
        mem.put_u64(gp + g.gopc, 0xAAAA);
        mem.put_u64(gp + g.startpc, 0xBBBB);
        mem.put_u64(gp + g.sched_pc, 0xC0DE + goid as u64);
        mem.put_u64(gp + g.sched_sp, 0xDDDD);
        mem.put_u64(gp + g.stack_lo, 0x7000);
        mem.put_u64(gp + g.stack_hi, 0x8000);
        mem.put_u64(gp + g.m, 0);
        if let Some(off) = g.parent_goid {
            mem.put_u64(gp + off, parent as u64);
        }
    }

    /// Build a process with: main(1) running on thread 4242, child(2)
    /// chan-receive-blocked with parent 1, child(3) sleep-blocked parent 1,
    /// plus a g0 (goid 0) that must be skipped.
    fn scenario() -> (GoLayout, FakeMemory) {
        let layout = layout();
        let mut mem = FakeMemory {
            bytes: BTreeMap::new(),
            frames: vec![PhysicalFrame {
                pc: 0x1234,
                sp: 0x7fff,
                function_name: Some("main.spinForever".to_string()),
                location: None,
            }],
        };
        let addrs = [0x10_0000, 0x10_0400, 0x10_0800, 0x10_0c00];
        mem.put_u64(layout.allgs_addr, 0x2_0000);
        mem.put_u64(layout.allgs_addr + 8, addrs.len() as u64);
        for (i, a) in addrs.iter().enumerate() {
            mem.put_u64(0x2_0000 + i as u64 * 8, *a);
        }
        // main goroutine, running, m -> procid 4242.
        write_g(&mut mem, &layout, addrs[0], 1, 2, 0, 0);
        mem.put_u64(addrs[0] + layout.g.m, 0x30_0000);
        mem.put_u64(0x30_0000 + 72, 4242);
        write_g(&mut mem, &layout, addrs[1], 2, 4, 14, 1); // chan receive
        write_g(&mut mem, &layout, addrs[2], 3, 4, 19, 1); // sleep
        write_g(&mut mem, &layout, addrs[3], 0, 3, 0, 0); // g0 syscall, skipped
        (layout, mem)
    }

    #[test]
    fn decode_tasks_builds_goroutine_tree_with_parent_edges() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        let tree = decoder.decode_tasks(&mem).expect("decode");
        // goid 0 skipped -> three tasks.
        assert_eq!(tree.len(), 3);
        assert_eq!(tree.roots(), &[TaskId::new(1)]);
        assert_eq!(
            tree.children(TaskId::new(1)),
            &[TaskId::new(2), TaskId::new(3)]
        );
        let main = tree.node(TaskId::new(1)).expect("main node");
        assert_eq!(main.kind, TaskKind::Goroutine);
        assert_eq!(main.state, TaskState::Running);
    }

    #[test]
    fn blocked_states_carry_reasons() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        let tree = decoder.decode_tasks(&mem).expect("decode");
        assert_eq!(
            tree.node(TaskId::new(2)).expect("g2").state,
            TaskState::Blocked {
                on: BlockReason::Channel {
                    detail: Some("chan receive".to_string())
                }
            }
        );
        assert_eq!(
            tree.node(TaskId::new(3)).expect("g3").state,
            TaskState::Blocked { on: BlockReason::Timer }
        );
    }

    #[test]
    fn logical_stack_of_running_goroutine_is_thread_stack() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        let stack = decoder
            .logical_stack(&mem, TaskId::new(1))
            .expect("running stack");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].display_name, "main.spinForever");
        assert_eq!(stack[0].origin, FrameOrigin::Physical);
    }

    #[test]
    fn logical_stack_of_parked_goroutine_is_synthesized_start() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        let stack = decoder
            .logical_stack(&mem, TaskId::new(2))
            .expect("parked stack");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].origin, FrameOrigin::Synthesized);
        assert!(stack[0].display_name.contains("parked"));
        assert_eq!(
            stack[0].suspend.as_ref().map(|s| s.kind.clone()),
            Some(SuspendKind::ChannelRecv)
        );
    }

    #[test]
    fn wake_cause_reflects_wait_reason() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        assert_eq!(
            decoder.wake_cause(&mem, TaskId::new(3)).expect("g3 wake"),
            WakeCause::Timer
        );
        assert_eq!(
            decoder.wake_cause(&mem, TaskId::new(1)).expect("g1 wake"),
            WakeCause::Unknown
        );
    }

    #[test]
    fn unknown_task_errors() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        let err = decoder
            .logical_stack(&mem, TaskId::new(999))
            .expect_err("no such goroutine");
        assert!(matches!(err, DecoderError::UnknownTask(_)));
    }

    #[test]
    fn locals_are_empty_but_validate_task() {
        let (layout, mem) = scenario();
        let decoder = GoroutineDecoder::from_layout(layout);
        let frame = LogicalFrame {
            display_name: "x".to_string(),
            location: None,
            suspend: None,
            origin: FrameOrigin::Synthesized,
        };
        assert!(decoder
            .locals_at(&mem, TaskId::new(1), &frame)
            .expect("known task")
            .is_empty());
    }
}
