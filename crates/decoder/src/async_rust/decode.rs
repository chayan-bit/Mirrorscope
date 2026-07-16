//! The novel core: turn a coroutine instance in target memory into an async
//! backtrace and a lifecycle state, by reading its `__state` discriminant and
//! recursing the `__awaitee` chain (`CLAUDE.md`: "select!/join! → a tree, not
//! a stack" — this file produces the vertical await *stack* per task; the
//! horizontal fan-out lives in each variant's `children`, assembled into the
//! tree by [`super::decoder`]).
//!
//! Everything here is pure over [`ProcessView`] + [`AsyncLayouts`], so it is
//! unit-tested on any host with fake memory and synthetic layouts, exactly
//! like the Go decoder's `gwalk`.

use crate::error::DecoderError;
use crate::model::{
    BlockReason, FrameOrigin, LogicalFrame, SuspendKind, SuspendPoint, TaskState, WakeCause,
};
use crate::process_view::ProcessView;

use super::layout::{AsyncFnLayout, AsyncLayouts, ChildRef, VariantInfo};
use super::state::{self, LeafClass};

/// Hard cap on `__awaitee` recursion, guarding against a cyclic or
/// misresolved chain that would otherwise recurse unboundedly.
const MAX_AWAIT_DEPTH: usize = 64;

/// Read the little-endian discriminant of the coroutine at `base`.
fn read_discriminant(
    view: &dyn ProcessView,
    base: u64,
    layout: &AsyncFnLayout,
) -> Result<u64, DecoderError> {
    let addr = base + layout.discr_offset;
    let bytes = view.read_memory(addr, layout.discr_size as usize)?;
    let mut value: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        value |= u64::from(*b) << (8 * i);
    }
    Ok(value)
}

/// The active variant of the coroutine at `base`, selected by its
/// discriminant. Returns [`DecoderError::NotApplicable`] if the discriminant
/// matches no variant (a corrupt or misresolved layout — honesty over a wrong
/// guess).
pub fn active_variant<'a>(
    view: &dyn ProcessView,
    base: u64,
    layout: &'a AsyncFnLayout,
) -> Result<(u64, &'a VariantInfo), DecoderError> {
    let discr = read_discriminant(view, base, layout)?;
    let variant = layout
        .variant_for(discr)
        .ok_or_else(|| DecoderError::NotApplicable {
            reason: format!(
                "coroutine {} has discriminant {discr} matching no variant",
                layout.type_name
            ),
        })?;
    Ok((discr, variant))
}

/// Walk the `__awaitee` chain from the coroutine at `base` to the innermost
/// non-coroutine (leaf) future, returning its type name — what the whole task
/// is ultimately parked on. `None` if the task is not suspended or awaits
/// nothing recorded.
pub fn leaf_type(
    view: &dyn ProcessView,
    base: u64,
    layout: &AsyncFnLayout,
    layouts: &AsyncLayouts,
) -> Result<Option<String>, DecoderError> {
    let mut cur_base = base;
    let mut cur_layout = layout;
    for _ in 0..MAX_AWAIT_DEPTH {
        let (_, variant) = active_variant(view, cur_base, cur_layout)?;
        let Some(awaitee) = variant.awaitee.as_ref() else {
            return Ok(None);
        };
        match layouts.get(&awaitee.type_name) {
            Some(next) => {
                cur_base += awaitee.offset;
                cur_layout = next;
            }
            None => return Ok(Some(awaitee.type_name.clone())),
        }
    }
    Ok(None)
}

/// The portable lifecycle state of the coroutine at `base`. Prefers Tokio
/// `Header` state bits when `header_addr` is available; otherwise derives the
/// state from the coroutine's own variant. A blocked task's [`BlockReason`] is
/// refined from its leaf future.
pub fn task_state(
    view: &dyn ProcessView,
    base: u64,
    layout: &AsyncFnLayout,
    layouts: &AsyncLayouts,
    header_addr: Option<u64>,
) -> Result<TaskState, DecoderError> {
    let (_, variant) = active_variant(view, base, layout)?;
    let base_state = match header_addr {
        Some(addr) => {
            let bytes = view.read_memory(addr, std::mem::size_of::<usize>())?;
            let word = read_usize(&bytes);
            state::classify_header_state(word)
        }
        None => state::state_from_variant(variant.kind),
    };
    match base_state {
        TaskState::Blocked { .. } => {
            let block = match leaf_type(view, base, layout, layouts)? {
                Some(leaf) => state::classify_leaf(&leaf).block,
                None => BlockReason::Unknown,
            };
            Ok(TaskState::Blocked { on: block })
        }
        other => Ok(other),
    }
}

/// The best-effort wake cause for the coroutine at `base`: the classification
/// of its leaf future when suspended, else [`WakeCause::Unknown`].
pub fn wake_cause(
    view: &dyn ProcessView,
    base: u64,
    layout: &AsyncFnLayout,
    layouts: &AsyncLayouts,
) -> Result<WakeCause, DecoderError> {
    match leaf_type(view, base, layout, layouts)? {
        Some(leaf) => Ok(state::classify_leaf(&leaf).wake),
        None => Ok(WakeCause::Unknown),
    }
}

/// The children (fan-out branches, e.g. `join!`) of the coroutine at `base`:
/// the inline child coroutines of its active variant. Each carries the child's
/// absolute base address and type name for the tree assembler to recurse into.
pub fn fan_out_children(
    view: &dyn ProcessView,
    base: u64,
    layout: &AsyncFnLayout,
) -> Result<Vec<(u64, String)>, DecoderError> {
    let (_, variant) = active_variant(view, base, layout)?;
    Ok(variant
        .children
        .iter()
        .map(|c| (base + c.offset, c.type_name.clone()))
        .collect())
}

/// Build the logical async backtrace for the coroutine at `base`: one
/// synthesized frame per coroutine along the `__awaitee` chain (naming each
/// nested `async fn`), terminated by a leaf frame naming the innermost awaited
/// future with its classified suspend kind.
pub fn logical_stack(
    view: &dyn ProcessView,
    base: u64,
    type_name: &str,
    layouts: &AsyncLayouts,
) -> Result<Vec<LogicalFrame>, DecoderError> {
    let mut frames = Vec::new();
    let mut cur_base = base;
    let mut cur_type = type_name.to_string();

    for _ in 0..MAX_AWAIT_DEPTH {
        let layout = layouts
            .get(&cur_type)
            .ok_or_else(|| DecoderError::NotApplicable {
                reason: format!("no layout for coroutine type {cur_type}"),
            })?;
        let (_, variant) = active_variant(view, cur_base, layout)?;

        if !variant.kind.is_suspend() {
            frames.push(coroutine_frame(layout, variant, None));
            break;
        }
        match variant.awaitee.as_ref() {
            None => {
                frames.push(coroutine_frame(layout, variant, None));
                break;
            }
            Some(child) if layouts.is_coroutine(&child.type_name) => {
                // Intermediate frame: this async fn is awaiting a nested one.
                let suspend = SuspendPoint {
                    kind: SuspendKind::Other,
                    detail: Some(short_type(&child.type_name)),
                };
                frames.push(coroutine_frame(layout, variant, Some(suspend)));
                cur_base += child.offset;
                cur_type = child.type_name.clone();
            }
            Some(child) => {
                // Innermost coroutine frame awaiting a leaf future, plus the
                // leaf frame itself.
                let leaf = state::classify_leaf(&child.type_name);
                frames.push(coroutine_frame(
                    layout,
                    variant,
                    Some(leaf_suspend(&leaf, child)),
                ));
                frames.push(leaf_frame(child, &leaf));
                break;
            }
        }
    }
    Ok(frames)
}

/// A synthesized frame for one coroutine in the chain.
fn coroutine_frame(
    layout: &AsyncFnLayout,
    variant: &VariantInfo,
    suspend: Option<SuspendPoint>,
) -> LogicalFrame {
    LogicalFrame {
        display_name: layout.short_name(),
        location: variant.await_location.clone(),
        suspend,
        origin: FrameOrigin::Synthesized,
    }
}

/// A synthesized terminal frame naming the leaf future being awaited.
fn leaf_frame(child: &ChildRef, leaf: &LeafClass) -> LogicalFrame {
    LogicalFrame {
        display_name: short_type(&child.type_name),
        location: None,
        suspend: Some(leaf_suspend(leaf, child)),
        origin: FrameOrigin::Synthesized,
    }
}

fn leaf_suspend(leaf: &LeafClass, child: &ChildRef) -> SuspendPoint {
    SuspendPoint {
        kind: leaf.suspend.clone(),
        detail: Some(short_type(&child.type_name)),
    }
}

/// The last path component of a type name, generics stripped, for display.
fn short_type(type_name: &str) -> String {
    let head = type_name.split('<').next().unwrap_or(type_name);
    head.rsplit("::").next().unwrap_or(head).to_string()
}

/// Read a native-width `usize` from a little-endian byte slice (zero-extended
/// if short).
fn read_usize(bytes: &[u8]) -> usize {
    let mut word: usize = 0;
    for (i, b) in bytes.iter().take(std::mem::size_of::<usize>()).enumerate() {
        word |= (*b as usize) << (8 * i);
    }
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_rust::layout::{VariantInfo, VariantKind};
    use crate::model::SourceLocation;
    use crate::process_view::{PhysicalFrame, Registers, ThreadId};
    use std::collections::{BTreeMap, HashMap};

    /// Flat address->byte fake process image (mirrors the Go decoder tests).
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
                    self.bytes
                        .get(&(addr + i))
                        .copied()
                        .ok_or(DecoderError::MemoryReadFailed {
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

    fn loc(line: u32) -> SourceLocation {
        SourceLocation {
            path: "src/main.rs".to_string(),
            line,
            column: 0,
        }
    }

    /// sleeper: Suspend0 (discr 3) awaits a leaf `Sleep` at offset 8.
    fn sleeper_layout() -> AsyncFnLayout {
        let mut variants = BTreeMap::new();
        variants.insert(0, VariantInfo::terminal(VariantKind::Unresumed));
        variants.insert(1, VariantInfo::terminal(VariantKind::Returned));
        variants.insert(2, VariantInfo::terminal(VariantKind::Panicked));
        variants.insert(
            3,
            VariantInfo {
                kind: VariantKind::Suspend(0),
                await_location: Some(loc(20)),
                awaitee: Some(ChildRef::new(8, "tokio::time::sleep::Sleep")),
                children: vec![],
            },
        );
        AsyncFnLayout {
            type_name: "probe::sleeper::{async_fn_env#0}".to_string(),
            byte_size: 128,
            discr_offset: 120,
            discr_size: 1,
            variants,
        }
    }

    /// inner_leaf: Suspend0 awaits a leaf channel `Recv` at offset 16.
    fn inner_leaf_layout() -> AsyncFnLayout {
        let mut variants = BTreeMap::new();
        variants.insert(0, VariantInfo::terminal(VariantKind::Unresumed));
        variants.insert(
            3,
            VariantInfo {
                kind: VariantKind::Suspend(0),
                await_location: Some(loc(5)),
                awaitee: Some(ChildRef::new(16, "tokio::sync::mpsc::bounded::Recv<u32>")),
                children: vec![],
            },
        );
        AsyncFnLayout {
            type_name: "probe::inner_leaf::{async_fn_env#0}".to_string(),
            byte_size: 48,
            discr_offset: 40,
            discr_size: 1,
            variants,
        }
    }

    /// nested_parent: Suspend0 awaits the inner_leaf coroutine at offset 8.
    fn nested_parent_layout() -> AsyncFnLayout {
        let mut variants = BTreeMap::new();
        variants.insert(0, VariantInfo::terminal(VariantKind::Unresumed));
        variants.insert(
            3,
            VariantInfo {
                kind: VariantKind::Suspend(0),
                await_location: Some(loc(10)),
                awaitee: Some(ChildRef::new(8, "probe::inner_leaf::{async_fn_env#0}")),
                children: vec![],
            },
        );
        AsyncFnLayout {
            type_name: "probe::nested_parent::{async_fn_env#0}".to_string(),
            byte_size: 64,
            discr_offset: 56,
            discr_size: 1,
            variants,
        }
    }

    /// joiner: Suspend0 awaits a leaf poll_fn, with two inline sleeper children.
    fn joiner_layout() -> AsyncFnLayout {
        let mut variants = BTreeMap::new();
        variants.insert(0, VariantInfo::terminal(VariantKind::Unresumed));
        variants.insert(
            3,
            VariantInfo {
                kind: VariantKind::Suspend(0),
                await_location: Some(loc(18)),
                awaitee: Some(ChildRef::new(272, "core::future::poll_fn::PollFn")),
                children: vec![
                    ChildRef::new(0, "probe::sleeper::{async_fn_env#0}"),
                    ChildRef::new(128, "probe::sleeper::{async_fn_env#0}"),
                ],
            },
        );
        AsyncFnLayout {
            type_name: "probe::joiner::{async_fn_env#0}".to_string(),
            byte_size: 296,
            discr_offset: 288,
            discr_size: 1,
            variants,
        }
    }

    fn layouts() -> AsyncLayouts {
        let mut l = AsyncLayouts::new();
        l.insert(sleeper_layout());
        l.insert(inner_leaf_layout());
        l.insert(nested_parent_layout());
        l.insert(joiner_layout());
        l
    }

    #[test]
    fn reads_discriminant_and_selects_suspend_variant() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3); // sleeper parked at Suspend0
        let layout = sleeper_layout();
        let (discr, variant) = active_variant(&mem, 0x1000, &layout).expect("active variant");
        assert_eq!(discr, 3);
        assert_eq!(variant.kind, VariantKind::Suspend(0));
    }

    #[test]
    fn unknown_discriminant_declines() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 9);
        let err = active_variant(&mem, 0x1000, &sleeper_layout()).expect_err("no such variant");
        assert!(matches!(err, DecoderError::NotApplicable { .. }));
    }

    #[test]
    fn sleeper_leaf_is_the_timer() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        let leaf = leaf_type(&mem, 0x1000, &sleeper_layout(), &layouts())
            .expect("leaf")
            .expect("some leaf");
        assert!(leaf.contains("Sleep"));
    }

    #[test]
    fn nested_stack_names_both_async_fns_and_leaf() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x2000 + 56, 3); // nested_parent Suspend0
        mem.put_u8(0x2000 + 8 + 40, 3); // inner_leaf (at +8) Suspend0
        let frames = logical_stack(
            &mem,
            0x2000,
            "probe::nested_parent::{async_fn_env#0}",
            &layouts(),
        )
        .expect("stack");
        let names: Vec<&str> = frames.iter().map(|f| f.display_name.as_str()).collect();
        assert!(names.contains(&"nested_parent"), "frames: {names:?}");
        assert!(names.contains(&"inner_leaf"), "frames: {names:?}");
        // Innermost is the channel-recv leaf.
        assert_eq!(
            frames
                .last()
                .expect("leaf frame")
                .suspend
                .as_ref()
                .expect("suspend")
                .kind,
            SuspendKind::ChannelRecv
        );
        // The nested_parent frame carries its await source line.
        assert_eq!(
            frames[0].location.as_ref().expect("await location").line,
            10
        );
    }

    #[test]
    fn state_of_parked_sleeper_is_timer_blocked() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        let st = task_state(&mem, 0x1000, &sleeper_layout(), &layouts(), None).expect("state");
        assert_eq!(
            st,
            TaskState::Blocked {
                on: BlockReason::Timer
            }
        );
    }

    #[test]
    fn state_uses_header_bits_when_available() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        // Header word at 0x9000: COMPLETE bit set -> Completed regardless of
        // variant. Map the full usize-wide word (low byte carries the bits).
        mem.put_u8(0x9000, state::bits::COMPLETE as u8);
        for i in 1..8 {
            mem.put_u8(0x9000 + i, 0);
        }
        let st =
            task_state(&mem, 0x1000, &sleeper_layout(), &layouts(), Some(0x9000)).expect("state");
        assert_eq!(st, TaskState::Completed);
    }

    #[test]
    fn wake_cause_of_sleeper_is_timer() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 3);
        let wc = wake_cause(&mem, 0x1000, &sleeper_layout(), &layouts()).expect("wake");
        assert_eq!(wc, WakeCause::Timer);
    }

    #[test]
    fn joiner_fans_out_to_two_children() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x3000 + 288, 3); // joiner Suspend0
        let children = fan_out_children(&mem, 0x3000, &joiner_layout()).expect("children");
        assert_eq!(children.len(), 2);
        assert_eq!(
            children[0],
            (0x3000, "probe::sleeper::{async_fn_env#0}".to_string())
        );
        assert_eq!(
            children[1],
            (0x3000 + 128, "probe::sleeper::{async_fn_env#0}".to_string())
        );
    }

    #[test]
    fn unresumed_task_is_runnable_with_single_frame() {
        let mut mem = FakeMemory::new();
        mem.put_u8(0x1000 + 120, 0); // Unresumed
        let st = task_state(&mem, 0x1000, &sleeper_layout(), &layouts(), None).expect("state");
        assert_eq!(st, TaskState::Runnable);
        let frames = logical_stack(&mem, 0x1000, "probe::sleeper::{async_fn_env#0}", &layouts())
            .expect("stack");
        assert_eq!(frames.len(), 1);
    }
}
