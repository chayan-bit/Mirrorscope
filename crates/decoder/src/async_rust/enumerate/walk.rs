//! Walking Tokio's `OwnedTasks`: from a resolved `CONTEXT` address, follow the
//! vendored [`TokioRuntimeLayout`] offset chain through the scheduler `Handle`,
//! the sharded task list, and each shard's intrusive linked list, yielding one
//! [`RawTask`] per live spawned task.
//!
//! Pure over an abstract [`ProcessView`] plus the byte layout, so it
//! unit-tests on any host against a synthetic in-memory runtime — exactly like
//! the Go decoder's `gwalk`.

use crate::error::DecoderError;
use crate::process_view::ProcessView;

use super::error::EnumerateError;
use super::layout::TokioRuntimeLayout;

/// Upper bound on shards read from a `ShardedList`, guarding a misresolved
/// `lists` fat-pointer length that would otherwise drive an unbounded loop.
/// Real runtimes shard to at most a few hundred.
const MAX_SHARDS: u64 = 1 << 16;

/// Upper bound on tasks collected across all shards, guarding a corrupt
/// intrusive list (self-cycle) from looping forever.
const MAX_TASKS: usize = 1 << 20;

/// One task discovered by the `OwnedTasks` walk, before type resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTask {
    /// Absolute address of the task's `Header`.
    pub header: u64,
    /// Absolute (runtime) address of the task's `raw::poll::<T, S>` function,
    /// read from its vtable — de-biased to a static address and mapped to the
    /// future type `T` by the caller.
    pub poll_runtime: u64,
    /// Absolute address of the task's inline future (coroutine) instance.
    pub future: u64,
}

/// Read a little-endian `u64` from the target at `addr`.
fn read_u64(view: &dyn ProcessView, addr: u64) -> Result<u64, DecoderError> {
    let bytes = view.read_memory(addr, 8)?;
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| DecoderError::MemoryReadFailed {
            addr,
            len: 8,
            reason: "short read".to_string(),
        })?;
    Ok(u64::from_le_bytes(arr))
}

/// Resolve the scheduler `Handle`'s `OwnedTasks` address from a thread's
/// `CONTEXT`, or `Ok(None)` if this thread holds no live runtime handle (the
/// current-thread variant stores a null `Arc` when the runtime is not entered).
fn owned_tasks_addr(
    view: &dyn ProcessView,
    context_addr: u64,
    layout: &TokioRuntimeLayout,
) -> Result<Option<u64>, DecoderError> {
    let handle_cell = context_addr + layout.context_current;
    let arc_ptr = read_u64(view, handle_cell + layout.handle_cell_value)?;
    if arc_ptr == 0 {
        return Ok(None);
    }
    let handle = arc_ptr + layout.arc_data;
    let shared = handle + layout.handle_shared;
    Ok(Some(shared + layout.shared_owned))
}

/// Walk every shard's intrusive list, collecting each task's `Header`, poll
/// address, and future address.
fn collect_from_owned(
    view: &dyn ProcessView,
    owned: u64,
    layout: &TokioRuntimeLayout,
    out: &mut Vec<RawTask>,
) -> Result<(), EnumerateError> {
    let list = owned + layout.owned_list;
    let data_ptr = read(view, list + layout.sharded_lists)?;
    let len = read(view, list + layout.sharded_lists + 8)?;
    if len > MAX_SHARDS {
        return Err(EnumerateError::Implausible(format!(
            "ShardedList reports {len} shards"
        )));
    }
    for shard in 0..len {
        let mutex = data_ptr + shard * layout.shard_stride;
        let head = read(view, mutex + layout.mutex_data + layout.list_head)?;
        walk_shard(view, head, layout, out)?;
    }
    Ok(())
}

/// Walk one shard's intrusive list starting at `head` (0 = empty).
fn walk_shard(
    view: &dyn ProcessView,
    head: u64,
    layout: &TokioRuntimeLayout,
    out: &mut Vec<RawTask>,
) -> Result<(), EnumerateError> {
    let mut node = head;
    while node != 0 {
        if out.len() >= MAX_TASKS {
            return Err(EnumerateError::Implausible(
                "task count exceeded MAX_TASKS; list likely cyclic".to_string(),
            ));
        }
        let vtable = read(view, node + layout.header_vtable)?;
        let poll_runtime = read(view, vtable + layout.vtable_poll)?;
        let trailer_offset = read(view, vtable + layout.vtable_trailer_offset)?;
        out.push(RawTask {
            header: node,
            poll_runtime,
            future: node + layout.future_offset,
        });
        let trailer = node + trailer_offset;
        node = read(view, trailer + layout.trailer_owned_next)?;
    }
    Ok(())
}

/// [`read_u64`] with the error mapped into [`EnumerateError::Parse`]-free
/// [`EnumerateError`] space (memory failures decline enumeration honestly).
fn read(view: &dyn ProcessView, addr: u64) -> Result<u64, EnumerateError> {
    read_u64(view, addr).map_err(|e| EnumerateError::Implausible(e.to_string()))
}

/// Walk the `OwnedTasks` reachable from `context_addr`, appending every live
/// task to `out`. Returns `Ok(false)` (no tasks appended) when the thread
/// holds no live runtime handle, `Ok(true)` when a runtime was found.
///
/// # Errors
/// [`EnumerateError::Implausible`] on a misresolved layout (bad shard count,
/// cyclic list, or unreadable pointer).
pub fn walk_context(
    view: &dyn ProcessView,
    context_addr: u64,
    layout: &TokioRuntimeLayout,
    out: &mut Vec<RawTask>,
) -> Result<bool, EnumerateError> {
    let owned = owned_tasks_addr(view, context_addr, layout)
        .map_err(|e| EnumerateError::Implausible(e.to_string()))?;
    match owned {
        Some(owned) => {
            collect_from_owned(view, owned, layout, out)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_rust::enumerate::layout::TokioVersion;
    use crate::process_view::{PhysicalFrame, Registers, ThreadId};
    use std::collections::BTreeMap;

    struct FakeMemory {
        bytes: BTreeMap<u64, u8>,
    }
    impl FakeMemory {
        fn new() -> Self {
            Self {
                bytes: BTreeMap::new(),
            }
        }
        fn put_u64(&mut self, addr: u64, v: u64) {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.bytes.insert(addr + i as u64, *b);
            }
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

    fn layout() -> TokioRuntimeLayout {
        TokioRuntimeLayout::vendored(TokioVersion::new(1, 44, 2)).expect("1.44")
    }

    /// Build a synthetic runtime: `CONTEXT` at `ctx`, a scheduler `Arc` whose
    /// `OwnedTasks` has `shard_count` shards, and each `(header, vtable,
    /// shard)` task chained into its named shard's intrusive list. Task headers
    /// must be spaced past their 8-byte fields; the vtable advertises
    /// `trailer_offset` and the future sits at `header + future_offset`.
    fn build(
        mem: &mut FakeMemory,
        l: &TokioRuntimeLayout,
        ctx: u64,
        tasks: &[(u64, u64, usize)],
        shard_count: u64,
    ) {
        let arc = 0x5000;
        mem.put_u64(ctx + l.context_current + l.handle_cell_value, arc);
        let owned = arc + l.arc_data + l.handle_shared + l.shared_owned;
        let data_ptr = 0x6000;
        mem.put_u64(owned + l.owned_list + l.sharded_lists, data_ptr);
        mem.put_u64(owned + l.owned_list + l.sharded_lists + 8, shard_count);
        let trailer_offset = 0x400u64;
        let mut shard_head: Vec<u64> = vec![0; shard_count as usize];
        let mut shard_prev: Vec<u64> = vec![0; shard_count as usize];
        for &(header, vtable, s) in tasks {
            mem.put_u64(header + l.header_vtable, vtable);
            mem.put_u64(vtable + l.vtable_poll, 0xAAAA_0000 + header);
            mem.put_u64(vtable + l.vtable_trailer_offset, trailer_offset);
            if shard_head[s] == 0 {
                shard_head[s] = header;
            } else {
                mem.put_u64(
                    shard_prev[s] + trailer_offset + l.trailer_owned_next,
                    header,
                );
            }
            mem.put_u64(header + trailer_offset + l.trailer_owned_next, 0);
            shard_prev[s] = header;
        }
        for (s, &head) in shard_head.iter().enumerate() {
            let mutex = data_ptr + s as u64 * l.shard_stride;
            mem.put_u64(mutex + l.mutex_data + l.list_head, head);
        }
    }

    #[test]
    fn walks_two_tasks_in_separate_shards() {
        let l = layout();
        let mut mem = FakeMemory::new();
        let ctx = 0x1000;
        build(
            &mut mem,
            &l,
            ctx,
            &[(0x10000, 0x9000, 0), (0x20000, 0x9000, 1)],
            4,
        );
        let mut out = Vec::new();
        let found = walk_context(&mem, ctx, &l, &mut out).expect("walk");
        assert!(found);
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|t| t.header == 0x10000 && t.future == 0x10000 + l.future_offset));
        assert!(out.iter().any(|t| t.header == 0x20000));
    }

    #[test]
    fn walks_multiple_tasks_in_one_shard() {
        let l = layout();
        let mut mem = FakeMemory::new();
        let ctx = 0x1000;
        build(
            &mut mem,
            &l,
            ctx,
            &[
                (0x20000, 0x9000, 0),
                (0x21000, 0x9000, 0),
                (0x22000, 0x9000, 0),
            ],
            1,
        );
        let mut out = Vec::new();
        walk_context(&mem, ctx, &l, &mut out).expect("walk");
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn null_handle_reports_no_runtime() {
        let l = layout();
        let mut mem = FakeMemory::new();
        let ctx = 0x1000;
        mem.put_u64(ctx + l.context_current + l.handle_cell_value, 0); // null Arc
        let mut out = Vec::new();
        assert!(!walk_context(&mem, ctx, &l, &mut out).expect("walk"));
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_implausible_shard_count() {
        let l = layout();
        let mut mem = FakeMemory::new();
        let ctx = 0x1000;
        let arc = 0x5000;
        mem.put_u64(ctx + l.context_current + l.handle_cell_value, arc);
        let owned = arc + l.arc_data + l.handle_shared + l.shared_owned;
        mem.put_u64(owned + l.owned_list + l.sharded_lists, 0x6000);
        mem.put_u64(owned + l.owned_list + l.sharded_lists + 8, MAX_SHARDS + 1);
        let mut out = Vec::new();
        let err = walk_context(&mem, ctx, &l, &mut out).expect_err("implausible");
        assert!(matches!(err, EnumerateError::Implausible(_)));
    }
}
