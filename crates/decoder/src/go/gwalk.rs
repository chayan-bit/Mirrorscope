//! Walking `runtime.allgs`: given a [`ProcessView`] and a resolved
//! [`GoLayout`], read every live goroutine's `g` struct into a portable
//! [`GoroutineInfo`]. Pure over the abstract view + byte layout, so it is
//! unit-tested on any host with a synthetic in-memory `g` list.

use crate::error::DecoderError;
use crate::model::TaskState;
use crate::process_view::{ProcessView, ThreadId};

use super::offsets::GoLayout;
use super::status::{self, GoStatus};

/// Upper bound on the goroutine count read from `runtime.allgs`, guarding
/// against a corrupt/misresolved slice length that would otherwise drive an
/// unbounded allocation. Real programs stay far below this.
const MAX_GOROUTINES: u64 = 1 << 20;

/// One goroutine's decoded runtime state — the raw material the decoder turns
/// into a [`crate::model::TaskNode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoroutineInfo {
    /// `g.goid`.
    pub goid: i64,
    /// Raw `g.atomicstatus` (with any `_Gscan` bit preserved).
    pub raw_status: u32,
    /// Decoded run status.
    pub status: GoStatus,
    /// Portable lifecycle state.
    pub state: TaskState,
    /// Raw `g.waitreason` byte.
    pub wait_reason: u8,
    /// Human-readable wait-reason phrase (vendored table).
    pub wait_reason_str: &'static str,
    /// `g.gopc`: PC of the creating `go` statement.
    pub gopc: u64,
    /// `g.startpc`: entry-function PC.
    pub startpc: u64,
    /// `g.sched.pc`: saved resume PC (meaningful when parked).
    pub sched_pc: u64,
    /// `g.sched.sp`: saved stack pointer (meaningful when parked).
    pub sched_sp: u64,
    /// `g.stack.lo`: goroutine stack low bound.
    pub stack_lo: u64,
    /// `g.stack.hi`: goroutine stack high bound.
    pub stack_hi: u64,
    /// `g.m`: pointer to the running M, or 0.
    pub m_ptr: u64,
    /// `g.parentGoid`, when the field exists on this Go version.
    pub parent_goid: Option<i64>,
    /// OS thread running this goroutine, resolved via `m.procid` for a
    /// running/syscall goroutine. `None` when parked or unresolved.
    pub thread: Option<ThreadId>,
}

/// Read a little-endian `u64` from the target at `addr`.
fn read_u64(view: &dyn ProcessView, addr: u64) -> Result<u64, DecoderError> {
    let bytes = view.read_memory(addr, 8)?;
    let arr: [u8; 8] = bytes.try_into().map_err(|_| short_read(addr, 8))?;
    Ok(u64::from_le_bytes(arr))
}

/// Read a little-endian `u32` from the target at `addr`.
fn read_u32(view: &dyn ProcessView, addr: u64) -> Result<u32, DecoderError> {
    let bytes = view.read_memory(addr, 4)?;
    let arr: [u8; 4] = bytes.try_into().map_err(|_| short_read(addr, 4))?;
    Ok(u32::from_le_bytes(arr))
}

/// Read a single byte from the target at `addr`.
fn read_u8(view: &dyn ProcessView, addr: u64) -> Result<u8, DecoderError> {
    let bytes = view.read_memory(addr, 1)?;
    bytes.first().copied().ok_or_else(|| short_read(addr, 1))
}

fn short_read(addr: u64, len: usize) -> DecoderError {
    DecoderError::MemoryReadFailed {
        addr,
        len,
        reason: "short read from process view".to_string(),
    }
}

/// Read the `runtime.allgs` slice header and return `(data_ptr, len)`.
fn read_allgs_header(
    view: &dyn ProcessView,
    layout: &GoLayout,
) -> Result<(u64, u64), DecoderError> {
    let allgs = layout.allgs_addr + layout.load_bias;
    let data = read_u64(view, allgs)?;
    let len = read_u64(view, allgs + layout.slice_len_offset())?;
    if len > MAX_GOROUTINES {
        return Err(DecoderError::NotApplicable {
            reason: format!("runtime.allgs length {len} is implausible; layout likely misresolved"),
        });
    }
    Ok((data, len))
}

/// Read one goroutine's `g` struct at `gp` into a [`GoroutineInfo`].
fn read_goroutine(
    view: &dyn ProcessView,
    layout: &GoLayout,
    gp: u64,
) -> Result<GoroutineInfo, DecoderError> {
    let g = &layout.g;
    let raw_status = read_u32(view, gp + g.atomicstatus)?;
    let status = GoStatus::from_raw(raw_status);
    let wait_reason = read_u8(view, gp + g.waitreason)?;
    let m_ptr = read_u64(view, gp + g.m)?;
    let parent_goid = match g.parent_goid {
        Some(off) => Some(read_u64(view, gp + off)? as i64),
        None => None,
    };
    let thread = resolve_thread(view, layout, status, m_ptr)?;

    Ok(GoroutineInfo {
        goid: read_u64(view, gp + g.goid)? as i64,
        raw_status,
        status,
        state: status.to_task_state(wait_reason),
        wait_reason,
        wait_reason_str: status::wait_reason_str(wait_reason),
        gopc: read_u64(view, gp + g.gopc)?,
        startpc: read_u64(view, gp + g.startpc)?,
        sched_pc: read_u64(view, gp + g.sched_pc)?,
        sched_sp: read_u64(view, gp + g.sched_sp)?,
        stack_lo: read_u64(view, gp + g.stack_lo)?,
        stack_hi: read_u64(view, gp + g.stack_hi)?,
        m_ptr,
        parent_goid,
        thread,
    })
}

/// Map a running/syscall goroutine to its OS thread via `m.procid`, when the
/// `procid` offset is known and the M pointer is non-null.
fn resolve_thread(
    view: &dyn ProcessView,
    layout: &GoLayout,
    status: GoStatus,
    m_ptr: u64,
) -> Result<Option<ThreadId>, DecoderError> {
    let is_on_m = matches!(status, GoStatus::Running | GoStatus::Syscall);
    match (is_on_m, m_ptr, layout.m_procid) {
        (true, m, Some(procid_off)) if m != 0 => {
            let procid = read_u64(view, m + procid_off)?;
            Ok(Some(ThreadId::new(procid)))
        }
        _ => Ok(None),
    }
}

/// Walk `runtime.allgs` and return every *live* goroutine (dead/free-list
/// slots are omitted). Null slots in the slice are skipped.
///
/// # Errors
/// Returns [`DecoderError::MemoryReadFailed`] if the slice or any `g` struct
/// cannot be read, or [`DecoderError::NotApplicable`] if the slice length is
/// implausibly large (a misresolved layout).
pub fn walk_goroutines(
    view: &dyn ProcessView,
    layout: &GoLayout,
) -> Result<Vec<GoroutineInfo>, DecoderError> {
    let (data, len) = read_allgs_header(view, layout)?;
    let mut out = Vec::new();
    for index in 0..len {
        let slot = data + index * u64::from(layout.ptr_size);
        let gp = read_u64(view, slot)?;
        if gp == 0 {
            continue;
        }
        let info = read_goroutine(view, layout, gp)?;
        if !info.status.is_dead() {
            out.push(info);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::go::offsets::{GStructOffsets, LayoutSource};
    use crate::go::version::GoVersion;
    use crate::model::BlockReason;
    use crate::process_view::{PhysicalFrame, Registers};
    use std::collections::BTreeMap;

    /// A fake process image: a flat address->byte map a decoder reads over.
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
                let b = self.bytes.get(&(addr + i)).copied().ok_or_else(|| {
                    DecoderError::MemoryReadFailed {
                        addr,
                        len,
                        reason: "unmapped".to_string(),
                    }
                })?;
                out.push(b);
            }
            Ok(out)
        }
        fn physical_frames(&self, _t: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError> {
            Ok(vec![])
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

    /// Lay out `count` g pointers at `data_base`, each g struct spaced 0x400
    /// apart starting at `g_base`. Returns the g base addresses.
    fn build_slice(mem: &mut FakeMemory, layout: &GoLayout, g_addrs: &[u64]) {
        mem.put_u64(layout.allgs_addr, 0x2_0000); // data ptr
        mem.put_u64(layout.allgs_addr + 8, g_addrs.len() as u64); // len
        for (i, gp) in g_addrs.iter().enumerate() {
            mem.put_u64(0x2_0000 + i as u64 * 8, *gp);
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
        mem.put_u64(gp + g.gopc, 0xAAAA + goid as u64);
        mem.put_u64(gp + g.startpc, 0xBBBB + goid as u64);
        mem.put_u64(gp + g.sched_pc, 0xCCCC + goid as u64);
        mem.put_u64(gp + g.sched_sp, 0xDDDD + goid as u64);
        mem.put_u64(gp + g.stack_lo, 0x7000);
        mem.put_u64(gp + g.stack_hi, 0x8000);
        mem.put_u64(gp + g.m, 0);
        if let Some(off) = g.parent_goid {
            mem.put_u64(gp + off, parent as u64);
        }
    }

    #[test]
    fn walks_three_goroutines_in_distinct_states() {
        let layout = layout();
        let mut mem = FakeMemory::new();
        let g_addrs = [0x10_0000, 0x10_0400, 0x10_0800];
        build_slice(&mut mem, &layout, &g_addrs);
        // g1: running (main). g2: waiting/chan receive (14). g3: waiting/sleep (19).
        write_g(&mut mem, &layout, g_addrs[0], 1, 2, 0, 0);
        write_g(&mut mem, &layout, g_addrs[1], 2, 4, 14, 1);
        write_g(&mut mem, &layout, g_addrs[2], 3, 4, 19, 1);

        let gs = walk_goroutines(&mem, &layout).expect("walk succeeds");
        assert_eq!(gs.len(), 3);
        assert_eq!(gs[0].goid, 1);
        assert_eq!(gs[0].state, TaskState::Running);
        assert_eq!(
            gs[1].state,
            TaskState::Blocked {
                on: BlockReason::Channel {
                    detail: Some("chan receive".to_string())
                }
            }
        );
        assert_eq!(
            gs[2].state,
            TaskState::Blocked {
                on: BlockReason::Timer
            }
        );
        assert_eq!(gs[1].parent_goid, Some(1));
        assert_eq!(gs[2].wait_reason_str, "sleep");
    }

    #[test]
    fn skips_dead_and_null_slots() {
        let layout = layout();
        let mut mem = FakeMemory::new();
        // slot 0 -> null, slot 1 -> a dead g, slot 2 -> a live g.
        mem.put_u64(layout.allgs_addr, 0x2_0000);
        mem.put_u64(layout.allgs_addr + 8, 3);
        mem.put_u64(0x2_0000, 0);
        mem.put_u64(0x2_0000 + 8, 0x10_0400);
        mem.put_u64(0x2_0000 + 16, 0x10_0800);
        write_g(&mut mem, &layout, 0x10_0400, 5, 6, 0, 0); // _Gdead
        write_g(&mut mem, &layout, 0x10_0800, 7, 1, 0, 0); // _Grunnable

        let gs = walk_goroutines(&mem, &layout).expect("walk succeeds");
        assert_eq!(gs.len(), 1);
        assert_eq!(gs[0].goid, 7);
        assert_eq!(gs[0].state, TaskState::Runnable);
    }

    #[test]
    fn resolves_running_goroutine_thread_via_procid() {
        let layout = layout();
        let mut mem = FakeMemory::new();
        build_slice(&mut mem, &layout, &[0x10_0000]);
        write_g(&mut mem, &layout, 0x10_0000, 1, 2, 0, 0);
        // Point g.m at an M whose procid (offset 72) is tid 4242.
        mem.put_u64(0x10_0000 + layout.g.m, 0x30_0000);
        mem.put_u64(0x30_0000 + 72, 4242);

        let gs = walk_goroutines(&mem, &layout).expect("walk succeeds");
        assert_eq!(gs[0].thread, Some(ThreadId::new(4242)));
    }

    #[test]
    fn rejects_implausible_slice_length() {
        let layout = layout();
        let mut mem = FakeMemory::new();
        mem.put_u64(layout.allgs_addr, 0x2_0000);
        mem.put_u64(layout.allgs_addr + 8, MAX_GOROUTINES + 1);
        let err = walk_goroutines(&mem, &layout).expect_err("implausible length rejected");
        assert!(matches!(err, DecoderError::NotApplicable { .. }));
    }
}
