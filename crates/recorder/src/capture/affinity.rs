//! Pin tracees to a single CPU so the whole process serializes on one core.
//!
//! Single-core serialization (rr's trick, adapted to ARM without perf
//! counters) is only meaningful if no two threads ever run simultaneously.
//! Pinning every followed thread to the same CPU is the mechanism: the OS then
//! time-slices them on one core, giving shared memory a total order for free.

use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;

use crate::capture::error::CaptureError;

/// The CPU every tracked thread is pinned to. CPU 0 always exists.
pub const SERIALIZATION_CPU: usize = 0;

/// Pin thread `pid` to [`SERIALIZATION_CPU`].
///
/// Affinity is per-thread on Linux and is inherited across `clone`/`fork`, but
/// we pin each newly followed thread explicitly so the guarantee never depends
/// on inheritance quirks.
pub fn pin_to_serialization_cpu(pid: Pid) -> Result<(), CaptureError> {
    let mut set = CpuSet::new();
    set.set(SERIALIZATION_CPU)
        .map_err(|source| CaptureError::Affinity {
            tid: pid.as_raw(),
            cpu: SERIALIZATION_CPU,
            source,
        })?;
    sched_setaffinity(pid, &set).map_err(|source| CaptureError::Affinity {
        tid: pid.as_raw(),
        cpu: SERIALIZATION_CPU,
        source,
    })
}
