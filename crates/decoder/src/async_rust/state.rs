//! Task lifecycle + suspend-point classification for async Rust.
//!
//! Three independent mappings live here, all pure and vendored with version
//! notes (the "layout DB" ethos applied to constants rather than offsets):
//!
//! 1. [`classify_header_state`] — Tokio's task `Header.state` atomic bits →
//!    portable [`TaskState`]. Bit constants vendored from tokio.
//! 2. [`state_from_variant`] — the coroutine's own suspend discriminant →
//!    [`TaskState`], executor-independent (works for any rustc coroutine).
//! 3. [`classify_leaf`] — a parked task's leaf future *type name* →
//!    [`SuspendKind`] / [`WakeCause`] / [`BlockReason`], the cheap
//!    waker-cause heuristic v1 commits to (deeper causality is #21).

use crate::model::{BlockReason, IoWakeDetail, SuspendKind, TaskState, WakeCause};

use super::layout::VariantKind;

/// Tokio `runtime::task::state::State` bit constants (an `AtomicUsize`).
///
/// Source of truth: tokio `src/runtime/task/state.rs`. These have been stable
/// across the tokio 1.x line (verified against 1.44 and 1.52); the lifecycle
/// bits (0..=5) in particular have not changed since the sharded-task rework.
pub mod bits {
    /// The task is currently being polled by a worker.
    pub const RUNNING: usize = 0b0001;
    /// The task has finished (its future returned `Ready`).
    pub const COMPLETE: usize = 0b0010;
    /// A wake was requested; the task is scheduled to be polled.
    pub const NOTIFIED: usize = 0b0100;
    /// A `JoinHandle` still exists and wants the output.
    pub const JOIN_INTEREST: usize = 0b1000;
    /// A waker has been stored for the `JoinHandle`.
    pub const JOIN_WAKER: usize = 0b1_0000;
    /// The task has been cancelled.
    pub const CANCELLED: usize = 0b10_0000;
    /// Bits 0..=5 are lifecycle/flags; bits 6+ are the reference count.
    pub const REF_COUNT_SHIFT: u32 = 6;
}

/// Portable interpretation of a Tokio task `Header.state` atomic word.
///
/// Precedence mirrors how tokio itself transitions a task: a completed or
/// cancelled task is terminal; an actively-polled task is running; a task
/// with a pending notification is runnable (scheduled); otherwise it is idle
/// (parked, waiting for a waker) which the portable model expresses as
/// [`TaskState::Blocked`] with an as-yet-unclassified reason (the caller
/// refines it from the leaf future via [`classify_leaf`]).
#[must_use]
pub fn classify_header_state(state: usize) -> TaskState {
    if state & bits::COMPLETE != 0 || state & bits::CANCELLED != 0 {
        TaskState::Completed
    } else if state & bits::RUNNING != 0 {
        TaskState::Running
    } else if state & bits::NOTIFIED != 0 {
        TaskState::Runnable
    } else {
        TaskState::Blocked {
            on: BlockReason::Unknown,
        }
    }
}

/// The task reference count encoded in the high bits of the state word.
#[must_use]
pub fn ref_count(state: usize) -> usize {
    state >> bits::REF_COUNT_SHIFT
}

/// Derive a portable [`TaskState`] from the coroutine's own active variant,
/// independent of any executor's task header — the honest fallback when no
/// Tokio `Header` is available (e.g. a bare polled future, or a custom
/// executor). A suspended coroutine is blocked; the reason is refined by the
/// caller from the leaf future.
#[must_use]
pub fn state_from_variant(kind: VariantKind) -> TaskState {
    match kind {
        VariantKind::Unresumed => TaskState::Runnable,
        VariantKind::Returned | VariantKind::Panicked => TaskState::Completed,
        VariantKind::Suspend(_) => TaskState::Blocked {
            on: BlockReason::Unknown,
        },
    }
}

/// Classify a parked task's *leaf* future by its DWARF type name into the
/// display-oriented triple the model exposes. This is the cheap, honest v1
/// waker heuristic: it reads what the task is parked on straight off the
/// innermost awaited future's type, and reports [`WakeCause::Unknown`] /
/// [`SuspendKind::Other`] when the type is not one it recognizes rather than
/// inventing causality (that is #21's job).
#[must_use]
pub fn classify_leaf(type_name: &str) -> LeafClass {
    // Match on distinctive substrings of the fully-qualified type name; order
    // matters (channel receivers mention "Recv", timers mention "Sleep").
    if contains_any(type_name, &["time::sleep::Sleep", "time::Sleep", "Timeout"]) {
        LeafClass::new(SuspendKind::Timer, WakeCause::Timer, BlockReason::Timer)
    } else if contains_any(
        type_name,
        &["Recv", "channel", "mpsc", "oneshot", "broadcast", "watch"],
    ) {
        let detail = Some(short_name(type_name));
        LeafClass::new(
            SuspendKind::ChannelRecv,
            WakeCause::Channel {
                detail: detail.clone(),
            },
            BlockReason::Channel { detail },
        )
    } else if contains_any(type_name, &["Mutex", "RwLock", "Semaphore", "Barrier"]) {
        let detail = Some(short_name(type_name));
        LeafClass::new(
            SuspendKind::Lock,
            WakeCause::Manual,
            BlockReason::Lock { detail },
        )
    } else if contains_any(
        type_name,
        &["TcpStream", "net::", "io::", "AsyncFd", "poll_read"],
    ) {
        LeafClass::new(
            SuspendKind::Io,
            WakeCause::Io {
                detail: IoWakeDetail {
                    fd: None,
                    description: Some(short_name(type_name)),
                },
            },
            BlockReason::Io {
                detail: Some(short_name(type_name)),
            },
        )
    } else {
        LeafClass::new(SuspendKind::Other, WakeCause::Unknown, BlockReason::Unknown)
    }
}

/// The classification of one leaf (innermost) awaited future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafClass {
    /// How to render the suspend point on the logical frame.
    pub suspend: SuspendKind,
    /// The best-effort wake cause for the parked task.
    pub wake: WakeCause,
    /// The portable block reason for the task's state.
    pub block: BlockReason,
}

impl LeafClass {
    fn new(suspend: SuspendKind, wake: WakeCause, block: BlockReason) -> Self {
        Self {
            suspend,
            wake,
            block,
        }
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// The last `::`-separated component of a type path, stripping generic args,
/// for a compact human-facing detail string.
fn short_name(type_name: &str) -> String {
    let head = type_name.split('<').next().unwrap_or(type_name);
    head.rsplit("::").next().unwrap_or(head).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_bit_is_running() {
        assert_eq!(
            classify_header_state(bits::RUNNING | (3 << 6)),
            TaskState::Running
        );
    }

    #[test]
    fn complete_and_cancelled_are_completed() {
        assert_eq!(classify_header_state(bits::COMPLETE), TaskState::Completed);
        assert_eq!(classify_header_state(bits::CANCELLED), TaskState::Completed);
    }

    #[test]
    fn notified_only_is_runnable() {
        assert_eq!(
            classify_header_state(bits::NOTIFIED | bits::JOIN_INTEREST | (3 << 6)),
            TaskState::Runnable
        );
    }

    #[test]
    fn idle_is_blocked_unknown() {
        // JOIN_INTEREST set but no lifecycle bit: a parked, idle task.
        assert_eq!(
            classify_header_state(bits::JOIN_INTEREST | (2 << 6)),
            TaskState::Blocked {
                on: BlockReason::Unknown
            }
        );
    }

    #[test]
    fn ref_count_reads_high_bits() {
        assert_eq!(ref_count((3 << 6) | bits::NOTIFIED), 3);
    }

    #[test]
    fn variant_maps_to_state() {
        assert_eq!(
            state_from_variant(VariantKind::Unresumed),
            TaskState::Runnable
        );
        assert_eq!(
            state_from_variant(VariantKind::Returned),
            TaskState::Completed
        );
        assert_eq!(
            state_from_variant(VariantKind::Suspend(0)),
            TaskState::Blocked {
                on: BlockReason::Unknown
            }
        );
    }

    #[test]
    fn classifies_sleep_as_timer() {
        let c = classify_leaf("tokio::time::sleep::Sleep");
        assert_eq!(c.suspend, SuspendKind::Timer);
        assert_eq!(c.wake, WakeCause::Timer);
        assert_eq!(c.block, BlockReason::Timer);
    }

    #[test]
    fn classifies_channel_recv() {
        let c = classify_leaf("tokio::sync::mpsc::bounded::Recv<u32>");
        assert_eq!(c.suspend, SuspendKind::ChannelRecv);
        assert!(matches!(c.block, BlockReason::Channel { .. }));
        assert!(matches!(c.wake, WakeCause::Channel { .. }));
    }

    #[test]
    fn unrecognized_leaf_is_honestly_unknown() {
        let c = classify_leaf("my_crate::CustomFuture");
        assert_eq!(c.suspend, SuspendKind::Other);
        assert_eq!(c.wake, WakeCause::Unknown);
        assert_eq!(c.block, BlockReason::Unknown);
    }

    #[test]
    fn short_name_strips_path_and_generics() {
        assert_eq!(super::short_name("tokio::sync::mpsc::Recv<u32>"), "Recv");
    }
}
