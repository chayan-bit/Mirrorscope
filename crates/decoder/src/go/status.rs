//! Goroutine status + wait-reason constants, vendored from the Go runtime,
//! and their mapping onto the portable [`TaskState`]/[`BlockReason`]/
//! [`WakeCause`] model.
//!
//! Source of truth: `go1.24.0` `src/runtime/runtime2.go` (status constants)
//! and `src/runtime/runtime2.go` `waitReason`/`waitReasonStrings` (wait
//! reasons). The numeric *status* values (`_Gidle`..`_Gpreempted`, plus the
//! `_Gscan` bit `0x1000`) have been stable since Go 1.5 and are treated as a
//! cross-version constant here. The *wait-reason indices* shift between Go
//! releases (new reasons are appended); [`wait_reason_str`] therefore returns
//! `"?"` for indices outside the vendored table rather than guessing, and the
//! decoder still reports the goroutine as blocked with
//! [`BlockReason::Unknown`].

use crate::model::{BlockReason, IoWakeDetail, TaskState, WakeCause};

/// The `_Gscan` bit ORed into a status while the GC is scanning a goroutine's
/// stack; masked off before interpreting the base status.
pub const G_SCAN: u32 = 0x1000;

/// A decoded goroutine run status (the `_Gxxx` constants, `_Gscan` masked
/// off). `#[non_exhaustive]` because the runtime may add states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GoStatus {
    /// `_Gidle` (0): just allocated, not yet initialized.
    Idle,
    /// `_Grunnable` (1): on a run queue, not currently executing.
    Runnable,
    /// `_Grunning` (2): executing on an M; owns a stack.
    Running,
    /// `_Gsyscall` (3): executing a syscall, not on the user run queue.
    Syscall,
    /// `_Gwaiting` (4): blocked in the runtime (see the wait reason).
    Waiting,
    /// `_Gdead` (6): unused — either just exited or on a free list.
    Dead,
    /// `_Gcopystack` (8): stack is being moved; transiently not runnable.
    Copystack,
    /// `_Gpreempted` (9): stopped by preemption, awaiting re-scheduling.
    Preempted,
    /// A reserved/unused (`_Gmoribund_unused`, `_Genqueue_unused`) or
    /// otherwise unrecognized raw status value.
    Other(u32),
}

impl GoStatus {
    /// Decode a raw `atomicstatus` value, masking off the `_Gscan` bit.
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        match raw & !G_SCAN {
            0 => Self::Idle,
            1 => Self::Runnable,
            2 => Self::Running,
            3 => Self::Syscall,
            4 => Self::Waiting,
            6 => Self::Dead,
            8 => Self::Copystack,
            9 => Self::Preempted,
            other => Self::Other(other),
        }
    }

    /// Whether this status denotes a free-list / never-live slot the decoder
    /// should omit from the task tree (`_Gdead` and the reserved unused
    /// states). Live-but-idle (`_Gidle`) goroutines are kept.
    #[must_use]
    pub fn is_dead(self) -> bool {
        matches!(self, Self::Dead | Self::Other(5) | Self::Other(7))
    }

    /// Map this status (plus the wait reason, when [`Self::Waiting`]) onto the
    /// portable lifecycle state.
    #[must_use]
    pub fn to_task_state(self, wait_reason: u8) -> TaskState {
        match self {
            // A goroutine mid-syscall owns an M and is progressing in the
            // kernel; surface it as running rather than pretending it is
            // parked on a specific resource.
            Self::Running | Self::Syscall => TaskState::Running,
            Self::Runnable | Self::Copystack | Self::Preempted | Self::Idle => TaskState::Runnable,
            Self::Waiting => TaskState::Blocked {
                on: block_reason(wait_reason),
            },
            Self::Dead | Self::Other(_) => TaskState::Completed,
        }
    }
}

/// The vendored `waitReasonStrings` table for `go1.24.0`, indexed by the
/// `waitreason` byte. Kept verbatim so the DAP layer can render the exact
/// runtime phrase; see the module docs for the version caveat.
pub const WAIT_REASON_STRINGS: &[&str] = &[
    "",                        // 0  waitReasonZero
    "GC assist marking",       // 1
    "IO wait",                 // 2
    "chan receive (nil chan)", // 3
    "chan send (nil chan)",    // 4
    "dumping heap",            // 5
    "garbage collection",      // 6
    "garbage collection scan", // 7
    "panicwait",               // 8
    "select",                  // 9
    "select (no cases)",       // 10
    "GC assist wait",          // 11
    "GC sweep wait",           // 12
    "GC scavenge wait",        // 13
    "chan receive",            // 14
    "chan send",               // 15
    "finalizer wait",          // 16
    "force gc (idle)",         // 17
    "semacquire",              // 18
    "sleep",                   // 19
    "sync.Cond.Wait",          // 20
    "sync.Mutex.Lock",         // 21
    "sync.RWMutex.RLock",      // 22
    "sync.RWMutex.Lock",       // 23
    "sync.WaitGroup.Wait",     // 24
    "trace reader (blocked)",  // 25
    "wait for GC cycle",       // 26
    "GC worker (idle)",        // 27
    "GC worker (active)",      // 28
    "preempted",               // 29
    "debug call",              // 30
    "GC mark termination",     // 31
    "stopping the world",      // 32
    "flushing proc caches",    // 33
    "trace goroutine status",  // 34
    "trace proc status",       // 35
    "page trace flush",        // 36
    "coroutine",               // 37
    "GC weak to strong wait",  // 38
    "synctest.Run",            // 39
    "synctest.Wait",           // 40
    "chan receive (synctest)", // 41
    "chan send (synctest)",    // 42
    "select (synctest)",       // 43
];

/// The runtime phrase for a `waitreason` byte, or `"?"` if the index is
/// outside the vendored table (a newer/older Go than the vendored version).
#[must_use]
pub fn wait_reason_str(wait_reason: u8) -> &'static str {
    WAIT_REASON_STRINGS
        .get(wait_reason as usize)
        .copied()
        .unwrap_or("?")
}

/// Classify a `_Gwaiting` goroutine's wait reason into a portable
/// [`BlockReason`], carrying the raw runtime phrase as detail so nothing is
/// lost in translation.
#[must_use]
pub fn block_reason(wait_reason: u8) -> BlockReason {
    let detail = || Some(wait_reason_str(wait_reason).to_string());
    match wait_reason {
        // chan receive/send, nil-chan, synctest variants, and select (which
        // multiplexes channel operations).
        3 | 4 | 9 | 10 | 14 | 15 | 41 | 42 | 43 => BlockReason::Channel { detail: detail() },
        2 => BlockReason::Io { detail: detail() },
        18 | 20 | 21 | 22 | 23 => BlockReason::Lock { detail: detail() },
        24 => BlockReason::Join { on: None }, // sync.WaitGroup.Wait
        19 => BlockReason::Timer,
        _ => BlockReason::Unknown,
    }
}

/// Best-effort wake cause for a *currently blocked* goroutine: what kind of
/// event will unblock it, derived from its wait reason. Honest
/// [`WakeCause::Unknown`] when the reason is not a user-facing wait — true
/// waker *causality* (which specific channel/timer) is #21's job.
#[must_use]
pub fn wake_cause(wait_reason: u8) -> WakeCause {
    match wait_reason {
        3 | 4 | 9 | 10 | 14 | 15 | 41 | 42 | 43 => WakeCause::Channel {
            detail: Some(wait_reason_str(wait_reason).to_string()),
        },
        2 => WakeCause::Io {
            detail: IoWakeDetail {
                fd: None,
                description: Some(wait_reason_str(wait_reason).to_string()),
            },
        },
        19 => WakeCause::Timer,
        18 | 20 | 21 | 22 | 23 | 24 => WakeCause::Manual,
        _ => WakeCause::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base_statuses() {
        assert_eq!(GoStatus::from_raw(2), GoStatus::Running);
        assert_eq!(GoStatus::from_raw(4), GoStatus::Waiting);
        assert_eq!(GoStatus::from_raw(9), GoStatus::Preempted);
    }

    #[test]
    fn masks_scan_bit() {
        // _Gscanrunning (0x1002) decodes to the same base as _Grunning.
        assert_eq!(GoStatus::from_raw(G_SCAN | 2), GoStatus::Running);
        assert_eq!(GoStatus::from_raw(G_SCAN | 4), GoStatus::Waiting);
    }

    #[test]
    fn dead_and_reserved_are_dead() {
        assert!(GoStatus::from_raw(6).is_dead());
        assert!(GoStatus::from_raw(5).is_dead());
        assert!(GoStatus::from_raw(7).is_dead());
        assert!(!GoStatus::from_raw(4).is_dead());
    }

    #[test]
    fn running_and_syscall_map_to_running() {
        assert_eq!(GoStatus::Running.to_task_state(0), TaskState::Running);
        assert_eq!(GoStatus::Syscall.to_task_state(0), TaskState::Running);
    }

    #[test]
    fn waiting_carries_block_reason() {
        // waitReasonChanReceive == 14.
        assert_eq!(
            GoStatus::Waiting.to_task_state(14),
            TaskState::Blocked {
                on: BlockReason::Channel {
                    detail: Some("chan receive".to_string())
                }
            }
        );
    }

    #[test]
    fn sleep_reason_is_timer() {
        assert_eq!(block_reason(19), BlockReason::Timer);
        assert_eq!(wake_cause(19), WakeCause::Timer);
    }

    #[test]
    fn mutex_reason_is_lock() {
        assert_eq!(
            block_reason(21),
            BlockReason::Lock {
                detail: Some("sync.Mutex.Lock".to_string())
            }
        );
    }

    #[test]
    fn out_of_range_wait_reason_is_unknown_not_panic() {
        assert_eq!(wait_reason_str(250), "?");
        assert_eq!(block_reason(250), BlockReason::Unknown);
        assert_eq!(wake_cause(250), WakeCause::Unknown);
    }

    #[test]
    fn wait_reason_strings_cover_known_indices() {
        assert_eq!(wait_reason_str(0), "");
        assert_eq!(wait_reason_str(2), "IO wait");
        assert_eq!(wait_reason_str(19), "sleep");
    }
}
