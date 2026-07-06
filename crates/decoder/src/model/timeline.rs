//! The minimal event shape the DAP `taskTimeline` custom request (#27)
//! will consume to render a task's lifecycle across replay history.

use super::ids::TaskId;
use super::task::TaskState;

/// One state transition of one task, anchored to the recorder's global
/// sequence numbers (see `recorder::trace`) so a DAP client can map a
/// timeline event straight onto `jumpToEvent`.
///
/// Deliberately minimal: this is not a general event log, just enough for
/// a scrub-timeline UI to draw "task N was blocked from seq A to seq B."
/// Richer detail (wake cause, suspend point) is looked up separately via
/// [`crate::SemanticDecoder::wake_cause`] and [`crate::SemanticDecoder::logical_stack`]
/// at the seq of interest, rather than duplicated onto every event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTimelineEvent {
    /// The task this transition applies to.
    pub task: TaskId,
    /// Global sequence number the transition started at.
    pub seq_start: u64,
    /// Global sequence number the transition ended at (exclusive), or equal
    /// to `seq_start` if the transition is instantaneous / still ongoing.
    pub seq_end: u64,
    /// State before the transition.
    pub from_state: TaskState,
    /// State after the transition.
    pub to_state: TaskState,
}

impl TaskTimelineEvent {
    /// Whether `seq` falls within `[seq_start, seq_end)`.
    #[must_use]
    pub fn covers(&self, seq: u64) -> bool {
        seq >= self.seq_start && seq < self.seq_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::task::BlockReason;

    fn event(seq_start: u64, seq_end: u64) -> TaskTimelineEvent {
        TaskTimelineEvent {
            task: TaskId::new(1),
            seq_start,
            seq_end,
            from_state: TaskState::Running,
            to_state: TaskState::Blocked {
                on: BlockReason::Timer,
            },
        }
    }

    #[test]
    fn covers_is_inclusive_start_exclusive_end() {
        let event = event(100, 200);
        assert!(event.covers(100));
        assert!(event.covers(150));
        assert!(!event.covers(200));
        assert!(!event.covers(99));
    }
}
