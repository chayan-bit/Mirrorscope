//! The portable, language-agnostic data model every [`crate::SemanticDecoder`]
//! produces and every consumer (replay, DAP, waker causality) reads.
//!
//! Split by concept rather than crammed into one file: identifiers, the
//! task tree itself, logical stack frames, wake causality, the DAP
//! timeline event shape, and variable values.

mod frame;
mod ids;
mod task;
mod timeline;
mod tree;
mod variable;
mod wake;

pub use frame::{FrameOrigin, LogicalFrame, SourceLocation, SuspendKind, SuspendPoint};
pub use ids::TaskId;
pub use task::{BlockReason, TaskKind, TaskNode, TaskState};
pub use timeline::TaskTimelineEvent;
pub use tree::TaskTree;
pub use variable::Variable;
pub use wake::{IoWakeDetail, WakeCause};
