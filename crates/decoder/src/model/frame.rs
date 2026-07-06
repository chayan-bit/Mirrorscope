//! One frame of a task's *logical* stack — as opposed to the physical call
//! stack a native unwinder produces. An `async fn`'s await points, or a
//! goroutine's runtime-hidden state, show up here as synthesized frames
//! layered over (or replacing) the physical ones.

use crate::process_view::PhysicalFrame;

/// A source location, shared by [`LogicalFrame`] and anything else that
/// needs to point at a line of source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    /// Path to the source file, as recorded in debug info.
    pub path: String,
    /// One-based line number.
    pub line: u32,
    /// One-based column number.
    pub column: u32,
}

/// What kind of thing a task is suspended waiting for, at a
/// [`LogicalFrame`]'s await/suspend point.
///
/// Structured so the DAP layer composes a display string (e.g. "awaiting:
/// recv on channel #4") instead of the decoder pre-rendering prose that
/// then has to be re-parsed. `#[non_exhaustive]` for the same forward
/// compatibility reason as [`super::TaskKind`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuspendKind {
    /// Awaiting a channel receive.
    ChannelRecv,
    /// Awaiting a channel send.
    ChannelSend,
    /// Awaiting a timer or sleep.
    Timer,
    /// Awaiting I/O readiness.
    Io,
    /// Awaiting another task via `join!`/`.await` on a spawned handle.
    Join,
    /// Parked inside a `select!` awaiting the first ready branch.
    Select,
    /// Awaiting a lock.
    Lock,
    /// A suspend point the decoder cannot further classify.
    Other,
}

/// Structured detail for one suspend point, rendered into prose by
/// [`LogicalFrame::describe_suspend`] rather than stored pre-formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspendPoint {
    /// The category of thing being awaited.
    pub kind: SuspendKind,
    /// Decoder-supplied specifics (a channel name, a fd number, …).
    pub detail: Option<String>,
}

/// Whether a [`LogicalFrame`] came directly off the physical call stack, or
/// was synthesized by a decoder (e.g. one state-machine `.await` point
/// materialized as its own frame with no matching physical frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOrigin {
    /// Copied 1:1 from an unwound physical frame.
    Physical,
    /// Synthesized by the decoder from runtime/compiler metadata.
    Synthesized,
}

/// One frame of a task's logical stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalFrame {
    /// Human-readable frame label (function name, task label, …).
    pub display_name: String,
    /// Source location, when known.
    pub location: Option<SourceLocation>,
    /// The await/suspend point this frame represents, if any.
    pub suspend: Option<SuspendPoint>,
    /// Whether this frame is a direct physical-stack copy or synthesized.
    pub origin: FrameOrigin,
}

impl LogicalFrame {
    /// Build a logical frame that is a 1:1, unannotated copy of a physical
    /// frame — the shape [`crate::native::NativeThreadsDecoder`] produces,
    /// and the fallback tail every richer decoder can reuse below its
    /// synthesized frames (e.g. the executor's own poll-loop frames below
    /// an async task's synthesized await points).
    #[must_use]
    pub fn from_physical(frame: &PhysicalFrame) -> Self {
        Self {
            display_name: frame
                .function_name
                .clone()
                .unwrap_or_else(|| format!("0x{:x}", frame.pc)),
            location: frame.location.clone(),
            suspend: None,
            origin: FrameOrigin::Physical,
        }
    }

    /// Render this frame's suspend point as prose, e.g. `"awaiting: recv on
    /// channel #4"`. Returns `None` if the frame has no suspend point.
    #[must_use]
    pub fn describe_suspend(&self) -> Option<String> {
        let suspend = self.suspend.as_ref()?;
        let kind = match suspend.kind {
            SuspendKind::ChannelRecv => "recv on channel",
            SuspendKind::ChannelSend => "send on channel",
            SuspendKind::Timer => "timer",
            SuspendKind::Io => "I/O",
            SuspendKind::Join => "join",
            SuspendKind::Select => "select",
            SuspendKind::Lock => "lock",
            SuspendKind::Other => "unknown suspend point",
        };
        Some(match &suspend.detail {
            Some(detail) => format!("awaiting: {kind} {detail}"),
            None => format!("awaiting: {kind}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_physical_uses_pc_when_name_missing() {
        let physical = PhysicalFrame {
            pc: 0xdead_beef,
            sp: 0,
            function_name: None,
            location: None,
        };
        let frame = LogicalFrame::from_physical(&physical);
        assert_eq!(frame.display_name, "0xdeadbeef");
        assert_eq!(frame.origin, FrameOrigin::Physical);
        assert!(frame.suspend.is_none());
    }

    #[test]
    fn from_physical_prefers_function_name() {
        let physical = PhysicalFrame {
            pc: 1,
            sp: 0,
            function_name: Some("main".to_string()),
            location: None,
        };
        assert_eq!(LogicalFrame::from_physical(&physical).display_name, "main");
    }

    #[test]
    fn describe_suspend_composes_kind_and_detail() {
        let frame = LogicalFrame {
            display_name: "poll".to_string(),
            location: None,
            suspend: Some(SuspendPoint {
                kind: SuspendKind::ChannelRecv,
                detail: Some("#4".to_string()),
            }),
            origin: FrameOrigin::Synthesized,
        };
        assert_eq!(
            frame.describe_suspend(),
            Some("awaiting: recv on channel #4".to_string())
        );
    }

    #[test]
    fn describe_suspend_without_detail() {
        let frame = LogicalFrame {
            display_name: "poll".to_string(),
            location: None,
            suspend: Some(SuspendPoint {
                kind: SuspendKind::Timer,
                detail: None,
            }),
            origin: FrameOrigin::Synthesized,
        };
        assert_eq!(
            frame.describe_suspend(),
            Some("awaiting: timer".to_string())
        );
    }

    #[test]
    fn describe_suspend_none_when_not_suspended() {
        let frame = LogicalFrame {
            display_name: "main".to_string(),
            location: None,
            suspend: None,
            origin: FrameOrigin::Physical,
        };
        assert_eq!(frame.describe_suspend(), None);
    }
}
