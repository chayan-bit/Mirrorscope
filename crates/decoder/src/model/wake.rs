//! Why a task woke up — the "waker causality" model that #21 will populate
//! from `tracing`/uprobe waker events. Native debuggers cannot answer this
//! at all; it falls out of replay plus the async-Rust semantic layer.

/// Structured detail for an I/O-driven wake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoWakeDetail {
    /// File descriptor that became ready, when known.
    pub fd: Option<i32>,
    /// Decoder-supplied description (e.g. "socket readable").
    pub description: Option<String>,
}

/// Why a task transitioned out of [`super::TaskState::Blocked`].
///
/// `#[non_exhaustive]`: waker causality is deliberately left open for
/// finer-grained reasons once #21 lands (e.g. distinguishing which timer,
/// which channel).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WakeCause {
    /// Woken by a timer firing.
    Timer,
    /// Woken by I/O readiness.
    Io {
        /// Structured detail about the I/O source.
        detail: IoWakeDetail,
    },
    /// Woken by a channel send/receive completing.
    Channel {
        /// Decoder-supplied detail (e.g. a channel identifier).
        detail: Option<String>,
    },
    /// Woken by an explicit `Waker::wake()` call not attributable to one of
    /// the above (a custom executor, a manual notify).
    Manual,
    /// The decoder has no wake-causality information for this task. This is
    /// an honest "don't know", not an error — see [`crate::error::DecoderError`]
    /// for the "cannot decode at all" case.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_wake_cause_carries_fd_and_description() {
        let cause = WakeCause::Io {
            detail: IoWakeDetail {
                fd: Some(4),
                description: Some("socket readable".to_string()),
            },
        };
        match cause {
            WakeCause::Io { detail } => {
                assert_eq!(detail.fd, Some(4));
                assert_eq!(detail.description.as_deref(), Some("socket readable"));
            }
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    #[test]
    fn unknown_is_distinct_from_manual() {
        assert_ne!(WakeCause::Unknown, WakeCause::Manual);
    }
}
