//! Identifier newtypes shared across the decoder model.

/// Stable identifier for one logical task in a [`super::TaskTree`].
///
/// Deliberately generic: depending on which [`crate::SemanticDecoder`]
/// produced it, a "task" might back an OS thread, a spawned async task, a
/// goroutine, or a C++20/Swift coroutine frame. The model does not encode
/// language identity in the id itself — that lives on [`super::TaskNode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    /// Build a `TaskId` from a raw numeric identifier.
    #[must_use]
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw numeric identifier.
    #[must_use]
    pub fn raw(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::TaskId;

    #[test]
    fn round_trips_raw_value() {
        let id = TaskId::new(42);
        assert_eq!(id.raw(), 42);
        assert_eq!(id, TaskId(42));
    }

    #[test]
    fn orders_by_raw_value() {
        assert!(TaskId::new(1) < TaskId::new(2));
    }
}
