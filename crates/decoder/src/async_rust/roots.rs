//! The task-enumeration seam: where the set of top-level task futures a
//! [`super::TokioDecoder`] decodes comes from.
//!
//! ## Why this is a seam, not a walk (honest v1 scope)
//! The truly robust production anchor — reading the `tokio::runtime::context::
//! CONTEXT` thread-local, following it through the runtime `Handle` into the
//! *sharded* `OwnedTasks` intrusive linked list, and mapping each task
//! `Header.vtable` back to its concrete future type — is a large, fragile,
//! tokio-internal-offset-dependent subsystem (a "living compatibility DB" for
//! tokio, distinct from the rustc-layout DB this crate already carries). It is
//! deliberately **not** implemented in v1: per the honesty rule, guessing
//! those offsets is worse than declining.
//!
//! Instead the decoder accepts an explicit set of [`TaskRoot`]s — each the
//! address and DWARF type name of a live task's coroutine, plus (optionally)
//! its Tokio task `Header` for state bits. Production enumeration will produce
//! these; the integration test supplies real addresses read from a running
//! process (mirroring how the Go decoder's test supplies a real fixture). The
//! decoding those roots feed is fully real either way.

/// One top-level task to decode: a coroutine instance in target memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRoot {
    /// Stable task id for the produced [`crate::model::TaskNode`].
    pub id: u64,
    /// Absolute address of the coroutine (`{async_fn_env#N}`) instance.
    pub base: u64,
    /// Fully-qualified DWARF type name of the coroutine at [`Self::base`].
    pub type_name: String,
    /// Absolute address of the Tokio task `Header` (`AtomicUsize` state at
    /// offset 0), when known — enables reading real lifecycle bits. `None`
    /// falls back to deriving the state from the coroutine's own variant.
    pub header_addr: Option<u64>,
}

impl TaskRoot {
    /// A root with no associated Tokio header (state derived from the
    /// coroutine variant).
    #[must_use]
    pub fn new(id: u64, base: u64, type_name: impl Into<String>) -> Self {
        Self {
            id,
            base,
            type_name: type_name.into(),
            header_addr: None,
        }
    }

    /// A root carrying its Tokio task `Header` address for real state bits.
    #[must_use]
    pub fn with_header(mut self, header_addr: u64) -> Self {
        self.header_addr = Some(header_addr);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_fields() {
        let r = TaskRoot::new(7, 0x1000, "probe::sleeper::{async_fn_env#0}").with_header(0x9000);
        assert_eq!(r.id, 7);
        assert_eq!(r.base, 0x1000);
        assert_eq!(r.header_addr, Some(0x9000));
        assert_eq!(r.type_name, "probe::sleeper::{async_fn_env#0}");
    }
}
