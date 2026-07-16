//! Live Tokio task enumeration — feeding the [`super::roots`] seam without a
//! test-fixture address side channel (completing the async-Rust flagship,
//! `CLAUDE.md` Phase 4).
//!
//! The sanctioned v1 anchor (README §9: "consume/extend tokio-console's
//! instrumentation … uprobes only for uninstrumented executors") is realized
//! here as an *inspection-time* walk that needs no target rebuild flags and no
//! new recording: from each stopped thread's `tokio::runtime::context::CONTEXT`
//! thread-local, follow the scheduler `Handle` into the sharded `OwnedTasks`
//! intrusive list and read each task's `Header`, mapping its vtable's
//! `poll::<T, S>` back to the future type `T` the coroutine decoder already
//! understands.
//!
//! Layering (each piece isolated and portably unit-tested, per `CLAUDE.md`):
//! - [`layout`] — vendored, version-gated Tokio-internal offsets (the tokio
//!   compatibility DB); declines unknown versions honestly.
//! - [`tls`] — architecture TLS math (`tp` + symbol offset → address).
//! - [`walk`] — the pure `OwnedTasks` pointer chase over a [`ProcessView`].
//! - [`dwarf`] — per-binary facts: `CONTEXT` TLS offset, load geometry, and
//!   the `poll<T, S>` → future-type map.
//!
//! Coverage: **tokio 1.44.x, current-thread scheduler, aarch64/x86-64**,
//! verified end-to-end against a live tokio 1.44.2 target on aarch64. Anything
//! else (unverified tokio version, multi-thread scheduler, stripped `CONTEXT`,
//! a backend with no thread pointer) declines, and the decoder falls back.

pub mod dwarf;
pub mod error;
pub mod layout;
pub mod tls;
pub mod walk;

use std::collections::BTreeMap;

use crate::process_view::ProcessView;

use super::layout::AsyncLayouts;
use super::roots::TaskRoot;

pub use dwarf::BinaryFacts;
pub use error::EnumerateError;
pub use layout::{TokioRuntimeLayout, TokioVersion};
pub use walk::RawTask;

/// A resolved, reusable plan for enumerating a specific Tokio binary's tasks:
/// its vendored internal layout plus the per-binary DWARF/ELF facts. Built
/// once from the target image (like the coroutine layouts) and reused on every
/// decode so stepping a replay re-reads fresh task state.
#[derive(Debug, Clone)]
pub struct EnumerationPlan {
    facts: BinaryFacts,
    layout: TokioRuntimeLayout,
}

impl EnumerationPlan {
    /// Resolve the enumeration plan for a Tokio target from its binary image.
    ///
    /// # Errors
    /// Declines with [`EnumerateError`] when the tokio version is unknown or
    /// unverified, the `CONTEXT` symbol or DWARF is missing, or the ELF cannot
    /// be parsed.
    pub fn resolve(image: &[u8]) -> Result<Self, EnumerateError> {
        let facts = dwarf::resolve(image)?;
        let layout = TokioRuntimeLayout::vendored(facts.version)?;
        Ok(Self { facts, layout })
    }

    /// Enumerate the target's live spawned tasks into [`TaskRoot`]s, keeping
    /// only those whose future type is a coroutine the supplied `layouts`
    /// resolved (foreign/boxed futures are skipped honestly).
    ///
    /// # Errors
    /// Declines with [`EnumerateError`] when no thread pointer or load base is
    /// available, no stopped thread holds a runtime handle, or a pointer chase
    /// reads implausible data.
    pub fn enumerate_roots(
        &self,
        view: &dyn ProcessView,
        layouts: &AsyncLayouts,
    ) -> Result<Vec<TaskRoot>, EnumerateError> {
        let load_bias = self.load_bias(view)?;
        let raw = self.collect_raw(view)?;
        Ok(self.roots_from_raw(&raw, load_bias, layouts))
    }

    /// Load bias = runtime executable base − minimum `PT_LOAD` vaddr.
    fn load_bias(&self, view: &dyn ProcessView) -> Result<u64, EnumerateError> {
        let base = view
            .executable_base()
            .ok_or(EnumerateError::LoadBaseUnavailable)?;
        Ok(base.wrapping_sub(self.facts.min_load_vaddr))
    }

    /// Walk every stopped thread's `CONTEXT`, returning the deduplicated set of
    /// raw tasks (keyed by `Header` address) from the first thread(s) holding a
    /// live runtime handle.
    fn collect_raw(&self, view: &dyn ProcessView) -> Result<Vec<RawTask>, EnumerateError> {
        let variant = tls::TlsVariant::host();
        let mut by_header: BTreeMap<u64, RawTask> = BTreeMap::new();
        let mut any_thread_pointer = false;
        let mut any_runtime = false;

        for tid in view.thread_ids() {
            let Some(tp) = view
                .thread_pointer(tid)
                .map_err(|e| EnumerateError::Implausible(e.to_string()))?
            else {
                continue;
            };
            any_thread_pointer = true;
            let context = tls::static_tls_address(
                variant,
                tp,
                self.facts.context_tls_offset,
                self.facts.tls_align,
                self.facts.tls_block_size,
            );
            let mut raw = Vec::new();
            if walk::walk_context(view, context, &self.layout, &mut raw)? {
                any_runtime = true;
                for task in raw {
                    by_header.insert(task.header, task);
                }
            }
        }

        if !any_thread_pointer {
            return Err(EnumerateError::ThreadPointerUnavailable);
        }
        if !any_runtime {
            return Err(EnumerateError::NoRuntimeHandle);
        }
        Ok(by_header.into_values().collect())
    }

    /// Turn raw tasks into decodable [`TaskRoot`]s: de-bias each poll address,
    /// resolve its future type, and keep the coroutines the decoder can read.
    fn roots_from_raw(
        &self,
        raw: &[RawTask],
        load_bias: u64,
        layouts: &AsyncLayouts,
    ) -> Vec<TaskRoot> {
        let mut roots = Vec::new();
        let mut next_id = 1u64;
        for task in raw {
            let static_poll = task.poll_runtime.wrapping_sub(load_bias);
            let Some(type_name) = self.facts.future_type_for(static_poll) else {
                continue;
            };
            if !layouts.is_coroutine(type_name) {
                continue;
            }
            roots.push(TaskRoot::new(next_id, task.future, type_name).with_header(task.header));
            next_id += 1;
        }
        roots
    }
}
