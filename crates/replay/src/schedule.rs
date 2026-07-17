//! Portable schedule-enforcement state for multi-threaded replay (issue #10).
//!
//! Two ptrace-free pieces the rest of the engine builds on, kept here so their
//! correctness is unit-tested on the macOS dev host (there is no tracee here):
//!
//! - [`TidMap`] — the recorded-tid ↔ live-pid remapping table. Replay tids
//!   *always* differ from the recording (a fresh process, freshly cloned
//!   threads), so every thread-attributed trace record must be routed through
//!   this table to reach the right live thread.
//! - [`trace_is_multithreaded`] — the single scan that decides whether a trace
//!   needs schedule enforcement at all. A purely single-threaded recording (v1,
//!   v2, or single-threaded v3) emits none of the v3-only lifecycle kinds, so it
//!   keeps flowing through the original single-tracee driver untouched.

use recorder::trace::{EventKind, Record};

/// Whether a trace carries the single-core thread schedule that replay must
/// enforce. True iff any record is a v3-only thread-lifecycle kind
/// ([`EventKind::SchedSwitch`] / [`EventKind::ThreadSpawn`] /
/// [`EventKind::ThreadExit`]); the recorder emits these only once a second
/// thread is followed, so a single-threaded trace scans to `false` and replays
/// exactly as it did before this feature.
///
/// `pub` (re-exported at the crate root) so callers outside this crate — e.g.
/// a DAP frontend deciding up front whether a trace needs schedule-aware
/// handling — can reuse this exact predicate instead of duplicating the scan.
pub fn trace_is_multithreaded(records: &[Record]) -> bool {
    records.iter().any(|r| {
        matches!(
            r.event.kind,
            EventKind::SchedSwitch | EventKind::ThreadSpawn | EventKind::ThreadExit
        )
    })
}

/// A recorded/live thread-id mapping mismatch — always surfaced as divergence,
/// never silently reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TidMapError {
    /// A recorded tid already bound to a different live pid was re-bound.
    RecordedRebound {
        /// The recorded tid whose binding was contested.
        recorded: u32,
        /// The live pid it is already bound to.
        existing: i32,
        /// The live pid the caller tried to bind it to.
        attempted: i32,
    },
    /// A live pid already bound to a different recorded tid was re-bound.
    LiveRebound {
        /// The live pid whose binding was contested.
        live: i32,
        /// The recorded tid it is already bound to.
        existing: u32,
        /// The recorded tid the caller tried to bind it to.
        attempted: u32,
    },
}

/// Bidirectional map between a recorded thread id and the live tracee pid replay
/// spawned/cloned for it.
#[derive(Debug, Default)]
pub(crate) struct TidMap {
    to_live: std::collections::HashMap<u32, i32>,
    to_recorded: std::collections::HashMap<i32, u32>,
}

impl TidMap {
    /// An empty map, before any thread is bound.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Bind recorded tid `recorded` to live pid `live`. Idempotent for an
    /// identical existing binding; a conflicting binding on either side is a
    /// [`TidMapError`] the caller turns into divergence.
    pub(crate) fn bind(&mut self, recorded: u32, live: i32) -> Result<(), TidMapError> {
        if let Some(&existing) = self.to_live.get(&recorded) {
            if existing != live {
                return Err(TidMapError::RecordedRebound {
                    recorded,
                    existing,
                    attempted: live,
                });
            }
        }
        if let Some(&existing) = self.to_recorded.get(&live) {
            if existing != recorded {
                return Err(TidMapError::LiveRebound {
                    live,
                    existing,
                    attempted: recorded,
                });
            }
        }
        self.to_live.insert(recorded, live);
        self.to_recorded.insert(live, recorded);
        Ok(())
    }

    /// The live pid a recorded tid maps to, if bound.
    pub(crate) fn live_of(&self, recorded: u32) -> Option<i32> {
        self.to_live.get(&recorded).copied()
    }

    /// Drop the binding for a recorded tid (an exited thread), returning the
    /// live pid it had been bound to.
    pub(crate) fn unbind_recorded(&mut self, recorded: u32) -> Option<i32> {
        let live = self.to_live.remove(&recorded)?;
        self.to_recorded.remove(&live);
        Some(live)
    }

    /// Whether nothing is bound yet — the signal that the next thread-attributed
    /// record names the recorded main thread, to be bound to the live leader.
    pub(crate) fn is_empty(&self) -> bool {
        self.to_live.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recorder::capture::payload::{SchedSwitch, SyscallEnter, ThreadSpawn};
    use recorder::trace::{Event, EventKind};

    fn record(seq: u64, kind: EventKind, tid: u32, payload: Vec<u8>) -> Record {
        Record {
            seq,
            event: Event::new_with_tid(kind, seq, tid, payload),
        }
    }

    #[test]
    fn binds_and_resolves_a_recorded_tid() {
        let mut map = TidMap::new();
        assert!(map.is_empty());
        map.bind(1000, 4242).expect("first bind");
        assert_eq!(map.live_of(1000), Some(4242));
        assert!(!map.is_empty());
    }

    #[test]
    fn rebinding_the_same_pair_is_idempotent() {
        let mut map = TidMap::new();
        map.bind(1, 100).expect("bind");
        map.bind(1, 100).expect("idempotent rebind");
        assert_eq!(map.live_of(1), Some(100));
    }

    #[test]
    fn conflicting_recorded_binding_is_rejected() {
        let mut map = TidMap::new();
        map.bind(1, 100).expect("bind");
        assert_eq!(
            map.bind(1, 200),
            Err(TidMapError::RecordedRebound {
                recorded: 1,
                existing: 100,
                attempted: 200,
            })
        );
    }

    #[test]
    fn conflicting_live_binding_is_rejected() {
        let mut map = TidMap::new();
        map.bind(1, 100).expect("bind");
        assert_eq!(
            map.bind(2, 100),
            Err(TidMapError::LiveRebound {
                live: 100,
                existing: 1,
                attempted: 2,
            })
        );
    }

    #[test]
    fn unbind_forgets_both_directions() {
        let mut map = TidMap::new();
        map.bind(7, 700).expect("bind");
        assert_eq!(map.unbind_recorded(7), Some(700));
        assert_eq!(map.live_of(7), None);
        // The live side is freed too: 700 can be re-bound to a different tid.
        map.bind(8, 700).expect("live pid reusable after unbind");
        assert_eq!(map.unbind_recorded(7), None);
    }

    #[test]
    fn single_threaded_trace_scans_as_single_threaded() {
        let recs = vec![
            record(
                1,
                EventKind::SyscallEnter,
                5,
                SyscallEnter {
                    nr: 0,
                    args: [0; 6],
                }
                .encode(),
            ),
            record(2, EventKind::SyscallExit, 5, vec![0; 20]),
        ];
        assert!(!trace_is_multithreaded(&recs));
    }

    #[test]
    fn any_lifecycle_kind_marks_a_trace_multithreaded() {
        let sched = record(
            1,
            EventKind::SchedSwitch,
            9,
            SchedSwitch { tid: 9 }.encode(),
        );
        assert!(trace_is_multithreaded(&[sched]));

        let spawn = record(
            1,
            EventKind::ThreadSpawn,
            5,
            ThreadSpawn {
                parent_tid: 5,
                child_tid: 6,
            }
            .encode(),
        );
        assert!(trace_is_multithreaded(&[spawn]));

        let exit = record(1, EventKind::ThreadExit, 6, 6u32.to_le_bytes().to_vec());
        assert!(trace_is_multithreaded(&[exit]));
    }
}
