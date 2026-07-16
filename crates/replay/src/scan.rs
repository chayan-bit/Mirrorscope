//! The retroactive-watchpoint scan entry point (issue #12).
//!
//! [`WatchpointScan`] is the small, composable front door over the session
//! machinery: it launches a fresh replay, arms a hardware watchpoint over the
//! *entire* recorded history, drives to the end, and returns every hit. This is
//! the killer feature that only replay makes possible — "every write to X, ever"
//! — with no per-write logging at record time.

use std::path::{Path, PathBuf};

use crate::error::ReplayError;
use crate::session::ReplaySession;
use crate::watchpoint::{WatchHit, WatchKind};

/// A configured "find every access to this address across history" query.
///
/// Build it, optionally widen it to reads with [`watch_reads`](Self::watch_reads),
/// then [`run`](Self::run) it. Each run is independent — it spawns its own
/// replay tracee from process entry — so a `WatchpointScan` can be reused.
pub struct WatchpointScan {
    trace_path: PathBuf,
    addr: u64,
    len: u8,
    kind: WatchKind,
}

impl WatchpointScan {
    /// Watch `len` bytes (1, 2, 4, or 8) at `addr` for **writes** across the
    /// whole history recorded in `trace_path`.
    pub fn new(trace_path: &Path, addr: u64, len: u8) -> Self {
        Self {
            trace_path: trace_path.to_path_buf(),
            addr,
            len,
            kind: WatchKind::Write,
        }
    }

    /// Widen the scan to trap on reads as well as writes.
    pub fn watch_reads(mut self) -> Self {
        self.kind = WatchKind::ReadWrite;
        self
    }

    /// Run the scan: launch a fresh replay, arm the watchpoint, replay to the
    /// end, and return every hit in execution order.
    pub fn run(&self) -> Result<Vec<WatchHit>, ReplayError> {
        let mut session = ReplaySession::launch(&self.trace_path)?;
        session.watch(self.addr, self.len, self.kind)?;
        session.run_to_end()?;
        Ok(session.take_watch_hits())
    }
}
