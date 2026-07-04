//! Layer 4 — the Debug Adapter Protocol server.
//!
//! Implements standard DAP (`initialize`/`launch`/`threads`/`stackTrace`,
//! then `reverseContinue`/`stepBack`) plus Mirrorscope's vendor extensions
//! (`listCheckpoints`, `taskTimeline`, `jumpToEvent`). This is the only
//! contract any client — VS Code, nvim-dap, the Workbench — depends on.
//!
//! The skeleton serves a static [`stub`] target so clients can attach
//! before the replay engine exists; `stepBack`/`reverseContinue` are
//! polite stubs until Phase 1 wires them to `replay` (issue #8).

pub mod protocol;
pub mod server;
pub mod stub;
pub mod transport;
