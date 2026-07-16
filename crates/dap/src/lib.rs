//! Layer 4 — the Debug Adapter Protocol server.
//!
//! Implements standard DAP (`initialize`/`launch`/`threads`/`stackTrace`,
//! then `reverseContinue`/`stepBack`) plus Mirrorscope's vendor extensions
//! (`listCheckpoints`, `taskTimeline`, `jumpToEvent`). This is the only
//! contract any client — VS Code, nvim-dap, the Workbench — depends on.
//!
//! Requests are dispatched through a [`backend::DebugBackend`]: the portable
//! [`backend::StubBackend`] serves a static target on every platform, and the
//! Linux-only [`replay_backend::ReplayBackend`] drives a real recorded trace
//! under the replay engine when `launch` is given a `trace` argument (Phase 1,
//! issue #8).

pub mod backend;
pub mod protocol;
#[cfg(target_os = "linux")]
pub mod replay_backend;
pub mod server;
pub mod stub;
pub mod transport;
