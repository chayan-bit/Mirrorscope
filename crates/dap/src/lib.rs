//! Layer 4 — the Debug Adapter Protocol server.
//!
//! Implements standard DAP (`initialize`/`launch`/`threads`/`stackTrace`,
//! then `reverseContinue`/`stepBack`) plus Mirrorscope's vendor extensions
//! (`listCheckpoints`, `taskTimeline`, `jumpToEvent`). This is the only
//! contract any client — VS Code, nvim-dap, the Workbench — depends on.
//!
//! The server skeleton lands with issue #3.
