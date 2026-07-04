//! Layer 2 — replay execution engine.
//!
//! Restores the nearest preceding checkpoint and re-runs the target forward,
//! feeding it recorded syscall results and scheduling decisions from the
//! [`recorder::trace`] log until the requested global sequence number.
//!
//! Implementation lands with the fork-checkpoint backend (issue #5) and the
//! replay engine (issue #6).
