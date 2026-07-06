//! The append-only recording log every capture backend writes into.
//!
//! On-disk layout (all integers little-endian):
//!
//! ```text
//! header: magic "MSCOPETR" (8B) | version u16 | header_len u16 | cmdline… (v2+)
//! record: body_len u32 | body | crc32(body) u32
//! body:   seq u64 | timestamp_ns u64 | kind u16 | payload
//! ```
//!
//! - `seq` is the monotonic **global** sequence number across all captured
//!   event sources (syscalls, scheduling, sync primitives, signals); the
//!   writer assigns it, the reader enforces it.
//! - `header_len` makes the header forward-compatible: newer minor writers
//!   may append fields, older readers skip them.
//! - Every record carries its own CRC32 so corruption and truncation are
//!   surfaced per record instead of poisoning the whole trace.

mod format;
mod reader;
mod writer;

pub use format::{Cmdline, Event, EventKind, Record, TraceError, FORMAT_VERSION, MAGIC};
pub use reader::TraceReader;
pub use writer::TraceWriter;
