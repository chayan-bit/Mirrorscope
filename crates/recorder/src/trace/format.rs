//! Shared types and constants of the trace log format.

/// File magic identifying a Mirrorscope trace.
pub const MAGIC: [u8; 8] = *b"MSCOPETR";

/// Current format version written by [`super::TraceWriter`].
///
/// v2 embeds the recorded command line in the header (see [`Cmdline`]) so the
/// replay engine knows what to re-execute; v1 traces carry none.
pub const FORMAT_VERSION: u16 = 2;

/// Fixed portion of the header: magic + version + header_len.
pub(crate) const BASE_HEADER_LEN: usize = 12;

/// First format version whose header can embed a [`Cmdline`].
pub(crate) const CMDLINE_MIN_VERSION: u16 = 2;

/// The command line a trace was recorded from: the program plus its arguments.
///
/// Stored in the variable-length header region of a v2+ trace as length-prefixed
/// UTF-8, so replay can spawn the exact same target. `None` for v1 traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmdline {
    /// The recorded program (argv[0] as passed to the recorder).
    pub program: String,
    /// The recorded arguments following the program.
    pub args: Vec<String>,
}

/// Encode a command line for the v2+ header: program, then arg count, then each
/// arg, every string a `u32` little-endian length prefix followed by UTF-8 bytes.
pub(crate) fn encode_cmdline(program: &str, args: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    push_str(&mut out, program);
    out.extend_from_slice(&(args.len() as u32).to_le_bytes());
    for arg in args {
        push_str(&mut out, arg);
    }
    out
}

/// Decode a command line from the header region. Trailing bytes (reserved for
/// future header fields) are ignored, keeping the header forward-compatible.
pub(crate) fn decode_cmdline(buf: &[u8]) -> Result<Cmdline, TraceError> {
    let mut pos = 0usize;
    let program = read_str(buf, &mut pos)?;
    let count = read_u32(buf, &mut pos)? as usize;
    let mut args = Vec::new();
    for _ in 0..count {
        args.push(read_str(buf, &mut pos)?);
    }
    Ok(Cmdline { program, args })
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, TraceError> {
    let end = pos.checked_add(4).ok_or(TraceError::MalformedHeader)?;
    let slice = buf.get(*pos..end).ok_or(TraceError::MalformedHeader)?;
    *pos = end;
    Ok(u32::from_le_bytes(
        slice.try_into().expect("length checked"),
    ))
}

fn read_str(buf: &[u8], pos: &mut usize) -> Result<String, TraceError> {
    let len = read_u32(buf, pos)? as usize;
    let end = pos.checked_add(len).ok_or(TraceError::MalformedHeader)?;
    let slice = buf.get(*pos..end).ok_or(TraceError::MalformedHeader)?;
    *pos = end;
    String::from_utf8(slice.to_vec()).map_err(|_| TraceError::MalformedHeader)
}

/// Body bytes preceding the payload: seq + timestamp_ns + kind.
pub(crate) const BODY_PREFIX_LEN: usize = 18;

/// A captured source of non-determinism, before a sequence number is assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// What kind of event this is.
    pub kind: EventKind,
    /// Monotonic capture timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Kind-specific encoded data (registers, syscall results, tids, …).
    pub payload: Vec<u8>,
}

impl Event {
    /// Convenience constructor.
    pub fn new(kind: EventKind, timestamp_ns: u64, payload: Vec<u8>) -> Self {
        Self {
            kind,
            timestamp_ns,
            payload,
        }
    }
}

/// An [`Event`] as stored in the log, with its assigned global sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Monotonic global sequence number across all event sources.
    pub seq: u64,
    /// The captured event.
    pub event: Event,
}

/// Event discriminants. Unknown values round-trip via [`EventKind::Unknown`]
/// so older readers can carry newer traces without loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
    /// Syscall entry (nr + args in payload).
    SyscallEnter,
    /// Syscall exit (return value in payload).
    SyscallExit,
    /// Scheduler switched threads.
    SchedSwitch,
    /// Signal delivered to the tracee.
    Signal,
    /// Sync primitive acquired (mutex/cond/parking_lot ordering).
    SyncAcquire,
    /// Sync primitive released.
    SyncRelease,
    /// Process/thread creation (fork/clone).
    Fork,
    /// A full-process checkpoint was taken at this point.
    Checkpoint,
    /// Kind emitted by a newer writer; preserved verbatim.
    Unknown(u16),
}

impl EventKind {
    /// Wire encoding of this kind.
    pub fn to_u16(self) -> u16 {
        match self {
            Self::SyscallEnter => 1,
            Self::SyscallExit => 2,
            Self::SchedSwitch => 3,
            Self::Signal => 4,
            Self::SyncAcquire => 5,
            Self::SyncRelease => 6,
            Self::Fork => 7,
            Self::Checkpoint => 8,
            Self::Unknown(raw) => raw,
        }
    }

    /// Decode from the wire; unrecognized values become [`Self::Unknown`].
    pub fn from_u16(raw: u16) -> Self {
        match raw {
            1 => Self::SyscallEnter,
            2 => Self::SyscallExit,
            3 => Self::SchedSwitch,
            4 => Self::Signal,
            5 => Self::SyncAcquire,
            6 => Self::SyncRelease,
            7 => Self::Fork,
            8 => Self::Checkpoint,
            other => Self::Unknown(other),
        }
    }
}

/// Errors surfaced by the trace reader/writer.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    /// The file does not start with [`MAGIC`].
    #[error("not a Mirrorscope trace (bad magic)")]
    BadMagic,
    /// The trace was written by a newer, incompatible format version.
    #[error("unsupported trace format version {found} (max supported {supported})")]
    UnsupportedVersion {
        /// Version found in the header.
        found: u16,
        /// Highest version this reader understands.
        supported: u16,
    },
    /// A record's CRC32 did not match its body.
    #[error("checksum mismatch in record at seq {seq}")]
    ChecksumMismatch {
        /// Sequence number claimed by the corrupt record.
        seq: u64,
    },
    /// The stream ended in the middle of a record frame.
    #[error("trace truncated mid-record")]
    Truncated,
    /// The header's embedded command line could not be decoded.
    #[error("malformed trace header (bad embedded command line)")]
    MalformedHeader,
    /// A record's sequence number did not strictly increase.
    #[error("non-monotonic sequence number {found} after {previous}")]
    NonMonotonicSequence {
        /// Sequence number that violated monotonicity.
        found: u64,
        /// Last valid sequence number seen.
        previous: u64,
    },
    /// Underlying I/O failure.
    #[error("trace I/O error: {0}")]
    Io(#[from] std::io::Error),
}
