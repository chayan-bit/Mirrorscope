//! Shared types and constants of the trace log format.

/// File magic identifying a Mirrorscope trace.
pub const MAGIC: [u8; 8] = *b"MSCOPETR";

/// Current format version written by [`super::TraceWriter`].
///
/// - v1: bare header, no embedded command line, record body carries no tid.
/// - v2: header embeds the recorded command line (see [`Cmdline`]) so the
///   replay engine knows what to re-execute.
/// - v3: every record body carries the originating thread id (`tid`), and the
///   multi-threaded capture backend emits [`EventKind::SchedSwitch`],
///   [`EventKind::ThreadSpawn`], and [`EventKind::ThreadExit`] so replay can
///   reconstruct the recorded single-core thread interleaving.
///
/// The reader understands every version ≤ this; older traces stay readable.
pub const FORMAT_VERSION: u16 = 3;

/// Fixed portion of the header: magic + version + header_len.
pub(crate) const BASE_HEADER_LEN: usize = 12;

/// First format version whose header can embed a [`Cmdline`].
pub(crate) const CMDLINE_MIN_VERSION: u16 = 2;

/// First format version whose record body carries a per-event thread id.
pub(crate) const TID_MIN_VERSION: u16 = 3;

/// Upper bound on a single record's declared body length, enforced by the
/// reader *before* it allocates a buffer for it.
///
/// `body_len` comes off the wire as an untrusted `u32`; without a cap, a
/// crafted or corrupt trace declaring e.g. `0xFFFF_FFFF` forces a ~4 GiB
/// allocation before `read_exact` has any chance to fail on the short read.
/// 16 MiB comfortably covers every body the recorder can legitimately emit:
/// syscall payloads carry at most a handful of captured buffers (`read`,
/// `pread64`, `recvfrom`, `getrandom`, …) and while the recorder does not
/// itself clamp how much of a large `read`/`recvfrom` it captures, buffers
/// that size in a *single* syscall are not a realistic recording workload —
/// see `capture::syscall::kernel_written_region`. Anything past this bound is
/// almost certainly a malformed or hostile trace, not a legitimate one.
pub(crate) const MAX_BODY_LEN: usize = 16 * 1024 * 1024;

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

/// Body bytes preceding the payload in a pre-v3 (tid-less) trace:
/// seq + timestamp_ns + kind.
pub(crate) const BODY_PREFIX_LEN: usize = 18;

/// Body bytes preceding the payload in a v3+ trace: seq + timestamp_ns +
/// tid + kind.
pub(crate) const BODY_PREFIX_LEN_V3: usize = 22;

/// Smallest legal record body for a trace written at `version`.
pub(crate) fn min_body_len(version: u16) -> usize {
    if version >= TID_MIN_VERSION {
        BODY_PREFIX_LEN_V3
    } else {
        BODY_PREFIX_LEN
    }
}

/// A captured source of non-determinism, before a sequence number is assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// What kind of event this is.
    pub kind: EventKind,
    /// Monotonic capture timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// The thread id this event was captured from. `None` for v1/v2 traces
    /// (which predate per-event tids) and for events not attributed to a
    /// specific thread; `Some` for every record in a v3+ trace.
    pub tid: Option<u32>,
    /// Kind-specific encoded data (registers, syscall results, tids, …).
    pub payload: Vec<u8>,
}

impl Event {
    /// Construct an event with no thread attribution (`tid == None`).
    ///
    /// A v3 [`super::TraceWriter`] still records a tid for it, defaulting to
    /// `0`; use [`Event::new_with_tid`] to attribute it to a real thread.
    pub fn new(kind: EventKind, timestamp_ns: u64, payload: Vec<u8>) -> Self {
        Self {
            kind,
            timestamp_ns,
            tid: None,
            payload,
        }
    }

    /// Construct an event captured from thread `tid`.
    pub fn new_with_tid(kind: EventKind, timestamp_ns: u64, tid: u32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            timestamp_ns,
            tid: Some(tid),
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
    /// A new thread/process was followed under ptrace. Payload is a
    /// [`ThreadSpawn`](crate::capture::payload::ThreadSpawn) (parent + child
    /// tids); the record's own `tid` is the spawning thread. (v3+)
    ThreadSpawn,
    /// A followed thread/process exited. Payload is a
    /// [`ThreadExit`](crate::capture::payload::ThreadExit); the record's own
    /// `tid` is the exiting thread. (v3+)
    ThreadExit,
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
            Self::ThreadSpawn => 9,
            Self::ThreadExit => 10,
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
            9 => Self::ThreadSpawn,
            10 => Self::ThreadExit,
            other => Self::Unknown(other),
        }
    }
}

/// Encode a record body for the current ([`FORMAT_VERSION`]) layout:
/// `seq | timestamp_ns | tid | kind | payload`. An event with no thread
/// attribution records tid `0`.
pub(crate) fn encode_body(seq: u64, event: &Event) -> Vec<u8> {
    let mut body = Vec::with_capacity(BODY_PREFIX_LEN_V3 + event.payload.len());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&event.timestamp_ns.to_le_bytes());
    body.extend_from_slice(&event.tid.unwrap_or(0).to_le_bytes());
    body.extend_from_slice(&event.kind.to_u16().to_le_bytes());
    body.extend_from_slice(&event.payload);
    body
}

/// Decode a record body written at `version`. Pre-v3 bodies carry no tid, so
/// the resulting [`Event::tid`] is `None`; v3+ bodies yield `Some(tid)`.
///
/// The caller has already verified `body.len() >= min_body_len(version)`.
pub(crate) fn decode_body(version: u16, body: &[u8]) -> Result<Record, TraceError> {
    let seq = u64::from_le_bytes(body[0..8].try_into().expect("length checked"));
    let timestamp_ns = u64::from_le_bytes(body[8..16].try_into().expect("length checked"));
    let (tid, kind_at) = if version >= TID_MIN_VERSION {
        let tid = u32::from_le_bytes(body[16..20].try_into().expect("length checked"));
        (Some(tid), 20)
    } else {
        (None, 16)
    };
    let kind = EventKind::from_u16(u16::from_le_bytes([body[kind_at], body[kind_at + 1]]));
    let payload = body[kind_at + 2..].to_vec();
    Ok(Record {
        seq,
        event: Event {
            kind,
            timestamp_ns,
            tid,
            payload,
        },
    })
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
    /// A record declared a body length larger than [`MAX_BODY_LEN`], the
    /// largest body the recorder can legitimately emit. Rejected before
    /// allocating a buffer for it, so a crafted or corrupt length can't be
    /// used to force an oversized allocation.
    #[error("record body length {found} exceeds the maximum of {max} bytes")]
    BodyTooLarge {
        /// The declared body length.
        found: usize,
        /// The maximum permitted body length.
        max: usize,
    },
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
