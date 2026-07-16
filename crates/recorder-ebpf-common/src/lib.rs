//! Wire format for the raw syscall events the eBPF kernel-side program
//! (`recorder-ebpf-programs`) writes into a `BPF_MAP_TYPE_RINGBUF`, and the
//! userspace loader (`recorder-ebpf`) drains and decodes.
//!
//! `#![no_std]` (except under `cfg(test)`, where the standard test harness
//! needs `std`) so the identical struct compiles both for the BPF target
//! (no allocator, no std) and for the ordinary host build — one wire format,
//! no drift between kernel and userspace encodings. See issue #14.

#![cfg_attr(not(test), no_std)]

/// [`RawSyscallEvent::kind`] value for a syscall-entry record.
pub const KIND_ENTER: u8 = 0;
/// [`RawSyscallEvent::kind`] value for a syscall-exit record.
pub const KIND_EXIT: u8 = 1;

/// Encoded size in bytes of [`RawSyscallEvent::encode`]'s output.
pub const RAW_EVENT_LEN: usize = 1 + 3 + 4 + 4 + 8 + 8 + 6 * 8 + 8;

/// A single syscall-enter or syscall-exit observation, as captured in-kernel
/// and handed to userspace over the ring buffer.
///
/// Mirrors the fields `recorder::capture::syscall` reads via ptrace
/// (`SyscallRegs` / [`SyscallEnter`](../../recorder/capture/payload/struct.SyscallEnter.html)),
/// so `recorder-ebpf`'s userspace collector can re-encode these into the
/// existing trace format's `EventKind::SyscallEnter`/`SyscallExit` records
/// without recorder needing to know eBPF exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSyscallEvent {
    /// [`KIND_ENTER`] or [`KIND_EXIT`].
    pub kind: u8,
    /// Thread-group id (process id) the event was captured from — the
    /// tracepoint filter key.
    pub tgid: u32,
    /// Thread id the event was captured from.
    pub tid: u32,
    /// Kernel monotonic timestamp in nanoseconds (`bpf_ktime_get_ns`).
    pub timestamp_ns: u64,
    /// Architecture-specific syscall number.
    pub nr: u64,
    /// The six raw syscall arguments (enter) or all-zero (exit).
    pub args: [u64; 6],
    /// Return value (exit only; `0` for enter records).
    pub ret: i64,
}

impl RawSyscallEvent {
    /// Encode to the fixed-size wire layout: `kind | pad[3] | tgid | tid |
    /// timestamp_ns | nr | args[6] | ret`, all integers little-endian.
    pub fn encode(&self) -> [u8; RAW_EVENT_LEN] {
        let mut out = [0u8; RAW_EVENT_LEN];
        let mut pos = 0usize;
        out[pos] = self.kind;
        pos += 1 + 3; // 3 reserved padding bytes, keeps u32 fields aligned.
        write_u32(&mut out, &mut pos, self.tgid);
        write_u32(&mut out, &mut pos, self.tid);
        write_u64(&mut out, &mut pos, self.timestamp_ns);
        write_u64(&mut out, &mut pos, self.nr);
        for arg in self.args {
            write_u64(&mut out, &mut pos, arg);
        }
        write_i64(&mut out, &mut pos, self.ret);
        debug_assert_eq!(pos, RAW_EVENT_LEN);
        out
    }

    /// Decode from a byte slice of at least [`RAW_EVENT_LEN`] bytes (the ring
    /// buffer may hand back a slightly larger slice depending on kernel
    /// padding; only the leading `RAW_EVENT_LEN` bytes are read).
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < RAW_EVENT_LEN {
            return None;
        }
        let mut pos = 0usize;
        let kind = buf[pos];
        pos += 1 + 3;
        let tgid = read_u32(buf, &mut pos);
        let tid = read_u32(buf, &mut pos);
        let timestamp_ns = read_u64(buf, &mut pos);
        let nr = read_u64(buf, &mut pos);
        let mut args = [0u64; 6];
        for arg in &mut args {
            *arg = read_u64(buf, &mut pos);
        }
        let ret = read_u64(buf, &mut pos) as i64;
        Some(Self {
            kind,
            tgid,
            tid,
            timestamp_ns,
            nr,
            args,
            ret,
        })
    }
}

fn write_u32(out: &mut [u8], pos: &mut usize, v: u32) {
    out[*pos..*pos + 4].copy_from_slice(&v.to_le_bytes());
    *pos += 4;
}

fn write_u64(out: &mut [u8], pos: &mut usize, v: u64) {
    out[*pos..*pos + 8].copy_from_slice(&v.to_le_bytes());
    *pos += 8;
}

fn write_i64(out: &mut [u8], pos: &mut usize, v: i64) {
    out[*pos..*pos + 8].copy_from_slice(&v.to_le_bytes());
    *pos += 8;
}

fn read_u32(buf: &[u8], pos: &mut usize) -> u32 {
    let v = u32::from_le_bytes(buf[*pos..*pos + 4].try_into().expect("length checked"));
    *pos += 4;
    v
}

fn read_u64(buf: &[u8], pos: &mut usize) -> u64 {
    let v = u64::from_le_bytes(buf[*pos..*pos + 8].try_into().expect("length checked"));
    *pos += 8;
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_event_round_trips() {
        let ev = RawSyscallEvent {
            kind: KIND_ENTER,
            tgid: 4242,
            tid: 4243,
            timestamp_ns: 123_456_789,
            nr: 63,
            args: [3, 0x7fff_0000, 4096, 0, u64::MAX, 7],
            ret: 0,
        };
        assert_eq!(RawSyscallEvent::decode(&ev.encode()).expect("decode"), ev);
    }

    #[test]
    fn exit_event_round_trips_negative_ret() {
        let ev = RawSyscallEvent {
            kind: KIND_EXIT,
            tgid: 1,
            tid: 1,
            timestamp_ns: 42,
            nr: 63,
            args: [0; 6],
            ret: -11, // -EAGAIN
        };
        assert_eq!(RawSyscallEvent::decode(&ev.encode()).expect("decode"), ev);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(RawSyscallEvent::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn encoded_len_matches_constant() {
        let ev = RawSyscallEvent {
            kind: KIND_ENTER,
            tgid: 0,
            tid: 0,
            timestamp_ns: 0,
            nr: 0,
            args: [0; 6],
            ret: 0,
        };
        assert_eq!(ev.encode().len(), RAW_EVENT_LEN);
    }
}
