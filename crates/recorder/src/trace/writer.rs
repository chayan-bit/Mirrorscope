//! Append-only trace writer: assigns global sequence numbers and frames
//! records with per-record CRC32 checksums.

use std::io::Write;

use super::format::{Event, TraceError, BASE_HEADER_LEN, FORMAT_VERSION, MAGIC};

/// Writes the versioned header, then appends checksummed records.
///
/// The writer owns the monotonic global sequence counter: every capture
/// backend funnels through one `TraceWriter`, which is what makes the
/// sequence number *global* across syscall/sched/sync/signal sources.
#[derive(Debug)]
pub struct TraceWriter<W: Write> {
    inner: W,
    next_seq: u64,
}

impl<W: Write> TraceWriter<W> {
    /// Wrap `inner` and write the file header.
    pub fn create(mut inner: W) -> Result<Self, TraceError> {
        inner.write_all(&MAGIC)?;
        inner.write_all(&FORMAT_VERSION.to_le_bytes())?;
        inner.write_all(&(BASE_HEADER_LEN as u16).to_le_bytes())?;
        Ok(Self { inner, next_seq: 0 })
    }

    /// Append one event; returns the global sequence number it was assigned.
    pub fn append(&mut self, event: &Event) -> Result<u64, TraceError> {
        let seq = self.next_seq;
        let body = encode_body(seq, event);
        let crc = crc32fast::hash(&body);

        self.inner.write_all(&(body.len() as u32).to_le_bytes())?;
        self.inner.write_all(&body)?;
        self.inner.write_all(&crc.to_le_bytes())?;

        self.next_seq = seq + 1;
        Ok(seq)
    }

    /// Flush and return the underlying sink.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

fn encode_body(seq: u64, event: &Event) -> Vec<u8> {
    let mut body = Vec::with_capacity(18 + event.payload.len());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&event.timestamp_ns.to_le_bytes());
    body.extend_from_slice(&event.kind.to_u16().to_le_bytes());
    body.extend_from_slice(&event.payload);
    body
}
