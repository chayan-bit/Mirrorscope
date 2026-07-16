//! Append-only trace writer: assigns global sequence numbers and frames
//! records with per-record CRC32 checksums.

use std::io::Write;

use super::format::{
    encode_body, encode_cmdline, Event, TraceError, BASE_HEADER_LEN, FORMAT_VERSION, MAGIC,
};

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
    /// Wrap `inner` and write a header with no embedded command line.
    ///
    /// Traces written this way cannot be replayed standalone (replay needs a
    /// command line); use [`TraceWriter::create_with_cmdline`] for that.
    pub fn create(inner: W) -> Result<Self, TraceError> {
        Self::write_header(inner, &[])
    }

    /// Wrap `inner` and write a v2 header embedding `program args…`, so a replay
    /// engine can re-execute the exact recorded target.
    pub fn create_with_cmdline(
        inner: W,
        program: &str,
        args: &[String],
    ) -> Result<Self, TraceError> {
        Self::write_header(inner, &encode_cmdline(program, args))
    }

    fn write_header(mut inner: W, cmdline: &[u8]) -> Result<Self, TraceError> {
        let header_len = BASE_HEADER_LEN + cmdline.len();
        inner.write_all(&MAGIC)?;
        inner.write_all(&FORMAT_VERSION.to_le_bytes())?;
        inner.write_all(&(header_len as u16).to_le_bytes())?;
        inner.write_all(cmdline)?;
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
