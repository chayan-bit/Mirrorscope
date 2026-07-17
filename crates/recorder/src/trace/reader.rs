//! Trace reader: validates the header, per-record checksums, and global
//! sequence-number monotonicity while iterating records.

use std::io::Read;

use super::format::{
    decode_body, decode_cmdline, min_body_len, Cmdline, Record, TraceError, BASE_HEADER_LEN,
    CMDLINE_MIN_VERSION, FORMAT_VERSION, MAGIC, MAX_BODY_LEN,
};

/// Iterates `Result<Record, TraceError>` over an append-only trace stream.
#[derive(Debug)]
pub struct TraceReader<R: Read> {
    inner: R,
    version: u16,
    cmdline: Option<Cmdline>,
    last_seq: Option<u64>,
    poisoned: bool,
}

impl<R: Read> TraceReader<R> {
    /// Validate the header and position the reader at the first record.
    ///
    /// Honors the header-length field: extra header bytes written by newer
    /// minor versions are skipped, not rejected.
    pub fn open(mut inner: R) -> Result<Self, TraceError> {
        let mut base = [0u8; BASE_HEADER_LEN];
        inner
            .read_exact(&mut base)
            .map_err(|_| TraceError::BadMagic)?;
        if base[..8] != MAGIC {
            return Err(TraceError::BadMagic);
        }

        let version = u16::from_le_bytes([base[8], base[9]]);
        if version > FORMAT_VERSION {
            return Err(TraceError::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }

        let header_len = u16::from_le_bytes([base[10], base[11]]) as usize;
        let extra = header_len.saturating_sub(BASE_HEADER_LEN);
        let mut extra_buf = vec![0u8; extra];
        inner
            .read_exact(&mut extra_buf)
            .map_err(|_| TraceError::Truncated)?;

        let cmdline = if version >= CMDLINE_MIN_VERSION && !extra_buf.is_empty() {
            Some(decode_cmdline(&extra_buf)?)
        } else {
            None
        };

        Ok(Self {
            inner,
            version,
            cmdline,
            last_seq: None,
            poisoned: false,
        })
    }

    /// The format version declared in the trace header.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The command line the trace was recorded from, or `None` for v1 traces
    /// (or v2 traces written without one).
    pub fn cmdline(&self) -> Option<&Cmdline> {
        self.cmdline.as_ref()
    }

    fn read_record(&mut self) -> Result<Option<Record>, TraceError> {
        let mut len_buf = [0u8; 4];
        match read_exact_or_eof(&mut self.inner, &mut len_buf)? {
            ReadOutcome::Eof => return Ok(None),
            ReadOutcome::Partial => return Err(TraceError::Truncated),
            ReadOutcome::Full => {}
        }

        let body_len = u32::from_le_bytes(len_buf) as usize;
        if body_len < min_body_len(self.version) {
            return Err(TraceError::Truncated);
        }
        // Bound-check before allocating: `body_len` is untrusted input, and an
        // unbounded `vec![0u8; body_len]` would let a crafted length (up to
        // ~4 GiB for a u32) force a huge allocation before `read_exact` ever
        // gets a chance to fail on the short read.
        if body_len > MAX_BODY_LEN {
            return Err(TraceError::BodyTooLarge {
                found: body_len,
                max: MAX_BODY_LEN,
            });
        }

        let mut body = vec![0u8; body_len];
        self.inner
            .read_exact(&mut body)
            .map_err(|_| TraceError::Truncated)?;
        let mut crc_buf = [0u8; 4];
        self.inner
            .read_exact(&mut crc_buf)
            .map_err(|_| TraceError::Truncated)?;

        let record = decode_body(self.version, &body)?;
        if crc32fast::hash(&body) != u32::from_le_bytes(crc_buf) {
            return Err(TraceError::ChecksumMismatch { seq: record.seq });
        }
        self.check_monotonic(record.seq)?;
        Ok(Some(record))
    }

    fn check_monotonic(&mut self, seq: u64) -> Result<(), TraceError> {
        if let Some(previous) = self.last_seq {
            if seq <= previous {
                return Err(TraceError::NonMonotonicSequence {
                    found: seq,
                    previous,
                });
            }
        }
        self.last_seq = Some(seq);
        Ok(())
    }
}

impl<R: Read> Iterator for TraceReader<R> {
    type Item = Result<Record, TraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }
        match self.read_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(err) => {
                self.poisoned = true;
                Some(Err(err))
            }
        }
    }
}

enum ReadOutcome {
    Full,
    Partial,
    Eof,
}

/// Distinguish clean EOF (no record follows) from mid-frame truncation.
fn read_exact_or_eof<R: Read>(inner: &mut R, buf: &mut [u8]) -> Result<ReadOutcome, TraceError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = inner.read(&mut buf[filled..])?;
        if n == 0 {
            return Ok(if filled == 0 {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Partial
            });
        }
        filled += n;
    }
    Ok(ReadOutcome::Full)
}
