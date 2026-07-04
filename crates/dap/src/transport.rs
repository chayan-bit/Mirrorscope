//! DAP base-protocol framing: `Content-Length: N\r\n\r\n<N bytes of JSON>`.

use std::io::{BufRead, Write};

use serde_json::Value;

/// Errors produced while framing/deframing DAP messages.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Header block ended without a `Content-Length` field.
    #[error("missing Content-Length header")]
    MissingContentLength,
    /// `Content-Length` was present but not a number.
    #[error("invalid Content-Length header: {0}")]
    InvalidContentLength(String),
    /// The payload was not valid JSON.
    #[error("malformed JSON payload: {0}")]
    MalformedJson(#[from] serde_json::Error),
    /// Underlying I/O failure.
    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Read one message. `Ok(None)` means clean EOF (client hung up).
pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Value>, TransportError> {
    let content_length = match read_headers(reader)? {
        Some(len) => len,
        None => return Ok(None),
    };
    let mut payload = vec![0u8; content_length];
    reader.read_exact(&mut payload)?;
    Ok(Some(serde_json::from_slice(&payload)?))
}

/// Write one message with its `Content-Length` header.
pub fn write_frame<W: Write>(writer: &mut W, message: &Value) -> Result<(), TransportError> {
    let payload = serde_json::to_vec(message)?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Parse the header block; returns the content length, or `None` on EOF
/// before any header byte.
fn read_headers<R: BufRead>(reader: &mut R) -> Result<Option<usize>, TransportError> {
    let mut content_length: Option<usize> = None;
    let mut saw_any_byte = false;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return if saw_any_byte {
                Err(TransportError::MissingContentLength)
            } else {
                Ok(None)
            };
        }
        saw_any_byte = true;

        let line = line.trim_end();
        if line.is_empty() {
            return content_length
                .map(Some)
                .ok_or(TransportError::MissingContentLength);
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            let value = value.trim();
            content_length = Some(
                value
                    .parse()
                    .map_err(|_| TransportError::InvalidContentLength(value.to_owned()))?,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_a_message() {
        let msg = json!({ "seq": 1, "type": "request", "command": "initialize" });
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).expect("write");
        let decoded = read_frame(&mut buf.as_slice()).expect("read");
        assert_eq!(decoded, Some(msg));
    }

    #[test]
    fn returns_none_on_clean_eof() {
        let empty: &[u8] = b"";
        assert!(matches!(read_frame(&mut &*empty), Ok(None)));
    }

    #[test]
    fn errors_when_content_length_is_missing() {
        let bad: &[u8] = b"X-Other: 1\r\n\r\n{}";
        assert!(matches!(
            read_frame(&mut &*bad),
            Err(TransportError::MissingContentLength)
        ));
    }

    #[test]
    fn errors_when_content_length_is_garbage() {
        let bad: &[u8] = b"Content-Length: nope\r\n\r\n{}";
        assert!(matches!(
            read_frame(&mut &*bad),
            Err(TransportError::InvalidContentLength(_))
        ));
    }
}
