//! Portable wire encoding of syscall event payloads stored in the trace.
//!
//! Kept free of any ptrace/Linux dependency so the replay engine (and these
//! tests) can decode traces on every host platform.

/// Payload of an [`EventKind::SyscallEnter`](crate::trace::EventKind) record:
/// the syscall number and its six raw arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEnter {
    /// Architecture-specific syscall number.
    pub nr: u64,
    /// The six raw syscall arguments.
    pub args: [u64; 6],
}

/// Payload of an [`EventKind::SyscallExit`](crate::trace::EventKind) record:
/// the return value plus any input data the kernel wrote into the tracee
/// (read buffers, `getrandom` bytes, `clock_gettime` results, …) — the
/// deterministic input stream replay feeds back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallExit {
    /// Architecture-specific syscall number.
    pub nr: u64,
    /// Raw return value (negative errno convention).
    pub ret: i64,
    /// Captured kernel-written data, empty when the syscall writes none.
    pub data: Vec<u8>,
}

/// Errors decoding a syscall payload.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// The payload was shorter than its fixed-size prefix.
    #[error("syscall payload too short: {found} bytes, need at least {need}")]
    TooShort {
        /// Bytes present.
        found: usize,
        /// Bytes required.
        need: usize,
    },
    /// The declared data length disagrees with the actual payload size.
    #[error("syscall payload data length mismatch")]
    LengthMismatch,
}

const ENTER_LEN: usize = 8 + 6 * 8;
const EXIT_PREFIX_LEN: usize = 8 + 8 + 4;

impl SyscallEnter {
    /// Encode for a trace record payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENTER_LEN);
        out.extend_from_slice(&self.nr.to_le_bytes());
        for arg in self.args {
            out.extend_from_slice(&arg.to_le_bytes());
        }
        out
    }

    /// Decode from a trace record payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() != ENTER_LEN {
            return Err(PayloadError::TooShort {
                found: payload.len(),
                need: ENTER_LEN,
            });
        }
        let nr = u64::from_le_bytes(payload[0..8].try_into().expect("length checked"));
        let mut args = [0u64; 6];
        for (i, arg) in args.iter_mut().enumerate() {
            let start = 8 + i * 8;
            *arg = u64::from_le_bytes(
                payload[start..start + 8]
                    .try_into()
                    .expect("length checked"),
            );
        }
        Ok(Self { nr, args })
    }
}

impl SyscallExit {
    /// Encode for a trace record payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXIT_PREFIX_LEN + self.data.len());
        out.extend_from_slice(&self.nr.to_le_bytes());
        out.extend_from_slice(&self.ret.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode from a trace record payload.
    pub fn decode(payload: &[u8]) -> Result<Self, PayloadError> {
        if payload.len() < EXIT_PREFIX_LEN {
            return Err(PayloadError::TooShort {
                found: payload.len(),
                need: EXIT_PREFIX_LEN,
            });
        }
        let nr = u64::from_le_bytes(payload[0..8].try_into().expect("length checked"));
        let ret = i64::from_le_bytes(payload[8..16].try_into().expect("length checked"));
        let data_len = u32::from_le_bytes(payload[16..20].try_into().expect("length checked"));
        let data = payload[EXIT_PREFIX_LEN..].to_vec();
        if data.len() != data_len as usize {
            return Err(PayloadError::LengthMismatch);
        }
        Ok(Self { nr, ret, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_enter_round_trips() {
        let enter = SyscallEnter {
            nr: 63,
            args: [3, 0x7fff_0000, 4096, 0, u64::MAX, 7],
        };
        assert_eq!(
            SyscallEnter::decode(&enter.encode()).expect("decode"),
            enter
        );
    }

    #[test]
    fn syscall_exit_round_trips_with_captured_data() {
        let exit = SyscallExit {
            nr: 63,
            ret: 5,
            data: vec![0xde, 0xad, 0xbe, 0xef, 0x00],
        };
        assert_eq!(SyscallExit::decode(&exit.encode()).expect("decode"), exit);
    }

    #[test]
    fn syscall_exit_round_trips_negative_errno_and_empty_data() {
        let exit = SyscallExit {
            nr: 63,
            ret: -11, // -EAGAIN
            data: vec![],
        };
        assert_eq!(SyscallExit::decode(&exit.encode()).expect("decode"), exit);
    }

    #[test]
    fn rejects_short_enter_payload() {
        assert!(matches!(
            SyscallEnter::decode(&[0u8; 10]),
            Err(PayloadError::TooShort { .. })
        ));
    }

    #[test]
    fn rejects_exit_payload_with_inconsistent_length() {
        let mut bytes = SyscallExit {
            nr: 0,
            ret: 4,
            data: vec![1, 2, 3, 4],
        }
        .encode();
        bytes.truncate(bytes.len() - 1);
        assert!(matches!(
            SyscallExit::decode(&bytes),
            Err(PayloadError::LengthMismatch)
        ));
    }
}
