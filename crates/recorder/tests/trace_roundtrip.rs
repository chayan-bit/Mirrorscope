//! Integration tests for the append-only trace log (issues #2, #9):
//! writer -> reader round-trip, global sequence numbers, checksums,
//! per-event thread ids (v3), and forward/backward compatibility.

use recorder::trace::{Cmdline, Event, EventKind, TraceError, TraceReader, TraceWriter, MAGIC};

/// A v3 fixture: every event carries a thread id so the tid round-trip is
/// exercised alongside kind/timestamp/payload.
fn fixture_events() -> Vec<Event> {
    vec![
        Event::new_with_tid(EventKind::SyscallEnter, 100, 7, vec![1, 2, 3]),
        Event::new_with_tid(EventKind::SyscallExit, 150, 7, vec![4, 5]),
        Event::new_with_tid(EventKind::SchedSwitch, 200, 9, vec![9, 0, 0, 0]),
        Event::new_with_tid(EventKind::ThreadSpawn, 210, 7, vec![7, 0, 0, 0, 9, 0, 0, 0]),
        Event::new_with_tid(EventKind::Signal, 250, 9, vec![9]),
        Event::new_with_tid(EventKind::SyncAcquire, 300, 9, vec![0xde, 0xad]),
        Event::new_with_tid(EventKind::ThreadExit, 340, 9, vec![9, 0, 0, 0]),
        Event::new_with_tid(EventKind::Fork, 350, 7, vec![7; 64]),
        Event::new_with_tid(EventKind::Checkpoint, 400, 7, vec![]),
    ]
}

fn write_fixture() -> Vec<u8> {
    let mut writer = TraceWriter::create(Vec::new()).expect("create writer");
    for event in fixture_events() {
        writer.append(&event).expect("append event");
    }
    writer.into_inner()
}

#[test]
fn round_trips_fixture_stream_with_stable_ordering_and_tids() {
    let bytes = write_fixture();
    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    assert_eq!(reader.version(), recorder::trace::FORMAT_VERSION);
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();

    let expected = fixture_events();
    assert_eq!(records.len(), expected.len());
    for (record, event) in records.iter().zip(&expected) {
        assert_eq!(record.event.kind, event.kind);
        assert_eq!(record.event.timestamp_ns, event.timestamp_ns);
        assert_eq!(
            record.event.tid, event.tid,
            "tid must survive the round-trip"
        );
        assert_eq!(record.event.payload, event.payload);
    }
}

#[test]
fn defaults_tid_to_zero_for_unattributed_events_in_v3() {
    let mut writer = TraceWriter::create(Vec::new()).expect("create writer");
    writer
        .append(&Event::new(EventKind::Checkpoint, 1, vec![]))
        .expect("append");
    let bytes = writer.into_inner();
    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(
        records[0].event.tid,
        Some(0),
        "a v3 record with no thread attribution records tid 0"
    );
}

#[test]
fn assigns_monotonic_global_sequence_numbers_starting_at_zero() {
    let mut writer = TraceWriter::create(Vec::new()).expect("create writer");
    let seqs: Vec<u64> = fixture_events()
        .iter()
        .map(|e| writer.append(e).expect("append"))
        .collect();
    assert_eq!(seqs, (0..fixture_events().len() as u64).collect::<Vec<_>>());

    let bytes = writer.into_inner();
    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let read_seqs: Vec<u64> = reader.map(|r| r.expect("valid record").seq).collect();
    assert_eq!(read_seqs, seqs);
}

#[test]
fn detects_corrupted_record_payload() {
    let mut bytes = write_fixture();
    let last = bytes.len() - 10;
    bytes[last] ^= 0xff;

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let results: Vec<_> = reader.collect();
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(TraceError::ChecksumMismatch { .. }))),
        "corruption must surface as ChecksumMismatch, got {results:?}"
    );
}

#[test]
fn errors_on_truncated_record() {
    let bytes = write_fixture();
    let truncated = &bytes[..bytes.len() - 3];

    let reader = TraceReader::open(truncated).expect("open reader");
    let results: Vec<_> = reader.collect();
    assert!(
        matches!(results.last(), Some(Err(TraceError::Truncated))),
        "truncation must surface as Truncated, got {results:?}"
    );
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = write_fixture();
    bytes[0] = b'X';
    assert!(matches!(
        TraceReader::open(&bytes[..]),
        Err(TraceError::BadMagic)
    ));
}

#[test]
fn rejects_unsupported_future_version() {
    let mut bytes = write_fixture();
    bytes[8] = 0xff;
    bytes[9] = 0xff;
    assert!(matches!(
        TraceReader::open(&bytes[..]),
        Err(TraceError::UnsupportedVersion { .. })
    ));
}

#[test]
fn round_trips_embedded_cmdline() {
    let mut writer = TraceWriter::create_with_cmdline(
        Vec::new(),
        "head",
        &["-c".to_owned(), "32".to_owned(), "file".to_owned()],
    )
    .expect("create writer");
    for event in fixture_events() {
        writer.append(&event).expect("append event");
    }
    let bytes = writer.into_inner();

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    assert_eq!(
        reader.cmdline(),
        Some(&Cmdline {
            program: "head".to_owned(),
            args: vec!["-c".to_owned(), "32".to_owned(), "file".to_owned()],
        })
    );
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(records.len(), fixture_events().len());
}

/// Hand-forge a pre-v3 (tid-less) trace body: `seq | ts | kind | payload`,
/// framed exactly like the writer does, so we can prove old traces stay
/// readable without the v3 writer (which always emits tids).
fn forge_legacy_trace(version: u16, events: &[(u64, EventKind, u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&12u16.to_le_bytes()); // header_len, no cmdline
    for (seq, kind, ts, payload) in events {
        let mut body = Vec::new();
        body.extend_from_slice(&seq.to_le_bytes());
        body.extend_from_slice(&ts.to_le_bytes());
        body.extend_from_slice(&kind.to_u16().to_le_bytes());
        body.extend_from_slice(payload);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        let crc = crc32fast::hash(&body);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc.to_le_bytes());
    }
    out
}

#[test]
fn reads_legacy_v1_trace_without_tids() {
    let events = vec![
        (0u64, EventKind::SyscallEnter, 100u64, vec![1, 2, 3]),
        (1, EventKind::SyscallExit, 150, vec![4, 5]),
    ];
    let bytes = forge_legacy_trace(1, &events);

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    assert_eq!(reader.version(), 1);
    assert_eq!(reader.cmdline(), None, "v1 traces carry no command line");
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].event.kind, EventKind::SyscallEnter);
    assert_eq!(records[0].event.tid, None, "v1 records carry no tid");
    assert_eq!(records[0].event.payload, vec![1, 2, 3]);
    assert_eq!(records[1].event.kind, EventKind::SyscallExit);
    assert_eq!(records[1].event.tid, None);
}

#[test]
fn reads_legacy_v2_trace_kinds_and_payloads() {
    let events = vec![
        (0u64, EventKind::SyscallEnter, 100u64, vec![9, 9]),
        (1, EventKind::Signal, 150, vec![11]),
        (2, EventKind::SyscallExit, 200, vec![0xaa]),
    ];
    let bytes = forge_legacy_trace(2, &events);

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    assert_eq!(reader.version(), 2);
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(records.len(), 3);
    for (record, (_, kind, ts, payload)) in records.iter().zip(&events) {
        assert_eq!(record.event.kind, *kind);
        assert_eq!(record.event.timestamp_ns, *ts);
        assert_eq!(record.event.tid, None, "pre-v3 records carry no tid");
        assert_eq!(&record.event.payload, payload);
    }
}

#[test]
fn skips_reserved_header_bytes_from_newer_minor_writers() {
    // A future writer may enlarge the header after the cmdline; readers must
    // honor the header-length field and skip bytes they do not understand.
    let mut writer =
        TraceWriter::create_with_cmdline(Vec::new(), "true", &[]).expect("create writer");
    for event in fixture_events() {
        writer.append(&event).expect("append event");
    }
    let bytes = writer.into_inner();
    let header_len = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;

    let mut extended = bytes[..header_len].to_vec();
    extended.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    let new_len = (header_len + 4) as u16;
    extended[10..12].copy_from_slice(&new_len.to_le_bytes());
    extended.extend_from_slice(&bytes[header_len..]);

    let reader = TraceReader::open(&extended[..]).expect("open reader");
    assert_eq!(
        reader.cmdline().map(|c| c.program.as_str()),
        Some("true"),
        "cmdline must survive trailing reserved header bytes"
    );
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(records.len(), fixture_events().len());
}

#[test]
fn preserves_unknown_event_kinds_for_forward_compat() {
    let mut writer = TraceWriter::create(Vec::new()).expect("create writer");
    writer
        .append(&Event::new(EventKind::Unknown(0x7abc), 42, vec![1]))
        .expect("append");

    let bytes = writer.into_inner();
    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(records[0].event.kind, EventKind::Unknown(0x7abc));
}

/// A crafted (or corrupt) trace declaring a huge `body_len` must be rejected
/// *before* the reader allocates a buffer for it — not after a ~4 GiB
/// allocation attempt. Forges a single record frame with a legitimate-looking
/// header but a `body_len` of `0xFFFF_FFFF` and no actual body bytes behind
/// it, proving the bound check runs ahead of the read.
#[test]
fn rejects_a_record_declaring_an_oversized_body_length_before_allocating() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&recorder::trace::FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&12u16.to_le_bytes()); // header_len, no cmdline
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // forged body_len
                                                            // Deliberately no body/crc bytes follow: if the reader tried to
                                                            // `read_exact` that many bytes it would hit `Truncated` instead, which
                                                            // would mask the bug this test guards against (the oversized
                                                            // allocation itself, not merely the eventual truncation).

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let results: Vec<_> = reader.collect();
    assert!(
        matches!(results.last(), Some(Err(TraceError::BodyTooLarge { .. }))),
        "an oversized declared body length must be rejected before allocation, got {results:?}"
    );
}

#[test]
fn reader_rejects_non_monotonic_sequence_numbers() {
    let mut writer = TraceWriter::create(Vec::new()).expect("create writer");
    writer
        .append(&Event::new(EventKind::SyscallEnter, 1, vec![]))
        .expect("append");
    let mut bytes = writer.into_inner();

    // Duplicate the first record frame verbatim: same seq twice.
    let header_len = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    let frame = bytes[header_len..].to_vec();
    bytes.extend_from_slice(&frame);

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let results: Vec<_> = reader.collect();
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(TraceError::NonMonotonicSequence { .. }))),
        "duplicate seq must surface as NonMonotonicSequence, got {results:?}"
    );
}
