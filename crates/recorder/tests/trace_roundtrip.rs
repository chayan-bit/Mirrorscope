//! Integration tests for the append-only trace log (issue #2):
//! writer -> reader round-trip, global sequence numbers, checksums,
//! and forward-compatibility of the header.

use recorder::trace::{Cmdline, Event, EventKind, TraceError, TraceReader, TraceWriter};

fn fixture_events() -> Vec<Event> {
    vec![
        Event::new(EventKind::SyscallEnter, 100, vec![1, 2, 3]),
        Event::new(EventKind::SyscallExit, 150, vec![4, 5]),
        Event::new(EventKind::SchedSwitch, 200, vec![]),
        Event::new(EventKind::Signal, 250, vec![9]),
        Event::new(EventKind::SyncAcquire, 300, vec![0xde, 0xad]),
        Event::new(EventKind::Fork, 350, vec![7; 64]),
        Event::new(EventKind::Checkpoint, 400, vec![]),
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
fn round_trips_fixture_stream_with_stable_ordering() {
    let bytes = write_fixture();
    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();

    let expected = fixture_events();
    assert_eq!(records.len(), expected.len());
    for (record, event) in records.iter().zip(&expected) {
        assert_eq!(record.event.kind, event.kind);
        assert_eq!(record.event.timestamp_ns, event.timestamp_ns);
        assert_eq!(record.event.payload, event.payload);
    }
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

#[test]
fn reads_v1_trace_without_a_cmdline() {
    // Forge a v1 trace (no embedded cmdline) by writing a header-less v2 trace
    // and stamping the version field back to 1: readers must still parse it and
    // report no cmdline.
    let mut writer = TraceWriter::create(Vec::new()).expect("create writer");
    for event in fixture_events() {
        writer.append(&event).expect("append event");
    }
    let mut bytes = writer.into_inner();
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());

    let reader = TraceReader::open(&bytes[..]).expect("open reader");
    assert_eq!(reader.cmdline(), None, "v1 traces carry no command line");
    let records: Vec<_> = reader.map(|r| r.expect("valid record")).collect();
    assert_eq!(records.len(), fixture_events().len());
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
