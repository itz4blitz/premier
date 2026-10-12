//! Storage-layer behavior: what readers and recovery do with damaged
//! journals, and that journals are read without rescanning or buffering.

use premier_trace::{
    ACTIVE_JOURNAL, ActiveCursor, FINAL_JOURNAL, JournalEnd, RecoveryOptions, TraceEvent,
    TraceWriter, build_journal_index, inspect_active_journal, read_active_events_after,
    read_active_events_from, read_events, read_events_page, read_events_page_indexed,
    read_manifest, recover_interrupted_trace_with, stream_events, verify,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn force() -> RecoveryOptions {
    RecoveryOptions {
        force: true,
        ..RecoveryOptions::default()
    }
}

/// An abandoned recording of `count` events, as a killed recorder leaves it.
fn abandoned(root: &Path, count: usize) -> Vec<TraceEvent> {
    let mut writer = TraceWriter::create(root, vec!["agent".into()]).unwrap();
    let events = (0..count)
        .map(|index| {
            writer
                .append(
                    "custom.step",
                    "test",
                    serde_json::json!({"index": index, "text": "x".repeat(40)}),
                )
                .unwrap()
        })
        .collect();
    drop(writer);
    events
}

fn finalized(root: &Path, count: usize) {
    let mut writer = TraceWriter::create(root, vec!["agent".into()]).unwrap();
    for index in 0..count {
        writer
            .append(
                "custom.step",
                "test",
                serde_json::json!({"index": index, "text": format!("line {index} {}", "y".repeat(index % 97))}),
            )
            .unwrap();
    }
    writer.finish(0).unwrap();
}

fn active(root: &Path) -> PathBuf {
    root.join("events").join(ACTIVE_JOURNAL)
}

fn append(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// Byte offsets at which each frame of an uncompressed journal starts.
fn frame_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        offsets.push(offset);
        offset += 4 + u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    }
    offsets
}

#[test]
fn zero_padding_after_a_crash_yields_no_phantom_events_and_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("padded.atrace");
    let recorded = abandoned(&root, 3);
    let valid_bytes = fs::metadata(active(&root)).unwrap().len();
    append(&active(&root), &[0_u8; 4096]);

    // Live-tail readers stop at the padding instead of emitting empty events.
    let tail = read_active_events_after(&root, 0).unwrap();
    assert_eq!(tail.events, recorded);
    assert_eq!(tail.next_byte_offset, valid_bytes);
    let again = read_active_events_after(&root, tail.next_byte_offset).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next_byte_offset, valid_bytes);
    let page = read_events_page(&root, 0, 100).unwrap();
    assert_eq!(page, recorded);

    // Whole-journal readers refuse to pass the prefix off as the journal.
    let error = read_events(&root).unwrap_err().to_string();
    assert!(error.contains("zero-length event frame"), "{error}");

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();
    assert_eq!(report.salvaged_events, 3);
    assert_eq!(report.discarded_bytes, 4096);
    assert_eq!(report.discarded_frames, None);
    assert!(report.reason.unwrap().contains("zero-length event frame"));

    let manifest = verify(&root).unwrap();
    let seal = manifest.seal.unwrap();
    assert!(seal.recovered);
    assert_eq!(seal.event_count, 4);
    assert_eq!(seal.discarded_bytes, 4096);
    assert_eq!(seal.discarded_frames, None);
    assert!(
        manifest
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "journal.recovery_discarded"
                && diagnostic.message.contains("4096 byte(s)")),
        "{:?}",
        manifest.diagnostics
    );
    let events = read_events(&root).unwrap();
    assert_eq!(events[..3], recorded[..]);
    assert_eq!(events[3].kind, "session.interrupted");
    assert_eq!(events[3].payload()["discarded_trailing_bytes"], 4096);
}

#[test]
fn a_flipped_byte_mid_journal_salvages_the_events_before_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("flipped.atrace");
    let recorded = abandoned(&root, 8);
    let mut bytes = fs::read(active(&root)).unwrap();
    let offsets = frame_offsets(&bytes);
    assert_eq!(offsets.len(), 8);
    // Inside the payload text of the fifth event: it still decodes, and the
    // sixth event no longer chains from it.
    let fifth = &bytes[offsets[4]..offsets[5]];
    let position = offsets[4] + fifth.windows(8).position(|run| run == b"xxxxxxxx").unwrap();
    bytes[position] ^= 0x01;
    fs::write(active(&root), &bytes).unwrap();

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();
    assert_eq!(report.salvaged_events, 4);
    assert_eq!(report.discarded_bytes, (bytes.len() - offsets[4]) as u64);
    assert_eq!(report.discarded_frames, Some(4));

    let manifest = verify(&root).unwrap();
    assert_eq!(manifest.journal.unwrap().event_count, 5);
    let events = read_events(&root).unwrap();
    assert_eq!(events[..4], recorded[..4]);
    assert_eq!(events[4].kind, "session.interrupted");
    assert_eq!(events[4].payload()["recovered_event_count"], 4);
    assert_eq!(events[4].payload()["discarded_frames"], 4);
}

#[test]
fn a_frame_that_no_longer_decodes_salvages_the_events_before_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("undecodable.atrace");
    let recorded = abandoned(&root, 6);
    let mut bytes = fs::read(active(&root)).unwrap();
    let offsets = frame_offsets(&bytes);
    // The first field tag of the fourth event becomes an invalid wire type.
    bytes[offsets[3] + 4] = 0xff;
    fs::write(active(&root), &bytes).unwrap();

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();
    assert_eq!(report.salvaged_events, 3);
    assert_eq!(report.discarded_bytes, (bytes.len() - offsets[3]) as u64);
    assert_eq!(report.discarded_frames, Some(3));
    verify(&root).unwrap();
    assert_eq!(read_events(&root).unwrap()[..3], recorded[..3]);
}

#[test]
fn an_oversized_tail_length_prefix_salvages_everything_before_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("oversized.atrace");
    let recorded = abandoned(&root, 4);
    let mut garbage = (65_u32 * 1024 * 1024).to_le_bytes().to_vec();
    garbage.extend_from_slice(b"not a frame");
    append(&active(&root), &garbage);

    let tail = read_active_events_after(&root, 0).unwrap();
    assert_eq!(tail.events, recorded);

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();
    assert_eq!(report.salvaged_events, 4);
    assert_eq!(report.discarded_bytes, garbage.len() as u64);
    assert_eq!(report.discarded_frames, None);
    assert!(report.reason.unwrap().contains("64 MiB"));
    verify(&root).unwrap();
    assert_eq!(read_events(&root).unwrap()[..4], recorded[..]);
}

#[test]
fn frames_of_another_trace_or_out_of_sequence_are_not_read() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("spliced.atrace");
    let other = temp.path().join("other.atrace");
    let recorded = abandoned(&root, 3);
    abandoned(&other, 5);
    let own = fs::read(active(&root)).unwrap();
    let foreign = fs::read(active(&other)).unwrap();
    let foreign_offsets = frame_offsets(&foreign);

    // A frame of another trace at the right sequence.
    append(
        &active(&root),
        &foreign[foreign_offsets[3]..foreign_offsets[4]],
    );
    let report = inspect_active_journal(&root).unwrap();
    assert_eq!(report.events, 3);
    assert_eq!(
        report.end,
        JournalEnd::Invalid {
            reason: "event from a different trace".into(),
            chain_break: false
        }
    );
    assert_eq!(read_active_events_after(&root, 0).unwrap().events, recorded);

    // A genuine frame replayed out of order.
    let offsets = frame_offsets(&own);
    let mut replayed = own.clone();
    replayed.extend_from_slice(&own[offsets[1]..offsets[2]]);
    fs::write(active(&root), &replayed).unwrap();
    let report = inspect_active_journal(&root).unwrap();
    assert_eq!(report.events, 3);
    assert!(
        matches!(&report.end, JournalEnd::Invalid { reason, .. } if reason.contains("does not follow")),
        "{:?}",
        report.end
    );
}

#[test]
fn inspecting_an_active_journal_checks_the_chain_and_changes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("live.atrace");
    abandoned(&root, 5);
    append(&active(&root), &[9, 0, 0, 0, 1, 2]);
    let before = fs::read(active(&root)).unwrap();
    let manifest_before = fs::read(root.join("manifest.json")).unwrap();

    let report = inspect_active_journal(&root).unwrap();

    assert_eq!(report.events, 5);
    assert_eq!(report.end, JournalEnd::TornTail);
    assert_eq!(report.total_bytes - report.valid_bytes, 6);
    assert_eq!(report.chain_head.map(|head| head.len()), Some(64));
    assert_eq!(fs::read(active(&root)).unwrap(), before);
    assert_eq!(
        fs::read(root.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert!(read_manifest(&root).unwrap().journal.is_none());
}

#[test]
fn a_truncated_finalized_journal_is_an_error_for_every_reader() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("truncated.atrace");
    finalized(&root, 400);
    let path = root.join("events").join(FINAL_JOURNAL);
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 400);

    for cut in [200, 1, bytes.len() - 5] {
        fs::write(&path, &bytes[..bytes.len() - cut]).unwrap();

        let error = format!("{:#}", read_events(&root).unwrap_err());
        assert!(error.contains("truncated"), "cut {cut}: {error}");
        assert!(read_events_page(&root, 0, usize::MAX).is_err(), "cut {cut}");
        assert!(read_events_page(&root, 390, 100).is_err(), "cut {cut}");
        let mut stream = stream_events(&root).unwrap();
        assert!(stream.any(|event| event.is_err()), "cut {cut}");
        assert_eq!(stream.end(), None);
        let error = verify(&root).unwrap_err().to_string();
        assert!(error.contains("digest mismatch"), "cut {cut}: {error}");
    }

    // The whole file reads and verifies again.
    fs::write(&path, &bytes).unwrap();
    assert_eq!(read_events(&root).unwrap().len(), 400);
    verify(&root).unwrap();
}

#[test]
fn a_finalized_journal_cut_inside_an_event_frame_is_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cut-frame.atrace");
    finalized(&root, 20);
    let path = root.join("events").join(FINAL_JOURNAL);
    let plain = zstd::stream::decode_all(fs::File::open(&path).unwrap()).unwrap();
    let offsets = frame_offsets(&plain);

    // A well-formed zstd stream whose content ends inside the last frame.
    let cut = &plain[..offsets[19] + 9];
    fs::write(&path, zstd::stream::encode_all(cut, 3).unwrap()).unwrap();
    let error = read_events(&root).unwrap_err().to_string();
    assert!(error.contains("ends inside an event frame"), "{error}");
    assert!(read_events_page(&root, 0, 100).is_err());

    // Ending on a frame boundary is a clean end to a reader; the manifest's
    // count and seal are what expose it.
    fs::write(
        &path,
        zstd::stream::encode_all(&plain[..offsets[19]], 3).unwrap(),
    )
    .unwrap();
    assert_eq!(read_events(&root).unwrap().len(), 19);
    assert!(verify(&root).is_err());
}

#[test]
fn indexed_pages_equal_scanned_pages_and_resume_inside_the_journal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("paged.atrace");
    let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
    for index in 0..3_000 {
        writer
            .append(
                "custom.step",
                "test",
                serde_json::json!({"index": index, "text": format!("{index:05}").repeat(200)}),
            )
            .unwrap();
    }
    writer.finish(0).unwrap();
    verify(&root).unwrap();
    let all = read_events(&root).unwrap();
    assert_eq!(all.len(), 3_000);

    let index = build_journal_index(&root).unwrap();
    assert!(index.resume_points() > 2, "{}", index.resume_points());

    for (after, limit) in [
        (0, 1),
        (0, 500),
        (499, 500),
        (1_500, 7),
        (2_990, 500),
        (2_999, 5),
        (3_000, 5),
        (9_999, 5),
    ] {
        let indexed = read_events_page_indexed(&root, &index, after, limit).unwrap();
        let scanned = read_events_page(&root, after, limit).unwrap();
        assert_eq!(indexed, scanned, "after {after} limit {limit}");
        let expected = all
            .iter()
            .filter(|event| event.sequence > after)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(indexed, expected, "after {after} limit {limit}");
    }

    // A full paged load visits every event exactly once.
    let mut after = 0;
    let mut loaded = Vec::new();
    loop {
        let page = read_events_page_indexed(&root, &index, after, 250).unwrap();
        let Some(last) = page.last() else { break };
        after = last.sequence;
        loaded.extend(page);
    }
    assert_eq!(loaded, all);
}

#[test]
fn an_index_resumes_without_reading_the_start_of_the_journal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("resume.atrace");
    let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
    for index in 0..3_000 {
        writer
            .append(
                "custom.step",
                "test",
                serde_json::json!({"text": format!("{index:05}").repeat(200)}),
            )
            .unwrap();
    }
    writer.finish(0).unwrap();
    let index = build_journal_index(&root).unwrap();
    let expected = read_events_page(&root, 2_900, 50).unwrap();

    // Destroy the first bytes of the compressed journal. A reader that
    // starts at the beginning fails; one that resumes never looks at them.
    let path = root.join("events").join(FINAL_JOURNAL);
    let mut bytes = fs::read(&path).unwrap();
    for byte in &mut bytes[..64] {
        *byte = 0;
    }
    fs::write(&path, bytes).unwrap();

    assert!(read_events_page(&root, 2_900, 50).is_err());
    assert_eq!(
        read_events_page_indexed(&root, &index, 2_900, 50).unwrap(),
        expected
    );
}

#[test]
fn an_index_of_another_journal_file_is_ignored() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.atrace");
    let second = temp.path().join("second.atrace");
    finalized(&first, 50);
    finalized(&second, 80);
    let stale = build_journal_index(&first).unwrap();

    let page = read_events_page_indexed(&second, &stale, 70, 100).unwrap();

    assert_eq!(page, read_events_page(&second, 70, 100).unwrap());
    assert_eq!(page.len(), 10);
}

#[test]
fn a_live_cursor_skips_what_the_client_already_has_and_keeps_validating() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cursor.atrace");
    let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
    let mut recorded = Vec::new();
    for index in 0..10 {
        recorded.push(
            writer
                .append("custom.step", "test", serde_json::json!({"index": index}))
                .unwrap(),
        );
    }

    // Events up to the resume sequence are decoded once and not returned;
    // batches are bounded.
    let first = read_active_events_from(&root, &ActiveCursor::start(), 6, 2).unwrap();
    assert_eq!(first.events, recorded[6..8]);
    assert_eq!(first.end, None);
    let second = read_active_events_from(&root, &first.cursor, 6, 100).unwrap();
    assert_eq!(second.events, recorded[8..]);
    assert_eq!(second.end, Some(JournalEnd::Clean));
    assert_eq!(second.cursor.sequence(), 10);

    // The cursor carries the chain: a frame that does not follow is refused
    // even though only the new bytes are read.
    let eleventh = writer
        .append("custom.step", "test", serde_json::json!({"index": 10}))
        .unwrap();
    let third = read_active_events_from(&root, &second.cursor, 6, 100).unwrap();
    assert_eq!(third.events, vec![eleventh]);
    let bytes = fs::read(active(&root)).unwrap();
    let offsets = frame_offsets(&bytes);
    append(&active(&root), &bytes[offsets[10]..]);
    let fourth = read_active_events_from(&root, &third.cursor, 6, 100).unwrap();
    assert!(fourth.events.is_empty());
    assert!(matches!(fourth.end, Some(JournalEnd::Invalid { .. })));
    assert_eq!(fourth.cursor.byte_offset(), third.cursor.byte_offset());
    drop(writer);
}
