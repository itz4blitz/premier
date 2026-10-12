//! Regression tests for review findings in trace storage: recovery
//! (journaled exit, time of death, repeatability, leftovers), exclusive trace
//! creation, claims on unfinalized traces, format-version errors, unknown
//! manifest fields, interrupted encryption, and lifecycle validation.

use premier_trace::{
    ACTIVE_JOURNAL, EncryptionKey, FINAL_JOURNAL, RECORDER_LEASE, RecoveryOptions, TerminationKind,
    TraceDiagnostic, TraceEvent, TraceWriter, UnsupportedFormatVersion, claim_local_trace,
    current_diagnostics, decode_utf8_chunk_lossy, finish_utf8_lossy, random_secret_hex,
    read_events, read_manifest, read_manifest_with_key, recover_interrupted_trace_with,
    reencrypt_finalized_trace_with_signing_key, validate_events, verify,
};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

fn force() -> RecoveryOptions {
    RecoveryOptions {
        force: true,
        ..RecoveryOptions::default()
    }
}

/// A recording whose recorder died after journaling `events`.
fn abandoned(root: &Path, events: &[(&str, &str, serde_json::Value)]) {
    let mut writer = TraceWriter::create(root, vec!["agent".into()]).unwrap();
    for (kind, source, payload) in events {
        writer.append(kind, source, payload.clone()).unwrap();
    }
    drop(writer);
}

fn finalized(root: &Path) {
    let mut writer = TraceWriter::create(root, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "premier", serde_json::json!({}))
        .unwrap();
    writer.finish(0).unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn kinds(root: &Path) -> Vec<String> {
    read_events(root)
        .unwrap()
        .into_iter()
        .map(|event| event.kind)
        .collect()
}

#[test]
fn recovery_keeps_the_exit_status_the_recorder_journaled() {
    let temp = tempfile::tempdir().unwrap();
    let exited = temp.path().join("exited.atrace");
    abandoned(
        &exited,
        &[
            ("session.start", "premier", serde_json::json!({})),
            (
                "process.exit",
                "command",
                serde_json::json!({"exit_code": 3, "success": false, "termination": "exit"}),
            ),
        ],
    );
    let report = recover_interrupted_trace_with(&exited, force(), None).unwrap();
    assert!(report.journaled_exit);
    let manifest = verify(&exited).unwrap();
    assert_eq!(manifest.exit_code, Some(3));
    let termination = manifest.termination.unwrap();
    assert_eq!(termination.kind, TerminationKind::Exit);
    assert_eq!(termination.exit_code, Some(3));
    let events = read_events(&exited).unwrap();
    assert_eq!(events.last().unwrap().kind, "session.interrupted");
    assert_eq!(events.last().unwrap().payload()["exit_recorded"], true);

    let signaled = temp.path().join("signaled.atrace");
    abandoned(
        &signaled,
        &[(
            "process.exit",
            "command",
            serde_json::json!({
                "exit_code": 143, "success": false, "termination": "signal",
                "signal": 15, "signal_name": "SIGTERM",
            }),
        )],
    );
    let manifest = recover_interrupted_trace_with(&signaled, force(), None)
        .unwrap()
        .manifest;
    let termination = manifest.termination.unwrap();
    assert_eq!(termination.kind, TerminationKind::Signal);
    assert_eq!(termination.signal, Some(15));
    assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
    assert_eq!(manifest.exit_code, Some(143));

    // Without a journaled exit the status is unknown: interrupted, 130.
    let unknown = temp.path().join("unknown.atrace");
    abandoned(
        &unknown,
        &[("session.start", "premier", serde_json::json!({}))],
    );
    let report = recover_interrupted_trace_with(&unknown, force(), None).unwrap();
    assert!(!report.journaled_exit);
    assert_eq!(report.manifest.exit_code, Some(130));
    assert_eq!(
        report.manifest.termination.unwrap().kind,
        TerminationKind::Interrupted
    );
    let events = read_events(&unknown).unwrap();
    assert_eq!(events.last().unwrap().payload()["exit_recorded"], false);
}

#[test]
fn an_exit_event_that_recovery_discards_does_not_set_the_exit_status() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("torn-exit.atrace");
    abandoned(
        &root,
        &[
            ("session.start", "premier", serde_json::json!({})),
            (
                "process.exit",
                "command",
                serde_json::json!({"exit_code": 0, "success": true, "termination": "exit"}),
            ),
        ],
    );
    // Cut the journal inside the process.exit frame.
    let active = root.join("events").join(ACTIVE_JOURNAL);
    let bytes = fs::read(&active).unwrap();
    fs::write(&active, &bytes[..bytes.len() - 5]).unwrap();

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();

    assert!(!report.journaled_exit);
    assert_eq!(report.salvaged_events, 1);
    assert_eq!(report.manifest.exit_code, Some(130));
}

#[test]
fn recovery_dates_the_end_of_the_run_by_its_last_activity_not_by_the_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("old.atrace");
    abandoned(
        &root,
        &[("session.start", "premier", serde_json::json!({}))],
    );
    let started_at = read_manifest(&root).unwrap().started_at;
    // The recorder last wrote ten seconds after it started; it is recovered
    // much later.
    let died = SystemTime::from(started_at) + Duration::from_secs(10);
    fs::File::options()
        .write(true)
        .open(root.join("events").join(ACTIVE_JOURNAL))
        .unwrap()
        .set_modified(died)
        .unwrap();

    let before_recovery = chrono::Utc::now();
    let manifest = recover_interrupted_trace_with(&root, force(), None)
        .unwrap()
        .manifest;

    let ended_at = manifest.ended_at.unwrap();
    assert_eq!(
        (ended_at - started_at).num_seconds(),
        10,
        "ended_at {ended_at} should be the journal's last write"
    );
    let events = read_events(&root).unwrap();
    let marker = events.last().unwrap();
    assert_eq!(marker.kind, "session.interrupted");
    let last_activity = chrono::DateTime::parse_from_rfc3339(
        marker.payload()["last_activity_at"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(last_activity, ended_at);
    // The marker itself is stamped with the time of the recovery.
    let recovered_at = chrono::DateTime::parse_from_rfc3339(&marker.timestamp).unwrap();
    assert!(recovered_at >= before_recovery - chrono::Duration::seconds(1));
    verify(&root).unwrap();
}

/// A recovery killed after it rewrote the journal (kept frames plus
/// `session.interrupted`) but before it committed the manifest.
#[test]
fn a_repeated_recovery_does_not_append_a_second_interruption_marker() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.atrace");
    abandoned(
        &first,
        &[
            ("session.start", "premier", serde_json::json!({})),
            ("custom.step", "test", serde_json::json!({"index": 1})),
        ],
    );
    // Two copies of the same abandoned recording, to rebuild both crash states.
    let journal_only = temp.path().join("journal-only.atrace");
    let compressed_only = temp.path().join("compressed-only.atrace");
    copy_dir(&first, &journal_only);
    copy_dir(&first, &compressed_only);
    let recovered = recover_interrupted_trace_with(&first, force(), None)
        .unwrap()
        .manifest;
    let recovered_events = read_events(&first).unwrap();
    assert_eq!(
        kinds(&first),
        ["session.start", "custom.step", "session.interrupted"]
    );
    let compressed = first.join("events").join(FINAL_JOURNAL);

    // Killed before the compressed journal was published: the rewritten
    // active journal is all there is.
    let mut rewritten = Vec::new();
    zstd::stream::copy_decode(fs::File::open(&compressed).unwrap(), &mut rewritten).unwrap();
    fs::write(journal_only.join("events").join(ACTIVE_JOURNAL), rewritten).unwrap();
    let report = recover_interrupted_trace_with(&journal_only, force(), None).unwrap();
    assert_eq!(report.salvaged_events, 2);
    assert_eq!(read_events(&journal_only).unwrap(), recovered_events);
    assert_eq!(report.manifest.ended_at, recovered.ended_at);
    verify(&journal_only).unwrap();

    // The compressed journal was published, the manifest was not committed,
    // and the active journal has since been lost.
    fs::copy(
        &compressed,
        compressed_only.join("events").join(FINAL_JOURNAL),
    )
    .unwrap();
    fs::remove_file(compressed_only.join("events").join(ACTIVE_JOURNAL)).unwrap();
    let report = recover_interrupted_trace_with(&compressed_only, force(), None).unwrap();
    assert_eq!(report.salvaged_events, 2);
    assert_eq!(read_events(&compressed_only).unwrap(), recovered_events);
    verify(&compressed_only).unwrap();
}

#[test]
fn recovery_of_a_finalized_trace_only_removes_what_finalization_left_behind() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("leftovers.atrace");
    finalized(&root);
    let manifest_before = fs::read(root.join("manifest.json")).unwrap();
    let journal_before = fs::read(root.join("events").join(FINAL_JOURNAL)).unwrap();
    // Finalization commits the manifest, then removes these two.
    fs::write(root.join("events").join(ACTIVE_JOURNAL), b"stale frames").unwrap();
    fs::write(root.join(RECORDER_LEASE), "1").unwrap();

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();

    assert_eq!(
        report.removed_leftovers,
        [
            format!("events/{ACTIVE_JOURNAL}"),
            RECORDER_LEASE.to_owned()
        ]
    );
    assert!(!root.join("events").join(ACTIVE_JOURNAL).exists());
    assert!(!root.join(RECORDER_LEASE).exists());
    assert_eq!(
        fs::read(root.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(root.join("events").join(FINAL_JOURNAL)).unwrap(),
        journal_before
    );
    verify(&root).unwrap();
    // With nothing left over, recovery has nothing to do and says so.
    let error = recover_interrupted_trace_with(&root, force(), None).unwrap_err();
    assert!(error.to_string().contains("already finalized"), "{error:#}");
}

#[test]
fn leftovers_of_a_finalized_trace_that_does_not_verify_are_kept() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("damaged.atrace");
    finalized(&root);
    fs::write(
        root.join("events").join(ACTIVE_JOURNAL),
        b"maybe the only copy",
    )
    .unwrap();
    fs::write(root.join("events").join(FINAL_JOURNAL), b"not a journal").unwrap();

    let error = recover_interrupted_trace_with(&root, force(), None).unwrap_err();

    assert!(error.to_string().contains("does not verify"), "{error:#}");
    assert!(root.join("events").join(ACTIVE_JOURNAL).exists());
}

#[test]
fn a_trace_directory_is_created_exclusively() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("nested").join("contended.atrace");
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| TraceWriter::create(&root, vec!["agent".into()])))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let (winners, losers): (Vec<_>, Vec<_>) = results.into_iter().partition(Result::is_ok);
    assert_eq!(winners.len(), 1, "exactly one recorder may own the path");
    for loser in losers {
        let error = loser.err().unwrap();
        assert!(
            error.to_string().contains("trace path already exists"),
            "{error:#}"
        );
        let io = error.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists);
    }
    // The winner's manifest is the one on disk, untouched by the losers.
    let winner = winners.into_iter().next().unwrap().unwrap();
    assert_eq!(read_manifest(&root).unwrap().trace_id, winner.trace_id());
    winner.finish(0).unwrap();
    verify(&root).unwrap();

    // An empty directory someone else made is not taken over either.
    let existing = temp.path().join("existing.atrace");
    fs::create_dir(&existing).unwrap();
    assert!(TraceWriter::create(&existing, vec!["agent".into()]).is_err());
    assert_eq!(fs::read_dir(&existing).unwrap().count(), 0);
}

#[test]
fn a_trace_that_is_not_finalized_cannot_be_claimed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("live.atrace");
    let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "premier", serde_json::json!({}))
        .unwrap();

    let error = claim_local_trace(&root, "team-a").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("only a finalized trace may be claimed"),
        "{error:#}"
    );
    assert_eq!(read_manifest(&root).unwrap().tenant_id, "local");

    // Once its recorder has finalized it, the claim holds.
    writer.finish(0).unwrap();
    claim_local_trace(&root, "team-a").unwrap();
    assert_eq!(verify(&root).unwrap().tenant_id, "team-a");
}

#[test]
fn a_later_format_version_is_reported_as_such_whatever_its_manifest_looks_like() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("future.atrace");
    fs::create_dir_all(&root).unwrap();
    // A shape this build could not decode: `command` is no longer a list.
    fs::write(
        root.join("manifest.json"),
        r#"{"format_version": 3, "trace_id": "t", "command": "agent run", "layout": {"shards": 4}}"#,
    )
    .unwrap();

    let error = read_manifest(&root).unwrap_err();

    let unsupported = error.downcast_ref::<UnsupportedFormatVersion>().unwrap();
    assert_eq!(unsupported.found, 3);
    assert!(unsupported.is_newer());
    assert!(
        error.to_string().contains("a newer premier is needed"),
        "{error:#}"
    );
    assert_eq!(premier_trace::declared_format_version(&root), Some(3));
}

#[test]
fn manifest_fields_this_build_does_not_know_survive_a_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("extended.atrace");
    abandoned(
        &root,
        &[("session.start", "premier", serde_json::json!({}))],
    );
    // A later build of the same format version recorded two more fields.
    let path = root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["retention"] = serde_json::json!({"days": 30});
    manifest["labels"] = serde_json::json!(["nightly"]);
    fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    // Recovery, then a claim: two commands that rewrite the manifest.
    recover_interrupted_trace_with(&root, force(), None).unwrap();
    claim_local_trace(&root, "team-a").unwrap();

    let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored["retention"], serde_json::json!({"days": 30}));
    assert_eq!(stored["labels"], serde_json::json!(["nightly"]));
    assert_eq!(stored["tenant_id"], "team-a");
    // They are sealed like every other field.
    verify(&root).unwrap();
    let mut edited = stored.clone();
    edited["retention"]["days"] = 3650.into();
    fs::write(&path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    assert!(verify(&root).is_err());
}

fn event(sequence: u64, kind: &str, actor: &str) -> TraceEvent {
    TraceEvent {
        event_id: format!("event-{sequence}"),
        trace_id: "trace".into(),
        sequence,
        kind: kind.into(),
        actor_id: actor.into(),
        status: "ok".into(),
        payload_json: "{}".into(),
        ..TraceEvent::default()
    }
}

fn codes(diagnostics: &[TraceDiagnostic]) -> Vec<(&str, Option<u64>)> {
    diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.sequence))
        .collect()
}

#[test]
fn a_synthesized_decision_needs_no_request_but_a_recorded_one_does() {
    let synthesized = TraceEvent {
        status: "denied".into(),
        payload_json: r#"{"synthesized": true, "synthesized_from": "permission_denials"}"#.into(),
        ..event(1, "approval.decision", "agent")
    };
    let recorded = TraceEvent {
        status: "denied".into(),
        ..event(2, "approval.decision", "agent")
    };

    let diagnostics = validate_events(&[synthesized, recorded]);

    assert_eq!(codes(&diagnostics), [("missing_lifecycle_start", Some(2))]);
}

#[test]
fn each_finish_is_paired_with_the_start_it_names() {
    // Two calls by one actor, without correlation ids, each result naming
    // its invocation as its parent.
    let mut events = Vec::new();
    for (sequence, kind) in [
        (1, "tool.invocation"),
        (2, "tool.result"),
        (3, "tool.invocation"),
        (4, "tool.result"),
    ] {
        let mut next = event(sequence, kind, "coder");
        if kind == "tool.result" {
            next.parent_event_id = format!("event-{}", sequence - 1);
        }
        events.push(next);
    }
    assert_eq!(codes(&validate_events(&events)), []);

    // Overlapping calls: the results arrive in the order the calls started.
    let mut overlapping = vec![
        event(1, "tool.invocation", "coder"),
        event(2, "tool.invocation", "coder"),
        event(3, "tool.result", "coder"),
        event(4, "tool.result", "coder"),
    ];
    overlapping[2].links = vec!["event-1".into()];
    overlapping[3].parent_event_id = "event-2".into();
    assert_eq!(codes(&validate_events(&overlapping)), []);

    // Sequential calls paired by actor alone are closed one by one.
    let by_actor: Vec<_> = [
        (1, "approval.request"),
        (2, "approval.decision"),
        (3, "approval.request"),
        (4, "approval.decision"),
        (5, "approval.request"),
    ]
    .into_iter()
    .map(|(sequence, kind)| event(sequence, kind, "reviewer"))
    .collect();
    // Nothing but the actor ties them together, which is still reported;
    // only the third request is left open.
    assert_eq!(
        codes(&validate_events(&by_actor)),
        [
            ("missing_causal_link", Some(2)),
            ("missing_causal_link", Some(4)),
            ("missing_lifecycle_finish", Some(5)),
        ]
    );
}

#[test]
fn a_finish_recorded_before_its_start_is_not_paired_with_it() {
    let events = [
        event(1, "approval.decision", "reviewer"),
        event(2, "approval.request", "reviewer"),
    ];
    assert_eq!(
        codes(&validate_events(&events)),
        [
            ("missing_lifecycle_start", Some(1)),
            ("missing_lifecycle_finish", Some(2)),
        ]
    );
}

#[test]
fn a_status_is_judged_without_its_surrounding_whitespace() {
    let padded = TraceEvent {
        status: " ok ".into(),
        ..event(1, "tool.execution", "coder")
    };
    assert_eq!(codes(&validate_events(&[padded])), []);
    let unknown = TraceEvent {
        status: " sideways ".into(),
        ..event(1, "tool.execution", "coder")
    };
    assert_eq!(
        codes(&validate_events(&[unknown])),
        [("invalid_status", Some(1))]
    );
}

#[test]
fn reported_diagnostics_are_recomputed_and_keep_what_only_the_recorder_knew() {
    let warning = |code: &str| TraceDiagnostic {
        severity: premier_trace::DiagnosticSeverity::Warning,
        code: code.into(),
        message: code.into(),
        event_id: None,
        sequence: None,
    };
    let stored = [
        warning("missing_lifecycle_finish"),
        warning("journal.write_failed"),
        warning("journal.recovery_discarded"),
    ];

    let reported = current_diagnostics(&stored, vec![warning("missing_causal_link")]);

    assert_eq!(
        reported
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>(),
        [
            "missing_causal_link",
            "journal.write_failed",
            "journal.recovery_discarded"
        ]
    );
}

fn key() -> EncryptionKey {
    EncryptionKey::from_hex(&"3c".repeat(32)).unwrap()
}

fn encrypt_work_dirs(parent: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".encrypt-"))
        .collect();
    names.sort();
    names
}

#[test]
fn encrypt_restores_a_trace_stranded_by_an_interrupted_swap() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stranded.atrace");
    finalized(&root);
    let trace_id = read_manifest(&root).unwrap().trace_id;
    // Killed between the two renames: the trace sits under its backup name
    // and nothing is at its own path. An unfinished copy lies beside it.
    fs::rename(
        &root,
        temp.path().join(".stranded.atrace.encrypt-0001.backup"),
    )
    .unwrap();
    fs::create_dir(temp.path().join(".stranded.atrace.encrypt-0001.tmp")).unwrap();

    reencrypt_finalized_trace_with_signing_key(&root, key(), None).unwrap();

    let manifest = read_manifest_with_key(&root, &key()).unwrap();
    assert_eq!(manifest.trace_id, trace_id);
    assert!(manifest.encryption.is_some());
    assert_eq!(encrypt_work_dirs(temp.path()), Vec::<String>::new());
}

#[test]
fn encrypt_removes_the_previous_copy_an_interrupted_run_left_beside_the_trace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("swapped.atrace");
    finalized(&root);
    // Killed after the swap, before the previous (plaintext) copy was removed.
    let stale = temp.path().join(".swapped.atrace.encrypt-0001.backup");
    copy_dir(&root, &stale);

    reencrypt_finalized_trace_with_signing_key(&root, key(), None).unwrap();

    assert!(!stale.exists(), "the plaintext copy must not survive");
    assert_eq!(encrypt_work_dirs(temp.path()), Vec::<String>::new());
}

#[test]
fn encrypt_does_not_delete_a_backup_of_some_other_trace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("reused.atrace");
    let other = temp.path().join("other.atrace");
    finalized(&root);
    finalized(&other);
    // The path was reused for a new recording after an interrupted encrypt:
    // the backup holds a different trace, and is its only copy.
    let backup = temp.path().join(".reused.atrace.encrypt-0001.backup");
    fs::rename(&other, &backup).unwrap();

    let error = reencrypt_finalized_trace_with_signing_key(&root, key(), None).unwrap_err();

    assert!(error.to_string().contains("is not a copy"), "{error:#}");
    assert!(backup.join("manifest.json").exists());
    assert!(read_manifest(&root).unwrap().encryption.is_none());
}

#[test]
fn invalid_utf8_is_replaced_and_counted() {
    let mut pending = Vec::new();
    let (text, replaced) = decode_utf8_chunk_lossy(&mut pending, b"ok \xff\xfe end \xe2\x82");
    assert_eq!(text, "ok \u{fffd}\u{fffd} end ");
    assert_eq!(replaced, 2);
    // The held prefix of a euro sign is completed by the next chunk.
    let (text, replaced) = decode_utf8_chunk_lossy(&mut pending, b"\xac");
    assert_eq!((text.as_str(), replaced), ("\u{20ac}", 0));
    // A genuine U+FFFD in the stream is not a replacement.
    let (text, replaced) = decode_utf8_chunk_lossy(&mut pending, "\u{fffd}".as_bytes());
    assert_eq!((text.as_str(), replaced), ("\u{fffd}", 0));
    // A sequence the stream ends inside is.
    let (_, replaced) = decode_utf8_chunk_lossy(&mut pending, b"\xe2\x82");
    assert_eq!(replaced, 0);
    assert_eq!(finish_utf8_lossy(&mut pending), ("\u{fffd}".to_owned(), 1));
}

#[test]
fn random_secrets_are_256_bits_of_hex_and_differ() {
    let first = random_secret_hex().unwrap();
    let second = random_secret_hex().unwrap();
    assert_eq!(first.len(), 64);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first, second);
    // It is a valid trace key.
    EncryptionKey::from_hex(&first).unwrap();
}
