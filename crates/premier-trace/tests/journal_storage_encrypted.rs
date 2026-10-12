//! Recovery of an encrypted active journal. Kept in its own test binary: the
//! trace key is configured once per process.

use premier_trace::{
    ACTIVE_JOURNAL, EncryptionKey, RecoveryOptions, RedactionConfig, TraceWriter,
    build_journal_index, read_events, read_events_page_indexed, recover_interrupted_trace_with,
    verify,
};
use std::fs;
use std::sync::OnceLock;

/// The process-wide trace key, configured on first use and shared by every
/// test in this binary.
fn configured_key() -> EncryptionKey {
    static KEY_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    KEY_DIR.get_or_init(|| {
        let directory = tempfile::tempdir().unwrap();
        let key_file = directory.path().join("trace.key");
        fs::write(&key_file, "5a".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        premier_trace::set_key_file(&key_file);
        directory
    });
    EncryptionKey::from_hex(&"5a".repeat(32)).unwrap()
}

#[test]
fn encrypted_active_journals_recover_their_valid_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("encrypted.atrace");
    let key = configured_key();
    let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
        &root,
        vec!["agent".into()],
        None,
        "local",
        RedactionConfig::default(),
        key,
    )
    .unwrap();
    let recorded = (0..6)
        .map(|index| {
            writer
                .append("custom.step", "test", serde_json::json!({"index": index}))
                .unwrap()
        })
        .collect::<Vec<_>>();
    drop(writer);
    let active = root.join("events").join(ACTIVE_JOURNAL);
    let mut bytes = fs::read(&active).unwrap();
    let mut offsets = Vec::new();
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        offsets.push(offset);
        offset += 4 + u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    }
    // Ciphertext of the fourth event: it no longer authenticates.
    bytes[offsets[3] + 40] ^= 0x01;
    fs::write(&active, &bytes).unwrap();

    let report = recover_interrupted_trace_with(
        &root,
        RecoveryOptions {
            force: true,
            ..RecoveryOptions::default()
        },
        None,
    )
    .unwrap();

    assert_eq!(report.salvaged_events, 3);
    assert_eq!(report.discarded_bytes, (bytes.len() - offsets[3]) as u64);
    assert_eq!(report.discarded_frames, Some(3));
    let seal = verify(&root).unwrap().seal.unwrap();
    assert!(seal.recovered);
    assert_eq!(seal.discarded_frames, Some(3));
    let events = read_events(&root).unwrap();
    assert_eq!(events[..3], recorded[..3]);
    assert_eq!(events[3].kind, "session.interrupted");

    let index = build_journal_index(&root).unwrap();
    assert_eq!(
        read_events_page_indexed(&root, &index, 2, 10).unwrap(),
        events[2..]
    );
}

/// Recovery of an encrypted trace keeps the exit status its recorder
/// journaled, can be repeated, and leaves a trace that verifies.
#[test]
fn encrypted_recovery_keeps_the_journaled_exit_and_is_repeatable() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("encrypted-exit.atrace");
    let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
        &root,
        vec!["agent".into()],
        None,
        "local",
        RedactionConfig::default(),
        configured_key(),
    )
    .unwrap();
    writer
        .append("session.start", "premier", serde_json::json!({}))
        .unwrap();
    writer
        .append(
            "process.exit",
            "command",
            serde_json::json!({"exit_code": 7, "success": false, "termination": "exit"}),
        )
        .unwrap();
    drop(writer);
    let force = || RecoveryOptions {
        force: true,
        ..RecoveryOptions::default()
    };

    let report = recover_interrupted_trace_with(&root, force(), None).unwrap();

    assert!(report.journaled_exit);
    assert_eq!(report.manifest.exit_code, Some(7));
    let manifest = verify(&root).unwrap();
    assert_eq!(manifest.exit_code, Some(7));
    assert!(manifest.seal.unwrap().recovered);
    let events = read_events(&root).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].kind, "session.interrupted");
    assert_eq!(events[2].payload()["exit_recorded"], true);
    // Nothing is left to do, and nothing is rewritten.
    let error = recover_interrupted_trace_with(&root, force(), None).unwrap_err();
    assert!(error.to_string().contains("already finalized"), "{error:#}");
    assert_eq!(read_events(&root).unwrap(), events);
}
