//! Storage hardening seen through the CLI and the viewer API: recovery of
//! damaged journals, `verify --live`, truncated journals, key rotation,
//! streamed exports, and paged reads that resume inside the journal.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use premier_cli::evidence::{RedactionOptions, portable_evidence_with, write_portable_evidence};
use premier_cli::{AuthPolicy, app};
use premier_trace::{
    ACTIVE_JOURNAL, EncryptionKey, FINAL_JOURNAL, RedactionConfig, TraceEvent, TraceWriter,
    read_events, read_events_with_key, read_manifest, read_manifest_with_key, stream_events,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tower::ServiceExt;

fn premier() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_premier"));
    command
        .env_remove(premier_trace::KEY_FILE_ENV)
        .env_remove(premier_trace::SIGN_KEY_FILE_ENV);
    command
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", stderr(output));
}

fn private_file(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn keygen(directory: &Path) -> (PathBuf, String) {
    let key = directory.join("sign.key");
    assert_success(&premier().arg("keygen").arg(&key).output().unwrap());
    let public = std::fs::read_to_string(directory.join("sign.key.pub")).unwrap();
    (key, public.trim().to_owned())
}

/// An unfinalized trace with `count` events, as a killed recorder leaves it.
fn abandoned(path: &Path, count: usize) -> Vec<TraceEvent> {
    let mut writer = TraceWriter::create(path, vec!["agent".into()]).unwrap();
    let events = (0..count)
        .map(|index| {
            writer
                .append("custom.step", "test", serde_json::json!({"index": index}))
                .unwrap()
        })
        .collect();
    drop(writer);
    events
}

fn finalized(path: &Path, count: usize, text_bytes: usize) {
    let mut writer = TraceWriter::create(path, vec!["agent".into()]).unwrap();
    for index in 0..count {
        writer
            .append(
                "process.stdout",
                "test",
                serde_json::json!({"text": format!("{index:06} ").repeat(text_bytes / 7 + 1)}),
            )
            .unwrap();
    }
    writer.finish(0).unwrap();
}

fn append(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
fn recover_salvages_a_padded_journal_reports_the_loss_and_signs_with_a_key() {
    let temp = tempfile::tempdir().unwrap();
    let (key, public) = keygen(temp.path());
    let trace = temp.path().join("padded.atrace");
    let recorded = abandoned(&trace, 3);
    append(&trace.join("events").join(ACTIVE_JOURNAL), &[0_u8; 4096]);

    let output = premier()
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .arg("--sign-key")
        .arg(&key)
        .output()
        .unwrap();

    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("(4 events, exit 130)"), "{text}");
    assert!(text.contains("kept 3 recorded event(s)"), "{text}");
    assert!(
        text.contains("discarded 4096 byte(s) (an unknown number of frames) after sequence 3: zero-length event frame"),
        "{text}"
    );
    assert!(
        text.contains("signed the recovered trace with key sha256:"),
        "{text}"
    );
    let seal = read_manifest(&trace).unwrap().seal.unwrap();
    assert!(seal.recovered);
    assert_eq!(seal.discarded_bytes, 4096);
    assert!(seal.signature.is_some());
    assert_success(
        &premier()
            .arg("verify")
            .arg(&trace)
            .args(["--public-key", &public])
            .output()
            .unwrap(),
    );
    let events = read_events(&trace).unwrap();
    assert_eq!(events[..3], recorded[..]);
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|event| !event.kind.is_empty()));
}

#[test]
fn recover_salvages_the_prefix_before_a_corrupt_frame() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("corrupt.atrace");
    let recorded = abandoned(&trace, 9);
    let active = trace.join("events").join(ACTIVE_JOURNAL);
    let mut bytes = std::fs::read(&active).unwrap();
    // The first tag byte of the sixth frame.
    let mut offset = 0;
    for _ in 0..5 {
        offset += 4 + u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    }
    bytes[offset + 4] = 0xff;
    std::fs::write(&active, &bytes).unwrap();

    let output = premier()
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();

    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("kept 5 recorded event(s)"), "{text}");
    assert!(
        text.contains(&format!(
            "discarded {} byte(s) (4 frame(s)) after sequence 5",
            bytes.len() - offset
        )),
        "{text}"
    );
    assert!(!text.contains("signed"), "{text}");
    assert_success(&premier().arg("verify").arg(&trace).output().unwrap());
    let events = read_events(&trace).unwrap();
    assert_eq!(events[..5], recorded[..5]);
    assert_eq!(events[5].kind, "session.interrupted");
    assert_eq!(events.len(), 6);
}

#[test]
fn verify_live_checks_an_unfinalized_journal_and_changes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("live.atrace");
    abandoned(&trace, 4);
    let active = trace.join("events").join(ACTIVE_JOURNAL);
    append(&active, &[200, 0, 0, 0, 1, 2, 3]);
    let journal = std::fs::read(&active).unwrap();
    let manifest = std::fs::read(trace.join("manifest.json")).unwrap();

    let plain = premier().arg("verify").arg(&trace).output().unwrap();
    assert!(!plain.status.success());
    let text = stderr(&plain);
    assert!(text.contains("trace is not finalized"), "{text}");
    assert!(text.contains("premier verify --live"), "{text}");

    let live = premier()
        .arg("verify")
        .arg("--live")
        .arg(&trace)
        .output()
        .unwrap();
    assert_success(&live);
    let text = stdout(&live);
    assert!(
        text.starts_with("live: frames and hash chain valid up to the last complete frame:"),
        "{text}"
    );
    assert!(text.contains("(4 events, not finalized"), "{text}");
    assert!(
        text.contains("the last 7 byte(s) are an incomplete frame"),
        "{text}"
    );
    assert_eq!(std::fs::read(&active).unwrap(), journal);
    assert_eq!(
        std::fs::read(trace.join("manifest.json")).unwrap(),
        manifest
    );
    assert!(!trace.join("events").join(FINAL_JOURNAL).exists());

    // A frame that does not chain is reported, with the count that is valid.
    let mut edited = journal[..journal.len() - 7].to_vec();
    let position = edited
        .windows(9)
        .rposition(|run| run == b"\"index\":2")
        .unwrap();
    edited[position + 8] = b'7';
    std::fs::write(&active, &edited).unwrap();
    let broken = premier()
        .arg("verify")
        .arg("--live")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(!broken.status.success());
    let text = stderr(&broken);
    assert!(text.contains("invalid: the active journal"), "{text}");
    assert!(text.contains("after 3 valid event(s)"), "{text}");
    assert!(
        text.contains("event chain is broken at sequence 4"),
        "{text}"
    );
    assert_eq!(std::fs::read(&active).unwrap(), edited);
}

#[test]
fn verify_live_on_a_finalized_trace_is_an_ordinary_verification() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("final.atrace");
    finalized(&trace, 3, 20);

    let output = premier()
        .arg("verify")
        .arg("--live")
        .arg(&trace)
        .output()
        .unwrap();

    assert_success(&output);
    assert!(
        stdout(&output).starts_with("consistent: chain and seal valid, unsigned:"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_truncated_finalized_journal_fails_every_command_that_reads_events() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("truncated.atrace");
    let intact = temp.path().join("intact.atrace");
    finalized(&trace, 200, 20);
    finalized(&intact, 3, 20);
    let journal = trace.join("events").join(FINAL_JOURNAL);
    let bytes = std::fs::read(&journal).unwrap();
    std::fs::write(&journal, &bytes[..bytes.len() - 20]).unwrap();
    let export = temp.path().join("export.json");

    let commands: Vec<Vec<&std::ffi::OsStr>> = vec![
        vec!["query".as_ref(), trace.as_ref()],
        vec!["query".as_ref(), trace.as_ref(), "--json".as_ref()],
        vec!["replay".as_ref(), trace.as_ref(), "--no-sleep".as_ref()],
        vec!["export".as_ref(), trace.as_ref()],
        vec![
            "export".as_ref(),
            trace.as_ref(),
            "--output".as_ref(),
            export.as_ref(),
        ],
        vec!["diff".as_ref(), trace.as_ref(), intact.as_ref()],
        vec!["diff".as_ref(), intact.as_ref(), trace.as_ref()],
    ];
    for arguments in commands {
        // Verification refuses it outright.
        let refused = premier().args(&arguments).output().unwrap();
        assert!(!refused.status.success(), "{arguments:?}");
        assert!(
            stderr(&refused).contains("journal digest mismatch"),
            "{arguments:?}: {}",
            stderr(&refused)
        );
        // Reading it anyway still ends in an error, never in a short result.
        let forced = premier()
            .args(&arguments)
            .arg("--allow-unverified")
            .output()
            .unwrap();
        assert!(!forced.status.success(), "{arguments:?}");
        assert!(
            stderr(&forced).contains("journal is truncated"),
            "{arguments:?}: {}",
            stderr(&forced)
        );
    }
    assert!(!export.exists());
    assert!(
        std::fs::read_dir(temp.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")),
        "a partial export was left behind"
    );
}

#[cfg(unix)]
#[test]
fn encrypt_rotates_an_encrypted_trace_to_a_new_key() {
    let temp = tempfile::tempdir().unwrap();
    let (sign_key, public) = keygen(temp.path());
    let old_key_file = temp.path().join("old.key");
    let new_key_file = temp.path().join("new.key");
    private_file(&old_key_file, &"3c".repeat(32));
    private_file(&new_key_file, &"4d".repeat(32));
    let old_key = EncryptionKey::from_hex(&"3c".repeat(32)).unwrap();
    let new_key = EncryptionKey::from_hex(&"4d".repeat(32)).unwrap();
    let trace = temp.path().join("rotated.atrace");
    let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
        &trace,
        vec!["agent".into(), "run".into()],
        Some("rotation".into()),
        "local",
        RedactionConfig::default(),
        old_key.clone(),
    )
    .unwrap();
    for index in 0..40 {
        writer
            .append(
                "agent.message",
                "test",
                serde_json::json!({"private": format!("evidence {index}")}),
            )
            .unwrap();
    }
    writer.finish(0).unwrap();
    assert_success(
        &premier()
            .env(premier_trace::KEY_FILE_ENV, &old_key_file)
            .arg("sign")
            .arg(&trace)
            .arg("--sign-key")
            .arg(&sign_key)
            .output()
            .unwrap(),
    );
    let before_manifest = read_manifest_with_key(&trace, &old_key).unwrap();
    let before_events = read_events_with_key(&trace, &old_key).unwrap();
    let before_seal = before_manifest.seal.clone().unwrap();

    // Without the old key the trace cannot be rotated, and is left alone.
    let locked = premier()
        .arg("encrypt")
        .arg(&trace)
        .arg("--new-key-file")
        .arg(&new_key_file)
        .output()
        .unwrap();
    assert!(!locked.status.success());
    assert_eq!(
        read_events_with_key(&trace, &old_key).unwrap(),
        before_events
    );

    let rotated = premier()
        .env(premier_trace::KEY_FILE_ENV, &old_key_file)
        .arg("encrypt")
        .arg(&trace)
        .arg("--new-key-file")
        .arg(&new_key_file)
        .arg("--sign-key")
        .arg(&sign_key)
        .output()
        .unwrap();
    assert_success(&rotated);
    assert!(
        stdout(&rotated).contains("re-sealed and signed with the configured signing key"),
        "{}",
        stdout(&rotated)
    );

    // The old key no longer opens it; the new one does, to the same events.
    assert!(read_manifest_with_key(&trace, &old_key).is_err());
    let stale = premier()
        .env(premier_trace::KEY_FILE_ENV, &old_key_file)
        .arg("verify")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(stderr(&stale).contains("wrong key"), "{}", stderr(&stale));
    let after_manifest = read_manifest_with_key(&trace, &new_key).unwrap();
    assert_eq!(
        read_events_with_key(&trace, &new_key).unwrap(),
        before_events
    );
    assert_eq!(after_manifest.trace_id, before_manifest.trace_id);
    assert_eq!(after_manifest.name, before_manifest.name);
    assert_eq!(after_manifest.command, before_manifest.command);
    assert_eq!(
        after_manifest.encryption.as_ref().unwrap().key_id,
        new_key.key_id()
    );
    let after_seal = after_manifest.seal.unwrap();
    assert_eq!(after_seal.chain_head, before_seal.chain_head);
    assert_eq!(after_seal.event_count, before_seal.event_count);
    assert_ne!(after_seal.digest, before_seal.digest);
    let verified = premier()
        .env(premier_trace::KEY_FILE_ENV, &new_key_file)
        .arg("verify")
        .arg(&trace)
        .args(["--public-key", &public])
        .output()
        .unwrap();
    assert_success(&verified);
    assert!(
        stdout(&verified).starts_with("verified:"),
        "{}",
        stdout(&verified)
    );
    // No ciphertext under the old key, and no staging directory, is left.
    let leftovers = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".encrypt-"))
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // Rotating again without a signing key drops the signature and says so.
    let third_key_file = temp.path().join("third.key");
    private_file(&third_key_file, &"5e".repeat(32));
    let unsigned = premier()
        .env(premier_trace::KEY_FILE_ENV, &new_key_file)
        .arg("encrypt")
        .arg(&trace)
        .arg("--new-key-file")
        .arg(&third_key_file)
        .output()
        .unwrap();
    assert_success(&unsigned);
    assert!(
        stdout(&unsigned).contains("previous signature covered the old manifest and was dropped"),
        "{}",
        stdout(&unsigned)
    );
    assert_success(
        &premier()
            .env(premier_trace::KEY_FILE_ENV, &third_key_file)
            .arg("verify")
            .arg(&trace)
            .output()
            .unwrap(),
    );
}

#[test]
fn a_streamed_export_is_the_document_built_in_memory() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("export.atrace");
    let mut writer = TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    writer
        .append(
            "tool.invocation",
            "test",
            serde_json::json!({"input": {"api_key": "hunter2", "path": "/tmp/x"}}),
        )
        .unwrap();
    writer
        .append(
            "process.stdout",
            "test",
            serde_json::json!({"text": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\n"}),
        )
        .unwrap();
    // Shapes only the shared redactor handles: a JSON object on a line of its
    // own inside terminal text, and a credential in a URL query.
    writer
        .append(
            "process.stdout",
            "test",
            serde_json::json!({"text": "starting\n{\"type\":\"login\",\"password\":\"line-secret\",\"user\":\"sam\"}\n"}),
        )
        .unwrap();
    writer
        .append(
            "tool.result",
            "test",
            serde_json::json!({"note": "fetched https://api.host.test/cb?access_token=query-secret-0123456789&page=2"}),
        )
        .unwrap();
    writer.finish(0).unwrap();
    let manifest = read_manifest(&trace).unwrap();
    let options = RedactionOptions {
        default_secret_patterns: true,
        known_secrets_in_terminal: true,
    };

    let mut expected = serde_json::to_vec_pretty(&portable_evidence_with(
        &manifest,
        &read_events(&trace).unwrap(),
        options,
    ))
    .unwrap();
    let mut streamed = Vec::new();
    let counts = write_portable_evidence(
        &mut streamed,
        &manifest,
        stream_events(&trace).unwrap(),
        options,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(streamed.clone()).unwrap(),
        String::from_utf8(expected.clone()).unwrap()
    );
    // Removed by this export: the header value and the JSON line's field,
    // both in terminal text. Removed when recorded: the field value and the
    // URL query credential.
    assert_eq!(counts.total, 2, "{counts:?}");
    assert_eq!(counts.field_names, 1, "{counts:?}");
    assert_eq!(counts.value_patterns["authorization-header"], 1);
    assert_eq!(counts.already_redacted, 2, "{counts:?}");

    // The CLI writes that document, to a file and to stdout alike.
    expected.push(b'\n');
    let file = temp.path().join("export.json");
    let to_file = premier()
        .arg("export")
        .arg(&trace)
        .arg("--redact-known-secrets")
        .arg("--output")
        .arg(&file)
        .output()
        .unwrap();
    assert_success(&to_file);
    assert!(
        stdout(&to_file).contains(&format!(
            "({} value(s) redacted by this export",
            counts.total
        )),
        "{}",
        stdout(&to_file)
    );
    assert_eq!(std::fs::read(&file).unwrap(), expected);
    let to_stdout = premier()
        .arg("export")
        .arg(&trace)
        .arg("--redact-known-secrets")
        .output()
        .unwrap();
    assert_success(&to_stdout);
    assert_eq!(to_stdout.stdout, expected);
    let document: serde_json::Value = serde_json::from_slice(&expected).unwrap();
    assert_eq!(document["events"].as_array().unwrap().len(), 4);
    assert_eq!(
        document["redaction"]["redacted"],
        serde_json::to_value(&counts).unwrap()
    );
    let text = String::from_utf8_lossy(&expected);
    for secret in [
        "hunter2",
        "abcdefghijklmnopqrstuvwxyz012345",
        "line-secret",
        "query-secret-0123456789",
    ] {
        assert!(!text.contains(secret), "{secret} exported");
    }
    assert_eq!(
        document["events"][2]["payload"]["text"],
        "starting\n{\"password\":\"[REDACTED]\",\"type\":\"login\",\"user\":\"sam\"}\n"
    );
    // `source` leads and `redaction` follows the events it counts.
    let keys: Vec<_> = document.as_object().unwrap().keys().cloned().collect();
    let position = |key: &str| text.find(&format!("\n  \"{key}\":")).unwrap();
    assert_eq!(keys.len(), 5, "{keys:?}");
    assert!(position("format") < position("source"));
    assert!(position("source") < position("manifest"));
    assert!(position("manifest") < position("events"));
    assert!(position("events") < position("redaction"));
}

fn viewer_dir(root: &Path) -> PathBuf {
    let viewer = root.join("viewer");
    std::fs::create_dir_all(&viewer).unwrap();
    std::fs::write(viewer.join("index.html"), "viewer").unwrap();
    viewer
}

async fn get_json(app: &axum::Router, uri: String) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn paged_event_reads_over_a_large_journal_return_every_event_once() {
    let temp = tempfile::tempdir().unwrap();
    let trace_dir = temp.path().join("traces");
    let trace = trace_dir.join("large.atrace");
    // Several megabytes, so the journal has resume points to page from.
    finalized(&trace, 2_500, 1_400);
    let trace_id = read_manifest(&trace).unwrap().trace_id;
    let all = serde_json::to_value(read_events(&trace).unwrap()).unwrap();
    let all = all.as_array().unwrap();
    assert!(
        premier_trace::build_journal_index(&trace)
            .unwrap()
            .resume_points()
            > 2
    );
    let app = app(
        trace_dir,
        Some(viewer_dir(temp.path())),
        AuthPolicy::default(),
    );

    // Before and after the server has verified (and indexed) the trace.
    for round in 0..2 {
        let mut after = 0;
        let mut loaded = Vec::new();
        loop {
            let page = get_json(
                &app,
                format!("/api/traces/{trace_id}/events?after_sequence={after}&limit=400"),
            )
            .await;
            let page = page.as_array().unwrap().clone();
            let Some(last) = page.last() else { break };
            assert!(page.len() <= 400);
            after = last["sequence"].as_u64().unwrap();
            loaded.extend(page);
        }
        assert_eq!(&loaded, all, "round {round}");
        let detail = get_json(&app, format!("/api/traces/{trace_id}")).await;
        assert_eq!(detail["integrity"], "verified");
    }
    let tail = get_json(
        &app,
        format!("/api/traces/{trace_id}/events?after_sequence=2490&limit=400"),
    )
    .await;
    assert_eq!(tail.as_array().unwrap()[..], all[2490..]);
    let everything = get_json(&app, format!("/api/traces/{trace_id}/events")).await;
    assert_eq!(everything.as_array().unwrap(), all);
}

#[tokio::test]
async fn a_live_stream_resumed_after_a_sequence_sends_each_later_event_once() {
    let temp = tempfile::tempdir().unwrap();
    let trace_dir = temp.path().join("traces");
    let trace = trace_dir.join("live.atrace");
    let mut writer = TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    let trace_id = writer.trace_id().to_owned();
    // A lease naming this process: the recording is live, not abandoned.
    std::fs::write(
        trace.join(premier_trace::RECORDER_LEASE),
        premier_cli::liveness::lease_contents(),
    )
    .unwrap();
    // More than one stream batch, so the tail is read in several steps.
    let mut recorded = Vec::new();
    for index in 0..1_300 {
        recorded.push(
            writer
                .append("custom.step", "test", serde_json::json!({"index": index}))
                .unwrap(),
        );
    }
    let app = app(
        trace_dir,
        Some(viewer_dir(temp.path())),
        AuthPolicy::default(),
    );
    let finisher = tokio::task::spawn_blocking(move || {
        std::thread::sleep(std::time::Duration::from_millis(700));
        let last = writer
            .append("custom.step", "test", serde_json::json!({"index": "last"}))
            .unwrap();
        writer.finish(0).unwrap();
        last
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/traces/{trace_id}/stream?after_sequence=1200"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    recorded.push(finisher.await.unwrap());

    assert_eq!(text.matches("event: trace.event").count(), 101, "{text}");
    for event in &recorded[..1_200] {
        assert!(
            !text.contains(&event.event_id),
            "replayed {}",
            event.sequence
        );
    }
    for event in &recorded[1_200..] {
        assert_eq!(
            text.matches(&event.event_id).count(),
            1,
            "sequence {}",
            event.sequence
        );
    }
    assert_eq!(text.matches("event: trace.complete").count(), 1);
}
