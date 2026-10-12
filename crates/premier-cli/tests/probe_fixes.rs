//! Regression tests for defects found by runtime probes: collector input
//! validation, timestamps, half-open collector connections, export privacy,
//! terminal-safe text output, broken pipes, and encryption discoverability.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use premier_trace::{EncryptionKey, EventInput, TraceWriter, read_events};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::ServiceExt;

const KEY_HEX: &str = "7171717171717171717171717171717171717171717171717171717171717171";

fn premier() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_premier"));
    command.env_remove("PREMIER_TRACE_KEY_FILE");
    command
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write_key_file(dir: &Path) -> PathBuf {
    let key_file = dir.join("trace.key");
    std::fs::write(&key_file, KEY_HEX).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    key_file
}

/// A finalized trace holding `inputs`, written by the library directly so the
/// fields are stored exactly as given.
fn trace_with(path: &Path, name: &str, inputs: Vec<EventInput>) {
    let mut writer =
        TraceWriter::create_named(path, vec!["agent".into()], Some(name.to_owned())).unwrap();
    for input in inputs {
        writer.append_input(input).unwrap();
    }
    writer.finish(0).unwrap();
}

fn encrypted_trace(path: &Path, name: &str) {
    trace_with(
        path,
        name,
        vec![EventInput {
            kind: "agent.result".into(),
            actor_id: "coordinator".into(),
            payload: serde_json::json!({"private": "top-secret-evidence"}),
            ..EventInput::default()
        }],
    );
    premier_trace::reencrypt_finalized_trace(path, EncryptionKey::from_hex(KEY_HEX).unwrap())
        .unwrap();
}

struct Collector {
    app: axum::Router,
    writer: Arc<Mutex<TraceWriter>>,
    root: PathBuf,
    _temp: tempfile::TempDir,
}

impl Collector {
    fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("collector.atrace");
        let writer = Arc::new(Mutex::new(
            TraceWriter::create(&root, vec!["agent".into()]).unwrap(),
        ));
        Self {
            app: premier_cli::instrumentation_app(writer.clone(), "collector-secret".into()),
            writer,
            root,
            _temp: temp,
        }
    }

    async fn post_raw(&self, body: Vec<u8>) -> (StatusCode, String) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer collector-secret")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn post(&self, body: serde_json::Value) -> (StatusCode, String) {
        self.post_raw(body.to_string().into_bytes()).await
    }

    fn finish(self) -> Vec<premier_trace::TraceEvent> {
        let Self {
            app, writer, root, ..
        } = self;
        drop(app);
        let Ok(writer) = Arc::try_unwrap(writer) else {
            panic!("collector still owns the trace writer");
        };
        writer.into_inner().unwrap().finish(0).unwrap();
        read_events(&root).unwrap()
    }
}

#[tokio::test]
async fn collector_rejects_lookalike_and_unprintable_identity_fields() {
    let collector = Collector::start();
    for forged in [
        // Zero-width space, fullwidth full stop, and a Cyrillic `о`: each
        // renders like the recorder's own `process.exit`.
        serde_json::json!({"kind": "process\u{200b}.exit", "payload": {"exit_code": 0}}),
        serde_json::json!({"kind": "process\u{ff0e}exit"}),
        serde_json::json!({"kind": "pr\u{043e}cess.exit"}),
        serde_json::json!({"kind": "tool.execution", "source": "premier\u{200b}"}),
        serde_json::json!({"kind": "tool.execution", "source": "c\u{043e}mmand"}),
        serde_json::json!({"kind": "tool.execution", "source": ""}),
        serde_json::json!({"kind": "tool.execution", "actor_type": "pro\u{0441}ess"}),
        serde_json::json!({"kind": "tool execution"}),
        serde_json::json!({"kind": "tool.execution\n"}),
        serde_json::json!({"kind": "k".repeat(500)}),
        serde_json::json!({"kind": ""}),
        serde_json::json!({"kind": "   "}),
        serde_json::json!({"kind": "tool.execution", "actor_id": "evil\u{1b}[31m"}),
        serde_json::json!({"kind": "tool.execution", "actor_id": "nul\u{0}"}),
        serde_json::json!({"kind": "tool.execution", "status": "ok\r\nforged line"}),
        serde_json::json!({"kind": "tool.execution", "span_id": "span\u{7}"}),
        serde_json::json!({"kind": "tool.execution", "parent_span_id": "a\tb"}),
        serde_json::json!({"kind": "tool.execution", "correlation_id": "c\u{9b}"}),
        serde_json::json!({"kind": "tool.execution", "span_id": "s".repeat(5_000)}),
    ] {
        let (status, body) = collector.post(forged.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{forged} -> {body}");
        assert!(body.contains("error"), "{forged} -> {body}");
    }
    for honest in [
        serde_json::json!({"kind": "agent.spawn", "actor_id": "researcher"}),
        serde_json::json!({"kind": "tool.execution", "source": "premier-sdk", "actor_type": "subagent"}),
        serde_json::json!({"kind": "custom:Kind_1-x", "actor_id": "Zoë (reviewer)", "status": "ok"}),
    ] {
        let (status, body) = collector.post(honest.clone()).await;
        assert_eq!(status, StatusCode::OK, "{honest} -> {body}");
    }
    assert_eq!(collector.finish().len(), 3);
}

#[tokio::test]
async fn collector_reports_an_oversize_body_as_payload_too_large() {
    let collector = Collector::start();
    let body = serde_json::json!({
        "kind": "tool.execution",
        "payload": {"blob": "x".repeat(3 * 1024 * 1024)},
    });
    let (status, _) = collector.post(body).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(collector.finish().is_empty());
}

#[tokio::test]
async fn collector_stamps_receipt_time_and_keeps_the_producer_timestamp_as_evidence() {
    let collector = Collector::start();
    for invalid in [
        serde_json::json!({"kind": "tool.execution", "timestamp": "not-a-date"}),
        serde_json::json!({"kind": "tool.execution", "timestamp": "2026-07-15 12:00:00"}),
        serde_json::json!({"kind": "tool.execution", "timestamp": "9".repeat(300 * 1024)}),
    ] {
        let (status, body) = collector.post(invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let before = chrono::Utc::now();
    for claimed in ["1999-01-01T00:00:00Z", "2999-01-01T00:00:00+02:00"] {
        let (status, body) = collector
            .post(serde_json::json!({
                "kind": "tool.execution",
                "timestamp": claimed,
                "payload": {"tool": "search"},
            }))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, _) = collector
        .post(serde_json::json!({"kind": "tool.execution", "timestamp": "2001-02-03T04:05:06Z"}))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a missing payload still keeps the claim"
    );
    let after = chrono::Utc::now();

    let events = collector.finish();
    assert_eq!(events.len(), 3);
    for (event, claimed) in events.iter().zip([
        "1999-01-01T00:00:00Z",
        "2999-01-01T00:00:00+02:00",
        "2001-02-03T04:05:06Z",
    ]) {
        let recorded = chrono::DateTime::parse_from_rfc3339(&event.timestamp).unwrap();
        assert!(
            recorded >= before - chrono::Duration::seconds(1)
                && recorded <= after + chrono::Duration::seconds(1),
            "event time must be the recorder's receipt time, got {}",
            event.timestamp
        );
        assert_eq!(event.payload()["producer_timestamp"], claimed);
    }
    assert_eq!(events[0].payload()["tool"], "search");
}

fn wait_bounded(
    child: &mut std::process::Child,
    limit: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn replay_never_sleeps_for_an_absurd_recorded_gap() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("gap.atrace");
    let at = |timestamp: &str| EventInput {
        kind: "agent.turn".into(),
        timestamp: Some(timestamp.into()),
        ..EventInput::default()
    };
    trace_with(
        &trace,
        "gap",
        vec![
            at("1999-01-01T00:00:00Z"),
            at("2026-07-15T12:00:00Z"),
            at("2999-01-01T00:00:00Z"),
        ],
    );
    // Even at 1000x, a 27-year gap would otherwise sleep for days.
    let mut child = premier()
        .arg("replay")
        .arg(&trace)
        .args(["--speed", "1000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_bounded(&mut child, Duration::from_secs(8))
        .expect("replay must not hang on a bad timestamp");
    assert!(status.success());
    let mut replayed = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut replayed).unwrap();
    assert_eq!(replayed.lines().count(), 3);
}

#[cfg(unix)]
#[test]
fn record_finalizes_while_a_collector_connection_is_left_half_open() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("half-open.atrace");
    let handoff = temp.path().join("collector");
    let release = temp.path().join("release");
    let script = format!(
        "printf '%s %s' \"$PREMIER_COLLECTOR_URL\" \"$PREMIER_COLLECTOR_TOKEN\" > '{0}.tmp' && mv '{0}.tmp' '{0}'; while [ ! -e '{1}' ]; do sleep 0.05; done",
        handoff.display(),
        release.display()
    );
    let mut recorder = premier()
        .arg("record")
        .arg("--output")
        .arg(&trace)
        .args(["--", "sh", "-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !handoff.exists() {
        assert!(Instant::now() < deadline, "recorded command never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let collector = std::fs::read_to_string(&handoff).unwrap();
    let (url, token) = collector.split_once(' ').unwrap();
    let address = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap();
    // Stands in for a detached grandchild that outlives the command: it
    // promises 1000 body bytes, sends nine, and keeps the socket open.
    let mut stalled = std::net::TcpStream::connect(address).unwrap();
    write!(
        stalled,
        "POST /v1/events HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{\"kind\":\""
    )
    .unwrap();
    stalled.flush().unwrap();
    // A second connection that never finishes its request head.
    let mut silent = std::net::TcpStream::connect(address).unwrap();
    silent
        .write_all(b"POST /v1/events HTTP/1.1\r\nHost: ")
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    std::fs::write(&release, "go").unwrap();
    let status = wait_bounded(&mut recorder, Duration::from_secs(15));
    assert!(
        status.is_some(),
        "the recorder must not wait for a half-open collector connection"
    );
    assert!(status.unwrap().success());
    premier_trace::verify(&trace).unwrap();
    assert!(
        read_events(&trace)
            .unwrap()
            .iter()
            .any(|event| event.kind == "process.exit")
    );
    drop((stalled, silent));
}

#[test]
fn export_of_an_encrypted_trace_is_owner_only_and_warns_that_it_is_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let key_file = write_key_file(temp.path());
    let trace = temp.path().join("sealed.atrace");
    encrypted_trace(&trace, "sealed");
    let exported = temp.path().join("export.json");
    let output = premier()
        .env("PREMIER_TRACE_KEY_FILE", &key_file)
        .arg("export")
        .arg(&trace)
        .arg("--output")
        .arg(&exported)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let warning = stderr(&output);
    assert!(
        warning.contains("warning") && warning.contains("plaintext"),
        "an encrypted source must be called out: {warning}"
    );
    assert!(
        std::fs::read_to_string(&exported)
            .unwrap()
            .contains("top-secret-evidence")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&exported).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "export must be owner-only, got {mode:o}");
    }

    // Writing to stdout still warns.
    let piped = premier()
        .env("PREMIER_TRACE_KEY_FILE", &key_file)
        .arg("export")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(piped.status.success());
    assert!(stderr(&piped).contains("plaintext"));

    // A plaintext source needs no warning, but its export is still private.
    let plain = temp.path().join("plain.atrace");
    trace_with(&plain, "plain", Vec::new());
    let plain_export = temp.path().join("plain.json");
    let output = premier()
        .arg("export")
        .arg(&plain)
        .arg("--output")
        .arg(&plain_export)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("plaintext"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&plain_export)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn text_output_escapes_control_characters_and_json_stays_exact() {
    let temp = tempfile::tempdir().unwrap();
    let trace_dir = temp.path().join("traces");
    let trace = trace_dir.join("hostile.atrace");
    let actor = "evil\u{1b}[31mred";
    let status = "ok\r\nforged line";
    trace_with(
        &trace,
        "run \u{1b}[2J\u{0}named\r\nsecond line",
        vec![
            EventInput {
                kind: "tool.exe\u{0}cution".into(),
                actor_id: actor.into(),
                status: status.into(),
                ..EventInput::default()
            },
            EventInput {
                kind: "agent.turn".into(),
                status: "ok".into(),
                ..EventInput::default()
            },
        ],
    );

    let text = premier().arg("query").arg(&trace).output().unwrap();
    assert!(text.status.success(), "{}", stderr(&text));
    let shown = stdout(&text);
    assert_eq!(shown.lines().count(), 2, "one line per event: {shown:?}");
    assert!(
        !shown.chars().any(|c| c.is_control() && c != '\n'),
        "{shown:?}"
    );
    assert!(shown.contains("evil\\u{1b}[31mred"), "{shown:?}");
    assert!(shown.contains("ok\\r\\nforged line"), "{shown:?}");
    // An event without an actor is not attributed to `root`.
    let unattributed = shown.lines().nth(1).unwrap();
    assert!(!unattributed.contains("root"), "{unattributed:?}");
    assert!(unattributed.contains(" - "), "{unattributed:?}");

    let json = premier()
        .arg("query")
        .arg(&trace)
        .arg("--json")
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(result["events"][0]["actor_id"], actor);
    assert_eq!(result["events"][0]["status"], status);
    assert_eq!(result["events"][0]["kind"], "tool.exe\u{0}cution");

    let listed = premier()
        .arg("list")
        .arg("--trace-dir")
        .arg(&trace_dir)
        .output()
        .unwrap();
    assert!(listed.status.success(), "{}", stderr(&listed));
    let shown = stdout(&listed);
    assert_eq!(shown.lines().count(), 1, "{shown:?}");
    assert!(
        !shown.chars().any(|c| c.is_control() && c != '\n'),
        "{shown:?}"
    );
    assert!(shown.contains("\\u{1b}[2J"), "{shown:?}");
}

#[cfg(unix)]
#[test]
fn a_closed_stdout_pipe_ends_evidence_commands_quietly() {
    use std::os::unix::process::ExitStatusExt;
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("wide.atrace");
    // Far more output than a pipe buffers, so the write is still in progress
    // when the reader goes away.
    let events = (0..1000)
        .map(|index| EventInput {
            kind: "tool.execution".into(),
            actor_id: format!("actor-{index}-{}", "x".repeat(400)),
            status: "ok".into(),
            timestamp: Some("2026-07-15T12:00:00Z".into()),
            ..EventInput::default()
        })
        .collect();
    trace_with(&trace, "wide", events);
    for arguments in [
        vec!["query", "--limit", "1000"],
        vec!["query", "--limit", "1000", "--json"],
        vec!["replay", "--no-sleep"],
        vec!["export"],
    ] {
        let mut child = premier()
            .arg(arguments[0])
            .arg(&trace)
            .args(&arguments[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        let errors = stderr(&output);
        assert!(
            !errors.contains("panicked") && !errors.contains("Broken pipe"),
            "{arguments:?}: {errors}"
        );
        assert!(
            output.status.signal() == Some(13) || output.status.code() == Some(141),
            "{arguments:?} must end like a tool killed by SIGPIPE, got {:?}",
            output.status
        );
    }
}

#[test]
fn key_file_option_is_documented_and_unlocks_an_encrypted_trace() {
    let temp = tempfile::tempdir().unwrap();
    let key_file = write_key_file(temp.path());
    let trace_dir = temp.path().join("traces");
    let trace = trace_dir.join("sealed.atrace");
    encrypted_trace(&trace, "sealed run");

    for command in [
        "record", "query", "export", "verify", "list", "serve", "encrypt",
    ] {
        let help = premier().args([command, "--help"]).output().unwrap();
        let help = stdout(&help);
        assert!(help.contains("--key-file"), "{command}: {help}");
        assert!(help.contains("PREMIER_TRACE_KEY_FILE"), "{command}: {help}");
        assert!(help.contains("64 hex"), "{command}: {help}");
        assert!(help.contains("0600"), "{command}: {help}");
    }

    let locked = premier().arg("query").arg(&trace).output().unwrap();
    assert!(!locked.status.success());
    assert!(
        stderr(&locked).contains("--key-file"),
        "{}",
        stderr(&locked)
    );

    let by_flag = premier()
        .arg("query")
        .arg(&trace)
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .unwrap();
    assert!(by_flag.status.success(), "{}", stderr(&by_flag));
    assert!(stdout(&by_flag).contains("agent.result"));

    let by_env = premier()
        .env("PREMIER_TRACE_KEY_FILE", &key_file)
        .arg("query")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(by_env.status.success(), "{}", stderr(&by_env));
    assert!(stdout(&by_env).contains("agent.result"));
}

#[test]
fn list_names_encrypted_traces_it_cannot_open() {
    let temp = tempfile::tempdir().unwrap();
    let key_file = write_key_file(temp.path());
    let trace_dir = temp.path().join("traces");
    let trace = trace_dir.join("sealed.atrace");
    encrypted_trace(&trace, "sealed run");
    let trace_id =
        premier_trace::read_manifest_with_key(&trace, &EncryptionKey::from_hex(KEY_HEX).unwrap())
            .unwrap()
            .trace_id;

    let locked = premier()
        .arg("list")
        .arg("--trace-dir")
        .arg(&trace_dir)
        .output()
        .unwrap();
    assert!(locked.status.success(), "{}", stderr(&locked));
    let shown = stdout(&locked);
    assert!(shown.contains(&trace_id), "{shown}");
    assert!(shown.contains("[encrypted: key required]"), "{shown}");
    assert!(
        !shown.contains("sealed run"),
        "the name is private: {shown}"
    );

    let wrong_key = temp.path().join("wrong.key");
    std::fs::write(&wrong_key, "22".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrong_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mismatched = premier()
        .arg("list")
        .arg("--trace-dir")
        .arg(&trace_dir)
        .arg("--key-file")
        .arg(&wrong_key)
        .output()
        .unwrap();
    assert!(mismatched.status.success(), "{}", stderr(&mismatched));
    let shown = stdout(&mismatched);
    assert!(shown.contains(&trace_id), "{shown}");
    assert!(shown.contains("[encrypted: "), "{shown}");
    assert!(!shown.contains("key required"), "{shown}");

    let unlocked = premier()
        .arg("list")
        .arg("--trace-dir")
        .arg(&trace_dir)
        .arg("--key-file")
        .arg(&key_file)
        .output()
        .unwrap();
    assert!(unlocked.status.success(), "{}", stderr(&unlocked));
    let shown = stdout(&unlocked);
    assert!(shown.contains("sealed run"), "{shown}");
    assert!(!shown.contains("[encrypted"), "{shown}");
}

#[tokio::test]
async fn viewer_lists_an_encrypted_trace_without_a_key_as_locked_not_damaged() {
    let temp = tempfile::tempdir().unwrap();
    let trace_dir = temp.path().join("traces");
    encrypted_trace(&trace_dir.join("sealed.atrace"), "sealed run");
    // A genuinely damaged manifest keeps the invalid state.
    let broken = trace_dir.join("broken.atrace");
    std::fs::create_dir_all(&broken).unwrap();
    std::fs::write(broken.join("manifest.json"), "{not json").unwrap();
    let viewer = temp.path().join("viewer");
    std::fs::create_dir_all(&viewer).unwrap();
    std::fs::write(viewer.join("index.html"), "viewer").unwrap();
    let app = premier_cli::app_with_options(
        trace_dir,
        Some(viewer),
        premier_cli::AuthPolicy::default(),
        premier_cli::ServerOptions {
            disable_assistant: true,
            ..Default::default()
        },
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/traces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let traces: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    let entry = |artifact: &str| {
        traces
            .iter()
            .find(|trace| trace["artifact"] == artifact)
            .unwrap_or_else(|| panic!("{artifact} missing from {traces:?}"))
    };
    let sealed = entry("sealed.atrace");
    assert_eq!(sealed["integrity"], "locked", "{sealed}");
    let detail = sealed["integrity_detail"].as_str().unwrap();
    assert!(detail.contains("encrypted"), "{detail}");
    assert!(detail.contains("PREMIER_TRACE_KEY_FILE"), "{detail}");
    assert!(sealed["encryption"].is_object(), "{sealed}");
    assert_eq!(entry("broken.atrace")["integrity"], "invalid");
}

#[test]
fn forced_recovery_removes_the_recorder_lease() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("abandoned.atrace");
    let mut writer = TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "test", serde_json::json!({}))
        .unwrap();
    drop(writer);
    let lease = trace.join(premier_trace::RECORDER_LEASE);
    std::fs::write(&lease, "999999").unwrap();
    let output = premier()
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!lease.exists(), "recovery must not leave the lease behind");
    premier_trace::verify(&trace).unwrap();
}

#[cfg(unix)]
#[test]
fn forced_recovery_under_a_live_recorder_does_not_get_its_lease_back() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("live.atrace");
    let lease = trace.join(premier_trace::RECORDER_LEASE);
    let mut recorder = premier()
        .arg("record")
        .arg("--output")
        .arg(&trace)
        .args(["--", "sleep", "4"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !lease.exists() || read_events(&trace).map_or(true, |events| events.is_empty()) {
        assert!(Instant::now() < deadline, "recorder never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = premier()
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!lease.exists());
    // The recorder refreshes its lease every two seconds while it runs.
    std::thread::sleep(Duration::from_millis(2_600));
    assert!(
        !lease.exists(),
        "the live recorder's heartbeat must not recreate a removed lease"
    );
    wait_bounded(&mut recorder, Duration::from_secs(20)).expect("recorder exits");
    assert!(!lease.exists());
    premier_trace::verify(&trace).unwrap();
}
