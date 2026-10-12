//! Regression tests for review findings in the recorder, the collector and
//! the trace-handling commands: what `record` says about encryption and
//! signing, default trace names, protection of live recordings, `list` rows
//! for traces that cannot be opened, recovery output, `replay --speed`
//! bounds, collector body and token handling, viewer shutdown on signals, and
//! PTY input end-of-file and resizes.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use premier_cli::{AuthPolicy, app};
use premier_trace::{
    ACTIVE_JOURNAL, EncryptionKey, FINAL_JOURNAL, RECORDER_LEASE, TraceEvent, TraceWriter,
    read_events, read_manifest,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

fn finalized(path: &Path) {
    let mut writer = TraceWriter::create(path, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "premier", serde_json::json!({}))
        .unwrap();
    writer.finish(0).unwrap();
}

/// An unfinalized trace, as a killed recorder leaves it.
fn abandoned(path: &Path, events: &[(&str, &str, serde_json::Value)]) {
    let mut writer = TraceWriter::create(path, vec!["agent".into()]).unwrap();
    for (kind, source, payload) in events {
        writer.append(kind, source, payload.clone()).unwrap();
    }
    drop(writer);
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
fn record_says_whether_the_trace_it_wrote_is_encrypted_and_signed() {
    let temp = tempfile::tempdir().unwrap();
    let plain = temp.path().join("plain.atrace");
    let output = premier()
        .args(["record", "--output"])
        .arg(&plain)
        .args(["--", "sh", "-c", "true"])
        .output()
        .unwrap();
    assert_success(&output);
    let summary = stderr(&output);
    assert!(
        summary.contains(
            "protection: NOT encrypted (plaintext on disk; pass --key-file to encrypt); unsigned"
        ),
        "{summary}"
    );

    // Both keys come from `premier keygen`.
    let trace_key = temp.path().join("trace.key");
    let generated = premier()
        .args(["keygen", "--encryption"])
        .arg(&trace_key)
        .output()
        .unwrap();
    assert_success(&generated);
    let key_text = std::fs::read_to_string(&trace_key).unwrap();
    let key = EncryptionKey::from_hex(key_text.trim()).unwrap();
    assert!(stdout(&generated).contains(&key.key_id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&trace_key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // An existing key file is never overwritten.
    assert!(
        !premier()
            .args(["keygen", "--encryption"])
            .arg(&trace_key)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(&trace_key).unwrap(), key_text);
    let sign_key = temp.path().join("sign.key");
    assert_success(&premier().arg("keygen").arg(&sign_key).output().unwrap());

    let sealed = temp.path().join("sealed.atrace");
    let output = premier()
        .arg("--key-file")
        .arg(&trace_key)
        .args(["record", "--sign-key"])
        .arg(&sign_key)
        .arg("--output")
        .arg(&sealed)
        .args(["--", "sh", "-c", "true"])
        .output()
        .unwrap();
    assert_success(&output);
    let summary = stderr(&output);
    assert!(
        summary.contains(&format!(
            "protection: encrypted at rest (key {}); signed (key sha256:",
            key.key_id()
        )),
        "{summary}"
    );
    assert!(premier_trace::trace_is_encrypted(&sealed).unwrap());
}

#[test]
fn parallel_recordings_without_an_output_path_never_share_a_directory() {
    let temp = tempfile::tempdir().unwrap();
    let recorders: Vec<_> = (0..6)
        .map(|index| {
            premier()
                .current_dir(temp.path())
                .args(["record", "--", "sh", "-c", &format!("echo run-{index}")])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for recorder in recorders {
        assert_success(&recorder.wait_with_output().unwrap());
    }

    let mut names: Vec<String> = std::fs::read_dir(temp.path().join(".premier/traces"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 6, "{names:?}");
    let mut outputs = Vec::new();
    for name in &names {
        // trace-<unix milliseconds>-<8 hex digits>.atrace
        let stem = name
            .strip_prefix("trace-")
            .and_then(|rest| rest.strip_suffix(".atrace"))
            .unwrap_or_else(|| panic!("unexpected default name {name}"));
        let (millis, suffix) = stem.split_once('-').unwrap();
        assert!(millis.bytes().all(|byte| byte.is_ascii_digit()), "{name}");
        assert_eq!(suffix.len(), 8, "{name}");
        assert!(
            suffix.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{name}"
        );
        let trace = temp.path().join(".premier/traces").join(name);
        assert_success(&premier().arg("verify").arg(&trace).output().unwrap());
        outputs.extend(
            read_events(&trace)
                .unwrap()
                .into_iter()
                .filter(|event| event.kind == "process.stdout")
                .map(|event| event.payload()["text"].as_str().unwrap().trim().to_owned()),
        );
    }
    outputs.sort();
    assert_eq!(
        outputs,
        ["run-0", "run-1", "run-2", "run-3", "run-4", "run-5"]
    );
}

#[test]
fn demo_does_not_replace_a_trace_that_is_being_recorded() {
    let temp = tempfile::tempdir().unwrap();
    let live = temp.path().join("live.atrace");
    let mut writer = TraceWriter::create(&live, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "premier", serde_json::json!({}))
        .unwrap();
    // This test process plays the recorder: its lease names a live process.
    std::fs::write(
        live.join(RECORDER_LEASE),
        premier_cli::liveness::lease_contents(),
    )
    .unwrap();

    let refused = premier()
        .args(["demo", "--output"])
        .arg(&live)
        .output()
        .unwrap();

    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("it is being recorded right now"),
        "{}",
        stderr(&refused)
    );
    // The recording is untouched and its recorder can still finalize it.
    writer
        .append("custom.step", "test", serde_json::json!({}))
        .unwrap();
    let manifest = writer.finish(0).unwrap();
    assert_eq!(manifest.journal.unwrap().event_count, 2);

    // Once finalized it is a recorded trace, which `demo` replaces only when
    // told to.
    let refused = premier()
        .args(["demo", "--output"])
        .arg(&live)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("not an earlier demo"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(read_manifest(&live).unwrap().trace_id, manifest.trace_id);
    let replaced = premier()
        .args(["demo", "--force", "--output"])
        .arg(&live)
        .output()
        .unwrap();
    assert_success(&replaced);
    assert_ne!(read_manifest(&live).unwrap().trace_id, manifest.trace_id);
}

#[test]
fn claim_refuses_a_trace_that_is_still_being_recorded() {
    let temp = tempfile::tempdir().unwrap();
    let live = temp.path().join("live.atrace");
    let mut writer = TraceWriter::create(&live, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "premier", serde_json::json!({}))
        .unwrap();

    let refused = premier()
        .arg("claim")
        .arg(&live)
        .args(["--tenant", "team-a"])
        .output()
        .unwrap();

    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("only a finalized trace may be claimed"),
        "{}",
        stderr(&refused)
    );
    // The owner the recorder finalizes with is the one on record.
    assert_eq!(writer.finish(0).unwrap().tenant_id, "local");
    assert_success(
        &premier()
            .arg("claim")
            .arg(&live)
            .args(["--tenant", "team-a"])
            .output()
            .unwrap(),
    );
    assert_eq!(premier_trace::verify(&live).unwrap().tenant_id, "team-a");
}

/// A trace directory in a format later than this build reads, shaped so that
/// this build could not decode it.
fn newer_format_trace(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(
        path.join("manifest.json"),
        r#"{"format_version": 9, "trace_id": "0196f000-0000-7000-8000-00000000f009",
            "started_at": "2026-05-04T03:02:01Z", "command": "agent run", "shards": 4}"#,
    )
    .unwrap();
}

#[test]
fn list_shows_traces_it_cannot_open_and_why() {
    let temp = tempfile::tempdir().unwrap();
    let traces = temp.path().join("traces");
    finalized(&traces.join("readable.atrace"));
    newer_format_trace(&traces.join("future.atrace"));
    let torn = traces.join("torn.atrace");
    std::fs::create_dir_all(&torn).unwrap();
    std::fs::write(
        torn.join("manifest.json"),
        r#"{"format_version": 2, "trace"#,
    )
    .unwrap();
    let encrypted = traces.join("sealed.atrace");
    finalized(&encrypted);
    premier_trace::reencrypt_finalized_trace(
        &encrypted,
        EncryptionKey::from_hex(&"5b".repeat(32)).unwrap(),
    )
    .unwrap();
    // Not a trace at all: no manifest, no row.
    std::fs::create_dir_all(traces.join("notes")).unwrap();

    let output = premier()
        .args(["list", "--trace-dir"])
        .arg(&traces)
        .output()
        .unwrap();

    assert_success(&output);
    let listing = stdout(&output);
    let row = |needle: &str| {
        listing
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no row for {needle} in:\n{listing}"))
    };
    assert_eq!(listing.lines().count(), 4, "{listing}");
    assert!(
        row("future.atrace").ends_with("[needs a newer premier: format version 9]"),
        "{listing}"
    );
    assert!(
        row("future.atrace").contains("0196f000-0000-7000-8000-00000000f009"),
        "{listing}"
    );
    assert!(row("torn.atrace").contains("[unreadable: "), "{listing}");
    assert!(
        row("sealed.atrace").ends_with("[encrypted: key required]"),
        "{listing}"
    );
    // Every row prints its start time the same way.
    let readable_time = read_manifest(traces.join("readable.atrace"))
        .unwrap()
        .started_at
        .to_string();
    assert!(row("agent").contains(&readable_time), "{listing}");
    let sealed_time: serde_json::Value =
        serde_json::from_slice(&std::fs::read(encrypted.join("manifest.json")).unwrap()).unwrap();
    let sealed_time =
        chrono::DateTime::parse_from_rfc3339(sealed_time["started_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc)
            .to_string();
    assert!(row("sealed.atrace").contains(&sealed_time), "{listing}");
    assert!(
        row("future.atrace").contains("2026-05-04 03:02:01 UTC"),
        "{listing}"
    );
}

fn viewer_dir(root: &Path) -> PathBuf {
    let viewer = root.join("viewer");
    std::fs::create_dir_all(&viewer).unwrap();
    std::fs::write(viewer.join("index.html"), "viewer").unwrap();
    viewer
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn the_viewer_lists_a_newer_format_trace_as_unsupported_not_damaged() {
    let temp = tempfile::tempdir().unwrap();
    let traces = temp.path().join("traces");
    newer_format_trace(&traces.join("future.atrace"));
    let app = app(traces, Some(viewer_dir(temp.path())), AuthPolicy::default());

    let (status, body) = get(&app, "/api/traces").await;

    assert_eq!(status, StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(listed[0]["integrity"], "unsupported");
    assert_eq!(listed[0]["trace_id"], "unsupported:future.atrace");
    let detail = listed[0]["integrity_detail"].as_str().unwrap();
    assert!(
        detail.starts_with("needs a newer Premier: this trace is in format version 9"),
        "{detail}"
    );
}

#[tokio::test]
async fn an_internal_error_is_logged_not_sent_to_the_client() {
    let temp = tempfile::tempdir().unwrap();
    let traces = temp.path().join("traces");
    let trace = traces.join("damaged.atrace");
    finalized(&trace);
    let trace_id = read_manifest(&trace).unwrap().trace_id;
    // The journal no longer decodes, so reading its events fails inside the
    // server with an error that names what it tripped over.
    std::fs::write(trace.join("events").join(FINAL_JOURNAL), b"not a journal").unwrap();
    let app = app(traces, Some(viewer_dir(temp.path())), AuthPolicy::default());

    let (status, body) = get(&app, &format!("/api/traces/{trace_id}/events")).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error": "internal error; see the premier server log"})
    );
}

#[test]
fn recover_keeps_a_journaled_exit_and_verify_names_the_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("exited.atrace");
    abandoned(
        &trace,
        &[
            ("session.start", "premier", serde_json::json!({})),
            (
                "process.exit",
                "command",
                serde_json::json!({"exit_code": 4, "success": false, "termination": "exit"}),
            ),
        ],
    );

    let recovered = premier()
        .args(["recover", "--force"])
        .arg(&trace)
        .output()
        .unwrap();

    assert_success(&recovered);
    let report = stdout(&recovered);
    assert!(report.contains("(3 events, exit 4)"), "{report}");
    assert!(
        report.contains("the command's exit was already recorded (process.exit)"),
        "{report}"
    );
    let verified = premier().arg("verify").arg(&trace).output().unwrap();
    assert_success(&verified);
    assert!(
        stdout(&verified).contains("note: finalized by `premier recover`, not by its recorder"),
        "{}",
        stdout(&verified)
    );

    // Recovery can be run again: with nothing left to do it says so, and
    // with leftovers of an interrupted finalization it removes them.
    let again = premier()
        .args(["recover", "--force"])
        .arg(&trace)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(stderr(&again).contains("already finalized"));
    std::fs::write(trace.join("events").join(ACTIVE_JOURNAL), b"stale").unwrap();
    let cleaned = premier()
        .args(["recover", "--force"])
        .arg(&trace)
        .output()
        .unwrap();
    assert_success(&cleaned);
    assert!(
        stdout(&cleaned).contains(&format!(
            "is already finalized (3 events); removed what an interrupted finalization left behind: events/{ACTIVE_JOURNAL}"
        )),
        "{}",
        stdout(&cleaned)
    );
    assert!(!trace.join("events").join(ACTIVE_JOURNAL).exists());
    assert_success(&premier().arg("verify").arg(&trace).output().unwrap());

    // A trace its recorder finalized carries no such note.
    let ordinary = temp.path().join("ordinary.atrace");
    finalized(&ordinary);
    let verified = premier().arg("verify").arg(&ordinary).output().unwrap();
    assert!(!stdout(&verified).contains("premier recover"));
}

#[test]
fn replay_rejects_a_speed_too_small_to_wait_out() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("replay.atrace");
    let mut writer = TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    for second in [0, 5] {
        writer
            .append_input(premier_trace::EventInput {
                kind: "custom.step".into(),
                timestamp: Some(format!("2026-01-01T00:00:0{second}Z")),
                ..premier_trace::EventInput::default()
            })
            .unwrap();
    }
    writer.finish(0).unwrap();

    for speed in ["1e-300", "0.0000001", "5e-324"] {
        let mut replay = premier()
            .args(["replay", "--speed", speed])
            .arg(&trace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let status = wait_bounded(&mut replay, Duration::from_secs(20))
            .unwrap_or_else(|| panic!("replay --speed {speed} did not return"));
        let output = replay.wait_with_output().unwrap();
        assert_eq!(status.code(), Some(2), "{}", stderr(&output));
        assert!(
            stderr(&output).contains("speed must be at least 0.001"),
            "{}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("panicked"));
    }
    // The slowest accepted speed is still a speed.
    let help = premier().args(["replay", "--help"]).output().unwrap();
    assert!(stdout(&help).contains("at least 0.001"));
}

#[test]
fn emit_refuses_field_options_alongside_a_json_body() {
    for extra in [
        ["--kind", "agent.message"],
        ["--actor", "coder"],
        ["--status", "ok"],
        ["--payload", "{}"],
        ["--source", "mine"],
    ] {
        let output = premier()
            .args(["emit", "--json", r#"{"kind":"agent.message"}"#])
            .args(extra)
            .env("PREMIER_COLLECTOR_URL", "http://127.0.0.1:9/v1/events")
            .env("PREMIER_COLLECTOR_TOKEN", "unused")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{extra:?}");
        assert!(
            stderr(&output).contains("cannot be used with"),
            "{extra:?}: {}",
            stderr(&output)
        );
    }
}

struct Collector {
    app: axum::Router,
    writer: Arc<Mutex<TraceWriter>>,
    trace_id: String,
    root: PathBuf,
    _temp: tempfile::TempDir,
}

impl Collector {
    fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("collector.atrace");
        let writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        let trace_id = writer.trace_id().to_owned();
        let writer = Arc::new(Mutex::new(writer));
        Self {
            app: premier_cli::instrumentation_app(writer.clone(), "collector-credential".into()),
            writer,
            trace_id,
            root,
            _temp: temp,
        }
    }

    async fn post_as(&self, token: Option<&str>, body: String) -> (StatusCode, String) {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/events")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn post(&self, body: serde_json::Value) -> (StatusCode, String) {
        self.post_as(Some("collector-credential"), body.to_string())
            .await
    }

    fn finish(self) -> Vec<TraceEvent> {
        let Self {
            app, writer, root, ..
        } = self;
        drop(app);
        Arc::try_unwrap(writer)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap()
            .finish(0)
            .unwrap();
        read_events(root).unwrap()
    }
}

#[tokio::test]
async fn collector_accepts_only_a_json_object_of_known_fields() {
    let collector = Collector::start();

    // An array used to be read positionally as kind, source, actor_id, ...
    let (status, body) = collector
        .post(serde_json::json!(["agent.message", "sdk", "coder"]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("event body must be a JSON object"), "{body}");
    for scalar in ["\"agent.message\"", "7", "null", "true"] {
        let (status, body) = collector
            .post_as(Some("collector-credential"), scalar.into())
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{scalar}: {body}");
    }

    // A misspelt field is named instead of being dropped.
    let (status, body) = collector
        .post(serde_json::json!({"kind": "agent.message", "actor": "coder"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("unknown event field `actor`"), "{body}");
    assert!(body.contains("actor_id"), "{body}");

    // What the SDKs send besides the event: the trace it is for, and the run.
    let (status, body) = collector
        .post(serde_json::json!({
            "kind": "agent.message",
            "actor_id": "coder",
            "status": "ok",
            "payload": {},
            "trace_id": collector.trace_id,
            "run": {"name": "nightly"},
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = collector
        .post(serde_json::json!({
            "kind": "agent.message",
            "trace_id": "0196f000-0000-7000-8000-000000000001",
        }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("addressed to a different trace"), "{body}");
    let (status, _) = collector
        .post(serde_json::json!({"kind": "agent.message", "trace_id": 7}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let events = collector.finish();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor_id, "coder");
}

#[tokio::test]
async fn collector_slows_and_records_requests_without_its_token() {
    let collector = Collector::start();
    let event = serde_json::json!({"kind": "agent.message", "payload": {}}).to_string();

    let started = Instant::now();
    for token in [None, Some("guess-one"), Some("guess-two")] {
        let (status, body) = collector.post_as(token, event.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.contains("invalid collector token"), "{body}");
    }
    // 100 ms, then 200 ms, then 300 ms.
    assert!(
        started.elapsed() >= Duration::from_millis(550),
        "three refusals took only {:?}",
        started.elapsed()
    );
    // The right token is answered at once, and resets the count.
    let started = Instant::now();
    let (status, body) = collector
        .post_as(Some("collector-credential"), event.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(started.elapsed() < Duration::from_millis(90));
    let started = Instant::now();
    collector.post_as(Some("guess-three"), event).await;
    assert!(started.elapsed() < Duration::from_millis(190));

    // The trace holds one mark for all of them, written by the recorder.
    let events = collector.finish();
    let kinds: Vec<_> = events.iter().map(|event| event.kind.as_str()).collect();
    assert_eq!(kinds, ["collector.unauthorized", "agent.message"]);
    assert_eq!(events[0].source, "premier");
    assert_eq!(events[0].status, "denied");
}

#[test]
fn the_collector_token_is_a_full_entropy_secret_unrelated_to_event_ids() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("token.atrace");
    let output = premier()
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "--",
            "sh",
            "-c",
            // Its length and alphabet, never the value itself.
            r#"printf '%s' "$PREMIER_COLLECTOR_TOKEN" | wc -c; case "$PREMIER_COLLECTOR_TOKEN" in *[!0-9a-f]*) echo other;; *) echo hex;; esac"#,
        ])
        .output()
        .unwrap();
    assert_success(&output);
    let printed = stdout(&output);
    let mut lines = printed.lines().map(str::trim);
    assert_eq!(lines.next(), Some("64"), "{printed}");
    assert_eq!(lines.next(), Some("hex"), "{printed}");
}

#[test]
fn captured_output_that_is_not_utf8_is_marked_lossy() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("lossy.atrace");
    let output = premier()
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "--",
            "sh",
            "-c",
            r"printf 'ok \377\376 end\n'; printf 'clean\n' >&2",
        ])
        .output()
        .unwrap();
    assert_success(&output);
    // The mirror is the command's exact bytes.
    assert_eq!(output.stdout, b"ok \xff\xfe end\n");

    let events = read_events(&trace).unwrap();
    let stdout_event = events
        .iter()
        .find(|event| event.kind == "process.stdout")
        .unwrap();
    let payload = stdout_event.payload();
    assert_eq!(payload["text"], "ok \u{fffd}\u{fffd} end\n");
    assert_eq!(payload["lossy"], true);
    assert_eq!(payload["replaced_sequences"], 2);
    assert_eq!(payload["byte_length"], 10);
    let stderr_event = events
        .iter()
        .find(|event| event.kind == "process.stderr")
        .unwrap();
    assert!(stderr_event.payload().get("lossy").is_none());
}

#[cfg(unix)]
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[cfg(unix)]
fn http_ok(port: u16, path: &str) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    if write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.starts_with("HTTP/1.1 200")
}

#[cfg(unix)]
fn wait_for_viewer(server: &mut std::process::Child, port: u16) {
    let started = Instant::now();
    while !http_ok(port, "/api/traces") {
        if started.elapsed() > Duration::from_secs(30) {
            let _ = server.kill();
            panic!("viewer did not start within 30s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn signal(child: &std::process::Child, signal: i32) {
    // SAFETY: the child is a process this test spawned and has not reaped.
    assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
}

#[cfg(unix)]
#[test]
fn serve_stops_cleanly_on_sigterm_and_on_ctrl_c() {
    let temp = tempfile::tempdir().unwrap();
    let traces = temp.path().join("traces");
    finalized(&traces.join("one.atrace"));
    for stop in [libc::SIGTERM, libc::SIGINT] {
        let port = free_port();
        let mut server = premier()
            .args(["serve", "--bind", &format!("127.0.0.1:{port}")])
            .arg("--trace-dir")
            .arg(&traces)
            .arg("--viewer-dir")
            .arg(viewer_dir(temp.path()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_viewer(&mut server, port);

        signal(&server, stop);

        let status = wait_bounded(&mut server, Duration::from_secs(10))
            .unwrap_or_else(|| panic!("the viewer ignored signal {stop}"));
        let output = server.wait_with_output().unwrap();
        assert!(status.success(), "signal {stop}: {status:?}");
        assert!(
            stderr(&output).contains("premier: viewer stopped"),
            "{}",
            stderr(&output)
        );
        assert!(!http_ok(port, "/api/traces"));
    }
}

/// After `record --open` the recorder's own signal handlers are still
/// installed; the viewer it then runs must be stoppable all the same.
#[cfg(unix)]
#[test]
fn the_viewer_of_record_open_stops_on_ctrl_c() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    // Never launch a real browser: shadow the platform opener with a no-op.
    let stubs = temp.path().join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    for opener in ["open", "xdg-open"] {
        let stub = stubs.join(opener);
        std::fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut path = std::ffi::OsString::from(&stubs);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());

    for stop in [libc::SIGINT, libc::SIGTERM] {
        let port = free_port();
        let recorded = temp.path().join(format!("recorded-{stop}.atrace"));
        let mut recorder = premier()
            .args(["record", "--open", "--bind", &format!("127.0.0.1:{port}")])
            .arg("--viewer-dir")
            .arg(viewer_dir(temp.path()))
            .arg("--output")
            .arg(&recorded)
            .args(["--", "sh", "-c", "echo recorded"])
            .env("PATH", &path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_viewer(&mut recorder, port);

        signal(&recorder, stop);

        let status = wait_bounded(&mut recorder, Duration::from_secs(10))
            .unwrap_or_else(|| panic!("the viewer of record --open ignored signal {stop}"));
        assert!(status.success(), "signal {stop}: {status:?}");
        assert_success(&premier().arg("verify").arg(&recorded).output().unwrap());
    }
}

#[cfg(unix)]
#[test]
fn pty_capture_ends_redirected_input_so_the_command_can_finish() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    for (name, input, expected) in [
        (
            "lines",
            "first line\nsecond line\n",
            "first line\r\nsecond line\r\n",
        ),
        // No trailing newline: the unfinished line is delivered, then the end.
        ("partial", "no newline", "no newline"),
        ("empty", "", ""),
    ] {
        let trace = temp.path().join(format!("{name}.atrace"));
        let mut recorder = premier()
            .args(["record", "--pty", "--output"])
            .arg(&trace)
            .args(["--", "cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = recorder.stdin.take().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
        drop(stdin);

        let status = wait_bounded(&mut recorder, Duration::from_secs(20))
            .unwrap_or_else(|| panic!("`cat` under --pty never saw the end of its input ({name})"));
        let output = recorder.wait_with_output().unwrap();
        assert!(status.success(), "{name}: {}", stderr(&output));
        // The input is forwarded, not typed: it appears once, as cat's output.
        let terminal: String = read_events(&trace)
            .unwrap()
            .iter()
            .filter(|event| event.kind == "process.terminal")
            .map(|event| event.payload()["text"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(terminal, expected, "{name}");
        assert_eq!(read_manifest(&trace).unwrap().exit_code, Some(0), "{name}");
    }
}

#[cfg(unix)]
#[test]
fn a_terminal_resize_reaches_the_pty_child_and_is_recorded() {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("resized.atrace");
    let flag = temp.path().join("resized.flag");
    // The terminal the recorder runs in: 24 rows by 80 columns to begin with.
    let (mut master, mut slave) = (0, 0);
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty fills in the two descriptors, which are owned below.
    let (master, slave) = unsafe {
        assert_eq!(
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                // The size parameter is `*const` on Linux and `*mut` on macOS.
                std::ptr::addr_of!(size).cast_mut(),
            ),
            0
        );
        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    };
    let mut recorder = premier()
        .args(["record", "--pty", "--output"])
        .arg(&trace)
        .args([
            "--",
            "sh",
            "-c",
            r#"echo ready; while [ ! -e "$0" ]; do sleep 0.1; done; stty size"#,
        ])
        .arg(&flag)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    let screen = Arc::new(Mutex::new(String::new()));
    let reader_screen = screen.clone();
    let mut reader = std::fs::File::from(master.try_clone().unwrap());
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 {
                break;
            }
            reader_screen
                .lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buffer[..count]));
        }
    });
    let wait_for = |needle: &str, recorder: &mut std::process::Child| {
        let started = Instant::now();
        while !screen.lock().unwrap().contains(needle) {
            if started.elapsed() > Duration::from_secs(30) {
                let _ = recorder.kill();
                panic!("never saw {needle:?}; screen: {:?}", screen.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    // Output from the command means the recorder is capturing.
    wait_for("ready", &mut recorder);

    // The window is resized to 40 rows by 100 columns.
    let resized = libc::winsize {
        ws_row: 40,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the descriptor is the PTY master opened above, and the pointer
    // is to a live winsize.
    assert_eq!(
        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &resized) },
        0
    );
    signal(&recorder, libc::SIGWINCH);
    std::thread::sleep(Duration::from_millis(500));
    std::fs::write(&flag, "").unwrap();

    wait_for("40 100", &mut recorder);
    let status = wait_bounded(&mut recorder, Duration::from_secs(20)).expect("recorder exits");
    assert!(status.success());
    let events = read_events(&trace).unwrap();
    assert_eq!(events[0].payload()["terminal"]["rows"], 24);
    assert_eq!(events[0].payload()["terminal"]["cols"], 80);
    let resizes: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "process.resize")
        .collect();
    assert_eq!(resizes.len(), 1);
    assert_eq!(resizes[0].source, "premier");
    assert_eq!(resizes[0].payload()["rows"], 40);
    assert_eq!(resizes[0].payload()["cols"], 100);
}
