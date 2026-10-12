//! Tests for review findings in the CLI's query, export, diff, demo, list,
//! open, and adapter paths, each named after the behaviour it pins down.
#![cfg(unix)]

use premier_trace::{EventInput, TraceWriter, read_events, read_manifest};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn premier() -> Command {
    Command::new(env!("CARGO_BIN_EXE_premier"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run(command: &mut Command) -> Output {
    command.output().unwrap()
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {} / {}", stdout(output), stderr(output)))
}

/// A `PATH` whose `open` and `xdg-open` only log their arguments, so no test
/// can start a real browser, and the file they log to.
fn stub_browser(temp: &Path) -> (String, PathBuf) {
    let bin = temp.join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = temp.join("browser.log");
    for name in ["open", "xdg-open"] {
        let path = bin.join(name);
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"$@\" >> '{}'\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    (path, log)
}

/// Wait until the viewer at `address` answers and the stub browser was
/// started, then stop the viewer the way Ctrl-C does.
fn stop_serving_viewer(child: &mut std::process::Child, address: &str, browser_log: &Path) {
    use std::io::{Read, Write};
    let started = Instant::now();
    while !browser_log.exists() {
        assert!(started.elapsed() < Duration::from_secs(20), "no browser");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .write_all(
            format!("GET /api/health HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    // SAFETY: `kill` has no memory-safety preconditions; the pid is the child's.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    assert!(child.wait().unwrap().success());
}

/// A directory that passes for a viewer build.
fn viewer_dir(temp: &Path) -> PathBuf {
    let viewer = temp.join("viewer");
    std::fs::create_dir_all(&viewer).unwrap();
    std::fs::write(viewer.join("index.html"), "viewer").unwrap();
    viewer
}

/// Run a command that must end by itself. One that is still running after
/// `timeout` (a viewer that started serving) is killed and fails the test.
fn run_to_exit(command: &mut Command, timeout: Duration) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > timeout {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "the command kept running instead of failing: {} / {}",
                stdout(&output),
                stderr(&output)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn evidence_trace(path: &Path, variant: &str) -> String {
    let mut writer = TraceWriter::create_named(
        path,
        vec!["agent".into(), "run".into()],
        Some(format!("{variant} evidence")),
    )
    .unwrap();
    let trace_id = writer.trace_id().to_owned();
    writer
        .append_input(EventInput {
            kind: "agent.turn".into(),
            actor_id: "coordinator".into(),
            actor_type: "agent".into(),
            status: "running".into(),
            span_id: "turn".into(),
            payload: json!({"task": "inspect billing"}),
            timestamp: Some("2026-07-15T12:00:00Z".into()),
            ..Default::default()
        })
        .unwrap();
    writer
        .append_input(EventInput {
            kind: "tool.execution".into(),
            actor_id: "researcher".into(),
            actor_type: "subagent".into(),
            status: if variant == "current" { "error" } else { "ok" }.into(),
            parent_span_id: "turn".into(),
            correlation_id: "call-1".into(),
            payload: json!({
                "tool": "search",
                "query": if variant == "current" { "invoices" } else { "billing" },
            }),
            timestamp: Some("2026-07-15T12:00:01Z".into()),
            ..Default::default()
        })
        .unwrap();
    if variant == "current" {
        writer
            .append_input(EventInput {
                kind: "agent.result".into(),
                actor_id: "coordinator".into(),
                actor_type: "agent".into(),
                status: "ok".into(),
                payload: json!({"result": "done"}),
                timestamp: Some("2026-07-15T12:00:02Z".into()),
                ..Default::default()
            })
            .unwrap();
    }
    writer.finish(0).unwrap();
    trace_id
}

/// Record `sh -c <script>` in `cwd`, with extra environment for the script.
fn record(cwd: &Path, output: &str, script: &str, env: &[(&str, &str)]) -> Output {
    let mut command = premier();
    command
        .current_dir(cwd)
        .args(["record", "--adapter", "none", "-o", output, "--"])
        .args(["sh", "-c", script]);
    for (name, value) in env {
        command.env(name, value);
    }
    run(&mut command)
}

#[test]
fn two_recordings_of_one_command_diff_clean_and_exit_code_reports_a_difference() {
    let temp = tempfile::tempdir().unwrap();
    // The output is written in pieces whose boundaries differ between runs,
    // and each run's collector listens on a different port.
    let script =
        "printf 'one\\n'; printf \"$WORD\"; sleep 0.05; printf '\\nthree\\n'; exit ${CODE:-0}";
    for name in ["a.atrace", "b.atrace"] {
        let recorded = record(temp.path(), name, script, &[("WORD", "two")]);
        assert!(recorded.status.success(), "{}", stderr(&recorded));
    }
    let ports: Vec<String> = ["a.atrace", "b.atrace"]
        .iter()
        .map(|name| {
            read_events(temp.path().join(name)).unwrap()[0].payload()["instrumentation"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_ne!(ports[0], ports[1], "each run has its own collector port");

    let clean = run(premier().current_dir(temp.path()).args([
        "diff",
        "a.atrace",
        "b.atrace",
        "--exit-code",
    ]));
    assert_eq!(clean.status.code(), Some(0), "{}", stdout(&clean));
    assert!(
        stdout(&clean).contains("no differences"),
        "{}",
        stdout(&clean)
    );
    let clean = json_stdout(&run(premier()
        .current_dir(temp.path())
        .args(["diff", "a.atrace", "b.atrace", "--json"])));
    assert_eq!(clean["identical"], true, "{clean}");
    assert_eq!(clean["format"], "premier.semantic-diff.v2");
    assert_eq!(clean["first_divergence"], Value::Null);
    assert_eq!(clean["counts"]["changed"], 0);

    let recorded = record(
        temp.path(),
        "c.atrace",
        script,
        &[("WORD", "TWO"), ("CODE", "3")],
    );
    assert_eq!(recorded.status.code(), Some(3));
    let differs = run(premier().current_dir(temp.path()).args([
        "diff",
        "a.atrace",
        "c.atrace",
        "--exit-code",
    ]));
    assert_eq!(differs.status.code(), Some(1), "{}", stderr(&differs));
    let text = stdout(&differs);
    assert!(
        text.contains("first divergence: changed process.stdout:root#1"),
        "{text}"
    );
    assert!(text.contains("text.line[2]: \"two\" → \"TWO\""), "{text}");
    assert!(text.contains("manifest\texit_code: 0 → 3"), "{text}");
    assert!(text.contains("payload.exit_code: 0 → 3"), "{text}");

    // Without --exit-code the status still reports only whether diff ran.
    let differs = run(premier()
        .current_dir(temp.path())
        .args(["diff", "a.atrace", "c.atrace", "--json"]));
    assert_eq!(differs.status.code(), Some(0));
    let differs = json_stdout(&differs);
    assert_eq!(differs["identical"], false);
    assert_eq!(differs["first_divergence"]["key"], "process.stdout:root#1");
    assert_eq!(
        differs["first_divergence"]["change"]["field"],
        "text.line[2]"
    );
    assert_eq!(differs["manifest"][0]["field"], "exit_code");
    let differs = run(premier().current_dir(temp.path()).args([
        "diff",
        "a.atrace",
        "c.atrace",
        "--json",
        "--exit-code",
    ]));
    assert_eq!(differs.status.code(), Some(1));
    assert_eq!(json_stdout(&differs)["identical"], false);
}

#[test]
fn an_export_can_be_verified_queried_and_diffed_and_edits_are_detected() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("baseline.atrace");
    let current = temp.path().join("current.atrace");
    let trace_id = evidence_trace(&trace, "baseline");
    evidence_trace(&current, "current");
    let full = temp.path().join("full.json");
    let selected = temp.path().join("selected.json");

    let exported = run(premier().arg("export").arg(&trace).arg("-o").arg(&full));
    assert!(exported.status.success(), "{}", stderr(&exported));
    assert!(stdout(&exported).contains("export digest: sha256:"));
    assert!(!stdout(&exported).contains("selection:"));
    let exported = run(premier()
        .arg("export")
        .arg(&trace)
        .arg("-o")
        .arg(&selected)
        .args(["--kind", "tool.execution", "--after-sequence", "1"]));
    assert!(exported.status.success(), "{}", stderr(&exported));
    assert!(
        stdout(&exported).contains("selection: 1 of 2 events exported"),
        "{}",
        stdout(&exported)
    );
    let document: Value = serde_json::from_slice(&std::fs::read(&selected).unwrap()).unwrap();
    assert_eq!(document["source"]["verification"], "verified");
    assert_eq!(document["source"]["finalized"], true);
    assert_eq!(
        document["selection"]["filters"],
        json!({"kind": ["tool.execution"], "after_sequence": 1})
    );
    assert_eq!(document["events"].as_array().unwrap().len(), 1);

    let verified = run(premier().arg("verify").arg(&selected));
    assert!(verified.status.success(), "{}", stderr(&verified));
    let text = stdout(&verified);
    assert!(text.contains("export consistent:"), "{text}");
    assert!(text.contains("1 events"), "{text}");
    assert!(
        text.contains(&format!("derived from trace {trace_id}")),
        "{text}"
    );
    assert!(
        text.contains("a selection kept 1 of the 2 source events"),
        "{text}"
    );
    assert!(text.contains("source signature: none"), "{text}");
    assert!(text.contains("not the sealed original"), "{text}");
    assert!(text.contains(document["integrity"]["digest"].as_str().unwrap()));

    // The export answers queries and can stand in for the trace in a diff.
    let queried = run(premier()
        .arg("query")
        .arg(&full)
        .args(["--actor", "researcher", "--json"]));
    assert!(queried.status.success(), "{}", stderr(&queried));
    assert!(
        stderr(&queried).contains("is an export"),
        "{}",
        stderr(&queried)
    );
    let queried = json_stdout(&queried);
    assert_eq!(queried["matched"], 1);
    assert_eq!(queried["source"]["kind"], "export");
    assert_eq!(queried["events"][0]["kind"], "tool.execution");
    let diff = run(premier().arg("diff").arg(&full).arg(&current).arg("--json"));
    assert!(diff.status.success(), "{}", stderr(&diff));
    let diff = json_stdout(&diff);
    assert_eq!(diff["counts"]["unchanged"], 1, "{diff}");
    assert_eq!(diff["counts"]["changed"], 1);
    assert_eq!(diff["counts"]["added"], 1);
    let against_itself = run(premier()
        .arg("diff")
        .arg(&full)
        .arg(&trace)
        .arg("--exit-code"));
    assert_eq!(
        against_itself.status.code(),
        Some(0),
        "{}",
        stdout(&against_itself)
    );

    // An edited export fails everywhere, unless reading it is explicitly allowed.
    let edited = temp.path().join("edited.json");
    let text = std::fs::read_to_string(&full).unwrap();
    assert!(text.contains("\"billing\""));
    std::fs::write(&edited, text.replace("\"billing\"", "\"payroll\"")).unwrap();
    let verified = run(premier().arg("verify").arg(&edited));
    assert!(!verified.status.success());
    assert!(
        stderr(&verified).contains("events digest mismatch"),
        "{}",
        stderr(&verified)
    );
    for command in [
        vec!["query".as_ref(), edited.as_os_str()],
        vec!["diff".as_ref(), edited.as_os_str(), trace.as_os_str()],
    ] {
        let refused = run(premier().args(&command));
        assert!(!refused.status.success(), "{command:?}");
        assert!(refused.stdout.is_empty(), "{command:?}");
        assert!(
            stderr(&refused).contains("--allow-unverified"),
            "{}",
            stderr(&refused)
        );
    }
    let allowed = run(premier()
        .arg("query")
        .arg(&edited)
        .args(["--json", "--allow-unverified"]));
    assert!(allowed.status.success(), "{}", stderr(&allowed));
    assert_eq!(json_stdout(&allowed)["source"]["verification"], "failed");

    // Neither a file that is no export, nor an export as an export's source.
    let other = temp.path().join("other.json");
    std::fs::write(&other, "{\"format\": \"something-else\"}").unwrap();
    let refused = run(premier().arg("verify").arg(&other));
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("not a premier export"),
        "{}",
        stderr(&refused)
    );
    let refused = run(premier().arg("export").arg(&full));
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("cannot be exported again"));
}

#[test]
fn an_export_of_a_signed_trace_states_and_checks_its_source_signature() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("signed.atrace");
    evidence_trace(&trace, "baseline");
    let key = temp.path().join("sign.key");
    let other_key = temp.path().join("other.key");
    for path in [&key, &other_key] {
        let generated = run(premier().arg("keygen").arg(path));
        assert!(generated.status.success(), "{}", stderr(&generated));
    }
    let signed = run(premier()
        .arg("sign")
        .arg(&trace)
        .arg("--sign-key")
        .arg(&key));
    assert!(signed.status.success(), "{}", stderr(&signed));
    let export = temp.path().join("signed.json");
    let exported = run(premier().arg("export").arg(&trace).arg("-o").arg(&export));
    assert!(exported.status.success(), "{}", stderr(&exported));

    let verified = run(premier().arg("verify").arg(&export));
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(
        stdout(&verified)
            .contains("source signature: valid for the source seal, by an unknown key sha256:"),
        "{}",
        stdout(&verified)
    );
    let public = |path: &Path| PathBuf::from(format!("{}.pub", path.display()));
    let verified = run(premier()
        .arg("verify")
        .arg(&export)
        .arg("--public-key")
        .arg(public(&key)));
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(
        stdout(&verified).contains("by the supplied key"),
        "{}",
        stdout(&verified)
    );
    let refused = run(premier()
        .arg("verify")
        .arg(&export)
        .arg("--public-key")
        .arg(public(&other_key)));
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("signed by a different key"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn export_refuses_to_write_into_a_trace_directory() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("kept.atrace");
    evidence_trace(&trace, "baseline");
    for target in [
        trace.join("manifest.json"),
        trace.join("export.json"),
        trace.join("events").join("export.json"),
        trace.clone(),
    ] {
        let refused = run(premier().arg("export").arg(&trace).arg("-o").arg(&target));
        assert!(!refused.status.success(), "{}", target.display());
        assert!(
            stderr(&refused).contains("refusing to export to"),
            "{}",
            stderr(&refused)
        );
    }
    premier_trace::verify(&trace).unwrap();
    assert!(!trace.join("export.json").exists());
}

#[test]
fn query_pages_follows_ids_and_marks_an_unfinalized_trace_in_json() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("query.atrace");
    evidence_trace(&trace, "current");
    let query = |args: &[&str]| run(premier().arg("query").arg(&trace).args(args));

    let page = query(&["--limit", "1"]);
    assert!(page.status.success(), "{}", stderr(&page));
    assert!(
        stderr(&page)
            .contains("3 matched; 1 returned (limit reached; continue with --after-sequence 1)"),
        "{}",
        stderr(&page)
    );
    let page = json_stdout(&query(&["--limit", "1", "--after-sequence", "1", "--json"]));
    assert_eq!(page["events"][0]["sequence"], 2);
    assert_eq!(page["truncated"], true);
    assert_eq!(page["next_after_sequence"], 2);
    assert_eq!(
        page["source"],
        json!({"kind": "trace", "finalized": true, "verification": "verified"})
    );

    let by_correlation = json_stdout(&query(&["--correlation", "call-1", "--json"]));
    assert_eq!(by_correlation["matched"], 1);
    assert_eq!(by_correlation["events"][0]["kind"], "tool.execution");
    let children = json_stdout(&query(&["--parent-span", "turn", "--json"]));
    assert_eq!(children["matched"], 1);
    let issues = json_stdout(&query(&["--issues", "--json"]));
    assert_eq!(issues["matched"], 1);
    assert_eq!(issues["events"][0]["status"], "error");
    let window = json_stdout(&query(&[
        "--since",
        "2026-07-15T12:00:01Z",
        "--until",
        "2026-07-15T12:00:02Z",
        "--json",
    ]));
    assert_eq!(window["matched"], 1);
    let refused = query(&["--since", "yesterday"]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("RFC 3339"),
        "{}",
        stderr(&refused)
    );

    let live = temp.path().join("live.atrace");
    let mut writer = TraceWriter::create(&live, vec!["agent".into()]).unwrap();
    writer.append("agent.turn", "test", json!({})).unwrap();
    let result = json_stdout(&run(premier().arg("query").arg(&live).arg("--json")));
    assert_eq!(
        result["source"],
        json!({"kind": "trace", "finalized": false, "verification": "not_finalized"})
    );
    drop(writer);
}

#[test]
fn open_refuses_a_claimed_trace_before_starting_a_server_or_a_browser() {
    let temp = tempfile::tempdir().unwrap();
    let (path, browser_log) = stub_browser(temp.path());
    let trace = temp.path().join("claimed.atrace");
    evidence_trace(&trace, "baseline");
    let claimed = run(premier()
        .arg("claim")
        .arg(&trace)
        .args(["--tenant", "acme"]));
    assert!(claimed.status.success(), "{}", stderr(&claimed));

    let opened = run_to_exit(
        premier()
            .env("PATH", &path)
            .arg("open")
            .arg(&trace)
            .args(["--bind", "127.0.0.1:0", "--no-assistant", "--viewer-dir"])
            .arg(viewer_dir(temp.path())),
        Duration::from_secs(20),
    );
    assert!(!opened.status.success());
    let message = stderr(&opened);
    assert!(message.contains("owned by tenant 'acme'"), "{message}");
    assert!(message.contains("bearer token"), "{message}");
    assert!(
        message.contains("cannot show tenant-owned traces"),
        "{message}"
    );
    assert!(!message.contains("to view it"), "{message}");
    assert!(
        !stdout(&opened).contains("Premier viewer"),
        "{}",
        stdout(&opened)
    );
    assert!(!browser_log.exists(), "the browser was launched");

    // Recording for a tenant no longer suggests the command that cannot work.
    let recorded = run(premier().current_dir(temp.path()).args([
        "record",
        "--tenant",
        "acme",
        "-o",
        "tenant.atrace",
        "--",
        "true",
    ]));
    assert!(recorded.status.success(), "{}", stderr(&recorded));
    let message = stderr(&recorded);
    assert!(!message.contains("next: premier open"), "{message}");
    assert!(message.contains("owned by tenant 'acme'"), "{message}");
    let refused = run(premier().env("PATH", &path).current_dir(temp.path()).args([
        "record",
        "--tenant",
        "acme",
        "--open",
        "-o",
        "never.atrace",
        "--",
        "true",
    ]));
    assert!(!refused.status.success());
    assert!(
        !stderr(&refused).contains("to view it"),
        "{}",
        stderr(&refused)
    );
    assert!(!temp.path().join("never.atrace").exists());
    assert!(!browser_log.exists(), "the browser was launched");
}

#[test]
fn a_busy_port_fails_before_the_browser_is_sent_to_it() {
    let temp = tempfile::tempdir().unwrap();
    let (path, browser_log) = stub_browser(temp.path());
    let viewer = viewer_dir(temp.path());
    let trace_dir = temp.path().join("traces");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = taken.local_addr().unwrap().to_string();

    let opened = run_to_exit(
        premier()
            .env("PATH", &path)
            .arg("open")
            .arg("--trace-dir")
            .arg(&trace_dir)
            .args(["--bind", &address, "--no-assistant", "--viewer-dir"])
            .arg(&viewer),
        Duration::from_secs(20),
    );
    assert!(!opened.status.success());
    assert!(
        stderr(&opened).contains("is already in use"),
        "{}",
        stderr(&opened)
    );
    assert!(stderr(&opened).contains("--bind"), "{}", stderr(&opened));
    assert!(
        !stdout(&opened).contains("Premier viewer"),
        "{}",
        stdout(&opened)
    );
    assert!(
        !browser_log.exists(),
        "the browser was sent to a port premier does not own"
    );

    // `record --open` finds a missing viewer build before running the command.
    let marker = temp.path().join("ran");
    let refused = run(premier()
        .env("PATH", &path)
        .current_dir(temp.path())
        .args(["record", "--open", "-o", "open.atrace", "--viewer-dir"])
        .arg(temp.path().join("no-such-viewer"))
        .args(["--", "touch"])
        .arg(&marker));
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("viewer build not found"),
        "{}",
        stderr(&refused)
    );
    assert!(
        !marker.exists(),
        "the command ran before the viewer was checked"
    );
    assert!(!temp.path().join("open.atrace").exists());

    // With a free port the address is announced, and opened, once it is bound.
    let mut child = premier()
        .env("PATH", &path)
        .arg("open")
        .arg("--trace-dir")
        .arg(&trace_dir)
        .args(["--bind", "127.0.0.1:0", "--no-assistant", "--viewer-dir"])
        .arg(&viewer)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let url = line
        .trim()
        .strip_prefix("Premier viewer: ")
        .unwrap_or_else(|| panic!("{line}"));
    let bound = url.strip_prefix("http://").unwrap();
    assert!(!bound.ends_with(":0"), "{url}");
    stop_serving_viewer(&mut child, bound, &browser_log);
    assert_eq!(std::fs::read_to_string(&browser_log).unwrap().trim(), url);
}

#[test]
fn open_focuses_a_trace_by_its_directory_name() {
    let temp = tempfile::tempdir().unwrap();
    let (path, browser_log) = stub_browser(temp.path());
    let trace = temp.path().join("my run #1.atrace");
    evidence_trace(&trace, "baseline");
    let mut child = premier()
        .env("PATH", &path)
        .arg("open")
        .arg(&trace)
        .args(["--bind", "127.0.0.1:0", "--no-assistant", "--viewer-dir"])
        .arg(viewer_dir(temp.path()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let url = line.trim().strip_prefix("Premier viewer: ").unwrap();
    let address = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap();
    stop_serving_viewer(&mut child, address, &browser_log);
    assert!(url.ends_with("/?trace=my%20run%20%231.atrace"), "{url}");
    assert_eq!(std::fs::read_to_string(&browser_log).unwrap().trim(), url);
}

#[test]
fn demo_replaces_only_an_earlier_demo_and_never_before_the_new_one_is_written() {
    let temp = tempfile::tempdir().unwrap();
    let recording = temp.path().join("real.atrace");
    let trace_id = evidence_trace(&recording, "baseline");

    let refused = run(premier().arg("demo").arg("-o").arg(&recording));
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("not an earlier demo"),
        "{}",
        stderr(&refused)
    );
    assert!(stderr(&refused).contains("--force"), "{}", stderr(&refused));
    assert_eq!(
        premier_trace::verify(&recording).unwrap().trace_id,
        trace_id
    );

    let demo = temp.path().join("demo.atrace");
    for _ in 0..2 {
        let written = run(premier().arg("demo").arg("-o").arg(&demo));
        assert!(written.status.success(), "{}", stderr(&written));
    }
    let first = premier_trace::verify(&demo).unwrap().trace_id;

    // A demo that cannot be written leaves the one already there in place.
    let bad_key = temp.path().join("bad.key");
    std::fs::write(&bad_key, "not a key").unwrap();
    std::fs::set_permissions(&bad_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let failed = run(premier()
        .arg("--key-file")
        .arg(&bad_key)
        .arg("demo")
        .arg("-o")
        .arg(&demo));
    assert!(!failed.status.success());
    assert_eq!(premier_trace::verify(&demo).unwrap().trace_id, first);
    let leftovers: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".demo-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    let forced = run(premier()
        .arg("demo")
        .arg("--force")
        .arg("-o")
        .arg(&recording));
    assert!(forced.status.success(), "{}", stderr(&forced));
    assert_eq!(
        read_manifest(&recording).unwrap().command,
        ["premier", "demo"]
    );
}

#[test]
fn the_demo_reviewer_is_spawned_by_the_coordinator_as_its_payload_says() {
    let temp = tempfile::tempdir().unwrap();
    let demo = temp.path().join("demo.atrace");
    let written = run(premier().arg("demo").arg("-o").arg(&demo));
    assert!(written.status.success(), "{}", stderr(&written));
    let events = read_events(&demo).unwrap();
    let spawn = events
        .iter()
        .find(|event| event.kind == "agent.spawn" && event.actor_id == "reviewer")
        .unwrap();
    assert_eq!(spawn.payload()["parent_actor"], "coordinator");
    let parent = events
        .iter()
        .find(|event| event.event_id == spawn.parent_event_id)
        .unwrap();
    assert_eq!(parent.actor_id, "coordinator");
    // The patch under review is linked, not made the spawn's cause.
    let patch = events
        .iter()
        .find(|event| event.payload()["tool"] == "apply_patch")
        .unwrap();
    assert_eq!(spawn.links, std::slice::from_ref(&patch.event_id));
    assert!(read_manifest(&demo).unwrap().diagnostics.is_empty());
}

#[test]
fn list_shows_how_a_run_ended_and_where_it_is_stored() {
    let temp = tempfile::tempdir().unwrap();
    let failed = record(temp.path(), "failed.atrace", "exit 3", &[]);
    assert_eq!(failed.status.code(), Some(3));
    let passed = record(temp.path(), "passed.atrace", "exit 0", &[]);
    assert!(passed.status.success());
    // Working copies are not traces.
    std::fs::create_dir_all(temp.path().join(".passed.atrace.encrypt-1.tmp")).unwrap();
    std::fs::copy(
        temp.path().join("passed.atrace").join("manifest.json"),
        temp.path()
            .join(".passed.atrace.encrypt-1.tmp")
            .join("manifest.json"),
    )
    .unwrap();
    let listed = run(premier().arg("list").arg("--trace-dir").arg(temp.path()));
    assert!(listed.status.success(), "{}", stderr(&listed));
    let text = stdout(&listed);
    let line = |name: &str| {
        text.lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name} is not listed: {text}"))
            .to_owned()
    };
    assert!(line("(failed.atrace)").contains("[exit 3]"), "{text}");
    assert!(!line("(passed.atrace)").contains("[exit"), "{text}");
    assert_eq!(text.lines().count(), 2, "{text}");
}

#[test]
fn an_adapter_given_plain_text_says_so_once_instead_of_once_per_line() {
    let temp = tempfile::tempdir().unwrap();
    let recorded = run(premier()
        .current_dir(temp.path())
        .args(["record", "--adapter", "claude", "-o", "plain.atrace", "--"])
        .args([
            "sh",
            "-c",
            "i=0; while [ $i -lt 60 ]; do echo \"plain line $i\"; i=$((i+1)); done",
        ]));
    assert!(recorded.status.success(), "{}", stderr(&recorded));
    let message = stderr(&recorded);
    assert!(
        message.contains("the claude adapter found no native JSONL events in 60 line(s) of output"),
        "{message}"
    );
    let trace = temp.path().join("plain.atrace");
    let events = read_events(&trace).unwrap();
    let count = |kind: &str| events.iter().filter(|event| event.kind == kind).count();
    assert_eq!(count("adapter.diagnostic"), 20);
    assert_eq!(count("adapter.summary"), 1);
    let summary = events
        .iter()
        .find(|event| event.kind == "adapter.summary")
        .unwrap()
        .payload();
    assert_eq!(summary["lines"], 60);
    assert_eq!(summary["normalized_lines"], 0);
    assert_eq!(summary["suppressed_diagnostics"], 40);
    let manifest = premier_trace::verify(&trace).unwrap();
    assert_eq!(manifest.adapter.unwrap().completeness, "no-native-events");

    // A stream of native events is recorded as before, with nothing to report.
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/adapters/claude.jsonl");
    let recorded = run(premier()
        .current_dir(temp.path())
        .args([
            "record",
            "--adapter",
            "claude",
            "-o",
            "native.atrace",
            "--",
            "cat",
        ])
        .arg(&fixture));
    assert!(recorded.status.success(), "{}", stderr(&recorded));
    assert!(
        !stderr(&recorded).contains("adapter"),
        "{}",
        stderr(&recorded)
    );
    let trace = temp.path().join("native.atrace");
    assert!(
        read_events(&trace)
            .unwrap()
            .iter()
            .all(|event| event.kind != "adapter.summary")
    );
    assert_eq!(
        read_manifest(&trace).unwrap().adapter.unwrap().completeness,
        "provider-native-best-effort"
    );
}
