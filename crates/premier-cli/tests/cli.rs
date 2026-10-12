use premier_trace::read_events;
#[cfg(unix)]
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

fn evidence_trace(path: &std::path::Path, variant: &str) {
    let mut writer = premier_trace::TraceWriter::create_named(
        path,
        vec!["agent".into(), "run".into()],
        Some(format!("{variant} evidence")),
    )
    .unwrap();
    writer
        .append_input(premier_trace::EventInput {
            kind: "agent.turn".into(),
            actor_id: "coordinator".into(),
            actor_type: "agent".into(),
            status: "running".into(),
            payload: serde_json::json!({"task": "inspect billing", "api_key": "top-secret"}),
            timestamp: Some("2026-07-15T12:00:00Z".into()),
            ..Default::default()
        })
        .unwrap();
    writer
        .append_input(premier_trace::EventInput {
            kind: "tool.execution".into(),
            actor_id: "researcher".into(),
            actor_type: "subagent".into(),
            status: if variant == "current" {
                "warning".into()
            } else {
                "ok".into()
            },
            duration_ms: if variant == "current" { 240 } else { 100 },
            payload: serde_json::json!({
                "tool": "search",
                "query": if variant == "current" { "invoices" } else { "billing" },
                "headers": {"Authorization": "Bearer hidden"},
                "nested": [{"client_secret": "also-hidden"}]
            }),
            timestamp: Some("2026-07-15T12:00:00.100Z".into()),
            ..Default::default()
        })
        .unwrap();
    if variant == "current" {
        writer
            .append_input(premier_trace::EventInput {
                kind: "agent.result".into(),
                actor_id: "coordinator".into(),
                actor_type: "agent".into(),
                status: "ok".into(),
                payload: serde_json::json!({"result": "done"}),
                timestamp: Some("2026-07-15T12:00:00.200Z".into()),
                ..Default::default()
            })
            .unwrap();
    }
    writer.finish(0).unwrap();
}

#[test]
fn query_filters_local_events_and_bounds_json_results() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("query.atrace");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("query")
        .arg(&trace)
        .args([
            "--actor",
            "researcher",
            "--kind",
            "tool.execution",
            "--status",
            "ok",
            "--search",
            "billing",
            "--limit",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["matched"], 1);
    assert_eq!(result["returned"], 1);
    assert_eq!(result["events"][0]["kind"], "tool.execution");
    assert_eq!(result["events"][0]["actor_id"], "researcher");
}

/// Make a finalized trace fail `premier verify` while leaving its journal decodable.
fn break_journal_digest(trace: &std::path::Path) {
    let path = trace.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["journal"]["sha256"] = serde_json::json!("0".repeat(64));
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    assert!(premier_trace::verify(trace).is_err());
}

#[test]
fn query_and_export_refuse_an_unverifiable_trace_unless_explicitly_allowed() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("tampered.atrace");
    evidence_trace(&trace, "baseline");
    break_journal_digest(&trace);
    let premier = env!("CARGO_BIN_EXE_premier");
    let exported = temp.path().join("evidence.json");

    let query = Command::new(premier)
        .arg("query")
        .arg(&trace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!query.status.success(), "query must fail closed");
    assert!(query.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&query.stderr);
    assert!(stderr.contains("failed verification"), "{stderr}");
    assert!(stderr.contains("journal digest mismatch"), "{stderr}");
    assert!(stderr.contains("--allow-unverified"), "{stderr}");

    let export = Command::new(premier)
        .arg("export")
        .arg(&trace)
        .arg("--output")
        .arg(&exported)
        .output()
        .unwrap();
    assert!(!export.status.success(), "export must fail closed");
    assert!(!exported.exists());
    assert!(String::from_utf8_lossy(&export.stderr).contains("--allow-unverified"));

    let query = Command::new(premier)
        .arg("query")
        .arg(&trace)
        .args(["--json", "--allow-unverified"])
        .output()
        .unwrap();
    assert!(
        query.status.success(),
        "{}",
        String::from_utf8_lossy(&query.stderr)
    );
    let stderr = String::from_utf8_lossy(&query.stderr);
    assert!(stderr.contains("warning"), "{stderr}");
    assert!(stderr.contains("failed verification"), "{stderr}");
    let result: serde_json::Value = serde_json::from_slice(&query.stdout).unwrap();
    assert_eq!(result["matched"], 2);

    let export = Command::new(premier)
        .arg("export")
        .arg(&trace)
        .arg("--allow-unverified")
        .arg("--output")
        .arg(&exported)
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(String::from_utf8_lossy(&export.stderr).contains("failed verification"));
    assert!(exported.exists());
}

#[test]
fn query_and_export_read_a_live_trace_with_a_stderr_note() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("live.atrace");
    let mut writer = premier_trace::TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    writer
        .append("agent.turn", "test", serde_json::json!({"live": true}))
        .unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");
    for command in ["query", "export"] {
        let output = Command::new(premier)
            .arg(command)
            .arg(&trace)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{command}: {stderr}");
        assert!(stderr.contains("not finalized"), "{command}: {stderr}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("agent.turn"));
    }
    drop(writer);
}

#[test]
fn verify_reports_an_unfinalized_trace_without_panicking() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("live.atrace");
    let writer = premier_trace::TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("verify")
        .arg(&trace)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not finalized"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    drop(writer);
}

#[test]
fn query_rejects_an_unbounded_limit() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("query-limit.atrace");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("query")
        .arg(&trace)
        .args(["--limit", "1001", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("between 1 and 1000"));
}

#[test]
fn export_writes_portable_json_with_recursive_secret_redaction() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("export.atrace");
    let exported = temp.path().join("evidence.json");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("export")
        .arg(&trace)
        .args(["--output"])
        .arg(&exported)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(exported).unwrap();
    assert!(!text.contains("top-secret"));
    assert!(!text.contains("Bearer hidden"));
    assert!(!text.contains("also-hidden"));
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["format"], "premier.portable-evidence.v1");
    assert_eq!(document["events"][0]["payload"]["api_key"], "[REDACTED]");
    assert_eq!(
        document["events"][1]["payload"]["headers"]["Authorization"],
        "[REDACTED]"
    );
    assert_eq!(
        document["events"][1]["payload"]["nested"][0]["client_secret"],
        "[REDACTED]"
    );
}

#[test]
fn diff_uses_semantic_structure_and_ignores_generated_trace_identity() {
    let temp = tempfile::tempdir().unwrap();
    let baseline = temp.path().join("baseline.atrace");
    let current = temp.path().join("current.atrace");
    evidence_trace(&baseline, "baseline");
    evidence_trace(&current, "current");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("diff")
        .arg(&baseline)
        .arg(&current)
        .args(["--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["counts"]["unchanged"], 1);
    assert_eq!(result["counts"]["changed"], 1);
    assert_eq!(result["counts"]["added"], 1);
    assert_eq!(result["counts"]["removed"], 0);
    let changed = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["status"] == "changed")
        .unwrap();
    assert!(
        changed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["field"] == "duration_ms")
    );
    assert!(
        changed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["field"] == "payload.query")
    );
}

#[test]
fn replay_is_explicitly_non_execution_and_can_skip_timing_delays() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("replay.atrace");
    evidence_trace(&trace, "baseline");
    let output = Command::new(env!("CARGO_BIN_EXE_premier"))
        .arg("replay")
        .arg(&trace)
        .arg("--no-sleep")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("NON-EXECUTION evidence replay"));
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[0]).unwrap()["sequence"],
        1
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&lines[1]).unwrap()["sequence"],
        2
    );
}

#[test]
fn records_and_verifies_a_real_command() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("cli.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--name", "CLI smoke test", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "printf premier-e2e"])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), "premier-e2e");
    assert_eq!(
        premier_trace::read_manifest(&trace)
            .unwrap()
            .name
            .as_deref(),
        Some("CLI smoke test")
    );

    let verified = Command::new(premier)
        .arg("verify")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    // No signing key was configured, so the trace is only self-consistent.
    assert!(
        String::from_utf8_lossy(&verified.stdout)
            .contains("consistent: chain and seal valid, unsigned")
    );
}

#[test]
fn child_process_can_emit_subagent_events_through_the_local_collector() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("agent.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let script = r#"curl -sS -X POST -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" -H "Content-Type: application/json" --data '{"kind":"agent.spawn","actor_id":"researcher","actor_type":"subagent","span_id":"research","parent_span_id":"root","status":"running","payload":{"task":"investigate"}}' "$PREMIER_COLLECTOR_URL" >/dev/null"#;
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", script])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let events = read_events(&trace).unwrap();
    let spawned = events
        .iter()
        .find(|event| event.kind == "agent.spawn")
        .unwrap();
    assert_eq!(spawned.actor_id, "researcher");
    assert_eq!(spawned.parent_span_id, "root");
}

#[test]
fn native_adapter_preserves_stdout_and_adds_normalized_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("native-adapter.atrace");
    let fixture = include_str!("fixtures/adapters/codex.jsonl");
    let fixture_path = temp.path().join("codex.jsonl");
    std::fs::write(&fixture_path, fixture).unwrap();
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--adapter", "codex", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "cat \"$1\"", "sh"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), fixture);
    let events = read_events(&trace).unwrap();
    let raw: String = events
        .iter()
        .filter(|event| event.kind == "process.stdout")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(raw, fixture);
    assert!(
        events
            .iter()
            .any(|event| { event.kind == "tool.result" && event.source == "adapter.codex.v1" })
    );
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(manifest.capabilities.contains(&"adapter.codex.v1".into()));
    assert_eq!(manifest.adapter.unwrap().provider, "codex");
}

#[test]
fn malformed_native_output_is_diagnostic_and_does_not_fail_recording() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("malformed-adapter.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--adapter", "gemini", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "printf 'not-json\\n'"])
        .output()
        .unwrap();
    assert!(recorded.status.success());
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), "not-json\n");
    let diagnostic = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "adapter.diagnostic")
        .unwrap();
    assert_eq!(diagnostic.status, "warning");
    assert_eq!(diagnostic.source, "adapter.gemini.v1");
}

#[cfg(unix)]
#[test]
fn auto_adapter_detects_a_structured_provider_command() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("auto-adapter.atrace");
    let executable = temp.path().join("codex");
    let fixture = include_str!("fixtures/adapters/codex.jsonl");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            fixture.replace('\u{27}', "'\\''")
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&executable, permissions).unwrap();
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--output"])
        .arg(&trace)
        .arg(&executable)
        .args(["exec", "--json"])
        .output()
        .unwrap();
    assert!(recorded.status.success());
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.adapter.unwrap().provider, "codex");
    assert!(
        read_events(&trace)
            .unwrap()
            .iter()
            .any(|event| event.source == "adapter.codex.v1")
    );
}

#[test]
fn record_redacts_collector_payloads_and_documents_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("redacted-agent.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let script = r#"curl -sS -X POST -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" -H "Content-Type: application/json" --data '{"kind":"tool.execution","payload":{"authorization":"Bearer collector-secret","nested":[{"password":"nested-secret","account_pin":"4815"}]}}' "$PREMIER_COLLECTOR_URL" >/dev/null"#;
    let recorded = Command::new(premier)
        .args(["record", "--redact-field", "account_pin", "--output"])
        .arg(&trace)
        .args(["sh", "-c", script])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    let journal = std::fs::read(trace.join("events/000001.events.pb.zst")).unwrap();
    assert!(!String::from_utf8_lossy(&journal).contains("collector-secret"));
    let event = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "tool.execution")
        .unwrap();
    assert_eq!(event.payload()["authorization"], "[REDACTED]");
    assert_eq!(event.payload()["nested"][0]["password"], "[REDACTED]");
    assert_eq!(event.payload()["nested"][0]["account_pin"], "[REDACTED]");
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.redaction.unwrap().custom_fields,
        vec!["account_pin"]
    );
}

#[test]
fn record_only_redacts_terminal_text_with_explicit_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("redacted-terminal.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args([
            "record",
            "--redact-literal",
            "literal-secret",
            "--redact-regex",
            "token=[A-Za-z0-9-]+",
            "--output",
        ])
        .arg(&trace)
        .args(["sh", "-c", "printf 'literal-secret token=regex-secret'"])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        "literal-secret token=regex-secret"
    );
    let stored: String = read_events(&trace)
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "process.stdout")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(stored, "[REDACTED] [REDACTED]");
    let provenance = premier_trace::read_manifest(&trace)
        .unwrap()
        .redaction
        .unwrap();
    assert_eq!(provenance.terminal_literal_count, 1);
    assert_eq!(provenance.terminal_regex_count, 1);
}

#[test]
fn child_process_can_emit_via_premier_emit_cli() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("emit-cli.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    // Use the same binary via PATH so the child can invoke `premier emit`.
    let bin_dir = std::path::Path::new(premier)
        .parent()
        .expect("cargo bin dir");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "premier emit --kind agent.spawn --actor researcher --actor-type subagent --span research --parent-span root --status running --payload '{\"task\":\"investigate\"}'",
        ])
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );
    let events = read_events(&trace).unwrap();
    let spawned = events
        .iter()
        .find(|event| event.kind == "agent.spawn")
        .expect("agent.spawn event");
    assert_eq!(spawned.actor_id, "researcher");
    assert_eq!(spawned.actor_type, "subagent");
    assert_eq!(spawned.parent_span_id, "root");
}

#[test]
fn demo_creates_a_verifiable_multi_agent_trace() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("demo.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let generated = Command::new(premier)
        .args(["demo", "--output"])
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let events = read_events(&trace).unwrap();
    assert!(events.iter().any(|event| event.kind == "agent.delegation"));
    assert!(events.iter().any(|event| event.kind == "approval.decision"));
    assert!(events.iter().any(|event| event.actor_type == "subagent"));
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(
        manifest.diagnostics.is_empty(),
        "{:?}",
        manifest.diagnostics
    );
}

#[test]
fn first_party_adapter_fixtures_validate_without_lifecycle_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    for provider in [
        "claude", "codex", "droid", "gemini", "grok", "kimi", "opencode",
    ] {
        let trace = temp.path().join(format!("{provider}.atrace"));
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/adapters")
            .join(format!("{provider}.jsonl"));
        let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
            .args(["record", "--adapter", provider, "--output"])
            .arg(&trace)
            .args(["sh", "-c", "cat \"$1\"", "sh"])
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            recorded.status.success(),
            "{}",
            String::from_utf8_lossy(&recorded.stderr)
        );
        let source = format!("adapter.{provider}.v1");
        let events = read_events(&trace).unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.source == source && event.kind != "adapter.diagnostic")
        );
        assert!(
            !events
                .iter()
                .any(|event| event.kind == "adapter.diagnostic")
        );
        let manifest = premier_trace::read_manifest(&trace).unwrap();
        assert!(
            manifest.diagnostics.is_empty(),
            "{provider}: {:?}",
            manifest.diagnostics
        );
    }
}

#[test]
fn demo_refuses_to_delete_an_arbitrary_existing_directory() {
    let temp = tempfile::tempdir().unwrap();
    let precious = temp.path().join("user-project");
    std::fs::create_dir_all(&precious).unwrap();
    std::fs::write(precious.join("important.txt"), "keep me").unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");
    let generated = Command::new(premier)
        .args(["demo", "--output"])
        .arg(&precious)
        .output()
        .unwrap();
    assert!(
        !generated.status.success(),
        "demo must not succeed against a non-trace directory"
    );
    let stderr = String::from_utf8_lossy(&generated.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "stderr should explain refusal: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(precious.join("important.txt")).unwrap(),
        "keep me"
    );
}

#[test]
fn demo_refuses_a_foreign_directory_that_contains_a_manifest_json() {
    let temp = tempfile::tempdir().unwrap();
    let extension = temp.path().join("my-extension");
    std::fs::create_dir_all(extension.join("src")).unwrap();
    std::fs::write(
        extension.join("manifest.json"),
        r#"{"manifest_version":3,"name":"My extension"}"#,
    )
    .unwrap();
    std::fs::write(extension.join("src").join("main.js"), "keep me").unwrap();
    let generated = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["demo", "--output"])
        .arg(&extension)
        .output()
        .unwrap();
    assert!(!generated.status.success());
    assert!(String::from_utf8_lossy(&generated.stderr).contains("refusing to overwrite"));
    assert_eq!(
        std::fs::read_to_string(extension.join("src").join("main.js")).unwrap(),
        "keep me"
    );
}

#[test]
fn demo_refuses_to_replace_the_current_directory_even_when_it_is_a_trace() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("cwd.atrace");
    premier_trace::TraceWriter::create(&trace, vec!["agent".into()])
        .unwrap()
        .finish(0)
        .unwrap();
    let generated = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["demo", "--output", "."])
        .current_dir(&trace)
        .output()
        .unwrap();
    assert!(!generated.status.success());
    let stderr = String::from_utf8_lossy(&generated.stderr);
    assert!(stderr.contains("current directory"), "{stderr}");
    premier_trace::verify(&trace).unwrap();
}

#[test]
fn demo_may_replace_an_existing_trace_directory() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("demo.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    for _ in 0..2 {
        let generated = Command::new(premier)
            .args(["demo", "--output"])
            .arg(&trace)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
    }
    assert!(read_events(&trace).unwrap().len() > 5);
}

#[test]
fn record_preserves_multibyte_utf8_check_marks() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("utf8.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    // 400 check marks exercise multi-byte sequences across 8 KiB pump chunks.
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "python3",
            "-c",
            "import sys; sys.stdout.buffer.write(('✓'*400).encode())",
        ])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let events = read_events(&trace).unwrap();
    let stdout: String = events
        .iter()
        .filter(|event| event.kind == "process.stdout")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert_eq!(stdout.chars().filter(|&c| c == '✓').count(), 400);
    assert!(
        !stdout.contains('\u{FFFD}'),
        "must not inject replacement characters into valid UTF-8"
    );
}

#[cfg(unix)]
#[test]
fn pty_record_exposes_a_terminal_and_records_merged_ordered_output() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("pty.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--pty", "--output"])
        .arg(&trace)
        .args([
            "python3",
            "-c",
            "import os,sys; print(f'TTY={os.isatty(0)},{os.isatty(1)},{os.isatty(2)}'); sys.stdout.write('OUT-'); sys.stdout.flush(); sys.stderr.write('ERR-'); sys.stderr.flush(); sys.stdout.write('DONE' + '✓'*400); sys.stdout.flush()",
        ])
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(
        manifest
            .capabilities
            .iter()
            .any(|item| item == "terminal.pty")
    );
    assert!(
        manifest
            .capabilities
            .iter()
            .any(|item| item == "terminal.merged-output")
    );
    let events = read_events(&trace).unwrap();
    let start = events
        .iter()
        .find(|event| event.kind == "session.start")
        .expect("session.start");
    assert_eq!(start.payload()["terminal"]["mode"], "pty");
    assert!(start.payload()["terminal"]["rows"].as_u64().unwrap() > 0);
    assert!(start.payload()["terminal"]["cols"].as_u64().unwrap() > 0);
    let terminal: String = events
        .iter()
        .filter(|event| event.kind == "process.terminal")
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect();
    assert!(terminal.contains("TTY=True,True,True"), "{terminal:?}");
    assert!(terminal.contains("OUT-ERR-DONE"), "{terminal:?}");
    assert_eq!(
        terminal
            .chars()
            .filter(|character| *character == '✓')
            .count(),
        400
    );
    assert!(!terminal.contains('\u{FFFD}'));
}

#[cfg(unix)]
#[test]
fn pty_record_finalizes_exact_exit_and_signal_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");

    let exit_trace = temp.path().join("pty-exit.atrace");
    let exited = Command::new(premier)
        .args(["record", "--pty", "--output"])
        .arg(&exit_trace)
        .args(["sh", "-c", "exit 37"])
        .output()
        .unwrap();
    assert_eq!(exited.status.code(), Some(37));
    premier_trace::verify(&exit_trace).unwrap();
    let exit_manifest = premier_trace::read_manifest(&exit_trace).unwrap();
    assert_eq!(exit_manifest.exit_code, Some(37));
    assert_eq!(
        exit_manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Exit
    );

    let signal_trace = temp.path().join("pty-signal.atrace");
    let signaled = Command::new(premier)
        .args(["record", "--pty", "--output"])
        .arg(&signal_trace)
        .args(["sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    assert_eq!(signaled.status.code(), Some(143));
    premier_trace::verify(&signal_trace).unwrap();
    let signal_manifest = premier_trace::read_manifest(&signal_trace).unwrap();
    assert_eq!(signal_manifest.exit_code, Some(143));
    let termination = signal_manifest.termination.unwrap();
    assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
    assert_eq!(termination.signal, Some(15));
    assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
}

#[cfg(unix)]
#[test]
fn record_preserves_exact_child_signal_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("signal.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();

    assert!(!recorded.status.success());
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(143));
    let termination = manifest.termination.expect("termination metadata");
    assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
    assert_eq!(termination.signal, Some(15));
    assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
    let exit = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "process.exit")
        .expect("process.exit event");
    assert_eq!(exit.payload()["exit_code"], 143);
    assert_eq!(exit.payload()["signal"], 15);
    assert_eq!(exit.payload()["signal_name"], "SIGTERM");
    assert_eq!(exit.payload()["termination"], "signal");
}

#[test]
fn record_returns_the_child_exit_code_after_finalization() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("exit-37.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let recorded = Command::new(premier)
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "exit 37"])
        .output()
        .unwrap();

    assert_eq!(recorded.status.code(), Some(37));
    premier_trace::verify(&trace).unwrap();
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(37));
    assert_eq!(
        manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Exit
    );
}

#[test]
fn recover_command_requires_force_for_a_fresh_trace_then_finalizes_it() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("abandoned.atrace");
    let mut writer = premier_trace::TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "test", serde_json::json!({"live": true}))
        .unwrap();
    drop(writer);
    let premier = env!("CARGO_BIN_EXE_premier");

    let guarded = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(!guarded.status.success());
    assert!(
        String::from_utf8_lossy(&guarded.stderr).contains("appears active"),
        "{}",
        String::from_utf8_lossy(&guarded.stderr)
    );

    let recovered = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(String::from_utf8_lossy(&recovered.stdout).contains("recovered"));
    premier_trace::verify(&trace).unwrap();
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Interrupted
    );
}

#[cfg(unix)]
#[test]
fn recorder_sigterm_is_forwarded_and_finalized_without_timing_races() {
    assert_recorder_signal_is_forwarded("-TERM", 15, 143, false);
}

#[cfg(unix)]
#[test]
fn recorder_sigint_is_forwarded_and_finalized_without_timing_races() {
    assert_recorder_signal_is_forwarded("-INT", 2, 130, false);
}

#[cfg(unix)]
#[test]
fn pty_recorder_sigterm_is_forwarded_to_the_process_group_and_finalized() {
    assert_recorder_signal_is_forwarded("-TERM", 15, 143, true);
}

#[cfg(unix)]
fn assert_recorder_signal_is_forwarded(
    kill_argument: &str,
    expected_signal: i32,
    expected_exit_code: i32,
    pty: bool,
) {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("forwarded-signal.atrace");
    let premier = env!("CARGO_BIN_EXE_premier");
    let mut command = Command::new(premier);
    command.arg("record");
    if pty {
        command.arg("--pty");
    }
    let mut recorder = command
        .arg("--output")
        .arg(&trace)
        .args(["sh", "-c", "printf 'READY %s\\n' \"$$\"; exec sleep 300"])
        // A recorder in its terminal's foreground process group treats SIGINT
        // as Ctrl-C; a supervised recorder is not in the foreground.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Reading the child's output through Premier proves the child is running
    // and Premier's signal forwarder has already been installed.
    let mut stdout = BufReader::new(recorder.stdout.take().unwrap());
    let mut ready = String::new();
    while !ready.contains("READY ") {
        let mut line = String::new();
        assert!(stdout.read_line(&mut line).unwrap() > 0, "readiness EOF");
        ready.push_str(&line);
    }
    let ready_marker = ready.find("READY ").expect("child readiness marker");
    let child_pid = ready[ready_marker..]
        .trim()
        .strip_prefix("READY ")
        .unwrap()
        .parse::<u32>()
        .expect("child pid");

    let signal = Command::new("kill")
        .args([kill_argument, &recorder.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let status = recorder.wait().unwrap();

    assert_eq!(status.code(), Some(expected_exit_code));
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(expected_exit_code));
    let termination = manifest.termination.expect("termination metadata");
    assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
    assert_eq!(termination.signal, Some(expected_signal));
    let events = read_events(&trace).unwrap();
    let exit = events
        .iter()
        .find(|event| event.kind == "process.exit")
        .expect("process.exit event");
    assert_eq!(exit.payload()["termination"], "signal");
    assert_eq!(exit.payload()["signal"], expected_signal);
    assert_eq!(exit.payload()["forwarded_by_recorder"], true);
    premier_trace::verify(&trace).unwrap();
    assert!(!trace.join(premier_trace::RECORDER_LEASE).exists());
    let child_still_exists = Command::new("kill")
        .args(["-0", &child_pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !child_still_exists.success(),
        "recorded child was not reaped"
    );
}

/// Spawn `premier record` around a shell script that prints `READY` once it
/// is running, and wait for that marker through Premier's mirrored stdout.
#[cfg(unix)]
fn spawn_ready_recorder(
    trace: &std::path::Path,
    pty: bool,
    stop_grace_ms: &str,
    script: &str,
) -> (std::process::Child, BufReader<std::process::ChildStdout>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_premier"));
    command.arg("record");
    if pty {
        command.arg("--pty");
    }
    let mut recorder = command
        .arg("--output")
        .arg(trace)
        .args(["sh", "-c", script])
        .env("PREMIER_STOP_GRACE_MS", stop_grace_ms)
        // Keep the recorder out of the terminal's foreground process group,
        // like a supervised recorder, even when the tests run interactively.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(recorder.stdout.take().unwrap());
    let mut line = String::new();
    while !line.contains("READY") {
        line.clear();
        assert!(stdout.read_line(&mut line).unwrap() > 0, "readiness EOF");
    }
    (recorder, stdout)
}

#[cfg(unix)]
fn signal_process(kill_argument: &str, pid: u32) {
    // The target may already be gone when signals are sent repeatedly.
    let _ = Command::new("kill")
        .args([kill_argument, &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .unwrap();
}

/// Wait for the recorder without letting a regression hang the test suite.
#[cfg(unix)]
fn wait_bounded(
    recorder: &mut std::process::Child,
    mut while_waiting: impl FnMut(),
) -> std::process::ExitStatus {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = recorder.try_wait().unwrap() {
            return status;
        }
        if started.elapsed() > std::time::Duration::from_secs(30) {
            recorder.kill().unwrap();
            panic!("recorder did not stop within 30s");
        }
        while_waiting();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn process_exit_payload(trace: &std::path::Path) -> serde_json::Value {
    read_events(trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "process.exit")
        .expect("process.exit event")
        .payload()
}

#[cfg(unix)]
#[test]
fn recorder_signal_keeps_the_exit_status_of_a_child_that_handles_it() {
    for (pty, exit_code) in [(false, 0), (false, 7), (true, 0)] {
        let temp = tempfile::tempdir().unwrap();
        let trace = temp.path().join("handled-signal.atrace");
        let script = format!(
            "trap 'echo cleaned; exit {exit_code}' TERM; echo READY; while :; do sleep 0.1; done"
        );
        let (mut recorder, _stdout) = spawn_ready_recorder(&trace, pty, "60000", &script);
        signal_process("-TERM", recorder.id());
        let status = wait_bounded(&mut recorder, || {});

        assert_eq!(status.code(), Some(exit_code), "pty={pty}");
        premier_trace::verify(&trace).unwrap();
        let manifest = premier_trace::read_manifest(&trace).unwrap();
        assert_eq!(manifest.exit_code, Some(exit_code));
        let termination = manifest.termination.expect("termination metadata");
        assert_eq!(termination.kind, premier_trace::TerminationKind::Exit);
        let exit = process_exit_payload(&trace);
        assert_eq!(exit["termination"], "exit");
        assert_eq!(exit["exit_code"], exit_code);
        assert_eq!(exit["recorder_signal"], libc::SIGTERM);
        assert_eq!(exit["recorder_signal_name"], "SIGTERM");
        assert_eq!(exit["forwarded_by_recorder"], true);
    }
}

#[cfg(unix)]
#[test]
fn terminal_interrupt_reaches_a_pipe_mode_child_exactly_once() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("ctrl-c.atrace");
    // Make the recorder the foreground job of a real controlling terminal,
    // press Ctrl-C once, and count C-level SIGINT deliveries in the child.
    let driver = r#"
import os, pty, sys
premier, trace = sys.argv[1], sys.argv[2]
child = r'''
import os, signal, time
reader, writer = os.pipe()
os.set_blocking(writer, False)
os.set_blocking(reader, False)
signal.set_wakeup_fd(writer, warn_on_full_buffer=False)
signal.signal(signal.SIGINT, lambda *_: None)
print("READY", flush=True)
seen = b""
deadline = time.time() + 20
while not seen and time.time() < deadline:
    time.sleep(0.05)
    try:
        seen += os.read(reader, 64)
    except BlockingIOError:
        pass
time.sleep(1.0)
try:
    seen += os.read(reader, 64)
except BlockingIOError:
    pass
print(f"SIGINT_DELIVERIES={len(seen)}", flush=True)
'''
pid, fd = pty.fork()
if pid == 0:
    os.execv(premier, [premier, "record", "--output", trace, "--", sys.executable, "-c", child])
output = b""
pressed = False
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    output += chunk
    if not pressed and b"READY" in output:
        os.write(fd, b"\x03")
        pressed = True
_, status = os.waitpid(pid, 0)
sys.stdout.write(output.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
"#;
    let driven = Command::new("python3")
        .args(["-c", driver, env!("CARGO_BIN_EXE_premier")])
        .arg(&trace)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&driven.stdout);
    assert!(output.contains("SIGINT_DELIVERIES=1"), "{output}");
    // The child handled the interrupt and finished normally.
    assert_eq!(driven.status.code(), Some(0), "{output}");
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(0));
    assert_eq!(
        process_exit_payload(&trace)["recorder_signal"],
        libc::SIGINT
    );
}

#[cfg(unix)]
#[test]
fn recorder_sigterm_escalates_to_sigkill_when_the_child_ignores_it() {
    for pty in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let trace = temp.path().join("ignored-term.atrace");
        let (mut recorder, _stdout) = spawn_ready_recorder(
            &trace,
            pty,
            "300",
            "trap '' TERM; echo READY; exec sleep 300",
        );
        signal_process("-TERM", recorder.id());
        let status = wait_bounded(&mut recorder, || {});

        assert_eq!(status.code(), Some(128 + libc::SIGKILL), "pty={pty}");
        premier_trace::verify(&trace).unwrap();
        let termination = premier_trace::read_manifest(&trace)
            .unwrap()
            .termination
            .expect("termination metadata");
        assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
        assert_eq!(termination.signal, Some(libc::SIGKILL));
        assert_eq!(termination.signal_name.as_deref(), Some("SIGKILL"));
        let exit = process_exit_payload(&trace);
        assert_eq!(exit["recorder_signal"], libc::SIGTERM);
        assert_eq!(exit["killed_by_recorder"], true);
    }
}

#[cfg(unix)]
#[test]
fn repeated_recorder_sigint_kills_a_child_that_ignores_it() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("ignored-int.atrace");
    let (mut recorder, _stdout) = spawn_ready_recorder(
        &trace,
        false,
        "60000",
        "trap '' INT; echo READY; exec sleep 300",
    );
    let recorder_pid = recorder.id();
    let status = wait_bounded(&mut recorder, || signal_process("-INT", recorder_pid));

    assert_eq!(status.code(), Some(128 + libc::SIGKILL));
    premier_trace::verify(&trace).unwrap();
    let exit = process_exit_payload(&trace);
    assert_eq!(exit["signal"], libc::SIGKILL);
    assert_eq!(exit["recorder_signal"], libc::SIGINT);
    assert_eq!(exit["killed_by_recorder"], true);
}

#[cfg(unix)]
#[test]
fn record_finalizes_when_a_descendant_keeps_the_output_pipe_open() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("held-pipe.atrace");
    let started = std::time::Instant::now();
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "sleep 20 & echo done; exit 3"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .unwrap();

    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "recorder waited for the descendant: {:?}",
        started.elapsed()
    );
    assert_eq!(recorded.code(), Some(3));
    premier_trace::verify(&trace).unwrap();
    let events = read_events(&trace).unwrap();
    assert!(events.iter().any(|event| event.kind == "process.stdout"
        && event.payload()["text"].as_str().unwrap().contains("done")));
    let exit = process_exit_payload(&trace);
    assert_eq!(exit["exit_code"], 3);
    assert_eq!(exit["output_open_at_exit"], true);
}

#[cfg(unix)]
#[test]
fn record_names_signals_with_the_platform_numbering_in_both_capture_modes() {
    let premier = env!("CARGO_BIN_EXE_premier");
    for pty in [false, true] {
        for (kill_name, number, name) in [
            ("USR1", libc::SIGUSR1, "SIGUSR1"),
            ("USR2", libc::SIGUSR2, "SIGUSR2"),
            ("BUS", libc::SIGBUS, "SIGBUS"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let trace = temp.path().join("named-signal.atrace");
            let mut command = Command::new(premier);
            command.arg("record");
            if pty {
                command.arg("--pty");
            }
            let recorded = command
                .arg("--output")
                .arg(&trace)
                .args(["sh", "-c", &format!("ulimit -c 0; kill -{kill_name} $$")])
                .stdin(Stdio::null())
                .output()
                .unwrap();

            assert_eq!(
                recorded.status.code(),
                Some(128 + number),
                "pty={pty} {name}: {}",
                String::from_utf8_lossy(&recorded.stderr)
            );
            let termination = premier_trace::read_manifest(&trace)
                .unwrap()
                .termination
                .expect("termination metadata");
            assert_eq!(termination.kind, premier_trace::TerminationKind::Signal);
            assert_eq!(termination.signal, Some(number), "pty={pty} {name}");
            assert_eq!(termination.signal_name.as_deref(), Some(name), "pty={pty}");
        }
    }
}

#[cfg(unix)]
#[test]
fn pty_record_runs_the_child_in_the_invoking_directory() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("workdir");
    std::fs::create_dir(&work).unwrap();
    let work = work.canonicalize().unwrap();
    let trace = temp.path().join("pty-cwd.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .current_dir(&work)
        .args(["record", "--pty", "--output"])
        .arg(&trace)
        .args(["python3", "-c", "import os; print('CWD=' + os.getcwd())"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(recorded.status.success());
    let stdout = String::from_utf8_lossy(&recorded.stdout);
    assert!(
        stdout.contains(&format!("CWD={}", work.display())),
        "{stdout}"
    );
    let events = read_events(&trace).unwrap();
    let start = events
        .iter()
        .find(|event| event.kind == "session.start")
        .expect("session.start");
    let recorded_cwd = std::path::PathBuf::from(start.payload()["cwd"].as_str().unwrap());
    assert_eq!(recorded_cwd.canonicalize().unwrap(), work);
}

#[cfg(unix)]
#[test]
fn journal_write_failure_keeps_the_command_running_and_returns_its_exit_code() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("journal-full.atrace");
    // A file size limit makes journal writes fail mid-run the same way a full
    // disk does; the recorded command writes to a pipe and is unaffected.
    let recorded = Command::new("sh")
        .args(["-c", "trap '' XFSZ; ulimit -f 16; exec \"$@\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--output"])
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "i=0; while [ $i -lt 600 ]; do echo line-$i-0123456789012345678901234567890123456789; i=$((i+1)); done; echo COMPLETED; exit 7",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&recorded.stdout);
    let stderr = String::from_utf8_lossy(&recorded.stderr);

    assert_eq!(recorded.status.code(), Some(7), "{stderr}");
    assert_eq!(stdout.lines().count(), 601, "passthrough was cut short");
    assert!(stdout.ends_with("COMPLETED\n"));
    assert!(stderr.contains("recording failed"), "{stderr}");
    // The journal was rolled back to whole frames, so the trace still
    // finalizes with the real exit status and says evidence is missing.
    let manifest = premier_trace::verify(&trace).unwrap();
    assert_eq!(manifest.exit_code, Some(7));
    assert!(
        manifest
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "journal.write_failed")
    );
}

#[test]
fn list_and_verify_point_abandoned_traces_at_recover() {
    let temp = tempfile::tempdir().unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");
    let unfinished = |name: &str, lease: Option<String>| {
        let trace = temp.path().join(name);
        let mut writer = premier_trace::TraceWriter::create(&trace, vec![name.to_owned()]).unwrap();
        writer
            .append("session.start", "test", serde_json::json!({}))
            .unwrap();
        drop(writer);
        if let Some(lease) = lease {
            std::fs::write(trace.join(premier_trace::RECORDER_LEASE), lease).unwrap();
        }
        trace
    };
    let abandoned = unfinished("abandoned.atrace", None);
    // This test process stands in for a recorder that is still running.
    let live = unfinished("live.atrace", Some(std::process::id().to_string()));
    let finished = temp.path().join("finished.atrace");
    premier_trace::TraceWriter::create(&finished, vec!["finished.atrace".into()])
        .unwrap()
        .finish(0)
        .unwrap();

    let listed = Command::new(premier)
        .args(["list", "--trace-dir"])
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed = String::from_utf8_lossy(&listed.stdout);
    let line = |name: &str| {
        listed
            .lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name} missing from {listed}"))
            .to_owned()
    };
    assert!(line("abandoned.atrace").contains("abandoned"), "{listed}");
    assert!(
        line("abandoned.atrace").contains("premier recover"),
        "{listed}"
    );
    assert!(line("live.atrace").contains("recording"), "{listed}");
    assert!(!line("live.atrace").contains("abandoned"), "{listed}");
    assert!(!line("finished.atrace").contains("recover"), "{listed}");

    let verify = |trace: &std::path::Path| {
        let output = Command::new(premier)
            .arg("verify")
            .arg(trace)
            .output()
            .unwrap();
        assert!(!output.status.success());
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let stderr = verify(&abandoned);
    assert!(stderr.contains("abandoned"), "{stderr}");
    assert!(stderr.contains("premier recover"), "{stderr}");
    let stderr = verify(&live);
    assert!(stderr.contains("still recording"), "{stderr}");
    assert!(!stderr.contains("premier recover"), "{stderr}");
}

#[test]
fn claim_command_migrates_local_tenant_ownership_once() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("claim.atrace");
    premier_trace::TraceWriter::create(&trace, vec!["agent".into()])
        .unwrap()
        .finish(0)
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["claim", trace.to_str().unwrap(), "--tenant", "acme"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        premier_trace::read_manifest(&trace).unwrap().tenant_id,
        "acme"
    );
}

#[test]
fn encrypt_refuses_to_reseal_a_trace_that_fails_verification() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("tampered.atrace");
    evidence_trace(&trace, "baseline");
    break_journal_digest(&trace);
    let key_file = temp.path().join("key");
    std::fs::write(&key_file, "71".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let result = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args([
            "encrypt",
            trace.to_str().unwrap(),
            "--new-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success(), "encrypt must not re-seal");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("journal digest mismatch"), "{stderr}");
    assert!(!premier_trace::trace_is_encrypted(&trace).unwrap());
    assert!(premier_trace::verify(&trace).is_err());
}

#[test]
fn encrypt_command_migrates_and_verifies_a_finalized_trace() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("encrypt.atrace");
    let mut writer = premier_trace::TraceWriter::create_named(
        &trace,
        vec!["agent".into(), "private-command".into()],
        None,
    )
    .unwrap();
    writer
        .append(
            "agent.result",
            "test",
            serde_json::json!({"private":"evidence"}),
        )
        .unwrap();
    writer.finish(0).unwrap();
    let key_file = temp.path().join("key");
    std::fs::write(&key_file, "71".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let result = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args([
            "encrypt",
            trace.to_str().unwrap(),
            "--new-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let key = premier_trace::EncryptionKey::from_file(&key_file).unwrap();
    assert!(premier_trace::trace_is_encrypted(&trace).unwrap());
    assert_eq!(
        premier_trace::read_events_with_key(&trace, &key)
            .unwrap()
            .len(),
        1
    );
    let stored = std::fs::read_to_string(trace.join("manifest.json")).unwrap();
    assert!(!stored.contains("private-command"));
}

#[test]
fn diff_and_replay_refuse_an_unverifiable_trace_unless_explicitly_allowed() {
    let temp = tempfile::tempdir().unwrap();
    let intact = temp.path().join("intact.atrace");
    let tampered = temp.path().join("tampered.atrace");
    evidence_trace(&intact, "baseline");
    evidence_trace(&tampered, "current");
    break_journal_digest(&tampered);
    let premier = env!("CARGO_BIN_EXE_premier");
    let run =
        |arguments: &[&std::ffi::OsStr]| Command::new(premier).args(arguments).output().unwrap();
    let intact_arg = intact.as_os_str();
    let tampered_arg = tampered.as_os_str();
    let os = std::ffi::OsStr::new;

    // Either side of a comparison failing verification fails the comparison.
    for arguments in [
        vec![os("diff"), intact_arg, tampered_arg, os("--json")],
        vec![os("diff"), tampered_arg, intact_arg, os("--json")],
        vec![os("replay"), tampered_arg, os("--no-sleep")],
    ] {
        let output = run(&arguments);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{arguments:?} must fail closed");
        assert!(output.stdout.is_empty(), "{arguments:?} printed evidence");
        assert!(stderr.contains("failed verification"), "{stderr}");
        assert!(stderr.contains("--allow-unverified"), "{stderr}");
    }

    let diff = run(&[
        os("diff"),
        intact_arg,
        tampered_arg,
        os("--json"),
        os("--allow-unverified"),
    ]);
    let stderr = String::from_utf8_lossy(&diff.stderr);
    assert!(diff.status.success(), "{stderr}");
    assert!(stderr.contains("warning"), "{stderr}");
    let result: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(result["counts"]["added"], 1);

    let replay = run(&[
        os("replay"),
        tampered_arg,
        os("--no-sleep"),
        os("--allow-unverified"),
    ]);
    let stderr = String::from_utf8_lossy(&replay.stderr);
    assert!(replay.status.success(), "{stderr}");
    assert!(stderr.contains("failed verification"), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&replay.stdout).lines().count(), 3);
}

#[test]
fn diff_and_replay_read_a_live_trace_with_a_stderr_note() {
    let temp = tempfile::tempdir().unwrap();
    let live = temp.path().join("live.atrace");
    let finished = temp.path().join("finished.atrace");
    evidence_trace(&finished, "baseline");
    let mut writer = premier_trace::TraceWriter::create(&live, vec!["agent".into()]).unwrap();
    writer
        .append("agent.turn", "test", serde_json::json!({"live": true}))
        .unwrap();
    let premier = env!("CARGO_BIN_EXE_premier");
    let diff = Command::new(premier)
        .arg("diff")
        .arg(&finished)
        .arg(&live)
        .output()
        .unwrap();
    let replay = Command::new(premier)
        .arg("replay")
        .arg(&live)
        .arg("--no-sleep")
        .output()
        .unwrap();
    for output in [diff, replay] {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("not finalized"), "{stderr}");
    }
    drop(writer);
}

/// A trace whose recorder never finalized it, as left behind by a crash.
#[cfg(unix)]
fn unfinalized_trace(trace: &std::path::Path, lease: String) {
    let mut writer = premier_trace::TraceWriter::create(trace, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "test", serde_json::json!({"live": true}))
        .unwrap();
    drop(writer);
    std::fs::write(trace.join(premier_trace::RECORDER_LEASE), lease).unwrap();
}

#[cfg(unix)]
#[test]
fn recover_refuses_a_trace_whose_recorder_is_alive_even_past_the_idle_threshold() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("live.atrace");
    // This test process stands in for a recorder that is still running.
    unfinalized_trace(&trace, std::process::id().to_string());
    let premier = env!("CARGO_BIN_EXE_premier");

    let guarded = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .args(["--stale-after-seconds", "0"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&guarded.stderr);
    assert!(!guarded.status.success(), "a live recording was finalized");
    assert!(stderr.contains("still being recorded"), "{stderr}");
    assert!(stderr.contains(&std::process::id().to_string()), "{stderr}");
    assert!(stderr.contains("--force"), "{stderr}");
    assert!(
        premier_trace::read_manifest(&trace)
            .unwrap()
            .journal
            .is_none()
    );

    let forced = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    premier_trace::verify(&trace).unwrap();
}

#[cfg(unix)]
#[test]
fn recover_finalizes_a_fresh_trace_without_force_when_its_recorder_is_dead() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("dead.atrace");
    // A reaped child's process id names a recorder that is certainly gone.
    let mut finished = Command::new("true").spawn().unwrap();
    let dead_pid = finished.id();
    finished.wait().unwrap();
    unfinalized_trace(&trace, dead_pid.to_string());
    let premier = env!("CARGO_BIN_EXE_premier");

    let listed = Command::new(premier)
        .args(["list", "--trace-dir"])
        .arg(temp.path())
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.contains("premier recover"), "{listed}");
    assert!(!listed.contains("--force"), "{listed}");

    let recovered = Command::new(premier)
        .arg("recover")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    premier_trace::verify(&trace).unwrap();
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.termination.unwrap().kind,
        premier_trace::TerminationKind::Interrupted
    );
    assert!(!trace.join(premier_trace::RECORDER_LEASE).exists());
}

#[cfg(unix)]
#[test]
fn recorder_sighup_is_forwarded_and_finalized() {
    assert_recorder_signal_is_forwarded("-HUP", libc::SIGHUP, 128 + libc::SIGHUP, false);
}

#[cfg(unix)]
#[test]
fn recorder_sigquit_is_forwarded_and_finalized() {
    assert_recorder_signal_is_forwarded("-QUIT", libc::SIGQUIT, 128 + libc::SIGQUIT, false);
}

#[cfg(unix)]
#[test]
fn pty_recorder_sighup_and_sigquit_are_forwarded_to_the_process_group_and_finalized() {
    assert_recorder_signal_is_forwarded("-HUP", libc::SIGHUP, 128 + libc::SIGHUP, true);
    assert_recorder_signal_is_forwarded("-QUIT", libc::SIGQUIT, 128 + libc::SIGQUIT, true);
}

#[cfg(unix)]
#[test]
fn recorder_sighup_and_sigquit_keep_a_handling_childs_status_and_escalate_when_ignored() {
    for (kill_argument, trap_name, signal) in [
        ("-HUP", "HUP", libc::SIGHUP),
        ("-QUIT", "QUIT", libc::SIGQUIT),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let handled = temp.path().join("handled.atrace");
        let script = format!(
            "trap 'echo cleaned; exit 7' {trap_name}; echo READY; while :; do sleep 0.1; done"
        );
        let (mut recorder, _stdout) = spawn_ready_recorder(&handled, false, "60000", &script);
        signal_process(kill_argument, recorder.id());
        let status = wait_bounded(&mut recorder, || {});
        assert_eq!(status.code(), Some(7), "{trap_name}");
        premier_trace::verify(&handled).unwrap();
        let exit = process_exit_payload(&handled);
        assert_eq!(exit["termination"], "exit", "{trap_name}");
        assert_eq!(exit["recorder_signal"], signal, "{trap_name}");
        assert_eq!(exit["recorder_signal_name"], format!("SIG{trap_name}"));

        let ignored = temp.path().join("ignored.atrace");
        let script = format!("trap '' {trap_name}; echo READY; exec sleep 300");
        let (mut recorder, _stdout) = spawn_ready_recorder(&ignored, false, "300", &script);
        signal_process(kill_argument, recorder.id());
        let status = wait_bounded(&mut recorder, || {});
        assert_eq!(status.code(), Some(128 + libc::SIGKILL), "{trap_name}");
        premier_trace::verify(&ignored).unwrap();
        let exit = process_exit_payload(&ignored);
        assert_eq!(exit["recorder_signal"], signal, "{trap_name}");
        assert_eq!(exit["killed_by_recorder"], true, "{trap_name}");
    }
}

fn assert_failed_start_is_finalized(
    recorded: &std::process::Output,
    trace: &std::path::Path,
    exit_code: i32,
) {
    let stderr = String::from_utf8_lossy(&recorded.stderr);
    assert_eq!(recorded.status.code(), Some(exit_code), "{stderr}");
    assert!(stderr.contains("failed to start"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    // The directory is a finalized, verifiable trace, not an abandoned one.
    premier_trace::verify(trace).unwrap();
    assert!(!trace.join(premier_trace::RECORDER_LEASE).exists());
    let manifest = premier_trace::read_manifest(trace).unwrap();
    assert_eq!(manifest.exit_code, Some(exit_code));
    let events = read_events(trace).unwrap();
    let failure = events
        .iter()
        .find(|event| event.kind == "process.spawn_failed")
        .expect("process.spawn_failed event");
    assert_eq!(failure.status, "error");
    assert_eq!(failure.payload()["exit_code"], exit_code);
    assert!(
        failure.payload()["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
    assert!(!events.iter().any(|event| event.kind == "process.exit"));
    let listed = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["list", "--trace-dir"])
        .arg(trace.parent().unwrap())
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(!listed.contains("recover"), "{listed}");
    assert!(!listed.contains("recording"), "{listed}");
}

#[test]
fn record_finalizes_the_trace_and_exits_127_when_the_command_is_not_found() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("missing.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--output"])
        .arg(&trace)
        .arg("premier-test-command-that-does-not-exist")
        .output()
        .unwrap();
    assert_failed_start_is_finalized(&recorded, &trace, 127);
    let stderr = String::from_utf8_lossy(&recorded.stderr);
    assert!(stderr.contains("command not found"), "{stderr}");
    assert!(
        stderr.contains("premier-test-command-that-does-not-exist"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn record_exits_126_when_the_command_exists_but_cannot_be_executed() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let not_executable = temp.path().join("not-executable");
    std::fs::write(&not_executable, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644)).unwrap();
    for pty in [false, true] {
        let traces = temp.path().join(format!("pty-{pty}"));
        let trace = traces.join("denied.atrace");
        let mut command = Command::new(env!("CARGO_BIN_EXE_premier"));
        command.arg("record");
        if pty {
            command.arg("--pty");
        }
        let recorded = command
            .arg("--output")
            .arg(&trace)
            .arg(&not_executable)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_failed_start_is_finalized(&recorded, &trace, 126);
    }
}

#[cfg(unix)]
#[test]
fn pty_record_finalizes_the_trace_and_exits_127_when_the_command_is_not_found() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("missing-pty.atrace");
    let recorded = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--pty", "--output"])
        .arg(&trace)
        .arg("premier-test-command-that-does-not-exist")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_failed_start_is_finalized(&recorded, &trace, 127);
}

/// `GET path` against a local viewer: the whole HTTP response, or `None`
/// while the server is not accepting connections yet.
#[cfg(unix)]
fn http_get(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

#[cfg(unix)]
#[test]
fn record_open_serves_only_the_recorded_trace_not_its_siblings() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let traces = temp.path().join("traces");
    std::fs::create_dir_all(&traces).unwrap();
    let sibling = traces.join("sibling.atrace");
    evidence_trace(&sibling, "baseline");
    let sibling_id = premier_trace::read_manifest(&sibling).unwrap().trace_id;
    let recorded = traces.join("recorded.atrace");

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
    let viewer = temp.path().join("viewer");
    std::fs::create_dir_all(&viewer).unwrap();
    std::fs::write(viewer.join("index.html"), "<!doctype html>").unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let mut recorder = Command::new(env!("CARGO_BIN_EXE_premier"))
        .args(["record", "--open", "--bind", &format!("127.0.0.1:{port}")])
        .arg("--viewer-dir")
        .arg(&viewer)
        .arg("--output")
        .arg(&recorded)
        .args(["sh", "-c", "echo recorded"])
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    let listed = loop {
        if let Some(response) = http_get(port, "/api/traces") {
            break response;
        }
        if started.elapsed() > std::time::Duration::from_secs(30) {
            recorder.kill().unwrap();
            panic!("viewer did not start within 30s");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let sibling_lookup = http_get(port, &format!("/api/traces/{sibling_id}"));
    recorder.kill().unwrap();
    recorder.wait().unwrap();

    let recorded_id = premier_trace::read_manifest(&recorded).unwrap().trace_id;
    assert!(listed.starts_with("HTTP/1.1 200"), "{listed}");
    assert!(listed.contains(&recorded_id), "{listed}");
    assert!(!listed.contains(&sibling_id), "sibling published: {listed}");
    let sibling_lookup = sibling_lookup.expect("sibling lookup response");
    assert!(
        sibling_lookup.starts_with("HTTP/1.1 404"),
        "{sibling_lookup}"
    );
}
