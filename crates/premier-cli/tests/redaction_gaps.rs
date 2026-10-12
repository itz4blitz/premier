//! Regression tests for redaction gaps found by runtime probes: secret field
//! names, event envelope fields, structured shapes at record time, URL query
//! credentials, well-known argument forms, the injected collector token, and
//! multi-line JSON text in exports.

use premier_cli::evidence::portable_evidence;
use premier_trace::{
    EventInput, RedactionConfig, TraceEvent, TraceWriter, is_secret_field_name, read_events,
    read_manifest, redact_builtin_secrets, redact_command_secrets,
};
use serde_json::json;
use std::path::Path;
use std::process::{Command, Output};

fn premier() -> Command {
    Command::new(env!("CARGO_BIN_EXE_premier"))
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Everything a reader of the trace can see: the manifest plus every event.
fn persisted(trace: &Path) -> String {
    let mut text = std::fs::read_to_string(trace.join("manifest.json")).unwrap();
    for event in read_events(trace).unwrap() {
        text.push_str(&serde_json::to_string(&event).unwrap());
    }
    text
}

fn record_inputs(trace: &Path, redaction: RedactionConfig, inputs: Vec<EventInput>) {
    let mut writer =
        TraceWriter::create_named_with_redaction(trace, vec!["agent".into()], None, redaction)
            .unwrap();
    for input in inputs {
        writer.append_input(input).unwrap();
    }
    writer.finish(0).unwrap();
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[test]
fn secret_field_names_cover_auth_jwt_passphrase_and_key_material() {
    for name in [
        "auth",
        "Auth",
        "basic_auth",
        "proxy-auth",
        "jwt",
        "id_jwt",
        "passphrase",
        "key_passphrase",
        "private_key_pem",
        "privateKeyPem",
        "secret_key",
        "aws_secret_key",
        "signing_key",
        "signingKey",
        "session_token",
        "refresh_token",
        "id_token",
        "bearer_token",
        "webhook_secret",
        "x-auth-token",
        "X-Auth-Token",
        "access_key",
        "aws_access_key_id",
    ] {
        assert!(is_secret_field_name(name), "{name} should be secret");
    }
    for name in [
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "max_tokens",
        "maxTokens",
        "token_count",
        "tokens",
        "cached_tokens",
        "reasoning_tokens",
        "tokenizer",
        "author",
        "authors",
        "authority",
        "authorized_by",
        "authored_by",
        "co_author",
        "authentication_method",
        "auth_method",
        "keyboard",
        "public_key",
        "key_id",
        "primary_key",
        "jwt_algorithm",
        "passphrase_hint",
        "usage_reported_on",
    ] {
        assert!(!is_secret_field_name(name), "{name} should not be secret");
    }
}

#[test]
fn literal_and_regex_rules_reach_event_envelope_fields() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("envelope.atrace");
    let redaction =
        RedactionConfig::new(std::iter::empty::<String>(), ["LIT-SECRET"], ["env-[0-9]+"])
            .unwrap()
            .multiline_regexes(["multi-[a-z]+"])
            .unwrap();
    record_inputs(
        &trace,
        redaction,
        vec![EventInput {
            kind: "tool.result".into(),
            source: "sdk-LIT-SECRET".into(),
            actor_id: "agent-LIT-SECRET".into(),
            actor_type: "agent".into(),
            span_id: "span-env-111".into(),
            parent_span_id: "parent-env-222".into(),
            correlation_id: "call-multi-abc".into(),
            status: "ok".into(),
            payload: json!({"note": "plain"}),
            ..EventInput::default()
        }],
    );
    let stored = persisted(&trace);
    for secret in ["LIT-SECRET", "env-111", "env-222", "multi-abc"] {
        assert!(!stored.contains(secret), "{secret} persisted: {stored}");
    }
    let event = &read_events(&trace).unwrap()[0];
    assert_eq!(event.actor_id, "agent-[REDACTED]");
    assert_eq!(event.source, "sdk-[REDACTED]");
    assert_eq!(event.span_id, "span-[REDACTED]");
    assert_eq!(event.parent_span_id, "parent-[REDACTED]");
    assert_eq!(event.correlation_id, "call-[REDACTED]");
    // Fields no rule matches are stored as given.
    assert_eq!(event.kind, "tool.result");
    assert_eq!(event.status, "ok");
    assert_eq!(event.actor_type, "agent");
}

#[test]
fn header_pairs_json_bodies_and_argument_lists_are_redacted_in_the_journal() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("structured.atrace");
    let redaction =
        RedactionConfig::new(["tenant_pin"], std::iter::empty::<String>(), [""; 0]).unwrap();
    record_inputs(
        &trace,
        redaction,
        vec![EventInput {
            kind: "tool.invocation".into(),
            status: "running".into(),
            payload: json!({
                "headers": [
                    {"name": "Authorization", "value": "Bearer pair-secret"},
                    {"name": "Accept", "value": "application/json"},
                    {"key": "X-Api-Key", "value": "key-secret"},
                    {"header": "Tenant-Pin", "values": ["custom-pair-secret"]}
                ],
                "raw_headers": [["Cookie", "session=cookie-secret"], ["Accept", "text/html"]],
                "body": "{\"api_key\":\"body-secret\",\"region\":\"eu\"}",
                "nested_body": "{\"inner\":\"{\\\"tenant_pin\\\":\\\"deep-secret\\\"}\"}",
                "plain": "{\"region\": \"eu\"}",
                "argv": ["deploy", "--api-key", "argv-secret", "--max-tokens", "64"],
                "env": ["TENANT_PIN=env-secret", "HOME=/home/agent"],
                "usage": {"input_tokens": 1200, "output_tokens": 400}
            }),
            ..EventInput::default()
        }],
    );
    let stored = persisted(&trace);
    for secret in [
        "pair-secret",
        "key-secret",
        "custom-pair-secret",
        "cookie-secret",
        "body-secret",
        "deep-secret",
        "argv-secret",
        "env-secret",
    ] {
        assert!(!stored.contains(secret), "{secret} persisted: {stored}");
    }
    let payload = read_events(&trace).unwrap()[0].payload();
    assert_eq!(payload["headers"][0]["name"], "Authorization");
    assert_eq!(payload["headers"][1]["value"], "application/json");
    assert_eq!(payload["raw_headers"][1], json!(["Accept", "text/html"]));
    // An untouched JSON document keeps its exact text.
    assert_eq!(payload["plain"], "{\"region\": \"eu\"}");
    let body: serde_json::Value = serde_json::from_str(payload["body"].as_str().unwrap()).unwrap();
    assert_eq!(body, json!({"api_key": "[REDACTED]", "region": "eu"}));
    assert_eq!(
        payload["argv"],
        json!(["deploy", "--api-key", "[REDACTED]", "--max-tokens", "64"])
    );
    assert_eq!(payload["env"][1], "HOME=/home/agent");
    assert_eq!(
        payload["usage"],
        json!({"input_tokens": 1200, "output_tokens": 400})
    );
}

#[test]
fn terminal_text_that_is_json_stays_raw_at_record_time_without_an_adapter() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("raw.atrace");
    record_inputs(
        &trace,
        RedactionConfig::default(),
        vec![EventInput {
            kind: "process.stdout".into(),
            payload: json!({"text": "{\"password\":\"printed\"}\n", "byte_length": 23}),
            ..EventInput::default()
        }],
    );
    let payload = read_events(&trace).unwrap()[0].payload();
    assert_eq!(payload["text"], "{\"password\":\"printed\"}\n");
}

#[test]
fn url_query_credentials_are_a_built_in_value_pattern() {
    for (text, expected) in [
        (
            "GET https://api.example.test/v1/items?token=abc123&page=2",
            "GET https://api.example.test/v1/items?token=[REDACTED]&page=2",
        ),
        (
            "https://example.test/cb?state=x&access_token=ya29.a0AfH6SMBx&expires_in=3600",
            "https://example.test/cb?state=x&access_token=[REDACTED]&expires_in=3600",
        ),
        (
            "curl 'https://example.test/data?api_key=k-12345'",
            "curl 'https://example.test/data?api_key=[REDACTED]'",
        ),
        (
            "https://bucket.example.test/o?X-Amz-Date=20260101T000000Z&X-Amz-Signature=0a1b2c3d4e5f#frag",
            "https://bucket.example.test/o?X-Amz-Date=20260101T000000Z&X-Amz-Signature=[REDACTED]#frag",
        ),
        (
            "https://blob.example.test/c/f?sv=2022&sig=AbC%2Bdef%3D&se=2026",
            "https://blob.example.test/c/f?sv=2022&sig=[REDACTED]&se=2026",
        ),
        (
            "{\"url\":\"https://example.test/hook?signature=deadbeef01\"}",
            "{\"url\":\"https://example.test/hook?signature=[REDACTED]\"}",
        ),
    ] {
        let mut matched = Vec::new();
        let redacted = redact_builtin_secrets(text, &mut |rule| matched.push(rule));
        assert_eq!(redacted.as_deref(), Some(expected), "{text}");
        assert_eq!(matched, ["url-query-credentials"], "{text}");
        assert_eq!(redact_builtin_secrets(expected, &mut |_| {}), None);
    }
    for text in [
        "https://example.test/search?q=token&page=2",
        "https://example.test/list?max_tokens=4096&token_count=12",
        "https://example.test/list?page_token_count=3",
        "https://example.test/a?design=flat&assign=me&key=value",
        "run with token=abc outside a query string",
        "a && b && token = c",
        "https://example.test/?token=",
        "https://example.test/?token=[REDACTED]",
    ] {
        assert_eq!(redact_builtin_secrets(text, &mut |_| {}), None, "{text}");
    }
}

#[test]
fn well_known_command_line_credential_forms_are_redacted() {
    for (command, expected) in [
        (
            vec!["curl", "-u", "deploy:hunter2", "https://example.test"],
            vec!["curl", "-u", "deploy:[REDACTED]", "https://example.test"],
        ),
        (
            vec!["/usr/bin/curl", "--user", "deploy:hunter2", "-s"],
            vec!["/usr/bin/curl", "--user", "deploy:[REDACTED]", "-s"],
        ),
        (
            vec!["curl", "--user=deploy:hunter2", "--proxy-user", "p:pw"],
            vec![
                "curl",
                "--user=deploy:[REDACTED]",
                "--proxy-user",
                "p:[REDACTED]",
            ],
        ),
        (
            vec!["curl", "-udeploy:hunter2", "https://example.test"],
            vec!["curl", "-udeploy:[REDACTED]", "https://example.test"],
        ),
        (
            vec!["curl", "-H", "X-Api-Key: abc123", "--header", "Accept: */*"],
            vec![
                "curl",
                "-H",
                "X-Api-Key: [REDACTED]",
                "--header",
                "Accept: */*",
            ],
        ),
        (
            vec!["curl", "--header=X-Auth-Token: abc123", "-HCookie: sid=1"],
            vec![
                "curl",
                "--header=X-Auth-Token: [REDACTED]",
                "-HCookie: [REDACTED]",
            ],
        ),
        (
            vec![
                "tool",
                "--password=pw1",
                "--passwd",
                "pw2",
                "--secret",
                "s3",
            ],
            vec![
                "tool",
                "--password=[REDACTED]",
                "--passwd",
                "[REDACTED]",
                "--secret",
                "[REDACTED]",
            ],
        ),
        (
            vec!["tool", "--token", "t0", "--api-key", "k1", "--api-key=k2"],
            vec![
                "tool",
                "--token",
                "[REDACTED]",
                "--api-key",
                "[REDACTED]",
                "--api-key=[REDACTED]",
            ],
        ),
        (
            vec!["mysql", "-uroot", "-phunter2", "-P3306", "shop"],
            vec!["mysql", "-uroot", "-p[REDACTED]", "-P3306", "shop"],
        ),
        (
            vec!["env", "X=1", "mysqldump", "-phunter2", "--port", "3306"],
            vec!["env", "X=1", "mysqldump", "-p[REDACTED]", "--port", "3306"],
        ),
    ] {
        assert_eq!(
            redact_command_secrets(&strings(&command)),
            strings(&expected),
            "{command:?}"
        );
    }
    // Outside the tools where they mean a credential, the same flags are left alone.
    for command in [
        vec!["sort", "-u", "names:sorted"],
        vec!["docker", "run", "-u", "1000:1000", "--user", "1000:1000"],
        vec!["git", "push", "-u", "origin", "main"],
        vec!["psql", "-p5432", "-h", "db"],
        vec!["ssh", "-p2222", "host"],
        vec!["mkdir", "-pv", "a/b"],
        // `mysql -p name`: the next argument is the database, not a password.
        vec!["mysql", "-p", "shop", "-P3306"],
        vec![
            "tool",
            "--max-tokens",
            "64",
            "--author",
            "sam",
            "--authority",
            "x",
        ],
    ] {
        let command = strings(&command);
        assert_eq!(redact_command_secrets(&command), command);
    }
}

#[test]
fn the_injected_collector_token_is_never_stored_when_the_child_prints_it() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("env.atrace");
    let token_file = temp.path().join("token");
    let recorded = premier()
        .arg("record")
        .arg("--output")
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "printf %s \"$PREMIER_COLLECTOR_TOKEN\" > \"$1\"; env; \
             echo \"err $PREMIER_COLLECTOR_TOKEN\" >&2; \
             \"$PREMIER\" emit --kind tool.result --actor agent \
               --payload \"{\\\"note\\\":\\\"saw $PREMIER_COLLECTOR_TOKEN\\\"}\" >/dev/null",
            "sh",
        ])
        .arg(&token_file)
        .env("PREMIER", env!("CARGO_BIN_EXE_premier"))
        .output()
        .unwrap();
    assert_success(&recorded);
    let token = std::fs::read_to_string(&token_file).unwrap();
    assert!(token.len() >= 16, "{token:?}");
    // The live output is not rewritten.
    assert!(String::from_utf8_lossy(&recorded.stdout).contains(&token));

    let stored = persisted(&trace);
    assert!(!stored.contains(&token), "collector token persisted");
    let events = read_events(&trace).unwrap();
    let text = |kind: &str| -> String {
        events
            .iter()
            .filter(|event| event.kind == kind)
            .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
            .collect()
    };
    assert!(
        text("process.stdout").contains("PREMIER_COLLECTOR_TOKEN=[REDACTED]\n"),
        "{}",
        text("process.stdout")
    );
    assert_eq!(text("process.stderr"), "err [REDACTED]\n");
    let emitted = events
        .iter()
        .find(|event| event.kind == "tool.result")
        .unwrap();
    assert_eq!(emitted.payload()["note"], "saw [REDACTED]");

    // The implicit rule is named in provenance; it is not a user rule and
    // does not claim that terminal redaction was requested.
    let manifest = read_manifest(&trace).unwrap();
    let provenance = manifest.redaction.unwrap();
    assert_eq!(provenance.terminal_literal_count, 0);
    let provenance = serde_json::to_value(&provenance).unwrap();
    assert_eq!(provenance["implicit_rules"], json!(["collector-token"]));
    assert!(
        !manifest
            .capabilities
            .contains(&"terminal-redaction".to_owned())
    );
}

fn stdout_event(text: &str) -> TraceEvent {
    TraceEvent {
        event_id: "e".into(),
        trace_id: "t".into(),
        sequence: 1,
        timestamp: "now".into(),
        kind: "process.stdout".into(),
        source: "command".into(),
        payload_json: json!({"text": text, "byte_length": text.len(), "stream": "stdout"})
            .to_string(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        parent_event_id: String::new(),
        span_id: "command".into(),
        parent_span_id: "session".into(),
        correlation_id: String::new(),
        status: "running".into(),
        duration_ms: 0,
        links: Vec::new(),
        prev_hash: String::new(),
    }
}

#[test]
fn export_redacts_json_lines_however_stdout_was_chunked() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("lines.atrace");
    TraceWriter::create(&root, vec!["agent".into()])
        .unwrap()
        .finish(0)
        .unwrap();
    let manifest = read_manifest(&root).unwrap();
    let first = r#"{"type":"login","password":"line-one-secret","user":"sam"}"#;
    let second =
        r#"{"type":"call","headers":[{"name":"Authorization","value":"Bearer line-two-secret"}]}"#;

    // One event per line, as a default run usually stores them.
    let separate = portable_evidence(
        &manifest,
        &[
            stdout_event(&format!("{first}\n")),
            stdout_event(&format!("{second}\n")),
        ],
    );
    // Both lines in one event, as line-holding stores them.
    let merged = portable_evidence(
        &manifest,
        &[stdout_event(&format!(
            "starting\n{first}\n{second}\nnot json {{\"password\"\n"
        ))],
    );
    for export in [&separate, &merged] {
        let text = serde_json::to_string(&export.events).unwrap();
        for secret in ["line-one-secret", "line-two-secret"] {
            assert!(!text.contains(secret), "{secret} exported: {text}");
        }
        assert_eq!(export.redaction.redacted.field_names, 2);
    }
    let text = merged.events[0]["payload"]["text"].as_str().unwrap();
    let lines: Vec<_> = text.split('\n').collect();
    assert_eq!(lines[0], "starting");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(lines[1]).unwrap(),
        json!({"type": "login", "password": "[REDACTED]", "user": "sam"})
    );
    assert_eq!(lines[3], "not json {\"password\"");
    assert_eq!(lines[4], "");
}

#[test]
fn recorded_json_lines_of_an_adapter_run_are_redacted_line_by_line_with_a_regex_rule() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("adapter-lines.atrace");
    let fixture = concat!(
        r#"{"type":"system","subtype":"init","session_id":"s"}"#,
        "\n",
        r#"{"type":"assistant","session_id":"s","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"http","input":{"headers":[{"name":"Authorization","value":"Bearer pair-in-line"}],"argv":["curl","--api-key","argv-in-line"]}}]}}"#,
        "\n",
        r#"{"type":"result","subtype":"success","session_id":"s","result":"done id-777"}"#,
        "\n",
    );
    let fixture_path = temp.path().join("claude.jsonl");
    std::fs::write(&fixture_path, fixture).unwrap();
    let recorded = premier()
        .args([
            "record",
            "--adapter",
            "claude",
            "--redact-regex",
            "id-[0-9]+",
            "--output",
        ])
        .arg(&trace)
        .args(["sh", "-c", "cat \"$1\"", "sh"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    assert_success(&recorded);
    let stored = persisted(&trace);
    for secret in ["pair-in-line", "argv-in-line", "id-777"] {
        assert!(!stored.contains(secret), "{secret} persisted: {stored}");
    }
    let exported = premier().arg("export").arg(&trace).output().unwrap();
    assert_success(&exported);
    let exported = String::from_utf8_lossy(&exported.stdout);
    for secret in ["pair-in-line", "argv-in-line", "id-777"] {
        assert!(!exported.contains(secret), "{secret} exported");
    }
}
