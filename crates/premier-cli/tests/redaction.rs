use premier_trace::{TraceEvent, read_events};
use std::process::{Command, Output, Stdio};

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

fn stored_text(events: &[TraceEvent], kind: &str) -> String {
    events
        .iter()
        .filter(|event| event.kind == kind)
        .filter_map(|event| event.payload().get("text")?.as_str().map(str::to_owned))
        .collect()
}

/// Everything a reader of the trace can see: the manifest plus every event.
fn persisted(trace: &std::path::Path) -> String {
    let mut text = std::fs::read_to_string(trace.join("manifest.json")).unwrap();
    for event in read_events(trace).unwrap() {
        text.push_str(&serde_json::to_string(&event).unwrap());
    }
    text
}

#[test]
fn terminal_rules_redact_secrets_split_across_separate_writes() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("split.atrace");
    let script = "printf SUPERSECRET; sleep 0.3; printf 'VALUE\\n'; \
                  printf sk-abc; sleep 0.3; printf 'def123\\n'; printf 'tail SUPERSEC'";
    let recorded = premier()
        .args([
            "record",
            "--redact-literal",
            "SUPERSECRETVALUE",
            "--redact-regex",
            "sk-[a-z0-9]+",
            "--output",
        ])
        .arg(&trace)
        .args(["sh", "-c", script])
        .output()
        .unwrap();
    assert_success(&recorded);
    // The live terminal stays raw; only the journal is redacted.
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        "SUPERSECRETVALUE\nsk-abcdef123\ntail SUPERSEC"
    );
    let events = read_events(&trace).unwrap();
    assert_eq!(
        stored_text(&events, "process.stdout"),
        "[REDACTED]\n[REDACTED]\ntail SUPERSEC"
    );
}

#[test]
fn terminal_rules_redact_a_secret_straddling_the_read_buffer() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("boundary.atrace");
    // One contiguous stream whose secret crosses the 8192-byte read boundary.
    let script = "x=$(head -c 8185 /dev/zero | tr '\\0' x); printf '%sSUPERSECRETVALUE\\n' \"$x\"";
    let recorded = premier()
        .args(["record", "--redact-literal", "SUPERSECRETVALUE", "--output"])
        .arg(&trace)
        .args(["sh", "-c", script])
        .output()
        .unwrap();
    assert_success(&recorded);
    let stored = stored_text(&read_events(&trace).unwrap(), "process.stdout");
    assert_eq!(stored, format!("{}[REDACTED]\n", "x".repeat(8185)));
}

#[cfg(unix)]
#[test]
fn pty_terminal_rules_redact_secrets_split_across_separate_writes() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("split-pty.atrace");
    let recorded = premier()
        .args([
            "record",
            "--pty",
            "--redact-literal",
            "SUPERSECRETVALUE",
            "--output",
        ])
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "printf SUPERSECRET; sleep 0.3; printf 'VALUE\\n'",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_success(&recorded);
    let stored = stored_text(&read_events(&trace).unwrap(), "process.terminal");
    assert!(stored.contains("[REDACTED]"), "{stored:?}");
    assert!(!stored.contains("SUPERSECRET"), "{stored:?}");
}

#[test]
fn adapter_runs_apply_every_redaction_rule_to_native_and_raw_copies() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("adapter.atrace");
    let fixture = concat!(
        r#"{"type":"system","subtype":"init","session_id":"claude-session"}"#,
        "\n",
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tool-1","name":"deploy","input":{"api_key":"sk-KEYED-SECRET","headers":{"Authorization":"Bearer hdr-KEYED-SECRET"},"region":"eu"}}]}}"#,
        "\n",
        r#"{"type":"result","subtype":"success","result":"used LITERAL-RULE-SECRET and id-12345"}"#,
        "\n",
    );
    let fixture_path = temp.path().join("claude.jsonl");
    std::fs::write(&fixture_path, fixture).unwrap();
    let recorded = premier()
        .args([
            "record",
            "--adapter",
            "claude",
            "--redact-literal",
            "LITERAL-RULE-SECRET",
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
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), fixture);

    let events = read_events(&trace).unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.source == "adapter.claude.v1")
    );
    for event in &events {
        for secret in [
            "sk-KEYED-SECRET",
            "hdr-KEYED-SECRET",
            "LITERAL-RULE-SECRET",
            "id-12345",
        ] {
            assert!(
                !event.payload_json.contains(secret),
                "{secret} persisted in {} ({}): {}",
                event.kind,
                event.source,
                event.payload_json
            );
        }
    }
    // Lines without secret fields keep their exact bytes in the raw copy, and
    // non-secret evidence on a redacted line survives.
    let raw = stored_text(&events, "process.stdout");
    assert!(raw.starts_with(fixture.lines().next().unwrap()), "{raw}");
    assert!(raw.contains(r#""region":"eu""#), "{raw}");
    assert_eq!(raw.lines().count(), 3);
}

#[test]
fn redact_field_names_without_letters_or_digits_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("empty-field.atrace");
    let recorded = premier()
        .args(["record", "--redact-field=@@@", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "echo should-not-run"])
        .output()
        .unwrap();
    assert!(!recorded.status.success());
    assert!(
        String::from_utf8_lossy(&recorded.stderr).contains("redact"),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), "");
    assert!(!trace.exists());
}

#[test]
fn non_ascii_redact_field_only_redacts_the_named_field() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("cjk-field.atrace");
    let recorded = premier()
        .args(["record", "--redact-field", "密码", "--output"])
        .arg(&trace)
        .args(["sh", "-c", "echo important evidence line"])
        .output()
        .unwrap();
    assert_success(&recorded);
    let events = read_events(&trace).unwrap();
    assert_eq!(
        stored_text(&events, "process.stdout"),
        "important evidence line\n"
    );
    let start = events
        .iter()
        .find(|event| event.kind == "session.start")
        .unwrap();
    assert_eq!(start.payload()["capture_mode"], "pipes");
}

#[test]
fn recorded_command_line_is_redacted_everywhere_it_is_stored() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("argv.atrace");
    let exported = temp.path().join("argv.json");
    let recorded = premier()
        .args([
            "record",
            "--name",
            "deploy with sk-live-LITERAL",
            "--redact-literal",
            "sk-live-LITERAL",
            "--output",
        ])
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "echo ran",
            "ignored",
            "--api-key=sk-live-KEYED",
            "--token",
            "tok-SEPARATE",
            "--header",
            "Authorization: Bearer hdr-ARGV",
            "plain-sk-live-LITERAL",
            "--max-tokens",
            "4096",
        ])
        .output()
        .unwrap();
    assert_success(&recorded);

    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.command,
        [
            "sh",
            "-c",
            "echo ran",
            "ignored",
            "--api-key=[REDACTED]",
            "--token",
            "[REDACTED]",
            "--header",
            "Authorization: [REDACTED]",
            "plain-[REDACTED]",
            "--max-tokens",
            "4096",
        ]
    );
    assert_eq!(manifest.name.as_deref(), Some("deploy with [REDACTED]"));
    let start = read_events(&trace)
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "session.start")
        .unwrap();
    assert_eq!(
        start.payload()["command"],
        serde_json::json!(manifest.command)
    );

    let export = premier()
        .arg("export")
        .arg(&trace)
        .arg("--output")
        .arg(&exported)
        .output()
        .unwrap();
    assert_success(&export);
    let listed = premier()
        .arg("list")
        .arg("--trace-dir")
        .arg(temp.path())
        .output()
        .unwrap();
    let everything = format!(
        "{}{}{}",
        persisted(&trace),
        std::fs::read_to_string(&exported).unwrap(),
        String::from_utf8_lossy(&listed.stdout)
    );
    for secret in [
        "sk-live-LITERAL",
        "sk-live-KEYED",
        "tok-SEPARATE",
        "hdr-ARGV",
    ] {
        assert!(!everything.contains(secret), "{secret} persisted");
    }
}
