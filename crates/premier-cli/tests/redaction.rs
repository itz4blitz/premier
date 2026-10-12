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

#[cfg(unix)]
#[test]
fn pty_capture_redacts_a_split_secret_and_keeps_the_rest_of_the_output_intact() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("pty-redaction.atrace");
    let recorded = premier()
        .args(["record", "--pty", "--redact-literal", "SECRET", "--output"])
        .arg(&trace)
        .args([
            "sh",
            "-c",
            "printf 'before\\n'; printf 'token=SEC'; sleep 0.3; printf 'RET done\\n'; printf 'after ✓\\n'",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_success(&recorded);
    // The terminal translates each newline to CRLF. The live display stays
    // raw; only the journal is redacted.
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        "before\r\ntoken=SECRET done\r\nafter ✓\r\n"
    );
    let events = read_events(&trace).unwrap();
    assert_eq!(
        stored_text(&events, "process.terminal"),
        "before\r\ntoken=[REDACTED] done\r\nafter ✓\r\n"
    );
    assert!(!persisted(&trace).contains("SECRET"));
    // Redaction replaces text; it must not lose track of the captured bytes.
    let captured: u64 = events
        .iter()
        .filter(|event| event.kind == "process.terminal")
        .filter_map(|event| event.payload()["byte_length"].as_u64())
        .sum();
    assert_eq!(captured, recorded.stdout.len() as u64);
    premier_trace::verify(&trace).unwrap();
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(
        manifest
            .capabilities
            .iter()
            .any(|capability| capability == "terminal.pty")
    );
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

const TOKEN_BODY: &str = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

/// Record a command that emits one structured event carrying a token-shaped
/// value under an ordinary key and prints a credentialed URL, which is also
/// on its command line. Returns the token and the URL password.
fn record_secret_shaped_values(trace: &std::path::Path, flags: &[&str]) -> (String, String) {
    // Assembled at run time so this file never holds a credential-shaped string.
    let token = format!("ghp_{TOKEN_BODY}");
    let password = "hunter2pw".to_owned();
    let payload = serde_json::json!({
        "note": format!("pushed with {token}"),
        "usage": {"input_tokens": 1200, "output_tokens": 400},
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "commit": "7ebad3a1c0ffee00deadbeef0123456789abcdef",
    });
    let recorded = premier()
        .arg("record")
        .args(flags)
        .arg("--output")
        .arg(trace)
        .args([
            "sh",
            "-c",
            "\"$PREMIER\" emit --kind tool.result --actor agent --payload \"$PAYLOAD\" >/dev/null; printf 'cloning %s\\n' \"$1\"",
            "sh",
        ])
        .arg(format!("https://deploy:{password}@git.example.test/r.git"))
        .env("PREMIER", env!("CARGO_BIN_EXE_premier"))
        .env("PAYLOAD", payload.to_string())
        .output()
        .unwrap();
    assert_success(&recorded);
    (token, password)
}

fn export_json(trace: &std::path::Path, flags: &[&str]) -> serde_json::Value {
    let exported = premier()
        .arg("export")
        .arg(trace)
        .args(flags)
        .output()
        .unwrap();
    assert_success(&exported);
    serde_json::from_slice(&exported.stdout).unwrap()
}

fn emitted_payload(events: &[TraceEvent]) -> serde_json::Value {
    events
        .iter()
        .find(|event| event.kind == "tool.result")
        .expect("emitted event")
        .payload()
}

#[test]
fn built_in_patterns_redact_secret_shaped_values_under_ordinary_keys_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("default.atrace");
    let (token, password) = record_secret_shaped_values(&trace, &[]);

    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert_eq!(
        manifest.command.last().unwrap(),
        "https://deploy:[REDACTED]@git.example.test/r.git"
    );
    let events = read_events(&trace).unwrap();
    let payload = emitted_payload(&events);
    assert_eq!(payload["note"], "pushed with [REDACTED]");
    // Ordinary evidence survives.
    assert_eq!(payload["usage"]["input_tokens"], 1200);
    assert_eq!(payload["id"], "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(
        payload["commit"],
        "7ebad3a1c0ffee00deadbeef0123456789abcdef"
    );
    // Terminal output is raw unless the user opts in.
    assert_eq!(
        stored_text(&events, "process.stdout"),
        format!("cloning https://deploy:{password}@git.example.test/r.git\n")
    );
    let stored = persisted(&trace);
    assert!(!stored.contains(&token), "{stored}");
    assert_eq!(stored.matches(&password).count(), 1);
    let provenance = manifest.redaction.unwrap();
    assert!(provenance.builtin_patterns_structured);
    assert!(!provenance.builtin_patterns_terminal);
    assert!(provenance.builtin_patterns.contains(&"github-token".into()));
    assert!(
        provenance
            .builtin_patterns
            .contains(&"url-credentials".into())
    );
}

#[test]
fn known_secret_patterns_reach_terminal_output_only_on_request() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("terminal.atrace");
    let (token, password) = record_secret_shaped_values(&trace, &["--redact-known-secrets"]);
    let stored = persisted(&trace);
    assert!(!stored.contains(&token), "{stored}");
    assert!(!stored.contains(&password), "{stored}");
    assert_eq!(
        stored_text(&read_events(&trace).unwrap(), "process.stdout"),
        "cloning https://deploy:[REDACTED]@git.example.test/r.git\n"
    );
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(manifest.redaction.unwrap().builtin_patterns_terminal);
    assert!(manifest.capabilities.contains(&"terminal-redaction".into()));
}

#[test]
fn default_secret_patterns_can_be_switched_off() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("off.atrace");
    let (token, password) = record_secret_shaped_values(&trace, &["--no-default-secret-patterns"]);
    let events = read_events(&trace).unwrap();
    assert_eq!(
        emitted_payload(&events)["note"],
        format!("pushed with {token}")
    );
    let manifest = premier_trace::read_manifest(&trace).unwrap();
    assert!(manifest.command.last().unwrap().contains(&password));
    let provenance = manifest.redaction.unwrap();
    assert!(provenance.builtin_patterns.is_empty());
    assert!(!provenance.builtin_patterns_structured);
}

#[test]
fn export_reports_what_it_redacted_and_the_active_rules() {
    let temp = tempfile::tempdir().unwrap();
    // A trace recorded without the built-in patterns still holds the values.
    let raw = temp.path().join("raw.atrace");
    let (token, password) = record_secret_shaped_values(&raw, &["--no-default-secret-patterns"]);

    let export = export_json(&raw, &[]);
    let text = export.to_string();
    assert!(!text.contains(&token), "{text}");
    // Exported terminal text is as recorded unless asked otherwise.
    assert_eq!(text.matches(&password).count(), 1);
    let redaction = &export["redaction"];
    assert_eq!(redaction["applied"], true);
    assert_eq!(redaction["redacted"]["value_patterns"]["github-token"], 1);
    // The command line appears in the manifest and in session.start.
    assert_eq!(
        redaction["redacted"]["value_patterns"]["url-credentials"],
        2
    );
    assert_eq!(redaction["redacted"]["field_names"], 0);
    assert_eq!(redaction["redacted"]["total"], 3);
    assert_eq!(redaction["redacted"]["already_redacted"], 0);
    assert_eq!(redaction["rules"]["builtin_patterns_structured"], true);
    assert_eq!(redaction["rules"]["builtin_patterns_terminal"], false);
    assert!(
        redaction["rules"]["builtin_patterns"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("github-token"))
    );
    assert!(
        redaction["rules"]["secret_field_names"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("passwd"))
    );

    let export = export_json(&raw, &["--redact-known-secrets"]);
    assert!(!export.to_string().contains(&password));
    assert_eq!(
        export["redaction"]["redacted"]["value_patterns"]["url-credentials"],
        3
    );
    assert_eq!(
        export["redaction"]["rules"]["builtin_patterns_terminal"],
        true
    );

    let export = export_json(&raw, &["--no-default-secret-patterns"]);
    assert!(export.to_string().contains(&token));
    assert_eq!(export["redaction"]["applied"], false);
    assert_eq!(export["redaction"]["redacted"]["total"], 0);
    assert_eq!(
        export["redaction"]["rules"]["builtin_patterns"],
        serde_json::json!([])
    );

    // A trace redacted when it was recorded leaves the export nothing to do,
    // and the report says so instead of claiming it applied redaction.
    let clean = temp.path().join("clean.atrace");
    record_secret_shaped_values(&clean, &[]);
    let export = export_json(&clean, &[]);
    assert_eq!(export["redaction"]["applied"], false);
    assert_eq!(export["redaction"]["redacted"]["total"], 0);
    assert_eq!(export["redaction"]["redacted"]["already_redacted"], 3);
}

/// Spawn a recorder with a regex rule around a command that prints a prompt
/// without a line break and then waits, and return once the prompt has been
/// mirrored to the recorder's stdout.
#[cfg(unix)]
fn record_unterminated_prompt(trace: &std::path::Path) -> std::process::Child {
    use std::io::Read;
    use std::os::unix::process::CommandExt;

    let mut recorder = premier()
        .args(["record", "--redact-regex", "sk-[a-z0-9]+", "--output"])
        .arg(trace)
        .args([
            "sh",
            "-c",
            "printf 'key sk-abc123 Password: '; exec sleep 20",
        ])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = recorder.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut byte = [0_u8; 1];
    while !String::from_utf8_lossy(&seen).ends_with("Password: ") {
        assert_eq!(stdout.read(&mut byte).unwrap(), 1, "prompt EOF");
        seen.push(byte[0]);
    }
    recorder
}

#[cfg(unix)]
#[test]
fn a_held_prompt_is_journaled_after_an_idle_period_and_survives_a_killed_recorder() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("idle.atrace");
    let mut recorder = record_unterminated_prompt(&trace);
    // The line never ends, so only the idle flush can journal it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut stored = String::new();
    while stored.is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
        stored = stored_text(&read_events(&trace).unwrap(), "process.stdout");
    }
    // Kill the whole group: the recorder gets no chance to finalize.
    let group = format!("-{}", recorder.id());
    let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
    recorder.wait().unwrap();
    assert_eq!(stored, "key [REDACTED] Password: ");
    assert_eq!(
        stored_text(&read_events(&trace).unwrap(), "process.stdout"),
        "key [REDACTED] Password: "
    );
}

#[cfg(unix)]
#[test]
fn a_held_prompt_is_journaled_when_the_recorder_finalizes_after_a_signal() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("signal.atrace");
    let mut recorder = record_unterminated_prompt(&trace);
    let signal = Command::new("kill")
        .args(["-TERM", &recorder.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    recorder.wait().unwrap();
    premier_trace::verify(&trace).unwrap();
    assert_eq!(
        stored_text(&read_events(&trace).unwrap(), "process.stdout"),
        "key [REDACTED] Password: "
    );
}

#[test]
fn redact_regex_help_states_its_line_scope_and_limits() {
    let help = premier().args(["record", "--help"]).output().unwrap();
    assert_success(&help);
    let help = String::from_utf8_lossy(&help.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for statement in [
        "Regex rules are line-scoped",
        "never spans a line break",
        "256 KiB",
        "--no-default-secret-patterns",
        "--redact-known-secrets",
    ] {
        assert!(help.contains(statement), "{statement} missing: {help}");
    }
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
