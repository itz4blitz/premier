//! `--adapter auto` against wrapped commands and PTY capture. The "agent" is a
//! shell script named `codex` that prints two fixture lines; no real agent CLI
//! is ever run.
#![cfg(unix)]

use premier_trace::{read_events, read_manifest};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn premier() -> Command {
    Command::new(env!("CARGO_BIN_EXE_premier"))
}

fn fake_codex(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("codex");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         printf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"t\"}'\n\
         printf '%s\\n' '{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn record(trace: &Path, flags: &[&str], command: &[&str]) -> Output {
    let output = premier()
        .arg("record")
        .args(flags)
        .arg("--output")
        .arg(trace)
        .arg("--")
        .args(command)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn adapter_of(trace: &Path) -> Option<String> {
    read_manifest(trace)
        .unwrap()
        .adapter
        .map(|adapter| adapter.provider)
}

#[test]
fn auto_sees_through_env_and_a_simple_shell_command_but_respects_end_of_options() {
    let temp = tempfile::tempdir().unwrap();
    let codex = fake_codex(temp.path());
    let codex = codex.to_str().unwrap();

    let wrapped = temp.path().join("env.atrace");
    record(
        &wrapped,
        &[],
        &["env", "X=1", codex, "exec", "--json", "hi"],
    );
    assert_eq!(adapter_of(&wrapped).as_deref(), Some("codex"));
    let kinds: Vec<_> = read_events(&wrapped)
        .unwrap()
        .into_iter()
        .filter(|event| event.source == "adapter.codex.v1")
        .map(|event| event.kind)
        .collect();
    assert_eq!(kinds, ["agent.turn", "agent.result"]);

    let shell = temp.path().join("shell.atrace");
    let script = format!("exec '{codex}' exec --json hi");
    record(&shell, &[], &["sh", "-c", &script]);
    assert_eq!(adapter_of(&shell).as_deref(), Some("codex"));

    // `--json` after `--` is the prompt, not the structured-output flag.
    let prompt = temp.path().join("prompt.atrace");
    record(&prompt, &[], &[codex, "exec", "--", "--json"]);
    assert_eq!(adapter_of(&prompt), None);

    let piped = temp.path().join("piped.atrace");
    let script = format!("'{codex}' exec --json hi | cat");
    record(&piped, &[], &["sh", "-c", &script]);
    assert_eq!(adapter_of(&piped), None);
}

#[test]
fn auto_under_pty_says_that_structured_capture_is_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    let codex = fake_codex(temp.path());
    let codex = codex.to_str().unwrap();

    let trace = temp.path().join("pty.atrace");
    let recorded = record(&trace, &["--pty"], &[codex, "exec", "--json", "hi"]);
    let stderr = String::from_utf8_lossy(&recorded.stderr);
    let notes: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("structured capture"))
        .collect();
    assert_eq!(notes.len(), 1, "{stderr}");
    assert!(notes[0].starts_with("premier: "), "{stderr}");
    assert!(notes[0].contains("codex"), "{stderr}");
    assert!(notes[0].contains("PTY"), "{stderr}");
    assert_eq!(adapter_of(&trace), None);

    // No note when no adapter would have run anyway, or when adapters are switched off.
    for (name, flags, command) in [
        ("plain.atrace", &["--pty"][..], &[codex, "exec", "hi"][..]),
        (
            "none.atrace",
            &["--pty", "--adapter", "none"],
            &[codex, "exec", "--json"],
        ),
        ("pipes.atrace", &[], &[codex, "exec", "--json"]),
    ] {
        let recorded = record(&temp.path().join(name), flags, command);
        let stderr = String::from_utf8_lossy(&recorded.stderr);
        assert!(!stderr.contains("structured capture"), "{name}: {stderr}");
    }
}
