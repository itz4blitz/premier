//! `premier delete`, `premier prune`, and the `.gitignore` a new `.premier`
//! directory gets.
#![cfg(unix)]

use premier_trace::{EventInput, RECORDER_LEASE, TraceWriter};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// A finalized trace that ended `days_ago` days ago.
fn finished(trace_dir: &Path, name: &str, days_ago: i64, exit_code: i32) -> PathBuf {
    let path = trace_dir.join(name);
    let mut writer = TraceWriter::create(&path, vec!["agent".into()]).unwrap();
    writer
        .append("agent.note", "agent", json!({"text": "hello"}))
        .unwrap();
    writer.finish(exit_code).unwrap();
    set_ended(&path, days_ago);
    path
}

fn set_ended(path: &Path, days_ago: i64) {
    let manifest_path = path.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let ended = chrono::Utc::now() - chrono::Duration::days(days_ago);
    manifest["ended_at"] = json!(ended.to_rfc3339());
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

/// A trace that was never finalized. With `recording`, its lease names this
/// test process, which is alive; without, there is no recorder.
fn unfinalized(trace_dir: &Path, name: &str, recording: bool) -> PathBuf {
    let path = trace_dir.join(name);
    let mut writer = TraceWriter::create(&path, vec!["agent".into()]).unwrap();
    writer
        .append("agent.note", "agent", json!({"text": "partial"}))
        .unwrap();
    drop(writer);
    if recording {
        std::fs::write(
            path.join(RECORDER_LEASE),
            premier_cli::liveness::lease_contents(),
        )
        .unwrap();
    }
    path
}

fn prune(trace_dir: &Path, extra: &[&str]) -> Output {
    premier()
        .args(["prune", "--trace-dir"])
        .arg(trace_dir)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn delete_removes_named_traces_and_reports_their_size() {
    let temp = tempfile::tempdir().unwrap();
    let first = finished(temp.path(), "first.atrace", 0, 0);
    let second = finished(temp.path(), "second.atrace", 0, 1);
    let kept = finished(temp.path(), "kept.atrace", 0, 0);

    let dry = premier()
        .args(["delete", "--dry-run"])
        .args([&first, &second])
        .output()
        .unwrap();
    assert!(dry.status.success(), "{}", stderr(&dry));
    assert!(stdout(&dry).contains(&format!("would remove  {}  (", first.display())));
    assert!(stdout(&dry).contains("would remove 2 traces ("));
    assert!(first.exists() && second.exists());

    let deleted = premier()
        .arg("delete")
        .args([&first, &second])
        .output()
        .unwrap();
    assert!(deleted.status.success(), "{}", stderr(&deleted));
    let text = stdout(&deleted);
    assert!(
        text.contains(&format!("removed  {}  (", first.display())),
        "{text}"
    );
    assert!(text.contains(" B)") || text.contains("iB)"), "{text}");
    assert!(text.contains("removed 2 traces ("), "{text}");
    assert!(!first.exists() && !second.exists());
    assert!(kept.exists());

    // Naming no trace is a usage error, not "removed 0 traces".
    assert!(!premier().arg("delete").output().unwrap().status.success());
}

#[test]
fn delete_refuses_what_is_not_a_finished_trace_and_exits_non_zero() {
    let temp = tempfile::tempdir().unwrap();
    let good = finished(temp.path(), "good.atrace", 0, 0);
    let recording = unfinalized(temp.path(), "recording.atrace", true);
    let abandoned = unfinalized(temp.path(), "abandoned.atrace", false);
    let notes = temp.path().join("notes");
    std::fs::create_dir(&notes).unwrap();
    std::fs::write(notes.join("todo.txt"), "keep me").unwrap();
    // A trace with a file of the user's own in it.
    let mixed = finished(temp.path(), "mixed.atrace", 0, 0);
    std::fs::write(mixed.join("notes.txt"), "keep me too").unwrap();
    let linked_target = finished(temp.path(), "target.atrace", 0, 0);
    let link = temp.path().join("link.atrace");
    std::os::unix::fs::symlink(&linked_target, &link).unwrap();
    let missing = temp.path().join("missing.atrace");

    let output = premier()
        .arg("delete")
        .args([
            &good, &recording, &abandoned, &notes, &mixed, &link, &missing,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    let errors = stderr(&output);
    for (path, reason) in [
        (&recording, "still being recorded"),
        (&abandoned, "pass --include-abandoned to delete it"),
        (&notes, "is not a Premier trace directory"),
        (&mixed, "unexpected entry `notes.txt`"),
        (&link, "is a symbolic link"),
        (&missing, "does not exist"),
    ] {
        let line = errors
            .lines()
            .find(|line| line.contains(&format!("not removed: {}:", path.display())))
            .unwrap_or_else(|| panic!("no refusal for {}: {errors}", path.display()));
        assert!(line.contains(reason), "{line}");
    }
    assert!(errors.contains("6 traces could not be removed"), "{errors}");
    assert!(errors.contains("premier recover"), "{errors}");
    // The one that could be removed was, and everything refused is intact.
    assert!(stdout(&output).contains("removed 1 trace ("));
    assert!(!good.exists());
    assert!(recording.join("manifest.json").exists());
    assert!(abandoned.join("manifest.json").exists());
    assert_eq!(
        std::fs::read_to_string(notes.join("todo.txt")).unwrap(),
        "keep me"
    );
    assert!(mixed.join("notes.txt").exists());
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(linked_target.join("manifest.json").exists());

    let forced = premier()
        .args(["delete", "--include-abandoned"])
        .args([&abandoned, &recording])
        .output()
        .unwrap();
    assert_eq!(forced.status.code(), Some(1));
    assert!(
        stdout(&forced).contains(", abandoned)"),
        "{}",
        stdout(&forced)
    );
    assert!(!abandoned.exists());
    assert!(
        recording.exists(),
        "--include-abandoned must not remove a live recording"
    );
}

#[test]
fn delete_does_not_follow_links_out_of_the_trace() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("precious.txt"), "keep").unwrap();
    let trace = finished(temp.path(), "run.atrace", 0, 0);
    // `blobs` is a directory a trace may have; a link inside it is unlinked,
    // not descended into.
    std::fs::create_dir_all(trace.join("blobs")).unwrap();
    std::os::unix::fs::symlink(&outside, trace.join("blobs").join("escape")).unwrap();

    let output = premier().arg("delete").arg(&trace).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!trace.exists());
    assert_eq!(
        std::fs::read_to_string(outside.join("precious.txt")).unwrap(),
        "keep"
    );
}

#[test]
fn a_trace_that_cannot_be_removed_fails_the_command() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let locked = temp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let trace = finished(&locked, "run.atrace", 0, 0);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    // A user who may write anywhere (root in a container) cannot be refused this way.
    let enforced = std::fs::write(locked.join("probe"), "").is_err();
    let output = premier().arg("delete").arg(&trace).output().unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    if enforced {
        assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
        assert!(
            stderr(&output).contains("not removed:"),
            "{}",
            stderr(&output)
        );
        assert!(stdout(&output).contains("removed 0 traces"));
    }
}

#[test]
fn prune_removes_only_finalized_traces_older_than_the_duration() {
    let temp = tempfile::tempdir().unwrap();
    let trace_dir = temp.path().join("traces");
    let old = finished(&trace_dir, "old.atrace", 40, 0);
    let old_failed = finished(&trace_dir, "old-failed.atrace", 40, 2);
    let recent = finished(&trace_dir, "recent.atrace", 3, 0);
    let recording = unfinalized(&trace_dir, "recording.atrace", true);
    let abandoned = unfinalized(&trace_dir, "abandoned.atrace", false);
    // Not traces: a plain directory, a working copy, a link to an old trace.
    let plain = trace_dir.join("plain");
    std::fs::create_dir(&plain).unwrap();
    std::fs::write(plain.join("file"), "x").unwrap();
    let working = finished(&trace_dir, ".old.atrace.tmp", 40, 0);
    let elsewhere = finished(temp.path(), "elsewhere.atrace", 40, 0);
    let link = trace_dir.join("link.atrace");
    std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
    let everything = [
        &old,
        &old_failed,
        &recent,
        &recording,
        &abandoned,
        &plain,
        &working,
        &elsewhere,
    ];

    let dry = prune(&trace_dir, &["--older-than", "30d", "--dry-run"]);
    assert!(dry.status.success(), "{}", stderr(&dry));
    let text = stdout(&dry);
    assert!(
        text.contains(&format!("would remove  {}  (", old.display())),
        "{text}"
    );
    assert!(text.contains(", ended "), "{text}");
    assert!(text.contains("would remove 2 traces ("), "{text}");
    assert!(
        text.contains(
            "kept 1 newer, 1 still recording, 1 abandoned (--include-abandoned removes them)"
        ),
        "{text}"
    );
    assert!(everything.iter().all(|path| path.exists()));

    // Failed runs can be kept for a later look.
    let keeping = prune(&trace_dir, &["--older-than", "30d", "--keep-issues"]);
    assert!(keeping.status.success(), "{}", stderr(&keeping));
    assert!(
        stdout(&keeping).contains("removed 1 trace ("),
        "{}",
        stdout(&keeping)
    );
    assert!(
        stdout(&keeping).contains("1 with issues"),
        "{}",
        stdout(&keeping)
    );
    assert!(!old.exists());
    assert!(old_failed.exists());

    let pruned = prune(&trace_dir, &["--older-than", "720h"]);
    assert!(pruned.status.success(), "{}", stderr(&pruned));
    assert!(!old_failed.exists());
    for kept in [
        &recent, &recording, &abandoned, &plain, &working, &elsewhere,
    ] {
        assert!(kept.exists(), "{} was removed", kept.display());
    }
    assert!(link.symlink_metadata().is_ok());

    // An abandoned trace goes only when asked for, by when it was last written.
    let not_yet = prune(&trace_dir, &["--older-than", "30d", "--include-abandoned"]);
    assert!(not_yet.status.success());
    assert!(abandoned.exists());
    let with_abandoned = prune(&trace_dir, &["--older-than", "0s", "--include-abandoned"]);
    assert!(
        with_abandoned.status.success(),
        "{}",
        stderr(&with_abandoned)
    );
    assert!(
        stdout(&with_abandoned).contains("abandoned, last written "),
        "{}",
        stdout(&with_abandoned)
    );
    assert!(!abandoned.exists());
    assert!(!recent.exists());
    assert!(
        recording.exists(),
        "a live recording is never pruned, whatever the age"
    );
}

#[test]
fn prune_keeps_a_trace_with_an_issue_event_and_rejects_a_bad_duration() {
    let temp = tempfile::tempdir().unwrap();
    let trace_dir = temp.path().join("traces");
    let path = trace_dir.join("issue.atrace");
    let mut writer = TraceWriter::create(&path, vec!["agent".into()]).unwrap();
    writer
        .append_input(EventInput {
            kind: "tool.result".into(),
            source: "agent".into(),
            status: "error".into(),
            payload: json!({"tool": "build"}),
            ..EventInput::default()
        })
        .unwrap();
    writer.finish(0).unwrap();
    set_ended(&path, 10);

    let kept = prune(&trace_dir, &["--older-than", "1d", "--keep-issues"]);
    assert!(kept.status.success(), "{}", stderr(&kept));
    assert!(stdout(&kept).contains("removed 0 traces (0 B); kept 1 with issues"));
    assert!(path.exists());

    for invalid in ["30", "soon", "1.5d"] {
        let output = prune(&trace_dir, &["--older-than", invalid]);
        assert_eq!(output.status.code(), Some(2), "{invalid}");
        assert!(
            stderr(&output).contains("is not a duration"),
            "{}",
            stderr(&output)
        );
    }
    assert!(
        !prune(&trace_dir, &[]).status.success(),
        "--older-than is required"
    );
    assert!(path.exists());

    // A trace directory that does not exist is nothing to prune, not an error.
    let absent = prune(&temp.path().join("nowhere"), &["--older-than", "1d"]);
    assert!(absent.status.success(), "{}", stderr(&absent));
    assert!(stdout(&absent).contains("removed 0 traces"));
}

#[test]
fn a_new_premier_directory_ignores_its_own_contents() {
    let temp = tempfile::tempdir().unwrap();
    let ignore = temp.path().join(".premier").join(".gitignore");

    let recorded = premier()
        .current_dir(temp.path())
        .args(["record", "--", "true"])
        .output()
        .unwrap();
    assert!(recorded.status.success(), "{}", stderr(&recorded));
    assert_eq!(std::fs::read_to_string(&ignore).unwrap(), "*\n");

    // Only on creation: a directory that exists is left as its owner has it.
    std::fs::remove_file(&ignore).unwrap();
    let again = premier()
        .current_dir(temp.path())
        .args(["record", "--", "true"])
        .output()
        .unwrap();
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(!ignore.exists());

    // `demo` creates the directory the same way, and an explicit output
    // under a new `.premier` counts too.
    let demo_home = temp.path().join("demo");
    std::fs::create_dir(&demo_home).unwrap();
    let demo = premier()
        .current_dir(&demo_home)
        .arg("demo")
        .output()
        .unwrap();
    assert!(demo.status.success(), "{}", stderr(&demo));
    assert_eq!(
        std::fs::read_to_string(demo_home.join(".premier").join(".gitignore")).unwrap(),
        "*\n"
    );
    let explicit = temp.path().join("explicit");
    let output = premier()
        .args(["record", "--output"])
        .arg(explicit.join(".premier").join("runs").join("one.atrace"))
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        std::fs::read_to_string(explicit.join(".premier").join(".gitignore")).unwrap(),
        "*\n"
    );

    // An output outside any `.premier` directory gets no ignore file.
    let plain = temp.path().join("plain");
    let output = premier()
        .args(["record", "--output"])
        .arg(plain.join("one.atrace"))
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!plain.join(".gitignore").exists());
}
