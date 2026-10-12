use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn premier() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_premier"));
    command
        .env_remove(premier_trace::SIGN_KEY_FILE_ENV)
        .env_remove(premier_trace::KEY_FILE_ENV);
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

/// Run `premier keygen`, returning the private key path and the public key hex.
fn keygen(directory: &Path, name: &str) -> (PathBuf, String) {
    let path = directory.join(name);
    let output = premier().arg("keygen").arg(&path).output().unwrap();
    assert_success(&output);
    let public = std::fs::read_to_string(directory.join(format!("{name}.pub"))).unwrap();
    (path, public.trim().to_owned())
}

fn sample_trace(path: &Path) {
    let mut writer = premier_trace::TraceWriter::create_named(
        path,
        vec!["agent".into(), "run".into()],
        Some("tamper evidence".into()),
    )
    .unwrap();
    writer
        .append("agent.result", "test", serde_json::json!({"text": "real"}))
        .unwrap();
    writer.finish(0).unwrap();
}

fn verify(trace: &Path, public_key: Option<&str>) -> Output {
    let mut command = premier();
    command.arg("verify").arg(trace);
    if let Some(key) = public_key {
        command.args(["--public-key", key]);
    }
    command.output().unwrap()
}

#[test]
fn keygen_writes_a_private_key_file_and_prints_the_public_key() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sign.key");
    let output = premier().arg("keygen").arg(&path).output().unwrap();
    assert_success(&output);

    let key = premier_trace::SigningKey::from_file(&path).unwrap();
    let public = key.public_key();
    let text = stdout(&output);
    assert!(
        text.contains(&format!("public key: {}", public.to_hex())),
        "{text}"
    );
    assert!(text.contains(&public.fingerprint()), "{text}");
    assert!(!text.contains(&key.to_hex()), "{text}");
    assert_eq!(
        std::fs::read_to_string(temp.path().join("sign.key.pub"))
            .unwrap()
            .trim(),
        public.to_hex()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let again = premier().arg("keygen").arg(&path).output().unwrap();
    assert!(!again.status.success(), "keygen must not overwrite a key");
    assert_eq!(
        premier_trace::SigningKey::from_file(&path)
            .unwrap()
            .to_hex(),
        key.to_hex()
    );
}

#[test]
fn record_signs_with_a_key_and_verify_reports_each_distinct_outcome() {
    let temp = tempfile::tempdir().unwrap();
    let (key, public) = keygen(temp.path(), "sign.key");
    let (_, other_public) = keygen(temp.path(), "other.key");
    let fingerprint = premier_trace::PublicKey::from_hex(&public)
        .unwrap()
        .fingerprint();

    let signed = temp.path().join("signed.atrace");
    let recorded = premier()
        .args(["record", "--output"])
        .arg(&signed)
        .arg("--sign-key")
        .arg(&key)
        .args(["--", "/bin/sh", "-c", "printf signed"])
        .output()
        .unwrap();
    assert_success(&recorded);

    // Signed by the key the caller trusts, given as hex or as a file.
    for public_key in [public.clone(), format!("{}.pub", key.to_str().unwrap())] {
        let output = verify(&signed, Some(&public_key));
        assert_success(&output);
        let text = stdout(&output);
        assert!(
            text.contains(&format!("signed by the supplied key {fingerprint}")),
            "{text}"
        );
        assert!(text.starts_with("verified"), "{text}");
        assert!(!text.contains("note:"), "{text}");
    }

    // Signed, but nobody told us which key to expect.
    let output = verify(&signed, None);
    assert_success(&output);
    let text = stdout(&output);
    assert!(
        text.contains(&format!("signed by an unknown key {fingerprint}")),
        "{text}"
    );
    assert!(!text.starts_with("verified"), "{text}");

    // Signed by someone other than the expected key.
    let output = verify(&signed, Some(&other_public));
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("invalid"), "{text}");
    assert!(text.contains("signed by a different key"), "{text}");

    // Recorded through the environment variable instead of the flag.
    let by_env = temp.path().join("env.atrace");
    let recorded = premier()
        .env(premier_trace::SIGN_KEY_FILE_ENV, &key)
        .args(["record", "--output"])
        .arg(&by_env)
        .args(["--", "/bin/sh", "-c", "printf env"])
        .output()
        .unwrap();
    assert_success(&recorded);
    assert_success(&verify(&by_env, Some(&public)));
}

#[test]
fn unsigned_traces_are_reported_as_consistent_not_as_verified_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("unsigned.atrace");
    sample_trace(&trace);

    let output = verify(&trace, None);
    assert_success(&output);
    let text = stdout(&output);
    assert!(
        text.starts_with("consistent: chain and seal valid, unsigned"),
        "{text}"
    );
    assert!(
        text.contains("anyone who can write to the trace can rebuild the chain and seal"),
        "{text}"
    );
    assert!(!text.contains("verified"), "{text}");

    let (_, public) = keygen(temp.path(), "sign.key");
    let output = verify(&trace, Some(&public));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("trace is not signed"));
}

#[test]
fn verify_names_what_failed_for_an_edited_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let trace = temp.path().join("edited.atrace");
    sample_trace(&trace);
    let path = trace.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["exit_code"] = 3.into();
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let output = verify(&trace, None);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(text.contains("invalid"), "{text}");
    assert!(text.contains("manifest seal mismatch"), "{text}");
}

#[test]
fn sign_command_signs_a_finalized_trace_and_any_later_edit_breaks_it() {
    let temp = tempfile::tempdir().unwrap();
    let (key, public) = keygen(temp.path(), "sign.key");
    let trace = temp.path().join("late.atrace");
    sample_trace(&trace);

    let output = premier()
        .arg("sign")
        .arg(&trace)
        .arg("--sign-key")
        .arg(&key)
        .output()
        .unwrap();
    assert_success(&output);
    assert!(stdout(&output).contains("signed"));
    assert_success(&verify(&trace, Some(&public)));

    let path = trace.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["name"] = "renamed".into();
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    assert!(!verify(&trace, Some(&public)).status.success());

    // A trace that fails verification is never signed.
    let output = premier()
        .arg("sign")
        .arg(&trace)
        .arg("--sign-key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn version_1_traces_verify_as_digest_only() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../premier-trace/tests/fixtures/v1.atrace");
    let output = verify(&fixture, None);
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("v1: digest only"), "{text}");
    assert!(!text.starts_with("verified"), "{text}");
}

#[test]
fn export_states_the_chain_seal_and_signature_it_was_derived_from() {
    let temp = tempfile::tempdir().unwrap();
    let (key, public) = keygen(temp.path(), "sign.key");
    let trace = temp.path().join("export.atrace");
    sample_trace(&trace);

    let export = |trace: &Path| -> serde_json::Value {
        let output = premier().arg("export").arg(trace).output().unwrap();
        assert_success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let seal = premier_trace::read_manifest(&trace).unwrap().seal.unwrap();
    let unsigned = export(&trace);
    assert_eq!(unsigned["source"]["format_version"], 2);
    assert_eq!(unsigned["source"]["protection"], "sealed");
    assert_eq!(unsigned["source"]["chain_head"], seal.chain_head);
    assert_eq!(unsigned["source"]["seal"], seal.digest);
    assert_eq!(unsigned["source"]["event_count"], 1);
    assert!(unsigned["source"].get("signature").is_none());

    assert_success(
        &premier()
            .arg("sign")
            .arg(&trace)
            .arg("--sign-key")
            .arg(&key)
            .output()
            .unwrap(),
    );
    let signature = premier_trace::read_manifest(&trace)
        .unwrap()
        .seal
        .unwrap()
        .signature
        .unwrap();
    let signed = export(&trace);
    assert_eq!(signed["source"]["protection"], "signed");
    assert_eq!(signed["source"]["signature"], signature.signature);
    assert_eq!(signed["source"]["public_key"], public);
    assert_eq!(
        signed["source"]["public_key_fingerprint"],
        premier_trace::PublicKey::from_hex(&public)
            .unwrap()
            .fingerprint()
    );
    assert_eq!(signed["source"]["seal"], seal.digest);
}

#[cfg(unix)]
fn encryption_key_file(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join("trace.key");
    std::fs::write(&path, "71".repeat(32)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn encrypt_reports_a_dropped_signature_and_reapplies_it_with_a_signing_key() {
    let temp = tempfile::tempdir().unwrap();
    let (key, public) = keygen(temp.path(), "sign.key");
    let trace_key = encryption_key_file(temp.path());
    let sign = |trace: &Path| {
        assert_success(
            &premier()
                .arg("sign")
                .arg(trace)
                .arg("--sign-key")
                .arg(&key)
                .output()
                .unwrap(),
        );
    };
    let verify_encrypted = |trace: &Path, public_key: Option<&str>| {
        let mut command = premier();
        command
            .env(premier_trace::KEY_FILE_ENV, &trace_key)
            .arg("verify")
            .arg(trace);
        if let Some(public_key) = public_key {
            command.args(["--public-key", public_key]);
        }
        command.output().unwrap()
    };

    let dropped = temp.path().join("dropped.atrace");
    sample_trace(&dropped);
    sign(&dropped);
    let output = premier()
        .arg("encrypt")
        .arg(&dropped)
        .arg("--new-key-file")
        .arg(&trace_key)
        .output()
        .unwrap();
    assert_success(&output);
    assert!(
        stdout(&output).contains("previous signature covered the old manifest and was dropped"),
        "{}",
        stdout(&output)
    );
    let output = verify_encrypted(&dropped, None);
    assert_success(&output);
    assert!(stdout(&output).contains("unsigned"), "{}", stdout(&output));
    assert!(!verify_encrypted(&dropped, Some(&public)).status.success());

    // `premier sign` restores the signature on the encrypted trace.
    assert_success(
        &premier()
            .env(premier_trace::KEY_FILE_ENV, &trace_key)
            .arg("sign")
            .arg(&dropped)
            .arg("--sign-key")
            .arg(&key)
            .output()
            .unwrap(),
    );
    assert_success(&verify_encrypted(&dropped, Some(&public)));

    let resigned = temp.path().join("resigned.atrace");
    sample_trace(&resigned);
    sign(&resigned);
    let output = premier()
        .arg("encrypt")
        .arg(&resigned)
        .arg("--new-key-file")
        .arg(&trace_key)
        .arg("--sign-key")
        .arg(&key)
        .output()
        .unwrap();
    assert_success(&output);
    assert!(
        stdout(&output).contains("re-sealed and signed"),
        "{}",
        stdout(&output)
    );
    assert_success(&verify_encrypted(&resigned, Some(&public)));
}

#[test]
fn recover_seals_the_recovered_journal_and_signs_it_when_a_key_is_configured() {
    let temp = tempfile::tempdir().unwrap();
    let (key, public) = keygen(temp.path(), "sign.key");
    let trace = temp.path().join("abandoned.atrace");
    let mut writer = premier_trace::TraceWriter::create(&trace, vec!["agent".into()]).unwrap();
    writer
        .append("session.start", "test", serde_json::json!({"live": true}))
        .unwrap();
    drop(writer);

    let output = premier()
        .env(premier_trace::SIGN_KEY_FILE_ENV, &key)
        .arg("recover")
        .arg(&trace)
        .arg("--force")
        .output()
        .unwrap();
    assert_success(&output);
    let seal = premier_trace::read_manifest(&trace).unwrap().seal.unwrap();
    assert!(seal.recovered);
    assert_eq!(seal.event_count, 2);
    assert_success(&verify(&trace, Some(&public)));
}
