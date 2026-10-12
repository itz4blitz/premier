//! Integrity assessment for traces shown by the viewer and CLI.

use crate::{Protection, read_manifest, verify_trace};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Viewer-facing integrity state for a single trace artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Recording is still open (no finalized journal).
    Live,
    /// No finalized journal and the recorder is gone; `premier recover` finalizes it.
    Abandoned,
    /// Finalized journal passed every check its format version supports. What
    /// that is worth is stated by [`IntegrityReport::protection`].
    Verified,
    /// Finalized or readable trace failed verification.
    Invalid,
    /// Encrypted, and no usable key was supplied: the evidence is sealed, not damaged.
    Locked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub status: IntegrityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// What a `Verified` trace is protected by: digest only (v1), an unsigned
    /// seal (self-consistent, not proof against a deliberate rewrite), or a
    /// signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<Protection>,
    /// Fingerprint of the key that signed the seal. The key comes from the
    /// trace itself, so this identifies the signer without vouching for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

impl IntegrityReport {
    /// Report without protection details (live, abandoned or invalid traces).
    pub fn new(status: IntegrityStatus, detail: Option<String>) -> Self {
        Self {
            status,
            detail,
            protection: None,
            signer: None,
        }
    }
}

/// Assess integrity of the trace at `root` without panicking on bad input.
pub fn assess_integrity(root: impl AsRef<Path>) -> IntegrityReport {
    let root = root.as_ref();
    let manifest = match read_manifest(root) {
        Ok(manifest) => manifest,
        Err(error) => {
            return IntegrityReport::new(IntegrityStatus::Invalid, Some(error.to_string()));
        }
    };
    if manifest.journal.is_none() {
        return IntegrityReport::new(IntegrityStatus::Live, None);
    }
    match verify_trace(root, None) {
        Ok(verified) => IntegrityReport {
            status: IntegrityStatus::Verified,
            detail: None,
            protection: Some(verified.protection),
            signer: verified.signer.map(|key| key.fingerprint()),
        },
        Err(error) => IntegrityReport::new(IntegrityStatus::Invalid, Some(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventInput, SigningKey, TraceWriter};
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn live_traces_are_not_verified() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("live.atrace");
        let _writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Live);
        assert!(report.detail.is_none());
    }

    #[test]
    fn abandoned_is_a_distinct_wire_state() {
        assert_eq!(
            serde_json::to_string(&IntegrityStatus::Abandoned).unwrap(),
            "\"abandoned\""
        );
        assert_ne!(IntegrityStatus::Abandoned, IntegrityStatus::Live);
    }

    #[test]
    fn finalized_traces_verify() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ok.atrace");
        let mut writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "session.start".into(),
                ..EventInput::default()
            })
            .unwrap();
        writer.finish(0).unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Verified);
        assert_eq!(report.protection, Some(Protection::Sealed));
        assert_eq!(report.signer, None);
    }

    #[test]
    fn signed_traces_report_the_signer_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("signed.atrace");
        let key = SigningKey::generate();
        let mut writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer.set_signing_key(key.clone());
        writer.finish(0).unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Verified);
        assert_eq!(report.protection, Some(Protection::Signed));
        assert_eq!(report.signer, Some(key.public_key().fingerprint()));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["protection"], "signed");
    }

    #[test]
    fn tampered_journals_are_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bad.atrace");
        let writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer.finish(0).unwrap();
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join("000001.events.pb.zst"))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        let report = assess_integrity(&root);
        assert_eq!(report.status, IntegrityStatus::Invalid);
        assert!(
            report
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("digest")),
            "{:?}",
            report.detail
        );
    }

    #[test]
    fn missing_manifest_is_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let report = assess_integrity(temp.path());
        assert_eq!(report.status, IntegrityStatus::Invalid);
        assert!(report.detail.is_some());
    }
}
