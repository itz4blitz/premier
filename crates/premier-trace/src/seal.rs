//! Tamper evidence for trace format version 2: the per-event hash chain, the
//! manifest seal, and the optional Ed25519 signature over that seal. The
//! byte-level definitions here are specified in `docs/trace-format.md`.

use crate::{TraceEvent, TraceManifest};
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// Environment variable naming the Ed25519 private key file used to sign
/// traces at finalization (same convention as `PREMIER_TRACE_KEY_FILE`).
pub const SIGN_KEY_FILE_ENV: &str = "PREMIER_SIGN_KEY_FILE";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

const CHAIN_GENESIS_DOMAIN: &[u8] = b"premier:chain-genesis:v2\0";
const CHAIN_EVENT_DOMAIN: &[u8] = b"premier:chain-event:v2\0";
const SEAL_DOMAIN: &[u8] = b"premier:manifest-seal:v2\0";
const SIGNATURE_DOMAIN: &[u8] = b"premier:manifest-signature:v2\0";

/// Tamper-evidence record of a finalized version 2 manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSeal {
    /// Hash of the last event's canonical bytes (the genesis value when the
    /// journal is empty), lowercase hex.
    pub chain_head: String,
    pub event_count: u64,
    /// Set when `premier recover` re-derived the chain head from an abandoned
    /// journal instead of the recorder that wrote it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub recovered: bool,
    /// Bytes of the abandoned journal that recovery could not keep: a torn
    /// trailing frame, or everything from the first frame that failed its
    /// checks. Written only when non-zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub discarded_bytes: u64,
    /// Number of frames in those bytes, when recovery could tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discarded_frames: Option<u64>,
    /// SHA-256 over the canonical manifest (every field except this digest,
    /// the signature and the encrypted envelope), lowercase hex.
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
}

/// Detached Ed25519 signature over the seal digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSignature {
    pub algorithm: String,
    /// Signer's public key, 64 hexadecimal characters.
    pub public_key: String,
    /// Signature, 128 hexadecimal characters.
    pub signature: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// How strongly a trace that passed verification is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    /// Version 1: journal digest and structural checks only.
    DigestOnly,
    /// Version 2 without a signature: detects accidental or careless changes.
    /// Anyone with write access can rebuild the chain and the seal.
    Sealed,
    /// Version 2 with a valid signature by the embedded public key. Whether
    /// that key is one the reader trusts is a separate question.
    Signed,
}

/// Result of checking a manifest's tamper evidence against its events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealStatus {
    pub protection: Protection,
    /// The key that produced a valid signature, when there is one.
    pub signer: Option<PublicKey>,
}

/// Ed25519 private key used to sign manifest seals.
#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&rand::random()))
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                bail!("signing key file must not be accessible by group or other users")
            }
        }
        let text = fs::read_to_string(path)?;
        Self::from_hex(text.trim())
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = decode_hex::<32>(value)
            .context("signing key must be exactly 64 hexadecimal characters")?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&bytes)))
    }

    /// The 32-byte private seed as hex, the content of a signing key file.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    fn sign(&self, digest: &[u8; 32]) -> ManifestSignature {
        ManifestSignature {
            algorithm: SIGNATURE_ALGORITHM.into(),
            public_key: self.public_key().to_hex(),
            signature: encode_hex(&self.0.sign(&signature_message(digest)).to_bytes()),
        }
    }
}

/// Ed25519 public key a signature is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = decode_hex::<32>(value)
            .context("public key must be exactly 64 hexadecimal characters")?;
        Ok(Self(
            VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 public key")?,
        ))
    }

    /// Accept either the hex key itself or a path to a file containing it.
    pub fn from_hex_or_file(value: &str) -> Result<Self> {
        if let Ok(key) = Self::from_hex(value.trim()) {
            return Ok(key);
        }
        let text = fs::read_to_string(value)
            .with_context(|| format!("{value} is neither a hex public key nor a readable file"))?;
        Self::from_hex(text.trim())
    }

    pub fn to_hex(&self) -> String {
        encode_hex(self.0.as_bytes())
    }

    /// Check that `signature` (hex) is this key's signature over a manifest
    /// seal `digest` (hex), as stored in `seal.signature`. It shows that the
    /// key's holder signed a trace with that seal digest, and nothing about
    /// any other copy of that trace's content.
    pub fn verify_seal_signature(&self, digest: &str, signature: &str) -> Result<()> {
        let digest = decode_hex::<32>(digest).context("seal digest is not 64 hex characters")?;
        let signature =
            decode_hex::<64>(signature).context("signature is not 128 hex characters")?;
        self.0
            .verify_strict(
                &signature_message(&digest),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .map_err(|_| anyhow::anyhow!("manifest signature is invalid"))
    }

    /// Short stable identifier: `sha256:` plus the first 16 bytes of the
    /// SHA-256 of the raw public key.
    pub fn fingerprint(&self) -> String {
        format!(
            "sha256:{}",
            encode_hex(&Sha256::digest(self.0.as_bytes())[..16])
        )
    }
}

pub(crate) fn signing_key_from_environment() -> Result<Option<SigningKey>> {
    std::env::var_os(SIGN_KEY_FILE_ENV)
        .map(|path| {
            SigningKey::from_file(Path::new(&path))
                .with_context(|| format!("cannot load the {SIGN_KEY_FILE_ENV} signing key"))
        })
        .transpose()
}

/// Value the first event of a trace chains from.
pub(crate) fn chain_genesis(trace_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_GENESIS_DOMAIN);
    hasher.update(trace_id.as_bytes());
    encode_hex(&hasher.finalize())
}

/// Hash of an event's canonical bytes: its protobuf encoding, which includes
/// the `prev_hash` linking it to its predecessor.
pub(crate) fn event_hash(event: &TraceEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_EVENT_DOMAIN);
    hasher.update(event.encode_to_vec());
    encode_hex(&hasher.finalize())
}

/// Recompute the hash chain over `events` and return its head. Fails at the
/// first event that does not chain from its predecessor.
pub(crate) fn chain_head(trace_id: &str, events: &[TraceEvent]) -> Result<String> {
    let mut chain = Chain::new(trace_id);
    for event in events {
        chain.push(event);
    }
    chain.finish()
}

/// The hash chain walked one event at a time. It stops hashing at the first
/// event that does not chain from its predecessor.
pub(crate) struct Chain {
    head: String,
    broken_at: Option<u64>,
}

impl Chain {
    pub(crate) fn new(trace_id: &str) -> Self {
        Self {
            head: chain_genesis(trace_id),
            broken_at: None,
        }
    }

    pub(crate) fn push(&mut self, event: &TraceEvent) {
        if self.broken_at.is_some() {
            return;
        }
        if event.prev_hash != self.head {
            self.broken_at = Some(event.sequence);
            return;
        }
        self.head = event_hash(event);
    }

    /// The chain head, or the error naming the first broken link.
    pub(crate) fn finish(self) -> Result<String> {
        match self.broken_at {
            Some(sequence) => bail!(
                "event chain is broken at sequence {sequence}: an event was edited, inserted, removed or reordered"
            ),
            None => Ok(self.head),
        }
    }
}

/// Seal digest of `manifest` as raw bytes. The input is the manifest's
/// canonical JSON without `seal.digest`, `seal.signature` and
/// `encryption.private_manifest`.
fn seal_digest(manifest: &TraceManifest) -> Result<[u8; 32]> {
    let mut value = serde_json::to_value(manifest)?;
    if let Some(seal) = value.get_mut("seal").and_then(|seal| seal.as_object_mut()) {
        seal.remove("digest");
        seal.remove("signature");
    }
    if let Some(encryption) = value
        .get_mut("encryption")
        .and_then(|encryption| encryption.as_object_mut())
    {
        encryption.remove("private_manifest");
    }
    let mut bytes = SEAL_DOMAIN.to_vec();
    write_canonical_json(&value, &mut bytes)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Deterministic JSON: object members sorted by key bytes, null members
/// omitted, no insignificant whitespace.
fn write_canonical_json(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            let mut members: Vec<_> = object
                .iter()
                .filter(|(_, value)| !value.is_null())
                .collect();
            members.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            out.push(b'{');
            for (index, (key, value)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                write_canonical_json(value, out)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, scalar)?,
    }
    Ok(())
}

fn signature_message(digest: &[u8; 32]) -> Vec<u8> {
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(digest);
    message
}

/// Seal a finalized manifest over the given chain state. Without a signing
/// key the manifest is left unsigned.
#[cfg(test)]
pub(crate) fn seal_manifest(
    manifest: &mut TraceManifest,
    chain_head: String,
    event_count: u64,
    recovered: bool,
    signing_key: Option<&SigningKey>,
) -> Result<()> {
    seal_recovered_manifest(
        manifest,
        chain_head,
        event_count,
        recovered,
        0,
        None,
        signing_key,
    )
}

/// [`seal_manifest`] that also records what recovery had to discard.
pub(crate) fn seal_recovered_manifest(
    manifest: &mut TraceManifest,
    chain_head: String,
    event_count: u64,
    recovered: bool,
    discarded_bytes: u64,
    discarded_frames: Option<u64>,
    signing_key: Option<&SigningKey>,
) -> Result<()> {
    manifest.seal = Some(ManifestSeal {
        chain_head,
        event_count,
        recovered,
        discarded_bytes,
        discarded_frames,
        digest: String::new(),
        signature: None,
    });
    reseal_manifest(manifest, signing_key)
}

/// Recompute the seal after a manifest field changed. Any previous signature
/// covered the old seal, so it is replaced when a signing key is available
/// and dropped otherwise. Manifests without a seal (version 1, or still
/// recording) are left untouched.
pub(crate) fn reseal_manifest(
    manifest: &mut TraceManifest,
    signing_key: Option<&SigningKey>,
) -> Result<()> {
    if manifest.seal.is_none() {
        return Ok(());
    }
    let digest = seal_digest(manifest)?;
    let seal = manifest.seal.as_mut().expect("seal exists");
    seal.digest = encode_hex(&digest);
    seal.signature = signing_key.map(|key| key.sign(&digest));
    Ok(())
}

/// Check a finalized manifest's chain, seal and signature against its decoded
/// events. Version 1 manifests carry none of these and report
/// [`Protection::DigestOnly`].
pub fn verify_tamper_evidence(
    manifest: &TraceManifest,
    events: &[TraceEvent],
) -> Result<SealStatus> {
    verify_sealed_chain(
        manifest,
        chain_head(&manifest.trace_id, events),
        events.len() as u64,
    )
}

/// [`verify_tamper_evidence`] for a chain that was already walked: `chain` is
/// its head, or the error of the first event that did not chain.
pub(crate) fn verify_sealed_chain(
    manifest: &TraceManifest,
    chain: Result<String>,
    event_count: u64,
) -> Result<SealStatus> {
    if manifest.format_version < 2 {
        return Ok(SealStatus {
            protection: Protection::DigestOnly,
            signer: None,
        });
    }
    let seal = manifest
        .seal
        .as_ref()
        .context("version 2 manifest has no seal")?;
    let head = chain?;
    if seal.event_count != event_count {
        bail!("sealed event count does not match the journal")
    }
    if head != seal.chain_head {
        bail!("event chain head does not match the manifest seal")
    }
    let digest = seal_digest(manifest)?;
    if encode_hex(&digest) != seal.digest {
        bail!("manifest seal mismatch: a manifest field was changed after finalization")
    }
    let Some(signature) = seal.signature.as_ref() else {
        return Ok(SealStatus {
            protection: Protection::Sealed,
            signer: None,
        });
    };
    if signature.algorithm != SIGNATURE_ALGORITHM {
        bail!("unsupported manifest signature algorithm")
    }
    let signer = PublicKey::from_hex(&signature.public_key)
        .context("manifest signature has an invalid public key")?;
    let bytes = decode_hex::<64>(&signature.signature)
        .context("manifest signature is not 128 hexadecimal characters")?;
    signer
        .0
        .verify_strict(
            &signature_message(&digest),
            &ed25519_dalek::Signature::from_bytes(&bytes),
        )
        .map_err(|_| anyhow::anyhow!("manifest signature is invalid"))?;
    Ok(SealStatus {
        protection: Protection::Signed,
        signer: Some(signer),
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected {} hexadecimal characters", N * 2)
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_and_omits_null_members() {
        let value = serde_json::json!({"b": [1, {"z": null, "a": "x\n"}], "a": null, "A": true});
        let mut bytes = Vec::new();
        write_canonical_json(&value, &mut bytes).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"A":true,"b":[1,{"a":"x\n"}]}"#
        );
    }

    #[test]
    fn signing_keys_round_trip_through_hex_and_have_stable_fingerprints() {
        let key = SigningKey::from_hex(&"07".repeat(32)).unwrap();
        assert_eq!(
            SigningKey::from_hex(&key.to_hex()).unwrap().to_hex(),
            key.to_hex()
        );
        let public = key.public_key();
        assert_eq!(PublicKey::from_hex(&public.to_hex()).unwrap(), public);
        assert!(public.fingerprint().starts_with("sha256:"));
        assert_eq!(public.fingerprint().len(), "sha256:".len() + 32);
        assert_ne!(
            SigningKey::generate().to_hex(),
            SigningKey::generate().to_hex()
        );
        assert!(SigningKey::from_hex("abc").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sign.key");
        fs::write(&path, SigningKey::generate().to_hex()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SigningKey::from_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        SigningKey::from_file(&path).unwrap();
    }
}
