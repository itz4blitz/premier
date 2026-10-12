mod crypto;
mod integrity;
mod output;
mod seal;
mod utf8;

pub use crypto::{EncryptionKey, KEY_FILE_ENV, key_file_configured, set_key_file};
pub use integrity::{IntegrityReport, IntegrityStatus, assess_integrity};
pub use output::prepare_trace_output;
pub use seal::{
    ManifestSeal, ManifestSignature, Protection, PublicKey, SIGN_KEY_FILE_ENV, SealStatus,
    SigningKey, verify_tamper_evidence,
};
pub use utf8::{decode_utf8_chunk, finish_utf8};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration as StdDuration, SystemTime};
use uuid::Uuid;

/// Version written by this build. Version 2 adds the event hash chain, the
/// manifest seal and the optional signature (`docs/trace-format.md`).
pub const FORMAT_VERSION: u32 = 2;
/// Oldest version still read and verified (digest only).
pub const MIN_FORMAT_VERSION: u32 = 1;
pub const LOCAL_TENANT: &str = "local";
pub const RECORDER_LEASE: &str = "recorder.lease";
/// Append-in-progress journal file name inside a trace's `events/` directory.
pub const ACTIVE_JOURNAL: &str = "active.events.pb";
/// Finalized compressed journal file name inside a trace's `events/` directory.
pub const FINAL_JOURNAL: &str = "000001.events.pb.zst";
/// Hard cap on one journal frame, enforced identically by writers and readers.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct TraceEvent {
    #[prost(string, tag = "1")]
    pub event_id: String,
    #[prost(string, tag = "2")]
    pub trace_id: String,
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
    #[prost(string, tag = "4")]
    pub timestamp: String,
    #[prost(string, tag = "5")]
    pub kind: String,
    #[prost(string, tag = "6")]
    pub source: String,
    #[prost(string, tag = "7")]
    pub payload_json: String,
    #[prost(string, tag = "8")]
    pub actor_id: String,
    #[prost(string, tag = "9")]
    pub actor_type: String,
    #[prost(string, tag = "10")]
    pub parent_event_id: String,
    #[prost(string, tag = "11")]
    pub span_id: String,
    #[prost(string, tag = "12")]
    pub parent_span_id: String,
    #[prost(string, tag = "13")]
    pub correlation_id: String,
    #[prost(string, tag = "14")]
    pub status: String,
    #[prost(uint64, tag = "15")]
    pub duration_ms: u64,
    #[prost(string, repeated, tag = "16")]
    pub links: Vec<String>,
    /// Hash of the previous event's canonical bytes (hex), or the trace's
    /// genesis value on the first event. Empty in version 1 journals.
    #[prost(string, tag = "17")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prev_hash: String,
}

impl TraceEvent {
    pub fn payload(&self) -> serde_json::Value {
        serde_json::from_str(&self.payload_json).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventInput {
    pub kind: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub actor_id: String,
    #[serde(default)]
    pub actor_type: String,
    #[serde(default)]
    pub parent_event_id: String,
    #[serde(default)]
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: String,
    #[serde(default)]
    pub correlation_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Optional producer timestamp (RFC 3339). When omitted, receipt time is used.
    #[serde(default)]
    pub timestamp: Option<String>,
}

fn default_source() -> String {
    "sdk".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalFile {
    pub path: String,
    pub sha256: String,
    pub event_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

/// How the recorded root process stopped. `TraceManifest::exit_code` remains the
/// shell-compatible code for older readers; this structure preserves the exact
/// distinction between a normal exit, a signal, and an interrupted recorder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    Exit,
    Signal,
    Interrupted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTermination {
    pub kind: TerminationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
}

impl ProcessTermination {
    pub fn exited(exit_code: i32) -> Self {
        Self {
            kind: TerminationKind::Exit,
            exit_code: Some(exit_code),
            signal: None,
            signal_name: None,
        }
    }

    pub fn signaled(signal: i32, signal_name: Option<String>) -> Self {
        Self {
            kind: TerminationKind::Signal,
            exit_code: None,
            signal: Some(signal),
            signal_name,
        }
    }

    pub fn interrupted() -> Self {
        Self {
            kind: TerminationKind::Interrupted,
            exit_code: None,
            signal: None,
            signal_name: None,
        }
    }

    pub fn shell_exit_code(&self) -> i32 {
        self.exit_code
            .or_else(|| self.signal.map(|signal| 128_i32.saturating_add(signal)))
            .unwrap_or(130)
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryOptions {
    /// Refuse to recover a journal modified more recently than this duration.
    pub minimum_idle: StdDuration,
    /// Override the idle guard. This never permits rewriting a finalized trace.
    pub force: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            minimum_idle: StdDuration::from_secs(300),
            force: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceManifest {
    pub format_version: u32,
    pub trace_id: String,
    /// Immutable ownership boundary used by the viewer API. Old manifests default
    /// to the local-only tenant so they remain readable without becoming remotely
    /// visible to newly configured tenants.
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub command: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination: Option<ProcessTermination>,
    pub journal: Option<JournalFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<TraceDiagnostic>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterProvenance>,
    /// Chain head, seal digest and optional signature, written at
    /// finalization from format version 2 on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<ManifestSeal>,
    /// Public encryption envelope. When present, sensitive manifest fields and
    /// every event frame are XChaCha20-Poly1305 ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub key_id: String,
    pub private_manifest: String,
}

/// Sensitive manifest fields stored only as authenticated ciphertext. The
/// journal digest and event count live here so that an attacker without the
/// key cannot truncate trailing frames and rewrite the expected digest/count.
#[derive(Serialize, Deserialize)]
struct PrivateManifest {
    name: Option<String>,
    command: Vec<String>,
    ended_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    termination: Option<ProcessTermination>,
    journal: Option<JournalFile>,
    diagnostics: Vec<TraceDiagnostic>,
    capabilities: Vec<String>,
    redaction: Option<RedactionProvenance>,
    adapter: Option<AdapterProvenance>,
    /// The seal hashes plaintext fields and names the signer, so it stays
    /// inside the ciphertext. Absent in version 1 envelopes.
    #[serde(default)]
    seal: Option<ManifestSeal>,
}

fn default_tenant_id() -> String {
    LOCAL_TENANT.to_owned()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterProvenance {
    pub provider: String,
    pub schema_version: u32,
    pub transport: String,
    pub completeness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionProvenance {
    /// Safe defaults are always active for object-shaped event payloads.
    pub structured_defaults: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<String>,
    #[serde(default)]
    pub terminal_literal_count: usize,
    #[serde(default)]
    pub terminal_regex_count: usize,
    /// Rules given with `--redact-regex-multiline`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub terminal_multiline_regex_count: usize,
    /// Names of the built-in secret value patterns that were active (see
    /// [`builtin_secret_pattern_names`]). Empty when they were switched off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builtin_patterns: Vec<String>,
    /// The built-in patterns were applied to structured payload strings and
    /// the recorded command line.
    #[serde(default)]
    pub builtin_patterns_structured: bool,
    /// The built-in patterns were also applied to captured terminal text.
    #[serde(default)]
    pub builtin_patterns_terminal: bool,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// Replacement written wherever redaction removes a value.
const REDACTED: &str = "[REDACTED]";
/// Longest unterminated line a [`TerminalRedactionBuffer`] holds back before
/// it stops waiting for the line to end. Matches the native adapter line cap.
const MAX_HELD_LINE_BYTES: usize = 256 * 1024;
/// Tail a [`TerminalRedactionBuffer`] keeps when it is forced to cut a line
/// longer than [`MAX_HELD_LINE_BYTES`]. A literal or regex match no longer
/// than this cannot straddle the forced cut.
const HELD_OVERLAP_BYTES: usize = 16 * 1024;
/// Trailing terminal text a [`TerminalRedactionBuffer`] keeps held while a
/// multi-line regex rule is active. A multi-line match no longer than this
/// cannot straddle a release, however the output was chunked.
pub const MULTILINE_WINDOW_BYTES: usize = HELD_OVERLAP_BYTES;

/// One built-in secret value pattern: `group` is the capture group holding
/// the secret, and `accept` vets a candidate to keep false positives low.
struct SecretPattern {
    name: &'static str,
    regex: regex::Regex,
    group: usize,
    accept: fn(&str) -> bool,
}

fn any_candidate(_: &str) -> bool {
    true
}

fn has_digit(candidate: &str) -> bool {
    candidate.bytes().any(|byte| byte.is_ascii_digit())
}

const PEM_BEGIN: &str = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----";
const PEM_END: &str = r"-----END [A-Z0-9 ]*PRIVATE KEY-----";

/// `(name, regex, secret capture group, candidate check)`.
type SecretPatternSource = (&'static str, String, usize, fn(&str) -> bool);

/// The built-in secret value patterns. Deliberately conservative: each one
/// needs a distinctive prefix or shape, so token counts, UUIDs and git SHAs
/// survive.
fn builtin_pattern_table() -> Vec<SecretPatternSource> {
    vec![
        (
            "pem-private-key",
            // An unterminated block is redacted to the end of the text.
            format!(r"{PEM_BEGIN}(?s:.*?)(?:{PEM_END}|\z)"),
            0,
            any_candidate,
        ),
        (
            "authorization-header",
            r#"(?i)\b(?:proxy-)?authorization\\?["']?\s*[:=]\s*\\?["']?(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})"#.into(),
            1,
            any_candidate,
        ),
        (
            "bearer-token",
            r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})".into(),
            1,
            has_digit,
        ),
        (
            "url-credentials",
            r#"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@?#"'<>]*:([^\s/@?#"'<>]+)@"#.into(),
            1,
            any_candidate,
        ),
        (
            "sk-api-key",
            r"\bsk-[A-Za-z0-9_-]{20,}".into(),
            0,
            has_digit,
        ),
        (
            "github-token",
            r"\bgh[pousr]_[A-Za-z0-9]{36,}".into(),
            0,
            any_candidate,
        ),
        (
            "github-fine-grained-pat",
            r"\bgithub_pat_[A-Za-z0-9_]{22,}".into(),
            0,
            any_candidate,
        ),
        (
            "aws-access-key-id",
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b".into(),
            0,
            any_candidate,
        ),
        (
            "slack-token",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}".into(),
            0,
            has_digit,
        ),
        (
            "jwt",
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}".into(),
            0,
            any_candidate,
        ),
    ]
}

static BUILTIN_SECRET_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    builtin_pattern_table()
        .into_iter()
        .map(|(name, source, group, accept)| SecretPattern {
            name,
            regex: regex::Regex::new(&source).expect("built-in secret pattern compiles"),
            group,
            accept,
        })
        .collect()
});

/// Cheap pre-check: whether any built-in pattern could match at all.
static BUILTIN_SECRET_SET: LazyLock<regex::RegexSet> = LazyLock::new(|| {
    regex::RegexSet::new(builtin_pattern_table().into_iter().map(|entry| entry.1))
        .expect("built-in secret patterns compile")
});

static PEM_BEGIN_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(PEM_BEGIN).expect("PEM pattern compiles"));
static PEM_END_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(PEM_END).expect("PEM pattern compiles"));

/// Names of the built-in secret value patterns, in the order they apply.
pub fn builtin_secret_pattern_names() -> Vec<&'static str> {
    BUILTIN_SECRET_PATTERNS
        .iter()
        .map(|pattern| pattern.name)
        .collect()
}

/// Byte ranges of `text` one built-in pattern would redact. Values that are
/// already the redaction marker are skipped, so the pass is idempotent.
fn secret_pattern_spans(pattern: &SecretPattern, text: &str) -> Vec<(usize, usize)> {
    pattern
        .regex
        .captures_iter(text)
        .filter_map(|captures| captures.get(pattern.group))
        .filter(|secret| secret.as_str() != REDACTED && (pattern.accept)(secret.as_str()))
        .map(|secret| (secret.start(), secret.end()))
        .collect()
}

/// Replace every value in `text` that has the shape of a well-known secret
/// (see [`builtin_secret_pattern_names`]), calling `on_match` with the
/// pattern name for each replacement. `None` means nothing matched.
pub fn redact_builtin_secrets(
    text: &str,
    on_match: &mut dyn FnMut(&'static str),
) -> Option<String> {
    if !BUILTIN_SECRET_SET.is_match(text) {
        return None;
    }
    let mut current: Option<String> = None;
    for pattern in BUILTIN_SECRET_PATTERNS.iter() {
        let source = current.as_deref().unwrap_or(text);
        let spans = secret_pattern_spans(pattern, source);
        if spans.is_empty() {
            continue;
        }
        let mut redacted = String::with_capacity(source.len());
        let mut copied = 0;
        for (start, end) in spans {
            redacted.push_str(&source[copied..start]);
            redacted.push_str(REDACTED);
            copied = end;
            on_match(pattern.name);
        }
        redacted.push_str(&source[copied..]);
        current = Some(redacted);
    }
    current
}

fn is_terminal_kind(kind: &str) -> bool {
    matches!(
        kind,
        "process.stdout" | "process.stderr" | "process.terminal"
    )
}

/// Field names (normalized: lowercase letters and digits only) whose values
/// are secret. A key matches when it equals or ends with one of these names.
/// This is the single list shared by record-time redaction, recorded command
/// lines, and `premier export`.
pub const DEFAULT_REDACTED_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "token",
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "secretaccesskey",
    "privatekey",
    "credential",
    "credentials",
    "bearer",
];

#[derive(Clone, Debug)]
pub struct RedactionConfig {
    fields: HashSet<String>,
    custom_fields: Vec<String>,
    terminal_literals: Vec<String>,
    terminal_regexes: Vec<regex::Regex>,
    /// Regex rules that may match across line breaks (opt-in).
    terminal_multiline_regexes: Vec<regex::Regex>,
    /// Built-in value patterns on structured payloads and the command line.
    structured_patterns: bool,
    /// Built-in value patterns on captured terminal text (opt-in).
    terminal_patterns: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self::new(
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .expect("empty redaction patterns are valid")
    }
}

impl RedactionConfig {
    pub fn new(
        custom_fields: impl IntoIterator<Item = impl Into<String>>,
        terminal_literals: impl IntoIterator<Item = impl Into<String>>,
        terminal_regexes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let mut fields: HashSet<String> = DEFAULT_REDACTED_FIELDS
            .iter()
            .map(normalize_redaction_field)
            .collect();
        let mut custom_fields: Vec<String> = custom_fields
            .into_iter()
            .map(Into::into)
            .filter(|field| !field.trim().is_empty())
            .collect();
        custom_fields.sort();
        custom_fields.dedup();
        for field in &custom_fields {
            let normalized = normalize_redaction_field(field);
            // An empty name would suffix-match, and so erase, every field.
            if normalized.is_empty() {
                bail!("invalid redaction field name {field:?}: it must contain a letter or digit")
            }
            fields.insert(normalized);
        }
        let terminal_literals = terminal_literals
            .into_iter()
            .map(Into::into)
            .filter(|literal| !literal.is_empty())
            .collect();
        let terminal_regexes = terminal_regexes
            .into_iter()
            .map(Into::into)
            .map(|pattern: String| {
                regex::Regex::new(&pattern)
                    .with_context(|| format!("invalid terminal redaction regex: {pattern}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            fields,
            custom_fields,
            terminal_literals,
            terminal_regexes,
            terminal_multiline_regexes: Vec::new(),
            structured_patterns: true,
            terminal_patterns: false,
        })
    }

    /// Add regex rules that may match across line breaks. Unlike the
    /// line-scoped rules they are matched over a sliding window of held
    /// terminal text ([`MULTILINE_WINDOW_BYTES`]) and over whole string values
    /// in structured payloads. The syntax is unchanged: `.` still stops at a
    /// line break unless the pattern says otherwise (`(?s)`, `\n`, `\s`).
    pub fn multiline_regexes(
        mut self,
        patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        for pattern in patterns {
            let pattern: String = pattern.into();
            self.terminal_multiline_regexes
                .push(regex::Regex::new(&pattern).with_context(|| {
                    format!("invalid multi-line terminal redaction regex: {pattern}")
                })?);
        }
        Ok(self)
    }

    /// Whether the built-in secret value patterns (see
    /// [`builtin_secret_pattern_names`]) apply to structured payload strings
    /// and the recorded command line. On by default.
    pub fn default_secret_patterns(mut self, enabled: bool) -> Self {
        self.structured_patterns = enabled;
        self
    }

    /// Whether the built-in secret value patterns also apply to captured
    /// terminal text. Off by default: terminal output is stored raw unless
    /// the user configures a rule for it.
    pub fn known_secrets_in_terminal(mut self, enabled: bool) -> Self {
        self.terminal_patterns = enabled;
        self
    }

    fn provenance(&self) -> RedactionProvenance {
        let builtin = self.structured_patterns || self.terminal_patterns;
        RedactionProvenance {
            structured_defaults: true,
            custom_fields: self.custom_fields.clone(),
            terminal_literal_count: self.terminal_literals.len(),
            terminal_regex_count: self.terminal_regexes.len(),
            terminal_multiline_regex_count: self.terminal_multiline_regexes.len(),
            builtin_patterns: if builtin {
                builtin_secret_pattern_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            } else {
                Vec::new()
            },
            builtin_patterns_structured: self.structured_patterns,
            builtin_patterns_terminal: self.terminal_patterns,
        }
    }

    fn has_text_rules(&self) -> bool {
        !self.terminal_literals.is_empty()
            || !self.terminal_regexes.is_empty()
            || !self.terminal_multiline_regexes.is_empty()
    }

    /// Whether any rule can rewrite captured terminal text.
    fn redacts_terminal(&self) -> bool {
        self.has_text_rules() || self.terminal_patterns
    }

    fn redact_text(&self, text: &str) -> String {
        let mut redacted = String::with_capacity(text.len());
        let mut copied = 0;
        for (start, end) in literal_spans(text, &self.terminal_literals) {
            redacted.push_str(&text[copied..start]);
            redacted.push_str(REDACTED);
            copied = end;
        }
        redacted.push_str(&text[copied..]);
        for pattern in self
            .terminal_regexes
            .iter()
            .chain(&self.terminal_multiline_regexes)
        {
            redacted = pattern.replace_all(&redacted, REDACTED).into_owned();
        }
        redacted
    }

    /// Apply the literal and regex rules (`rules`) and the built-in secret
    /// value patterns (`patterns`) to every string value in `value`.
    fn redact_strings(&self, value: &mut serde_json::Value, rules: bool, patterns: bool) {
        match value {
            serde_json::Value::String(text) => {
                if rules {
                    *text = self.redact_text(text);
                }
                if patterns && let Some(redacted) = redact_builtin_secrets(text, &mut |_| {}) {
                    *text = redacted;
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    self.redact_strings(item, rules, patterns);
                }
            }
            serde_json::Value::Object(object) => {
                for (_, child) in object {
                    self.redact_strings(child, rules, patterns);
                }
            }
            _ => {}
        }
    }

    /// Redact a structured (non-terminal) string such as the run name or one
    /// command argument: the literal and regex rules, then the built-in
    /// secret value patterns unless they are switched off.
    fn redact_structured_text(&self, text: &str) -> String {
        let redacted = self.redact_text(text);
        if self.structured_patterns
            && let Some(redacted) = redact_builtin_secrets(&redacted, &mut |_| {})
        {
            return redacted;
        }
        redacted
    }

    /// Redact a recorded command line: values of secret-named flags,
    /// assignments and headers, then the literal and regex rules and the
    /// built-in secret value patterns.
    fn redact_command(&self, command: &[String]) -> Vec<String> {
        redact_command_fields(command, &|name| field_is_secret(name, &self.fields))
            .iter()
            .map(|argument| self.redact_structured_text(argument))
            .collect()
    }

    /// `native_stdout` marks a trace whose stdout is also normalized by a
    /// native adapter, so its raw JSON lines carry the same structured fields.
    fn redact_event(&self, kind: &str, payload: &mut serde_json::Value, native_stdout: bool) {
        redact_structured_fields(payload, &self.fields);
        if kind == "session.start"
            && let Some(command) = payload.get("command").and_then(string_items)
        {
            payload["command"] = serde_json::json!(self.redact_command(&command));
        }
        if native_stdout
            && kind == "process.stdout"
            && let Some(text) = payload.get("text").and_then(serde_json::Value::as_str)
            && let Some(redacted) = self.redact_structured_lines(text)
        {
            payload["text"] = serde_json::Value::String(redacted);
        }
        // Captured terminal text is raw unless the user opted in.
        let patterns = if is_terminal_kind(kind) {
            self.terminal_patterns
        } else {
            self.structured_patterns
        };
        let rules = self.has_text_rules();
        if rules || patterns {
            self.redact_strings(payload, rules, patterns);
        }
    }

    /// Redact the JSON-object lines of raw terminal text the way the same
    /// objects are redacted as structured payloads: secret fields, plus the
    /// built-in secret value patterns. Lines that are not JSON objects, or
    /// need no redaction, keep their exact bytes; `None` means nothing changed.
    fn redact_structured_lines(&self, text: &str) -> Option<String> {
        let mut changed = false;
        let mut output = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let body = line.trim_end_matches(['\r', '\n']);
            let redacted = body
                .trim_start()
                .starts_with('{')
                .then(|| serde_json::from_str::<serde_json::Value>(body).ok())
                .flatten()
                .and_then(|original| {
                    let mut value = original.clone();
                    redact_structured_fields(&mut value, &self.fields);
                    self.redact_strings(&mut value, false, self.structured_patterns);
                    (value != original).then(|| value.to_string())
                });
            match redacted {
                Some(redacted) => {
                    changed = true;
                    output.push_str(&redacted);
                    output.push_str(&line[body.len()..]);
                }
                None => output.push_str(line),
            }
        }
        changed.then_some(output)
    }
}

fn normalize_redaction_field(field: impl AsRef<str>) -> String {
    field
        .as_ref()
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn field_is_secret<'a>(name: &str, fields: impl IntoIterator<Item = &'a String>) -> bool {
    let normalized = normalize_redaction_field(name);
    fields
        .into_iter()
        .any(|sensitive| normalized == *sensitive || normalized.ends_with(sensitive.as_str()))
}

/// Whether a payload key, flag, or header name is secret under the default
/// field list ([`DEFAULT_REDACTED_FIELDS`]).
pub fn is_secret_field_name(name: &str) -> bool {
    let normalized = normalize_redaction_field(name);
    DEFAULT_REDACTED_FIELDS
        .iter()
        .any(|sensitive| normalized == *sensitive || normalized.ends_with(sensitive))
}

/// Redact secret values from an argument or header list using the default
/// field list: `--api-key=VALUE`, `--token VALUE`, `API_KEY=VALUE` and
/// `Authorization: VALUE`. Names and non-secret arguments are preserved.
pub fn redact_command_secrets(command: &[String]) -> Vec<String> {
    redact_command_fields(command, &is_secret_field_name)
}

fn redact_command_fields(command: &[String], is_secret: &dyn Fn(&str) -> bool) -> Vec<String> {
    let is_name = |name: &str| !name.contains(char::is_whitespace) && is_secret(name);
    let mut value_follows = false;
    command
        .iter()
        .map(|argument| {
            // `--token VALUE`: the value is the next argument unless that is a flag.
            if std::mem::take(&mut value_follows) && !argument.starts_with('-') {
                return REDACTED.to_owned();
            }
            for separator in ['=', ':'] {
                if let Some((name, value)) = argument.split_once(separator)
                    && !value.trim().is_empty()
                    && is_name(name)
                {
                    let space = if value.starts_with(' ') { " " } else { "" };
                    return format!("{name}{separator}{space}{REDACTED}");
                }
            }
            value_follows = argument.starts_with('-') && is_name(argument);
            argument.clone()
        })
        .collect()
}

fn string_items(value: &serde_json::Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// Carry-over buffer that keeps redaction correct when captured terminal
/// output arrives in arbitrary chunks. It never rewrites text: it only delays
/// it, releasing each piece at a point no literal rule can straddle (and, when
/// regex or structured-line rules are active, only at line ends), so the
/// per-event redaction in [`TraceWriter::append_input`] sees secrets whole.
/// With no rules configured it is a pass-through.
///
/// Limits, stated explicitly:
/// - Regex rules are line-scoped: a match is only guaranteed within one line
///   of terminal output, never across a line break. The one multi-line
///   built-in, a PEM private key block, is held until its end marker.
/// - A line longer than [`MAX_HELD_LINE_BYTES`] without a line break is cut
///   early, keeping the last [`HELD_OVERLAP_BYTES`] held and never cutting
///   inside a match, so a match up to that size cannot straddle the cut.
/// - Multi-line regex rules are matched over a sliding window instead: the
///   last [`MULTILINE_WINDOW_BYTES`] stay held and a release never cuts
///   inside a match, so a match up to that size is seen whole across line
///   breaks and chunk boundaries. A longer match may be split.
/// - [`Self::flush_idle`] releases a held partial line (such as a prompt)
///   early; a regex match the stream pauses inside may then be split.
#[derive(Clone, Debug)]
pub struct TerminalRedactionBuffer {
    literals: Vec<String>,
    regexes: Vec<regex::Regex>,
    /// Regex rules that may match across line breaks.
    multiline_regexes: Vec<regex::Regex>,
    /// The built-in secret value patterns apply to this stream.
    known_secrets: bool,
    /// The stream is JSONL whose object lines are redacted as structured data.
    structured_lines: bool,
    held: String,
    held_bytes: usize,
}

impl TerminalRedactionBuffer {
    /// Add decoded text plus the number of captured bytes it accounts for.
    /// Returns the text that is now safe to journal, with its byte length.
    pub fn push(&mut self, text: &str, byte_length: usize) -> Option<(String, usize)> {
        self.held.push_str(text);
        self.held_bytes += byte_length;
        let cut = self.safe_cut();
        self.release(cut)
    }

    /// Release everything still held once the stream has ended.
    pub fn finish(&mut self) -> Option<(String, usize)> {
        self.release(self.held.len())
    }

    /// Release a held partial line once the stream has gone quiet, so an
    /// unterminated line such as an interactive prompt is journaled without
    /// waiting for its line break. What a literal rule or an open private key
    /// block could still complete stays held, and so does a partial JSONL
    /// line, which can only be redacted as structured data once it is whole.
    pub fn flush_idle(&mut self) -> Option<(String, usize)> {
        if self.structured_lines {
            return None;
        }
        let cut = self.literal_safe_cut(self.open_block_cut(self.held.len()));
        self.release(cut)
    }

    fn hold_lines(&self) -> bool {
        !self.regexes.is_empty() || self.known_secrets || self.structured_lines
    }

    fn release(&mut self, cut: usize) -> Option<(String, usize)> {
        if cut == 0 {
            return None;
        }
        let rest = self.held.split_off(cut);
        let text = std::mem::replace(&mut self.held, rest);
        let byte_length = if self.held.is_empty() {
            self.held_bytes
        } else {
            self.held_bytes.min(text.len())
        };
        self.held_bytes -= byte_length;
        Some((text, byte_length))
    }

    fn safe_cut(&self) -> usize {
        let cut = self.line_rule_cut();
        if self.multiline_regexes.is_empty() {
            cut
        } else {
            self.window_cut(cut)
        }
    }

    /// Cut for the multi-line rules, at or before `limit` (the cut every
    /// other rule allows): the last [`MULTILINE_WINDOW_BYTES`] stay held, and
    /// the cut moves back to the start of any rule match it would split. It
    /// stays on a line end while line-scoped rules are active. A single match
    /// too long to hold is split.
    fn window_cut(&self, limit: usize) -> usize {
        let text = self.held.as_str();
        let mut target = limit.min(text.len().saturating_sub(MULTILINE_WINDOW_BYTES));
        while !text.is_char_boundary(target) {
            target -= 1;
        }
        let line_end = if self.hold_lines() && target < limit {
            text[..target].rfind('\n').map_or(0, |index| index + 1)
        } else {
            target
        };
        [line_end, target]
            .into_iter()
            .map(|candidate| self.match_safe_cut(candidate))
            .find(|cut| text.len() - cut <= MAX_HELD_LINE_BYTES)
            .unwrap_or(target)
    }

    /// Latest point at or before `limit` that no complete regex, built-in
    /// pattern, or literal match extends across.
    fn match_safe_cut(&self, limit: usize) -> usize {
        let text = self.held.as_str();
        let mut spans = Vec::new();
        for regex in self.regexes.iter().chain(&self.multiline_regexes) {
            spans.extend(
                regex
                    .find_iter(text)
                    .map(|found| (found.start(), found.end())),
            );
        }
        if self.known_secrets {
            for pattern in BUILTIN_SECRET_PATTERNS.iter() {
                spans.extend(secret_pattern_spans(pattern, text));
            }
        }
        let mut cut = limit;
        loop {
            let moved = spans
                .iter()
                .filter(|(start, end)| *start < cut && cut < *end)
                .map(|(start, _)| *start)
                .min()
                .unwrap_or(cut);
            let moved = self.literal_safe_cut(moved);
            if moved == cut {
                return cut;
            }
            cut = moved;
        }
    }

    /// The cut the literal, line-scoped regex, and built-in rules allow.
    fn line_rule_cut(&self) -> usize {
        let text = self.held.as_str();
        let within_bound = |cut: usize| text.len() - cut <= MAX_HELD_LINE_BYTES;
        if self.hold_lines() {
            let line_end = text.rfind('\n').map_or(0, |index| index + 1);
            let cut = self.literal_safe_cut(self.open_block_cut(line_end));
            return if within_bound(cut) {
                cut
            } else {
                self.forced_cut()
            };
        }
        // An over-long literal prefix is released rather than held without bound.
        let cut = self.literal_safe_cut(text.len());
        if within_bound(cut) { cut } else { text.len() }
    }

    /// Cut for a line that outgrew [`MAX_HELD_LINE_BYTES`]: everything but an
    /// overlap window, moved back to the start of any rule match that would
    /// otherwise straddle the cut. A single match too long to hold is split.
    fn forced_cut(&self) -> usize {
        let text = self.held.as_str();
        let mut target = text.len().saturating_sub(HELD_OVERLAP_BYTES);
        while !text.is_char_boundary(target) {
            target -= 1;
        }
        let cut = self.match_safe_cut(target);
        if text.len() - cut <= MAX_HELD_LINE_BYTES {
            cut
        } else {
            target
        }
    }

    /// Latest point at or before `limit` that does not release the opening
    /// of a private key block whose end marker has not arrived yet.
    fn open_block_cut(&self, limit: usize) -> usize {
        if !self.known_secrets {
            return limit;
        }
        let text = &self.held[..limit];
        let Some(begin) = PEM_BEGIN_PATTERN.find_iter(text).last() else {
            return limit;
        };
        if PEM_END_PATTERN.is_match(&text[begin.end()..]) {
            return limit;
        }
        text[..begin.start()]
            .rfind('\n')
            .map_or(0, |index| index + 1)
    }

    /// Latest point at or before `limit` that no literal occurrence, complete
    /// or still arriving, extends across.
    fn literal_safe_cut(&self, limit: usize) -> usize {
        let text = self.held.as_str();
        let mut cut = limit;
        for literal in &self.literals {
            // A literal that could still be completed by later output.
            let earliest = text.len().saturating_sub(literal.len() - 1);
            if let Some(start) = (earliest..cut).find(|&start| {
                text.is_char_boundary(start)
                    && literal.as_bytes().starts_with(&text.as_bytes()[start..])
            }) {
                cut = start;
            }
        }
        // A complete occurrence the cut would split in two.
        literal_spans(text, &self.literals)
            .into_iter()
            .find(|(start, end)| *start < cut && cut < *end)
            .map_or(cut, |(start, _)| start)
    }
}

/// Byte ranges of `text` covered by an occurrence of any literal. Overlapping
/// occurrences are merged, so the result does not depend on rule order and a
/// range never ends inside a secret.
fn literal_spans(text: &str, literals: &[String]) -> Vec<(usize, usize)> {
    let mut occurrences = Vec::new();
    for literal in literals {
        let mut from = 0;
        while let Some(found) = text[from..].find(literal.as_str()) {
            let start = from + found;
            occurrences.push((start, start + literal.len()));
            from = start + text[start..].chars().next().map_or(1, char::len_utf8);
        }
    }
    occurrences.sort_unstable();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (start, end) in occurrences {
        match spans.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => spans.push((start, end)),
        }
    }
    spans
}

fn redact_structured_fields(value: &mut serde_json::Value, fields: &HashSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if field_is_secret(key, fields) {
                    *child = serde_json::Value::String(REDACTED.into());
                } else {
                    redact_structured_fields(child, fields);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_structured_fields(item, fields);
            }
        }
        _ => {}
    }
}

pub struct TraceWriter {
    root: PathBuf,
    manifest: TraceManifest,
    journal: File,
    sequence: u64,
    /// Journal length after the last fully written frame.
    committed_bytes: u64,
    /// Set while the journal may hold bytes past `committed_bytes`.
    dirty: bool,
    /// Events lost to journal write failures; surfaced as a manifest diagnostic.
    dropped_events: u64,
    redaction: RedactionConfig,
    encryption_key: Option<EncryptionKey>,
    /// Hash the next event chains from: the genesis value, then the hash of
    /// the last committed event.
    chain_head: String,
    /// Signs the manifest seal at finalization when configured.
    signing_key: Option<SigningKey>,
}

impl TraceWriter {
    pub fn create(root: impl AsRef<Path>, command: Vec<String>) -> Result<Self> {
        Self::create_named(root, command, None)
    }

    pub fn create_named(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
    ) -> Result<Self> {
        Self::create_named_with_redaction(root, command, name, RedactionConfig::default())
    }

    pub fn create_named_with_redaction(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        redaction: RedactionConfig,
    ) -> Result<Self> {
        Self::create_named_for_tenant_with_redaction(root, command, name, LOCAL_TENANT, redaction)
    }

    pub fn create_named_for_tenant_with_redaction(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        tenant_id: &str,
        redaction: RedactionConfig,
    ) -> Result<Self> {
        let master_key = crypto::key_from_environment()?;
        Self::create_with_master_key(root, command, name, tenant_id, redaction, master_key)
    }

    pub fn create_named_for_tenant_with_redaction_and_key(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        tenant_id: &str,
        redaction: RedactionConfig,
        master_key: EncryptionKey,
    ) -> Result<Self> {
        Self::create_with_master_key(root, command, name, tenant_id, redaction, Some(master_key))
    }

    fn create_with_master_key(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        tenant_id: &str,
        redaction: RedactionConfig,
        master_key: Option<EncryptionKey>,
    ) -> Result<Self> {
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty()
            || tenant_id.len() > 128
            || !tenant_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("tenant id must be 1-128 ASCII letters, digits, '.', '_' or '-'")
        }
        let signing_key = seal::signing_key_from_environment()?;
        let root = root.as_ref().to_path_buf();
        if root.exists() {
            bail!("trace path already exists: {}", root.display());
        }
        create_private_dir(&root)?;
        create_private_dir(&root.join("events"))?;
        create_private_dir(&root.join("blobs"))?;
        create_private_dir(&root.join("blobs/sha256"))?;
        create_private_dir(&root.join("indexes"))?;

        let mut capabilities = vec![
            "process".into(),
            "terminal".into(),
            "agent-events".into(),
            "causal-links".into(),
            "structured-redaction".into(),
        ];
        if redaction.redacts_terminal() {
            capabilities.push("terminal-redaction".into());
        }
        let trace_id = Uuid::now_v7().to_string();
        let encryption_key = master_key
            .as_ref()
            .map(|key| key.for_trace(&trace_id))
            .transpose()?;
        if encryption_key.is_some() {
            capabilities.push("encrypted-at-rest.xchacha20poly1305".into());
        }
        let manifest = TraceManifest {
            format_version: FORMAT_VERSION,
            trace_id,
            tenant_id: tenant_id.to_owned(),
            name: name
                .filter(|value| !value.trim().is_empty())
                .map(|value| redaction.redact_structured_text(&value)),
            command: redaction.redact_command(&command),
            started_at: Utc::now(),
            ended_at: None,
            exit_code: None,
            termination: None,
            journal: None,
            diagnostics: Vec::new(),
            capabilities,
            redaction: Some(redaction.provenance()),
            adapter: None,
            seal: None,
            encryption: encryption_key.as_ref().map(|_| EncryptionMetadata {
                algorithm: "XChaCha20-Poly1305".into(),
                key_id: master_key.as_ref().expect("master key exists").key_id(),
                private_manifest: String::new(),
            }),
        };
        write_manifest(&root, &manifest, encryption_key.as_ref())?;
        let journal = private_new_file(&root.join("events").join(ACTIVE_JOURNAL))?;
        let chain_head = seal::chain_genesis(&manifest.trace_id);
        Ok(Self {
            root,
            manifest,
            journal,
            sequence: 0,
            committed_bytes: 0,
            dirty: false,
            dropped_events: 0,
            redaction,
            encryption_key,
            chain_head,
            signing_key,
        })
    }

    pub fn trace_id(&self) -> &str {
        &self.manifest.trace_id
    }

    /// Sign the manifest seal with `key` when the trace is finalized,
    /// overriding any key configured through `PREMIER_SIGN_KEY_FILE`.
    pub fn set_signing_key(&mut self, key: SigningKey) {
        self.signing_key = Some(key);
    }

    /// Advertise an optional recorder feature in the portable manifest.
    /// Duplicate values are ignored so callers can compose capture modes.
    pub fn add_capability(&mut self, capability: impl Into<String>) -> Result<()> {
        let capability = capability.into();
        if !self.manifest.capabilities.contains(&capability) {
            self.manifest.capabilities.push(capability);
            write_manifest(&self.root, &self.manifest, self.encryption_key.as_ref())?;
        }
        Ok(())
    }

    /// Record which native structured stream contributed normalized evidence.
    pub fn set_adapter(&mut self, adapter: AdapterProvenance) -> Result<()> {
        let capability = format!("adapter.{}.v{}", adapter.provider, adapter.schema_version);
        if !self.manifest.capabilities.contains(&capability) {
            self.manifest.capabilities.push(capability);
        }
        self.manifest.adapter = Some(adapter);
        write_manifest(&self.root, &self.manifest, self.encryption_key.as_ref())
    }

    /// Carry-over buffer for one captured output stream of `kind`
    /// (`process.stdout`, `process.stderr` or `process.terminal`). Feed it the
    /// decoded chunks and journal what it releases, so the redaction rules
    /// also catch secrets split across reads.
    pub fn terminal_redaction_buffer(&self, kind: &str) -> TerminalRedactionBuffer {
        TerminalRedactionBuffer {
            literals: self.redaction.terminal_literals.clone(),
            regexes: self.redaction.terminal_regexes.clone(),
            multiline_regexes: self.redaction.terminal_multiline_regexes.clone(),
            known_secrets: self.redaction.terminal_patterns,
            structured_lines: kind == "process.stdout" && self.manifest.adapter.is_some(),
            held: String::new(),
            held_bytes: 0,
        }
    }

    pub fn append(
        &mut self,
        kind: &str,
        source: &str,
        payload: serde_json::Value,
    ) -> Result<TraceEvent> {
        self.append_input(EventInput {
            kind: kind.to_owned(),
            source: source.to_owned(),
            payload,
            ..EventInput::default()
        })
    }

    pub fn append_input(&mut self, mut input: EventInput) -> Result<TraceEvent> {
        if input.kind.trim().is_empty() {
            bail!("event kind cannot be empty")
        }
        self.redaction.redact_event(
            &input.kind,
            &mut input.payload,
            self.manifest.adapter.is_some(),
        );
        let timestamp = input
            .timestamp
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        let event = TraceEvent {
            event_id: Uuid::now_v7().to_string(),
            trace_id: self.manifest.trace_id.clone(),
            sequence: self.sequence + 1,
            timestamp,
            kind: input.kind,
            source: input.source,
            payload_json: serde_json::to_string(&input.payload)?,
            actor_id: input.actor_id,
            actor_type: input.actor_type,
            parent_event_id: input.parent_event_id,
            span_id: input.span_id,
            parent_span_id: input.parent_span_id,
            correlation_id: input.correlation_id,
            status: input.status,
            duration_ms: input.duration_ms,
            links: input.links,
            prev_hash: self.chain_head.clone(),
        };
        // Encode first so an oversized or unencryptable event never touches
        // the journal, then commit the frame with a single write.
        let mut frame = Vec::new();
        write_frame(
            &mut frame,
            &event,
            self.encryption_key.as_ref(),
            &self.manifest.trace_id,
        )?;
        if let Err(error) = self.commit_frame(&frame) {
            self.dropped_events += 1;
            return Err(error);
        }
        self.sequence = event.sequence;
        self.chain_head = seal::event_hash(&event);
        Ok(event)
    }

    /// Append one encoded frame, or leave the journal exactly as it was. A
    /// failed write (disk full, quota) is rolled back to the last complete
    /// frame so later appends neither bury a torn frame nor reuse a sequence.
    fn commit_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.restore_committed()?;
        self.dirty = true;
        if let Err(error) = self.journal.write_all(frame) {
            // If the rollback fails too the writer stays dirty, and every
            // later append or finish retries it before touching the journal.
            let _ = self.restore_committed();
            return Err(error).context("failed to write trace journal frame");
        }
        self.committed_bytes += frame.len() as u64;
        self.dirty = false;
        Ok(())
    }

    fn restore_committed(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.journal
            .set_len(self.committed_bytes)
            .and_then(|()| self.journal.seek(SeekFrom::Start(self.committed_bytes)))
            .context("trace journal is unusable: cannot discard a partially written frame")?;
        self.dirty = false;
        Ok(())
    }

    /// Number of events that could not be journaled because a write failed.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    pub fn finish(self, exit_code: i32) -> Result<TraceManifest> {
        self.finish_termination(ProcessTermination::exited(exit_code))
    }

    pub fn finish_termination(mut self, termination: ProcessTermination) -> Result<TraceManifest> {
        self.restore_committed()?;
        self.journal.sync_all()?;
        drop(self.journal);
        finalize_active_journal(
            &self.root,
            self.manifest,
            self.sequence,
            termination,
            self.encryption_key.as_ref(),
            self.dropped_events,
            self.signing_key.as_ref(),
            false,
        )
    }
}

/// Finalize an abandoned active trace while preserving every complete frame.
/// A torn trailing frame is discarded and represented by a terminal recovery
/// event. Fresh traces are guarded by default so operators cannot accidentally
/// recover a recording that is still receiving events.
pub fn recover_interrupted_trace(
    root: impl AsRef<Path>,
    options: RecoveryOptions,
) -> Result<TraceManifest> {
    let root = root.as_ref();
    let mut manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    if manifest.journal.is_some() {
        bail!("trace is already finalized")
    }
    let active = root.join("events").join(ACTIVE_JOURNAL);
    if !active.is_file() {
        bail!("trace has no active journal to recover")
    }
    if !options.force {
        let mut modified = fs::metadata(&active)?.modified()?;
        let lease = root.join(RECORDER_LEASE);
        if let Ok(lease_modified) = fs::metadata(lease).and_then(|metadata| metadata.modified()) {
            modified = modified.max(lease_modified);
        }
        let idle = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(StdDuration::ZERO);
        if idle < options.minimum_idle {
            bail!(
                "trace appears active (journal idle for {}s; require {}s or pass --force)",
                idle.as_secs(),
                options.minimum_idle.as_secs()
            )
        }
    }
    let bytes = fs::read(&active)?;
    let (mut events, valid_bytes) =
        read_complete_frames(&bytes, encryption_key.as_ref(), &manifest.trace_id)?;
    if events
        .iter()
        .any(|event| event.trace_id != manifest.trace_id)
    {
        bail!("active journal contains an event from a different trace")
    }
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1 {
            bail!("active journal event sequence is not contiguous")
        }
    }
    // Re-derive the chain head from the complete frames. A journal whose
    // chain is already broken was altered, so it is not sealed as recovered.
    let chained = manifest.format_version >= 2;
    let prev_hash = if chained {
        seal::chain_head(&manifest.trace_id, &events)
            .context("cannot recover: the active journal failed chain verification")?
    } else {
        String::new()
    };
    let signing_key = seal::signing_key_from_environment()?;
    let discarded_bytes = bytes.len().saturating_sub(valid_bytes);
    let recovery_event = TraceEvent {
        event_id: Uuid::now_v7().to_string(),
        trace_id: manifest.trace_id.clone(),
        sequence: events.len() as u64 + 1,
        timestamp: Utc::now().to_rfc3339(),
        kind: "session.interrupted".into(),
        source: "premier-recovery".into(),
        payload_json: serde_json::to_string(&serde_json::json!({
            "reason": "recorder_interrupted",
            "recovered_event_count": events.len(),
            "discarded_trailing_bytes": discarded_bytes,
        }))?,
        actor_id: "root".into(),
        actor_type: "process".into(),
        parent_event_id: String::new(),
        span_id: "session".into(),
        parent_span_id: String::new(),
        correlation_id: String::new(),
        status: "error".into(),
        duration_ms: 0,
        links: Vec::new(),
        prev_hash,
    };
    events.push(recovery_event);

    // A prior finalization may have crashed after publishing the compressed
    // journal but before committing the manifest. Do not remove that orphan
    // until the authoritative active journal has passed validation.
    let orphaned_final = root.join("events").join(FINAL_JOURNAL);
    if orphaned_final.exists() {
        fs::remove_file(orphaned_final)?;
    }

    let replacement = active.with_extension("pb.recovery.tmp");
    {
        let file = private_truncate_file(&replacement)?;
        let mut writer = BufWriter::new(file);
        for event in &events {
            write_frame(
                &mut writer,
                event,
                encryption_key.as_ref(),
                &manifest.trace_id,
            )?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(&replacement, &active)?;
    manifest.termination = None;
    finalize_active_journal(
        root,
        manifest,
        events.len() as u64,
        ProcessTermination::interrupted(),
        encryption_key.as_ref(),
        0,
        signing_key.as_ref(),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize_active_journal(
    root: &Path,
    mut manifest: TraceManifest,
    event_count: u64,
    termination: ProcessTermination,
    encryption_key: Option<&EncryptionKey>,
    dropped_events: u64,
    signing_key: Option<&SigningKey>,
    recovered: bool,
) -> Result<TraceManifest> {
    let active = root.join("events").join(ACTIVE_JOURNAL);
    let final_path = root.join("events").join(FINAL_JOURNAL);
    let temporary_final = root.join("events").join(format!("{FINAL_JOURNAL}.tmp"));
    let mut input = BufReader::new(File::open(&active)?);
    let output = BufWriter::new(private_truncate_file(&temporary_final)?);
    let mut encoder = zstd::stream::write::Encoder::new(output, 3)?;
    std::io::copy(&mut input, &mut encoder)?;
    encoder.finish()?.into_inner()?.sync_all()?;
    fs::rename(&temporary_final, &final_path)?;

    let events = read_frames(
        BufReader::new(File::open(&active)?),
        encryption_key,
        &manifest.trace_id,
    )?;
    manifest.diagnostics = validate_events(&events);
    if dropped_events > 0 {
        manifest.diagnostics.push(TraceDiagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "journal.write_failed".into(),
            message: format!(
                "{dropped_events} event(s) were not recorded because the journal could not be written"
            ),
            event_id: None,
            sequence: None,
        });
    }
    manifest.ended_at = Some(Utc::now());
    manifest.exit_code = Some(termination.shell_exit_code());
    manifest.termination = Some(termination);
    manifest.journal = Some(JournalFile {
        path: format!("events/{FINAL_JOURNAL}"),
        sha256: sha256_file(&final_path)?,
        event_count,
    });
    // Version 1 journals carry no chain; they finalize as digest-only traces.
    if manifest.format_version >= 2 {
        let chain_head = seal::chain_head(&manifest.trace_id, &events)?;
        seal::seal_manifest(
            &mut manifest,
            chain_head,
            events.len() as u64,
            recovered,
            signing_key,
        )?;
    }
    write_manifest(root, &manifest, encryption_key)?;
    fs::remove_file(active)?;
    let lease = root.join(RECORDER_LEASE);
    if lease.exists() {
        fs::remove_file(lease)?;
    }
    Ok(manifest)
}

pub fn validate_events(events: &[TraceEvent]) -> Vec<TraceDiagnostic> {
    // The kinds first-party producers emit: the demo, the SDK helpers and the native adapters.
    const KNOWN: [&str; 14] = [
        "agent.spawn",
        "agent.turn",
        "agent.result",
        "agent.delegation",
        "agent.join",
        "agent.message",
        "model.request",
        "model.response",
        "tool.invocation",
        "tool.result",
        "tool.execution",
        "tool.error",
        "approval.request",
        "approval.decision",
    ];
    const STATUSES: [&str; 14] = [
        "running",
        "ok",
        "error",
        "failed",
        "denied",
        "blocked",
        "pending",
        "approved",
        "rejected",
        "cancelled",
        "completed",
        "success",
        "warning",
        "skipped",
    ];
    let mut diagnostics = Vec::new();
    let mut seen_event_ids = HashSet::new();
    for event in events {
        if !event.parent_event_id.is_empty()
            && !seen_event_ids.contains(event.parent_event_id.as_str())
        {
            diagnostics.push(diagnostic(
                event,
                "unknown_parent_event",
                format!(
                    "{} references unknown or forward parent event {}",
                    event.kind, event.parent_event_id
                ),
            ));
        }
        seen_event_ids.insert(event.event_id.as_str());
    }
    for event in events {
        if !KNOWN.contains(&event.kind.as_str()) {
            continue;
        }
        if event.status.trim().is_empty() {
            diagnostics.push(diagnostic(
                event,
                "missing_status",
                format!("{} must declare a status", event.kind),
            ));
        } else if !STATUSES.contains(&event.status.to_ascii_lowercase().as_str()) {
            diagnostics.push(diagnostic(
                event,
                "invalid_status",
                format!("{} uses unknown status '{}'", event.kind, event.status),
            ));
        }
        if !event.payload().is_object() {
            diagnostics.push(diagnostic(
                event,
                "payload_not_object",
                format!("{} payload must be a JSON object", event.kind),
            ));
        }
    }
    for lifecycle in &LIFECYCLES {
        validate_pair(events, lifecycle, &mut diagnostics);
    }
    diagnostics
}

struct Lifecycle {
    starts: &'static [&'static str],
    finish: &'static str,
    /// Whether a finish with no recorded start is an evidence gap.
    start_required: bool,
    /// Whether a start that never finishes is an evidence gap.
    finish_required: bool,
}

/// Lifecycles as first-party producers emit them. `model.response` and `tool.result` are also
/// recorded as self-contained calls (like `tool.execution`), and an agent's `agent.spawn` or
/// `agent.turn` may stay open or be closed by `agent.join`, so only the remaining directions
/// count as incomplete.
const LIFECYCLES: [Lifecycle; 5] = [
    Lifecycle {
        starts: &["agent.spawn", "agent.turn"],
        finish: "agent.result",
        start_required: true,
        finish_required: false,
    },
    Lifecycle {
        starts: &["model.request"],
        finish: "model.response",
        start_required: false,
        finish_required: true,
    },
    Lifecycle {
        starts: &["tool.invocation"],
        finish: "tool.result",
        start_required: false,
        finish_required: true,
    },
    Lifecycle {
        starts: &["approval.request"],
        finish: "approval.decision",
        start_required: true,
        finish_required: true,
    },
    Lifecycle {
        starts: &["agent.delegation"],
        finish: "agent.join",
        start_required: true,
        finish_required: true,
    },
];

fn diagnostic(event: &TraceEvent, code: &str, message: String) -> TraceDiagnostic {
    TraceDiagnostic {
        severity: DiagnosticSeverity::Warning,
        code: code.into(),
        message,
        event_id: Some(event.event_id.clone()),
        sequence: Some(event.sequence),
    }
}

fn validate_pair(
    events: &[TraceEvent],
    lifecycle: &Lifecycle,
    diagnostics: &mut Vec<TraceDiagnostic>,
) {
    let start_kind = lifecycle.starts[0];
    let finish_kind = lifecycle.finish;
    let starts: Vec<_> = events
        .iter()
        .filter(|event| lifecycle.starts.contains(&event.kind.as_str()))
        .collect();
    let finishes: Vec<_> = events
        .iter()
        .filter(|event| event.kind == finish_kind)
        .collect();
    let mut by_correlation = HashMap::new();
    let mut by_span = HashMap::new();
    let mut by_actor = HashMap::new();
    for start in &starts {
        if !start.correlation_id.is_empty() {
            by_correlation
                .entry(start.correlation_id.as_str())
                .or_insert(*start);
        }
        if !start.span_id.is_empty() {
            by_span.entry(start.span_id.as_str()).or_insert(*start);
        }
        if !start.actor_id.is_empty() {
            by_actor.entry(start.actor_id.as_str()).or_insert(*start);
        }
    }
    let mut matched_starts = HashSet::new();
    let mut matched_correlations = HashSet::new();
    for finish in finishes {
        let antecedent = if !finish.correlation_id.is_empty() {
            by_correlation.get(finish.correlation_id.as_str()).copied()
        } else {
            by_span
                .get(finish.span_id.as_str())
                .or_else(|| by_span.get(finish.parent_span_id.as_str()))
                .or_else(|| by_actor.get(finish.actor_id.as_str()))
                .copied()
        };
        let Some(start) = antecedent else {
            if lifecycle.start_required {
                diagnostics.push(diagnostic(
                    finish,
                    "missing_lifecycle_start",
                    format!("{finish_kind} has no matching {start_kind}"),
                ));
            }
            continue;
        };
        matched_starts.insert(start.event_id.as_str());
        if !start.correlation_id.is_empty() {
            // Several records of one call (a hook and the call itself) share its correlation.
            matched_correlations.insert(start.correlation_id.as_str());
        }
        let causally_linked = finish.parent_event_id == start.event_id
            || finish.links.iter().any(|link| link == &start.event_id)
            || (!finish.span_id.is_empty() && finish.span_id == start.span_id)
            || (!finish.parent_span_id.is_empty()
                && (finish.parent_span_id == start.span_id
                    || finish.parent_span_id == start.parent_span_id))
            || (!finish.correlation_id.is_empty() && finish.correlation_id == start.correlation_id);
        if !causally_linked {
            diagnostics.push(diagnostic(
                finish,
                "missing_causal_link",
                format!("{finish_kind} matches {start_kind} but has no causal link"),
            ));
        }
    }
    if !lifecycle.finish_required {
        return;
    }
    for start in starts {
        if !matched_starts.contains(start.event_id.as_str())
            && !matched_correlations.contains(start.correlation_id.as_str())
        {
            diagnostics.push(diagnostic(
                start,
                "missing_lifecycle_finish",
                format!("{} has no matching {finish_kind}", start.kind),
            ));
        }
    }
}

pub fn read_events_page(
    root: impl AsRef<Path>,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<TraceEvent>> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    let final_path = root.join("events").join(FINAL_JOURNAL);
    let active_path = root.join("events").join(ACTIVE_JOURNAL);
    if final_path.exists() {
        let decoder = zstd::stream::read::Decoder::new(BufReader::new(File::open(final_path)?))?;
        read_frames_page(
            decoder,
            after_sequence,
            limit,
            encryption_key.as_ref(),
            &manifest.trace_id,
        )
    } else if active_path.exists() {
        read_frames_page(
            BufReader::new(File::open(active_path)?),
            after_sequence,
            limit,
            encryption_key.as_ref(),
            &manifest.trace_id,
        )
    } else {
        bail!("trace has no event journal")
    }
}

fn read_frames_page(
    mut reader: impl Read,
    after_sequence: u64,
    limit: usize,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::with_capacity(limit.min(1024));
    while events.len() < limit {
        let Some(event) = read_next_frame(&mut reader, encryption_key, trace_id)? else {
            break;
        };
        if event.sequence > after_sequence {
            events.push(event);
        }
    }
    Ok(events)
}

#[derive(Clone, Debug)]
pub struct ActiveEventTail {
    pub events: Vec<TraceEvent>,
    pub next_byte_offset: u64,
}

/// Read only complete frames appended to an active journal after `byte_offset`.
/// An incomplete trailing frame is intentionally left for the next poll.
pub fn read_active_events_after(
    root: impl AsRef<Path>,
    byte_offset: u64,
) -> Result<ActiveEventTail> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    let path = root.join("events").join(ACTIVE_JOURNAL);
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(byte_offset))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let (events, consumed) =
        read_complete_frames(&bytes, encryption_key.as_ref(), &manifest.trace_id)?;
    Ok(ActiveEventTail {
        events,
        next_byte_offset: byte_offset.saturating_add(consumed as u64),
    })
}

fn read_complete_frames(
    bytes: &[u8],
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<(Vec<TraceEvent>, usize)> {
    let mut events = Vec::new();
    let mut offset = 0_usize;
    while bytes.len().saturating_sub(offset) >= 4 {
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if length > MAX_FRAME_BYTES {
            bail!("event frame exceeds the 64 MiB safety limit")
        }
        let frame_end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .context("event frame length overflow")?;
        if frame_end > bytes.len() {
            break;
        }
        events.push(decode_frame(
            &bytes[offset + 4..frame_end],
            encryption_key,
            trace_id,
        )?);
        offset = frame_end;
    }
    Ok((events, offset))
}

pub fn read_manifest(root: impl AsRef<Path>) -> Result<TraceManifest> {
    read_manifest_with_optional_key(root.as_ref(), None)
}

pub fn read_manifest_with_key(
    root: impl AsRef<Path>,
    master_key: &EncryptionKey,
) -> Result<TraceManifest> {
    read_manifest_with_optional_key(root.as_ref(), Some(master_key))
}

fn read_manifest_with_optional_key(
    root: &Path,
    master_key: Option<&EncryptionKey>,
) -> Result<TraceManifest> {
    let bytes = fs::read(root.join("manifest.json"))?;
    let mut manifest: TraceManifest = serde_json::from_slice(&bytes)?;
    if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&manifest.format_version) {
        bail!(
            "unsupported trace format version {}: this build reads versions {MIN_FORMAT_VERSION} to {FORMAT_VERSION}; a newer premier is needed for later versions",
            manifest.format_version
        );
    }
    if let Some(metadata) = manifest.encryption.as_ref() {
        let key = if let Some(master_key) = master_key {
            if master_key.key_id() != metadata.key_id {
                bail!("trace decryption failed: wrong key")
            }
            master_key.for_trace(&manifest.trace_id)?
        } else {
            required_encryption_key(&manifest)?.context("encrypted trace requires a key")?
        };
        let aad = manifest_aad(&manifest);
        let plaintext = key.decrypt(&metadata.private_manifest, aad.as_bytes())?;
        let private: PrivateManifest = serde_json::from_slice(&plaintext)?;
        manifest.name = private.name;
        manifest.command = private.command;
        manifest.ended_at = private.ended_at;
        manifest.exit_code = private.exit_code;
        manifest.termination = private.termination;
        manifest.journal = private.journal;
        manifest.diagnostics = private.diagnostics;
        manifest.capabilities = private.capabilities;
        manifest.redaction = private.redaction;
        manifest.adapter = private.adapter;
        manifest.seal = private.seal;
    }
    Ok(manifest)
}

pub fn read_events(root: impl AsRef<Path>) -> Result<Vec<TraceEvent>> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    read_events_from_storage(root, &manifest, encryption_key.as_ref())
}

pub fn read_events_with_key(
    root: impl AsRef<Path>,
    master_key: &EncryptionKey,
) -> Result<Vec<TraceEvent>> {
    let root = root.as_ref();
    let manifest = read_manifest_with_key(root, master_key)?;
    let encryption_key = manifest
        .encryption
        .as_ref()
        .map(|_| master_key.for_trace(&manifest.trace_id))
        .transpose()?;
    read_events_from_storage(root, &manifest, encryption_key.as_ref())
}

fn read_events_from_storage(
    root: &Path,
    manifest: &TraceManifest,
    encryption_key: Option<&EncryptionKey>,
) -> Result<Vec<TraceEvent>> {
    let final_path = root.join("events").join(FINAL_JOURNAL);
    let active_path = root.join("events").join(ACTIVE_JOURNAL);
    if final_path.exists() {
        let decoder = zstd::stream::read::Decoder::new(BufReader::new(File::open(final_path)?))?;
        read_frames(decoder, encryption_key, &manifest.trace_id)
    } else if active_path.exists() {
        read_frames(
            BufReader::new(File::open(active_path)?),
            encryption_key,
            &manifest.trace_id,
        )
    } else {
        bail!("trace has no event journal")
    }
}

pub fn verify(root: impl AsRef<Path>) -> Result<TraceManifest> {
    Ok(verify_trace(root, None)?.manifest)
}

/// Outcome of a successful [`verify_trace`].
#[derive(Clone, Debug)]
pub struct VerifiedTrace {
    pub manifest: TraceManifest,
    pub protection: Protection,
    /// Key whose signature over the seal is valid, when the trace is signed.
    pub signer: Option<PublicKey>,
    /// True only when the caller supplied a key and it is the signer.
    pub trusted_signer: bool,
}

/// Verify a finalized trace and report how strongly it is protected. With
/// `trusted_key`, anything short of a valid signature by that key is an error.
/// Without it, a signed trace is only known to be signed by the key embedded
/// in its own manifest, and an unsigned one is merely self-consistent: whoever
/// can rewrite the directory can rebuild the chain and the seal.
pub fn verify_trace(
    root: impl AsRef<Path>,
    trusted_key: Option<&PublicKey>,
) -> Result<VerifiedTrace> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    verify_journal_digest(root, &manifest)?;
    let events = read_events(root)?;
    let status = verify_decoded_events(&manifest, &events)?;
    if let Some(trusted) = trusted_key {
        match status.signer.as_ref() {
            None if status.protection == Protection::DigestOnly => {
                bail!("version 1 traces cannot carry a signature (v1: digest only)")
            }
            None => bail!("trace is not signed"),
            Some(signer) if signer != trusted => bail!(
                "trace is signed by a different key ({}), not the supplied key ({})",
                signer.fingerprint(),
                trusted.fingerprint()
            ),
            Some(_) => {}
        }
    }
    Ok(VerifiedTrace {
        manifest,
        protection: status.protection,
        signer: status.signer,
        trusted_signer: trusted_key.is_some(),
    })
}

/// Sign (or re-sign) the seal of an already finalized version 2 trace. The
/// trace must verify first, so a signature is never added to altered evidence.
pub fn sign_finalized_trace(
    root: impl AsRef<Path>,
    signing_key: &SigningKey,
) -> Result<TraceManifest> {
    let root = root.as_ref();
    let mut manifest = verify(root)?;
    if manifest.seal.is_none() {
        bail!("version 1 traces have no seal to sign (v1: digest only)")
    }
    let encryption_key = required_encryption_key(&manifest)?;
    seal::reseal_manifest(&mut manifest, Some(signing_key))?;
    write_manifest(root, &manifest, encryption_key.as_ref())?;
    Ok(manifest)
}

/// Compare the finalized journal on disk against the manifest digest without
/// decoding any frames.
pub fn verify_journal_digest(root: impl AsRef<Path>, manifest: &TraceManifest) -> Result<()> {
    let journal = manifest
        .journal
        .as_ref()
        .context("trace is not finalized")?;
    if journal.path != format!("events/{FINAL_JOURNAL}") {
        bail!("manifest references a non-canonical journal path")
    }
    let actual_hash = sha256_file(&root.as_ref().join(&journal.path))?;
    if actual_hash != journal.sha256 {
        bail!("journal digest mismatch")
    }
    Ok(())
}

/// Check recorder-generated invariants of already-decoded events against the
/// manifest. Producer-controlled semantic references (`parent_event_id`,
/// `links`) are surfaced as [`validate_events`] diagnostics instead of
/// verification failures so a misbehaving subprocess cannot make an honest
/// trace permanently unverifiable. From format version 2 on this also checks
/// the event hash chain, the manifest seal and any signature.
pub fn verify_event_structure(manifest: &TraceManifest, events: &[TraceEvent]) -> Result<()> {
    verify_decoded_events(manifest, events).map(|_| ())
}

/// [`verify_event_structure`], returning the protection level that was verified.
pub fn verify_decoded_events(
    manifest: &TraceManifest,
    events: &[TraceEvent],
) -> Result<SealStatus> {
    let journal = manifest
        .journal
        .as_ref()
        .context("trace is not finalized")?;
    if events.len() as u64 != journal.event_count {
        bail!("event count mismatch")
    }
    if events
        .iter()
        .any(|event| event.trace_id != manifest.trace_id)
    {
        bail!("journal contains an event from a different trace")
    }
    let mut event_ids = HashSet::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if event.sequence != expected_sequence {
            bail!(
                "event sequence is not contiguous: expected {expected_sequence}, found {}",
                event.sequence
            )
        }
        if event.event_id.is_empty() || !event_ids.insert(event.event_id.as_str()) {
            bail!("journal contains an empty or duplicate event id")
        }
    }
    verify_tamper_evidence(manifest, events)
}

fn write_manifest(
    root: &Path,
    manifest: &TraceManifest,
    encryption_key: Option<&EncryptionKey>,
) -> Result<()> {
    let mut stored = manifest.clone();
    if let Some(key) = encryption_key {
        let private = PrivateManifest {
            name: stored.name.take(),
            command: std::mem::take(&mut stored.command),
            ended_at: stored.ended_at.take(),
            exit_code: stored.exit_code.take(),
            termination: stored.termination.take(),
            journal: stored.journal.take(),
            diagnostics: std::mem::take(&mut stored.diagnostics),
            capabilities: std::mem::take(&mut stored.capabilities),
            redaction: stored.redaction.take(),
            adapter: stored.adapter.take(),
            seal: stored.seal.take(),
        };
        let aad = manifest_aad(&stored);
        let encrypted = key.encrypt(&serde_json::to_vec(&private)?, aad.as_bytes())?;
        stored.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".into(),
            key_id: stored
                .encryption
                .as_ref()
                .map(|metadata| metadata.key_id.clone())
                .unwrap_or_else(|| key.key_id()),
            private_manifest: encrypted,
        });
    } else if stored.encryption.is_some() {
        bail!("refusing to write an encrypted manifest without its key")
    }
    let temporary = root.join("manifest.json.tmp");
    let mut file = private_truncate_file(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&stored)?)?;
    file.sync_all()?;
    fs::rename(temporary, root.join("manifest.json"))?;
    Ok(())
}

fn required_encryption_key(manifest: &TraceManifest) -> Result<Option<EncryptionKey>> {
    let Some(metadata) = manifest.encryption.as_ref() else {
        return Ok(None);
    };
    if metadata.algorithm != "XChaCha20-Poly1305" {
        bail!("unsupported trace encryption algorithm")
    }
    let master_key = crypto::key_from_environment()?
        .context("encrypted trace requires --key-file or PREMIER_TRACE_KEY_FILE")?;
    if master_key.key_id() != metadata.key_id {
        bail!("trace decryption failed: wrong key")
    }
    Ok(Some(master_key.for_trace(&manifest.trace_id)?))
}

fn manifest_aad(manifest: &TraceManifest) -> String {
    format!(
        "premier:manifest:v{}:{}:{}",
        manifest.format_version, manifest.trace_id, manifest.tenant_id
    )
}

/// Explicit offline ownership migration. Normal recording and viewer APIs never
/// mutate ownership; only a local trace may be claimed, and the manifest update
/// is atomic and re-encrypted under the existing key when applicable.
pub fn claim_local_trace(root: impl AsRef<Path>, tenant_id: &str) -> Result<TraceManifest> {
    validate_tenant_id(tenant_id)?;
    let root = root.as_ref();
    let mut manifest = read_manifest(root)?;
    if manifest.tenant_id != LOCAL_TENANT {
        bail!("only a local trace may be claimed")
    }
    let key = required_encryption_key(&manifest)?;
    manifest.tenant_id = tenant_id.to_owned();
    // The owner is a sealed field: re-seal, re-signing only when a signing
    // key is configured. Otherwise the previous signature is dropped.
    seal::reseal_manifest(
        &mut manifest,
        seal::signing_key_from_environment()?.as_ref(),
    )?;
    write_manifest(root, &manifest, key.as_ref())?;
    Ok(manifest)
}

/// Inspect only the public manifest envelope; no decryption key is required.
pub fn trace_is_encrypted(root: impl AsRef<Path>) -> Result<bool> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(root.as_ref().join("manifest.json"))?)?;
    Ok(value
        .get("encryption")
        .is_some_and(|value| !value.is_null()))
}

/// Encrypt a finalized plaintext trace or rotate an encrypted trace to a new
/// master key. The replacement is fully written and decrypted for verification
/// before the original directory is renamed; any publication failure rolls the
/// original directory back into place.
///
/// Events are re-encrypted unchanged, so the hash chain and its head are
/// preserved. The journal digest and encryption envelope are sealed fields,
/// so the seal is recomputed and an existing signature no longer applies: it
/// is re-applied with the `PREMIER_SIGN_KEY_FILE` key when one is configured
/// and dropped otherwise.
pub fn reencrypt_finalized_trace(
    root: impl AsRef<Path>,
    new_master_key: EncryptionKey,
) -> Result<TraceManifest> {
    let signing_key = seal::signing_key_from_environment()?;
    reencrypt_finalized_trace_with_signing_key(root, new_master_key, signing_key.as_ref())
}

/// [`reencrypt_finalized_trace`] with an explicit signing key choice.
pub fn reencrypt_finalized_trace_with_signing_key(
    root: impl AsRef<Path>,
    new_master_key: EncryptionKey,
    signing_key: Option<&SigningKey>,
) -> Result<TraceManifest> {
    let root = root.as_ref();
    let mut manifest = read_manifest(root)?;
    let events = read_events(root)?;
    let journal = manifest
        .journal
        .as_ref()
        .context("only finalized traces can be encrypted or rotated")?;
    if journal.path != format!("events/{FINAL_JOURNAL}") {
        bail!("trace uses a non-canonical journal path")
    }
    // Re-sealing writes a fresh digest and count for whatever decoded, so a
    // source that fails verification must never reach that step.
    verify_journal_digest(root, &manifest)?;
    verify_event_structure(&manifest, &events)?;
    ensure_no_unencrypted_auxiliary_files(root)?;

    let parent = root.parent().context("trace path has no parent")?;
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("trace");
    let nonce = Uuid::now_v7();
    let staging = parent.join(format!(".{name}.encrypt-{nonce}.tmp"));
    let backup = parent.join(format!(".{name}.encrypt-{nonce}.backup"));
    create_private_dir(&staging)?;
    create_private_dir(&staging.join("events"))?;
    create_private_dir(&staging.join("blobs"))?;
    create_private_dir(&staging.join("blobs/sha256"))?;
    create_private_dir(&staging.join("indexes"))?;

    let derived = new_master_key.for_trace(&manifest.trace_id)?;
    let final_path = staging.join("events").join(FINAL_JOURNAL);
    let output = BufWriter::new(private_truncate_file(&final_path)?);
    let mut encoder = zstd::stream::write::Encoder::new(output, 3)?;
    for event in &events {
        write_frame(&mut encoder, event, Some(&derived), &manifest.trace_id)?;
    }
    encoder.finish()?.into_inner()?.sync_all()?;
    manifest.journal = Some(JournalFile {
        path: format!("events/{FINAL_JOURNAL}"),
        sha256: sha256_file(&final_path)?,
        event_count: events.len() as u64,
    });
    if !manifest
        .capabilities
        .contains(&"encrypted-at-rest.xchacha20poly1305".to_owned())
    {
        manifest
            .capabilities
            .push("encrypted-at-rest.xchacha20poly1305".into());
    }
    manifest.encryption = Some(EncryptionMetadata {
        algorithm: "XChaCha20-Poly1305".into(),
        key_id: new_master_key.key_id(),
        private_manifest: String::new(),
    });
    seal::reseal_manifest(&mut manifest, signing_key)?;
    write_manifest(&staging, &manifest, Some(&derived))?;
    let verified_manifest = read_manifest_with_key(&staging, &new_master_key)?;
    let verified_events = read_events_with_key(&staging, &new_master_key)?;
    if verified_events != events
        || verify_event_structure(&verified_manifest, &verified_events).is_err()
    {
        fs::remove_dir_all(&staging)?;
        bail!("encrypted trace verification changed event evidence")
    }

    fs::rename(root, &backup)?;
    if let Err(error) = fs::rename(&staging, root) {
        let _ = fs::rename(&backup, root);
        let _ = fs::remove_dir_all(&staging);
        return Err(error.into());
    }
    fs::remove_dir_all(&backup)?;
    Ok(verified_manifest)
}

fn ensure_no_unencrypted_auxiliary_files(root: &Path) -> Result<()> {
    for relative in ["blobs", "indexes"] {
        let directory = root.join(relative);
        if !directory.exists() {
            continue;
        }
        let mut pending = vec![directory];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                } else {
                    bail!(
                        "cannot claim full at-rest encryption while auxiliary file {} exists",
                        entry.path().display()
                    )
                }
            }
        }
    }
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<()> {
    if tenant_id.is_empty()
        || tenant_id.len() > 128
        || !tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("tenant id must be 1-128 ASCII letters, digits, '.', '_' or '-'")
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn private_truncate_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn write_frame(
    writer: &mut impl Write,
    event: &TraceEvent,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<()> {
    let plaintext = event.encode_to_vec();
    let bytes = if let Some(key) = encryption_key {
        let mut envelope = event.sequence.to_le_bytes().to_vec();
        envelope.extend_from_slice(
            key.encrypt(&plaintext, event_aad(trace_id, event.sequence).as_bytes())?
                .as_bytes(),
        );
        envelope
    } else {
        plaintext
    };
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("event frame exceeds the 64 MiB safety limit")
    }
    let length = u32::try_from(bytes.len()).expect("frame length fits in u32");
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn read_frames(
    mut reader: impl Read,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::new();
    while let Some(event) = read_next_frame(&mut reader, encryption_key, trace_id)? {
        events.push(event);
    }
    Ok(events)
}

fn read_next_frame(
    reader: &mut impl Read,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Option<TraceEvent>> {
    let mut length_bytes = [0_u8; 4];
    match reader.read_exact(&mut length_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length > MAX_FRAME_BYTES {
        bail!("event frame exceeds the 64 MiB safety limit")
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(decode_frame(&bytes, encryption_key, trace_id)?))
}

fn decode_frame(
    bytes: &[u8],
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<TraceEvent> {
    let plaintext = if let Some(key) = encryption_key {
        if bytes.len() < 8 {
            bail!("encrypted event frame is truncated")
        }
        let sequence = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let envelope =
            std::str::from_utf8(&bytes[8..]).context("invalid encrypted event envelope")?;
        let plaintext = key.decrypt(envelope, event_aad(trace_id, sequence).as_bytes())?;
        let decoded = TraceEvent::decode(plaintext.as_slice())?;
        if decoded.sequence != sequence {
            bail!("encrypted event sequence binding mismatch")
        }
        return Ok(decoded);
    } else {
        bytes.to_vec()
    };
    Ok(TraceEvent::decode(plaintext.as_slice())?)
}

fn event_aad(trace_id: &str, sequence: u64) -> String {
    format!("premier:journal-frame:v1:{trace_id}:{sequence}")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration as StdDuration;

    fn rewrite_events(root: &Path, events: &[TraceEvent]) {
        let final_path = root.join("events").join(FINAL_JOURNAL);
        let output = BufWriter::new(File::create(&final_path).unwrap());
        let mut encoder = zstd::stream::write::Encoder::new(output, 3).unwrap();
        for event in events {
            write_frame(&mut encoder, event, None, &event.trace_id).unwrap();
        }
        encoder
            .finish()
            .unwrap()
            .into_inner()
            .unwrap()
            .sync_all()
            .unwrap();
        let mut manifest = read_manifest(root).unwrap();
        manifest.journal.as_mut().unwrap().sha256 = sha256_file(&final_path).unwrap();
        write_manifest(root, &manifest, None).unwrap();
    }

    #[test]
    fn writes_reads_and_verifies_finalized_trace() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("test.atrace");
        let mut writer = TraceWriter::create(&root, vec!["echo".into(), "hello".into()]).unwrap();
        writer
            .append(
                "session.start",
                "premier",
                serde_json::json!({"cwd": "/tmp"}),
            )
            .unwrap();
        writer
            .append(
                "process.stdout",
                "command",
                serde_json::json!({"text": "hello\n"}),
            )
            .unwrap();
        let manifest = writer.finish(0).unwrap();

        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        assert_eq!(read_events(&root).unwrap()[1].payload()["text"], "hello\n");
        verify(&root).unwrap();
    }

    #[test]
    fn finalized_manifest_records_normal_exit_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("exit.atrace");
        let writer = TraceWriter::create(&root, vec!["sh".into()]).unwrap();

        let manifest = writer
            .finish_termination(ProcessTermination::exited(42))
            .unwrap();

        assert_eq!(manifest.exit_code, Some(42));
        assert_eq!(
            manifest.termination,
            Some(ProcessTermination {
                kind: TerminationKind::Exit,
                exit_code: Some(42),
                signal: None,
                signal_name: None,
            })
        );
        verify(&root).unwrap();
    }

    proptest! {
        #[test]
        fn normal_exit_codes_round_trip_exactly(code in 0_i32..=255) {
            prop_assert_eq!(ProcessTermination::exited(code).shell_exit_code(), code);
        }

        #[test]
        fn signal_exit_codes_follow_shell_convention(signal in 1_i32..=64) {
            prop_assert_eq!(
                ProcessTermination::signaled(signal, None).shell_exit_code(),
                128 + signal
            );
        }
    }

    #[test]
    fn older_manifests_without_termination_metadata_remain_readable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy.atrace");
        TraceWriter::create(&root, vec!["true".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        let manifest_path = root.join("manifest.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        json.as_object_mut().unwrap().remove("termination");
        fs::write(&manifest_path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        let manifest = read_manifest(&root).unwrap();

        assert_eq!(manifest.exit_code, Some(0));
        assert_eq!(manifest.termination, None);
    }

    #[test]
    fn finalized_manifest_records_exact_signal_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("signal.atrace");
        let writer = TraceWriter::create(&root, vec!["sh".into()]).unwrap();

        let manifest = writer
            .finish_termination(ProcessTermination::signaled(15, Some("SIGTERM".into())))
            .unwrap();

        assert_eq!(manifest.exit_code, Some(143));
        let termination = manifest.termination.unwrap();
        assert_eq!(termination.kind, TerminationKind::Signal);
        assert_eq!(termination.signal, Some(15));
        assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
        verify(&root).unwrap();
    }

    #[test]
    fn recovery_refuses_a_fresh_active_trace_without_force() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("live.atrace");
        let _writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();

        let error = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                minimum_idle: StdDuration::from_secs(300),
                force: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("appears active"));
    }

    #[test]
    fn recovery_discards_a_torn_tail_and_finalizes_valid_frames() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("interrupted.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("session.start", "test", serde_json::json!({"ok": true}))
            .unwrap();
        drop(writer);
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join(ACTIVE_JOURNAL))
            .unwrap()
            .write_all(&[8, 0, 0, 0, 1, 2])
            .unwrap();
        fs::write(root.join(RECORDER_LEASE), "abandoned-recorder").unwrap();

        let manifest = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap();

        assert_eq!(manifest.exit_code, Some(130));
        assert_eq!(
            manifest.termination.as_ref().map(|value| &value.kind),
            Some(&TerminationKind::Interrupted)
        );
        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        let events = read_events(&root).unwrap();
        assert_eq!(events[0].kind, "session.start");
        assert_eq!(events[1].kind, "session.interrupted");
        verify(&root).unwrap();
        assert!(!root.join("events").join(ACTIVE_JOURNAL).exists());
        assert!(!root.join(RECORDER_LEASE).exists());
    }

    #[test]
    fn recovery_refuses_to_rewrite_a_finalized_trace() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("final.atrace");
        TraceWriter::create(&root, vec!["true".into()])
            .unwrap()
            .finish(0)
            .unwrap();

        let error = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("already finalized"));
    }

    #[test]
    fn recovery_resumes_after_a_crash_between_journal_and_manifest_commit() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("half-finalized.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("session.start", "test", serde_json::Value::Null)
            .unwrap();
        drop(writer);
        fs::write(
            root.join("events").join(FINAL_JOURNAL),
            b"orphaned partial finalization",
        )
        .unwrap();

        let manifest = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap();

        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        verify(&root).unwrap();
    }

    #[test]
    fn semantic_validation_is_advisory_and_ignores_custom_kinds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("diagnostics.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "custom.acme.telemetry".into(),
                status: "company-specific".into(),
                payload: serde_json::Value::Null,
                ..EventInput::default()
            })
            .unwrap();
        writer
            .append_input(EventInput {
                kind: "tool.invocation".into(),
                actor_id: "coder".into(),
                status: "mystery".into(),
                payload: serde_json::Value::Null,
                ..EventInput::default()
            })
            .unwrap();

        let manifest = writer.finish(0).unwrap();

        let codes: Vec<_> = manifest
            .diagnostics
            .iter()
            .map(|item| item.code.as_str())
            .collect();
        assert!(codes.contains(&"invalid_status"));
        assert!(codes.contains(&"payload_not_object"));
        assert!(codes.contains(&"missing_lifecycle_finish"));
        assert_eq!(
            manifest
                .diagnostics
                .iter()
                .filter(|item| item.sequence == Some(1))
                .count(),
            0
        );
        verify(&root).unwrap();
    }

    #[test]
    fn paired_lifecycle_events_with_correlation_are_semantically_clean() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("paired.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "model.request".into(),
                actor_id: "coder".into(),
                span_id: "request".into(),
                correlation_id: "model-call-1".into(),
                status: "running".into(),
                payload: serde_json::json!({"model": "test"}),
                ..EventInput::default()
            })
            .unwrap();
        writer
            .append_input(EventInput {
                kind: "model.response".into(),
                actor_id: "coder".into(),
                span_id: "response".into(),
                correlation_id: "model-call-1".into(),
                status: "ok".into(),
                payload: serde_json::json!({"response": "done"}),
                ..EventInput::default()
            })
            .unwrap();

        let manifest = writer.finish(0).unwrap();

        assert!(
            manifest.diagnostics.is_empty(),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn first_party_one_shot_kinds_are_clean_but_real_gaps_are_still_reported() {
        let input = |kind: &str, status: &str, correlation: &str| EventInput {
            kind: kind.into(),
            actor_id: "researcher".into(),
            correlation_id: correlation.into(),
            status: status.into(),
            payload: serde_json::json!({}),
            ..EventInput::default()
        };
        let temp = tempfile::tempdir().unwrap();
        let clean = temp.path().join("one-shot.atrace");
        let mut writer = TraceWriter::create(&clean, vec!["agent".into()]).unwrap();
        // What the README SDK example, the demo and the adapters emit without a counterpart.
        for (kind, status, correlation) in [
            ("agent.spawn", "running", ""),
            ("agent.turn", "running", ""),
            ("model.response", "ok", ""),
            ("tool.execution", "ok", ""),
            ("tool.error", "error", ""),
            ("agent.message", "ok", ""),
            ("tool.result", "ok", "call-1"),
            ("tool.invocation", "running", "call-2"),
            ("tool.invocation", "running", "call-2"),
            ("tool.result", "error", "call-2"),
        ] {
            writer
                .append_input(input(kind, status, correlation))
                .unwrap();
        }
        let manifest = writer.finish(0).unwrap();
        assert!(
            manifest.diagnostics.is_empty(),
            "{:?}",
            manifest.diagnostics
        );

        let gaps = temp.path().join("gaps.atrace");
        let mut writer = TraceWriter::create(&gaps, vec!["agent".into()]).unwrap();
        for (kind, status, correlation) in [
            ("tool.invocation", "running", "call-3"),
            ("model.request", "running", "turn-1"),
            ("approval.decision", "approved", "approval-1"),
            ("agent.result", "ok", "session-1"),
            ("tool.execution", "mystery", ""),
        ] {
            writer
                .append_input(input(kind, status, correlation))
                .unwrap();
        }
        let manifest = writer.finish(0).unwrap();
        let found: Vec<_> = manifest
            .diagnostics
            .iter()
            .map(|item| (item.code.as_str(), item.sequence.unwrap()))
            .collect();
        assert_eq!(found.len(), 5, "{found:?}");
        for expected in [
            ("missing_lifecycle_finish", 1),
            ("missing_lifecycle_finish", 2),
            ("missing_lifecycle_start", 3),
            ("missing_lifecycle_start", 4),
            ("invalid_status", 5),
        ] {
            assert!(found.contains(&expected), "{expected:?} not in {found:?}");
        }
    }

    #[test]
    fn paginated_event_reads_are_sequence_based_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("page.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        for index in 0..5 {
            writer
                .append("custom.event", "test", serde_json::json!({"index": index}))
                .unwrap();
        }
        writer.finish(0).unwrap();

        let page = read_events_page(&root, 2, 2).unwrap();

        assert_eq!(
            page.iter().map(|event| event.sequence).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn active_tail_reads_only_new_complete_frames() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tail.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("custom.one", "test", serde_json::Value::Null)
            .unwrap();
        let first = read_active_events_after(&root, 0).unwrap();
        writer
            .append("custom.two", "test", serde_json::Value::Null)
            .unwrap();

        let second = read_active_events_after(&root, first.next_byte_offset).unwrap();

        assert_eq!(
            first
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            second
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(second.next_byte_offset > first.next_byte_offset);
    }

    #[test]
    fn rejects_modified_journal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("test.atrace");
        let writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer.finish(0).unwrap();
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join(FINAL_JOURNAL))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        assert!(
            verify(&root)
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
    }

    fn sample_trace(root: &Path, signing_key: Option<&SigningKey>) -> TraceManifest {
        let mut writer = TraceWriter::create_named(
            root,
            vec!["agent".into(), "run".into()],
            Some("sample".into()),
        )
        .unwrap();
        if let Some(key) = signing_key {
            writer.set_signing_key(key.clone());
        }
        for (kind, payload) in [
            ("session.start", serde_json::json!({"cwd": "/tmp"})),
            ("process.stdout", serde_json::json!({"text": "real"})),
            ("session.end", serde_json::json!({"exit_code": 7})),
        ] {
            writer.append(kind, "test", payload).unwrap();
        }
        writer.finish(7).unwrap()
    }

    /// The forgery version 1 could not see: rewrite the journal, then publish
    /// a matching digest and event count the way the recorder would.
    fn rewrite_consistently(root: &Path, events: &[TraceEvent]) {
        rewrite_events(root, events);
        let mut manifest = read_manifest(root).unwrap();
        manifest.journal.as_mut().unwrap().event_count = events.len() as u64;
        write_manifest(root, &manifest, None).unwrap();
    }

    /// The strongest forgery open to someone with write access but no signing
    /// key: re-chain the events and recompute digest, count, chain head and
    /// seal. `signature` is whatever they decide to leave in the manifest.
    fn rebuild_chain_and_seal(
        root: &Path,
        events: &mut [TraceEvent],
        signature: Option<ManifestSignature>,
    ) {
        let mut head = seal::chain_genesis(&read_manifest(root).unwrap().trace_id);
        for (index, event) in events.iter_mut().enumerate() {
            event.sequence = index as u64 + 1;
            event.prev_hash = head;
            head = seal::event_hash(event);
        }
        rewrite_consistently(root, events);
        let mut manifest = read_manifest(root).unwrap();
        seal::seal_manifest(&mut manifest, head, events.len() as u64, false, None).unwrap();
        manifest.seal.as_mut().unwrap().signature = signature;
        write_manifest(root, &manifest, None).unwrap();
    }

    fn edit_manifest_json(root: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = root.join("manifest.json");
        let mut json = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(&mut json);
        fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    }

    #[test]
    fn consistent_journal_rewrite_is_detected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("forged.atrace");
        sample_trace(&root, None);
        let mut events = read_events(&root).unwrap();
        events[1].payload_json = r#"{"text":"forged"}"#.into();
        rewrite_consistently(&root, &events);

        // The journal matches its manifest digest again, which is everything
        // version 1 verification looked at.
        verify_journal_digest(&root, &read_manifest(&root).unwrap()).unwrap();
        let error = verify(&root).unwrap_err().to_string();
        assert!(
            error.contains("event chain is broken at sequence 3"),
            "{error}"
        );
    }

    #[test]
    fn every_manifest_field_edit_is_detected() {
        type Edit = fn(&mut serde_json::Value);
        let edits: [(&str, Edit); 12] = [
            ("name", |json| json["name"] = "forged".into()),
            ("command", |json| {
                json["command"] = serde_json::json!(["forged"])
            }),
            ("exit_code", |json| json["exit_code"] = 0.into()),
            ("termination", |json| {
                json["termination"]["exit_code"] = 0.into()
            }),
            ("started_at", |json| {
                json["started_at"] = "2020-01-01T00:00:00Z".into()
            }),
            ("ended_at", |json| {
                json["ended_at"] = "2020-01-01T00:00:00Z".into()
            }),
            ("tenant_id", |json| json["tenant_id"] = "acme".into()),
            ("capabilities", |json| {
                json["capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .push("forged".into())
            }),
            ("adapter", |json| {
                json["adapter"] = serde_json::json!({
                    "provider": "forged", "schema_version": 1,
                    "transport": "stdout-jsonl", "completeness": "complete",
                })
            }),
            ("redaction", |json| {
                json["redaction"]["terminal_literal_count"] = 9.into()
            }),
            ("diagnostics", |json| {
                json["diagnostics"] = serde_json::json!([
                    {"severity": "warning", "code": "forged", "message": "forged"}
                ])
            }),
            ("seal.recovered", |json| {
                json["seal"]["recovered"] = true.into()
            }),
        ];
        for (field, edit) in edits {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("edited.atrace");
            sample_trace(&root, None);
            edit_manifest_json(&root, edit);
            let error = verify(&root).unwrap_err().to_string();
            assert!(error.contains("manifest seal mismatch"), "{field}: {error}");
        }
    }

    #[test]
    fn reordered_inserted_and_truncated_events_are_detected() {
        type Forgery = fn(&mut Vec<TraceEvent>);
        let forgeries: [(&str, Forgery); 3] = [
            ("reorder", |events| events.swap(0, 1)),
            ("insert", |events| {
                let mut extra = events[1].clone();
                extra.event_id = Uuid::now_v7().to_string();
                events.insert(1, extra);
            }),
            ("truncate", |events| {
                events.pop();
            }),
        ];
        for (name, forge) in forgeries {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("forged.atrace");
            sample_trace(&root, None);
            let mut events = read_events(&root).unwrap();
            forge(&mut events);
            // Renumber and republish digest and counts, so every check that
            // predates the chain passes.
            for (index, event) in events.iter_mut().enumerate() {
                event.sequence = index as u64 + 1;
            }
            rewrite_consistently(&root, &events);
            let mut manifest = read_manifest(&root).unwrap();
            manifest.seal.as_mut().unwrap().event_count = events.len() as u64;
            write_manifest(&root, &manifest, None).unwrap();

            let error = verify(&root).unwrap_err().to_string();
            assert!(error.contains("event chain"), "{name}: {error}");
        }
    }

    #[test]
    fn an_unsigned_trace_can_be_rebuilt_by_anyone_with_write_access() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("rebuilt.atrace");
        sample_trace(&root, None);
        let mut events = read_events(&root).unwrap();
        events[1].payload_json = r#"{"text":"forged"}"#.into();
        rebuild_chain_and_seal(&root, &mut events, None);

        // This is the documented limit of an unsigned trace: it is reported
        // as sealed, never as signed.
        let verified = verify_trace(&root, None).unwrap();
        assert_eq!(verified.protection, Protection::Sealed);
        assert!(verified.signer.is_none());
        assert!(!verified.trusted_signer);
    }

    #[test]
    fn signed_trace_verifies_with_the_right_key_and_fails_with_a_wrong_key() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("signed.atrace");
        let key = SigningKey::generate();
        sample_trace(&root, Some(&key));

        let verified = verify_trace(&root, Some(&key.public_key())).unwrap();
        assert_eq!(verified.protection, Protection::Signed);
        assert_eq!(verified.signer, Some(key.public_key()));
        assert!(verified.trusted_signer);

        let unknown = verify_trace(&root, None).unwrap();
        assert_eq!(unknown.protection, Protection::Signed);
        assert_eq!(unknown.signer, Some(key.public_key()));
        assert!(!unknown.trusted_signer);

        let wrong = SigningKey::generate().public_key();
        let error = verify_trace(&root, Some(&wrong)).unwrap_err().to_string();
        assert!(error.contains("signed by a different key"), "{error}");
        assert!(error.contains(&key.public_key().fingerprint()), "{error}");

        let unsigned = temp.path().join("unsigned.atrace");
        sample_trace(&unsigned, None);
        let error = verify_trace(&unsigned, Some(&wrong))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not signed"), "{error}");
    }

    #[test]
    fn signature_breaks_on_any_manifest_or_event_change() {
        let temp = tempfile::tempdir().unwrap();
        let key = SigningKey::generate();

        // An event change with chain, digest and seal all rebuilt.
        let root = temp.path().join("event.atrace");
        let signature = sample_trace(&root, Some(&key)).seal.unwrap().signature;
        let mut events = read_events(&root).unwrap();
        events[1].payload_json = r#"{"text":"forged"}"#.into();
        rebuild_chain_and_seal(&root, &mut events, signature.clone());
        let error = verify(&root).unwrap_err().to_string();
        assert!(error.contains("manifest signature is invalid"), "{error}");

        // Dropping the signature instead leaves an unsigned trace, which a
        // verifier holding the expected key rejects.
        rebuild_chain_and_seal(&root, &mut events, None);
        assert_eq!(
            verify_trace(&root, None).unwrap().protection,
            Protection::Sealed
        );
        let error = verify_trace(&root, Some(&key.public_key()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not signed"), "{error}");

        // A manifest change with the seal recomputed.
        let root = temp.path().join("manifest.atrace");
        let mut manifest = sample_trace(&root, Some(&key));
        manifest.exit_code = Some(0);
        manifest.termination = Some(ProcessTermination::exited(0));
        seal::reseal_manifest(&mut manifest, None).unwrap();
        manifest.seal.as_mut().unwrap().signature = signature;
        write_manifest(&root, &manifest, None).unwrap();
        let error = verify(&root).unwrap_err().to_string();
        assert!(error.contains("manifest signature is invalid"), "{error}");

        // Re-signing with another key is valid for that key only.
        let forger = SigningKey::generate();
        seal::reseal_manifest(&mut manifest, Some(&forger)).unwrap();
        write_manifest(&root, &manifest, None).unwrap();
        assert_eq!(
            verify_trace(&root, None).unwrap().signer,
            Some(forger.public_key())
        );
        let error = verify_trace(&root, Some(&key.public_key()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("signed by a different key"), "{error}");
    }

    #[test]
    fn signing_a_finalized_trace_requires_it_to_verify_first() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("late-signed.atrace");
        let before = sample_trace(&root, None).seal.unwrap();
        let key = SigningKey::generate();

        let signed = sign_finalized_trace(&root, &key).unwrap().seal.unwrap();
        assert_eq!(signed.digest, before.digest);
        assert_eq!(signed.chain_head, before.chain_head);
        verify_trace(&root, Some(&key.public_key())).unwrap();

        let mut events = read_events(&root).unwrap();
        events[0].payload_json = r#"{"cwd":"/forged"}"#.into();
        rewrite_consistently(&root, &events);
        assert!(sign_finalized_trace(&root, &key).is_err());
    }

    #[test]
    fn v1_fixture_still_reads_and_verifies_as_digest_only() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1.atrace");
        let manifest = read_manifest(&fixture).unwrap();
        assert_eq!(manifest.format_version, 1);
        assert!(manifest.seal.is_none());
        let events = read_events(&fixture).unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| event.prev_hash.is_empty()));

        let verified = verify_trace(&fixture, None).unwrap();
        assert_eq!(verified.protection, Protection::DigestOnly);
        assert!(verified.signer.is_none());
        let key = SigningKey::generate();
        let error = verify_trace(&fixture, Some(&key.public_key()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("v1: digest only"), "{error}");

        // Version 1 keeps exactly its old guarantees on a working copy.
        let temp = tempfile::tempdir().unwrap();
        let copy = temp.path().join("v1.atrace");
        fs::create_dir_all(copy.join("events")).unwrap();
        for file in ["manifest.json", "events/000001.events.pb.zst"] {
            fs::copy(fixture.join(file), copy.join(file)).unwrap();
        }
        let error = sign_finalized_trace(&copy, &key).unwrap_err().to_string();
        assert!(error.contains("v1: digest only"), "{error}");
        OpenOptions::new()
            .append(true)
            .open(copy.join("events").join(FINAL_JOURNAL))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        let error = verify(&copy).unwrap_err().to_string();
        assert!(error.contains("digest mismatch"), "{error}");
    }

    #[test]
    fn unknown_future_format_versions_are_rejected_with_a_clear_error() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("future.atrace");
        sample_trace(&root, None);
        edit_manifest_json(&root, |json| json["format_version"] = 3.into());
        let error = read_manifest(&root).unwrap_err().to_string();
        assert!(
            error.contains("unsupported trace format version 3"),
            "{error}"
        );
        assert!(error.contains("reads versions 1 to 2"), "{error}");
        assert!(read_events(&root).is_err());
    }

    #[test]
    fn a_version_2_manifest_without_a_seal_is_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("stripped.atrace");
        sample_trace(&root, None);
        edit_manifest_json(&root, |json| {
            json.as_object_mut().unwrap().remove("seal");
        });
        let error = verify(&root).unwrap_err().to_string();
        assert!(error.contains("has no seal"), "{error}");
    }

    #[test]
    fn recovery_rederives_the_chain_and_marks_the_seal_recovered() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("interrupted.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("one", "test", serde_json::Value::Null)
            .unwrap();
        writer
            .append("two", "test", serde_json::Value::Null)
            .unwrap();
        drop(writer);
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join(ACTIVE_JOURNAL))
            .unwrap()
            .write_all(&[8, 0, 0, 0, 1, 2])
            .unwrap();

        let manifest = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap();

        let sealed = manifest.seal.unwrap();
        assert!(sealed.recovered);
        assert_eq!(sealed.event_count, 3);
        let events = read_events(&root).unwrap();
        assert_eq!(events[2].kind, "session.interrupted");
        assert_eq!(events[2].prev_hash, seal::event_hash(&events[1]));
        assert_eq!(sealed.chain_head, seal::event_hash(&events[2]));
        assert_eq!(
            verify_trace(&root, None).unwrap().protection,
            Protection::Sealed
        );

        // The recovered marker is itself sealed.
        edit_manifest_json(&root, |json| {
            json["seal"].as_object_mut().unwrap().remove("recovered");
        });
        assert!(verify(&root).is_err());
    }

    #[test]
    fn recovery_refuses_an_active_journal_whose_chain_is_broken() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("edited-live.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        for kind in ["one", "two", "three"] {
            writer
                .append(kind, "test", serde_json::Value::Null)
                .unwrap();
        }
        drop(writer);
        let active = root.join("events").join(ACTIVE_JOURNAL);
        let mut events = read_events(&root).unwrap();
        events[0].payload_json = r#"{"forged":true}"#.into();
        let mut bytes = Vec::new();
        for event in &events {
            write_frame(&mut bytes, event, None, &event.trace_id).unwrap();
        }
        fs::write(&active, bytes).unwrap();

        let error = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap_err();

        let error = format!("{error:#}");
        assert!(error.contains("failed chain verification"), "{error}");
        assert!(
            error.contains("event chain is broken at sequence 2"),
            "{error}"
        );
        assert!(active.exists());
        assert!(read_manifest(&root).unwrap().journal.is_none());
    }

    #[test]
    fn encrypted_traces_are_chained_and_sealed_inside_the_private_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("encrypted-sealed.atrace");
        let key = EncryptionKey::from_hex(&"81".repeat(32)).unwrap();
        let signer = SigningKey::generate();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into()],
            None,
            "local",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer.set_signing_key(signer.clone());
        writer.append("one", "test", serde_json::json!({})).unwrap();
        writer.append("two", "test", serde_json::json!({})).unwrap();
        writer.finish(0).unwrap();

        let public: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert!(public.get("seal").is_none(), "{public}");
        assert!(!public.to_string().contains(&signer.public_key().to_hex()));

        let manifest = read_manifest_with_key(&root, &key).unwrap();
        let events = read_events_with_key(&root, &key).unwrap();
        assert_eq!(events[1].prev_hash, seal::event_hash(&events[0]));
        let status = verify_decoded_events(&manifest, &events).unwrap();
        assert_eq!(status.protection, Protection::Signed);
        assert_eq!(status.signer, Some(signer.public_key()));
        // Dropping the last event is caught by the chain head as well as the
        // authenticated count.
        assert!(verify_tamper_evidence(&manifest, &events[..1]).is_err());
    }

    #[test]
    fn encryption_preserves_the_chain_and_reseals_dropping_or_reapplying_the_signature() {
        let temp = tempfile::tempdir().unwrap();
        let signer = SigningKey::generate();
        let key = EncryptionKey::from_hex(&"91".repeat(32)).unwrap();

        let root = temp.path().join("dropped.atrace");
        let before = sample_trace(&root, Some(&signer)).seal.unwrap();
        let after = reencrypt_finalized_trace_with_signing_key(&root, key.clone(), None)
            .unwrap()
            .seal
            .unwrap();
        assert_eq!(after.chain_head, before.chain_head);
        assert_eq!(after.event_count, before.event_count);
        assert_ne!(after.digest, before.digest);
        assert!(after.signature.is_none());
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        let events = read_events_with_key(&root, &key).unwrap();
        assert_eq!(
            verify_decoded_events(&manifest, &events)
                .unwrap()
                .protection,
            Protection::Sealed
        );

        let root = temp.path().join("resigned.atrace");
        sample_trace(&root, Some(&signer));
        reencrypt_finalized_trace_with_signing_key(&root, key.clone(), Some(&signer)).unwrap();
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        let events = read_events_with_key(&root, &key).unwrap();
        let status = verify_decoded_events(&manifest, &events).unwrap();
        assert_eq!(status.protection, Protection::Signed);
        assert_eq!(status.signer, Some(signer.public_key()));
    }

    #[test]
    fn claiming_a_trace_reseals_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("claimed.atrace");
        let before = sample_trace(&root, None).seal.unwrap();
        let after = claim_local_trace(&root, "acme").unwrap().seal.unwrap();
        assert_ne!(after.digest, before.digest);
        assert_eq!(after.chain_head, before.chain_head);
        assert_eq!(verify(&root).unwrap().tenant_id, "acme");
    }

    #[test]
    fn preserves_subagent_causality_and_links() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("agents.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        let parent = writer
            .append_input(EventInput {
                kind: "agent.delegation".into(),
                actor_id: "coordinator".into(),
                actor_type: "agent".into(),
                span_id: "span-root".into(),
                status: "running".into(),
                payload: serde_json::json!({"delegate_to": "researcher"}),
                ..EventInput::default()
            })
            .unwrap();
        writer
            .append_input(EventInput {
                kind: "agent.turn".into(),
                actor_id: "researcher".into(),
                actor_type: "subagent".into(),
                parent_event_id: parent.event_id.clone(),
                span_id: "span-child".into(),
                parent_span_id: "span-root".into(),
                links: vec![parent.event_id],
                status: "ok".into(),
                ..EventInput::default()
            })
            .unwrap();
        writer.finish(0).unwrap();
        let events = read_events(&root).unwrap();
        assert_eq!(events[1].actor_type, "subagent");
        assert_eq!(events[1].parent_span_id, "span-root");
        assert_eq!(events[1].links.len(), 1);
    }

    #[test]
    fn rejects_reordered_sequences_even_when_the_manifest_digest_is_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("reordered.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("one", "test", serde_json::Value::Null)
            .unwrap();
        writer
            .append("two", "test", serde_json::Value::Null)
            .unwrap();
        writer.finish(0).unwrap();
        let mut events = read_events(&root).unwrap();
        events.swap(0, 1);
        rewrite_events(&root, &events);
        assert!(verify(&root).unwrap_err().to_string().contains("sequence"));
    }

    #[test]
    fn rejects_duplicate_event_ids_even_when_the_manifest_digest_is_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("duplicate.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("one", "test", serde_json::Value::Null)
            .unwrap();
        writer
            .append("two", "test", serde_json::Value::Null)
            .unwrap();
        writer.finish(0).unwrap();
        let mut events = read_events(&root).unwrap();
        events[1].event_id = events[0].event_id.clone();
        rewrite_events(&root, &events);
        assert!(verify(&root).unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn unknown_parent_references_are_diagnostics_not_verification_failures() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bogus-parent.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "tool.result".into(),
                parent_event_id: "not-a-recorded-event".into(),
                status: "ok".into(),
                payload: serde_json::json!({}),
                ..EventInput::default()
            })
            .unwrap();
        let manifest = writer.finish(0).unwrap();

        verify(&root).unwrap();
        assert!(
            manifest
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unknown_parent_event"),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn oversized_frames_are_rejected_at_write_time_without_corrupting_the_trace() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("oversized.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        let error = writer
            .append(
                "blob",
                "test",
                serde_json::json!({"text": "x".repeat(MAX_FRAME_BYTES + 1)}),
            )
            .unwrap_err();
        assert!(error.to_string().contains("64 MiB"), "{error}");

        writer
            .append("small", "test", serde_json::json!({}))
            .unwrap();
        let manifest = writer.finish(0).unwrap();
        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 1);
        verify(&root).unwrap();
    }

    #[test]
    fn failed_append_rolls_back_so_later_appends_stay_contiguous() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("failed-append.atrace");
        let active = root.join("events").join(ACTIVE_JOURNAL);
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("first", "test", serde_json::json!({}))
            .unwrap();
        let committed = fs::metadata(&active).unwrap().len();

        // A read-only handle fails both the write and the rollback, like a
        // journal that became unwritable mid-run.
        let writable = std::mem::replace(&mut writer.journal, File::open(&active).unwrap());
        for _ in 0..2 {
            let error = writer
                .append("lost", "test", serde_json::json!({}))
                .unwrap_err();
            assert!(format!("{error:#}").contains("trace journal"), "{error:#}");
        }
        assert_eq!(fs::metadata(&active).unwrap().len(), committed);

        // Once the journal is writable again a torn frame left by the failed
        // write is discarded before the next frame is appended.
        writer.journal = writable;
        writer.journal.write_all(&[0xff, 0xff, 0x00]).unwrap();
        writer.dirty = true;
        let second = writer
            .append("second", "test", serde_json::json!({}))
            .unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(writer.dropped_events(), 2);

        let manifest = writer.finish(0).unwrap();
        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        assert!(
            manifest
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "journal.write_failed")
        );
        verify(&root).unwrap();
        let kinds: Vec<_> = read_events(&root)
            .unwrap()
            .into_iter()
            .map(|event| (event.sequence, event.kind))
            .collect();
        assert_eq!(kinds, [(1, "first".into()), (2, "second".into())]);
    }

    #[test]
    fn encrypted_truncation_is_detected_even_when_the_public_manifest_is_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("truncated.atrace");
        let key = EncryptionKey::from_hex(&"71".repeat(32)).unwrap();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into()],
            None,
            "local",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer.append("one", "test", serde_json::json!({})).unwrap();
        writer.append("two", "test", serde_json::json!({})).unwrap();
        writer.finish(0).unwrap();

        let public: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert!(
            public["journal"].is_null(),
            "encrypted manifests must not publish the journal digest: {public}"
        );

        // Attacker without the key: drop the trailing frame at a frame boundary
        // and publish a matching digest/count in the plaintext manifest.
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        let events = read_events_with_key(&root, &key).unwrap();
        let derived = key.for_trace(&manifest.trace_id).unwrap();
        let final_path = root.join("events").join(FINAL_JOURNAL);
        let output = BufWriter::new(File::create(&final_path).unwrap());
        let mut encoder = zstd::stream::write::Encoder::new(output, 3).unwrap();
        write_frame(&mut encoder, &events[0], Some(&derived), &manifest.trace_id).unwrap();
        encoder
            .finish()
            .unwrap()
            .into_inner()
            .unwrap()
            .sync_all()
            .unwrap();
        let mut doctored = public;
        doctored["journal"] = serde_json::json!({
            "path": format!("events/{FINAL_JOURNAL}"),
            "sha256": sha256_file(&final_path).unwrap(),
            "event_count": 1,
        });
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&doctored).unwrap(),
        )
        .unwrap();

        let reread = read_manifest_with_key(&root, &key).unwrap();
        let error = verify_journal_digest(&root, &reread).unwrap_err();
        assert!(error.to_string().contains("digest mismatch"), "{error}");
    }

    #[test]
    fn recording_redacts_nested_secret_fields_before_the_journal_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("redacted.atrace");
        let redaction = RedactionConfig::new(
            ["customer_pin"],
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .unwrap();
        let mut writer =
            TraceWriter::create_named_with_redaction(&root, vec!["agent".into()], None, redaction)
                .unwrap();

        writer
            .append_input(EventInput {
                kind: "tool.execution".into(),
                payload: serde_json::json!({
                    "authorization": "Bearer do-not-store",
                    "X-API-Key": "vendor-key",
                    "nested": [{"password": "hunter2", "customer_pin": "4815"}],
                    "safe": "keep me"
                }),
                ..EventInput::default()
            })
            .unwrap();

        let active = fs::read(root.join("events").join(ACTIVE_JOURNAL)).unwrap();
        let active_text = String::from_utf8_lossy(&active);
        assert!(!active_text.contains("do-not-store"));
        assert!(!active_text.contains("hunter2"));
        assert!(!active_text.contains("4815"));
        assert!(!active_text.contains("vendor-key"));

        let manifest = writer.finish(0).unwrap();
        let event = &read_events(&root).unwrap()[0];
        assert_eq!(event.payload()["authorization"], "[REDACTED]");
        assert_eq!(event.payload()["X-API-Key"], "[REDACTED]");
        assert_eq!(event.payload()["nested"][0]["password"], "[REDACTED]");
        assert_eq!(event.payload()["nested"][0]["customer_pin"], "[REDACTED]");
        assert_eq!(event.payload()["safe"], "keep me");
        assert!(
            manifest
                .capabilities
                .contains(&"structured-redaction".into())
        );
        assert_eq!(
            manifest.redaction.as_ref().unwrap().custom_fields,
            vec!["customer_pin"]
        );
    }

    #[test]
    fn terminal_output_is_raw_by_default_and_only_redacted_when_explicitly_configured() {
        let temp = tempfile::tempdir().unwrap();
        let raw_root = temp.path().join("raw.atrace");
        let mut raw = TraceWriter::create(&raw_root, vec!["command".into()]).unwrap();
        raw.append_input(EventInput {
            kind: "process.stdout".into(),
            payload: serde_json::json!({"text": "token=visible-by-default"}),
            ..EventInput::default()
        })
        .unwrap();
        raw.finish(0).unwrap();
        assert_eq!(
            read_events(&raw_root).unwrap()[0].payload()["text"],
            "token=visible-by-default"
        );

        let protected_root = temp.path().join("protected.atrace");
        let redaction = RedactionConfig::new(
            std::iter::empty::<String>(),
            ["literal-secret"],
            [r"token=[A-Za-z0-9-]+"],
        )
        .unwrap();
        let mut protected = TraceWriter::create_named_with_redaction(
            &protected_root,
            vec!["command".into()],
            None,
            redaction,
        )
        .unwrap();
        protected
            .append_input(EventInput {
                kind: "process.stderr".into(),
                payload: serde_json::json!({"text": "literal-secret token=regex-secret"}),
                ..EventInput::default()
            })
            .unwrap();
        let manifest = protected.finish(0).unwrap();
        let text = read_events(&protected_root).unwrap()[0].payload()["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(text, "[REDACTED] [REDACTED]");
        let provenance = manifest.redaction.unwrap();
        assert_eq!(provenance.terminal_literal_count, 1);
        assert_eq!(provenance.terminal_regex_count, 1);
        let manifest_text = fs::read_to_string(protected_root.join("manifest.json")).unwrap();
        assert!(!manifest_text.contains("literal-secret"));
        assert!(!manifest_text.contains("token=[A-Za-z0-9-]+"));
    }

    fn text_rules(literals: &[&str], regexes: &[&str]) -> RedactionConfig {
        RedactionConfig::new(
            std::iter::empty::<String>(),
            literals.iter().copied(),
            regexes.iter().copied(),
        )
        .unwrap()
    }

    /// Journal `chunks` the way the recorder does and return the stored text.
    fn journal_chunks(redaction: RedactionConfig, kind: &str, chunks: &[&str]) -> String {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("chunks.atrace");
        let mut writer = TraceWriter::create_named_with_redaction(
            &root,
            vec!["command".into()],
            None,
            redaction,
        )
        .unwrap();
        let mut buffer = writer.terminal_redaction_buffer(kind);
        let mut released = Vec::new();
        for chunk in chunks {
            released.extend(buffer.push(chunk, chunk.len()));
        }
        released.extend(buffer.finish());
        let total: usize = released.iter().map(|(_, bytes)| bytes).sum();
        assert_eq!(total, chunks.iter().map(|chunk| chunk.len()).sum::<usize>());
        for (text, byte_length) in released {
            writer
                .append(
                    kind,
                    "command",
                    serde_json::json!({"text": text, "byte_length": byte_length}),
                )
                .unwrap();
        }
        writer.finish(0).unwrap();
        read_events(&root)
            .unwrap()
            .iter()
            .map(|event| event.payload()["text"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn terminal_rules_redact_secrets_split_across_chunks() {
        let rules = || text_rules(&["SUPERSECRETVALUE"], &["sk-[a-z0-9]+"]);
        assert_eq!(
            journal_chunks(
                rules(),
                "process.stdout",
                &[
                    "SUPERSECRET",
                    "VALUE\nsk-abc",
                    "def123\nSUPERSEC",
                    "RET",
                    "VALUE sk-",
                    "zz9\n"
                ]
            ),
            "[REDACTED]\n[REDACTED]\n[REDACTED] [REDACTED]\n"
        );
        // An unfinished prefix is not a secret and is flushed at stream end.
        assert_eq!(
            journal_chunks(rules(), "process.stderr", &["ok SUPERSEC"]),
            "ok SUPERSEC"
        );
        // Overlapping literals are redacted as one span however they arrive.
        assert_eq!(
            journal_chunks(
                text_rules(&["abc", "cde"], &[]),
                "process.stdout",
                &["xabc", "de!"]
            ),
            "x[REDACTED]!"
        );
        assert_eq!(
            journal_chunks(
                text_rules(&["pässwört"], &[]),
                "process.terminal",
                &["a pä", "sswö", "rt b"]
            ),
            "a [REDACTED] b"
        );
    }

    #[test]
    fn terminal_buffer_only_holds_back_what_a_rule_could_still_match() {
        let temp = tempfile::tempdir().unwrap();
        let plain = TraceWriter::create(temp.path().join("plain.atrace"), vec![]).unwrap();
        let mut buffer = plain.terminal_redaction_buffer("process.stdout");
        assert_eq!(buffer.push("partial", 7), Some(("partial".into(), 7)));
        assert_eq!(buffer.push("", 2), None);
        assert_eq!(buffer.finish(), None);

        let literal = TraceWriter::create_named_with_redaction(
            temp.path().join("literal.atrace"),
            vec![],
            None,
            text_rules(&["hunter2"], &[]),
        )
        .unwrap();
        let mut buffer = literal.terminal_redaction_buffer("process.stdout");
        assert_eq!(buffer.push("prompt> hun", 11), Some(("prompt> ".into(), 8)));
        assert_eq!(buffer.push("gry\n", 4), Some(("hungry\n".into(), 7)));

        let regex = TraceWriter::create_named_with_redaction(
            temp.path().join("regex.atrace"),
            vec![],
            None,
            text_rules(&[], &["x+"]),
        )
        .unwrap();
        let mut buffer = regex.terminal_redaction_buffer("process.stdout");
        assert_eq!(buffer.push("one\ntwo", 7), Some(("one\n".into(), 4)));
        // A line that never ends is eventually released instead of growing,
        // except for an overlap window a later match could still begin in.
        let long = "y".repeat(MAX_HELD_LINE_BYTES);
        let (text, _) = buffer.push(&long, long.len()).unwrap();
        assert_eq!(text.len(), MAX_HELD_LINE_BYTES + 3 - HELD_OVERLAP_BYTES);
    }

    #[test]
    fn a_forced_cut_of_an_over_long_line_never_splits_a_rule_match() {
        // The secret arrives exactly where the unterminated line outgrows the
        // hold limit, split across two reads.
        let filler = "x".repeat(MAX_HELD_LINE_BYTES - 2);
        for (rules, head, tail) in [
            (text_rules(&[], &["sk-[a-z0-9]+"]), "sk-ab", "cdef123"),
            (
                text_rules(&["SUPERSECRETVALUE"], &["never-matches"]),
                "SUPERSEC",
                "RETVALUE",
            ),
        ] {
            let first = format!("{filler} {head}");
            let second = format!("{tail} done\n");
            let stored = journal_chunks(rules, "process.stdout", &[&first, &second]);
            assert_eq!(stored, format!("{filler} [REDACTED] done\n"));
        }
        // A match longer than the hold limit cannot be held; it is still
        // redacted piecewise and the buffer stays bounded.
        let mut buffer = TraceWriter::create_named_with_redaction(
            tempfile::tempdir().unwrap().path().join("long.atrace"),
            vec![],
            None,
            text_rules(&[], &["y+"]),
        )
        .unwrap()
        .terminal_redaction_buffer("process.stdout");
        let long = "y".repeat(MAX_HELD_LINE_BYTES + 1);
        let (text, _) = buffer.push(&long, long.len()).unwrap();
        assert_eq!(text.len(), long.len() - HELD_OVERLAP_BYTES);
    }

    /// Split ASCII `text` into chunks of `size` bytes.
    fn chunked(text: &str, size: usize) -> Vec<&str> {
        text.as_bytes()
            .chunks(size)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect()
    }

    #[test]
    fn multiline_regex_rules_redact_secrets_spanning_lines_split_across_chunks() {
        let rules = || {
            text_rules(&[], &[])
                .multiline_regexes([r"token:\s+[a-z0-9]+", r"(?s)BEGIN TOKEN.*?END TOKEN"])
                .unwrap()
        };
        // A secret spanning two lines, and one spanning three, each split
        // inside every one of its lines.
        assert_eq!(
            journal_chunks(
                rules(),
                "process.stdout",
                &["one\ntok", "en:\n  sk9", "abc\ntwo\n"]
            ),
            "one\n[REDACTED]\ntwo\n"
        );
        assert_eq!(
            journal_chunks(
                rules(),
                "process.stderr",
                &["log\nBEGIN TO", "KEN\nabc", "def\nEND TOK", "EN\nafter\n"]
            ),
            "log\n[REDACTED]\nafter\n"
        );
        // The same line-scoped rule releases each line as it ends, so it
        // never sees the block whole.
        assert!(
            journal_chunks(
                text_rules(&[], &["(?s)BEGIN TOKEN.*?END TOKEN"]),
                "process.stdout",
                &["BEGIN TO", "KEN\nabc", "def\nEND TOKEN\n"]
            )
            .contains("abcdef")
        );

        // Far more output than the window holds, cut at every kind of chunk
        // boundary: the secrets are still seen whole.
        let filler = "a line of ordinary output\n".repeat(2_000);
        let text =
            format!("{filler}token:\n  sk9abc\n{filler}BEGIN TOKEN\nabc\ndef\nEND TOKEN\n{filler}");
        let expected = format!("{filler}[REDACTED]\n{filler}[REDACTED]\n{filler}");
        assert!(filler.len() > 2 * MULTILINE_WINDOW_BYTES);
        for size in [1_000, 4_093, 8_192, 100_000] {
            assert_eq!(
                journal_chunks(rules(), "process.stdout", &chunked(&text, size)),
                expected,
                "chunk size {size}"
            );
        }
    }

    #[test]
    fn multiline_regex_rules_compose_with_line_rules_and_stay_bounded() {
        // Line-scoped rules keep their whole-line guarantee next to a
        // multi-line rule: `id=` is followed by more than a window of text.
        let long_id = "7".repeat(MULTILINE_WINDOW_BYTES * 2);
        let filler = "ordinary output\n".repeat(3_000);
        let text =
            format!("{filler}id={long_id}\nSUPERSECRETVALUE\nfirst half\nsecond half\n{filler}");
        let rules = || {
            text_rules(&["SUPERSECRETVALUE"], &["id=[0-9]+"])
                .multiline_regexes([r"first half\nsecond half"])
                .unwrap()
        };
        let expected = format!("{filler}[REDACTED]\n[REDACTED]\n[REDACTED]\n{filler}");
        for size in [1_000, 4_093, 8_192] {
            assert_eq!(
                journal_chunks(rules(), "process.stdout", &chunked(&text, size)),
                expected,
                "chunk size {size}"
            );
        }

        // The window slides: everything but its tail is released, and a text
        // with no line break at all cannot grow the buffer without bound.
        let temp = tempfile::tempdir().unwrap();
        let writer = TraceWriter::create_named_with_redaction(
            temp.path().join("window.atrace"),
            vec![],
            None,
            text_rules(&[], &[]).multiline_regexes(["x\ny"]).unwrap(),
        )
        .unwrap();
        let mut buffer = writer.terminal_redaction_buffer("process.stdout");
        assert_eq!(buffer.push("short\n", 6), None);
        let long = "z".repeat(MAX_HELD_LINE_BYTES * 2);
        let (text, _) = buffer.push(&long, long.len()).unwrap();
        assert_eq!(text.len(), 6 + long.len() - MULTILINE_WINDOW_BYTES);
        let (rest, _) = buffer.finish().unwrap();
        assert_eq!(rest.len(), MULTILINE_WINDOW_BYTES);
        // A match longer than the buffer can hold is split, not held forever.
        let writer = TraceWriter::create_named_with_redaction(
            temp.path().join("too-long.atrace"),
            vec![],
            None,
            text_rules(&[], &[]).multiline_regexes(["(?s)z.*"]).unwrap(),
        )
        .unwrap();
        let mut buffer = writer.terminal_redaction_buffer("process.stdout");
        let (text, _) = buffer.push(&long, long.len()).unwrap();
        assert_eq!(text.len(), long.len() - MULTILINE_WINDOW_BYTES);
    }

    #[test]
    fn multiline_regex_rules_apply_to_whole_structured_strings_and_are_counted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("structured.atrace");
        let redaction = text_rules(&[], &["line-[a-z]+"])
            .multiline_regexes([r"(?s)-----BEGIN NOTE-----.*?-----END NOTE-----"])
            .unwrap();
        let mut writer =
            TraceWriter::create_named_with_redaction(&root, vec!["agent".into()], None, redaction)
                .unwrap();
        writer
            .append(
                "tool.result",
                "sdk",
                serde_json::json!({
                    "output": "before\n-----BEGIN NOTE-----\nprivate\ntext\n-----END NOTE-----\nafter line-abc",
                    "nested": [{"note": "-----BEGIN NOTE-----\nmore\n-----END NOTE-----"}],
                }),
            )
            .unwrap();
        let manifest = writer.finish(0).unwrap();
        let payload = read_events(&root).unwrap()[0].payload();
        assert_eq!(payload["output"], "before\n[REDACTED]\nafter [REDACTED]");
        assert_eq!(payload["nested"][0]["note"], "[REDACTED]");
        let provenance = manifest.redaction.unwrap();
        assert_eq!(provenance.terminal_regex_count, 1);
        assert_eq!(provenance.terminal_multiline_regex_count, 1);
        assert!(
            RedactionConfig::default()
                .multiline_regexes(["("])
                .unwrap_err()
                .to_string()
                .contains("invalid multi-line terminal redaction regex")
        );
    }

    #[test]
    fn idle_flush_releases_a_held_prompt_but_not_a_possible_literal_or_jsonl_line() {
        let temp = tempfile::tempdir().unwrap();
        let writer = TraceWriter::create_named_with_redaction(
            temp.path().join("idle.atrace"),
            vec![],
            None,
            text_rules(&["hunter2"], &["sk-[a-z0-9]+"]),
        )
        .unwrap();
        let mut buffer = writer.terminal_redaction_buffer("process.terminal");
        assert_eq!(
            buffer.push("done\nPassword: ", 15),
            Some(("done\n".into(), 5))
        );
        assert_eq!(buffer.flush_idle(), Some(("Password: ".into(), 10)));
        assert_eq!(buffer.flush_idle(), None);
        // The start of a literal secret stays held however long the pause.
        assert_eq!(buffer.push("token hun", 9), None);
        assert_eq!(buffer.flush_idle(), Some(("token ".into(), 6)));
        assert_eq!(buffer.push("ter2\n", 5), Some(("hunter2\n".into(), 8)));

        let mut adapter = TraceWriter::create(temp.path().join("jsonl.atrace"), vec![]).unwrap();
        adapter
            .set_adapter(AdapterProvenance {
                provider: "claude".into(),
                schema_version: 1,
                transport: "stdout-jsonl".into(),
                completeness: "provider-native-best-effort".into(),
            })
            .unwrap();
        let mut buffer = adapter.terminal_redaction_buffer("process.stdout");
        assert_eq!(buffer.push(r#"{"api_key":"abc"#, 16), None);
        assert_eq!(buffer.flush_idle(), None);
        assert!(buffer.finish().is_some());
    }

    /// Secret-shaped sample values, assembled at run time so the source file
    /// itself never contains a credential-shaped string.
    fn sample_secrets() -> Vec<(&'static str, String)> {
        let body = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
        vec![
            (
                "pem-private-key",
                format!(
                    "-----BEGIN RSA {0}-----\nMIIEow{body}\n{body}\n-----END RSA {0}-----",
                    "PRIVATE KEY"
                ),
            ),
            ("sk-api-key", format!("sk-{body}")),
            ("sk-api-key", format!("sk-ant-api03-{body}")),
            ("github-token", format!("ghp_{body}")),
            ("github-token", format!("ghs_{body}")),
            (
                "github-fine-grained-pat",
                format!("github_pat_{body}_{body}"),
            ),
            ("aws-access-key-id", format!("AKIA{}", "IOSFODNN7EXAMPLE")),
            ("slack-token", format!("xoxb-1234567890-{body}")),
            (
                "jwt",
                format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{body}"),
            ),
        ]
    }

    #[test]
    fn builtin_patterns_redact_well_known_secret_shapes_and_name_the_rule() {
        for (name, secret) in sample_secrets() {
            let text = format!("before {secret} after");
            let mut matched = Vec::new();
            let redacted = redact_builtin_secrets(&text, &mut |rule| matched.push(rule)).unwrap();
            assert_eq!(redacted, "before [REDACTED] after", "{name}");
            assert_eq!(matched, [name]);
            // A second pass over redacted text changes nothing.
            assert_eq!(redact_builtin_secrets(&redacted, &mut |_| {}), None);
        }
        let body = "a1B2c3D4e5F6g7H8i9J0k1L2";
        for (name, text, expected) in [
            (
                "authorization-header",
                format!("curl -H 'Authorization: Bearer {body}' https://example.test"),
                "curl -H 'Authorization: Bearer [REDACTED]' https://example.test".to_owned(),
            ),
            (
                "authorization-header",
                r#"{\"authorization\": \"Basic dXNlcjpwYXNz\", "n": 1}"#.to_owned(),
                r#"{\"authorization\": \"Basic [REDACTED]\", "n": 1}"#.to_owned(),
            ),
            (
                "bearer-token",
                format!("sent bearer {body} upstream"),
                "sent bearer [REDACTED] upstream".to_owned(),
            ),
            (
                "url-credentials",
                "git clone https://deploy:hunter2@git.example.test/repo.git".to_owned(),
                "git clone https://deploy:[REDACTED]@git.example.test/repo.git".to_owned(),
            ),
            (
                "url-credentials",
                "postgres://:p%40ss@db:5432/app".to_owned(),
                "postgres://:[REDACTED]@db:5432/app".to_owned(),
            ),
            (
                "pem-private-key",
                // Split so the repository secret scan does not flag this fixture.
                format!("-----BEGIN {}-----\nMIIEvQ truncated", "PRIVATE KEY"),
                "[REDACTED]".to_owned(),
            ),
        ] {
            let mut matched = Vec::new();
            let redacted = redact_builtin_secrets(&text, &mut |rule| matched.push(rule));
            assert_eq!(redacted.as_deref(), Some(expected.as_str()), "{name}");
            assert_eq!(matched, [name]);
        }
        assert_eq!(
            builtin_secret_pattern_names(),
            [
                "pem-private-key",
                "authorization-header",
                "bearer-token",
                "url-credentials",
                "sk-api-key",
                "github-token",
                "github-fine-grained-pat",
                "aws-access-key-id",
                "slack-token",
                "jwt",
            ]
        );
    }

    #[test]
    fn builtin_patterns_leave_ordinary_values_alone() {
        for text in [
            "input_tokens=1200 output_tokens=400 total 1600",
            "550e8400-e29b-41d4-a716-446655440000",
            "0195f3a2-7b1c-7def-8abc-0123456789ab",
            "commit 7ebad3a1c0ffee00deadbeef0123456789abcdef",
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "https://example.test:8443/path?user=a@b.test",
            "http://localhost:3000/callback",
            "ssh://git@github.com:22/org/repo.git",
            "git@github.com:org/repo.git",
            "mailto:dev@example.test",
            "Authorization: Bearer <token>",
            "Authorization: Bearer $API_TOKEN",
            "authorization: required",
            "use bearer authentication for every request",
            "the task-runner and disk-usage-report-for-all-volumes",
            "sk-learn-style-hyphenated-slug-without-digits",
            "sk-short1",
            "ghp_tooshort123",
            concat!("AKIA", "IOSFODNN7EXAMPLEEXTRA"),
            "xoxo-gossip-girl",
            "eyJhbGciOiJIUzI1NiJ9 alone is not a token",
            "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
            "[REDACTED]",
            "https://user:[REDACTED]@host/path",
        ] {
            assert_eq!(redact_builtin_secrets(text, &mut |_| {}), None, "{text}");
        }
    }

    #[test]
    fn builtin_patterns_cover_structured_payloads_and_the_command_by_default() {
        let temp = tempfile::tempdir().unwrap();
        let key = format!("sk-{}", "a1B2c3D4e5F6g7H8i9J0k1L2");
        let command = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!("curl -H 'Authorization: Bearer {key}' https://u:pw123@example.test"),
        ];
        let payload = serde_json::json!({
            "note": format!("called with {key}"),
            "items": ["clone https://deploy:hunter2@git.example.test/r.git"],
            "usage": {"input_tokens": 1200, "output_tokens": 400},
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "commit": "7ebad3a1c0ffee00deadbeef0123456789abcdef",
        });
        let record = |name: &str, redaction: RedactionConfig| {
            let root = temp.path().join(name);
            let mut writer = TraceWriter::create_named_with_redaction(
                &root,
                command.clone(),
                Some(format!("run {key}")),
                redaction,
            )
            .unwrap();
            writer
                .append("tool.result", "sdk", payload.clone())
                .unwrap();
            writer
                .append(
                    "process.stdout",
                    "command",
                    serde_json::json!({"text": format!("printed {key}\n")}),
                )
                .unwrap();
            let manifest = writer.finish(0).unwrap();
            let stored = format!(
                "{}{}",
                fs::read_to_string(root.join("manifest.json")).unwrap(),
                read_events(&root)
                    .unwrap()
                    .iter()
                    .map(|event| event.payload_json.clone())
                    .collect::<String>()
            );
            (manifest, read_events(&root).unwrap(), stored)
        };

        let (manifest, events, stored) = record("default.atrace", RedactionConfig::default());
        assert_eq!(
            manifest.command[2],
            "curl -H 'Authorization: Bearer [REDACTED]' https://u:[REDACTED]@example.test"
        );
        assert_eq!(manifest.name.as_deref(), Some("run [REDACTED]"));
        let stored_payload = events[0].payload();
        assert_eq!(stored_payload["note"], "called with [REDACTED]");
        assert_eq!(
            stored_payload["items"][0],
            "clone https://deploy:[REDACTED]@git.example.test/r.git"
        );
        for kept in ["usage", "id", "commit"] {
            assert_eq!(stored_payload[kept], payload[kept]);
        }
        // Terminal text stays raw unless the user opts in.
        assert_eq!(events[1].payload()["text"], format!("printed {key}\n"));
        assert_eq!(stored.matches(&key).count(), 1);
        let provenance = manifest.redaction.unwrap();
        assert_eq!(provenance.builtin_patterns, builtin_secret_pattern_names());
        assert!(provenance.builtin_patterns_structured);
        assert!(!provenance.builtin_patterns_terminal);
        assert!(!manifest.capabilities.contains(&"terminal-redaction".into()));

        let (manifest, _, stored) = record(
            "terminal.atrace",
            RedactionConfig::default().known_secrets_in_terminal(true),
        );
        assert!(!stored.contains(&key), "{stored}");
        assert!(manifest.redaction.unwrap().builtin_patterns_terminal);
        assert!(manifest.capabilities.contains(&"terminal-redaction".into()));

        let (manifest, events, stored) = record(
            "off.atrace",
            RedactionConfig::default().default_secret_patterns(false),
        );
        assert_eq!(events[0].payload(), payload);
        assert_eq!(stored.matches(&key).count(), 4);
        let provenance = manifest.redaction.unwrap();
        assert!(provenance.builtin_patterns.is_empty());
        assert!(!provenance.builtin_patterns_structured);
    }

    #[test]
    fn opted_in_terminal_patterns_hold_split_tokens_and_whole_key_blocks() {
        let key = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let (head, tail) = key.split_at(12);
        let rules = || RedactionConfig::default().known_secrets_in_terminal(true);
        assert_eq!(
            journal_chunks(
                rules(),
                "process.terminal",
                &["export GH=", head, tail, "\nok\n"]
            ),
            "export GH=[REDACTED]\nok\n"
        );
        let block = [
            "key:\n-----BEGIN OPENSSH ",
            "PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAA\n",
            "QyNTUxOQAAACD\n",
            "-----END OPENSSH PRIVATE KEY-----\n",
            "after\n",
        ];
        assert_eq!(
            journal_chunks(rules(), "process.stdout", &block),
            "key:\n[REDACTED]\nafter\n"
        );
        // Without the opt-in the same output is stored exactly as captured.
        assert_eq!(
            journal_chunks(RedactionConfig::default(), "process.stdout", &block),
            block.concat()
        );
    }

    #[test]
    fn adapter_stdout_lines_get_the_same_value_patterns_as_their_native_copy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("adapter-values.atrace");
        let key = format!("sk-{}", "a1B2c3D4e5F6g7H8i9J0k1L2");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .set_adapter(AdapterProvenance {
                provider: "claude".into(),
                schema_version: 1,
                transport: "stdout-jsonl".into(),
                completeness: "provider-native-best-effort".into(),
            })
            .unwrap();
        let line = format!(r#"{{"type":"result","result":"used {key}"}}"#);
        writer
            .append(
                "process.stdout",
                "command",
                serde_json::json!({"text": format!("{line}\nplain {key}\n")}),
            )
            .unwrap();
        writer.finish(0).unwrap();
        assert_eq!(
            read_events(&root).unwrap()[0].payload()["text"],
            format!("{{\"result\":\"used [REDACTED]\",\"type\":\"result\"}}\nplain {key}\n")
        );
    }

    proptest::proptest! {
        #[test]
        fn chunked_terminal_redaction_matches_unchunked(
            pieces in proptest::collection::vec("(ab|abc|cab|b|c|x|\n){0,6}", 0..8)
        ) {
            let chunks: Vec<&str> = pieces.iter().map(String::as_str).collect();
            let whole = pieces.concat();
            let rules = || text_rules(&["abc", "cab", "bb"], &[]);
            proptest::prop_assert_eq!(
                journal_chunks(rules(), "process.stdout", &chunks),
                journal_chunks(rules(), "process.stdout", &[whole.as_str()])
            );
        }
    }

    #[test]
    fn text_rules_apply_to_every_string_of_every_event_payload() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("payloads.atrace");
        let mut writer = TraceWriter::create_named_with_redaction(
            &root,
            vec!["agent".into()],
            None,
            text_rules(&["LITERAL-SECRET"], &["id-[0-9]+"]),
        )
        .unwrap();
        writer
            .append(
                "provider.event",
                "adapter.claude.v1",
                serde_json::json!({
                    "native": {"result": "used LITERAL-SECRET", "items": ["id-42", {"note": "LITERAL-SECRET id-7"}]},
                    "count": 3
                }),
            )
            .unwrap();
        writer.finish(0).unwrap();
        let payload = read_events(&root).unwrap()[0].payload();
        assert_eq!(payload["native"]["result"], "used [REDACTED]");
        assert_eq!(payload["native"]["items"][0], "[REDACTED]");
        assert_eq!(
            payload["native"]["items"][1]["note"],
            "[REDACTED] [REDACTED]"
        );
        assert_eq!(payload["count"], 3);
    }

    #[test]
    fn adapter_traces_redact_secret_fields_in_the_raw_stdout_copy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("native.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        let line = r#"{"type":"tool_use","input":{"api_key":"sk-RAW","region":"eu"}}"#;
        let untouched = "{\"type\": \"init\"}\r\nplain text token=visible\n";
        let text = format!("{untouched}{line}\r\n");
        // Without an adapter, terminal text stays raw.
        writer
            .append(
                "process.stdout",
                "command",
                serde_json::json!({"text": text}),
            )
            .unwrap();
        writer
            .set_adapter(AdapterProvenance {
                provider: "claude".into(),
                schema_version: 1,
                transport: "stdout-jsonl".into(),
                completeness: "provider-native-best-effort".into(),
            })
            .unwrap();
        writer
            .append(
                "process.stdout",
                "command",
                serde_json::json!({"text": text}),
            )
            .unwrap();
        writer.finish(0).unwrap();
        let events = read_events(&root).unwrap();
        assert_eq!(events[0].payload()["text"], text);
        assert_eq!(
            events[1].payload()["text"],
            format!(
                "{untouched}{}\r\n",
                r#"{"input":{"api_key":"[REDACTED]","region":"eu"},"type":"tool_use"}"#
            )
        );
    }

    #[test]
    fn custom_field_names_that_normalize_to_nothing_are_rejected() {
        for name in ["---", "@@@", "_ _"] {
            let error = RedactionConfig::new(
                [name],
                std::iter::empty::<String>(),
                std::iter::empty::<String>(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("redaction field"), "{error}");
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("unicode-field.atrace");
        let redaction = RedactionConfig::new(
            ["密码"],
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .unwrap();
        let mut writer =
            TraceWriter::create_named_with_redaction(&root, vec!["agent".into()], None, redaction)
                .unwrap();
        writer
            .append(
                "tool.execution",
                "sdk",
                serde_json::json!({"密码": "hunter2", "user_密码": "hunter3", "safe": "keep me"}),
            )
            .unwrap();
        writer.finish(0).unwrap();
        let payload = read_events(&root).unwrap()[0].payload();
        assert_eq!(payload["密码"], "[REDACTED]");
        assert_eq!(payload["user_密码"], "[REDACTED]");
        assert_eq!(payload["safe"], "keep me");
    }

    #[test]
    fn recorded_command_and_name_are_redacted_in_the_manifest_and_session_start() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("argv.atrace");
        let command: Vec<String> = [
            "agent",
            "--api-key=sk-KEYED",
            "--token",
            "tok-SEPARATE",
            "--password",
            "--verbose",
            "OPENAI_API_KEY=sk-ENV",
            "-H",
            "Authorization: Bearer hdr-SECRET",
            "--header=X-Api-Key:hdr-TIGHT",
            "--max-tokens",
            "4096",
            "https://example.test/path",
            "say LITERAL-SECRET",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let expected = [
            "agent",
            "--api-key=[REDACTED]",
            "--token",
            "[REDACTED]",
            "--password",
            "--verbose",
            "OPENAI_API_KEY=[REDACTED]",
            "-H",
            "Authorization: [REDACTED]",
            "--header=X-Api-Key:[REDACTED]",
            "--max-tokens",
            "4096",
            "https://example.test/path",
            "say [REDACTED]",
        ];
        let mut writer = TraceWriter::create_named_with_redaction(
            &root,
            command.clone(),
            Some("run LITERAL-SECRET".into()),
            text_rules(&["LITERAL-SECRET"], &[]),
        )
        .unwrap();
        writer
            .append(
                "session.start",
                "premier",
                serde_json::json!({"command": command, "cwd": "/work"}),
            )
            .unwrap();
        let manifest = writer.finish(0).unwrap();
        assert_eq!(manifest.command, expected);
        assert_eq!(manifest.name.as_deref(), Some("run [REDACTED]"));
        let manifest_text = fs::read_to_string(root.join("manifest.json")).unwrap();
        for secret in [
            "sk-KEYED",
            "tok-SEPARATE",
            "sk-ENV",
            "hdr-SECRET",
            "hdr-TIGHT",
        ] {
            assert!(!manifest_text.contains(secret), "{secret} persisted");
        }
        let payload = read_events(&root).unwrap()[0].payload();
        assert_eq!(payload["command"], serde_json::json!(expected));
        assert_eq!(payload["cwd"], "/work");
        assert_eq!(
            redact_command_secrets(&command)[..13],
            expected[..13],
            "default field list covers the same flags without custom rules"
        );
    }

    #[test]
    fn encrypted_trace_hides_manifest_and_active_events_and_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("encrypted.atrace");
        let key = EncryptionKey::from_hex(&"41".repeat(32)).unwrap();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into(), "super-secret-argument".into()],
            Some("private investigation".into()),
            "acme",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer
            .append(
                "agent.result",
                "test",
                serde_json::json!({"text":"private evidence"}),
            )
            .unwrap();

        let manifest_on_disk = fs::read_to_string(root.join("manifest.json")).unwrap();
        let active_on_disk = fs::read(root.join("events").join(ACTIVE_JOURNAL)).unwrap();
        assert!(!manifest_on_disk.contains("super-secret-argument"));
        assert!(!manifest_on_disk.contains("private investigation"));
        assert!(!String::from_utf8_lossy(&active_on_disk).contains("private evidence"));
        assert!(trace_is_encrypted(&root).unwrap());

        writer.finish(0).unwrap();
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        assert_eq!(manifest.tenant_id, "acme");
        assert_eq!(manifest.command[1], "super-secret-argument");
        assert_eq!(
            read_events_with_key(&root, &key).unwrap()[0].payload()["text"],
            "private evidence"
        );

        let wrong = EncryptionKey::from_hex(&"42".repeat(32)).unwrap();
        assert!(read_manifest_with_key(&root, &wrong).is_err());
        assert!(read_events_with_key(&root, &wrong).is_err());
    }

    #[test]
    fn encrypted_event_tampering_is_detected_before_decode() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tampered.atrace");
        let key = EncryptionKey::from_hex(&"51".repeat(32)).unwrap();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into()],
            None,
            "local",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer
            .append("agent.result", "test", serde_json::json!({"ok":true}))
            .unwrap();
        drop(writer);
        let path = root.join("events").join(ACTIVE_JOURNAL);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(read_events_with_key(&root, &key).is_err());
    }

    #[test]
    fn finalized_plaintext_trace_is_atomically_migrated_to_encryption() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy.atrace");
        let mut writer = TraceWriter::create_named(
            &root,
            vec!["agent".into(), "plaintext-command-secret".into()],
            Some("plaintext name".into()),
        )
        .unwrap();
        writer
            .append(
                "agent.result",
                "test",
                serde_json::json!({"text":"plaintext event secret"}),
            )
            .unwrap();
        writer.finish(0).unwrap();

        let key = EncryptionKey::from_hex(&"61".repeat(32)).unwrap();
        reencrypt_finalized_trace(&root, key.clone()).unwrap();
        assert!(trace_is_encrypted(&root).unwrap());
        let disk_manifest = fs::read_to_string(root.join("manifest.json")).unwrap();
        assert!(!disk_manifest.contains("plaintext-command-secret"));
        assert!(!disk_manifest.contains("plaintext name"));
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        assert_eq!(manifest.command[1], "plaintext-command-secret");
        assert_eq!(
            read_events_with_key(&root, &key).unwrap()[0].payload()["text"],
            "plaintext event secret"
        );
        assert!(!temp.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".backup")
        }));
    }

    #[test]
    fn local_trace_claim_is_explicit_and_one_way() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("claim.atrace");
        TraceWriter::create(&root, vec!["agent".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        assert_eq!(claim_local_trace(&root, "acme").unwrap().tenant_id, "acme");
        assert_eq!(read_manifest(&root).unwrap().tenant_id, "acme");
        assert!(claim_local_trace(&root, "other").is_err());
    }

    proptest! {
        #[test]
        fn tenant_validation_matches_the_bounded_identifier_contract(value in ".{0,180}") {
            let expected = !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                });
            prop_assert_eq!(validate_tenant_id(&value).is_ok(), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn trace_storage_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private.atrace");
        let writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("events"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("manifest.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("events").join(ACTIVE_JOURNAL))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(writer);
    }
}
