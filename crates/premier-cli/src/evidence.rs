use premier_trace::{PublicKey, TraceEvent, TraceManifest};
use serde::Serialize;
use serde::ser::{Error as _, SerializeSeq, SerializeStruct};
use serde_json::{Map, Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

pub const MAX_QUERY_LIMIT: usize = 1_000;
pub const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Debug)]
pub struct QueryOptions {
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
    /// Exact `event_id`.
    pub event_id: Option<String>,
    /// Exact `span_id`.
    pub span: Option<String>,
    /// Exact `parent_span_id`.
    pub parent_span: Option<String>,
    /// Exact `parent_event_id`.
    pub parent: Option<String>,
    /// Exact `correlation_id`.
    pub correlation: Option<String>,
    /// Only events with a sequence greater than this.
    pub after_sequence: Option<u64>,
    /// Only events with a sequence less than this.
    pub before_sequence: Option<u64>,
    /// Only events at or after this time.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Only events before this time.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    /// Only events that count as issues (see `docs/events.md`).
    pub issues: bool,
    pub limit: usize,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            kind: None,
            actor: None,
            status: None,
            search: None,
            event_id: None,
            span: None,
            parent_span: None,
            parent: None,
            correlation: None,
            after_sequence: None,
            before_sequence: None,
            since: None,
            until: None,
            issues: false,
            limit: 100,
        }
    }
}

/// Where queried evidence came from and how far it can be relied on.
#[derive(Clone, Debug, Serialize)]
pub struct QuerySource {
    /// `trace` or `export`.
    pub kind: &'static str,
    /// `false` for a trace that is still recording or was interrupted: its
    /// events are unverified and may be incomplete.
    pub finalized: bool,
    /// `verified`, `failed` (read with `--allow-unverified`) or `not_finalized`.
    pub verification: &'static str,
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub matched: usize,
    pub returned: usize,
    pub truncated: bool,
    /// When `truncated`: pass this as `--after-sequence` for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<QuerySource>,
    pub events: Vec<TraceEvent>,
}

fn exact_filter(expected: &Option<String>, actual: &str) -> bool {
    expected
        .as_deref()
        .is_none_or(|expected| expected.eq_ignore_ascii_case(actual))
}

/// Ids are opaque: they match exactly, case included.
fn id_filter(expected: &Option<String>, actual: &str) -> bool {
    expected
        .as_deref()
        .is_none_or(|expected| expected == actual)
}

pub fn query_events(events: &[TraceEvent], options: &QueryOptions) -> QueryResult {
    let mut matcher = QueryMatcher::new(options);
    for event in events {
        if matcher.matches(event) {
            matcher.keep(|| event.clone());
        }
    }
    matcher.finish()
}

/// Text with terminal control sequences (CSI, OSC and two-byte escapes) removed.
fn strip_ansi(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some('[') => {
                for next in characters.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(next) = characters.next() {
                    if next == '\u{7}' {
                        break;
                    }
                    if next == '\u{1b}' {
                        if characters.peek() == Some(&'\\') {
                            characters.next();
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    output
}

/// Every string in `value`, decoded, one per line.
fn collect_strings(value: &Value, output: &mut String) {
    match value {
        Value::String(text) => {
            output.push('\n');
            output.push_str(text);
        }
        Value::Array(items) => items.iter().for_each(|item| collect_strings(item, output)),
        Value::Object(object) => object
            .values()
            .for_each(|item| collect_strings(item, output)),
        _ => {}
    }
}

/// What `--search` looks in: the event's fields and ids, its payload as JSON
/// text (so key names match), and every payload string as it was recorded,
/// with and without terminal control sequences, so text matches as typed.
fn search_text(event: &TraceEvent) -> String {
    let mut text = [
        event.kind.as_str(),
        event.source.as_str(),
        event.actor_id.as_str(),
        event.actor_type.as_str(),
        event.status.as_str(),
        event.event_id.as_str(),
        event.span_id.as_str(),
        event.parent_span_id.as_str(),
        event.parent_event_id.as_str(),
        event.correlation_id.as_str(),
        event.timestamp.as_str(),
        event.payload_json.as_str(),
    ]
    .join(" ");
    for link in &event.links {
        text.push(' ');
        text.push_str(link);
    }
    // Only an escaped character makes the decoded text differ from the JSON.
    if event.payload_json.contains('\\') {
        let mut decoded = String::new();
        collect_strings(&event.payload(), &mut decoded);
        if decoded.contains('\u{1b}') {
            let plain = strip_ansi(&decoded);
            text.push_str(&plain);
        }
        text.push_str(&decoded);
    }
    text.to_lowercase()
}

/// [`query_events`] over events arriving one at a time: only the matches up
/// to the limit are kept.
pub struct QueryMatcher<'a> {
    options: &'a QueryOptions,
    search: Option<String>,
    matched: usize,
    returned: Vec<TraceEvent>,
}

impl<'a> QueryMatcher<'a> {
    pub fn new(options: &'a QueryOptions) -> Self {
        Self {
            options,
            search: options
                .search
                .as_deref()
                .map(str::trim)
                .filter(|query| !query.is_empty())
                .map(str::to_lowercase),
            matched: 0,
            returned: Vec::new(),
        }
    }

    /// Count `event` and keep it when it matches and the limit allows.
    pub fn push(&mut self, event: TraceEvent) {
        if self.matches(&event) {
            self.keep(|| event);
        }
    }

    fn matches(&self, event: &TraceEvent) -> bool {
        let options = self.options;
        let in_time = || {
            if options.since.is_none() && options.until.is_none() {
                return true;
            }
            // An event without a readable time is in no time window.
            let Ok(at) = chrono::DateTime::parse_from_rfc3339(&event.timestamp) else {
                return false;
            };
            options.since.is_none_or(|since| at >= since)
                && options.until.is_none_or(|until| at < until)
        };
        exact_filter(&options.kind, &event.kind)
            && exact_filter(&options.actor, &event.actor_id)
            && exact_filter(&options.status, &event.status)
            && id_filter(&options.event_id, &event.event_id)
            && id_filter(&options.span, &event.span_id)
            && id_filter(&options.parent_span, &event.parent_span_id)
            && id_filter(&options.parent, &event.parent_event_id)
            && id_filter(&options.correlation, &event.correlation_id)
            && options
                .after_sequence
                .is_none_or(|after| event.sequence > after)
            && options
                .before_sequence
                .is_none_or(|before| event.sequence < before)
            && (!options.issues || crate::issues::is_issue(event))
            && in_time()
            && self
                .search
                .as_ref()
                .is_none_or(|query| search_text(event).contains(query))
    }

    fn keep(&mut self, event: impl FnOnce() -> TraceEvent) {
        self.matched += 1;
        if self.returned.len() < self.options.limit {
            self.returned.push(event());
        }
    }

    pub fn finish(self) -> QueryResult {
        let truncated = self.matched > self.returned.len();
        QueryResult {
            matched: self.matched,
            returned: self.returned.len(),
            truncated,
            next_after_sequence: truncated
                .then(|| self.returned.last().map(|event| event.sequence))
                .flatten(),
            source: None,
            events: self.returned,
        }
    }
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub use premier_trace::RedactionCounts;
use premier_trace::SecretRedactor;

/// Which optional rules a redaction pass applies on top of secret field names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactionOptions {
    /// Built-in secret value patterns on structured strings and the command line.
    pub default_secret_patterns: bool,
    /// Built-in secret value patterns on captured terminal text as well.
    pub known_secrets_in_terminal: bool,
}

impl Default for RedactionOptions {
    fn default() -> Self {
        Self {
            default_secret_patterns: true,
            known_secrets_in_terminal: false,
        }
    }
}

/// Recursively replace the values of secret-named fields. Besides plain
/// object keys this covers header-style pairs (`{"name": "Authorization",
/// "value": ...}` and `["Authorization", ...]`), argument and header lists
/// (`--token VALUE`, `API_KEY=VALUE`, `Cookie: VALUE`), and JSON documents
/// stored inside string values. String values are also checked against the
/// built-in secret value patterns. Returns what was removed. The rules are
/// the recorder's own ([`SecretRedactor`]), which applies them before the
/// journal write; export repeats them for traces recorded earlier.
pub fn redact_secrets(value: &mut Value) -> RedactionCounts {
    redact_secrets_with(value, true)
}

/// [`redact_secrets`], with the built-in secret value patterns optional.
pub fn redact_secrets_with(value: &mut Value, value_patterns: bool) -> RedactionCounts {
    let mut redactor = SecretRedactor::new(value_patterns);
    redactor.redact(value);
    redactor.into_counts()
}

#[derive(Debug, Serialize)]
pub struct PortableEvidence {
    pub format: &'static str,
    pub exporter: PortableExporter,
    pub source: PortableSource,
    pub manifest: Value,
    pub events: Vec<Value>,
    /// Written after the events it counts, like `redaction` and
    /// `integrity`, so an export can be produced in one pass over the journal.
    pub selection: PortableSelection,
    pub redaction: PortableRedaction,
    pub integrity: PortableIntegrity,
}

const PORTABLE_FORMAT: &str = "premier.portable-evidence.v1";

/// The build that wrote an export.
#[derive(Clone, Debug, Serialize)]
pub struct PortableExporter {
    pub name: &'static str,
    pub version: &'static str,
}

const EXPORTER: PortableExporter = PortableExporter {
    name: "premier",
    version: env!("CARGO_PKG_VERSION"),
};

/// What `premier export` knew about the source trace when it read it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SourceState {
    /// A finalized trace that passed `premier verify`.
    Verified,
    /// A finalized trace that failed verification and was exported anyway.
    Failed,
    /// Still recording, or interrupted: the events may be incomplete.
    NotFinalized,
    /// The caller did not verify the trace.
    #[default]
    NotChecked,
}

impl SourceState {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::NotFinalized => "not_finalized",
            Self::NotChecked => "not_checked",
        }
    }
}

/// Which events an export keeps. Every condition that is set must hold.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ExportSelection {
    /// Event kinds to keep (exact, case-insensitive); empty keeps every kind.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kind: Vec<String>,
    /// Actor ids to keep (exact, case-insensitive); empty keeps every actor.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actor: Vec<String>,
    /// Keep events with a sequence greater than this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_sequence: Option<u64>,
    /// Keep events with a sequence less than this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_sequence: Option<u64>,
}

impl ExportSelection {
    pub fn is_everything(&self) -> bool {
        *self == Self::default()
    }

    fn selects(&self, event: &TraceEvent) -> bool {
        let any = |allowed: &[String], actual: &str| {
            allowed.is_empty()
                || allowed
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(actual))
        };
        any(&self.kind, &event.kind)
            && any(&self.actor, &event.actor_id)
            && self
                .after_sequence
                .is_none_or(|after| event.sequence > after)
            && self
                .before_sequence
                .is_none_or(|before| event.sequence < before)
    }
}

/// The selection an export applied and what it left.
#[derive(Debug, Serialize)]
pub struct PortableSelection {
    /// `false` when every event of the source was exported.
    pub applied: bool,
    pub filters: ExportSelection,
    /// Events read from the source trace.
    pub source_events: u64,
    /// Events in this export.
    pub exported_events: u64,
}

/// Everything that shapes an export.
#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    pub redaction: RedactionOptions,
    pub selection: ExportSelection,
    pub source_state: SourceState,
    /// Extra field names whose values are removed (`--redact-field`).
    pub redact_fields: Vec<String>,
    /// Exact texts removed from every string (`--redact-literal`).
    pub redact_literals: Vec<String>,
}

impl From<RedactionOptions> for ExportOptions {
    fn from(redaction: RedactionOptions) -> Self {
        Self {
            redaction,
            ..Self::default()
        }
    }
}

/// Tamper-evidence values of the trace an export was derived from, copied
/// from its manifest so the package states its origin.
#[derive(Debug, Serialize)]
pub struct PortableSource {
    pub trace_id: String,
    pub format_version: u32,
    /// `digest_only` (v1), `sealed` (v2, unsigned) or `signed`.
    pub protection: &'static str,
    /// Whether the source trace was finalized. `false` means it was still
    /// recording or had been interrupted, so the events may be incomplete.
    pub finalized: bool,
    /// What the exporter established about the source: `verified`, `failed`
    /// (exported with `--allow-unverified`), `not_finalized` or `not_checked`.
    pub verification: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_fingerprint: Option<String>,
    pub note: &'static str,
}

fn portable_source(manifest: &TraceManifest, state: SourceState) -> PortableSource {
    let seal = manifest.seal.as_ref();
    let signature = seal.and_then(|seal| seal.signature.as_ref());
    PortableSource {
        trace_id: manifest.trace_id.clone(),
        format_version: manifest.format_version,
        protection: match (seal, signature) {
            (None, _) => "digest_only",
            (Some(_), None) => "sealed",
            (Some(_), Some(_)) => "signed",
        },
        finalized: manifest.journal.is_some(),
        verification: if manifest.journal.is_none() {
            SourceState::NotFinalized.label()
        } else {
            state.label()
        },
        journal_sha256: manifest
            .journal
            .as_ref()
            .map(|journal| journal.sha256.clone()),
        chain_head: seal.map(|seal| seal.chain_head.clone()),
        event_count: seal.map(|seal| seal.event_count),
        seal: seal.map(|seal| seal.digest.clone()),
        signature: signature.map(|signature| signature.signature.clone()),
        public_key: signature.map(|signature| signature.public_key.clone()),
        public_key_fingerprint: signature
            .and_then(|signature| PublicKey::from_hex(&signature.public_key).ok())
            .map(|key| key.fingerprint()),
        note: "Copied from the source manifest. This export is a derived, redacted copy: the source's seal and signature do not cover it. `integrity` below is the export's own digest; verify the original trace with `premier verify`.",
    }
}

#[derive(Debug, Serialize)]
pub struct PortableRedaction {
    /// Whether this export removed at least one value. `false` means the
    /// rules below ran and found nothing left to redact.
    pub applied: bool,
    pub replacement: &'static str,
    pub policy: &'static str,
    /// The rules that were active for this export.
    pub rules: PortableRedactionRules,
    /// What this export removed, by rule type.
    pub redacted: RedactionCounts,
    /// What the export's own `--redact-field` and `--redact-literal` rules
    /// removed. Absent when none were given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomRedactionCounts>,
}

/// Values removed by rules given to `premier export` itself.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CustomRedactionCounts {
    /// Values replaced because their field name was given with `--redact-field`.
    pub fields: usize,
    /// Occurrences of a `--redact-literal` text that were replaced.
    pub literals: usize,
}

#[derive(Debug, Serialize)]
pub struct PortableRedactionRules {
    /// Field, flag and header names (normalized) whose values are removed.
    pub secret_field_names: &'static [&'static str],
    /// Built-in secret value patterns that were active; empty when off.
    pub builtin_patterns: Vec<&'static str>,
    pub builtin_patterns_structured: bool,
    pub builtin_patterns_terminal: bool,
    /// Field names given with `--redact-field`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<String>,
    /// How many `--redact-literal` texts were given; the texts are not stored.
    #[serde(skip_serializing_if = "is_zero")]
    pub literal_count: usize,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// The export's own identity: a digest over everything in it.
#[derive(Clone, Debug, Serialize)]
pub struct PortableIntegrity {
    pub algorithm: &'static str,
    pub event_count: u64,
    /// SHA-256 over the exported events, each as compact JSON with sorted
    /// keys and followed by a line feed.
    pub events_sha256: String,
    /// SHA-256 over the compact, sorted-key JSON of `format`, `exporter`,
    /// `source`, `manifest`, `selection`, `redaction`, `event_count` and
    /// `events_sha256`.
    pub digest: String,
    pub note: &'static str,
}

const INTEGRITY_NOTE: &str = "Recomputed by `premier verify <export.json>`. The digest is stored in the file it covers: it detects damage and careless edits, and lets two copies be compared, but whoever can rewrite the file can recompute it. Record the digest somewhere else to detect that.";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `value` as it reads back from a file. Digests are taken over this form,
/// not over the value in memory: a float does not always survive being
/// printed and parsed unchanged, and a verifier only has the parsed file.
fn as_read_back(value: &Value) -> Value {
    serde_json::to_vec(value)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| value.clone())
}

/// The digest over an export's blocks other than its events.
fn export_digest(blocks: [(&str, &Value); 6], event_count: u64, events_sha256: &str) -> String {
    let mut header = Map::new();
    for (name, value) in blocks {
        header.insert(name.to_owned(), value.clone());
    }
    header.insert("event_count".into(), json!(event_count));
    header.insert("events_sha256".into(), json!(events_sha256));
    sha256_hex(&serde_json::to_vec(&Value::Object(header)).unwrap_or_default())
}

pub fn portable_evidence(manifest: &TraceManifest, events: &[TraceEvent]) -> PortableEvidence {
    portable_evidence_with(manifest, events, RedactionOptions::default())
}

pub fn portable_evidence_with(
    manifest: &TraceManifest,
    events: &[TraceEvent],
    options: impl Into<ExportOptions>,
) -> PortableEvidence {
    let options = options.into();
    let mut state = ExportState::new(&options);
    let source = portable_source(manifest, options.source_state);
    let manifest = state.manifest(manifest);
    let events = events
        .iter()
        .filter_map(|event| state.event(event))
        .collect();
    let trailer = state.finish(&source, &manifest);
    PortableEvidence {
        format: PORTABLE_FORMAT,
        exporter: EXPORTER,
        source,
        manifest,
        events,
        selection: trailer.selection,
        redaction: trailer.redaction,
        integrity: trailer.integrity,
    }
}

/// The blocks of an export that are only known once every event was written.
struct ExportTrailer {
    selection: PortableSelection,
    redaction: PortableRedaction,
    integrity: PortableIntegrity,
}

/// Everything an export accumulates while its events go by: the two
/// redaction passes with what they removed, the selection counts, and the
/// digest. Both redaction passes are the recorder's shared
/// [`SecretRedactor`], so the in-memory and the streamed export apply exactly
/// the rules a recording does.
struct ExportState<'a> {
    options: &'a ExportOptions,
    structured: SecretRedactor<'static>,
    /// Captured terminal text is only pattern-matched when asked for.
    terminal: SecretRedactor<'static>,
    custom_fields: Vec<String>,
    custom: CustomRedactionCounts,
    source_events: u64,
    exported_events: u64,
    events_hash: sha2::Sha256,
}

impl<'a> ExportState<'a> {
    fn new(options: &'a ExportOptions) -> Self {
        use sha2::Digest;
        Self {
            options,
            structured: SecretRedactor::new(options.redaction.default_secret_patterns),
            terminal: SecretRedactor::new(options.redaction.known_secrets_in_terminal),
            custom_fields: options
                .redact_fields
                .iter()
                .map(|field| normalized_key(field))
                .filter(|field| !field.is_empty())
                .collect(),
            custom: CustomRedactionCounts::default(),
            source_events: 0,
            exported_events: 0,
            events_hash: sha2::Sha256::new(),
        }
    }

    fn has_custom_rules(&self) -> bool {
        !self.custom_fields.is_empty() || !self.options.redact_literals.is_empty()
    }

    /// Apply the export's own field and literal rules to `value`.
    fn redact_custom(&mut self, value: &mut Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object.iter_mut() {
                    if self.custom_fields.contains(&normalized_key(key)) {
                        if *value != json!(REDACTED) {
                            *value = json!(REDACTED);
                            self.custom.fields += 1;
                        }
                    } else {
                        self.redact_custom(value);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_custom(item);
                }
            }
            Value::String(text) => {
                for literal in &self.options.redact_literals {
                    let found = text.matches(literal.as_str()).count();
                    if !literal.is_empty() && found > 0 {
                        *text = text.replace(literal.as_str(), REDACTED);
                        self.custom.literals += found;
                    }
                }
            }
            _ => {}
        }
    }

    fn manifest(&mut self, manifest: &TraceManifest) -> Value {
        let mut manifest = serde_json::to_value(manifest).unwrap_or(Value::Null);
        self.structured.redact(&mut manifest);
        if self.has_custom_rules() {
            self.redact_custom(&mut manifest);
        }
        manifest
    }

    /// The exported form of `event`, or `None` when the selection leaves it out.
    fn event(&mut self, event: &TraceEvent) -> Option<Value> {
        use sha2::Digest;
        self.source_events += 1;
        if !self.options.selection.selects(event) {
            return None;
        }
        let mut object = match serde_json::to_value(event).unwrap_or(Value::Null) {
            Value::Object(object) => object,
            _ => Map::new(),
        };
        object.remove("payload_json");
        let mut payload = match serde_json::from_str::<Value>(&event.payload_json) {
            Ok(payload) => payload,
            // Not JSON: keep what was recorded instead of exporting `null`.
            Err(_) => {
                object.insert("payload_raw".into(), json!(event.payload_json));
                Value::Null
            }
        };
        let terminal_text = matches!(
            event.kind.as_str(),
            "process.stdout" | "process.stderr" | "process.terminal"
        )
        .then(|| payload.as_object_mut()?.remove("text"))
        .flatten();
        object.insert("payload".into(), payload);
        let mut event = Value::Object(object);
        self.structured.redact(&mut event);
        if let Some(mut text) = terminal_text {
            self.terminal.redact(&mut text);
            event["payload"]["text"] = text;
        }
        if self.has_custom_rules() {
            self.redact_custom(&mut event);
        }
        self.exported_events += 1;
        self.events_hash
            .update(serde_json::to_vec(&as_read_back(&event)).unwrap_or_default());
        self.events_hash.update(b"\n");
        Some(event)
    }

    /// The blocks that follow the events.
    fn finish(&self, source: &PortableSource, manifest: &Value) -> ExportTrailer {
        use sha2::Digest;
        let options = self.options.redaction;
        let mut redacted = self.structured.counts().clone();
        let terminal = self.terminal.counts().clone();
        redacted.total += terminal.total;
        redacted.field_names += terminal.field_names;
        redacted.already_redacted += terminal.already_redacted;
        for (name, count) in terminal.value_patterns {
            *redacted.value_patterns.entry(name).or_default() += count;
        }
        let builtin = options.default_secret_patterns || options.known_secrets_in_terminal;
        let mut custom_fields = self.options.redact_fields.clone();
        custom_fields.sort();
        custom_fields.dedup();
        let redaction = PortableRedaction {
            applied: redacted.total + self.custom.fields + self.custom.literals > 0,
            replacement: REDACTED,
            policy: "recursive common secret field names, including JSON strings and header or argument lists, plus built-in secret value patterns",
            rules: PortableRedactionRules {
                secret_field_names: premier_trace::DEFAULT_REDACTED_FIELDS,
                builtin_patterns: if builtin {
                    premier_trace::builtin_secret_pattern_names()
                } else {
                    Vec::new()
                },
                builtin_patterns_structured: options.default_secret_patterns,
                builtin_patterns_terminal: options.known_secrets_in_terminal,
                custom_fields,
                literal_count: self.options.redact_literals.len(),
            },
            redacted,
            custom: self.has_custom_rules().then(|| self.custom.clone()),
        };
        let selection = PortableSelection {
            applied: !self.options.selection.is_everything(),
            filters: self.options.selection.clone(),
            source_events: self.source_events,
            exported_events: self.exported_events,
        };
        let events_sha256: String = self
            .events_hash
            .clone()
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let digest = export_digest(
            [
                ("format", &json!(PORTABLE_FORMAT)),
                ("exporter", &block_value(&EXPORTER)),
                ("source", &block_value(source)),
                ("manifest", &as_read_back(manifest)),
                ("selection", &block_value(&selection)),
                ("redaction", &block_value(&redaction)),
            ],
            self.exported_events,
            &events_sha256,
        );
        ExportTrailer {
            selection,
            redaction,
            integrity: PortableIntegrity {
                algorithm: "sha256",
                event_count: self.exported_events,
                events_sha256,
                digest,
                note: INTEGRITY_NOTE,
            },
        }
    }
}

/// An export block as the JSON value a verifier reads back.
fn block_value<T: Serialize>(block: &T) -> Value {
    as_read_back(&serde_json::to_value(block).unwrap_or(Value::Null))
}

/// What a streamed export wrote.
#[derive(Clone, Debug)]
pub struct ExportSummary {
    pub redacted: RedactionCounts,
    pub custom: CustomRedactionCounts,
    pub source_events: u64,
    pub exported_events: u64,
    pub digest: String,
}

/// Write the same document as [`portable_evidence_with`] to `writer`,
/// redacting and serializing one event at a time instead of building the
/// export in memory. Returns what was redacted.
pub fn write_portable_evidence<W: std::io::Write>(
    writer: W,
    manifest: &TraceManifest,
    events: impl Iterator<Item = anyhow::Result<TraceEvent>>,
    options: RedactionOptions,
) -> anyhow::Result<RedactionCounts> {
    Ok(write_portable_evidence_with(writer, manifest, events, &options.into())?.redacted)
}

/// [`write_portable_evidence`] with a selection, export-time rules, and the
/// verification state of the source.
pub fn write_portable_evidence_with<W: std::io::Write>(
    writer: W,
    manifest: &TraceManifest,
    events: impl Iterator<Item = anyhow::Result<TraceEvent>>,
    options: &ExportOptions,
) -> anyhow::Result<ExportSummary> {
    let mut export = ExportState::new(options);
    let export = StreamedEvidence {
        source: portable_source(manifest, options.source_state),
        manifest: export.manifest(manifest),
        state: RefCell::new(StreamedState {
            events: Some(events),
            export,
            failure: None,
            summary: None,
        }),
    };
    let written = serde_json::to_writer_pretty(writer, &export);
    let state = export.state.into_inner();
    if let Some(error) = state.failure {
        return Err(error);
    }
    written?;
    state
        .summary
        .ok_or_else(|| anyhow::anyhow!("the export was not written completely"))
}

struct StreamedState<'a, I> {
    events: Option<I>,
    export: ExportState<'a>,
    /// The journal error that ended serialization early.
    failure: Option<anyhow::Error>,
    summary: Option<ExportSummary>,
}

struct StreamedEvidence<'a, I> {
    source: PortableSource,
    manifest: Value,
    state: RefCell<StreamedState<'a, I>>,
}

impl<I: Iterator<Item = anyhow::Result<TraceEvent>>> Serialize for StreamedEvidence<'_, I> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut document = serializer.serialize_struct("PortableEvidence", 8)?;
        document.serialize_field("format", PORTABLE_FORMAT)?;
        document.serialize_field("exporter", &EXPORTER)?;
        document.serialize_field("source", &self.source)?;
        document.serialize_field("manifest", &self.manifest)?;
        document.serialize_field("events", &StreamedEvents(&self.state))?;
        // Fields are written in order, so the counts are complete by now.
        let mut state = self.state.borrow_mut();
        let trailer = state.export.finish(&self.source, &self.manifest);
        document.serialize_field("selection", &trailer.selection)?;
        document.serialize_field("redaction", &trailer.redaction)?;
        document.serialize_field("integrity", &trailer.integrity)?;
        state.summary = Some(ExportSummary {
            redacted: trailer.redaction.redacted,
            custom: trailer.redaction.custom.unwrap_or_default(),
            source_events: trailer.selection.source_events,
            exported_events: trailer.selection.exported_events,
            digest: trailer.integrity.digest,
        });
        document.end()
    }
}

struct StreamedEvents<'s, 'a, I>(&'s RefCell<StreamedState<'a, I>>);

impl<I: Iterator<Item = anyhow::Result<TraceEvent>>> Serialize for StreamedEvents<'_, '_, I> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = self.0.borrow_mut();
        let state = &mut *state;
        let events = state
            .events
            .take()
            .ok_or_else(|| S::Error::custom("events were already written"))?;
        let mut sequence = serializer.serialize_seq(None)?;
        for event in events {
            match event {
                Ok(event) => {
                    if let Some(event) = state.export.event(&event) {
                        sequence.serialize_element(&event)?;
                    }
                }
                Err(error) => {
                    state.failure = Some(error);
                    return Err(S::Error::custom("cannot read the trace journal"));
                }
            }
        }
        sequence.end()
    }
}

/// A parsed export file.
#[derive(Debug)]
pub struct ExportDocument {
    /// The whole document.
    pub document: Value,
    pub events: Vec<TraceEvent>,
}

/// What [`ExportDocument::verify`] established.
#[derive(Debug)]
pub struct VerifiedExport {
    pub digest: String,
    pub event_count: u64,
    pub source_trace_id: String,
    pub source_protection: String,
    pub source_verification: String,
    pub selection_applied: bool,
    pub source_events: Option<u64>,
    /// The source's signer, when the copied signature is valid for the
    /// copied seal digest.
    pub source_signer: Option<PublicKey>,
}

impl ExportDocument {
    /// Parse `bytes` as a `premier export` document.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let document: Value = serde_json::from_slice(bytes)
            .map_err(|error| anyhow::anyhow!("not a premier export: invalid JSON: {error}"))?;
        if document.get("format").and_then(Value::as_str) != Some(PORTABLE_FORMAT) {
            anyhow::bail!("not a premier export: `format` is not \"{PORTABLE_FORMAT}\"")
        }
        let exported = document
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("not a premier export: `events` is not a list"))?;
        let mut events = Vec::with_capacity(exported.len());
        for (index, exported) in exported.iter().enumerate() {
            let mut object = exported
                .as_object()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("export event {} is not an object", index + 1))?;
            let payload = object.remove("payload").unwrap_or(Value::Null);
            let payload_json = match object.remove("payload_raw") {
                Some(Value::String(raw)) => raw,
                _ => serde_json::to_string(&payload)?,
            };
            object.insert("payload_json".into(), json!(payload_json));
            events.push(
                serde_json::from_value(Value::Object(object)).map_err(|error| {
                    anyhow::anyhow!("export event {} is malformed: {error}", index + 1)
                })?,
            );
        }
        Ok(Self { document, events })
    }

    /// The export's `manifest` block.
    pub fn manifest(&self) -> &Value {
        &self.document["manifest"]
    }

    /// Recompute the export's digest and compare it with the recorded one.
    /// This shows the file is the one `premier export` wrote (or one whose
    /// digest was recomputed); it says nothing about the source trace beyond
    /// what the `source` block claims.
    pub fn verify(&self) -> anyhow::Result<VerifiedExport> {
        use sha2::Digest;
        let document = &self.document;
        let integrity = document.get("integrity").filter(|value| value.is_object()).ok_or_else(|| {
            anyhow::anyhow!(
                "the export has no `integrity` block: it was written by a premier that predates export digests, or the block was removed"
            )
        })?;
        let recorded = |field: &str| integrity.get(field).and_then(Value::as_str).unwrap_or("");
        if recorded("algorithm") != "sha256" {
            anyhow::bail!(
                "unsupported export digest algorithm {:?}",
                recorded("algorithm")
            )
        }
        let exported = document["events"].as_array().map_or(&[][..], Vec::as_slice);
        let mut hasher = sha2::Sha256::new();
        for event in exported {
            hasher.update(serde_json::to_vec(event)?);
            hasher.update(b"\n");
        }
        let events_sha256: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let event_count = exported.len() as u64;
        if integrity.get("event_count").and_then(Value::as_u64) != Some(event_count) {
            anyhow::bail!(
                "export event count mismatch: the file holds {event_count} event(s) and its integrity block records {}",
                integrity.get("event_count").unwrap_or(&Value::Null)
            )
        }
        if events_sha256 != recorded("events_sha256") {
            anyhow::bail!(
                "export events digest mismatch: the events were changed, removed, added or reordered after the export was written"
            )
        }
        let null = Value::Null;
        let block = |name: &str| document.get(name).unwrap_or(&null);
        let digest = export_digest(
            [
                ("format", block("format")),
                ("exporter", block("exporter")),
                ("source", block("source")),
                ("manifest", block("manifest")),
                ("selection", block("selection")),
                ("redaction", block("redaction")),
            ],
            event_count,
            &events_sha256,
        );
        if digest != recorded("digest") {
            anyhow::bail!(
                "export digest mismatch: the source, manifest, selection or redaction block was changed after the export was written"
            )
        }
        let source = block("source");
        let text = |field: &str| {
            source
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let source_signer = match (
            source.get("seal").and_then(Value::as_str),
            source.get("signature").and_then(Value::as_str),
            source.get("public_key").and_then(Value::as_str),
        ) {
            (Some(seal), Some(signature), Some(public_key)) => {
                let key = PublicKey::from_hex(public_key).map_err(|error| {
                    anyhow::anyhow!("the export's source public key is invalid: {error}")
                })?;
                key.verify_seal_signature(seal, signature).map_err(|_| {
                    anyhow::anyhow!(
                        "the export's source signature is not valid for its source seal digest"
                    )
                })?;
                Some(key)
            }
            (_, None, _) => None,
            _ => anyhow::bail!(
                "the export's source block has a signature without its seal digest and public key"
            ),
        };
        Ok(VerifiedExport {
            digest,
            event_count,
            source_trace_id: text("trace_id"),
            source_protection: text("protection"),
            source_verification: text("verification"),
            selection_applied: document["selection"]["applied"].as_bool().unwrap_or(false),
            source_events: document["selection"]["source_events"].as_u64(),
            source_signer,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffStatus {
    Added,
    Removed,
    Changed,
    /// The same semantic event at a different place in the order. Its
    /// `changes` list what else differs, if anything.
    Moved,
    Unchanged,
}

#[derive(Debug, Default, Serialize)]
pub struct DiffCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub moved: usize,
    pub unchanged: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StructuralChange {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Serialize)]
pub struct DiffItem {
    pub key: String,
    pub status: DiffStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_sequence: Option<u64>,
    pub changes: Vec<StructuralChange>,
}

/// The first item, in trace order, at which the two traces stop agreeing.
#[derive(Debug, Serialize)]
pub struct FirstDivergence {
    /// Index into `items`.
    pub index: usize,
    pub key: String,
    pub status: DiffStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_sequence: Option<u64>,
    /// The first differing field of a changed item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change: Option<StructuralChange>,
}

#[derive(Debug, Serialize)]
pub struct TraceDiff {
    pub format: &'static str,
    /// No event differs and no compared manifest field differs.
    pub identical: bool,
    /// `ordered` when events were aligned in order; `per_key` when the traces
    /// differ in too many places for that and the n-th event of each semantic
    /// key was paired instead (order is then not compared).
    pub alignment: &'static str,
    pub counts: DiffCounts,
    pub first_divergence: Option<FirstDivergence>,
    /// Differences in the manifest fields that describe the run's outcome.
    pub manifest: Vec<StructuralChange>,
    pub items: Vec<DiffItem>,
}

fn compact_identity(value: &Value) -> String {
    match value {
        Value::String(value) => value.trim().to_lowercase(),
        _ => serde_json::to_string(value)
            .unwrap_or_default()
            .to_lowercase(),
    }
}

/// The first of `keys` in `source` that is a non-blank string, trimmed.
fn first_text<'a>(source: Option<&'a Value>, keys: &[&str]) -> Option<&'a str> {
    let source = source?.as_object()?;
    keys.iter().find_map(|key| {
        source
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    })
}

/// The tool a provider's own event names, for adapter events recorded
/// without `payload.tool`. Mirrors `toolFromNative` in the viewer
/// (`apps/viewer/src/lib/nativePayload.ts`).
fn native_tool(payload: &Value) -> Option<Value> {
    let native = payload.get("native").filter(|native| native.is_object())?;
    let item = native.get("item");
    let message = native.get("message");
    let blocks = [
        message.and_then(|message| message.get("content")),
        native.get("content"),
        item.and_then(|item| item.get("content")),
    ]
    .into_iter()
    .find_map(|content| content.and_then(Value::as_array));
    let block_tool = || {
        blocks?.iter().find_map(|block| {
            matches!(
                block.get("type").and_then(Value::as_str),
                Some("tool_use" | "function_call")
            )
            .then(|| first_text(Some(block), &["name"]))
            .flatten()
        })
    };
    let call_tool = || {
        let calls = native
            .get("tool_calls")
            .and_then(Value::as_array)
            .or_else(|| message?.get("tool_calls")?.as_array());
        calls
            .into_iter()
            .flatten()
            .map(Some)
            .chain([
                native.get("tool_call"),
                native.get("function"),
                native.get("params"),
            ])
            .find_map(|call| {
                first_text(call.and_then(|call| call.get("function")), &["name"])
                    .or_else(|| first_text(call, &["name", "tool"]))
            })
    };
    first_text(Some(native), &["tool_name", "tool", "name"])
        .or_else(|| first_text(item, &["tool", "name", "command"]))
        .or_else(|| first_text(native.get("part"), &["tool", "name"]))
        .or_else(block_tool)
        .or_else(call_tool)
        .or_else(|| first_text(Some(native), &["command"]))
        .map(|tool| json!(tool))
}

pub fn semantic_event_key(event: &TraceEvent) -> String {
    let payload = event.payload();
    let native;
    let discriminator = if event.kind.starts_with("tool.") {
        native = payload
            .get("tool")
            .or_else(|| payload.get("name"))
            .or_else(|| payload.get("command"))
            .is_none()
            .then(|| native_tool(&payload))
            .flatten();
        payload
            .get("tool")
            .or_else(|| payload.get("name"))
            .or_else(|| payload.get("command"))
            .or(native.as_ref())
    } else if event.kind.starts_with("approval.") {
        payload.get("operation").or_else(|| payload.get("action"))
    } else {
        None
    };
    // Adapter subagent actors end in the provider's generated tool-call id, which differs per run.
    let actor = event.actor_id.trim();
    let actor = match actor.split_once(":subagent:") {
        Some((provider, _)) if event.source.starts_with("adapter.") => {
            format!("{provider}:subagent")
        }
        _ => actor.to_owned(),
    };
    format!(
        "{}:{}{}",
        event.kind.trim().to_lowercase(),
        if actor.is_empty() { "root" } else { &actor }.to_lowercase(),
        discriminator
            .map(|value| format!(":{}", compact_identity(value)))
            .unwrap_or_default()
    )
}

fn generated_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "eventid"
            | "traceid"
            | "spanid"
            | "parentspanid"
            | "parenteventid"
            | "correlationid"
            | "timestamp"
            | "createdat"
    )
}

/// Ids a provider CLI generates per run; only ignored inside an adapter's `native` copy.
fn provider_generated_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "id" | "uuid"
            | "sessionid"
            | "threadid"
            | "messageid"
            | "requestid"
            | "itemid"
            | "callid"
            | "toolid"
            | "tooluseid"
            | "toolcallid"
            | "parenttooluseid"
    )
}

fn comparable_payload(value: &Value) -> Value {
    comparable_value(value, false)
}

fn comparable_value(value: &Value, native: bool) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !generated_key(key) && !(native && provider_generated_key(key)))
                .map(|(key, value)| {
                    (
                        key.clone(),
                        comparable_value(value, native || key == "native"),
                    )
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| comparable_value(item, native))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn flatten(prefix: &str, value: &Value, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) if !object.is_empty() => {
            for (key, value) in object {
                let field = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&field, value, output);
            }
        }
        _ => {
            output.insert(prefix.into(), value.clone());
        }
    }
}

/// Captured output kinds. A command's output is journaled one event per
/// `read()`, and where those reads fall differs from run to run, so a diff
/// compares each stream as one text instead of chunk by chunk.
fn is_terminal_stream(kind: &str) -> bool {
    matches!(
        kind,
        "process.stdout" | "process.stderr" | "process.terminal"
    )
}

/// The text of a stream as lines, with CRLF read as LF.
fn stream_lines(text: &str) -> Vec<String> {
    let text = text.replace("\r\n", "\n");
    let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

/// One thing a diff aligns: an event, or all the output of one stream.
struct Unit<'a> {
    /// The event, or the first event of the stream.
    event: &'a TraceEvent,
    key: String,
    /// Compared fields by name.
    fields: BTreeMap<String, Value>,
    /// Set for a stream: its whole text, as lines.
    lines: Option<Vec<String>>,
    /// Ids of every event folded into this unit.
    event_ids: Vec<&'a str>,
}

impl Unit<'_> {
    /// Canonical text of everything `compare_units` looks at.
    fn content(&self) -> String {
        let mut content = serde_json::to_string(&self.fields).unwrap_or_default();
        if let Some(lines) = &self.lines {
            content.push('\n');
            content.push_str(&lines.join("\n"));
        }
        content
    }
}

fn event_fields(event: &TraceEvent) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    fields.insert("status".to_owned(), json!(event.status));
    fields.insert("source".to_owned(), json!(event.source));
    fields.insert("actor_type".to_owned(), json!(event.actor_type));
    fields.insert("duration_ms".to_owned(), json!(event.duration_ms));
    let mut payload = comparable_payload(&event.payload());
    // The recorder's collector listens on a random port for each run.
    if event.kind == "session.start"
        && let Some(object) = payload.as_object_mut()
    {
        object.remove("instrumentation");
    }
    flatten("payload", &payload, &mut fields);
    fields
}

/// `events` as diff units, in order: every event that is not captured output,
/// and one unit per output stream at the place of that stream's first event.
fn diff_units(events: &[TraceEvent]) -> Vec<Unit<'_>> {
    let mut units: Vec<Unit<'_>> = Vec::new();
    let mut streams: HashMap<String, (usize, String)> = HashMap::new();
    for event in events {
        let key = semantic_event_key(event);
        if is_terminal_stream(&event.kind) {
            let text = event.payload();
            let text = text.get("text").and_then(Value::as_str).unwrap_or("");
            if let Some((index, collected)) = streams.get_mut(&key) {
                collected.push_str(text);
                units[*index].event_ids.push(&event.event_id);
                continue;
            }
            streams.insert(key.clone(), (units.len(), text.to_owned()));
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), json!(event.source));
            fields.insert("actor_type".to_owned(), json!(event.actor_type));
            units.push(Unit {
                event,
                key,
                fields,
                lines: Some(Vec::new()),
                event_ids: vec![&event.event_id],
            });
        } else {
            units.push(Unit {
                event,
                key,
                fields: event_fields(event),
                lines: None,
                event_ids: vec![&event.event_id],
            });
        }
    }
    for (index, text) in streams.into_values() {
        units[index].lines = Some(stream_lines(&text));
    }
    units
}

fn compare_units(baseline: &Unit<'_>, current: &Unit<'_>) -> Vec<StructuralChange> {
    let mut changes = Vec::new();
    // Event fields first, in a fixed order, then the payload by field name.
    let leading = ["status", "source", "actor_type", "duration_ms"];
    let fields = leading.into_iter().map(str::to_owned).chain(
        baseline
            .fields
            .keys()
            .chain(current.fields.keys())
            .filter(|field| !leading.contains(&field.as_str()))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
    );
    for field in fields {
        let before = baseline.fields.get(&field).cloned().unwrap_or(Value::Null);
        let after = current.fields.get(&field).cloned().unwrap_or(Value::Null);
        if before != after {
            changes.push(StructuralChange {
                field,
                before,
                after,
            });
        }
    }
    if let (Some(before), Some(after)) = (&baseline.lines, &current.lines)
        && before != after
    {
        if before.len() != after.len() {
            changes.push(StructuralChange {
                field: "text.lines".into(),
                before: json!(before.len()),
                after: json!(after.len()),
            });
        }
        let line = before
            .iter()
            .zip(after)
            .position(|(before, after)| before != after)
            .unwrap_or(before.len().min(after.len()));
        changes.push(StructuralChange {
            field: format!("text.line[{}]", line + 1),
            before: before.get(line).map_or(Value::Null, |line| json!(line)),
            after: after.get(line).map_or(Value::Null, |line| json!(line)),
        });
    }
    changes
}

/// Edit distance beyond which an ordered alignment is not attempted.
const MAX_ALIGNMENT_EDITS: usize = 2_000;

/// A longest common subsequence of `a` and `b` as index pairs in order
/// (Myers' O(ND) algorithm), or `None` when the two differ in more than
/// [`MAX_ALIGNMENT_EDITS`] places.
fn common_subsequence(a: &[u32], b: &[u32]) -> Option<Vec<(usize, usize)>> {
    let prefix = a.iter().zip(b).take_while(|(a, b)| a == b).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let mut pairs: Vec<(usize, usize)> = (0..prefix).map(|index| (index, index)).collect();
    let (inner_a, inner_b) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    for (x, y) in middle_subsequence(inner_a, inner_b)? {
        pairs.push((prefix + x, prefix + y));
    }
    pairs.extend((0..suffix).map(|index| (a.len() - suffix + index, b.len() - suffix + index)));
    Some(pairs)
}

/// A diagonal no path has reached.
const UNREACHED: isize = isize::MIN;

/// Where the furthest path on diagonal `k` starts its run of matches, given
/// the furthest x reached on the diagonals above (`down_from`, one more
/// current event) and below (`right_from`, one more baseline event). Steps
/// that would leave the grid are not taken. Returns the x and whether the
/// step came from above.
fn furthest_step(
    down_from: isize,
    right_from: isize,
    k: isize,
    (n, m): (isize, isize),
) -> Option<(isize, bool)> {
    let down = (down_from != UNREACHED && down_from - k <= m).then_some(down_from);
    let right = (right_from != UNREACHED && right_from < n).then_some(right_from + 1);
    match (down, right) {
        (Some(down), Some(right)) if down >= right => Some((down, true)),
        (_, Some(right)) => Some((right, false)),
        (Some(down), None) => Some((down, true)),
        (None, None) => None,
    }
}

fn middle_subsequence(a: &[u32], b: &[u32]) -> Option<Vec<(usize, usize)>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    if n == 0 || m == 0 {
        return Some(Vec::new());
    }
    let limit = ((n + m) as usize).min(MAX_ALIGNMENT_EDITS) as isize;
    let offset = limit + 1;
    // `furthest[offset + k]` is the furthest x reached on diagonal k = x - y.
    let mut furthest = vec![UNREACHED; 2 * limit as usize + 3];
    // The start: a step down from here lands on (0, 0).
    furthest[(offset + 1) as usize] = 0;
    // What `furthest` held on diagonals -d-1..=d+1 before round d, for the walk back.
    let mut rounds: Vec<Vec<isize>> = Vec::new();
    let mut reached = None;
    'search: for d in 0..=limit {
        rounds.push(furthest[(offset - d - 1) as usize..=(offset + d + 1) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let step = furthest_step(
                furthest[(offset + k + 1) as usize],
                furthest[(offset + k - 1) as usize],
                k,
                (n, m),
            );
            let Some((mut x, _)) = step else {
                furthest[(offset + k) as usize] = UNREACHED;
                k += 2;
                continue;
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            furthest[(offset + k) as usize] = x;
            if x == n && y == m {
                reached = Some(d);
                break 'search;
            }
            k += 2;
        }
    }
    let reached = reached?;
    let mut pairs = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..=reached).rev() {
        let round = &rounds[d as usize];
        // `round[0]` is diagonal -d - 1.
        let at = |k: isize| round[(k + d + 1) as usize];
        let k = x - y;
        let (start_x, down) = furthest_step(at(k + 1), at(k - 1), k, (n, m))?;
        // The run of matches that ended this round's path on diagonal k.
        while x > start_x {
            x -= 1;
            y -= 1;
            pairs.push((x as usize, y as usize));
        }
        // Undo the step that led onto the diagonal.
        if down {
            y -= 1;
        } else {
            x -= 1;
        }
    }
    pairs.reverse();
    Some(pairs)
}

/// Small integers standing for strings, so sequences compare cheaply.
#[derive(Default)]
struct Interner(HashMap<String, u32>);

impl Interner {
    fn id(&mut self, value: String) -> u32 {
        let next = self.0.len() as u32;
        *self.0.entry(value).or_insert(next)
    }
}

/// How one side's units map onto the other's.
enum Slot {
    Pair(usize, usize),
    Baseline(usize),
    Current(usize),
}

/// Align the two unit sequences in order: first the units that are the same
/// in every compared field, then, between those, units with the same
/// semantic key. Returns `None` when the sequences are too different.
fn ordered_alignment(baseline: &[&Unit<'_>], current: &[&Unit<'_>]) -> Option<Vec<Slot>> {
    let mut interner = Interner::default();
    let mut ids = |units: &[&Unit<'_>], exact: bool| -> Vec<u32> {
        units
            .iter()
            .map(|unit| {
                interner.id(if exact {
                    format!("{}\u{0}{}", unit.key, unit.content())
                } else {
                    unit.key.clone()
                })
            })
            .collect()
    };
    let (exact_a, exact_b) = (ids(baseline, true), ids(current, true));
    let (key_a, key_b) = (ids(baseline, false), ids(current, false));
    let mut anchors = common_subsequence(&exact_a, &exact_b)?;
    anchors.push((baseline.len(), current.len()));
    let mut slots = Vec::new();
    let (mut from_a, mut from_b) = (0, 0);
    for (anchor_a, anchor_b) in anchors {
        let pairs = common_subsequence(&key_a[from_a..anchor_a], &key_b[from_b..anchor_b])?;
        let (mut a, mut b) = (from_a, from_b);
        for (pair_a, pair_b) in pairs
            .into_iter()
            .map(|(x, y)| (from_a + x, from_b + y))
            .chain([(anchor_a, anchor_b)])
        {
            slots.extend((a..pair_a).map(Slot::Baseline));
            slots.extend((b..pair_b).map(Slot::Current));
            if pair_a < baseline.len() {
                slots.push(Slot::Pair(pair_a, pair_b));
            }
            (a, b) = (pair_a + 1, pair_b + 1);
        }
        (from_a, from_b) = (anchor_a + 1, anchor_b + 1);
    }
    Some(slots)
}

/// The fallback pairing: the n-th baseline unit of a semantic key with the
/// n-th current one, whatever their order.
fn per_key_alignment(baseline: &[&Unit<'_>], current: &[&Unit<'_>]) -> Vec<Slot> {
    let mut groups: HashMap<&str, VecDeque<usize>> = HashMap::new();
    for (index, unit) in current.iter().enumerate() {
        groups.entry(&unit.key).or_default().push_back(index);
    }
    let mut used = vec![false; current.len()];
    let mut slots = Vec::new();
    for (index, unit) in baseline.iter().enumerate() {
        match groups
            .get_mut(unit.key.as_str())
            .and_then(VecDeque::pop_front)
        {
            Some(paired) => {
                used[paired] = true;
                slots.push(Slot::Pair(index, paired));
            }
            None => slots.push(Slot::Baseline(index)),
        }
    }
    slots.extend(
        (0..current.len())
            .filter(|index| !used[*index])
            .map(Slot::Current),
    );
    slots
}

/// An item under construction, with the units it came from.
struct Aligned {
    baseline: Option<usize>,
    current: Option<usize>,
    moved: bool,
}

/// Pair what an ordered alignment left unpaired on both sides: a baseline
/// unit and a current unit with the same key are one event that moved. Units
/// that are equal in every field are paired first. The moved item takes the
/// current unit's place.
fn pair_moved(slots: Vec<Slot>, baseline: &[Unit<'_>], current: &[Unit<'_>]) -> Vec<Aligned> {
    let exact = |unit: &Unit<'_>| format!("{}\u{0}{}", unit.key, unit.content());
    let mut removed_exact: HashMap<String, VecDeque<usize>> = HashMap::new();
    let mut removed_by_key: HashMap<&str, VecDeque<usize>> = HashMap::new();
    let added: Vec<usize> = slots
        .iter()
        .filter_map(|slot| match slot {
            Slot::Current(index) => Some(*index),
            _ => None,
        })
        .collect();
    if !added.is_empty() {
        for slot in &slots {
            if let Slot::Baseline(index) = slot {
                let unit = &baseline[*index];
                removed_exact
                    .entry(exact(unit))
                    .or_default()
                    .push_back(*index);
                removed_by_key
                    .entry(&unit.key)
                    .or_default()
                    .push_back(*index);
            }
        }
    }
    let mut partner: HashMap<usize, usize> = HashMap::new();
    let mut taken: HashSet<usize> = HashSet::new();
    if !removed_by_key.is_empty() {
        for index in &added {
            if let Some(found) = removed_exact
                .get_mut(&exact(&current[*index]))
                .and_then(VecDeque::pop_front)
            {
                taken.insert(found);
                partner.insert(*index, found);
            }
        }
        for index in &added {
            if partner.contains_key(index) {
                continue;
            }
            let Some(candidates) = removed_by_key.get_mut(current[*index].key.as_str()) else {
                continue;
            };
            while let Some(found) = candidates.pop_front() {
                if taken.insert(found) {
                    partner.insert(*index, found);
                    break;
                }
            }
        }
    }
    slots
        .into_iter()
        .filter_map(|slot| match slot {
            Slot::Pair(baseline, current) => Some(Aligned {
                baseline: Some(baseline),
                current: Some(current),
                moved: false,
            }),
            Slot::Baseline(index) if taken.contains(&index) => None,
            Slot::Baseline(index) => Some(Aligned {
                baseline: Some(index),
                current: None,
                moved: false,
            }),
            Slot::Current(index) => Some(Aligned {
                baseline: partner.get(&index).copied(),
                current: Some(index),
                moved: partner.contains_key(&index),
            }),
        })
        .collect()
}

/// Put each output stream into the aligned events at the place of its first
/// output. Streams are paired by key alone: which of two pipes is read first
/// is a race, not a property of the run.
fn place_streams(aligned: &mut Vec<Aligned>, baseline: &[Unit<'_>], current: &[Unit<'_>]) {
    let streams = |units: &[Unit<'_>]| -> Vec<usize> {
        (0..units.len())
            .filter(|index| units[*index].lines.is_some())
            .collect()
    };
    let (before, after) = (streams(baseline), streams(current));
    let mut items: Vec<Aligned> = Vec::new();
    for index in &after {
        items.push(Aligned {
            baseline: before
                .iter()
                .copied()
                .find(|candidate| baseline[*candidate].key == current[*index].key),
            current: Some(*index),
            moved: false,
        });
    }
    for index in before {
        if !items.iter().any(|item| item.baseline == Some(index)) {
            items.push(Aligned {
                baseline: Some(index),
                current: None,
                moved: false,
            });
        }
    }
    for stream in items {
        let later = |item: &Aligned| match (stream.current, item.current) {
            (Some(stream), Some(item)) => item > stream,
            _ => match (stream.baseline, item.baseline) {
                (Some(stream), Some(item)) => item > stream,
                _ => false,
            },
        };
        let position = aligned.iter().position(later).unwrap_or(aligned.len());
        aligned.insert(position, stream);
    }
}

/// Where an event's causal reference points.
enum Reference<'r> {
    /// The field is empty.
    None,
    /// It names something that is not in the trace.
    Unresolved,
    /// The units it names: one event, or every event of a span or correlation.
    Units(&'r [usize]),
}

/// Lookups for one side's causal references.
struct References<'a> {
    by_event_id: HashMap<&'a str, Vec<usize>>,
    by_span: HashMap<&'a str, Vec<usize>>,
    by_correlation: HashMap<&'a str, Vec<usize>>,
}

impl<'a> References<'a> {
    fn new(units: &[Unit<'a>]) -> Self {
        let mut references = Self {
            by_event_id: HashMap::new(),
            by_span: HashMap::new(),
            by_correlation: HashMap::new(),
        };
        for (index, unit) in units.iter().enumerate() {
            for event_id in &unit.event_ids {
                references
                    .by_event_id
                    .entry(*event_id)
                    .or_insert_with(|| vec![index]);
            }
            if !unit.event.span_id.is_empty() {
                references
                    .by_span
                    .entry(unit.event.span_id.as_str())
                    .or_default()
                    .push(index);
            }
            if !unit.event.correlation_id.is_empty() {
                references
                    .by_correlation
                    .entry(unit.event.correlation_id.as_str())
                    .or_default()
                    .push(index);
            }
        }
        references
    }

    fn resolve<'r>(map: &'r HashMap<&str, Vec<usize>>, id: &str) -> Reference<'r> {
        if id.is_empty() {
            Reference::None
        } else {
            map.get(id)
                .map_or(Reference::Unresolved, |units| Reference::Units(units))
        }
    }
}

/// One side of a pair for [`causal_changes`]: the unit's index, every unit of
/// its trace, that trace's lookups, and the diff item each unit belongs to.
type CausalSide<'s, 'u> = (
    usize,
    &'s [Unit<'u>],
    &'s References<'u>,
    &'s [Option<usize>],
);

/// Compare what the two events of a pair refer to. Ids are generated per
/// run, so a reference is followed to the events it names, and two
/// references agree when they lead to a common item of the diff. A
/// correlation is compared through the other events that share it.
fn causal_changes(
    baseline: CausalSide<'_, '_>,
    current: CausalSide<'_, '_>,
) -> Vec<StructuralChange> {
    fn describe(side: CausalSide<'_, '_>, reference: &Reference<'_>) -> Value {
        match reference {
            Reference::None => Value::Null,
            Reference::Unresolved => json!({"unresolved": true}),
            Reference::Units(units) => units.first().map_or(Value::Null, |index| {
                json!({
                    "key": side.1[*index].key,
                    "sequence": side.1[*index].event.sequence,
                })
            }),
        }
    }
    /// The items a reference leads to, or `None` when there is nothing to follow.
    fn items(side: CausalSide<'_, '_>, reference: &Reference<'_>) -> Option<Vec<usize>> {
        match reference {
            Reference::None => Some(Vec::new()),
            Reference::Unresolved => None,
            Reference::Units(units) => {
                Some(units.iter().filter_map(|unit| side.3[*unit]).collect())
            }
        }
    }
    let mut changes = Vec::new();
    let mut compare = |field: &str, before: Reference<'_>, after: Reference<'_>, group: bool| {
        let (Some(mut before_items), Some(mut after_items)) =
            (items(baseline, &before), items(current, &after))
        else {
            return;
        };
        let stated = (
            !matches!(before, Reference::None),
            !matches!(after, Reference::None),
        );
        if group {
            // A group is known by its other members; an event alone in its
            // group on either side gives nothing to compare.
            before_items.retain(|item| Some(*item) != baseline.3[baseline.0]);
            after_items.retain(|item| Some(*item) != current.3[current.0]);
            if stated == (true, true) && (before_items.is_empty() || after_items.is_empty()) {
                return;
            }
        }
        let same = match stated {
            (false, false) => true,
            (true, true) => before_items.iter().any(|item| after_items.contains(item)),
            _ => false,
        };
        if !same {
            changes.push(StructuralChange {
                field: field.into(),
                before: describe(baseline, &before),
                after: describe(current, &after),
            });
        }
    };
    let (before, after) = (baseline.1[baseline.0].event, current.1[current.0].event);
    compare(
        "parent_event",
        References::resolve(&baseline.2.by_event_id, &before.parent_event_id),
        References::resolve(&current.2.by_event_id, &after.parent_event_id),
        false,
    );
    compare(
        "parent_span",
        References::resolve(&baseline.2.by_span, &before.parent_span_id),
        References::resolve(&current.2.by_span, &after.parent_span_id),
        false,
    );
    compare(
        "correlation",
        References::resolve(&baseline.2.by_correlation, &before.correlation_id),
        References::resolve(&current.2.by_correlation, &after.correlation_id),
        true,
    );
    let links = |side: CausalSide<'_, '_>| {
        let mut linked = Vec::new();
        let mut described = Vec::new();
        for link in &side.1[side.0].event.links {
            let reference = References::resolve(&side.2.by_event_id, link);
            linked.extend(items(side, &reference)?);
            described.push(describe(side, &reference));
        }
        linked.sort_unstable();
        linked.dedup();
        Some((linked, described))
    };
    if let (Some((before_items, before)), Some((after_items, after))) =
        (links(baseline), links(current))
        && before_items != after_items
    {
        changes.push(StructuralChange {
            field: "links".into(),
            before: Value::Array(before),
            after: Value::Array(after),
        });
    }
    changes
}

/// Manifest fields that describe what was run and how it ended.
const COMPARED_MANIFEST_FIELDS: [&str; 5] = [
    "command",
    "exit_code",
    "termination",
    "adapter",
    "capabilities",
];

/// Differences between two manifests (as JSON) in the fields that describe
/// the run: its command, exit code, termination, adapter and capabilities.
pub fn diff_manifests(baseline: &Value, current: &Value) -> Vec<StructuralChange> {
    let flattened = |manifest: &Value| {
        let mut fields = BTreeMap::new();
        for field in COMPARED_MANIFEST_FIELDS {
            match manifest.get(field) {
                None | Some(Value::Null) => {}
                // Lists are compared whole.
                Some(value @ Value::Array(_)) => {
                    fields.insert(field.to_owned(), value.clone());
                }
                Some(value) => flatten(field, value, &mut fields),
            }
        }
        fields
    };
    let (before, after) = (flattened(baseline), flattened(current));
    before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|field| {
            let before = before.get(field).cloned().unwrap_or(Value::Null);
            let after = after.get(field).cloned().unwrap_or(Value::Null);
            (before != after).then(|| StructuralChange {
                field: field.clone(),
                before,
                after,
            })
        })
        .collect()
}

pub fn diff_events(baseline: &[TraceEvent], current: &[TraceEvent]) -> TraceDiff {
    diff_traces(&Value::Null, baseline, &Value::Null, current)
}

/// Compare two traces: their events in order, and the manifest fields that
/// describe the run. See `docs/cli.md` for what is and is not compared.
pub fn diff_traces(
    baseline_manifest: &Value,
    baseline: &[TraceEvent],
    current_manifest: &Value,
    current: &[TraceEvent],
) -> TraceDiff {
    let baseline = diff_units(baseline);
    let current = diff_units(current);
    // Captured output is compared per stream and takes no part in the order.
    let events = |units: &[Unit<'_>]| -> Vec<usize> {
        (0..units.len())
            .filter(|index| units[*index].lines.is_none())
            .collect()
    };
    let (baseline_events, current_events) = (events(&baseline), events(&current));
    let before: Vec<&Unit<'_>> = baseline_events
        .iter()
        .map(|index| &baseline[*index])
        .collect();
    let after: Vec<&Unit<'_>> = current_events
        .iter()
        .map(|index| &current[*index])
        .collect();
    let (slots, alignment) = match ordered_alignment(&before, &after) {
        Some(slots) => (slots, "ordered"),
        None => (per_key_alignment(&before, &after), "per_key"),
    };
    let slots = slots
        .into_iter()
        .map(|slot| match slot {
            Slot::Pair(before, after) => Slot::Pair(baseline_events[before], current_events[after]),
            Slot::Baseline(index) => Slot::Baseline(baseline_events[index]),
            Slot::Current(index) => Slot::Current(current_events[index]),
        })
        .collect();
    let mut aligned = pair_moved(slots, &baseline, &current);
    place_streams(&mut aligned, &baseline, &current);
    let mut baseline_items = vec![None; baseline.len()];
    let mut current_items = vec![None; current.len()];
    for (index, item) in aligned.iter().enumerate() {
        if let Some(unit) = item.baseline {
            baseline_items[unit] = Some(index);
        }
        if let Some(unit) = item.current {
            current_items[unit] = Some(index);
        }
    }
    let baseline_references = References::new(&baseline);
    let current_references = References::new(&current);
    let mut occurrences: HashMap<&str, usize> = HashMap::new();
    let mut counts = DiffCounts::default();
    let mut items = Vec::with_capacity(aligned.len());
    for item in &aligned {
        let unit = item
            .current
            .map(|index| &current[index])
            .or(item.baseline.map(|index| &baseline[index]))
            .expect("an aligned item has a unit");
        let occurrence = occurrences.entry(&unit.key).or_default();
        *occurrence += 1;
        let key = format!("{}#{occurrence}", unit.key);
        let (status, changes) = match (item.baseline, item.current) {
            (Some(before_index), Some(after_index)) => {
                let (before, after) = (&baseline[before_index], &current[after_index]);
                let mut changes = compare_units(before, after);
                if before.lines.is_none() {
                    changes.extend(causal_changes(
                        (
                            before_index,
                            &baseline,
                            &baseline_references,
                            &baseline_items,
                        ),
                        (after_index, &current, &current_references, &current_items),
                    ));
                }
                let status = if item.moved {
                    DiffStatus::Moved
                } else if changes.is_empty() {
                    DiffStatus::Unchanged
                } else {
                    DiffStatus::Changed
                };
                (status, changes)
            }
            (Some(_), None) => (DiffStatus::Removed, Vec::new()),
            _ => (DiffStatus::Added, Vec::new()),
        };
        match status {
            DiffStatus::Added => counts.added += 1,
            DiffStatus::Removed => counts.removed += 1,
            DiffStatus::Changed => counts.changed += 1,
            DiffStatus::Moved => counts.moved += 1,
            DiffStatus::Unchanged => counts.unchanged += 1,
        }
        items.push(DiffItem {
            key,
            status,
            baseline_sequence: item.baseline.map(|index| baseline[index].event.sequence),
            current_sequence: item.current.map(|index| current[index].event.sequence),
            changes,
        });
    }
    let first_divergence = items
        .iter()
        .enumerate()
        .find(|(_, item)| item.status != DiffStatus::Unchanged)
        .map(|(index, item)| FirstDivergence {
            index,
            key: item.key.clone(),
            status: item.status,
            baseline_sequence: item.baseline_sequence,
            current_sequence: item.current_sequence,
            change: item.changes.first().cloned(),
        });
    let manifest = diff_manifests(baseline_manifest, current_manifest);
    TraceDiff {
        format: "premier.semantic-diff.v2",
        identical: first_divergence.is_none() && manifest.is_empty(),
        alignment,
        counts,
        first_divergence,
        manifest,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, payload: Value) -> TraceEvent {
        TraceEvent {
            event_id: "generated".into(),
            trace_id: "trace".into(),
            sequence: 1,
            timestamp: "now".into(),
            kind: kind.into(),
            source: "sdk".into(),
            payload_json: payload.to_string(),
            actor_id: "agent".into(),
            actor_type: "agent".into(),
            parent_event_id: String::new(),
            span_id: "span".into(),
            parent_span_id: String::new(),
            correlation_id: "correlation".into(),
            status: "ok".into(),
            duration_ms: 0,
            links: Vec::new(),
            prev_hash: String::new(),
        }
    }

    #[test]
    fn redacts_secret_fields_at_any_depth_and_preserves_safe_values() {
        let mut value = json!({
            "safe": "visible",
            "headers": {"Authorization": "bearer"},
            "items": [{"api-key": "secret", "github_token": "token", "aws_secret_access_key": "key"}]
        });
        redact_secrets(&mut value);
        assert_eq!(value["safe"], "visible");
        assert_eq!(value["headers"]["Authorization"], REDACTED);
        assert_eq!(value["items"][0]["api-key"], REDACTED);
        assert_eq!(value["items"][0]["github_token"], REDACTED);
        assert_eq!(value["items"][0]["aws_secret_access_key"], REDACTED);
    }

    #[test]
    fn redacts_secret_fields_inside_stringified_json_values() {
        let mut value = json!({
            "arguments": "{\"api_key\":\"sk-JSON-IN-STRING\",\"region\":\"eu\"}",
            "body": "[{\"password\":\"nested-pw\"}]",
            "double": "{\"inner\":\"{\\\"token\\\":\\\"deep-token\\\"}\"}",
            "plain": "{\"region\": \"eu\"}",
            "prose": "not json {token}"
        });
        redact_secrets(&mut value);
        let text = value.to_string();
        for secret in ["sk-JSON-IN-STRING", "nested-pw", "deep-token"] {
            assert!(!text.contains(secret), "{secret} survived: {text}");
        }
        let arguments: Value = serde_json::from_str(value["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(arguments, json!({"api_key": REDACTED, "region": "eu"}));
        assert_eq!(value["plain"], "{\"region\": \"eu\"}");
        assert_eq!(value["prose"], "not json {token}");
    }

    #[test]
    fn redacts_header_style_arrays_and_argument_lists() {
        let mut value = json!({
            "headers": [
                {"name": "Authorization", "value": "Bearer pair-secret"},
                {"name": "Accept", "value": "application/json"},
                {"key": "X-Api-Key", "value": "key-secret"}
            ],
            "raw_headers": [["Cookie", "session=cookie-secret"], ["Accept", "text/html"]],
            "lines": ["Authorization: Bearer line-secret", "Accept: */*"],
            "env": ["OPENAI_API_KEY=env-secret", "HOME=/home/agent"],
            "command": ["deploy", "--token", "argv-secret", "--password=flag-secret", "--max-tokens", "64"],
            "usage": {"input_tokens": 1200, "output_tokens": 400}
        });
        redact_secrets(&mut value);
        let text = value.to_string();
        for secret in [
            "pair-secret",
            "key-secret",
            "cookie-secret",
            "line-secret",
            "env-secret",
            "argv-secret",
            "flag-secret",
        ] {
            assert!(!text.contains(secret), "{secret} survived: {text}");
        }
        assert_eq!(value["headers"][0]["name"], "Authorization");
        assert_eq!(value["headers"][1]["value"], "application/json");
        assert_eq!(value["raw_headers"][1], json!(["Accept", "text/html"]));
        assert_eq!(
            value["lines"],
            json!(["Authorization: [REDACTED]", "Accept: */*"])
        );
        assert_eq!(value["env"][1], "HOME=/home/agent");
        assert_eq!(
            value["command"],
            json!([
                "deploy",
                "--token",
                REDACTED,
                "--password=[REDACTED]",
                "--max-tokens",
                "64"
            ])
        );
        assert_eq!(
            value["usage"],
            json!({"input_tokens": 1200, "output_tokens": 400})
        );
    }

    #[test]
    fn redaction_counts_separate_rule_types_and_recorded_markers() {
        let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let mut value = json!({
            "password": "pw",
            "api_key": REDACTED,
            "empty_token": null,
            "note": format!("used {token} and https://u:pw9@host.test/x"),
            "stored": "earlier [REDACTED] value",
            "command": ["deploy", "--token", "argv-secret", "--password=[REDACTED]"],
            "arguments": format!("{{\"secret\":\"s\",\"text\":\"{token}\"}}"),
            "usage": {"input_tokens": 1200, "output_tokens": 400},
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "commit": "7ebad3a1c0ffee00deadbeef0123456789abcdef"
        });
        let counts = redact_secrets(&mut value);
        assert!(!value.to_string().contains(&token));
        assert_eq!(
            counts.field_names, 3,
            "password, --token value, nested secret"
        );
        assert_eq!(counts.value_patterns["github-token"], 2);
        assert_eq!(counts.value_patterns["url-credentials"], 1);
        assert_eq!(counts.total, 6);
        assert_eq!(counts.already_redacted, 3, "api_key, stored, --password");
        assert_eq!(value["usage"]["input_tokens"], 1200);
        assert_eq!(value["id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(value["commit"], "7ebad3a1c0ffee00deadbeef0123456789abcdef");

        // A second pass finds nothing left to do.
        let again = redact_secrets(&mut value);
        assert_eq!(again.total, 0);
        assert!(again.value_patterns.is_empty());

        let mut untouched = json!({"note": format!("used {token}"), "password": "pw"});
        let counts = redact_secrets_with(&mut untouched, false);
        assert_eq!(untouched["note"], format!("used {token}"));
        assert_eq!((counts.total, counts.field_names), (1, 1));
    }

    #[test]
    fn portable_evidence_only_pattern_matches_terminal_text_on_request() {
        let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("export.atrace");
        let writer = premier_trace::TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer.finish(0).unwrap();
        let manifest = premier_trace::read_manifest(&root).unwrap();
        let events = [
            event("tool.result", json!({"note": format!("used {token}")})),
            event("process.stdout", json!({"text": format!("echo {token}\n")})),
        ];

        let export = portable_evidence(&manifest, &events);
        assert_eq!(export.events[0]["payload"]["note"], "used [REDACTED]");
        assert_eq!(
            export.events[1]["payload"]["text"],
            format!("echo {token}\n")
        );
        assert!(export.redaction.applied);
        assert_eq!(export.redaction.redacted.total, 1);
        assert!(!export.redaction.rules.builtin_patterns_terminal);

        let options = RedactionOptions {
            known_secrets_in_terminal: true,
            ..RedactionOptions::default()
        };
        let export = portable_evidence_with(&manifest, &events, options);
        assert_eq!(export.events[1]["payload"]["text"], "echo [REDACTED]\n");
        assert_eq!(export.redaction.redacted.value_patterns["github-token"], 2);

        let export = portable_evidence_with(
            &manifest,
            &events,
            RedactionOptions {
                default_secret_patterns: false,
                known_secrets_in_terminal: false,
            },
        );
        assert!(!export.redaction.applied);
        assert!(export.redaction.rules.builtin_patterns.is_empty());
        assert_eq!(export.events[0]["payload"]["note"], format!("used {token}"));
    }

    #[test]
    fn semantic_diff_ignores_generated_payload_fields() {
        let baseline = event(
            "model.response",
            json!({"result": "same", "event_id": "a", "timestamp": "one"}),
        );
        let current = event(
            "model.response",
            json!({"result": "same", "event_id": "b", "timestamp": "two"}),
        );
        let diff = diff_events(&[baseline], &[current]);
        assert_eq!(diff.counts.unchanged, 1);
        assert_eq!(diff.counts.changed, 0);
    }

    #[test]
    fn adapter_events_key_on_the_tool_and_ignore_provider_generated_ids() {
        let adapter = |tool: &str, id: &str, actor: &str| TraceEvent {
            source: "adapter.claude.v1".into(),
            actor_id: actor.into(),
            ..event(
                "tool.result",
                json!({"provider": "claude", "tool": tool, "id": "kept", "native": {
                    "uuid": id, "session_id": id,
                    "message": {"id": id, "content": [{"type": "tool_result", "tool_use_id": id}]}
                }}),
            )
        };
        let read = adapter("Read", "run-a", "claude:subagent:toolu_a");
        assert_eq!(
            semantic_event_key(&read),
            "tool.result:claude:subagent:read"
        );
        let baseline = [adapter("Grep", "run-a", "claude"), read];
        let current = [
            adapter("Read", "run-b", "claude:subagent:toolu_b"),
            adapter("Grep", "run-b", "claude"),
        ];
        let diff = diff_events(&baseline, &current);
        // Same content in a different order: one of the two is reported as moved.
        assert_eq!(
            (diff.counts.unchanged, diff.counts.moved),
            (1, 1),
            "{:?}",
            diff.items
        );
        assert!(diff.items.iter().all(|item| item.changes.is_empty()));

        // Outside `native`, a caller's own `id` field is still compared.
        let mut changed = adapter("Grep", "run-b", "claude");
        changed.payload_json = changed.payload_json.replace("kept", "edited");
        let diff = diff_events(&baseline[..1], &[changed]);
        assert_eq!(diff.counts.changed, 1);
    }
    /// An event of the shared diff fixture, with its unstated fields defaulted.
    fn fixture_event(side: &str, fields: &Value) -> TraceEvent {
        let text = |name: &str, default: &str| {
            fields
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or(default)
                .to_owned()
        };
        let sequence = fields["sequence"].as_u64().unwrap();
        TraceEvent {
            event_id: text("event_id", &format!("{side}-{sequence}")),
            trace_id: side.into(),
            sequence,
            timestamp: "2026-07-15T12:00:00Z".into(),
            kind: text("kind", ""),
            source: text("source", "sdk"),
            payload_json: fields.get("payload").unwrap_or(&json!({})).to_string(),
            actor_id: text("actor_id", "agent"),
            actor_type: text("actor_type", "agent"),
            parent_event_id: text("parent_event_id", ""),
            span_id: text("span_id", ""),
            parent_span_id: text("parent_span_id", ""),
            correlation_id: text("correlation_id", ""),
            status: text("status", "ok"),
            duration_ms: fields
                .get("duration_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            links: fields
                .get("links")
                .and_then(Value::as_array)
                .map(|links| {
                    links
                        .iter()
                        .filter_map(|link| link.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            prev_hash: String::new(),
        }
    }

    /// The viewer runs the same cases (`semanticCompare.test.ts`), so the
    /// two comparisons cannot drift apart unnoticed.
    #[test]
    fn diff_reproduces_the_cases_shared_with_the_viewer() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/diff/semantic-diff-cases.json"
        ))
        .unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() >= 7);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let side = |side: &str| -> Vec<TraceEvent> {
                case[side]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|event| fixture_event(side, event))
                    .collect()
            };
            let diff = diff_events(&side("baseline"), &side("current"));
            let items: Vec<Value> = diff
                .items
                .iter()
                .map(|item| {
                    json!({
                        "key": item.key,
                        "status": item.status,
                        "baseline_sequence": item.baseline_sequence,
                        "current_sequence": item.current_sequence,
                        "fields": item.changes.iter().map(|change| &change.field).collect::<Vec<_>>(),
                    })
                })
                .collect();
            let expected = &case["expected"];
            assert_eq!(json!(items), expected["items"], "{name}");
            assert_eq!(
                serde_json::to_value(&diff.counts).unwrap(),
                expected["counts"],
                "{name}"
            );
            let first = diff.first_divergence.as_ref().map(
                |first| json!({"index": first.index, "key": first.key, "status": first.status}),
            );
            assert_eq!(json!(first), expected["first_divergence"], "{name}");
            assert_eq!(diff.identical, first.is_none(), "{name}");
            assert_eq!(diff.alignment, "ordered", "{name}");
        }
    }

    #[test]
    fn tool_events_without_a_tool_field_are_keyed_by_the_native_tool() {
        let keyed = |native: Value| {
            semantic_event_key(&TraceEvent {
                source: "adapter.gemini.v1".into(),
                ..event(
                    "tool.result",
                    json!({"provider": "gemini", "native": native}),
                )
            })
        };
        assert_eq!(
            keyed(json!({"type": "tool_result", "name": " read_file "})),
            "tool.result:agent:read_file"
        );
        assert_eq!(
            keyed(json!({"item": {"type": "command_execution", "command": "cargo test"}})),
            "tool.result:agent:cargo test"
        );
        assert_eq!(
            keyed(
                json!({"message": {"content": [{"type": "text"}, {"type": "tool_use", "name": "Read"}]}})
            ),
            "tool.result:agent:read"
        );
        assert_eq!(
            keyed(json!({"tool_calls": [{"function": {"name": "search"}}]})),
            "tool.result:agent:search"
        );
        assert_eq!(keyed(json!({"type": "note"})), "tool.result:agent");
    }

    #[test]
    fn a_stream_change_names_the_first_differing_line_and_the_line_counts() {
        let stdout = |sequence: u64, text: &str| TraceEvent {
            sequence,
            actor_id: "root".into(),
            ..event("process.stdout", json!({"text": text}))
        };
        let diff = diff_events(
            &[stdout(1, "a\nb\n")],
            &[stdout(1, "a\n"), stdout(2, "b\nc\n")],
        );
        let changes: Vec<_> = diff.items[0]
            .changes
            .iter()
            .map(|change| (change.field.as_str(), &change.before, &change.after))
            .collect();
        assert_eq!(
            changes,
            [
                ("text.lines", &json!(2), &json!(3)),
                ("text.line[3]", &Value::Null, &json!("c")),
            ]
        );
        let first = diff.first_divergence.unwrap();
        assert_eq!(first.change.unwrap().field, "text.lines");
        assert!(!diff.identical);
    }

    #[test]
    fn which_pipe_was_read_first_is_not_a_difference() {
        let output = |sequence: u64, kind: &str, text: &str| TraceEvent {
            sequence,
            actor_id: "root".into(),
            ..event(kind, json!({"text": text}))
        };
        let diff = diff_events(
            &[
                output(1, "process.stdout", "out\n"),
                output(2, "process.stderr", "err\n"),
            ],
            &[
                output(1, "process.stderr", "err\n"),
                output(2, "process.stdout", "out\n"),
            ],
        );
        assert!(diff.identical, "{:?}", diff.items);
        assert_eq!(diff.counts.unchanged, 2);
    }

    #[test]
    fn manifest_outcome_fields_are_compared() {
        let changes = diff_manifests(
            &json!({"command": ["a", "b"], "exit_code": 0, "name": "one",
                    "termination": {"kind": "exit", "exit_code": 0}}),
            &json!({"command": ["a", "b"], "exit_code": 1, "name": "two",
                    "termination": {"kind": "signal", "signal": 9},
                    "adapter": {"provider": "claude"}}),
        );
        let fields: Vec<_> = changes.iter().map(|change| change.field.as_str()).collect();
        assert_eq!(
            fields,
            [
                "adapter.provider",
                "exit_code",
                "termination.exit_code",
                "termination.kind",
                "termination.signal",
            ]
        );
        let diff = diff_traces(&json!({"exit_code": 0}), &[], &json!({"exit_code": 2}), &[]);
        assert!(!diff.identical);
        assert!(diff.first_divergence.is_none());
        assert_eq!(diff.manifest[0].after, json!(2));
    }

    #[test]
    fn traces_too_different_to_align_fall_back_to_pairing_per_key() {
        let numbered = |prefix: &str| -> Vec<TraceEvent> {
            (0..(MAX_ALIGNMENT_EDITS as u64 / 2 + 50))
                .map(|index| TraceEvent {
                    sequence: index + 1,
                    ..event(
                        "tool.execution",
                        json!({"tool": format!("{prefix}{index}")}),
                    )
                })
                .collect()
        };
        let diff = diff_events(&numbered("a"), &numbered("b"));
        assert_eq!(diff.alignment, "per_key");
        assert_eq!(diff.counts.removed, diff.counts.added);
        assert_eq!(diff.counts.unchanged + diff.counts.changed, 0);
    }

    /// Longest common subsequence length by the textbook table.
    fn reference_lcs(a: &[u32], b: &[u32]) -> usize {
        let mut table = vec![vec![0_usize; b.len() + 1]; a.len() + 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                table[i + 1][j + 1] = if x == y {
                    table[i][j] + 1
                } else {
                    table[i][j + 1].max(table[i + 1][j])
                };
            }
        }
        table[a.len()][b.len()]
    }

    proptest::proptest! {
        #[test]
        fn common_subsequence_is_a_longest_one_and_stays_in_order(
            a in proptest::collection::vec(0_u32..4, 0..40),
            b in proptest::collection::vec(0_u32..4, 0..40),
        ) {
            let pairs = common_subsequence(&a, &b).unwrap();
            proptest::prop_assert_eq!(pairs.len(), reference_lcs(&a, &b));
            for (x, y) in &pairs {
                proptest::prop_assert_eq!(a[*x], b[*y]);
            }
            for pair in pairs.windows(2) {
                proptest::prop_assert!(pair[0].0 < pair[1].0 && pair[0].1 < pair[1].1);
            }
        }
    }

    fn sealed_manifest(name: &str) -> (tempfile::TempDir, TraceManifest) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join(name);
        let writer = premier_trace::TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer.finish(0).unwrap();
        let manifest = premier_trace::read_manifest(&root).unwrap();
        (temp, manifest)
    }

    fn export_bytes(
        manifest: &TraceManifest,
        events: &[TraceEvent],
        options: &ExportOptions,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_portable_evidence_with(
            &mut bytes,
            manifest,
            events.iter().cloned().map(Ok),
            options,
        )
        .unwrap();
        bytes
    }

    #[test]
    fn an_export_carries_a_digest_that_verifies_and_detects_edits() {
        let (_temp, manifest) = sealed_manifest("digest.atrace");
        let events = [
            TraceEvent {
                sequence: 1,
                ..event(
                    "tool.result",
                    json!({"note": "kept", "ratio": 0.1, "big": 1e300, "tiny": 4.35}),
                )
            },
            TraceEvent {
                sequence: 2,
                payload_json: "not json {".into(),
                ..event("custom.raw", json!({}))
            },
        ];
        let options = ExportOptions {
            source_state: SourceState::Verified,
            ..ExportOptions::default()
        };
        let bytes = export_bytes(&manifest, &events, &options);
        let export = ExportDocument::parse(&bytes).unwrap();
        let verified = export.verify().unwrap();
        assert_eq!(verified.event_count, 2);
        assert_eq!(verified.digest.len(), 64);
        assert_eq!(verified.source_trace_id, manifest.trace_id);
        assert_eq!(verified.source_verification, "verified");
        assert_eq!(export.document["source"]["finalized"], true);
        assert_eq!(export.document["exporter"]["name"], "premier");
        assert_eq!(export.document["integrity"]["digest"], verified.digest);
        // An unparseable payload is exported as recorded, and read back as such.
        assert_eq!(export.document["events"][1]["payload"], Value::Null);
        assert_eq!(export.document["events"][1]["payload_raw"], "not json {");
        assert_eq!(export.events[1].payload_json, "not json {");
        assert_eq!(export.events[0].payload()["note"], "kept");
        // The same input always gives the same export.
        assert_eq!(bytes, export_bytes(&manifest, &events, &options));

        let text = String::from_utf8(bytes).unwrap();
        let edited_event = text.replace("\"kept\"", "\"edited\"");
        let error = ExportDocument::parse(edited_event.as_bytes())
            .unwrap()
            .verify()
            .unwrap_err();
        assert!(
            error.to_string().contains("events digest mismatch"),
            "{error}"
        );

        let edited_source =
            text.replace(&manifest.trace_id, "00000000-0000-7000-8000-000000000000");
        let error = ExportDocument::parse(edited_source.as_bytes())
            .unwrap()
            .verify()
            .unwrap_err();
        assert!(
            error.to_string().contains("export digest mismatch"),
            "{error}"
        );

        let mut dropped: Value = serde_json::from_str(&text).unwrap();
        dropped["events"].as_array_mut().unwrap().pop();
        let error = ExportDocument::parse(&serde_json::to_vec(&dropped).unwrap())
            .unwrap()
            .verify()
            .unwrap_err();
        assert!(
            error.to_string().contains("event count mismatch"),
            "{error}"
        );

        let mut stripped: Value = serde_json::from_str(&text).unwrap();
        stripped.as_object_mut().unwrap().remove("integrity");
        let error = ExportDocument::parse(&serde_json::to_vec(&stripped).unwrap())
            .unwrap()
            .verify()
            .unwrap_err();
        assert!(
            error.to_string().contains("no `integrity` block"),
            "{error}"
        );
        assert!(ExportDocument::parse(b"{\"format\": \"other\"}").is_err());
    }

    #[test]
    fn an_export_records_the_selection_and_rules_it_applied() {
        let (_temp, manifest) = sealed_manifest("selection.atrace");
        let events: Vec<TraceEvent> = (1..=6)
            .map(|sequence| TraceEvent {
                sequence,
                actor_id: if sequence % 2 == 0 { "coder" } else { "reviewer" }.into(),
                ..event(
                    if sequence <= 4 { "tool.result" } else { "agent.message" },
                    json!({"note": "the build id is build-7781", "ticket": "T-1", "inner": {"Ticket": "T-2"}}),
                )
            })
            .collect();
        let options = ExportOptions {
            selection: ExportSelection {
                kind: vec!["TOOL.RESULT".into()],
                actor: vec!["coder".into()],
                after_sequence: Some(2),
                before_sequence: Some(6),
            },
            redact_fields: vec!["ticket".into()],
            redact_literals: vec!["build-7781".into()],
            ..ExportOptions::default()
        };
        let bytes = export_bytes(&manifest, &events, &options);
        let export = ExportDocument::parse(&bytes).unwrap();
        export.verify().unwrap();
        let document = &export.document;
        assert_eq!(export.events.len(), 1);
        assert_eq!(export.events[0].sequence, 4);
        assert_eq!(document["selection"]["applied"], true);
        assert_eq!(document["selection"]["source_events"], 6);
        assert_eq!(document["selection"]["exported_events"], 1);
        assert_eq!(
            document["selection"]["filters"],
            json!({"kind": ["TOOL.RESULT"], "actor": ["coder"], "after_sequence": 2, "before_sequence": 6})
        );
        let payload = &document["events"][0]["payload"];
        assert_eq!(payload["note"], "the build id is [REDACTED]");
        assert_eq!(payload["ticket"], REDACTED);
        assert_eq!(payload["inner"]["Ticket"], REDACTED);
        assert_eq!(document["redaction"]["applied"], true);
        assert_eq!(
            document["redaction"]["custom"],
            json!({"fields": 2, "literals": 1})
        );
        assert_eq!(
            document["redaction"]["rules"]["custom_fields"],
            json!(["ticket"])
        );
        assert_eq!(document["redaction"]["rules"]["literal_count"], 1);
        assert!(!String::from_utf8(bytes).unwrap().contains("build-7781"));

        // Without a selection or rules the blocks say so.
        let plain = export_bytes(&manifest, &events, &ExportOptions::default());
        let plain = ExportDocument::parse(&plain).unwrap();
        assert_eq!(plain.document["selection"]["applied"], false);
        assert_eq!(plain.document["selection"]["filters"], json!({}));
        assert_eq!(plain.document["source"]["verification"], "not_checked");
        assert!(plain.document["redaction"].get("custom").is_none());
        assert_eq!(plain.events.len(), 6);
    }

    #[test]
    fn an_export_verifies_the_copied_source_signature() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("signed.atrace");
        let key = premier_trace::SigningKey::generate();
        let mut writer = premier_trace::TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer.set_signing_key(premier_trace::SigningKey::from_hex(&key.to_hex()).unwrap());
        writer.finish(0).unwrap();
        let manifest = premier_trace::read_manifest(&root).unwrap();
        let bytes = export_bytes(&manifest, &[], &ExportOptions::default());
        let verified = ExportDocument::parse(&bytes).unwrap().verify().unwrap();
        assert_eq!(verified.source_protection, "signed");
        assert_eq!(verified.source_signer, Some(key.public_key()));

        // A signature that does not belong to the seal is caught even when
        // the export's own digest was recomputed to match.
        let mut forged: Value = serde_json::from_slice(&bytes).unwrap();
        forged["source"]["seal"] = json!("0".repeat(64));
        let error = ExportDocument::parse(&serde_json::to_vec(&forged).unwrap())
            .unwrap()
            .verify()
            .unwrap_err();
        assert!(error.to_string().contains("digest mismatch"), "{error}");
    }

    fn numbered_events() -> Vec<TraceEvent> {
        (1..=5)
            .map(|sequence| TraceEvent {
                sequence,
                event_id: format!("event-{sequence}"),
                span_id: format!("span-{sequence}"),
                parent_span_id: if sequence > 1 {
                    "span-1".into()
                } else {
                    String::new()
                },
                parent_event_id: if sequence == 3 {
                    "event-2".into()
                } else {
                    String::new()
                },
                correlation_id: if sequence >= 4 {
                    "call-9".into()
                } else {
                    String::new()
                },
                timestamp: format!("2026-07-15T12:00:0{sequence}Z"),
                status: if sequence == 5 {
                    "error".into()
                } else {
                    "ok".into()
                },
                ..event("tool.result", json!({"n": sequence}))
            })
            .collect()
    }

    #[test]
    fn query_reports_truncation_and_where_the_next_page_starts() {
        let events = numbered_events();
        let all = query_events(&events, &QueryOptions::default());
        assert_eq!((all.matched, all.returned, all.truncated), (5, 5, false));
        assert_eq!(all.next_after_sequence, None);

        let options = QueryOptions {
            limit: 2,
            ..QueryOptions::default()
        };
        let first = query_events(&events, &options);
        assert_eq!(
            (first.matched, first.returned, first.truncated),
            (5, 2, true)
        );
        assert_eq!(first.next_after_sequence, Some(2));
        let second = query_events(
            &events,
            &QueryOptions {
                after_sequence: first.next_after_sequence,
                ..options.clone()
            },
        );
        let sequences: Vec<_> = second.events.iter().map(|event| event.sequence).collect();
        assert_eq!(sequences, [3, 4]);
        let last = query_events(
            &events,
            &QueryOptions {
                after_sequence: second.next_after_sequence,
                ..options
            },
        );
        assert_eq!((last.returned, last.truncated), (1, false));
        assert!(MAX_QUERY_LIMIT >= QueryOptions::default().limit);
    }

    #[test]
    fn query_follows_causality_ids_sequences_times_and_issues() {
        let events = numbered_events();
        let sequences = |options: QueryOptions| -> Vec<u64> {
            query_events(&events, &options)
                .events
                .iter()
                .map(|event| event.sequence)
                .collect()
        };
        let with = QueryOptions::default;
        assert_eq!(
            sequences(QueryOptions {
                event_id: Some("event-2".into()),
                ..with()
            }),
            [2]
        );
        // Ids are exact: neither a prefix nor another case matches.
        assert!(
            sequences(QueryOptions {
                event_id: Some("EVENT-2".into()),
                ..with()
            })
            .is_empty()
        );
        assert_eq!(
            sequences(QueryOptions {
                span: Some("span-4".into()),
                ..with()
            }),
            [4]
        );
        assert_eq!(
            sequences(QueryOptions {
                parent_span: Some("span-1".into()),
                ..with()
            }),
            [2, 3, 4, 5]
        );
        assert_eq!(
            sequences(QueryOptions {
                parent: Some("event-2".into()),
                ..with()
            }),
            [3]
        );
        assert_eq!(
            sequences(QueryOptions {
                correlation: Some("call-9".into()),
                ..with()
            }),
            [4, 5]
        );
        assert_eq!(
            sequences(QueryOptions {
                before_sequence: Some(3),
                ..with()
            }),
            [1, 2]
        );
        assert_eq!(
            sequences(QueryOptions {
                issues: true,
                ..with()
            }),
            [5]
        );
        let at = |text: &str| {
            Some(
                chrono::DateTime::parse_from_rfc3339(text)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
        };
        assert_eq!(
            sequences(QueryOptions {
                since: at("2026-07-15T12:00:02Z"),
                until: at("2026-07-15T14:00:04+02:00"),
                ..with()
            }),
            [2, 3]
        );
        // Ids can be searched for as well as filtered on.
        assert_eq!(
            sequences(QueryOptions {
                search: Some("call-9".into()),
                ..with()
            }),
            [4, 5]
        );
    }

    #[test]
    fn search_matches_recorded_text_as_typed() {
        let events = [
            event(
                "process.stdout",
                json!({"text": "say \"hello\"\nnext line\n"}),
            ),
            event(
                "process.stdout",
                json!({"text": "\u{1b}[31mbuild failed\u{1b}[0m at step 2"}),
            ),
            event("tool.result", json!({"path": "C:\\temp\\out.txt"})),
        ];
        let matched = |query: &str| {
            query_events(
                &events,
                &QueryOptions {
                    search: Some(query.into()),
                    ..QueryOptions::default()
                },
            )
            .matched
        };
        assert_eq!(matched("say \"hello\""), 1);
        assert_eq!(matched("hello\"\nnext"), 1);
        assert_eq!(matched("build failed at step"), 1);
        assert_eq!(matched("c:\\temp\\out"), 1);
        // Key names and the JSON text still match, as before.
        assert_eq!(matched("\"text\""), 2);
        assert_eq!(matched("no such text"), 0);
    }
}
