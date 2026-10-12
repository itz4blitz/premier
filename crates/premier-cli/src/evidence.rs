use premier_trace::{TraceEvent, TraceManifest};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, VecDeque};

pub const MAX_QUERY_LIMIT: usize = 1_000;
pub const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Debug)]
pub struct QueryOptions {
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            kind: None,
            actor: None,
            status: None,
            search: None,
            limit: 100,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub matched: usize,
    pub returned: usize,
    pub truncated: bool,
    pub events: Vec<TraceEvent>,
}

fn exact_filter(expected: &Option<String>, actual: &str) -> bool {
    expected
        .as_deref()
        .is_none_or(|expected| expected.eq_ignore_ascii_case(actual))
}

pub fn query_events(events: &[TraceEvent], options: &QueryOptions) -> QueryResult {
    let query = options
        .search
        .as_deref()
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(str::to_lowercase);
    let filtered = events.iter().filter(|event| {
        exact_filter(&options.kind, &event.kind)
            && exact_filter(&options.actor, &event.actor_id)
            && exact_filter(&options.status, &event.status)
            && query.as_ref().is_none_or(|query| {
                [
                    event.kind.as_str(),
                    event.source.as_str(),
                    event.actor_id.as_str(),
                    event.actor_type.as_str(),
                    event.status.as_str(),
                    event.payload_json.as_str(),
                ]
                .join(" ")
                .to_lowercase()
                .contains(query)
            })
    });
    let mut matched = 0;
    let mut returned = Vec::with_capacity(options.limit.min(events.len()));
    for event in filtered {
        matched += 1;
        if returned.len() < options.limit {
            returned.push(event.clone());
        }
    }
    QueryResult {
        matched,
        returned: returned.len(),
        truncated: matched > returned.len(),
        events: returned,
    }
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Export shares the recorder's secret field list instead of keeping its own.
fn secret_key(key: &str) -> bool {
    premier_trace::is_secret_field_name(key)
}

/// Recursively replace the values of secret-named fields. Besides plain
/// object keys this covers header-style pairs (`{"name": "Authorization",
/// "value": ...}` and `["Authorization", ...]`), argument and header lists
/// (`--token VALUE`, `API_KEY=VALUE`, `Cookie: VALUE`), and JSON documents
/// stored inside string values.
pub fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let named_secret = ["name", "key", "header"]
                .iter()
                .filter_map(|field| object.get(*field)?.as_str())
                .any(secret_key);
            for (key, value) in object {
                if secret_key(key) || (named_secret && matches!(key.as_str(), "value" | "values")) {
                    *value = Value::String(REDACTED.into());
                } else {
                    redact_secrets(value);
                }
            }
        }
        Value::Array(items) => {
            let strings = items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>();
            if let Some(mut strings) = strings {
                // A bare header name followed by its value: `["Cookie", VALUE]`.
                let bare_name = |name: &str| {
                    !name.contains(|character: char| {
                        character.is_whitespace() || matches!(character, ':' | '=')
                    })
                };
                if strings.len() == 2 && bare_name(&strings[0]) && secret_key(&strings[0]) {
                    strings[1] = REDACTED.into();
                }
                for (item, redacted) in items
                    .iter_mut()
                    .zip(premier_trace::redact_command_secrets(&strings))
                {
                    *item = Value::String(redacted);
                }
            }
            for item in items {
                redact_secrets(item);
            }
        }
        Value::String(text) => {
            if text.trim_start().starts_with(['{', '['])
                && let Ok(original) = serde_json::from_str::<Value>(text)
            {
                let mut nested = original.clone();
                redact_secrets(&mut nested);
                // Untouched documents keep their exact original text.
                if nested != original {
                    *text = nested.to_string();
                }
            }
        }
        _ => {}
    }
}

#[derive(Debug, Serialize)]
pub struct PortableEvidence {
    pub format: &'static str,
    pub redaction: PortableRedaction,
    pub manifest: Value,
    pub events: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct PortableRedaction {
    pub applied: bool,
    pub replacement: &'static str,
    pub policy: &'static str,
}

pub fn portable_evidence(manifest: &TraceManifest, events: &[TraceEvent]) -> PortableEvidence {
    let mut manifest = serde_json::to_value(manifest).unwrap_or(Value::Null);
    redact_secrets(&mut manifest);
    let events = events
        .iter()
        .map(|event| {
            let mut object = match serde_json::to_value(event).unwrap_or(Value::Null) {
                Value::Object(object) => object,
                _ => Map::new(),
            };
            object.remove("payload_json");
            let mut payload = event.payload();
            redact_secrets(&mut payload);
            object.insert("payload".into(), payload);
            let mut event = Value::Object(object);
            redact_secrets(&mut event);
            event
        })
        .collect();
    PortableEvidence {
        format: "premier.portable-evidence.v1",
        redaction: PortableRedaction {
            applied: true,
            replacement: REDACTED,
            policy: "recursive common secret field names, including JSON strings and header or argument lists",
        },
        manifest,
        events,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffStatus {
    Added,
    Removed,
    Changed,
    Unchanged,
}

#[derive(Debug, Default, Serialize)]
pub struct DiffCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub unchanged: usize,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct TraceDiff {
    pub format: &'static str,
    pub counts: DiffCounts,
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

pub fn semantic_event_key(event: &TraceEvent) -> String {
    let payload = event.payload();
    let discriminator = if event.kind.starts_with("tool.") {
        payload
            .get("tool")
            .or_else(|| payload.get("name"))
            .or_else(|| payload.get("command"))
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

fn compare_pair(key: String, baseline: &TraceEvent, current: &TraceEvent) -> DiffItem {
    let mut changes = Vec::new();
    let mut add = |field: &str, before: Value, after: Value| {
        if before != after {
            changes.push(StructuralChange {
                field: field.into(),
                before,
                after,
            });
        }
    };
    add("status", json!(baseline.status), json!(current.status));
    add("source", json!(baseline.source), json!(current.source));
    add(
        "actor_type",
        json!(baseline.actor_type),
        json!(current.actor_type),
    );
    add(
        "duration_ms",
        json!(baseline.duration_ms),
        json!(current.duration_ms),
    );
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    flatten(
        "payload",
        &comparable_payload(&baseline.payload()),
        &mut before,
    );
    flatten(
        "payload",
        &comparable_payload(&current.payload()),
        &mut after,
    );
    let fields = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for field in fields {
        add(
            &field,
            before.get(&field).cloned().unwrap_or(Value::Null),
            after.get(&field).cloned().unwrap_or(Value::Null),
        );
    }
    DiffItem {
        key,
        status: if changes.is_empty() {
            DiffStatus::Unchanged
        } else {
            DiffStatus::Changed
        },
        baseline_sequence: Some(baseline.sequence),
        current_sequence: Some(current.sequence),
        changes,
    }
}

fn one_sided(key: String, status: DiffStatus, event: &TraceEvent) -> DiffItem {
    DiffItem {
        key,
        status,
        baseline_sequence: (status == DiffStatus::Removed).then_some(event.sequence),
        current_sequence: (status == DiffStatus::Added).then_some(event.sequence),
        changes: Vec::new(),
    }
}

pub fn diff_events(baseline: &[TraceEvent], current: &[TraceEvent]) -> TraceDiff {
    let mut current_groups: HashMap<String, VecDeque<usize>> = HashMap::new();
    for (index, event) in current.iter().enumerate() {
        current_groups
            .entry(semantic_event_key(event))
            .or_default()
            .push_back(index);
    }
    let mut used = vec![false; current.len()];
    let mut occurrences: HashMap<String, usize> = HashMap::new();
    let mut items = Vec::new();
    for event in baseline {
        let identity = semantic_event_key(event);
        let occurrence = occurrences.entry(identity.clone()).or_default();
        *occurrence += 1;
        let key = format!("{identity}#{occurrence}");
        if let Some(index) = current_groups
            .get_mut(&identity)
            .and_then(VecDeque::pop_front)
        {
            used[index] = true;
            items.push(compare_pair(key, event, &current[index]));
        } else {
            items.push(one_sided(key, DiffStatus::Removed, event));
        }
    }
    let mut added_occurrences = occurrences;
    for (index, event) in current.iter().enumerate() {
        if used[index] {
            continue;
        }
        let identity = semantic_event_key(event);
        let occurrence = added_occurrences.entry(identity.clone()).or_default();
        *occurrence += 1;
        items.push(one_sided(
            format!("{identity}#{occurrence}"),
            DiffStatus::Added,
            event,
        ));
    }
    let mut counts = DiffCounts::default();
    for item in &items {
        match item.status {
            DiffStatus::Added => counts.added += 1,
            DiffStatus::Removed => counts.removed += 1,
            DiffStatus::Changed => counts.changed += 1,
            DiffStatus::Unchanged => counts.unchanged += 1,
        }
    }
    TraceDiff {
        format: "premier.semantic-diff.v1",
        counts,
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
        assert_eq!(diff.counts.unchanged, 2, "{:?}", diff.items);

        // Outside `native`, a caller's own `id` field is still compared.
        let mut changed = adapter("Grep", "run-b", "claude");
        changed.payload_json = changed.payload_json.replace("kept", "edited");
        let diff = diff_events(&baseline[..1], &[changed]);
        assert_eq!(diff.counts.changed, 1);
    }
}
