//! The issue predicate behind trace list counts, `premier query --issues`
//! and the viewer's timeline.
//!
//! An event is an issue when
//!
//! 1. its status is `error`, `failed`, `denied`, `blocked` or `rejected`; or
//! 2. a whole segment of its kind (split at every character that is not a
//!    letter or digit) is `error`, `errors`, `errored`, `fail`, `failed` or
//!    `failure`, so `tool.execution_failed` is one and `tool.failover` is not;
//!    or
//! 3. the provider object under `payload.native` states a failure; or
//! 4. it has no status at all and its payload states a failure at the top
//!    level (`is_error`, a non-empty `error`, a non-zero `exit_code`, or a
//!    failing `status`). A status the producer did record is its own statement
//!    of the outcome and is not second-guessed.
//!
//! `isIssue` in the viewer (`apps/viewer/src/lib/analysis.ts`, with
//! `nativeFailure` and `payloadFailure` in `nativePayload.ts`) is the same
//! rule. Both run `tests/fixtures/issues/issue-cases.json`; change one and
//! the other must follow.

use premier_trace::TraceEvent;
use serde_json::Value;

pub fn is_issue(event: &TraceEvent) -> bool {
    let status = event.status.trim().to_ascii_lowercase();
    if matches!(
        status.as_str(),
        "error" | "failed" | "denied" | "blocked" | "rejected"
    ) {
        return true;
    }
    let kind = event.kind.trim().to_ascii_lowercase();
    if kind
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|segment| {
            matches!(
                segment,
                "error" | "errors" | "errored" | "fail" | "failed" | "failure"
            )
        })
    {
        return true;
    }
    payload_failure(event, status.is_empty())
}

/// Payload keys that can state a failure; an event without any of them is
/// never decoded.
const FAILURE_KEYS: [&str; 7] = [
    "\"is_error\"",
    "\"isError\"",
    "\"error\"",
    "\"exit_code\"",
    "\"exitCode\"",
    "\"status\"",
    "\"state\"",
];

/// A failure stated only in the payload: by the provider object an adapter
/// kept under `payload.native` (current adapters also record that as the
/// event status; older traces carry it only there), or at the top level of an
/// event recorded without a status (`unstated`).
fn payload_failure(event: &TraceEvent, unstated: bool) -> bool {
    // Most events carry neither; skip decoding their payload.
    let envelope = event.payload_json.contains("\"native\"");
    if !envelope
        && !(unstated
            && FAILURE_KEYS
                .iter()
                .any(|key| event.payload_json.contains(key)))
    {
        return false;
    }
    let payload = event.payload();
    if !payload.is_object() {
        return false;
    }
    native_failure(&payload, &event.correlation_id) || (unstated && states_failure(&payload))
}

fn native_failure(payload: &Value, correlation_id: &str) -> bool {
    let Some(native) = payload.get("native").filter(|native| native.is_object()) else {
        return false;
    };
    outcome_scopes(native).into_iter().any(states_failure)
        || native
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("error"))
        || failed_block(native, correlation_id)
}

/// Objects in which a provider states the outcome of the event itself: the
/// line, its `item` or `part`, and their `state`. Arguments, output and prose
/// are never consulted.
fn outcome_scopes(native: &Value) -> Vec<&Value> {
    let mut scopes = vec![native];
    for key in ["item", "part"] {
        if let Some(inner) = native.get(key).filter(|inner| inner.is_object()) {
            scopes.push(inner);
        }
    }
    let states: Vec<_> = scopes
        .iter()
        .filter_map(|scope| scope.get("state").filter(|state| state.is_object()))
        .collect();
    scopes.extend(states);
    scopes
}

fn flags_error(scope: &Value) -> bool {
    ["is_error", "isError"]
        .iter()
        .any(|key| scope.get(*key).and_then(Value::as_bool) == Some(true))
}

fn states_failure(scope: &Value) -> bool {
    flags_error(scope)
        || ["status", "state"]
            .iter()
            .find_map(|key| scope.get(*key)?.as_str())
            .is_some_and(|status| {
                matches!(
                    status.trim().to_ascii_lowercase().as_str(),
                    "error" | "errored" | "failed" | "failure" | "denied" | "rejected"
                )
            })
        || ["exit_code", "exitCode"]
            .iter()
            .find_map(|key| scope.get(*key).filter(|code| !code.is_null()))
            .and_then(Value::as_f64)
            .is_some_and(|code| code != 0.0)
        || scope.get("error").is_some_and(|error| match error {
            Value::Null => false,
            Value::Bool(flag) => *flag,
            Value::Number(number) => number.as_f64() != Some(0.0),
            Value::String(text) => !text.is_empty(),
            Value::Array(items) => !items.is_empty(),
            Value::Object(object) => !object.is_empty(),
        })
}

/// A chat-style line can carry several tool results. An event that names one
/// of them by correlation id answers only for that block; otherwise the event
/// stands for the whole line.
fn failed_block(native: &Value, correlation_id: &str) -> bool {
    let blocks: Vec<&Value> = [
        native
            .get("message")
            .and_then(|message| message.get("content")),
        native.get("content"),
        native.get("item").and_then(|item| item.get("content")),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_array)
    .map(|blocks| blocks.iter().filter(|block| block.is_object()).collect())
    .unwrap_or_default();
    let own: Vec<&Value> = blocks
        .iter()
        .copied()
        .filter(|block| {
            !correlation_id.is_empty()
                && ["tool_use_id", "tool_call_id", "call_id", "id"]
                    .iter()
                    .any(|key| block.get(*key).and_then(Value::as_str) == Some(correlation_id))
        })
        .collect();
    let candidates = if own.is_empty() { blocks } else { own };
    candidates.into_iter().any(flags_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn event(kind: &str, status: &str, correlation_id: &str, payload: Value) -> TraceEvent {
        TraceEvent {
            event_id: "event-1".into(),
            trace_id: "trace-1".into(),
            sequence: 1,
            timestamp: "2026-07-13T20:51:39Z".into(),
            kind: kind.into(),
            source: "adapter".into(),
            payload_json: payload.to_string(),
            actor_id: String::new(),
            actor_type: String::new(),
            parent_event_id: String::new(),
            span_id: String::new(),
            parent_span_id: String::new(),
            correlation_id: correlation_id.into(),
            status: status.into(),
            duration_ms: 0,
            links: Vec::new(),
            prev_hash: String::new(),
        }
    }

    fn native(native: Value) -> TraceEvent {
        event("tool.result", "ok", "", json!({ "native": native }))
    }

    #[test]
    fn status_and_kind_still_decide_first() {
        assert!(is_issue(&event("tool.result", "Denied", "", json!({}))));
        assert!(is_issue(&event(
            "tool.execution_failed",
            "ok",
            "",
            json!({})
        )));
        assert!(!is_issue(&event("tool.result", "ok", "", json!({}))));
        assert!(!is_issue(&event("tool.result", "ok", "", Value::Null)));
    }

    #[test]
    fn explicit_native_failures_are_issues_on_older_traces() {
        for failed in [
            json!({"type": "result", "is_error": true, "result": "boom"}),
            json!({"type": "tool_result", "isError": true}),
            json!({"type": "tool_result", "tool_id": "t1", "status": "error"}),
            json!({"type": "item.completed", "item": {"type": "command_execution", "exit_code": 2}}),
            json!({"type": "item.completed", "item": {"status": "failed"}}),
            json!({"type": "tool", "part": {"state": {"status": "error", "error": "exit 1"}}}),
            json!({"type": "turn", "error": {"message": "quota"}}),
            json!({"type": "error", "message": "overloaded"}),
            json!({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t1", "is_error": true}
            ]}}),
        ] {
            assert!(is_issue(&native(failed.clone())), "{failed}");
        }
    }

    #[test]
    fn healthy_native_events_are_not_issues() {
        for healthy in [
            json!({"type": "result", "is_error": false, "result": "done"}),
            json!({"type": "item.completed", "item": {"exit_code": 0, "status": "completed"}}),
            json!({"type": "item.started", "item": {"exit_code": null, "status": "in_progress"}}),
            json!({"type": "tool_result", "error": null}),
            json!({"type": "tool_result", "error": ""}),
            // Arguments and prose are never an outcome.
            json!({"type": "tool_use", "input": {"status": "failed", "is_error": true, "exit_code": 1}}),
            json!({"type": "assistant", "text": "the build failed with an error"}),
        ] {
            assert!(!is_issue(&native(healthy.clone())), "{healthy}");
        }
        // A status the producer recorded outranks what the payload says.
        assert!(!is_issue(&event(
            "tool.result",
            "ok",
            "",
            json!({"is_error": true})
        )));
        // Without one, the payload's own statement decides.
        assert!(is_issue(&event(
            "tool.result",
            "",
            "",
            json!({"is_error": true})
        )));
    }

    /// The cases the viewer's `isIssue` is tested against too.
    #[test]
    fn agrees_with_the_shared_issue_cases() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/issues/issue-cases.json"))
                .unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() > 30);
        for case in cases {
            let subject = event(
                case["kind"].as_str().unwrap(),
                case["status"].as_str().unwrap(),
                case["correlation_id"].as_str().unwrap_or(""),
                case["payload"].clone(),
            );
            assert_eq!(
                is_issue(&subject),
                case["issue"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn a_shared_native_line_flags_only_the_event_for_the_failed_block() {
        let line = json!({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
            {"type": "tool_result", "tool_use_id": "t2", "is_error": true}
        ]}});
        let payload = json!({ "native": line });
        assert!(!is_issue(&event(
            "tool.result",
            "ok",
            "t1",
            payload.clone()
        )));
        assert!(is_issue(&event("tool.result", "ok", "t2", payload.clone())));
        // An event that names none of the blocks speaks for the whole line.
        assert!(is_issue(&event("tool.result", "ok", "", payload)));
    }
}
