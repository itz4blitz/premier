//! The recorder's secret field names and value patterns, checked against the
//! fixture the viewer's "Export safe JSON" is also tested with
//! (`apps/viewer/src/lib/safeExport.test.ts`), so the two cannot drift apart.

use premier_trace::{DEFAULT_REDACTED_FIELDS, is_secret_field_name, redact_builtin_secrets};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/redaction-cases.json")).unwrap()
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect()
}

#[test]
fn secret_field_names_match_the_shared_fixture() {
    let fixture = fixture();
    assert_eq!(
        DEFAULT_REDACTED_FIELDS,
        strings(&fixture["default_redacted_fields"])
    );
    for name in strings(&fixture["secret_field_names"]) {
        assert!(is_secret_field_name(name), "{name} should be secret");
    }
    for name in strings(&fixture["ordinary_field_names"]) {
        assert!(!is_secret_field_name(name), "{name} should not be secret");
    }
}

#[test]
fn value_patterns_match_the_shared_fixture() {
    let fixture = fixture();
    for case in fixture["secret_values"].as_array().unwrap() {
        let pattern = case["pattern"].as_str().unwrap();
        let (before, after) = (
            case["before"].as_str().unwrap(),
            case["after"].as_str().unwrap(),
        );
        // Joined here so the fixture never holds a credential-shaped string.
        let secret = strings(&case["secret"]).concat();
        let text = format!("{before}{secret}{after}");
        let mut matched = Vec::new();
        let redacted = redact_builtin_secrets(&text, &mut |rule| matched.push(rule));
        assert_eq!(
            redacted.as_deref(),
            Some(format!("{before}[REDACTED]{after}").as_str()),
            "{pattern}: {text}"
        );
        assert_eq!(matched, [pattern], "{text}");
    }
    for text in strings(&fixture["ordinary_values"]) {
        assert_eq!(redact_builtin_secrets(text, &mut |_| {}), None, "{text}");
    }
}
