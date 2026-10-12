//! Structure-aware secret redaction shared by the recorder (before the
//! journal write) and `premier export` (for traces recorded earlier).

use super::{
    REDACTED, field_is_secret, is_secret_field_name, redact_builtin_secrets, redact_command_fields,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

/// What one redaction pass removed, by rule type.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RedactionCounts {
    /// Values this pass replaced: `field_names` plus every `value_patterns` count.
    pub total: usize,
    /// Values replaced because their field, flag or header name is secret.
    pub field_names: usize,
    /// Values replaced per built-in secret value pattern.
    pub value_patterns: BTreeMap<&'static str, usize>,
    /// Redaction markers that were already present, written at record time.
    pub already_redacted: usize,
}

/// Recursively replaces the values of secret-named fields. Besides plain
/// object keys this covers header-style pairs (`{"name": "Authorization",
/// "value": ...}` and `["Authorization", ...]`), argument and header lists
/// (`--token VALUE`, `API_KEY=VALUE`, `Cookie: VALUE`), and JSON documents
/// stored inside string values, whether the string is one document or text
/// with one JSON object per line. String values can also be checked against
/// the built-in secret value patterns.
pub struct SecretRedactor<'a> {
    /// Extra secret names on top of the default list; `None` is the default list.
    fields: Option<&'a HashSet<String>>,
    value_patterns: bool,
    counts: RedactionCounts,
}

impl SecretRedactor<'static> {
    /// A redactor for the default secret field names, with the built-in
    /// secret value patterns on string values when `value_patterns` is set.
    pub fn new(value_patterns: bool) -> Self {
        Self {
            fields: None,
            value_patterns,
            counts: RedactionCounts::default(),
        }
    }
}

impl<'a> SecretRedactor<'a> {
    /// A redactor for a recording's own field list (defaults plus
    /// `--redact-field`), leaving value patterns to the caller.
    pub(crate) fn with_fields(fields: &'a HashSet<String>) -> Self {
        Self {
            fields: Some(fields),
            value_patterns: false,
            counts: RedactionCounts::default(),
        }
    }

    /// What every [`Self::redact`] call so far removed.
    pub fn counts(&self) -> &RedactionCounts {
        &self.counts
    }

    pub fn into_counts(self) -> RedactionCounts {
        self.counts
    }

    fn secret_key(&self, key: &str) -> bool {
        match self.fields {
            Some(fields) => field_is_secret(key, fields),
            None => is_secret_field_name(key),
        }
    }

    fn replace_named(&mut self, value: &mut Value) {
        match value {
            Value::String(text) if text == REDACTED => self.counts.already_redacted += 1,
            Value::Null => {}
            Value::String(text) if text.is_empty() => {}
            _ => {
                self.counts.field_names += 1;
                self.counts.total += 1;
            }
        }
        *value = Value::String(REDACTED.into());
    }

    pub fn redact(&mut self, value: &mut Value) {
        match value {
            Value::Object(object) => {
                let named_secret = ["name", "key", "header"]
                    .iter()
                    .filter_map(|field| object.get(*field)?.as_str())
                    .any(|name| self.secret_key(name));
                for (key, value) in object {
                    if self.secret_key(key)
                        || (named_secret && matches!(key.as_str(), "value" | "values"))
                    {
                        self.replace_named(value);
                    } else {
                        self.redact(value);
                    }
                }
            }
            Value::Array(items) => {
                let strings = items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>();
                let Some(mut strings) = strings else {
                    for item in items {
                        self.redact(item);
                    }
                    return;
                };
                // A bare header name followed by its value: `["Cookie", VALUE]`.
                let bare_name = |name: &str| {
                    !name.contains(|character: char| {
                        character.is_whitespace() || matches!(character, ':' | '=')
                    })
                };
                if strings.len() == 2 && bare_name(&strings[0]) && self.secret_key(&strings[0]) {
                    strings[1] = REDACTED.into();
                }
                let redacted = redact_command_fields(&strings, &|name| self.secret_key(name));
                for (item, mut redacted) in items.iter_mut().zip(redacted) {
                    if item.as_str() == Some(redacted.as_str()) {
                        self.redact(item);
                    } else {
                        self.counts.field_names += 1;
                        self.counts.total += 1;
                        // The marker just written is not a recorded one.
                        self.redact_text(&mut redacted, false);
                        *item = Value::String(redacted);
                    }
                }
            }
            Value::String(text) => self.redact_string(text),
            _ => {}
        }
    }

    fn redact_string(&mut self, text: &mut String) {
        let body = text.trim();
        if body.starts_with(['{', '['])
            && let Ok(original) = serde_json::from_str::<Value>(body)
        {
            let mut nested = original.clone();
            self.redact(&mut nested);
            // Untouched documents keep their exact original text.
            if nested != original {
                let start = text.len() - text.trim_start().len();
                let end = start + body.len();
                *text = format!("{}{nested}{}", &text[..start], &text[end..]);
            }
        } else if let Some(redacted) = self.redact_json_lines(text) {
            *text = redacted;
        } else {
            self.redact_text(text, true);
        }
    }

    /// Text that is not one JSON document but holds JSON objects on lines of
    /// their own (JSONL output, or several lines stored as one chunk): each
    /// such line is redacted as a document, so the result does not depend on
    /// how the text was split into events. Other lines keep their bytes apart
    /// from value-pattern matches. `None` when no line is a JSON object.
    fn redact_json_lines(&mut self, text: &str) -> Option<String> {
        if !text.contains('\n') || !text.contains('{') {
            return None;
        }
        let mut plain_markers = 0;
        let mut documents = 0;
        let mut output = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let body = line.trim_end_matches(['\r', '\n']);
            let document = body
                .trim_start()
                .starts_with('{')
                .then(|| serde_json::from_str::<Value>(body).ok())
                .flatten();
            let Some(original) = document else {
                plain_markers += line.matches(REDACTED).count();
                output.push_str(line);
                continue;
            };
            documents += 1;
            let mut nested = original.clone();
            self.redact(&mut nested);
            if nested == original {
                output.push_str(line);
            } else {
                output.push_str(&nested.to_string());
                output.push_str(&line[body.len()..]);
            }
        }
        if documents == 0 {
            return None;
        }
        self.counts.already_redacted += plain_markers;
        // Value patterns may span lines (a private key block), so they run
        // over the whole text; the JSON lines above are already handled.
        self.redact_text(&mut output, false);
        Some(output)
    }

    /// Apply the built-in secret value patterns to one plain string.
    fn redact_text(&mut self, text: &mut String, count_markers: bool) {
        if count_markers {
            self.counts.already_redacted += text.matches(REDACTED).count();
        }
        if !self.value_patterns {
            return;
        }
        let counts = &mut self.counts;
        let mut on_match = |name: &'static str| {
            *counts.value_patterns.entry(name).or_default() += 1;
            counts.total += 1;
        };
        if let Some(redacted) = redact_builtin_secrets(text, &mut on_match) {
            *text = redacted;
        }
    }
}
