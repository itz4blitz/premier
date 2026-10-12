use chrono::{DateTime, SecondsFormat, Utc};
use premier_trace::EventInput;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;

pub const ADAPTER_SCHEMA_VERSION: u32 = 1;
/// Longer lines are still normalized, but the stored copy has its large strings truncated.
const MAX_NATIVE_LINE_BYTES: usize = 256 * 1024;
/// Hard bound on buffered bytes; a longer line is discarded with a sized diagnostic.
const MAX_BUFFERED_LINE_BYTES: usize = 16 * 1024 * 1024;
const TRUNCATED_STRING_BYTES: usize = 8 * 1024;
const MAX_TRACKED_TOOL_CALLS: usize = 1024;
/// Bound on remembered stored event ids; per-call entries are dropped first when it is reached.
const MAX_TRACKED_EVENT_IDS: usize = 4 * MAX_TRACKED_TOOL_CALLS;
const SESSION_KEY: &str = "session";
const TURN_KEY: &str = "turn";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterChoice {
    Auto,
    None,
    Codex,
    Claude,
    Gemini,
    Grok,
    Opencode,
    Kimi,
    Droid,
}

impl std::str::FromStr for AdapterChoice {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            "gemini" => Ok(Self::Gemini),
            "grok" => Ok(Self::Grok),
            "opencode" => Ok(Self::Opencode),
            "kimi" => Ok(Self::Kimi),
            "droid" => Ok(Self::Droid),
            _ => Err(
                "adapter must be auto, none, codex, claude, gemini, grok, opencode, kimi, or droid"
                    .into(),
            ),
        }
    }
}

impl AdapterChoice {
    pub fn is_explicit(self) -> bool {
        !matches!(self, Self::Auto | Self::None)
    }

    pub fn resolve(self, executable: &str, args: &[String], pty: bool) -> Option<Provider> {
        if pty || self == Self::None {
            return None;
        }
        let explicit = match self {
            Self::Codex => Some(Provider::Codex),
            Self::Claude => Some(Provider::Claude),
            Self::Gemini => Some(Provider::Gemini),
            Self::Grok => Some(Provider::Grok),
            Self::Opencode => Some(Provider::Opencode),
            Self::Kimi => Some(Provider::Kimi),
            Self::Droid => Some(Provider::Droid),
            Self::Auto | Self::None => None,
        };
        if explicit.is_some() {
            return explicit;
        }
        let name = Path::new(executable)
            .file_stem()
            .and_then(|value| value.to_str())?
            .trim_end_matches(".exe")
            .to_ascii_lowercase();
        let provider = Provider::from_name(&name)?;
        provider.has_structured_output(args).then_some(provider)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Codex,
    Claude,
    Gemini,
    Grok,
    Opencode,
    Kimi,
    Droid,
}

impl Provider {
    pub fn id(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Grok => "grok",
            Self::Opencode => "opencode",
            Self::Kimi => "kimi",
            Self::Droid => "droid",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "codex" => Some(Self::Codex),
            "claude" => Some(Self::Claude),
            "gemini" => Some(Self::Gemini),
            "grok" => Some(Self::Grok),
            "opencode" => Some(Self::Opencode),
            "kimi" => Some(Self::Kimi),
            "droid" => Some(Self::Droid),
            _ => None,
        }
    }

    fn has_structured_output(self, args: &[String]) -> bool {
        let has_pair = |flag: &str, value: &str| {
            args.windows(2)
                .any(|pair| pair[0] == flag && pair[1] == value)
                || args.iter().any(|arg| arg == &format!("{flag}={value}"))
        };
        match self {
            Self::Codex => args.iter().any(|arg| arg == "--json"),
            Self::Claude => has_pair("--output-format", "stream-json"),
            Self::Gemini => has_pair("--output-format", "stream-json"),
            Self::Grok => has_pair("--output-format", "streaming-json"),
            Self::Opencode => has_pair("--format", "json"),
            Self::Kimi => has_pair("--output-format", "stream-json"),
            Self::Droid => has_pair("--output-format", "json") || has_pair("-o", "json"),
        }
    }
}

/// A normalized event plus the causal references only the appender can resolve. The adapter
/// never sees the ids the writer assigns, so it names the events it depends on by key and
/// [`NativeAdapter::commit`] swaps the keys for stored event ids.
#[derive(Debug)]
pub struct AdapterEvent {
    pub input: EventInput,
    /// Key under which this event's stored id is remembered.
    opens: Option<String>,
    /// A weak opener (a hook line about a call) yields to the call itself.
    weak: bool,
    /// Key forgotten once this event is stored.
    closes: Option<String>,
    /// Candidate parents, most specific first; the first one already stored wins.
    parents: Vec<String>,
    /// Keys whose stored ids become `links`.
    links: Vec<String>,
}

impl AdapterEvent {
    fn unlinked(input: EventInput) -> Self {
        Self {
            input,
            opens: None,
            weak: false,
            closes: None,
            parents: Vec::new(),
            links: Vec::new(),
        }
    }
}

impl std::ops::Deref for AdapterEvent {
    type Target = EventInput;

    fn deref(&self) -> &EventInput {
        &self.input
    }
}

impl std::ops::DerefMut for AdapterEvent {
    fn deref_mut(&mut self) -> &mut EventInput {
        &mut self.input
    }
}

/// The stored event that opened a session, turn, tool call, approval or subagent.
struct Opened {
    event_id: String,
    weak: bool,
    actor_id: String,
}

/// Lines whose exact type states where a session or turn starts and ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    SessionStart,
    TurnStart,
    RunResult,
}

impl Phase {
    fn kind(self) -> &'static str {
        match self {
            Self::SessionStart | Self::TurnStart => "agent.turn",
            Self::RunResult => "agent.result",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::SessionStart => "session_start",
            Self::TurnStart => "turn_start",
            Self::RunResult => "run_result",
        }
    }
}

pub struct NativeAdapter {
    provider: Provider,
    pending: Vec<u8>,
    discarded_bytes: usize,
    line_number: u64,
    session_id: String,
    tool_names: HashMap<String, String>,
    /// Stored event ids by reference key, filled in by `commit`.
    event_ids: HashMap<String, Opened>,
    /// Subagents by spawning tool call id; true while the spawning call has no result yet.
    subagents: HashMap<String, bool>,
}

impl NativeAdapter {
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            pending: Vec::new(),
            discarded_bytes: 0,
            line_number: 0,
            session_id: String::new(),
            tool_names: HashMap::new(),
            event_ids: HashMap::new(),
            subagents: HashMap::new(),
        }
    }

    /// Stores `events` in order through `append`, which returns the event id the writer
    /// assigned. Reference keys become `parent_event_id` and `links`, and each stored id is
    /// remembered for the events that follow, so a parent is always an earlier stored event.
    pub fn commit<E>(
        &mut self,
        events: Vec<AdapterEvent>,
        mut append: impl FnMut(EventInput) -> Result<String, E>,
    ) -> Result<(), E> {
        for event in events {
            let AdapterEvent {
                mut input,
                opens,
                weak,
                closes,
                parents,
                links,
            } = event;
            if let Some(parent) = parents.iter().find_map(|key| self.event_ids.get(key)) {
                input.parent_event_id = parent.event_id.clone();
                // Only the stored spawning call knows which actor a subagent descends from.
                if input.kind == "agent.spawn" && !parent.actor_id.is_empty() {
                    input.payload["parent_actor"] = json!(parent.actor_id);
                }
            }
            for key in &links {
                if let Some(linked) = self.event_ids.get(key)
                    && !input.links.contains(&linked.event_id)
                {
                    input.links.push(linked.event_id.clone());
                }
            }
            let actor_id = input.actor_id.clone();
            let event_id = append(input)?;
            if let Some(key) = closes {
                self.event_ids.remove(&key);
            }
            if let Some(key) = opens {
                self.remember(
                    key,
                    Opened {
                        event_id,
                        weak,
                        actor_id,
                    },
                );
            }
        }
        Ok(())
    }

    fn remember(&mut self, key: String, opened: Opened) {
        // The latest session or turn wins; a call keeps its first record unless that was a hook.
        let replace = key == SESSION_KEY
            || key == TURN_KEY
            || self
                .event_ids
                .get(&key)
                .is_none_or(|existing| existing.weak && !opened.weak);
        if !replace {
            return;
        }
        if self.event_ids.len() >= MAX_TRACKED_EVENT_IDS {
            self.event_ids
                .retain(|key, _| key == SESSION_KEY || key == TURN_KEY);
        }
        self.event_ids.insert(key, opened);
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<AdapterEvent> {
        let mut events = Vec::new();
        for &byte in bytes {
            if self.discarded_bytes > 0 {
                if byte == b'\n' {
                    events.push(self.discarded_diagnostic());
                } else {
                    self.discarded_bytes += 1;
                }
                continue;
            }
            if byte == b'\n' {
                self.line_number += 1;
                let line = std::mem::take(&mut self.pending);
                events.extend(self.parse_line(&line));
            } else if self.pending.len() == MAX_BUFFERED_LINE_BYTES {
                self.discarded_bytes = self.pending.len() + 1;
                self.pending = Vec::new();
                self.line_number += 1;
            } else {
                self.pending.push(byte);
            }
        }
        events
    }

    pub fn finish(&mut self) -> Vec<AdapterEvent> {
        if self.discarded_bytes > 0 {
            return vec![self.discarded_diagnostic()];
        }
        if self.pending.is_empty() {
            return Vec::new();
        }
        self.line_number += 1;
        let line = std::mem::take(&mut self.pending);
        self.parse_line(&line)
    }

    fn parse_line(&mut self, line: &[u8]) -> Vec<AdapterEvent> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return Vec::new();
        }
        let line_bytes = line.len();
        let oversized = (line_bytes > MAX_NATIVE_LINE_BYTES).then_some(line_bytes);
        let line = strip_terminal_prefix(line);
        let native: Value = match serde_json::from_slice(line) {
            Ok(Value::Object(object)) => Value::Object(object),
            Ok(_) => {
                return vec![self.diagnostic("native JSONL event was not an object", oversized)];
            }
            Err(error) if oversized.is_some() => {
                return vec![self.diagnostic(
                    &format!(
                        "oversized native JSONL line ({line_bytes} bytes, limit \
                         {MAX_NATIVE_LINE_BYTES}) could not be parsed: {error}"
                    ),
                    oversized,
                )];
            }
            Err(error) => {
                return vec![self.diagnostic(&format!("malformed native JSONL: {error}"), None)];
            }
        };
        let mut events = self.normalize(native);
        if oversized.is_some() {
            // Status, pairing and identity came from the full line; only the stored copy shrinks.
            for event in &mut events {
                // Synthesized events hold no copy of the line.
                if event.payload.get("native").is_some() {
                    truncate_payload(&mut event.payload, line_bytes);
                }
            }
        }
        events
    }

    fn discarded_diagnostic(&mut self) -> AdapterEvent {
        let line_bytes = std::mem::take(&mut self.discarded_bytes);
        self.diagnostic(
            &format!(
                "oversized native JSONL line ({line_bytes} bytes) exceeded the \
                 {MAX_BUFFERED_LINE_BYTES} byte buffer and was discarded"
            ),
            Some(line_bytes),
        )
    }

    fn diagnostic(&self, message: &str, line_bytes: Option<usize>) -> AdapterEvent {
        let mut payload = json!({
            "provider": self.provider.id(),
            "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
            "line": self.line_number,
            "message": message,
        });
        if let Some(line_bytes) = line_bytes {
            payload["line_bytes"] = json!(line_bytes);
        }
        AdapterEvent::unlinked(EventInput {
            kind: "adapter.diagnostic".into(),
            source: format!("adapter.{}.v{ADAPTER_SCHEMA_VERSION}", self.provider.id()),
            actor_id: self.provider.id().into(),
            actor_type: "agent".into(),
            status: "warning".into(),
            payload,
            ..EventInput::default()
        })
    }

    fn normalize(&mut self, native: Value) -> Vec<AdapterEvent> {
        let provider = self.provider;
        let native_type = string_at(
            &native,
            &[
                &["type"],
                &["event"],
                &["kind"],
                &["method"],
                &["item", "type"],
                &["part", "type"],
            ],
        )
        .unwrap_or("unknown")
        .to_ascii_lowercase();
        if let Some(session) = string_at(&native, SESSION_ID_PATHS) {
            self.session_id = session.to_owned();
        }
        let parent_tool = string_at(&native, &[&["parent_tool_use_id"]])
            .unwrap_or("")
            .to_owned();
        let mut events = Vec::new();
        if !parent_tool.is_empty() && !self.subagents.contains_key(&parent_tool) {
            // The provider never announces a subagent; its first line is the earliest evidence.
            if self.subagents.len() >= MAX_TRACKED_TOOL_CALLS {
                self.subagents.clear();
            }
            self.subagents.insert(parent_tool.clone(), true);
            events.push(self.subagent_event(
                "agent.spawn",
                "running",
                "parent_tool_use_id",
                &parent_tool,
            ));
        }
        let discriminators = Discriminators::of(&native);
        let blocks = tool_blocks(&native);
        let scopes = outcome_scopes(&native);
        let decision = discriminators
            .has(APPROVAL_WORDS)
            .then(|| approval_decision(&scopes))
            .flatten();
        let completed = is_completed(&scopes, &discriminators) || decision.is_some();
        let phase = lifecycle_phase(provider, &native);
        let kind = classify_kind(provider, &native, &discriminators, phase, completed);
        let tool_kind = kind.starts_with("tool.") || kind.starts_with("approval.");
        // A line that is itself a tool event speaks for the first nested block of the same phase.
        let block = if tool_kind {
            blocks
                .iter()
                .find(|block| block_kind(block) == kind)
                .or(blocks.first())
                .copied()
        } else {
            None
        };
        let failed = scopes.iter().any(|scope| states_failure(scope))
            || block.is_some_and(states_failure)
            || type_states_failure(&native, block);
        // An explicit failure ends the lifecycle even when the provider never says "completed".
        let kind = if failed && !completed {
            classify_kind(provider, &native, &discriminators, phase, true)
        } else {
            kind
        };
        // A session's start, turns and result pair up through the session, not per-line ids.
        let session_scoped = matches!(kind, "agent.turn" | "agent.result")
            && parent_tool.is_empty()
            && !self.session_id.is_empty();
        let correlation_id = if tool_kind {
            tool_correlation(&native, block)
        } else if session_scoped {
            Some(self.session_id.as_str())
        } else {
            None
        }
        .or_else(|| string_at(&native, CORRELATION_PATHS))
        .unwrap_or("")
        .to_owned();
        let hook = native_type.starts_with("hook")
            || ["hook_name", "hook_event_name"]
                .iter()
                .any(|key| native.get(*key).is_some());
        let native_timestamp = native_timestamp(&native);
        let status = if let Some(decision) = decision {
            decision
        } else if failed {
            "error"
        } else if kind == "approval.request" {
            "pending"
        } else if completed || kind.ends_with("response") || kind.ends_with("result") {
            "ok"
        } else {
            "running"
        };
        let tool = if tool_kind {
            tool_name(&native, block).map(str::to_owned)
        } else {
            None
        };
        let tool = self.track_tool(kind, &correlation_id, tool);
        let mut extra = Vec::new();
        if tool_kind {
            for part in &blocks {
                if !block.is_some_and(|block| std::ptr::eq(block, *part)) {
                    extra.push(self.part_event(
                        part,
                        block_kind(part),
                        &parent_tool,
                        native_timestamp.as_deref(),
                    ));
                }
            }
        } else {
            for call in function_calls(&native) {
                extra.push(self.part_event(
                    call,
                    "tool.invocation",
                    &parent_tool,
                    native_timestamp.as_deref(),
                ));
            }
        }
        let mut payload = json!({
            "provider": provider.id(),
            "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
            "native_type": native_type,
        });
        if let Some(tool) = tool {
            payload["tool"] = json!(tool);
        }
        if tool_kind
            && let Some(command) = string_at(&native, &[&["command"], &["item", "command"]])
        {
            payload["command"] = json!(command);
        }
        if let Some(model) = string_at(&native, MODEL_PATHS) {
            payload["model"] = json!(model);
        }
        if let Some(usage) = normalized_usage(&native) {
            payload["usage"] = usage;
        }
        if !parent_tool.is_empty() {
            payload["parent_actor"] = json!(provider.id());
        }
        if let Some(phase) = phase {
            payload["lifecycle"] = json!(phase.label());
        }
        if session_scoped {
            payload["session_id"] = json!(self.session_id);
        }
        if let Some(timestamp) = &native_timestamp {
            payload["native_timestamp"] = json!(timestamp);
        }
        let duration_ms = native
            .get("duration_ms")
            .or_else(|| native.get("item")?.get("duration_ms"))
            .or_else(|| native.get("stats")?.get("duration_ms"))
            .and_then(Value::as_u64)
            .unwrap_or_default();
        payload["native"] = native;
        let main = EventInput {
            kind: kind.into(),
            status: status.into(),
            duration_ms,
            payload,
            ..self.identified(correlation_id, &parent_tool)
        };
        let parts = extra.into_iter().map(|part| (part, false, None));
        for (input, hook, phase) in std::iter::once((main, hook, phase)).chain(parts) {
            let event = self.linked(input, &parent_tool, hook, phase);
            let finished = self.subagent_result(&event);
            events.push(event);
            events.extend(finished);
        }
        events
    }

    /// Names the stored events this one hangs off: the call a result or approval answers, the
    /// spawn of the subagent it belongs to, then the open turn and the session.
    fn linked(
        &self,
        input: EventInput,
        parent_tool: &str,
        hook: bool,
        phase: Option<Phase>,
    ) -> AdapterEvent {
        let keyed = |prefix: &str| {
            (!input.correlation_id.is_empty()).then(|| format!("{prefix}:{}", input.correlation_id))
        };
        let (tool, approval, result) = (keyed("tool"), keyed("approval"), keyed("result"));
        let subagent = !parent_tool.is_empty();
        let (mut opens, mut closes) = (None, None);
        let (mut parents, mut links) = (Vec::new(), Vec::new());
        match input.kind.as_str() {
            "tool.invocation" => {
                if hook {
                    parents.extend(tool.clone());
                }
                opens = tool;
            }
            "tool.result" => {
                parents.extend(tool.clone());
                links.extend(tool);
                // Only a result that ends a subagent is referenced later.
                if self.subagents.get(&input.correlation_id) == Some(&true) {
                    opens = result;
                }
            }
            "approval.request" => {
                parents.extend(tool);
                opens = approval;
            }
            "approval.decision" => {
                parents.extend(approval.clone());
                parents.extend(tool);
                links.extend(approval);
            }
            "agent.turn" if !subagent => {
                let key = if phase == Some(Phase::SessionStart) {
                    SESSION_KEY
                } else {
                    TURN_KEY
                };
                opens = Some(key.to_owned());
            }
            "agent.result" if !subagent => closes = Some(TURN_KEY.to_owned()),
            _ => {}
        }
        if subagent {
            parents.push(format!("agent:{parent_tool}"));
        }
        if opens.as_deref() != Some(SESSION_KEY) {
            if opens.as_deref() != Some(TURN_KEY) {
                parents.push(TURN_KEY.to_owned());
            }
            parents.push(SESSION_KEY.to_owned());
        }
        AdapterEvent {
            input,
            opens,
            weak: hook,
            closes,
            parents,
            links,
        }
    }

    /// The subagent's completion, inferred from the result of the tool call that spawned it.
    fn subagent_result(&mut self, result: &EventInput) -> Option<AdapterEvent> {
        if result.kind != "tool.result" {
            return None;
        }
        let open = self.subagents.get_mut(&result.correlation_id)?;
        if !std::mem::take(open) {
            return None;
        }
        Some(self.subagent_event(
            "agent.result",
            &result.status,
            "tool_result",
            &result.correlation_id,
        ))
    }

    /// A subagent lifecycle event no native line states. `synthesized` marks it as inference,
    /// so it carries no `native` object; the links point at the evidence it was drawn from.
    fn subagent_event(
        &self,
        kind: &str,
        status: &str,
        evidence: &str,
        tool_id: &str,
    ) -> AdapterEvent {
        let provider = self.provider.id();
        let spawn = kind == "agent.spawn";
        let mut payload = json!({
            "provider": provider,
            "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
            "synthesized": true,
            "synthesized_from": evidence,
            "parent_tool_use_id": tool_id,
            "line": self.line_number,
        });
        if spawn {
            payload["parent_actor"] = json!(provider);
        }
        if let Some(tool) = self.tool_names.get(tool_id) {
            payload["tool"] = json!(tool);
        }
        let (agent_key, tool_key) = (format!("agent:{tool_id}"), format!("tool:{tool_id}"));
        let (parents, links) = if spawn {
            (
                vec![
                    tool_key.clone(),
                    TURN_KEY.to_owned(),
                    SESSION_KEY.to_owned(),
                ],
                vec![tool_key],
            )
        } else {
            (
                vec![agent_key.clone()],
                vec![agent_key.clone(), format!("result:{tool_id}")],
            )
        };
        AdapterEvent {
            input: EventInput {
                kind: kind.into(),
                source: format!("adapter.{provider}.v{ADAPTER_SCHEMA_VERSION}"),
                actor_id: format!("{provider}:subagent:{tool_id}"),
                actor_type: "subagent".into(),
                span_id: tool_id.into(),
                parent_span_id: self.session_id.clone(),
                correlation_id: tool_id.into(),
                status: status.into(),
                payload,
                ..EventInput::default()
            },
            opens: spawn.then_some(agent_key),
            weak: false,
            closes: None,
            parents,
            links,
        }
    }

    /// One event for a tool call or result that shares its native line with other content.
    fn part_event(
        &mut self,
        part: &Value,
        kind: &'static str,
        parent_tool: &str,
        native_timestamp: Option<&str>,
    ) -> EventInput {
        let correlation_id = string_at(
            part,
            &[&["tool_use_id"], &["tool_call_id"], &["call_id"], &["id"]],
        )
        .unwrap_or("")
        .to_owned();
        let tool = string_at(part, &[&["name"], &["function", "name"]]).map(str::to_owned);
        let tool = self.track_tool(kind, &correlation_id, tool);
        let failed = states_failure(part) || type_states_failure(&Value::Null, Some(part));
        let native_type = part
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("tool_call")
            .to_ascii_lowercase();
        let mut payload = json!({
            "provider": self.provider.id(),
            "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
            "native_type": native_type,
        });
        if let Some(tool) = tool {
            payload["tool"] = json!(tool);
        }
        if !parent_tool.is_empty() {
            payload["parent_actor"] = json!(self.provider.id());
        }
        if let Some(timestamp) = native_timestamp {
            payload["native_timestamp"] = json!(timestamp);
        }
        payload["native"] = part.clone();
        EventInput {
            kind: kind.into(),
            status: if failed {
                "error"
            } else if kind == "tool.result" {
                "ok"
            } else {
                "running"
            }
            .into(),
            payload,
            ..self.identified(correlation_id, parent_tool)
        }
    }

    /// Actor and span identity the provider states: the session is the root span and a Claude
    /// `parent_tool_use_id` names both the subagent and the tool call that spawned it.
    fn identified(&self, correlation_id: String, parent_tool: &str) -> EventInput {
        let provider = self.provider.id();
        let span_id = if correlation_id.is_empty() {
            self.session_id.clone()
        } else {
            correlation_id.clone()
        };
        let parent_span_id = if !parent_tool.is_empty() {
            parent_tool.to_owned()
        } else if span_id != self.session_id {
            self.session_id.clone()
        } else {
            String::new()
        };
        let (actor_id, actor_type) = if parent_tool.is_empty() {
            (provider.to_owned(), "agent")
        } else {
            (format!("{provider}:subagent:{parent_tool}"), "subagent")
        };
        EventInput {
            source: format!("adapter.{provider}.v{ADAPTER_SCHEMA_VERSION}"),
            actor_id,
            actor_type: actor_type.into(),
            span_id,
            parent_span_id,
            correlation_id,
            ..EventInput::default()
        }
    }

    /// Results rarely repeat the tool name, so remember it from the invocation sharing the id.
    fn track_tool(&mut self, kind: &str, id: &str, tool: Option<String>) -> Option<String> {
        if id.is_empty() {
            return tool;
        }
        match tool {
            Some(tool) => {
                if kind == "tool.invocation" {
                    if self.tool_names.len() >= MAX_TRACKED_TOOL_CALLS {
                        self.tool_names.clear();
                    }
                    self.tool_names.insert(id.to_owned(), tool.clone());
                }
                Some(tool)
            }
            None if kind == "tool.result" => self.tool_names.get(id).cloned(),
            None => None,
        }
    }
}

fn strip_terminal_prefix(mut line: &[u8]) -> &[u8] {
    loop {
        line = line.trim_ascii_start();
        if !line.starts_with(b"\x1b") {
            return line;
        }
        if line.starts_with(b"\x1b[") {
            let Some(end) = line[2..]
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))
            else {
                return line;
            };
            line = &line[end + 3..];
            continue;
        }
        if line.starts_with(b"\x1b]")
            && let Some(end) = line[2..].iter().position(|byte| *byte == 0x07)
        {
            line = &line[end + 3..];
            continue;
        }
        return line;
    }
}

/// Shrinks the stored copy of an oversized line: long strings keep a prefix plus an explicit
/// marker, and `native_truncated` records how much was dropped.
fn truncate_payload(payload: &mut Value, line_bytes: usize) {
    let mut stats = (0_u64, 0_u64);
    let mut candidate = payload.clone();
    truncate_strings(&mut candidate, TRUNCATED_STRING_BYTES, &mut stats);
    if serde_json::to_vec(&candidate).map_or(0, |bytes| bytes.len()) > MAX_NATIVE_LINE_BYTES {
        // Many medium strings: start over with a much smaller prefix.
        stats = (0, 0);
        candidate = payload.clone();
        truncate_strings(&mut candidate, TRUNCATED_STRING_BYTES / 32, &mut stats);
    }
    *payload = candidate;
    payload["native_truncated"] = json!({
        "line_bytes": line_bytes,
        "truncated_values": stats.0,
        "omitted_bytes": stats.1,
    });
}

fn truncate_strings(value: &mut Value, limit: usize, stats: &mut (u64, u64)) {
    match value {
        Value::String(text) if text.len() > limit => {
            let total = text.len();
            let mut keep = limit;
            while !text.is_char_boundary(keep) {
                keep -= 1;
            }
            text.truncate(keep);
            text.push_str(&format!(
                "… [premier truncated: kept {keep} of {total} bytes]"
            ));
            stats.0 += 1;
            stats.1 += (total - keep) as u64;
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                truncate_strings(value, limit, stats);
            }
        }
        Value::Array(items) => {
            for item in items {
                truncate_strings(item, limit, stats);
            }
        }
        _ => {}
    }
}

fn string_at<'a>(value: &'a Value, paths: &[&[&str]]) -> Option<&'a str> {
    paths.iter().find_map(|path| {
        let mut current = value;
        for key in *path {
            current = current.get(*key)?;
        }
        current.as_str()
    })
}

/// Lowercase words of a discriminator: `item.completed`, `tool_use` and `PreToolUse` split on
/// punctuation and case, so markers match whole words instead of substrings ("pending" is not
/// "end").
fn words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut after_lower = false;
    for character in value.chars() {
        let boundary = !character.is_alphanumeric() || (character.is_uppercase() && after_lower);
        if boundary && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        after_lower = character.is_lowercase() || character.is_ascii_digit();
        if character.is_alphanumeric() {
            word.extend(character.to_lowercase());
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

const COMPLETION_WORDS: &[&str] = &[
    "completed",
    "complete",
    "result",
    "results",
    "finish",
    "finished",
    "end",
    "ended",
];
const APPROVAL_WORDS: &[&str] = &["approval", "approvals", "permission", "permissions"];
const MESSAGE_WORDS: &[&str] = &["assistant", "message", "messages"];
const AGENT_WORDS: &[&str] = &["session", "thread", "agent", "step", "turn"];

fn is_tool_word(word: &str) -> bool {
    matches!(
        word,
        "tool" | "tools" | "toolcall" | "toolcalls" | "tooluse" | "toolresult" | "mcp"
    )
}

/// Every type-like value on a native line, each split into words.
struct Discriminators(Vec<Vec<String>>);

impl Discriminators {
    fn of(native: &Value) -> Self {
        let mut values = Vec::new();
        collect_discriminators(native, &mut values);
        Self(values.iter().map(|value| words(value)).collect())
    }

    fn has(&self, markers: &[&str]) -> bool {
        self.any(|word| markers.contains(&word))
    }

    fn any(&self, matches: impl Fn(&str) -> bool) -> bool {
        self.0.iter().flatten().any(|word| matches(word))
    }

    /// Two adjacent words of one value, such as `command_execution`.
    fn has_pair(&self, first: &str, second: &str) -> bool {
        self.0.iter().any(|value| {
            value
                .windows(2)
                .any(|pair| pair[0] == first && pair[1] == second)
        })
    }

    fn names_tool(&self) -> bool {
        self.any(is_tool_word)
            || self.has_pair("command", "execution")
            || self.has_pair("function", "call")
    }
}

fn collect_discriminators(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                // Tool arguments and output are caller data, not statements about the event.
                if matches!(
                    key.as_str(),
                    "input"
                        | "arguments"
                        | "args"
                        | "parameters"
                        | "output"
                        | "aggregated_output"
                        | "tool_input"
                        | "tool_response"
                ) {
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "type" | "subtype" | "kind" | "event" | "hook_name" | "role"
                ) && let Some(value) = value.as_str()
                {
                    output.push(value.to_owned());
                }
                collect_discriminators(value, output);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_discriminators(item, output);
            }
        }
        _ => {}
    }
}

/// A provider timestamp in a well-known field of the line (or its message, item or part),
/// normalized to RFC 3339 UTC. It is recorded beside the event, never as the event's own time:
/// that stays the recorder's receipt time.
fn native_timestamp(native: &Value) -> Option<String> {
    const KEYS: [&str; 6] = [
        "timestamp",
        "time",
        "created_at",
        "createdAt",
        "created",
        "ts",
    ];
    [
        Some(native),
        native.get("message"),
        native.get("item"),
        native.get("part"),
    ]
    .into_iter()
    .flatten()
    .find_map(|scope| {
        KEYS.iter()
            .find_map(|key| normalize_timestamp(scope.get(*key)?))
    })
}

fn normalize_timestamp(value: &Value) -> Option<String> {
    let instant = match value {
        Value::String(text) => {
            let text = text.trim();
            match DateTime::parse_from_rfc3339(text) {
                Ok(parsed) => parsed.with_timezone(&Utc),
                Err(_) => epoch_timestamp(text.parse().ok()?)?,
            }
        }
        Value::Number(number) => epoch_timestamp(number.as_f64()?)?,
        _ => return None,
    };
    Some(instant.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Epoch seconds or milliseconds. Values outside 2000-01-01..5138 in either unit are more
/// likely durations or counters than instants and are left alone.
fn epoch_timestamp(value: f64) -> Option<DateTime<Utc>> {
    const EARLIEST_SECONDS: f64 = 946_684_800.0;
    const LATEST_SECONDS: f64 = 100_000_000_000.0;
    let millis = if (EARLIEST_SECONDS..LATEST_SECONDS).contains(&value) {
        value * 1000.0
    } else if (EARLIEST_SECONDS * 1000.0..LATEST_SECONDS * 1000.0).contains(&value) {
        value
    } else {
        return None;
    };
    DateTime::from_timestamp_millis(millis.round() as i64)
}

/// Objects in which a provider states the outcome of the event itself: the line, its Codex
/// `item` or OpenCode `part`, and their `state`. Arguments, output and prose are never consulted.
fn outcome_scopes(native: &Value) -> Vec<&Value> {
    let mut scopes = vec![native];
    for key in ["item", "part"] {
        if let Some(inner) = native.get(key).filter(|inner| inner.is_object()) {
            scopes.push(inner);
        }
    }
    let states: Vec<_> = scopes
        .iter()
        .copied()
        .filter_map(|scope| scope.get("state").filter(|state| state.is_object()))
        .collect();
    scopes.extend(states);
    scopes
}

fn outcome_status(scope: &Value) -> Option<String> {
    ["status", "state"]
        .iter()
        .find_map(|key| scope.get(*key)?.as_str())
        .map(str::to_ascii_lowercase)
}

fn exit_code(scope: &Value) -> Option<&Value> {
    ["exit_code", "exitCode"]
        .iter()
        .find_map(|key| scope.get(*key))
        .filter(|code| !code.is_null())
}

fn is_completed(scopes: &[&Value], discriminators: &Discriminators) -> bool {
    discriminators.has(COMPLETION_WORDS)
        || scopes.iter().any(|scope| {
            exit_code(scope).is_some()
                || outcome_status(scope).is_some_and(|status| {
                    matches!(
                        status.as_str(),
                        "completed" | "complete" | "success" | "succeeded" | "done" | "finished"
                    )
                })
        })
}

/// True when the object carries an explicit failure field.
fn states_failure(scope: &Value) -> bool {
    ["is_error", "isError"]
        .iter()
        .any(|key| scope.get(*key).and_then(Value::as_bool) == Some(true))
        || outcome_status(scope).is_some_and(|status| {
            matches!(
                status.as_str(),
                "error" | "errored" | "failed" | "failure" | "denied" | "rejected"
            )
        })
        || exit_code(scope)
            .and_then(Value::as_i64)
            .is_some_and(|code| code != 0)
        || scope.get("error").is_some_and(|error| match error {
            Value::Null => false,
            Value::Bool(flag) => *flag,
            Value::Number(number) => number.as_f64() != Some(0.0),
            Value::String(text) => !text.is_empty(),
            Value::Array(items) => !items.is_empty(),
            Value::Object(object) => !object.is_empty(),
        })
}

/// True when the event's own type (never a nested argument's) names a failure, such as Codex
/// `turn.failed` or a Claude `error_max_turns` result subtype.
fn type_states_failure(native: &Value, block: Option<&Value>) -> bool {
    [
        native.get("type"),
        native.get("subtype"),
        native.get("event"),
        native.get("kind"),
        native.get("method"),
        native.get("item").and_then(|item| item.get("type")),
        native.get("part").and_then(|part| part.get("type")),
        block.and_then(|block| block.get("type")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .any(|value| {
        words(value).iter().any(|word| {
            matches!(
                word.as_str(),
                "error" | "errors" | "errored" | "fail" | "failed" | "failure"
            )
        })
    })
}

/// Keeps a refusal distinct from a grant instead of folding both into ok/error.
fn approval_decision(scopes: &[&Value]) -> Option<&'static str> {
    scopes.iter().find_map(|scope| {
        for key in ["approved", "allowed", "granted"] {
            if let Some(flag) = scope.get(key).and_then(Value::as_bool) {
                return Some(if flag { "approved" } else { "denied" });
            }
        }
        ["decision", "status", "state", "outcome", "behavior"]
            .iter()
            .filter_map(|key| scope.get(*key)?.as_str())
            .find_map(|value| match value.to_ascii_lowercase().as_str() {
                "approved" | "approve" | "allow" | "allowed" | "accepted" | "accept"
                | "granted" => Some("approved"),
                "denied" | "deny" | "rejected" | "reject" | "declined" | "blocked" => {
                    Some("denied")
                }
                _ => None,
            })
    })
}

/// Tool call and result blocks nested in a message, as Claude emits them.
fn tool_blocks(native: &Value) -> Vec<&Value> {
    [
        native
            .get("message")
            .and_then(|message| message.get("content")),
        native.get("content"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_array)
    .flatten()
    .filter(|block| {
        block
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| words(kind).iter().any(|word| is_tool_word(word)))
    })
    .collect()
}

fn block_kind(block: &Value) -> &'static str {
    let result = block
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| words(kind).iter().any(|word| word == "result"));
    lifecycle_kind(result, "tool.result", "tool.invocation")
}

/// OpenAI-style `tool_calls` requested by an assistant message, as Kimi emits them.
fn function_calls(native: &Value) -> Vec<&Value> {
    [
        native.get("tool_calls"),
        native
            .get("message")
            .and_then(|message| message.get("tool_calls")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_array)
    .flatten()
    .filter(|call| call.is_object())
    .collect()
}

const TOOL_ID_KEYS: [&str; 7] = [
    "call_id",
    "tool_use_id",
    "tool_call_id",
    "tool_id",
    "callID",
    "toolCallId",
    "toolUseId",
];

const CORRELATION_PATHS: &[&[&str]] = &[
    &["call_id"],
    &["tool_use_id"],
    &["tool_call_id"],
    &["item", "id"],
    &["message", "id"],
    &["request_id"],
    &["uuid"],
    &["id"],
    &["session_id"],
    &["thread_id"],
];

const SESSION_ID_PATHS: &[&[&str]] = &[
    &["session_id"],
    &["sessionID"],
    &["sessionId"],
    &["thread_id"],
    &["threadId"],
    &["part", "sessionID"],
];

const MODEL_PATHS: &[&[&str]] = &[
    &["model"],
    &["message", "model"],
    &["item", "model"],
    &["response", "model"],
    &["part", "model"],
    &["modelID"],
    &["part", "modelID"],
];

fn keyed_tool_id(scope: &Value) -> Option<&str> {
    TOOL_ID_KEYS
        .iter()
        .find_map(|key| scope.get(*key)?.as_str())
}

/// The id a tool call and its result share, wherever the provider puts it.
fn tool_correlation<'a>(native: &'a Value, block: Option<&'a Value>) -> Option<&'a str> {
    keyed_tool_id(native)
        .or_else(|| native.get("part").and_then(keyed_tool_id))
        .or_else(|| native.get("item").and_then(keyed_tool_id))
        .or_else(|| {
            let block = block?;
            keyed_tool_id(block).or_else(|| block.get("id")?.as_str())
        })
        .or_else(|| string_at(native, &[&["item", "id"], &["id"]]))
}

fn tool_name<'a>(native: &'a Value, block: Option<&'a Value>) -> Option<&'a str> {
    block
        .and_then(|block| block.get("name")?.as_str())
        .or_else(|| {
            string_at(
                native,
                &[
                    &["tool_name"],
                    &["toolName"],
                    &["tool"],
                    &["item", "tool"],
                    &["item", "name"],
                    &["part", "tool"],
                    &["part", "name"],
                    &["function", "name"],
                    &["name"],
                    // Codex names built-in tools only by item type, e.g. command_execution.
                    &["item", "type"],
                ],
            )
        })
}

/// Token usage under the field names the demo and SDK examples use, so one reader serves all.
fn normalized_usage(native: &Value) -> Option<Value> {
    const SOURCES: &[&[&str]] = &[
        &["usage"],
        &["message", "usage"],
        &["item", "usage"],
        &["response", "usage"],
        &["part", "usage"],
        &["part", "tokens"],
        &["tokens"],
        &["stats"],
    ];
    let source = SOURCES.iter().find_map(|path| {
        let mut current = native;
        for key in *path {
            current = current.get(*key)?;
        }
        current.is_object().then_some(current)
    });
    let number = |keys: &[&str]| keys.iter().find_map(|key| source?.get(*key)?.as_u64());
    let nested = |object: &str, key: &str| source?.get(object)?.get(key)?.as_u64();
    let input = number(&["input_tokens", "prompt_tokens", "inputTokens", "input"]);
    let output = number(&[
        "output_tokens",
        "completion_tokens",
        "outputTokens",
        "output",
    ]);
    let total =
        number(&["total_tokens", "totalTokens", "total"]).or_else(|| Some(input? + output?));
    let cached = number(&[
        "cached_input_tokens",
        "cache_read_input_tokens",
        "cached_tokens",
    ])
    .or_else(|| nested("input_tokens_details", "cached_tokens"))
    .or_else(|| nested("cache", "read"));
    let reasoning = number(&["reasoning_output_tokens", "reasoning_tokens", "reasoning"])
        .or_else(|| nested("output_tokens_details", "reasoning_tokens"));
    let cost = [
        native.get("total_cost_usd"),
        native.get("cost_usd"),
        source.and_then(|usage| usage.get("cost_usd")),
        native.get("part").and_then(|part| part.get("cost")),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_f64);
    let mut usage = serde_json::Map::new();
    for (key, value) in [
        ("input_tokens", input),
        ("output_tokens", output),
        ("total_tokens", total),
    ] {
        if let Some(value) = value {
            usage.insert(key.into(), json!(value));
        }
    }
    if let Some(cached) = cached {
        usage.insert(
            "input_tokens_details".into(),
            json!({"cached_tokens": cached}),
        );
    }
    if let Some(reasoning) = reasoning {
        usage.insert(
            "output_tokens_details".into(),
            json!({"reasoning_tokens": reasoning}),
        );
    }
    if let Some(cost) = cost {
        usage.insert("cost_usd".into(), json!(cost));
    }
    (!usage.is_empty()).then_some(Value::Object(usage))
}

/// Session and turn boundaries a provider states with an exact line type: Claude `system`/`init`
/// and `result`, Codex `thread.started` and `turn.*`, Gemini `init` and `result`.
fn lifecycle_phase(provider: Provider, native: &Value) -> Option<Phase> {
    let lower = |key: &str| {
        native
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    let kind = lower("type")?;
    match kind.as_str() {
        "system" if lower("subtype").as_deref() == Some("init") => Some(Phase::SessionStart),
        "init" | "thread.started" | "session.started" | "session.start" => {
            Some(Phase::SessionStart)
        }
        "turn.started" => Some(Phase::TurnStart),
        // Droid's JSON mode prints one result object and nothing before it: that object is
        // the model's answer, not the end of a recorded turn.
        "result" if provider != Provider::Droid => Some(Phase::RunResult),
        "turn.completed" | "turn.failed" => Some(Phase::RunResult),
        _ => None,
    }
}

fn classify_kind(
    provider: Provider,
    native: &Value,
    discriminators: &Discriminators,
    phase: Option<Phase>,
    completed: bool,
) -> &'static str {
    if let Some(phase) = phase {
        return phase.kind();
    }
    let native_type = native.get("type").and_then(Value::as_str);
    if provider == Provider::Droid && native_type == Some("result") {
        return "model.response";
    }
    if provider == Provider::Kimi && native.get("role").and_then(Value::as_str) == Some("tool") {
        return "tool.result";
    }
    // OpenCode streams assistant prose as bare `text` parts.
    if provider == Provider::Opencode && native_type == Some("text") {
        return "model.response";
    }
    if discriminators.has(APPROVAL_WORDS) {
        return lifecycle_kind(completed, "approval.decision", "approval.request");
    }
    if discriminators.names_tool() {
        return lifecycle_kind(completed, "tool.result", "tool.invocation");
    }
    let message = discriminators.has(MESSAGE_WORDS);
    if message || discriminators.has(&["model"]) {
        return lifecycle_kind(completed || message, "model.response", "model.request");
    }
    if discriminators.has(AGENT_WORDS) {
        return lifecycle_kind(completed, "agent.result", "agent.turn");
    }
    "provider.event"
}

fn lifecycle_kind(
    completed: bool,
    completed_kind: &'static str,
    running_kind: &'static str,
) -> &'static str {
    if completed {
        completed_kind
    } else {
        running_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn lines(provider: Provider, natives: &[Value]) -> Vec<AdapterEvent> {
        let mut adapter = NativeAdapter::new(provider);
        natives
            .iter()
            .flat_map(|native| adapter.push(format!("{native}\n").as_bytes()))
            .collect()
    }

    fn one(provider: Provider, native: Value) -> AdapterEvent {
        let mut events = lines(provider, &[native]);
        assert_eq!(events.len(), 1, "{events:?}");
        events.remove(0)
    }

    /// Feeds `chunks` through push and commit the way the recorder does, with `e1`, `e2`, …
    /// standing in for the ids the writer assigns.
    fn stored(provider: Provider, chunks: &[&[u8]]) -> Vec<EventInput> {
        let mut adapter = NativeAdapter::new(provider);
        let mut stored = Vec::new();
        for chunk in chunks {
            let events = adapter.push(chunk);
            adapter
                .commit(events, |input| {
                    stored.push(input);
                    Ok::<_, std::convert::Infallible>(format!("e{}", stored.len()))
                })
                .unwrap();
        }
        stored
    }

    fn stored_lines(provider: Provider, natives: &[Value]) -> Vec<EventInput> {
        let chunks: Vec<_> = natives.iter().map(|native| format!("{native}\n")).collect();
        let chunks: Vec<_> = chunks.iter().map(String::as_bytes).collect();
        stored(provider, &chunks)
    }

    #[test]
    fn auto_only_activates_for_native_structured_output() {
        assert_eq!(
            AdapterChoice::Auto.resolve("codex", &["exec".into(), "--json".into()], false),
            Some(Provider::Codex)
        );
        assert_eq!(
            AdapterChoice::Auto.resolve("codex", &["exec".into()], false),
            None
        );
        assert_eq!(
            AdapterChoice::Auto.resolve("claude", &["--output-format=stream-json".into()], false),
            Some(Provider::Claude)
        );
        assert_eq!(AdapterChoice::Codex.resolve("anything", &[], true), None);
    }

    #[test]
    fn provider_fixtures_normalize_to_typed_events() {
        type Row = (&'static str, &'static str, &'static str);
        let cases: [(Provider, &[u8], &[Row]); 7] = [
            (
                Provider::Claude,
                include_bytes!("../tests/fixtures/adapters/claude.jsonl"),
                &[
                    ("agent.turn", "running", "claude-session"),
                    ("model.response", "ok", "msg-1"),
                    ("tool.invocation", "running", "tool-1"),
                    ("tool.invocation", "running", "tool-1"),
                    ("tool.result", "ok", "tool-1"),
                    ("tool.invocation", "running", "tool-2"),
                    ("tool.result", "error", "tool-2"),
                    ("tool.invocation", "running", "tool-3"),
                    ("agent.spawn", "running", "tool-3"),
                    ("tool.invocation", "running", "tool-4"),
                    ("tool.result", "ok", "tool-4"),
                    ("model.response", "ok", "msg-6"),
                    ("tool.result", "ok", "tool-3"),
                    ("agent.result", "ok", "tool-3"),
                    ("model.response", "ok", "msg-7"),
                    ("agent.result", "ok", "claude-session"),
                ],
            ),
            (
                Provider::Codex,
                include_bytes!("../tests/fixtures/adapters/codex.jsonl"),
                &[
                    ("agent.turn", "running", "codex-thread"),
                    ("agent.turn", "running", "codex-thread"),
                    ("provider.event", "ok", "item_0"),
                    ("tool.invocation", "running", "item_1"),
                    ("tool.result", "ok", "item_1"),
                    ("tool.invocation", "running", "item_2"),
                    ("tool.result", "error", "item_2"),
                    ("model.response", "ok", "item_3"),
                    ("agent.result", "ok", "codex-thread"),
                ],
            ),
            (
                Provider::Gemini,
                include_bytes!("../tests/fixtures/adapters/gemini.jsonl"),
                &[
                    ("agent.turn", "running", "gemini-session"),
                    ("model.response", "ok", ""),
                    ("model.response", "ok", ""),
                    ("tool.invocation", "running", "read_file-1"),
                    ("tool.result", "ok", "read_file-1"),
                    ("tool.invocation", "running", "run_shell_command-2"),
                    ("tool.result", "error", "run_shell_command-2"),
                    ("model.response", "ok", ""),
                    ("agent.result", "ok", "gemini-session"),
                ],
            ),
            (
                Provider::Grok,
                include_bytes!("../tests/fixtures/adapters/grok.jsonl"),
                &[
                    ("agent.turn", "running", "grok-session"),
                    ("model.response", "ok", "msg-1"),
                    ("tool.invocation", "running", "call-1"),
                    ("tool.result", "ok", "call-1"),
                    ("tool.invocation", "running", "call-2"),
                    ("tool.result", "error", "call-2"),
                    ("model.response", "ok", "msg-2"),
                    ("agent.result", "ok", "grok-session"),
                ],
            ),
            (
                Provider::Opencode,
                include_bytes!("../tests/fixtures/adapters/opencode.jsonl"),
                &[
                    ("agent.turn", "running", "open-session"),
                    ("model.response", "ok", ""),
                    ("tool.result", "ok", "tool-1"),
                    ("tool.result", "error", "tool-2"),
                    ("agent.result", "ok", "open-session"),
                    ("agent.turn", "running", "open-session"),
                    ("model.response", "ok", ""),
                    ("agent.result", "ok", "open-session"),
                ],
            ),
            (
                Provider::Kimi,
                include_bytes!("../tests/fixtures/adapters/kimi.jsonl"),
                &[
                    ("model.response", "ok", ""),
                    ("tool.invocation", "running", "call-1"),
                    ("tool.result", "ok", "call-1"),
                    ("model.response", "ok", ""),
                    ("tool.invocation", "running", "call-2"),
                    // Kimi states this failure only in the result text, which is not evidence.
                    ("tool.result", "ok", "call-2"),
                    ("model.response", "ok", ""),
                    ("tool.invocation", "running", "call-3"),
                    ("tool.invocation", "running", "call-4"),
                    ("tool.result", "ok", "call-3"),
                    ("tool.result", "error", "call-4"),
                    ("model.response", "ok", ""),
                ],
            ),
            (
                Provider::Droid,
                include_bytes!("../tests/fixtures/adapters/droid.jsonl"),
                &[("model.response", "ok", "droid-session")],
            ),
        ];
        for (provider, fixture, expected) in cases {
            let events = stored(provider, &[fixture]);
            let rows: Vec<(&str, &str, &str)> = events
                .iter()
                .map(|event| {
                    (
                        event.kind.as_str(),
                        event.status.as_str(),
                        event.correlation_id.as_str(),
                    )
                })
                .collect();
            assert_eq!(rows, expected, "{}", provider.id());
            assert!(
                events
                    .iter()
                    .all(|event| event.source == format!("adapter.{}.v1", provider.id()))
            );
            for (index, event) in events.iter().enumerate() {
                // A parent or link is always an event stored earlier.
                for reference in event.links.iter().chain([&event.parent_event_id]) {
                    let earlier = reference
                        .strip_prefix('e')
                        .map(|id| id.parse::<usize>().unwrap());
                    assert!(
                        reference.is_empty() || earlier.is_some_and(|id| id <= index),
                        "{event:?}"
                    );
                }
                // Every paired tool result names the call it answers.
                let mut calls = (0..index).filter(|earlier| {
                    events[*earlier].kind == "tool.invocation"
                        && events[*earlier].correlation_id == event.correlation_id
                });
                if event.kind == "tool.result" && calls.clone().next().is_some() {
                    assert!(
                        calls.any(|call| event.links == [format!("e{}", call + 1)]),
                        "{event:?}"
                    );
                    assert_eq!(event.parent_event_id, event.links[0], "{event:?}");
                }
            }
        }
    }

    #[test]
    fn stored_event_ids_become_parents_and_links() {
        let events = stored_lines(
            Provider::Claude,
            &[
                json!({"type": "system", "subtype": "init", "session_id": "s", "uuid": "u-0"}),
                json!({"type": "hook_started", "hook_name": "PreToolUse",
                       "tool_use_id": "toolu_01", "tool_name": "Bash"}),
                json!({"type": "permission_request", "tool_use_id": "toolu_01"}),
                json!({"type": "permission_response", "tool_use_id": "toolu_01",
                       "behavior": "allow"}),
                json!({"type": "assistant", "session_id": "s", "message": {"id": "msg_1",
                       "content": [{"type": "tool_use", "id": "toolu_01", "name": "Bash"}]}}),
                json!({"type": "hook_started", "hook_name": "PostToolUse",
                       "tool_use_id": "toolu_01", "tool_name": "Bash"}),
                json!({"type": "user", "session_id": "s", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"},
                    {"type": "tool_result", "tool_use_id": "toolu_lost", "content": "ok"}
                ]}}),
                json!({"type": "result", "subtype": "success", "session_id": "s", "uuid": "u-9"}),
            ],
        );
        let shape: Vec<_> = events
            .iter()
            .map(|event| {
                (
                    event.kind.as_str(),
                    event.parent_event_id.as_str(),
                    event.links.join(","),
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                ("agent.turn", "", String::new()),
                ("tool.invocation", "e1", String::new()),
                // Until the call itself is stored, the hook line stands in for it.
                ("approval.request", "e2", String::new()),
                ("approval.decision", "e3", "e3".into()),
                ("tool.invocation", "e1", String::new()),
                // A later hook hangs off the call instead of replacing it.
                ("tool.invocation", "e5", String::new()),
                ("tool.result", "e5", "e5".into()),
                // A result whose call was never seen still belongs to the session.
                ("tool.result", "e1", String::new()),
                ("agent.result", "e1", String::new()),
            ]
        );
        // The session's start and result pair through the session id, not their own uuids.
        assert_eq!(events[0].correlation_id, "s");
        assert_eq!(events[8].correlation_id, "s");
        assert_eq!(events[0].payload["lifecycle"], "session_start");
        assert_eq!(events[0].payload["session_id"], "s");

        let codex = stored_lines(
            Provider::Codex,
            &[
                json!({"type": "thread.started", "thread_id": "t"}),
                json!({"type": "turn.started"}),
                json!({"type": "item.completed", "item": {"id": "m", "type": "agent_message"}}),
                json!({"type": "turn.completed"}),
                json!({"type": "turn.started"}),
                json!({"type": "turn.failed", "error": {"message": "quota"}}),
            ],
        );
        let parents: Vec<_> = codex
            .iter()
            .map(|event| event.parent_event_id.as_str())
            .collect();
        // Work hangs off its turn, a turn off the thread, and a closed turn adopts nothing.
        assert_eq!(parents, ["", "e1", "e2", "e2", "e1", "e5"]);
        assert_eq!(codex[1].payload["lifecycle"], "turn_start");
        assert_eq!(codex[5].payload["lifecycle"], "run_result");
        assert_eq!(codex[5].status, "error");
    }

    #[test]
    fn remembered_event_ids_stay_bounded() {
        let mut adapter = NativeAdapter::new(Provider::Gemini);
        let mut count = 0_usize;
        let mut feed = |adapter: &mut NativeAdapter, native: Value| {
            let events = adapter.push(format!("{native}\n").as_bytes());
            adapter
                .commit(events, |_| {
                    count += 1;
                    Ok::<_, std::convert::Infallible>(format!("e{count}"))
                })
                .unwrap();
        };
        feed(&mut adapter, json!({"type": "init", "session_id": "s"}));
        for index in 0..MAX_TRACKED_EVENT_IDS + 10 {
            feed(
                &mut adapter,
                json!({"type": "tool_use", "tool_id": format!("t{index}")}),
            );
            assert!(adapter.event_ids.len() <= MAX_TRACKED_EVENT_IDS);
        }
        assert_eq!(adapter.event_ids[SESSION_KEY].event_id, "e1");
    }

    #[test]
    fn subagent_lifecycle_is_synthesized_and_marked() {
        let events = stored_lines(
            Provider::Claude,
            &[
                json!({"type": "system", "subtype": "init", "session_id": "s"}),
                json!({"type": "assistant", "session_id": "s", "message": {"id": "m1", "content": [
                    {"type": "tool_use", "id": "task_1", "name": "Task", "input": {}}]}}),
                json!({"type": "assistant", "session_id": "s", "parent_tool_use_id": "task_1",
                       "message": {"id": "m2", "content": [
                    {"type": "tool_use", "id": "task_2", "name": "Task", "input": {}}]}}),
                json!({"type": "assistant", "session_id": "s", "parent_tool_use_id": "task_2",
                       "message": {"id": "m3", "content": [{"type": "text", "text": "deep"}]}}),
                json!({"type": "user", "session_id": "s", "parent_tool_use_id": "task_1",
                       "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "task_2", "is_error": true}]}}),
                json!({"type": "user", "session_id": "s", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "task_1", "content": "done"}]}}),
                // A straggler after the spawning call returned does not reopen the subagent.
                json!({"type": "assistant", "session_id": "s", "parent_tool_use_id": "task_1",
                       "message": {"id": "m4", "content": [{"type": "text", "text": "late"}]}}),
            ],
        );
        let kinds: Vec<_> = events.iter().map(|event| event.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "agent.turn",
                "tool.invocation",
                "agent.spawn",
                "tool.invocation",
                "agent.spawn",
                "model.response",
                "tool.result",
                "agent.result",
                "tool.result",
                "agent.result",
                "model.response",
            ]
        );
        let outer = &events[2];
        assert_eq!(outer.actor_id, "claude:subagent:task_1");
        assert_eq!(outer.actor_type, "subagent");
        assert_eq!(outer.source, "adapter.claude.v1");
        assert_eq!(outer.status, "running");
        assert_eq!(outer.parent_event_id, "e2");
        assert_eq!(outer.links, ["e2"]);
        assert_eq!(outer.span_id, "task_1");
        assert_eq!(outer.parent_span_id, "s");
        assert_eq!(outer.correlation_id, "task_1");
        assert_eq!(
            outer.payload,
            json!({"provider": "claude", "adapter_schema_version": 1, "synthesized": true,
                   "synthesized_from": "parent_tool_use_id", "parent_tool_use_id": "task_1",
                   "parent_actor": "claude", "tool": "Task", "line": 3})
        );
        // The subagent's own events hang off its spawn and are not marked as inference.
        assert_eq!(events[3].parent_event_id, "e3");
        assert!(events[3].payload.get("synthesized").is_none());

        // A nested subagent descends from the subagent whose tool call spawned it.
        let inner = &events[4];
        assert_eq!(inner.actor_id, "claude:subagent:task_2");
        assert_eq!(inner.parent_event_id, "e4");
        assert_eq!(inner.payload["parent_actor"], "claude:subagent:task_1");
        assert_eq!(events[5].parent_event_id, "e5");

        let failed = &events[7];
        assert_eq!(failed.actor_id, "claude:subagent:task_2");
        assert_eq!(failed.status, "error");
        assert_eq!(failed.parent_event_id, "e5");
        assert_eq!(failed.links, ["e5", "e7"]);
        assert_eq!(failed.payload["synthesized_from"], "tool_result");
        let finished = &events[9];
        assert_eq!(finished.status, "ok");
        assert_eq!(finished.correlation_id, "task_1");
        assert_eq!(finished.links, ["e3", "e9"]);
        assert_eq!(
            finished.payload,
            json!({"provider": "claude", "adapter_schema_version": 1, "synthesized": true,
                   "synthesized_from": "tool_result", "parent_tool_use_id": "task_1",
                   "tool": "Task", "line": 6})
        );
        assert_eq!(events[10].parent_event_id, "e3");
    }

    #[test]
    fn lifecycle_markers_match_whole_words() {
        assert_eq!(words("item.completed"), ["item", "completed"]);
        assert_eq!(words("PreToolUse"), ["pre", "tool", "use"]);
        assert_eq!(words("mcp__logs__search"), ["mcp", "logs", "search"]);
        assert_eq!(words("step-finish"), ["step", "finish"]);

        // "pending" contains "end" but does not say the call ended.
        let pending = one(
            Provider::Grok,
            json!({"type": "tool_call", "subtype": "pending", "call_id": "c1", "name": "bash"}),
        );
        assert_eq!(pending.kind, "tool.invocation");
        assert_eq!(pending.status, "running");
        let ended = one(
            Provider::Grok,
            json!({"type": "tool_call", "subtype": "end", "call_id": "c1"}),
        );
        assert_eq!(ended.kind, "tool.result");

        for (native, kind) in [
            // Words that merely contain a marker are not that marker.
            (json!({"type": "stool_sample"}), "provider.event"),
            (json!({"type": "remodel"}), "provider.event"),
            (json!({"type": "terrorism_report"}), "provider.event"),
            (json!({"type": "function", "id": "f"}), "provider.event"),
            (
                json!({"type": "function_call", "call_id": "f"}),
                "tool.invocation",
            ),
            (
                json!({"type": "mcp_call", "call_id": "f"}),
                "tool.invocation",
            ),
            (
                json!({"type": "toolCall", "call_id": "f"}),
                "tool.invocation",
            ),
            (json!({"type": "turn_start"}), "agent.turn"),
            (json!({"type": "turn_end"}), "agent.result"),
        ] {
            let event = one(Provider::Grok, native);
            assert_eq!(event.kind, kind, "{event:?}");
            assert_ne!(event.status, "error", "{event:?}");
        }
    }

    #[test]
    fn session_start_and_final_result_lines_are_typed_with_usage_and_cost() {
        let claude = one(
            Provider::Claude,
            json!({"type": "result", "subtype": "success", "is_error": false,
                   "duration_ms": 4210, "num_turns": 5, "session_id": "s", "uuid": "u",
                   "total_cost_usd": 0.5, "permission_denials": [],
                   "usage": {"input_tokens": 100, "output_tokens": 20,
                             "cache_read_input_tokens": 7}}),
        );
        assert_eq!(claude.kind, "agent.result");
        assert_eq!(claude.status, "ok");
        assert_eq!(claude.duration_ms, 4210);
        assert_eq!(claude.correlation_id, "s");
        assert_eq!(claude.span_id, "s");
        assert_eq!(claude.payload["lifecycle"], "run_result");
        assert_eq!(
            claude.payload["usage"],
            json!({"input_tokens": 100, "output_tokens": 20, "total_tokens": 120,
                   "input_tokens_details": {"cached_tokens": 7}, "cost_usd": 0.5})
        );
        let failed = one(
            Provider::Claude,
            json!({"type": "result", "subtype": "error_max_turns", "is_error": true,
                   "session_id": "s"}),
        );
        assert_eq!(failed.kind, "agent.result");
        assert_eq!(failed.status, "error");

        let gemini = lines(
            Provider::Gemini,
            &[
                json!({"type": "init", "session_id": "g", "model": "gemini-test"}),
                json!({"type": "result", "status": "success", "stats": {
                    "total_tokens": 30, "input_tokens": 20, "output_tokens": 10,
                    "duration_ms": 900}}),
            ],
        );
        assert_eq!(gemini[0].kind, "agent.turn");
        assert_eq!(gemini[0].status, "running");
        assert_eq!(gemini[0].payload["lifecycle"], "session_start");
        assert_eq!(gemini[0].payload["model"], "gemini-test");
        assert_eq!(gemini[1].kind, "agent.result");
        assert_eq!(gemini[1].correlation_id, "g");
        assert_eq!(gemini[1].duration_ms, 900);
        assert_eq!(gemini[1].payload["usage"]["total_tokens"], 30);

        let opencode = one(
            Provider::Opencode,
            json!({"type": "text", "sessionID": "o", "part": {"type": "text", "text": "hi"}}),
        );
        assert_eq!(opencode.kind, "model.response");
    }

    #[test]
    fn native_timestamps_are_recorded_beside_the_receipt_time() {
        for (native, expected) in [
            (
                json!({"type": "message", "timestamp": "2026-03-04T12:15:00.120+02:00"}),
                Some("2026-03-04T10:15:00.120Z"),
            ),
            (
                json!({"type": "message", "ts": 1_772_619_300}),
                Some("2026-03-04T10:15:00.000Z"),
            ),
            (
                json!({"type": "message", "time": 1_772_619_300_120_u64}),
                Some("2026-03-04T10:15:00.120Z"),
            ),
            (
                json!({"type": "message", "created_at": 1_772_619_300.5}),
                Some("2026-03-04T10:15:00.500Z"),
            ),
            (
                json!({"type": "message", "created_at": "1772619300"}),
                Some("2026-03-04T10:15:00.000Z"),
            ),
            (
                json!({"type": "item.completed", "item": {"id": "i", "type": "agent_message",
                       "created_at": "2026-03-04T10:15:00Z"}}),
                Some("2026-03-04T10:15:00.000Z"),
            ),
            // An elapsed time, an unparseable value and an object are not instants.
            (json!({"type": "message", "time": 12}), None),
            (json!({"type": "message", "timestamp": "yesterday"}), None),
            (
                json!({"type": "message", "time": {"start": 1_772_619_300}}),
                None,
            ),
            (json!({"type": "message"}), None),
        ] {
            let event = one(Provider::Grok, native);
            assert_eq!(
                event
                    .payload
                    .get("native_timestamp")
                    .and_then(Value::as_str),
                expected,
                "{:?}",
                event.payload
            );
            // The event's own time is left to the writer: its receipt time.
            assert_eq!(event.timestamp, None);
        }

        // Every event cut from one line carries that line's provider time.
        let parts = lines(
            Provider::Claude,
            &[
                json!({"type": "assistant", "timestamp": "2026-03-04T10:15:00Z",
                     "parent_tool_use_id": "task_1", "message": {"id": "m", "content": [
                {"type": "tool_use", "id": "a", "name": "Read"},
                {"type": "tool_use", "id": "b", "name": "Grep"}]}}),
            ],
        );
        assert_eq!(parts.len(), 3);
        assert!(parts[0].payload.get("native_timestamp").is_none());
        assert_eq!(parts[0].timestamp, None);
        for part in &parts[1..] {
            assert_eq!(part.payload["native_timestamp"], "2026-03-04T10:15:00.000Z");
        }
    }

    #[test]
    fn fragmented_and_malformed_lines_are_bounded_and_diagnostic() {
        let mut adapter = NativeAdapter::new(Provider::Codex);
        assert!(adapter.push(b"{\"type\":\"item.").is_empty());
        let events = adapter.push(
            b"completed\",\"item\":{\"type\":\"command_execution\",\"id\":\"x\"}}\nnot-json\n",
        );
        assert_eq!(events[0].kind, "tool.result");
        assert_eq!(events[1].kind, "adapter.diagnostic");
        let mut oversized = vec![b'x'; MAX_NATIVE_LINE_BYTES + 10];
        oversized.push(b'\n');
        let events = adapter.push(&oversized);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "adapter.diagnostic");
        let message = events[0].payload["message"].as_str().unwrap();
        assert!(message.contains("oversized"), "{message}");
        assert!(message.contains(&(MAX_NATIVE_LINE_BYTES + 10).to_string()));
        assert_eq!(events[0].payload["line_bytes"], MAX_NATIVE_LINE_BYTES + 10);
        assert!(adapter.pending.is_empty());
    }

    #[test]
    fn oversized_failing_tool_result_stays_typed_with_truncated_native_copy() {
        let mut adapter = NativeAdapter::new(Provider::Codex);
        let line = json!({"type": "item.completed", "item": {
            "id": "cmd-9", "type": "command_execution", "command": "cargo test",
            "exit_code": 101, "aggregated_output": "é".repeat(200 * 1024)
        }})
        .to_string();
        assert!(line.len() > MAX_NATIVE_LINE_BYTES);
        let events = adapter.push(format!("{line}\n").as_bytes());
        assert_eq!(events.len(), 1, "{:?}", events[0].kind);
        let event = &events[0];
        assert_eq!(event.kind, "tool.result");
        assert_eq!(event.status, "error");
        assert_eq!(event.correlation_id, "cmd-9");
        let output = event.payload["native"]["item"]["aggregated_output"]
            .as_str()
            .unwrap();
        assert!(output.len() < TRUNCATED_STRING_BYTES + 128);
        assert!(
            output.ends_with(&format!("of {} bytes]", 400 * 1024)),
            "{}",
            &output[output.len() - 80..]
        );
        assert_eq!(event.payload["native_truncated"]["line_bytes"], line.len());
        assert_eq!(event.payload["native_truncated"]["truncated_values"], 1);
        assert!(event.payload.to_string().len() < MAX_NATIVE_LINE_BYTES);
    }

    #[test]
    fn lines_beyond_the_buffer_bound_are_discarded_with_their_size() {
        let mut adapter = NativeAdapter::new(Provider::Codex);
        assert!(
            adapter
                .push(&vec![b'x'; MAX_BUFFERED_LINE_BYTES + 5])
                .is_empty()
        );
        assert!(adapter.pending.len() <= MAX_BUFFERED_LINE_BYTES);
        let events = adapter.push(b"\n{\"type\":\"thread.started\",\"thread_id\":\"t\"}\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "adapter.diagnostic");
        assert_eq!(events[0].payload["line_bytes"], MAX_BUFFERED_LINE_BYTES + 5);
        assert!(
            events[0].payload["message"]
                .as_str()
                .unwrap()
                .contains("discarded")
        );
        assert_eq!(events[1].kind, "agent.turn");

        let mut unterminated = NativeAdapter::new(Provider::Codex);
        unterminated.push(&vec![b'x'; MAX_BUFFERED_LINE_BYTES + 1]);
        let events = unterminated.finish();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "adapter.diagnostic");
    }

    #[test]
    fn nested_tool_content_and_nonzero_exit_are_normalized_truthfully() {
        let event = one(
            Provider::Claude,
            json!({
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "call-1"}]},
                "item": {"id": "call-1", "exit_code": 7, "duration_ms": 42}
            }),
        );
        assert_eq!(event.kind, "tool.result");
        assert_eq!(event.status, "error");
        assert_eq!(event.duration_ms, 42);
        assert_eq!(event.correlation_id, "call-1");
    }

    #[test]
    fn failure_comes_from_explicit_fields_not_arguments_or_text() {
        let failed = one(
            Provider::Claude,
            json!({"type": "user", "uuid": "u-3", "session_id": "s", "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_01",
                             "is_error": true, "content": "boom"}]
            }}),
        );
        assert_eq!(failed.kind, "tool.result");
        assert_eq!(failed.status, "error");

        let healthy = one(
            Provider::Claude,
            json!({"type": "assistant", "message": {"id": "msg_1", "content": [
                {"type": "tool_use", "id": "toolu_02", "name": "mcp__logs__search",
                 "input": {"filter": {"type": "error", "kind": "failed_login"},
                           "status": "failed", "is_error": true}}
            ]}}),
        );
        assert_eq!(healthy.kind, "tool.invocation");
        assert_eq!(healthy.status, "running");

        let prose = one(
            Provider::Grok,
            json!({"type": "assistant.message", "id": "m",
                   "content": "the build failed with an error"}),
        );
        assert_eq!(prose.status, "ok");

        for (provider, native, kind) in [
            (
                Provider::Droid,
                json!({"type": "result", "subtype": "success", "is_error": true, "result": "x"}),
                "model.response",
            ),
            (
                Provider::Gemini,
                json!({"type": "tool_result", "tool_id": "t1", "status": "error"}),
                "tool.result",
            ),
            (
                Provider::Opencode,
                json!({"type": "tool_use", "part": {"type": "tool", "callID": "c1", "tool": "bash",
                       "state": {"status": "error", "error": "exit 1"}}}),
                "tool.result",
            ),
            (
                Provider::Codex,
                json!({"type": "turn.failed", "error": {"message": "quota"}}),
                "agent.result",
            ),
            (
                Provider::Claude,
                json!({"type": "result", "subtype": "error_during_execution", "is_error": false}),
                "agent.result",
            ),
        ] {
            let event = one(provider, native);
            assert_eq!(event.kind, kind, "{event:?}");
            assert_eq!(event.status, "error", "{event:?}");
        }

        // A null exit code on a started item is neither a completion nor a failure.
        let started = one(
            Provider::Codex,
            json!({"type": "item.started", "item": {"id": "i", "type": "command_execution",
                   "exit_code": null, "status": "in_progress"}}),
        );
        assert_eq!(started.kind, "tool.invocation");
        assert_eq!(started.status, "running");
    }

    #[test]
    fn approval_outcomes_stay_distinct() {
        let request = one(
            Provider::Grok,
            json!({"type": "permission_request", "tool_use_id": "t1", "tool_name": "Bash"}),
        );
        assert_eq!(request.kind, "approval.request");
        assert_eq!(request.status, "pending");
        let denied = one(
            Provider::Grok,
            json!({"type": "permission_request", "tool_use_id": "t1", "status": "denied"}),
        );
        assert_eq!(denied.kind, "approval.decision");
        assert_eq!(denied.status, "denied");
        let approved = one(
            Provider::Grok,
            json!({"type": "permission_response", "tool_use_id": "t1", "behavior": "allow"}),
        );
        assert_eq!(approved.kind, "approval.decision");
        assert_eq!(approved.status, "approved");
        assert_eq!(approved.correlation_id, request.correlation_id);
    }

    #[test]
    fn tool_calls_and_results_share_nested_provider_ids() {
        let claude = lines(
            Provider::Claude,
            &[
                json!({"type": "assistant", "uuid": "u-1", "session_id": "s", "message": {
                "id": "msg_1", "content": [
                    {"type": "text", "text": "reading"},
                    {"type": "tool_use", "id": "toolu_01", "name": "Read", "input": {}},
                    {"type": "tool_use", "id": "toolu_02", "name": "Grep", "input": {}}
                ]}}),
                json!({"type": "user", "uuid": "u-2", "session_id": "s", "message": {
                "role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"},
                    {"type": "tool_result", "tool_use_id": "toolu_02", "is_error": true}
                ]}}),
            ],
        );
        let summary: Vec<_> = claude
            .iter()
            .map(|event| {
                (
                    event.kind.as_str(),
                    event.correlation_id.as_str(),
                    event.status.as_str(),
                    event.payload["tool"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("tool.invocation", "toolu_01", "running", "Read"),
                ("tool.invocation", "toolu_02", "running", "Grep"),
                ("tool.result", "toolu_01", "ok", "Read"),
                ("tool.result", "toolu_02", "error", "Grep"),
            ]
        );

        let gemini = lines(
            Provider::Gemini,
            &[
                json!({"type": "tool_use", "tool_name": "read_file", "tool_id": "g1",
                       "parameters": {"type": "result"}}),
                json!({"type": "tool_result", "tool_id": "g1", "status": "success"}),
            ],
        );
        assert_eq!(gemini[0].kind, "tool.invocation");
        assert_eq!(gemini[1].kind, "tool.result");
        assert_eq!(gemini[0].correlation_id, "g1");
        assert_eq!(gemini[1].correlation_id, "g1");
        assert_eq!(gemini[1].payload["tool"], "read_file");

        let opencode = one(
            Provider::Opencode,
            json!({"type": "tool_use", "sessionID": "ses_1", "part": {
                "id": "prt_1", "type": "tool", "callID": "call_9", "tool": "bash",
                "state": {"status": "completed", "output": "ok"}}}),
        );
        assert_eq!(opencode.kind, "tool.result");
        assert_eq!(opencode.status, "ok");
        assert_eq!(opencode.correlation_id, "call_9");
        assert_eq!(opencode.payload["tool"], "bash");

        let kimi = lines(
            Provider::Kimi,
            &[
                json!({"role": "assistant", "content": [{"type": "text", "text": "checking"}],
                       "tool_calls": [{"id": "call-1", "type": "function",
                                       "function": {"name": "Read", "arguments": "{}"}}]}),
                json!({"role": "tool", "tool_call_id": "call-1", "content": "ok"}),
            ],
        );
        assert_eq!(kimi[0].kind, "model.response");
        assert_eq!(kimi[1].kind, "tool.invocation");
        assert_eq!(kimi[1].correlation_id, "call-1");
        assert_eq!(kimi[2].kind, "tool.result");
        assert_eq!(kimi[2].correlation_id, "call-1");
        assert_eq!(kimi[2].payload["tool"], "Read");
    }

    #[test]
    fn stated_identity_model_and_usage_are_normalized() {
        let events = lines(
            Provider::Claude,
            &[
                json!({"type": "system", "subtype": "init", "session_id": "sess-1",
                       "uuid": "u-0", "model": "claude-test"}),
                json!({"type": "assistant", "uuid": "u-1", "session_id": "sess-1",
                "parent_tool_use_id": null, "message": {"id": "msg_1", "content": [
                    {"type": "tool_use", "id": "toolu_task", "name": "Task", "input": {}}
                ]}}),
                json!({"type": "assistant", "uuid": "u-2", "session_id": "sess-1",
                       "parent_tool_use_id": "toolu_task", "message": {
                           "id": "msg_2", "model": "claude-sub",
                           "content": [{"type": "text", "text": "working"}],
                           "usage": {"input_tokens": 10, "output_tokens": 5,
                                     "cache_read_input_tokens": 3}}}),
            ],
        );
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].kind, "agent.turn");
        assert_eq!(events[0].payload["model"], "claude-test");
        assert_eq!(events[1].actor_id, "claude");
        assert_eq!(events[1].actor_type, "agent");
        assert_eq!(events[1].span_id, "toolu_task");
        assert_eq!(events[1].parent_span_id, "sess-1");
        assert_eq!(events[1].payload["tool"], "Task");
        assert!(events[1].payload["native"]["message"].is_object());

        assert_eq!(events[2].kind, "agent.spawn");
        let sub = &events[3];
        assert_eq!(sub.kind, "model.response");
        assert_eq!(sub.actor_id, "claude:subagent:toolu_task");
        assert_eq!(sub.actor_type, "subagent");
        assert_eq!(sub.parent_span_id, "toolu_task");
        assert_eq!(sub.payload["parent_actor"], "claude");
        assert_eq!(sub.payload["model"], "claude-sub");
        assert_eq!(
            sub.payload["usage"],
            json!({"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                   "input_tokens_details": {"cached_tokens": 3}})
        );

        let codex = lines(
            Provider::Codex,
            &[
                json!({"type": "thread.started", "thread_id": "thread-1"}),
                json!({"type": "turn.started"}),
                json!({"type": "turn.completed", "usage": {"input_tokens": 7,
                       "cached_input_tokens": 2, "output_tokens": 1}}),
            ],
        );
        assert_eq!(codex[0].span_id, "thread-1");
        assert_eq!(codex[1].span_id, "thread-1");
        assert_eq!(codex[2].span_id, "thread-1");
        assert_eq!(codex[2].payload["usage"]["total_tokens"], 8);

        let opencode = one(
            Provider::Opencode,
            json!({"type": "step_finish", "sessionID": "ses_1", "part": {"type": "step-finish",
                   "cost": 0.25, "tokens": {"input": 4, "output": 2, "reasoning": 1,
                                             "cache": {"read": 9, "write": 0}}}}),
        );
        assert_eq!(
            opencode.payload["usage"],
            json!({"input_tokens": 4, "output_tokens": 2, "total_tokens": 6,
                   "input_tokens_details": {"cached_tokens": 9},
                   "output_tokens_details": {"reasoning_tokens": 1}, "cost_usd": 0.25})
        );
    }

    #[test]
    fn strips_bounded_terminal_control_prefixes_before_json() {
        let mut adapter = NativeAdapter::new(Provider::Droid);
        let events = adapter.push(
            b"\x1b[?u\x1b[c{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}\n",
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "model.response");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_chunking_never_panics_or_exceeds_the_line_bound(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..8192), 0..80)
        ) {
            let mut adapter = NativeAdapter::new(Provider::Codex);
            for chunk in chunks {
                let events = adapter.push(&chunk);
                prop_assert!(adapter.pending.len() <= MAX_BUFFERED_LINE_BYTES);
                prop_assert!(events.len() <= chunk.iter().filter(|byte| **byte == b'\n').count() + 1);
            }
            let _ = adapter.finish();
            prop_assert!(adapter.pending.is_empty());
        }
    }
}
