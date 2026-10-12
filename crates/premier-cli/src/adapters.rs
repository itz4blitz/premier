use chrono::{DateTime, SecondsFormat, Utc};
use premier_trace::EventInput;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
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
/// Per-line diagnostics stored before further ones are only counted. A command recorded with an
/// adapter but without its structured output flag prints nothing but non-JSON lines.
const MAX_LINE_DIAGNOSTICS: u64 = 20;
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

    /// The adapter that normalizes this recording, if any. PTY capture never has one.
    pub fn resolve(self, executable: &str, args: &[String], pty: bool) -> Option<Provider> {
        if pty {
            return None;
        }
        self.detect(executable, args)
    }

    /// The provider this choice selects for a command, before the capture mode is considered.
    pub fn detect(self, executable: &str, args: &[String]) -> Option<Provider> {
        match self {
            Self::None => None,
            Self::Codex => Some(Provider::Codex),
            Self::Claude => Some(Provider::Claude),
            Self::Gemini => Some(Provider::Gemini),
            Self::Grok => Some(Provider::Grok),
            Self::Opencode => Some(Provider::Opencode),
            Self::Kimi => Some(Provider::Kimi),
            Self::Droid => Some(Provider::Droid),
            Self::Auto => {
                let mut words = Vec::with_capacity(args.len() + 1);
                words.push(executable.to_owned());
                words.extend(args.iter().cloned());
                detect_command(&words, 0)
            }
        }
    }
}

/// Wrappers `auto` looks through before it gives up: `env`, a package runner and `sh -c`.
const MAX_WRAPPER_DEPTH: usize = 4;

fn program_name(word: &str) -> Option<String> {
    // `file_stem` already drops an extension such as `.exe` or `.cmd`.
    Some(Path::new(word).file_stem()?.to_str()?.to_ascii_lowercase())
}

/// Arguments up to a `--`: what follows is positional, so a prompt that is literally `--json`
/// is not a flag.
fn options(args: &[String]) -> &[String] {
    let end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    &args[..end]
}

/// The provider a command line runs with structured output, resolving the real executable
/// through `env`, a package runner (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`) and one simple
/// command inside `sh -c`.
fn detect_command(words: &[String], depth: usize) -> Option<Provider> {
    if depth > MAX_WRAPPER_DEPTH {
        return None;
    }
    let (program, args) = words.split_first()?;
    let name = program_name(program)?;
    match name.as_str() {
        "env" => detect_command(env_command(args)?, depth + 1),
        "npx" | "bunx" | "pnpx" => package_runner(args),
        "pnpm" | "yarn" if args.first().is_some_and(|arg| arg == "dlx") => {
            package_runner(&args[1..])
        }
        "sh" | "bash" | "zsh" | "dash" | "ksh" => {
            detect_command(&simple_shell_words(shell_script(args)?)?, depth + 1)
        }
        _ => {
            let provider = Provider::from_name(&name)?;
            provider
                .has_structured_output(options(args))
                .then_some(provider)
        }
    }
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|first: char| first.is_ascii_digit())
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

/// The command `env` runs: what follows its own flags and `NAME=VALUE` assignments. A flag
/// this does not know (such as `-S`, which re-splits a string) leaves the command unresolved.
fn env_command(args: &[String]) -> Option<&[String]> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "--" => return Some(&args[index + 1..]),
            "-" | "-i" | "--ignore-environment" => index += 1,
            "-u" | "--unset" | "-C" | "--chdir" => index += 2,
            flag if flag.starts_with("--unset=") || flag.starts_with("--chdir=") => index += 1,
            flag if flag.starts_with('-') => return None,
            word if is_assignment(word) => index += 1,
            _ => return Some(&args[index..]),
        }
    }
    None
}

/// The provider behind a package runner's arguments: its own flags, then a package (or, after
/// `-p <package>`, a command from it) and that command's arguments.
fn package_runner(args: &[String]) -> Option<Provider> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "-p" | "--package" => index += 2,
            // `-c` runs a shell string, which is not resolved here.
            "-c" | "--call" => return None,
            flag if flag.starts_with('-') => index += 1,
            package => {
                let provider = package_provider(package)?;
                return provider
                    .has_structured_output(options(&args[index + 1..]))
                    .then_some(provider);
            }
        }
    }
    None
}

/// Maps a package spec such as `@anthropic-ai/claude-code@latest` or `codex` to its provider.
fn package_provider(spec: &str) -> Option<Provider> {
    let version = spec
        .char_indices()
        .skip(1)
        .find_map(|(index, character)| (character == '@').then_some(index))
        .unwrap_or(spec.len());
    match spec[..version].to_ascii_lowercase().as_str() {
        "@anthropic-ai/claude-code" => Some(Provider::Claude),
        "@openai/codex" => Some(Provider::Codex),
        "@google/gemini-cli" => Some(Provider::Gemini),
        "opencode-ai" => Some(Provider::Opencode),
        name => Provider::from_name(name),
    }
}

/// The script of `sh -c SCRIPT`, when only flags come before it.
fn shell_script(args: &[String]) -> Option<&str> {
    let flag = args
        .iter()
        .position(|arg| !arg.starts_with('-') || arg.starts_with("--"))
        .unwrap_or(args.len())
        .checked_sub(1)?;
    args[flag]
        .contains('c')
        .then(|| args.get(flag + 1).map(String::as_str))
        .flatten()
}

/// Splits a script into words when it is one simple command: quotes and backslashes are read
/// as a shell would, and anything that chains, pipes, redirects, groups or substitutes commands
/// leaves it unresolved. A `$VAR` argument is kept as an opaque word. Leading assignments and
/// `exec` are dropped.
fn simple_shell_words(script: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut characters = script.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' => words.extend(word.take()),
            '\'' => {
                let quoted = word.get_or_insert_with(String::new);
                loop {
                    match characters.next()? {
                        '\'' => break,
                        inner => quoted.push(inner),
                    }
                }
            }
            '"' => {
                let quoted = word.get_or_insert_with(String::new);
                loop {
                    match characters.next()? {
                        '"' => break,
                        '`' => return None,
                        '$' if characters.peek() == Some(&'(') => return None,
                        '\\' => quoted.push(characters.next()?),
                        inner => quoted.push(inner),
                    }
                }
            }
            '\\' => word
                .get_or_insert_with(String::new)
                .push(characters.next()?),
            '$' if characters.peek() == Some(&'(') => return None,
            '|' | ';' | '&' | '<' | '>' | '(' | ')' | '`' | '\n' | '\r' | '#' => return None,
            other => word.get_or_insert_with(String::new).push(other),
        }
    }
    words.extend(word);
    let start = words
        .iter()
        .position(|word| !is_assignment(word) && word != "exec")?;
    let command = words.split_off(start);
    // The program itself must be a literal name.
    (!command[0].contains('$')).then_some(command)
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
    /// Message ids whose usage is already attached to an event.
    usage_messages: HashSet<String>,
    summary: AdapterSummary,
}

/// What an adapter made of the lines it was given.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdapterSummary {
    /// Non-blank lines seen.
    pub lines: u64,
    /// Lines that were native JSON objects and became events.
    pub normalized_lines: u64,
    /// Lines that were not: not JSON, not an object, or too long to keep.
    pub rejected_lines: u64,
    /// Rejected lines with no `adapter.diagnostic` event of their own.
    pub suppressed_diagnostics: u64,
}

impl AdapterSummary {
    /// Whether the recording differs from what its adapter provenance promises.
    pub fn needs_report(&self) -> bool {
        self.rejected_lines > 0 || self.normalized_lines == 0
    }

    /// `completeness` for the manifest's adapter provenance.
    pub fn completeness(&self) -> &'static str {
        if self.normalized_lines == 0 {
            "no-native-events"
        } else if self.rejected_lines > 0 {
            "provider-native-partial"
        } else {
            "provider-native-best-effort"
        }
    }
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
            usage_messages: HashSet::new(),
            summary: AdapterSummary::default(),
        }
    }

    /// Counts of the lines seen so far.
    pub fn summary(&self) -> AdapterSummary {
        self.summary
    }

    /// The `adapter.summary` event closing a recording whose lines were not all native events,
    /// or `None` when every line was. Call it after [`Self::finish`].
    pub fn summary_event(&self) -> Option<AdapterEvent> {
        let summary = self.summary;
        if !summary.needs_report() {
            return None;
        }
        let message = if summary.normalized_lines == 0 {
            format!(
                "none of the {} output line(s) was a native JSONL event; the trace holds no model or tool events from this adapter",
                summary.lines
            )
        } else {
            format!(
                "{} of {} output line(s) were not native JSONL events",
                summary.rejected_lines, summary.lines
            )
        };
        Some(AdapterEvent::unlinked(EventInput {
            kind: "adapter.summary".into(),
            source: format!("adapter.{}.v{ADAPTER_SCHEMA_VERSION}", self.provider.id()),
            actor_id: self.provider.id().into(),
            actor_type: "agent".into(),
            status: "warning".into(),
            payload: json!({
                "provider": self.provider.id(),
                "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
                "lines": summary.lines,
                "normalized_lines": summary.normalized_lines,
                "rejected_lines": summary.rejected_lines,
                "suppressed_diagnostics": summary.suppressed_diagnostics,
                "completeness": summary.completeness(),
                "message": message,
            }),
            ..EventInput::default()
        }))
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
                    events.extend(self.discarded_diagnostic());
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
            return self.discarded_diagnostic().into_iter().collect();
        }
        if self.pending.is_empty() {
            return Vec::new();
        }
        self.line_number += 1;
        let line = std::mem::take(&mut self.pending);
        self.parse_line(&line)
    }

    fn parse_line(&mut self, line: &[u8]) -> Vec<AdapterEvent> {
        let line_bytes = line.len();
        let oversized = (line_bytes > MAX_NATIVE_LINE_BYTES).then_some(line_bytes);
        // Decorations first: a line that holds nothing but a control sequence is blank.
        let line = strip_terminal_decorations(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            return Vec::new();
        }
        self.summary.lines += 1;
        let native: Value = match serde_json::from_slice(&line) {
            Ok(Value::Object(object)) => Value::Object(object),
            Ok(_) => {
                return self
                    .rejected("native JSONL event was not an object", oversized)
                    .into_iter()
                    .collect();
            }
            Err(error) if oversized.is_some() => {
                return self
                    .rejected(
                        &format!(
                            "oversized native JSONL line ({line_bytes} bytes, limit \
                             {MAX_NATIVE_LINE_BYTES}) could not be parsed: {error}"
                        ),
                        oversized,
                    )
                    .into_iter()
                    .collect();
            }
            Err(error) => {
                return self
                    .rejected(&format!("malformed native JSONL: {error}"), None)
                    .into_iter()
                    .collect();
            }
        };
        self.summary.normalized_lines += 1;
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

    fn discarded_diagnostic(&mut self) -> Option<AdapterEvent> {
        let line_bytes = std::mem::take(&mut self.discarded_bytes);
        self.summary.lines += 1;
        self.rejected(
            &format!(
                "oversized native JSONL line ({line_bytes} bytes) exceeded the \
                 {MAX_BUFFERED_LINE_BYTES} byte buffer and was discarded"
            ),
            Some(line_bytes),
        )
    }

    /// Count a line that did not become events, and describe it in a diagnostic event unless
    /// [`MAX_LINE_DIAGNOSTICS`] were already stored; the summary reports the rest.
    fn rejected(&mut self, message: &str, line_bytes: Option<usize>) -> Option<AdapterEvent> {
        self.summary.rejected_lines += 1;
        if self.summary.rejected_lines > MAX_LINE_DIAGNOSTICS {
            self.summary.suppressed_diagnostics += 1;
            return None;
        }
        let mut diagnostic = self.diagnostic(message, line_bytes);
        if self.summary.rejected_lines == MAX_LINE_DIAGNOSTICS {
            diagnostic.payload["further_diagnostics"] = json!("suppressed");
        }
        Some(diagnostic)
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
        // An assistant message that narrates and calls tools is the model's response; its tool
        // blocks each become an event of their own below.
        let narrated = kind.starts_with("tool.") && !blocks.is_empty() && assistant_text(&native);
        let kind = if narrated { "model.response" } else { kind };
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
        let kind = if failed && !completed && !narrated {
            classify_kind(provider, &native, &discriminators, phase, true)
        } else {
            kind
        };
        // A refusal is kept apart from a failure where the provider states one.
        let denied = kind.starts_with("tool.")
            && (scopes.iter().any(|scope| states_denial(scope))
                || block.is_some_and(states_denial));
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
        } else if denied {
            "denied"
        } else if failed {
            "error"
        } else if kind == "approval.request" {
            "pending"
        } else if completed
            || kind.ends_with("response")
            || kind.ends_with("result")
            || kind == "agent.message"
        {
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
        if tool_kind || narrated {
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
            match self.usage_already_reported(&native) {
                Some(message) => payload["usage_reported_on"] = json!(message),
                None => payload["usage"] = usage,
            }
        }
        if kind == "agent.message" {
            payload["role"] = json!("user");
        }
        if provider == Provider::Codex {
            codex_item_fields(&native, &mut payload);
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
        // Refusals the provider only lists at the end of the run. They are stored before the
        // result that carries them, while the turn they belong to is still open.
        let denials: Vec<_> = native
            .get("permission_denials")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|denial| denial.is_object())
            .map(|denial| self.denial_event(denial, &parent_tool, native_timestamp.as_deref()))
            .collect();
        events.extend(denials);
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

    /// A provider repeats one message's usage on every line cut from that message (Claude prints
    /// a line per content block). Only the first event of a message id carries it, so summing
    /// `payload.usage` over events counts each message once; later ones name that message id.
    fn usage_already_reported(&mut self, native: &Value) -> Option<String> {
        let message = native.get("message")?;
        // Usage stated on the line itself is not a per-message repeat.
        if native.get("usage").is_some_and(Value::is_object) || !message.get("usage")?.is_object() {
            return None;
        }
        let id = message.get("id")?.as_str()?;
        if self.usage_messages.contains(id) {
            return Some(id.to_owned());
        }
        if self.usage_messages.len() >= MAX_TRACKED_TOOL_CALLS {
            self.usage_messages.clear();
        }
        self.usage_messages.insert(id.to_owned());
        None
    }

    /// One refused tool call from a result line's `permission_denials`. The provider printed no
    /// line for the decision itself, so the event is marked `synthesized`; `native` is the
    /// list entry it was drawn from.
    fn denial_event(
        &self,
        denial: &Value,
        parent_tool: &str,
        native_timestamp: Option<&str>,
    ) -> AdapterEvent {
        let tool_id = keyed_tool_id(denial)
            .or_else(|| denial.get("id")?.as_str())
            .unwrap_or("")
            .to_owned();
        let tool = string_at(
            denial,
            &[&["tool_name"], &["toolName"], &["tool"], &["name"]],
        )
        .map(str::to_owned)
        .or_else(|| self.tool_names.get(&tool_id).cloned());
        let mut payload = json!({
            "provider": self.provider.id(),
            "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
            "native_type": "permission_denial",
            "synthesized": true,
            "synthesized_from": "permission_denials",
            "line": self.line_number,
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
        payload["native"] = denial.clone();
        let call = (!tool_id.is_empty()).then(|| format!("tool:{tool_id}"));
        let input = EventInput {
            kind: "approval.decision".into(),
            status: "denied".into(),
            payload,
            ..self.identified(tool_id, parent_tool)
        };
        let mut event = self.linked(input, parent_tool, false, None);
        // No request was printed, so the decision points at the call it refused.
        event.links.extend(call);
        event
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
        let denied = states_denial(part);
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
            status: if denied {
                "denied"
            } else if failed {
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

/// A line without what a terminal-minded CLI wraps around its JSON: a byte order mark, text
/// overwritten by a carriage return (a spinner), and control sequences before or after the
/// object (CSI such as colours and cursor moves, OSC ended by BEL or ST, charset selections,
/// the 8-bit CSI). A raw escape byte cannot occur inside JSON, so removing sequences wherever
/// they are never changes a valid event. A sequence that never ends is left in place.
fn strip_terminal_decorations(line: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let mut line = line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(line);
    if line.contains(&b'\r') {
        // What a terminal would show: the last non-blank carriage-return segment.
        line = line
            .split(|byte| *byte == b'\r')
            .rev()
            .find(|segment| !segment.iter().all(u8::is_ascii_whitespace))
            .unwrap_or(&[]);
    }
    let line = line.trim_ascii();
    let control = |index: usize, leading: bool| -> Option<usize> {
        // The length of the control sequence starting at `index`, if one starts and ends there.
        let rest = &line[index..];
        let (introducer, body) = match rest {
            [0x1b, b'[', body @ ..] => (2, body),
            // U+009B may be text inside a JSON string, so only before the event.
            [0xc2, 0x9b, body @ ..] if leading => (2, body),
            [0x1b, b']', body @ ..] => {
                let end = body
                    .iter()
                    .position(|byte| *byte == 0x07 || *byte == 0x1b)?;
                return match body[end..] {
                    [0x07, ..] => Some(2 + end + 1),
                    [0x1b, b'\\', ..] => Some(2 + end + 2),
                    _ => None,
                };
            }
            [0x1b, body @ ..] => {
                // ESC, intermediates, one final byte: `ESC ( B`, `ESC =`, `ESC 7`.
                let intermediates = body
                    .iter()
                    .take_while(|byte| (0x20..=0x2f).contains(*byte))
                    .count();
                return matches!(body.get(intermediates), Some(0x30..=0x7a | 0x7c..=0x7e))
                    .then_some(1 + intermediates + 1);
            }
            _ => return None,
        };
        let parameters = body
            .iter()
            .take_while(|byte| (0x20..=0x3f).contains(*byte))
            .count();
        match body.get(parameters) {
            // `{` could end a sequence, but here it is far more likely the event itself after
            // an introducer that was cut short.
            Some(b'{') | None => None,
            Some(0x40..=0x7e) => Some(introducer + parameters + 1),
            Some(_) => None,
        }
    };
    if !line.contains(&0x1b) && !line.starts_with(&[0xc2, 0x9b]) {
        return line.into();
    }
    let mut stripped = Vec::with_capacity(line.len());
    let mut index = 0;
    while index < line.len() {
        match control(index, stripped.is_empty()) {
            Some(length) => index += length,
            None if line[index..].starts_with(b"\x1b[") => {
                // An introducer with no sequence behind it: drop just the introducer.
                index += 2;
            }
            None => {
                stripped.push(line[index]);
                index += 1;
            }
        }
    }
    stripped.trim_ascii().to_vec().into()
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
            matches!(status.as_str(), "error" | "errored" | "failed" | "failure")
        })
        || states_denial(scope)
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

/// True when the object's status says the action was refused rather than that it broke.
fn states_denial(scope: &Value) -> bool {
    outcome_status(scope).is_some_and(|status| {
        matches!(
            status.as_str(),
            "denied" | "rejected" | "declined" | "blocked"
        )
    })
}

/// True when the line is an assistant message whose content has a non-empty text block.
fn assistant_text(native: &Value) -> bool {
    let message = native.get("message");
    let assistant = [native.get("type"), native.get("role")]
        .into_iter()
        .chain([message.and_then(|message| message.get("role"))])
        .flatten()
        .filter_map(Value::as_str)
        .any(|value| value.eq_ignore_ascii_case("assistant"));
    assistant
        && [
            message.and_then(|message| message.get("content")),
            native.get("content"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .flatten()
        .any(|block| {
            block.get("type").and_then(Value::as_str) == Some("text")
                && block
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty())
        })
}

/// True when the line, or the message it wraps, is spoken by the user rather than the model.
fn user_role(native: &Value) -> bool {
    [
        native.get("role"),
        native
            .get("message")
            .and_then(|message| message.get("role")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .any(|role| role.eq_ignore_ascii_case("user"))
}

/// Codex item types that have no word the generic rules recognise.
fn codex_item_type(native: &Value) -> Option<&str> {
    native.get("item")?.get("type")?.as_str()
}

/// Normalized fields for typed Codex items: the paths a `file_change` touched, the query of a
/// `web_search`, and a flag on `reasoning` so it can be told from an answer.
fn codex_item_fields(native: &Value, payload: &mut Value) {
    let Some(item) = native.get("item") else {
        return;
    };
    match codex_item_type(native) {
        Some("file_change") => {
            let paths: Vec<_> = item
                .get("changes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|change| change.get("path")?.as_str())
                .collect();
            payload["paths"] = json!(paths);
        }
        Some("web_search") => {
            if let Some(query) = item.get("query").and_then(Value::as_str) {
                payload["query"] = json!(query);
            }
        }
        Some("reasoning") => payload["reasoning"] = json!(true),
        _ => {}
    }
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
    let cached = number(&[
        "cached_input_tokens",
        "cache_read_input_tokens",
        "cached_tokens",
    ])
    .or_else(|| nested("input_tokens_details", "cached_tokens"))
    .or_else(|| nested("cache", "read"));
    let cache_creation = number(&[
        "cache_creation_input_tokens",
        "cache_creation_tokens",
        "cache_write_tokens",
    ])
    .or_else(|| nested("input_tokens_details", "cache_creation_tokens"))
    .or_else(|| nested("cache", "write"));
    // Claude (`cache_*_input_tokens`) and OpenCode (`cache.read` / `cache.write`) count cache
    // tokens apart from input tokens; the OpenAI-style fields are a subset of them. The total is
    // every token processed, so only the separately counted ones are added.
    let separate_cache = number(&["cache_read_input_tokens"])
        .or_else(|| nested("cache", "read"))
        .unwrap_or(0)
        + number(&["cache_creation_input_tokens"])
            .or_else(|| nested("cache", "write"))
            .unwrap_or(0);
    let total = number(&["total_tokens", "totalTokens", "total"])
        .or_else(|| Some(input? + output? + separate_cache));
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
    let mut input_details = serde_json::Map::new();
    for (key, value) in [
        ("cached_tokens", cached),
        ("cache_creation_tokens", cache_creation),
    ] {
        if let Some(value) = value {
            input_details.insert(key.into(), json!(value));
        }
    }
    if !input_details.is_empty() {
        usage.insert("input_tokens_details".into(), Value::Object(input_details));
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
    if provider == Provider::Codex {
        match codex_item_type(native) {
            Some("file_change" | "web_search") => {
                return lifecycle_kind(completed, "tool.result", "tool.invocation");
            }
            Some("reasoning") => return "model.response",
            Some("todo_list") => return "provider.event",
            _ => {}
        }
    }
    if discriminators.has(APPROVAL_WORDS) {
        return lifecycle_kind(completed, "approval.decision", "approval.request");
    }
    if discriminators.names_tool() {
        return lifecycle_kind(completed, "tool.result", "tool.invocation");
    }
    // What the user said is input to the agent, not something the model produced.
    let user = user_role(native);
    let message = discriminators.has(MESSAGE_WORDS);
    if message || discriminators.has(&["model"]) {
        if user {
            return "agent.message";
        }
        return lifecycle_kind(completed || message, "model.response", "model.request");
    }
    if discriminators.has(AGENT_WORDS) {
        return lifecycle_kind(completed, "agent.result", "agent.turn");
    }
    if user {
        return "agent.message";
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
                    // The text block of msg-2; its tool call follows on a line of its own.
                    ("model.response", "ok", "msg-2"),
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
                    ("model.response", "ok", "item_0"),
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
                    ("agent.message", "ok", ""),
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

    /// The Claude fixture as the recorder stores it, checked in so the viewer's usage totals
    /// are tested against real adapter output (`apps/viewer/src/lib/modelUsage.test.ts`).
    /// Regenerate with `PREMIER_UPDATE_FIXTURES=1 cargo test -p premier-cli normalized`.
    #[test]
    fn claude_fixture_matches_its_checked_in_normalized_events() {
        let fixture = include_bytes!("../tests/fixtures/adapters/claude.jsonl");
        let events: Vec<Value> = stored(Provider::Claude, &[fixture])
            .into_iter()
            .enumerate()
            .map(|(index, event)| {
                json!({
                    "event_id": format!("e{}", index + 1),
                    "sequence": index + 1,
                    "kind": event.kind,
                    "source": event.source,
                    "actor_id": event.actor_id,
                    "actor_type": event.actor_type,
                    "parent_event_id": event.parent_event_id,
                    "span_id": event.span_id,
                    "parent_span_id": event.parent_span_id,
                    "correlation_id": event.correlation_id,
                    "status": event.status,
                    "duration_ms": event.duration_ms,
                    "links": event.links,
                    "payload": event.payload,
                })
            })
            .collect();
        let rendered = format!("{}\n", serde_json::to_string_pretty(&events).unwrap());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/adapters/claude.normalized.json"
        );
        if std::env::var_os("PREMIER_UPDATE_FIXTURES").is_some() {
            std::fs::write(path, &rendered).unwrap();
        }
        let stored = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            stored == rendered,
            "claude.normalized.json is stale; regenerate it with PREMIER_UPDATE_FIXTURES=1"
        );
        // Each message's usage is attached once, so a plain sum over events is correct.
        let total: u64 = events
            .iter()
            .filter(|event| event["payload"]["lifecycle"] != "run_result")
            .filter_map(|event| event["payload"]["usage"]["total_tokens"].as_u64())
            .sum();
        assert_eq!(total, 266);
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
            json!({"input_tokens": 100, "output_tokens": 20, "total_tokens": 127,
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
                ("model.response", "msg_1", "ok", ""),
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
            json!({"input_tokens": 10, "output_tokens": 5, "total_tokens": 18,
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
            json!({"input_tokens": 4, "output_tokens": 2, "total_tokens": 15,
                   "input_tokens_details": {"cached_tokens": 9, "cache_creation_tokens": 0},
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

    fn command_words(command: &[&str]) -> (String, Vec<String>) {
        (
            command[0].to_owned(),
            command[1..].iter().map(|word| (*word).to_owned()).collect(),
        )
    }

    fn auto(command: &[&str]) -> Option<Provider> {
        let (executable, args) = command_words(command);
        AdapterChoice::Auto.resolve(&executable, &args, false)
    }

    #[test]
    fn auto_respects_end_of_options() {
        // A prompt that is literally `--json` is not the structured-output flag.
        assert_eq!(auto(&["codex", "exec", "--", "--json"]), None);
        assert_eq!(
            auto(&["claude", "-p", "--", "--output-format", "stream-json"]),
            None
        );
        assert_eq!(
            auto(&["codex", "exec", "--json", "--", "review this"]),
            Some(Provider::Codex)
        );
    }

    #[test]
    fn auto_resolves_the_agent_behind_env_package_runners_and_simple_shell_commands() {
        let stream = ["-p", "--output-format", "stream-json", "hi"];
        let with = |prefix: &[&str]| auto(&[prefix, &stream[..]].concat());
        for prefix in [
            &["env", "X=1", "claude"][..],
            &["/usr/bin/env", "-i", "PATH=/bin", "-u", "DEBUG", "claude"],
            &["env", "--", "claude"],
            &["npx", "claude"],
            &["npx", "-y", "@anthropic-ai/claude-code"],
            &["npx", "--yes", "@anthropic-ai/claude-code@latest"],
            &["npx", "-p", "@anthropic-ai/claude-code", "claude"],
            &["bunx", "@anthropic-ai/claude-code@2.0.1"],
            &["pnpm", "dlx", "@anthropic-ai/claude-code"],
            &["yarn", "dlx", "claude"],
            &["env", "CI=1", "npx", "claude"],
        ] {
            assert_eq!(with(prefix), Some(Provider::Claude), "{prefix:?}");
        }
        assert_eq!(
            auto(&["npx", "@openai/codex", "exec", "--json", "hi"]),
            Some(Provider::Codex)
        );
        assert_eq!(
            auto(&["pnpm", "dlx", "@openai/codex@0.50.0", "exec", "--json"]),
            Some(Provider::Codex)
        );
        for script in [
            "claude -p --output-format stream-json 'fix the test'",
            "exec claude -p \"say \\\"hi\\\"\" --output-format=stream-json",
            "CI=1 claude -p \"$PROMPT\" --output-format stream-json",
            "npx -y @anthropic-ai/claude-code -p hi --output-format stream-json",
        ] {
            assert_eq!(
                auto(&["sh", "-c", script]),
                Some(Provider::Claude),
                "{script}"
            );
            assert_eq!(
                auto(&["/bin/bash", "-lc", script, "sh", "arg"]),
                Some(Provider::Claude),
                "{script}"
            );
        }

        // Anything that is not one simple command, or does not ask for structured output, is
        // left to plain terminal capture.
        for command in [
            &[
                "sh",
                "-c",
                "claude -p --output-format stream-json hi | tee out.jsonl",
            ][..],
            &[
                "sh",
                "-c",
                "cd repo; claude -p --output-format stream-json hi",
            ],
            &[
                "sh",
                "-c",
                "cd repo && claude -p --output-format stream-json hi",
            ],
            &[
                "sh",
                "-c",
                "claude -p --output-format stream-json hi > out.jsonl",
            ],
            &[
                "sh",
                "-c",
                "claude -p --output-format stream-json \"$(cat prompt.txt)\"",
            ],
            &["sh", "-c", "echo 'claude -p --output-format stream-json'"],
            &[
                "sh",
                "script.sh",
                "-c",
                "claude --output-format stream-json",
            ],
            &[
                "sh",
                "-c",
                "claude -p 'unterminated --output-format stream-json",
            ],
            &["env", "X=1", "claude", "-p", "hi"],
            &["env", "-S", "claude -p --output-format stream-json"],
            &["npx", "claude", "-p", "hi"],
            &[
                "npx",
                "some-other-package",
                "--output-format",
                "stream-json",
            ],
            &[
                "npx",
                "--",
                "claude",
                "--",
                "--output-format",
                "stream-json",
            ],
            &["echo", "claude", "--output-format", "stream-json"],
            &["npm", "run", "claude", "--output-format", "stream-json"],
            &["pnpm", "claude", "--output-format", "stream-json"],
        ] {
            assert_eq!(auto(command), None, "{command:?}");
        }
        // PTY capture never has an adapter, but the provider is still recognised for the note.
        let (executable, args) = command_words(&["env", "X=1", "codex", "exec", "--json"]);
        assert_eq!(AdapterChoice::Auto.resolve(&executable, &args, true), None);
    }

    #[test]
    fn usage_counts_cache_tokens_and_is_attached_once_per_message() {
        let usage = json!({"input_tokens": 10, "output_tokens": 5,
                           "cache_read_input_tokens": 3, "cache_creation_input_tokens": 2});
        let block = |id: &str, content: Value| {
            json!({"type": "assistant", "session_id": "s", "message": {
                "id": id, "role": "assistant", "model": "claude-test",
                "content": [content], "usage": usage}})
        };
        let events = lines(
            Provider::Claude,
            &[
                block("m1", json!({"type": "text", "text": "reading"})),
                block(
                    "m1",
                    json!({"type": "tool_use", "id": "t1", "name": "Read"}),
                ),
                block(
                    "m1",
                    json!({"type": "tool_use", "id": "t2", "name": "Grep"}),
                ),
                block("m2", json!({"type": "text", "text": "done"})),
            ],
        );
        assert_eq!(events.len(), 4);
        // Claude counts cache reads and writes apart from input_tokens, so the total adds them.
        let expected = json!({"input_tokens": 10, "output_tokens": 5, "total_tokens": 20,
            "input_tokens_details": {"cached_tokens": 3, "cache_creation_tokens": 2}});
        assert_eq!(events[0].payload["usage"], expected);
        assert!(events[0].payload.get("usage_reported_on").is_none());
        for repeat in &events[1..3] {
            assert!(
                repeat.payload.get("usage").is_none(),
                "{:?}",
                repeat.payload
            );
            assert_eq!(repeat.payload["usage_reported_on"], "m1");
            // The provider's own copy is still kept as evidence.
            assert_eq!(repeat.payload["native"]["message"]["usage"], usage);
        }
        assert_eq!(events[3].payload["usage"], expected);
        let total: u64 = events
            .iter()
            .filter_map(|event| event.payload["usage"]["total_tokens"].as_u64())
            .sum();
        assert_eq!(total, 40);

        // Codex reports cached tokens as part of input_tokens: they are not added again.
        let codex = one(
            Provider::Codex,
            json!({"type": "turn.completed", "usage": {"input_tokens": 7,
                   "cached_input_tokens": 2, "output_tokens": 1}}),
        );
        assert_eq!(
            codex.payload["usage"],
            json!({"input_tokens": 7, "output_tokens": 1, "total_tokens": 8,
                   "input_tokens_details": {"cached_tokens": 2}})
        );
        // A stated total always wins.
        let stated = one(
            Provider::Gemini,
            json!({"type": "result", "status": "success", "stats": {"total_tokens": 30,
                   "input_tokens": 20, "output_tokens": 10, "cache_read_input_tokens": 5}}),
        );
        assert_eq!(stated.payload["usage"]["total_tokens"], 30);
    }

    #[test]
    fn assistant_text_beside_tool_calls_is_a_model_response_of_its_own() {
        let events = lines(
            Provider::Claude,
            &[
                json!({"type": "assistant", "uuid": "u-1", "session_id": "s", "message": {
                    "id": "msg_1", "role": "assistant", "content": [
                        {"type": "text", "text": "reading both files"},
                        {"type": "tool_use", "id": "toolu_01", "name": "Read", "input": {}},
                        {"type": "tool_use", "id": "toolu_02", "name": "Grep", "input": {}}
                    ], "usage": {"input_tokens": 4, "output_tokens": 2}}}),
            ],
        );
        let summary: Vec<_> = events
            .iter()
            .map(|event| {
                (
                    event.kind.as_str(),
                    event.status.as_str(),
                    event.correlation_id.as_str(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("model.response", "ok", "msg_1"),
                ("tool.invocation", "running", "toolu_01"),
                ("tool.invocation", "running", "toolu_02"),
            ]
        );
        // The response stands for the whole message and carries its usage once.
        assert!(events[0].payload["native"]["message"].is_object());
        assert_eq!(events[0].payload["usage"]["total_tokens"], 6);
        assert!(events[0].payload.get("tool").is_none());
        assert_eq!(events[1].payload["native"]["name"], "Read");
        assert!(events[1].payload.get("usage").is_none());

        // An empty text block, or a user line carrying text beside a tool result, adds nothing.
        let silent = lines(
            Provider::Claude,
            &[
                json!({"type": "assistant", "message": {"id": "m", "content": [
                    {"type": "text", "text": ""},
                    {"type": "tool_use", "id": "t1", "name": "Read"}]}}),
                json!({"type": "user", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
                    {"type": "text", "text": "continue"}]}}),
            ],
        );
        let kinds: Vec<_> = silent.iter().map(|event| event.kind.as_str()).collect();
        assert_eq!(kinds, ["tool.invocation", "tool.result"]);
    }

    #[test]
    fn user_messages_are_not_model_responses() {
        for (provider, native) in [
            (
                Provider::Gemini,
                json!({"type": "message", "role": "user", "content": "why does it fail?"}),
            ),
            (
                Provider::Claude,
                json!({"type": "user", "session_id": "s", "message": {"role": "user",
                       "content": [{"type": "text", "text": "why does it fail?"}]}}),
            ),
            (
                Provider::Kimi,
                json!({"role": "user", "content": "why does it fail?"}),
            ),
        ] {
            let event = one(provider, native);
            assert_eq!(event.kind, "agent.message", "{event:?}");
            assert_eq!(event.status, "ok");
            assert_eq!(event.payload["role"], "user");
        }
        let assistant = one(
            Provider::Gemini,
            json!({"type": "message", "role": "assistant", "content": "it truncates"}),
        );
        assert_eq!(assistant.kind, "model.response");
        assert!(assistant.payload.get("role").is_none());
    }

    #[test]
    fn codex_items_are_typed_and_a_two_turn_session_validates_cleanly() {
        let fixture = include_bytes!("../tests/fixtures/adapters/codex-two-turn.jsonl");
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("codex.atrace");
        let mut writer = premier_trace::TraceWriter::create(&root, vec!["codex".into()]).unwrap();
        let mut adapter = NativeAdapter::new(Provider::Codex);
        let events = adapter.push(fixture);
        adapter
            .commit(events, |input| {
                writer.append_input(input).map(|stored| stored.event_id)
            })
            .unwrap();
        writer.finish(0).unwrap();
        let events = premier_trace::read_events(&root).unwrap();
        let rows: Vec<_> = events
            .iter()
            .map(|event| {
                let payload = event.payload();
                (
                    event.kind.clone(),
                    event.status.clone(),
                    event.correlation_id.clone(),
                    payload["tool"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        let row = |kind: &str, status: &str, id: &str, tool: &str| {
            (
                kind.to_owned(),
                status.to_owned(),
                id.to_owned(),
                tool.to_owned(),
            )
        };
        assert_eq!(
            rows,
            [
                row("agent.turn", "running", "codex-thread-2", ""),
                row("agent.turn", "running", "codex-thread-2", ""),
                row("model.response", "ok", "item_0", ""),
                row("tool.invocation", "running", "item_1", "web_search"),
                row("tool.result", "ok", "item_1", "web_search"),
                row("provider.event", "running", "item_2", ""),
                row("tool.invocation", "running", "item_3", "file_change"),
                row("tool.result", "ok", "item_3", "file_change"),
                row("model.response", "ok", "item_4", ""),
                row("agent.result", "ok", "codex-thread-2", ""),
                row("agent.turn", "running", "codex-thread-2", ""),
                row("tool.invocation", "running", "item_5", "command_execution"),
                row("tool.result", "ok", "item_5", "command_execution"),
                row("tool.result", "error", "item_6", "file_change"),
                row("provider.event", "ok", "item_2", ""),
                row("model.response", "ok", "item_7", ""),
                row("agent.result", "ok", "codex-thread-2", ""),
            ]
        );
        let payload = |index: usize| events[index].payload();
        assert_eq!(payload(2)["reasoning"], true);
        assert!(payload(8).get("reasoning").is_none());
        assert_eq!(payload(3)["query"], "banker's rounding integer division");
        assert_eq!(
            payload(7)["paths"],
            json!(["src/ledger.rs", "tests/ledger.rs"])
        );
        assert_eq!(payload(13)["paths"], json!(["CHANGELOG.md"]));
        // Both turns hang off the thread and each turn's work off its own turn.
        assert_eq!(events[1].parent_event_id, events[0].event_id);
        assert_eq!(events[10].parent_event_id, events[0].event_id);
        assert_eq!(events[7].parent_event_id, events[6].event_id);
        assert_eq!(events[11].parent_event_id, events[10].event_id);
        assert_eq!(
            premier_trace::validate_events(&events),
            Vec::new(),
            "a multi-turn Codex trace has no lifecycle diagnostics"
        );
    }

    #[test]
    fn permission_denials_become_denied_approval_decisions() {
        let events = stored_lines(
            Provider::Claude,
            &[
                json!({"type": "system", "subtype": "init", "session_id": "s"}),
                json!({"type": "assistant", "session_id": "s", "message": {"id": "m1", "content": [
                    {"type": "tool_use", "id": "toolu_rm", "name": "Bash",
                     "input": {"command": "rm -rf build"}}]}}),
                json!({"type": "user", "session_id": "s", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_rm", "is_error": true,
                     "content": "Claude requested permissions to use Bash, but you haven't granted it yet."}]}}),
                json!({"type": "result", "subtype": "success", "is_error": false, "session_id": "s",
                       "permission_denials": [
                           {"tool_name": "Bash", "tool_use_id": "toolu_rm",
                            "tool_input": {"command": "rm -rf build"}},
                           {"tool_name": "Write", "tool_use_id": "toolu_unseen",
                            "tool_input": {"file_path": "/etc/hosts"}}]}),
            ],
        );
        let kinds: Vec<_> = events
            .iter()
            .map(|event| (event.kind.as_str(), event.status.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("agent.turn", "running"),
                ("tool.invocation", "running"),
                // The result line itself only says the tool failed.
                ("tool.result", "error"),
                ("approval.decision", "denied"),
                ("approval.decision", "denied"),
                ("agent.result", "ok"),
            ]
        );
        let denial = &events[3];
        assert_eq!(denial.source, "adapter.claude.v1");
        assert_eq!(denial.correlation_id, "toolu_rm");
        assert_eq!(denial.span_id, "toolu_rm");
        // It hangs off the call it refused and links to it.
        assert_eq!(denial.parent_event_id, "e2");
        assert_eq!(denial.links, ["e2"]);
        assert_eq!(
            denial.payload,
            json!({"provider": "claude", "adapter_schema_version": 1,
                   "native_type": "permission_denial", "synthesized": true,
                   "synthesized_from": "permission_denials", "tool": "Bash", "line": 4,
                   "native": {"tool_name": "Bash", "tool_use_id": "toolu_rm",
                              "tool_input": {"command": "rm -rf build"}}})
        );
        // A denial whose call was never printed still belongs to the session.
        assert_eq!(events[4].correlation_id, "toolu_unseen");
        assert_eq!(events[4].parent_event_id, "e1");
        assert!(events[4].links.is_empty());
        assert_eq!(events[4].payload["tool"], "Write");
        // An empty list adds nothing.
        let quiet = lines(
            Provider::Claude,
            &[
                json!({"type": "result", "subtype": "success", "session_id": "s",
                     "permission_denials": []}),
            ],
        );
        assert_eq!(quiet.len(), 1);
    }

    #[test]
    fn a_denied_tool_result_is_not_reported_as_a_failure() {
        for (provider, native) in [
            (
                Provider::Gemini,
                json!({"type": "tool_result", "tool_id": "t1", "status": "denied"}),
            ),
            (
                Provider::Opencode,
                json!({"type": "tool_use", "part": {"type": "tool", "callID": "c1", "tool": "bash",
                       "state": {"status": "rejected"}}}),
            ),
            (
                Provider::Codex,
                json!({"type": "item.completed", "item": {"id": "i", "type": "command_execution",
                       "status": "declined"}}),
            ),
        ] {
            let event = one(provider, native);
            assert_eq!(event.kind, "tool.result", "{event:?}");
            assert_eq!(event.status, "denied", "{event:?}");
        }
        let block = one(
            Provider::Claude,
            json!({"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "status": "denied"}]}}),
        );
        assert_eq!(block.status, "denied");
        // A plain failure is still an error, and a refused turn is not a tool denial.
        let failed = one(
            Provider::Gemini,
            json!({"type": "tool_result", "tool_id": "t1", "status": "error"}),
        );
        assert_eq!(failed.status, "error");
        let turn = one(
            Provider::Codex,
            json!({"type": "turn.completed", "status": "rejected"}),
        );
        assert_eq!(
            (turn.kind.as_str(), turn.status.as_str()),
            ("agent.result", "error")
        );
    }

    #[test]
    fn terminal_decorations_around_an_event_do_not_make_it_malformed() {
        let event = r#"{"type":"result","subtype":"success","result":"ok"}"#;
        let decorated: Vec<Vec<u8>> = vec![
            // Colour reset after the object, and around it.
            format!("{event}\x1b[0m").into_bytes(),
            format!("\x1b[1;32m{event}\x1b[0m\x1b[K").into_bytes(),
            // OSC ended by ST instead of BEL, and by BEL.
            format!("\x1b]0;agent title\x1b\\{event}").into_bytes(),
            format!("\x1b]8;;https://example.test\x07{event}").into_bytes(),
            // Charset selection, keypad mode, 8-bit CSI.
            format!("\x1b(B\x1b={event}").into_bytes(),
            [b"\xc2\x9b0m".as_slice(), event.as_bytes()].concat(),
            // Byte order mark, and a spinner overwritten by a carriage return.
            [b"\xef\xbb\xbf".as_slice(), event.as_bytes()].concat(),
            format!("working...\r{event}\r").into_bytes(),
            // An introducer with nothing behind it must not swallow the brace.
            format!("\x1b[{event}").into_bytes(),
        ];
        for line in decorated {
            let mut adapter = NativeAdapter::new(Provider::Droid);
            let events = adapter.push(&[line.as_slice(), b"\n"].concat());
            assert_eq!(events.len(), 1, "{:?}", String::from_utf8_lossy(&line));
            assert_eq!(
                events[0].kind,
                "model.response",
                "{:?}: {}",
                String::from_utf8_lossy(&line),
                events[0].payload
            );
            assert_eq!(adapter.summary().normalized_lines, 1);
        }
        // Text inside the event is never touched: an escaped escape stays, and so does U+009B.
        let mut adapter = NativeAdapter::new(Provider::Droid);
        let events = adapter
            .push("{\"type\":\"result\",\"result\":\"a\\u001b[31mred \u{9b}0m\"}\n".as_bytes());
        assert_eq!(
            events[0].payload["native"]["result"],
            "a\u{1b}[31mred \u{9b}0m"
        );
    }

    #[test]
    fn lines_holding_only_control_sequences_are_blank_not_malformed() {
        let mut adapter = NativeAdapter::new(Provider::Claude);
        let events = adapter.push(b"\x1b[2K\n\x1b[?25l\x1b[0m\n \r\n\xef\xbb\xbf\n");
        assert!(events.is_empty(), "{:?}", events[0].payload);
        adapter.push(b"\x1b[0m");
        assert!(adapter.finish().is_empty());
        assert_eq!(adapter.summary(), AdapterSummary::default());
        assert!(adapter.summary_event().is_some(), "nothing was normalized");
    }

    #[test]
    fn non_json_output_gets_a_bounded_number_of_diagnostics_and_a_summary() {
        let mut adapter = NativeAdapter::new(Provider::Claude);
        let mut events = Vec::new();
        for line in 0..500 {
            events.extend(adapter.push(format!("plain text line {line}\n").as_bytes()));
        }
        events.extend(adapter.finish());
        assert_eq!(events.len() as u64, MAX_LINE_DIAGNOSTICS);
        assert!(
            events
                .iter()
                .all(|event| event.kind == "adapter.diagnostic")
        );
        assert_eq!(
            events.last().unwrap().payload["further_diagnostics"],
            "suppressed"
        );
        let summary = adapter.summary();
        assert_eq!(
            summary,
            AdapterSummary {
                lines: 500,
                normalized_lines: 0,
                rejected_lines: 500,
                suppressed_diagnostics: 500 - MAX_LINE_DIAGNOSTICS,
            }
        );
        assert_eq!(summary.completeness(), "no-native-events");
        let event = adapter.summary_event().unwrap();
        assert_eq!(event.kind, "adapter.summary");
        assert_eq!(event.status, "warning");
        assert_eq!(event.payload["rejected_lines"], 500);
        assert_eq!(
            event.payload["suppressed_diagnostics"],
            500 - MAX_LINE_DIAGNOSTICS
        );
        assert_eq!(event.payload["completeness"], "no-native-events");

        // A clean run has nothing to report, and one stray line makes it partial.
        let mut clean = NativeAdapter::new(Provider::Codex);
        clean.push(b"{\"type\":\"thread.started\",\"thread_id\":\"t\"}\n");
        assert!(clean.finish().is_empty());
        assert!(clean.summary_event().is_none());
        assert_eq!(
            clean.summary().completeness(),
            "provider-native-best-effort"
        );
        clean.push(b"warning: deprecated flag\n");
        assert_eq!(clean.summary().completeness(), "provider-native-partial");
        let partial = clean.summary_event().unwrap();
        assert_eq!(partial.payload["normalized_lines"], 1);
        assert_eq!(partial.payload["rejected_lines"], 1);
    }

    #[test]
    fn structured_output_flags_are_matched_as_flags() {
        // Every provider's flag, in both spellings where there are two.
        for command in [
            &["codex", "exec", "--json", "task"][..],
            &["claude", "-p", "task", "--output-format", "stream-json"],
            &["claude", "--output-format=stream-json", "-p", "task"],
            &["gemini", "--output-format", "stream-json"],
            &["grok", "--output-format", "streaming-json"],
            &["opencode", "run", "--format", "json"],
            &["kimi", "--output-format=stream-json"],
            &["droid", "exec", "-o", "json"],
            &["droid", "exec", "--output-format", "json"],
            // A path, another case, and a Windows-style name.
            &["/usr/local/bin/codex", "exec", "--json"],
            &["Codex.EXE", "exec", "--json"],
            &["claude.cmd", "--output-format", "stream-json"],
        ] {
            assert!(auto(command).is_some(), "{command:?}");
        }
        for command in [
            // The value of another format, or the flag of another provider.
            &["claude", "--output-format", "json"][..],
            &["claude", "--output-format", "text", "stream-json"],
            &["grok", "--output-format", "stream-json"],
            &["codex", "exec", "--output-format", "stream-json"],
            // Only droid has the short form.
            &["claude", "-o", "json"],
            // A program that merely starts with a provider's name.
            &["codex-wrapper", "exec", "--json"],
            &["claude-code-router", "--output-format", "stream-json"],
            &["cat", "--json"],
        ] {
            assert_eq!(auto(command), None, "{command:?}");
        }
        assert!("CODEX".parse::<AdapterChoice>().is_ok());
        let error = "copilot".parse::<AdapterChoice>().unwrap_err();
        assert!(error.contains("auto, none, codex"), "{error}");
    }

    #[test]
    fn a_line_at_the_buffer_bound_is_kept_and_one_byte_more_is_discarded() {
        let mut at_bound = NativeAdapter::new(Provider::Codex);
        at_bound.push(&vec![b' '; MAX_BUFFERED_LINE_BYTES]);
        assert_eq!(at_bound.pending.len(), MAX_BUFFERED_LINE_BYTES);
        assert_eq!(at_bound.discarded_bytes, 0);
        // Blank, however long: no event.
        assert!(at_bound.push(b"\n").is_empty());

        let mut over = NativeAdapter::new(Provider::Codex);
        over.push(&vec![b' '; MAX_BUFFERED_LINE_BYTES + 1]);
        assert!(over.pending.is_empty());
        let events = over.push(b"\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload["line_bytes"], MAX_BUFFERED_LINE_BYTES + 1);
    }

    /// Every stored field of the events an input produces, for comparing two runs.
    fn stored_shape(provider: Provider, chunks: &[&[u8]]) -> Vec<String> {
        let mut adapter = NativeAdapter::new(provider);
        let mut stored = Vec::new();
        let mut commit = |adapter: &mut NativeAdapter, events: Vec<AdapterEvent>| {
            adapter
                .commit(events, |input| {
                    stored.push(format!(
                        "{} {} {} {} {} parent={} links={:?} {}",
                        input.kind,
                        input.status,
                        input.actor_id,
                        input.span_id,
                        input.correlation_id,
                        input.parent_event_id,
                        input.links,
                        input.payload
                    ));
                    Ok::<_, std::convert::Infallible>(format!("e{}", stored.len()))
                })
                .unwrap();
        };
        for chunk in chunks {
            let events = adapter.push(chunk);
            commit(&mut adapter, events);
        }
        let events = adapter.finish();
        commit(&mut adapter, events);
        stored
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// How the output is split into reads must not change what is recorded, including what
        /// `finish` emits for a last line without a line break.
        #[test]
        fn events_do_not_depend_on_how_the_stream_is_chunked(
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..24),
            garbage in prop::collection::vec(any::<u8>(), 0..64),
            terminated in any::<bool>(),
        ) {
            let mut stream = include_bytes!("../tests/fixtures/adapters/claude.jsonl").to_vec();
            // A line of arbitrary bytes in the middle, and optionally no final line break.
            stream.extend(garbage.iter().filter(|byte| **byte != b'\n'));
            stream.extend(b"\n{\"type\":\"result\",\"subtype\":\"success\",\"session_id\":\"s\"}");
            if terminated {
                stream.push(b'\n');
            }
            let whole = stored_shape(Provider::Claude, &[&stream]);
            prop_assert!(whole.len() > 4);
            let mut positions: Vec<usize> = cuts.iter().map(|cut| cut.index(stream.len())).collect();
            positions.sort_unstable();
            positions.dedup();
            let mut chunks = Vec::new();
            let mut start = 0;
            for position in positions {
                chunks.push(&stream[start..position]);
                start = position;
            }
            chunks.push(&stream[start..]);
            prop_assert_eq!(&stored_shape(Provider::Claude, &chunks), &whole);
            let bytes: Vec<&[u8]> = stream.chunks(1).collect();
            prop_assert_eq!(&stored_shape(Provider::Claude, &bytes), &whole);
        }
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
