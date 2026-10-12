use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use premier_cli::evidence::{
    DiffStatus, ExportDocument, ExportOptions, ExportSelection, MAX_QUERY_LIMIT, QueryMatcher,
    QueryOptions, QuerySource, RedactionOptions, SourceState, diff_traces as compare_traces,
    write_portable_evidence_with,
};
use premier_cli::liveness::{
    RecorderLiveness, UnfinalizedState, recorder_liveness, unfinalized_state,
};
use premier_cli::{
    AuthPolicy, ServerOptions, app_with_options, embedded_viewer_ready, instrumentation_app,
    validate_bind, validate_remote_trace_store,
};
use premier_trace::{
    EventInput, ProcessTermination, RECORDER_LEASE, RecoveryOptions, RedactionConfig,
    TerminationKind, TraceWriter, decode_utf8_chunk_lossy, finish_utf8_lossy, prepare_trace_output,
    read_events, read_manifest, recover_interrupted_trace_with, stream_events, verify,
    verify_trace_visiting,
};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration as StdDuration, Instant};
use tracing_subscriber::EnvFilter;

mod adapters;
use adapters::{ADAPTER_SCHEMA_VERSION, AdapterChoice, AdapterEvent, NativeAdapter, Provider};

#[derive(Parser)]
#[command(
    name = "premier",
    version,
    about = "Local-first agent trace recorder and viewer"
)]
struct Cli {
    /// Trace encryption key file, used to write new traces encrypted and to
    /// read encrypted ones. The file holds one 256-bit key as exactly 64 hex
    /// characters (from `premier keygen --encryption`, or for example
    /// `openssl rand -hex 32`) and must be readable only by its owner (mode
    /// 0600).
    #[arg(long, global = true, value_name = "PATH", env = premier_trace::KEY_FILE_ENV)]
    key_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record a command and its terminal output into a portable .atrace directory.
    Record {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Human-readable run name shown by list and the trace viewer.
        #[arg(long)]
        name: Option<String>,
        /// Immutable tenant owner recorded in the trace manifest.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Open the viewer focused on this recording when it finishes.
        #[arg(long)]
        open: bool,
        /// Run the command inside a pseudo-terminal (Unix only), preserving
        /// stdout/stderr ordering as one interactive terminal byte stream.
        #[arg(long)]
        pty: bool,
        /// Normalize a provider's native JSONL stream into typed evidence:
        /// auto, none, codex, claude, gemini, grok, opencode, kimi, or droid.
        /// Auto activates only when a recognized CLI already uses structured output.
        #[arg(long, default_value = "auto")]
        adapter: AdapterChoice,
        /// Optional disk viewer (for local UI development). Default: embedded viewer.
        #[arg(long)]
        viewer_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:4317")]
        bind: SocketAddr,
        /// Additional structured payload field name to redact recursively.
        #[arg(long = "redact-field")]
        redact_fields: Vec<String>,
        /// Exact text to redact from persisted terminal output, event payloads, and the
        /// recorded command line (terminal display stays raw).
        #[arg(long = "redact-literal")]
        redact_literals: Vec<String>,
        /// Regex to redact from persisted terminal output, event payloads, and the
        /// recorded command line (terminal display stays raw). Regex rules are
        /// line-scoped: in terminal output a match never spans a line break, so
        /// write one rule per line of a multi-line secret. A line longer than
        /// 256 KiB is stored in pieces, and only a match up to 16 KiB is
        /// guaranteed across such a cut. A partial line (such as a prompt) is
        /// stored after 1 second without output, so a match the output pauses
        /// inside can be split; use --redact-literal for exact secrets. Set
        /// PREMIER_REDACTION_IDLE_FLUSH_MS to change that idle period (in
        /// milliseconds).
        #[arg(long = "redact-regex")]
        redact_regexes: Vec<String>,
        /// Regex to redact that may match across line breaks, such as a
        /// multi-line token or key block. It applies to the same places as
        /// --redact-regex, with the same syntax (`.` crosses a line break
        /// only with `(?s)`; `\n` and `\s` always can). In terminal output
        /// it is matched over a sliding window: the most recent 16 KiB are
        /// held back, so a match up to 16 KiB is redacted however the output
        /// was split into lines and writes, and a longer match may be stored
        /// in part. In structured payloads it is matched over each whole
        /// string value. Held output is still stored after the idle period
        /// described under --redact-regex.
        #[arg(long = "redact-regex-multiline", value_name = "REGEX")]
        redact_multiline_regexes: Vec<String>,
        /// Do not apply the built-in secret value patterns (API keys, bearer
        /// credentials, URL passwords, private key blocks, JWTs) to structured
        /// event payloads and the recorded command line.
        #[arg(long)]
        no_default_secret_patterns: bool,
        /// Also apply the built-in secret value patterns to persisted terminal
        /// output, which is otherwise stored raw unless a --redact-literal or
        /// --redact-regex rule matches.
        #[arg(long)]
        redact_known_secrets: bool,
        /// Ed25519 private key file (from `premier keygen`) used to sign the
        /// trace when it is finalized.
        #[arg(long, value_name = "PATH", env = premier_trace::SIGN_KEY_FILE_ENV)]
        sign_key: Option<PathBuf>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Generate a rich local multi-agent trace for product evaluation and onboarding.
    Demo {
        /// Where to write the demo trace. An earlier demo at this path is
        /// replaced; any other trace is not, unless --force is given.
        #[arg(short, long, default_value = ".premier/traces/multi-agent-demo.atrace")]
        output: PathBuf,
        /// Replace a finalized trace at the output path even though it is not
        /// an earlier demo. A trace that is being recorded is never replaced.
        #[arg(long)]
        force: bool,
    },
    /// Emit a typed agent event to the active local collector (`PREMIER_COLLECTOR_*`).
    Emit {
        /// Full JSON event body. Use `-` to read from stdin. The body is
        /// sent as given, so it cannot be combined with the field options.
        #[arg(
            long,
            conflicts_with_all = [
                "kind", "actor", "actor_type", "span", "parent_span", "status", "payload", "source"
            ]
        )]
        json: Option<String>,
        /// Event kind (e.g. agent.spawn, model.response, tool.execution).
        #[arg(long)]
        kind: Option<String>,
        /// Actor identity for this event.
        #[arg(long)]
        actor: Option<String>,
        #[arg(long = "actor-type", default_value = "agent")]
        actor_type: String,
        #[arg(long)]
        span: Option<String>,
        #[arg(long = "parent-span")]
        parent_span: Option<String>,
        #[arg(long)]
        status: Option<String>,
        /// Payload as a JSON object string.
        #[arg(long)]
        payload: Option<String>,
        /// Source label written on the event (default: premier-emit).
        #[arg(long, default_value = "premier-emit")]
        source: String,
    },
    /// Verify a finalized trace's digest, event chain, manifest seal, and signature.
    /// Without a signature a trace is only internally consistent (docs/trace-format.md).
    /// Given a `premier export` file instead, recompute that export's own digest
    /// and report which trace it says it was derived from.
    Verify {
        /// A trace directory, or a JSON file written by `premier export`.
        trace: PathBuf,
        /// Require a valid signature by this Ed25519 public key (64 hex
        /// characters, or a file containing them). For an export file: require
        /// that its source block carries a valid signature by this key.
        #[arg(long, value_name = "PATH-OR-HEX")]
        public_key: Option<String>,
        /// For a trace that is not finalized (still recording, or abandoned):
        /// check the frames of its active journal and their hash chain up to
        /// the last complete frame, and report the event count. Nothing is
        /// modified. A finalized trace is verified as usual.
        #[arg(long)]
        live: bool,
    },
    /// Generate an Ed25519 signing key: writes the private key (mode 0600) and
    /// `<output>.pub`, and prints the public key. With --encryption, generate
    /// a trace encryption key file for --key-file instead.
    Keygen {
        /// Private key file to create. Must not already exist.
        output: PathBuf,
        /// Write a 256-bit trace encryption key (64 hex characters, mode
        /// 0600) from the system random number generator, for --key-file /
        /// PREMIER_TRACE_KEY_FILE. There is no public half.
        #[arg(long)]
        encryption: bool,
    },
    /// Sign (or re-sign) the manifest seal of an already finalized trace.
    Sign {
        trace: PathBuf,
        #[arg(long, value_name = "PATH", env = premier_trace::SIGN_KEY_FILE_ENV)]
        sign_key: PathBuf,
    },
    /// Safely finalize an abandoned active trace, discarding only a torn trailing frame.
    Recover {
        trace: PathBuf,
        /// Minimum journal idle time required before recovery.
        #[arg(long, default_value_t = 300)]
        stale_after_seconds: u64,
        /// Recover even when the journal was modified recently.
        #[arg(long)]
        force: bool,
        /// Ed25519 private key file (from `premier keygen`) used to sign the
        /// recovered trace. The signature is the recovering party's statement
        /// about what it found, not the recorder's.
        #[arg(long, value_name = "PATH", env = premier_trace::SIGN_KEY_FILE_ENV)]
        sign_key: Option<PathBuf>,
    },
    /// Atomically claim a legacy/local trace for a tenant.
    Claim {
        trace: PathBuf,
        #[arg(long)]
        tenant: String,
    },
    /// Atomically encrypt a finalized trace, or rotate it to a new master key.
    Encrypt {
        trace: PathBuf,
        #[arg(long, value_name = "PATH")]
        new_key_file: PathBuf,
        /// Re-sign the re-sealed trace. Without a key an existing signature is dropped.
        #[arg(long, value_name = "PATH", env = premier_trace::SIGN_KEY_FILE_ENV)]
        sign_key: Option<PathBuf>,
    },
    /// Filter local trace evidence without starting the viewer.
    Query {
        /// A trace directory, or a JSON file written by `premier export`.
        trace: PathBuf,
        /// Exact event kind, matched case-insensitively.
        #[arg(long)]
        kind: Option<String>,
        /// Exact actor id, matched case-insensitively.
        #[arg(long)]
        actor: Option<String>,
        /// Exact event status, matched case-insensitively.
        #[arg(long)]
        status: Option<String>,
        /// Case-insensitive search across event fields, ids, the payload
        /// JSON text, and every payload string as recorded (so quotes, line
        /// breaks, and text inside terminal colour codes match as typed).
        #[arg(long)]
        search: Option<String>,
        /// Exact event id.
        #[arg(long, value_name = "ID")]
        event_id: Option<String>,
        /// Exact span id.
        #[arg(long, value_name = "ID")]
        span: Option<String>,
        /// Exact parent span id: the events directly under a span.
        #[arg(long, value_name = "ID")]
        parent_span: Option<String>,
        /// Exact parent event id: the events caused directly by an event.
        #[arg(long, value_name = "EVENT-ID")]
        parent: Option<String>,
        /// Exact correlation id: for example a tool call and its result.
        #[arg(long, value_name = "ID")]
        correlation: Option<String>,
        /// Only events with a sequence greater than this. With --limit this
        /// pages through a trace: pass the last sequence of the previous page.
        #[arg(long, value_name = "N")]
        after_sequence: Option<u64>,
        /// Only events with a sequence less than this.
        #[arg(long, value_name = "N")]
        before_sequence: Option<u64>,
        /// Only events at or after this time (RFC 3339, for example
        /// 2026-07-15T12:00:00Z).
        #[arg(long, value_name = "TIME", value_parser = parse_query_time)]
        since: Option<chrono::DateTime<Utc>>,
        /// Only events before this time (RFC 3339).
        #[arg(long, value_name = "TIME", value_parser = parse_query_time)]
        until: Option<chrono::DateTime<Utc>>,
        /// Only events that count as issues: an error, failed, denied or
        /// blocked status, an error or failure kind, or a provider-stated failure.
        #[arg(long)]
        issues: bool,
        /// Maximum events returned (1-1000).
        #[arg(long, default_value_t = 100, value_parser = parse_query_limit)]
        limit: usize,
        /// Emit one structured JSON result instead of the compact text view.
        #[arg(long)]
        json: bool,
        /// Read a finalized trace even though it fails `premier verify`.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// Export portable JSON evidence with common secret fields recursively redacted.
    /// The `redaction` block reports the active rules and what was removed.
    Export {
        trace: PathBuf,
        /// Destination JSON file. Omit to write JSON to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Do not apply the built-in secret value patterns (API keys, bearer
        /// credentials, URL passwords, private key blocks, JWTs) to structured
        /// event payloads and the recorded command line.
        #[arg(long)]
        no_default_secret_patterns: bool,
        /// Also apply the built-in secret value patterns to captured terminal
        /// output, which is otherwise exported as recorded.
        #[arg(long)]
        redact_known_secrets: bool,
        /// Additional field name whose value is removed wherever it appears
        /// in the exported manifest and events. Repeatable.
        #[arg(long = "redact-field", value_name = "NAME")]
        redact_fields: Vec<String>,
        /// Exact text removed from every string of the exported manifest and
        /// events, terminal output included. Repeatable. The text itself is
        /// not written to the export.
        #[arg(long = "redact-literal", value_name = "TEXT")]
        redact_literals: Vec<String>,
        /// Export only events of this kind (exact, case-insensitive). Repeatable.
        #[arg(long, value_name = "KIND")]
        kind: Vec<String>,
        /// Export only events of this actor id (exact, case-insensitive). Repeatable.
        #[arg(long, value_name = "ACTOR")]
        actor: Vec<String>,
        /// Export only events with a sequence greater than this.
        #[arg(long, value_name = "N")]
        after_sequence: Option<u64>,
        /// Export only events with a sequence less than this.
        #[arg(long, value_name = "N")]
        before_sequence: Option<u64>,
        /// Export a finalized trace even though it fails `premier verify`.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// Compare two traces by semantic event structure, ignoring generated identity noise.
    /// Events are aligned in order, so an inserted, removed or moved event is
    /// reported as such; captured output is compared per stream, line by line.
    Diff {
        /// A trace directory, or a JSON file written by `premier export`.
        baseline: PathBuf,
        /// A trace directory, or a JSON file written by `premier export`.
        current: PathBuf,
        /// Emit the complete structural comparison as JSON.
        #[arg(long)]
        json: bool,
        /// Exit with status 1 when the traces differ (0 when they do not),
        /// for use in scripts and CI.
        #[arg(long)]
        exit_code: bool,
        /// Compare finalized traces even though one fails `premier verify`.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// Replay recorded evidence timing only; this never re-executes the traced command.
    /// A recorded gap longer than 10 seconds is replayed as 10 seconds.
    Replay {
        trace: PathBuf,
        /// Playback speed multiplier (for example 2 replays twice as fast),
        /// at least 0.001.
        #[arg(long, default_value_t = 1.0, value_parser = parse_replay_speed)]
        speed: f64,
        /// Emit evidence immediately while preserving recorded order.
        #[arg(long)]
        no_sleep: bool,
        /// Replay a finalized trace even though it fails `premier verify`.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// List traces in a directory.
    List {
        #[arg(long, default_value = ".premier/traces")]
        trace_dir: PathBuf,
    },
    /// Open the local viewer, optionally focused on one trace.
    Open {
        trace: Option<PathBuf>,
        #[arg(long, default_value = ".premier/traces")]
        trace_dir: PathBuf,
        /// Optional disk viewer (for local UI development). Default: embedded viewer.
        #[arg(long)]
        viewer_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:4317")]
        bind: SocketAddr,
        /// Do not expose the local assistant (also: PREMIER_DISABLE_ASSISTANT=1).
        #[arg(long)]
        no_assistant: bool,
    },
    /// Serve the viewer locally or to an authenticated team.
    Serve {
        #[arg(long, default_value = ".premier/traces")]
        trace_dir: PathBuf,
        /// Optional disk viewer (for local UI development). Default: embedded viewer.
        #[arg(long)]
        viewer_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:4317")]
        bind: SocketAddr,
        #[arg(long, env = "PREMIER_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// JSON file containing SHA-256 hashed bearer tokens, tenant ownership, and scopes.
        #[arg(long, env = "PREMIER_AUTH_CONFIG")]
        auth_config: Option<PathBuf>,
        /// PEM certificate chain for native HTTPS. Must be paired with --tls-key.
        #[arg(long, env = "PREMIER_TLS_CERT")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for native HTTPS. Must be paired with --tls-cert.
        #[arg(long, env = "PREMIER_TLS_KEY")]
        tls_key: Option<PathBuf>,
        /// Do not expose the local assistant (also: PREMIER_DISABLE_ASSISTANT=1).
        #[arg(long)]
        no_assistant: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    let cli = Cli::parse();
    if let Some(key_file) = cli.key_file {
        premier_trace::set_key_file(key_file);
    }
    if matches!(
        cli.command,
        Commands::Verify { .. }
            | Commands::Query { .. }
            | Commands::Export { .. }
            | Commands::Diff { .. }
            | Commands::Replay { .. }
            | Commands::List { .. }
    ) {
        die_quietly_on_broken_pipe();
    }
    match cli.command {
        Commands::Record {
            output,
            name,
            tenant,
            open,
            pty,
            adapter,
            viewer_dir,
            bind,
            redact_fields,
            redact_literals,
            redact_regexes,
            redact_multiline_regexes,
            no_default_secret_patterns,
            redact_known_secrets,
            sign_key,
            command,
        } => {
            let redaction = RedactionConfig::new(redact_fields, redact_literals, redact_regexes)?
                .multiline_regexes(redact_multiline_regexes)?
                .default_secret_patterns(!no_default_secret_patterns)
                .known_secrets_in_terminal(redact_known_secrets);
            let sign_key = load_signing_key(sign_key.as_deref())?;
            record(RecordOptions {
                output,
                name,
                tenant,
                command,
                open_viewer: open,
                pty,
                adapter,
                viewer_dir,
                bind,
                redaction,
                sign_key,
            })
            .await
        }
        Commands::Demo { output, force } => demo(output, force),
        Commands::Emit {
            json,
            kind,
            actor,
            actor_type,
            span,
            parent_span,
            status,
            payload,
            source,
        } => {
            emit_event(EmitArgs {
                json,
                kind,
                actor,
                actor_type,
                span,
                parent_span,
                status,
                payload,
                source,
            })
            .await
        }
        Commands::Verify {
            trace,
            public_key,
            live,
        } => {
            if trace.is_file() {
                if live {
                    bail!(
                        "--live checks a trace that is still being recorded; {} is an export file",
                        trace.display()
                    )
                }
                return verify_export(&trace, public_key.as_deref());
            }
            if let Ok(manifest) = read_manifest(&trace)
                && let Some(state) = unfinalized_state(&trace, &manifest)
            {
                if !live {
                    bail!(
                        "trace is not finalized ({}); `premier verify --live {}` checks the frames recorded so far without changing anything",
                        state.describe(&trace),
                        trace.display()
                    )
                }
                if public_key.is_some() {
                    bail!("a trace that is not finalized has no signature to check")
                }
                return verify_live(&trace, state);
            }
            let trusted_key = public_key
                .as_deref()
                .map(premier_trace::PublicKey::from_hex_or_file)
                .transpose()?;
            // Diagnostics are derived in the same pass that verifies.
            let mut validator = premier_trace::EventValidator::default();
            let verified =
                verify_trace_visiting(&trace, trusted_key.as_ref(), |event| validator.push(event))
                    .with_context(|| format!("invalid: {} failed verification", trace.display()))?;
            let (outcome, note) = verification_outcome(&verified);
            let mut manifest = verified.manifest;
            // Judged by this build's rules, not by those of whichever build
            // finalized the trace; what only the recorder knew is kept.
            manifest.diagnostics =
                premier_trace::current_diagnostics(&manifest.diagnostics, validator.finish());
            println!(
                "{outcome} {} ({} events, {} semantic diagnostics)",
                manifest.trace_id,
                manifest
                    .journal
                    .as_ref()
                    .map_or(0, |journal| journal.event_count),
                manifest.diagnostics.len(),
            );
            if let Some(note) = note {
                println!("note: {note}");
            }
            if manifest.seal.as_ref().is_some_and(|seal| seal.recovered) {
                println!(
                    "note: finalized by `premier recover`, not by its recorder. An unfinalized journal does not commit to its length, so this shows the kept events are genuine and in order, not that none were recorded after them"
                );
            }
            for diagnostic in &manifest.diagnostics {
                println!(
                    "warning {} at sequence {}: {}",
                    printable(&diagnostic.code),
                    diagnostic.sequence.unwrap_or(0),
                    printable(&diagnostic.message)
                );
            }
            Ok(())
        }
        Commands::Recover {
            trace,
            stale_after_seconds,
            force,
            sign_key,
        } => {
            let sign_key = load_signing_key(sign_key.as_deref())?;
            // The idle guard only approximates "is the recorder gone?"; the
            // lease answers it directly when it names a process.
            let mut skip_idle_guard = force;
            if !force {
                match recorder_liveness(&trace) {
                    // Without a liveness probe the idle guard stays in charge.
                    RecorderLiveness::Alive(pid) if cfg!(unix) => bail!(
                        "trace is still being recorded by process {pid}; stop that recorder and let it finalize the trace, or pass --force to finalize it anyway"
                    ),
                    RecorderLiveness::Dead => skip_idle_guard = true,
                    RecorderLiveness::Alive(_) | RecorderLiveness::Unknown => {}
                }
            }
            let report = recover_interrupted_trace_with(
                &trace,
                RecoveryOptions {
                    minimum_idle: StdDuration::from_secs(stale_after_seconds),
                    force: skip_idle_guard,
                },
                sign_key.as_ref(),
            )?;
            let manifest = &report.manifest;
            if !report.removed_leftovers.is_empty() {
                println!(
                    "{} is already finalized ({} events); removed what an interrupted finalization left behind: {}",
                    manifest.trace_id,
                    report.salvaged_events,
                    report.removed_leftovers.join(", ")
                );
                return Ok(());
            }
            println!(
                "recovered {} ({} events, exit {})",
                manifest.trace_id,
                manifest
                    .journal
                    .as_ref()
                    .map_or(0, |journal| journal.event_count),
                manifest.exit_code.unwrap_or(130)
            );
            println!(
                "kept {} recorded event(s) and appended session.interrupted",
                report.salvaged_events
            );
            if report.journaled_exit {
                println!(
                    "the command's exit was already recorded (process.exit); the trace keeps that exit status"
                );
            }
            if report.discarded_bytes > 0 {
                println!(
                    "discarded {} byte(s) ({}) after sequence {}: {}",
                    report.discarded_bytes,
                    report.discarded_frames.map_or_else(
                        || "an unknown number of frames".to_owned(),
                        |frames| format!("{frames} frame(s)")
                    ),
                    report.salvaged_events,
                    printable(
                        report
                            .reason
                            .as_deref()
                            .unwrap_or("the journal ends inside a frame")
                    )
                );
            }
            if let Some(key) = sign_key.as_ref().filter(|_| is_signed(Some(manifest))) {
                println!(
                    "signed the recovered trace with key {}",
                    key.public_key().fingerprint()
                );
            }
            Ok(())
        }
        Commands::Keygen { output, encryption } => {
            if encryption {
                keygen_encryption(&output)
            } else {
                keygen(&output)
            }
        }
        Commands::Sign { trace, sign_key } => {
            let key = premier_trace::SigningKey::from_file(&sign_key)
                .with_context(|| format!("cannot load signing key {}", sign_key.display()))?;
            let manifest = premier_trace::sign_finalized_trace(&trace, &key)?;
            println!(
                "signed {} with key {}",
                manifest.trace_id,
                key.public_key().fingerprint()
            );
            Ok(())
        }
        Commands::Claim { trace, tenant } => {
            let was_signed = is_signed(read_manifest(&trace).ok().as_ref());
            let manifest = premier_trace::claim_local_trace(&trace, &tenant)?;
            println!(
                "claimed {} for tenant {}",
                manifest.trace_id, manifest.tenant_id
            );
            report_resealed_signature(was_signed, &manifest);
            Ok(())
        }
        Commands::Encrypt {
            trace,
            new_key_file,
            sign_key,
        } => {
            let key = premier_trace::EncryptionKey::from_file(&new_key_file)?;
            let sign_key = load_signing_key(sign_key.as_deref())?;
            let was_signed = is_signed(read_manifest(&trace).ok().as_ref());
            let manifest = premier_trace::reencrypt_finalized_trace_with_signing_key(
                &trace,
                key,
                sign_key.as_ref(),
            )?;
            println!("encrypted {} ({})", manifest.trace_id, trace.display());
            report_resealed_signature(was_signed, &manifest);
            Ok(())
        }
        Commands::Query {
            trace,
            kind,
            actor,
            status,
            search,
            event_id,
            span,
            parent_span,
            parent,
            correlation,
            after_sequence,
            before_sequence,
            since,
            until,
            issues,
            limit,
            json,
            allow_unverified,
        } => query_trace(
            trace,
            QueryOptions {
                kind,
                actor,
                status,
                search,
                event_id,
                span,
                parent_span,
                parent,
                correlation,
                after_sequence,
                before_sequence,
                since,
                until,
                issues,
                limit,
            },
            json,
            allow_unverified,
        ),
        Commands::Export {
            trace,
            output,
            no_default_secret_patterns,
            redact_known_secrets,
            redact_fields,
            redact_literals,
            kind,
            actor,
            after_sequence,
            before_sequence,
            allow_unverified,
        } => {
            if trace.is_file() {
                bail!(
                    "{} is a file, not a trace directory; an export cannot be exported again",
                    trace.display()
                )
            }
            if redact_literals.iter().any(String::is_empty) {
                bail!("--redact-literal must not be empty")
            }
            let source_state = ensure_verified(&trace, allow_unverified)?;
            export_trace(
                trace,
                output,
                ExportOptions {
                    redaction: RedactionOptions {
                        default_secret_patterns: !no_default_secret_patterns,
                        known_secrets_in_terminal: redact_known_secrets,
                    },
                    selection: ExportSelection {
                        kind,
                        actor,
                        after_sequence,
                        before_sequence,
                    },
                    source_state,
                    redact_fields,
                    redact_literals,
                },
            )
        }
        Commands::Diff {
            baseline,
            current,
            json,
            exit_code,
            allow_unverified,
        } => diff_traces(baseline, current, json, exit_code, allow_unverified),
        Commands::Replay {
            trace,
            speed,
            no_sleep,
            allow_unverified,
        } => {
            ensure_verified(&trace, allow_unverified)?;
            replay_trace(trace, speed, no_sleep)
        }
        Commands::List { trace_dir } => list(trace_dir),
        Commands::Open {
            trace,
            trace_dir,
            viewer_dir,
            bind,
            no_assistant,
        } => {
            let mut options = server_options(no_assistant);
            let (trace_dir, focus) = if let Some(trace) = trace {
                let manifest = read_manifest(&trace)
                    .with_context(|| format!("cannot open trace {}", trace.display()))?;
                // The viewer this starts answers as the local identity, which
                // is never shown another tenant's trace: say so here instead
                // of opening a browser on a page that answers "not found".
                if manifest.tenant_id != premier_trace::LOCAL_TENANT {
                    bail!(
                        "cannot open {}: it is owned by tenant '{}', and `premier open` serves the local viewer identity, which cannot see it. {TENANT_TRACE_HINT}",
                        trace.display(),
                        manifest.tenant_id
                    )
                }
                let (trace_dir, only_artifact) = single_trace_scope(&trace)?;
                // Address the trace by its directory name: a copy elsewhere
                // may share its trace id.
                let focus = only_artifact.to_string_lossy().into_owned();
                options.only_artifact = Some(only_artifact);
                (trace_dir, Some(focus))
            } else {
                (trace_dir, None)
            };
            serve_viewer(
                trace_dir,
                viewer_dir,
                bind,
                AuthPolicy::default(),
                options,
                focus,
                true,
                None,
            )
            .await
        }
        Commands::Serve {
            trace_dir,
            viewer_dir,
            bind,
            password,
            auth_config,
            tls_cert,
            tls_key,
            no_assistant,
        } => {
            if !bind.ip().is_loopback()
                && password.as_deref().is_some_and(|password| {
                    password.trim().chars().count() < MIN_REMOTE_PASSWORD_CHARS
                })
            {
                eprintln!(
                    "warning: the viewer password is shorter than {MIN_REMOTE_PASSWORD_CHARS} characters and this server is reachable from other machines; it is one shared secret for every user, so use a long random one (failed sign-ins are delayed and logged, not locked out)"
                );
            }
            let auth = AuthPolicy::from_sources(password, auth_config.as_deref())?;
            let tls = TlsFiles::from_options(tls_cert, tls_key)?;
            let options = server_options(no_assistant);
            serve_viewer(trace_dir, viewer_dir, bind, auth, options, None, false, tls).await
        }
    }
}

/// A shorter viewer password on a non-loopback address draws a warning.
const MIN_REMOTE_PASSWORD_CHARS: usize = 12;

/// How a trace owned by a tenant other than `local` can be read. The browser
/// viewer cannot: it signs in with the server password, which is the local
/// identity, and sends no bearer token.
const TENANT_TRACE_HINT: &str = "A tenant's traces are readable through the HTTP API only: start `premier serve --auth-config <file>` and request `/api/traces` with that tenant's bearer token (`Authorization: Bearer <token>`). The browser viewer signs in with the server password, which is the local identity, so it cannot show tenant-owned traces";

/// Viewer options shared by every command that serves; the environment switch
/// also covers `record --open`.
fn server_options(no_assistant: bool) -> ServerOptions {
    let disabled_by_env = std::env::var("PREMIER_DISABLE_ASSISTANT")
        .is_ok_and(|value| !matches!(value.trim(), "" | "0" | "false" | "no" | "off"));
    ServerOptions {
        disable_assistant: no_assistant || disabled_by_env,
        ..ServerOptions::default()
    }
}

/// The directory to serve and the one entry in it to publish when the viewer
/// is opened for a single trace. Canonical so `.` and `dir/..` still name one
/// directory entry: opening a trace must not publish its siblings.
fn single_trace_scope(trace: &std::path::Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let trace = fs::canonicalize(trace)?;
    let only_artifact = trace
        .file_name()
        .context("trace path has no directory name")?
        .to_owned();
    Ok((trace_parent_dir(&trace), only_artifact))
}

fn load_signing_key(path: Option<&std::path::Path>) -> Result<Option<premier_trace::SigningKey>> {
    path.map(|path| {
        premier_trace::SigningKey::from_file(path)
            .with_context(|| format!("cannot load signing key {}", path.display()))
    })
    .transpose()
}

/// Create a signing key pair. The private key file is created exclusively
/// with owner-only permissions; the public half is safe to share.
fn keygen(output: &std::path::Path) -> Result<()> {
    let key = premier_trace::SigningKey::generate();
    let public = key.public_key();
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("cannot create private key file {}", output.display()))?;
    writeln!(file, "{}", key.to_hex())?;
    file.sync_all()?;
    let mut public_path = output.as_os_str().to_owned();
    public_path.push(".pub");
    let public_path = PathBuf::from(public_path);
    fs::write(&public_path, format!("{}\n", public.to_hex()))
        .with_context(|| format!("cannot write public key file {}", public_path.display()))?;
    println!(
        "wrote private signing key to {} (owner-only); keep it secret",
        output.display()
    );
    println!("wrote public key to {}", public_path.display());
    println!("public key: {}", public.to_hex());
    println!("fingerprint: {}", public.fingerprint());
    Ok(())
}

/// Create a trace encryption key file: one 256-bit key as 64 hex characters,
/// created exclusively and readable only by its owner.
fn keygen_encryption(output: &std::path::Path) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("cannot create trace key file {}", output.display()))?;
    let key = premier_trace::random_secret_hex()?;
    writeln!(file, "{key}")?;
    file.sync_all()?;
    println!(
        "wrote trace encryption key to {} (owner-only); keep it secret and backed up: traces encrypted with it cannot be read without it",
        output.display()
    );
    println!(
        "key id: {}",
        premier_trace::EncryptionKey::from_hex(&key)?.key_id()
    );
    println!(
        "use it with: premier --key-file {} record -- <command>",
        output.display()
    );
    Ok(())
}

/// `premier verify --live`: check an unfinalized trace's active journal up to
/// its last complete frame. Read-only.
fn verify_live(trace: &std::path::Path, state: UnfinalizedState) -> Result<()> {
    let report = premier_trace::inspect_active_journal(trace)
        .with_context(|| format!("cannot check the active journal of {}", trace.display()))?;
    let checked = if report.format_version >= 2 {
        "frames and hash chain valid"
    } else {
        "frames valid (v1: no hash chain)"
    };
    if let premier_trace::JournalEnd::Invalid { reason, .. } = &report.end {
        bail!(
            "invalid: the active journal of {} holds a frame that cannot be genuine after {} valid event(s), at byte {} of {}: {}. `premier recover` finalizes the valid part and records what it discards",
            report.trace_id,
            report.events,
            report.valid_bytes,
            report.total_bytes,
            printable(reason)
        )
    }
    println!(
        "live: {checked} up to the last complete frame: {} ({} events, not finalized: {})",
        report.trace_id,
        report.events,
        state.describe(trace)
    );
    if report.end == premier_trace::JournalEnd::TornTail {
        println!(
            "note: the last {} byte(s) are an incomplete frame: one still being written, or torn by an interruption",
            report.total_bytes - report.valid_bytes
        );
    }
    println!(
        "note: an unfinalized journal has no digest, seal or signature. This shows that the complete frames belong to this trace and follow one another; events removed from the end leave no mark"
    );
    Ok(())
}

/// Leading words and caveat of a successful `premier verify`. Only a
/// signature by a key the caller supplied is called verified; everything else
/// is described as what it is.
fn verification_outcome(verified: &premier_trace::VerifiedTrace) -> (String, Option<&'static str>) {
    let fingerprint = verified
        .signer
        .as_ref()
        .map(|key| key.fingerprint())
        .unwrap_or_default();
    match verified.protection {
        premier_trace::Protection::Signed if verified.trusted_signer => (
            format!("verified: chain and seal valid, signed by the supplied key {fingerprint}:"),
            None,
        ),
        premier_trace::Protection::Signed => (
            format!("consistent: chain and seal valid, signed by an unknown key {fingerprint}:"),
            Some(
                "the signature is valid for the key stored in the trace itself, which says nothing about who signed it; pass --public-key with a key you trust",
            ),
        ),
        premier_trace::Protection::Sealed => (
            "consistent: chain and seal valid, unsigned:".into(),
            Some(
                "an unsigned trace is only internally consistent. That catches accidental or careless changes; anyone who can write to the trace can rebuild the chain and seal. Sign traces (premier keygen, record --sign-key, premier sign) for tamper evidence",
            ),
        ),
        premier_trace::Protection::DigestOnly => (
            "consistent (v1: digest only):".into(),
            Some(
                "version 1 traces have no event chain, seal or signature; the journal only matches a digest stored in the same unsigned manifest",
            ),
        ),
    }
}

fn is_signed(manifest: Option<&premier_trace::TraceManifest>) -> bool {
    manifest
        .and_then(|manifest| manifest.seal.as_ref())
        .is_some_and(|seal| seal.signature.is_some())
}

/// Say what happened to the signature of a trace whose manifest was re-sealed.
fn report_resealed_signature(was_signed: bool, manifest: &premier_trace::TraceManifest) {
    match (was_signed, is_signed(Some(manifest))) {
        (_, true) => println!("re-sealed and signed with the configured signing key"),
        (true, false) => println!(
            "warning: the previous signature covered the old manifest and was dropped; re-sign with `premier sign`"
        ),
        (false, false) => {}
    }
}

/// Gate evidence-reading commands on the same checks as `premier verify`.
/// A live trace has no digest yet, so it is readable with a note; a finalized
/// trace that fails verification is refused unless explicitly allowed.
fn ensure_verified(trace: &std::path::Path, allow_unverified: bool) -> Result<SourceState> {
    let manifest =
        read_manifest(trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    if manifest.journal.is_none() {
        eprintln!(
            "note: {} is not finalized (still recording or interrupted); its events are unverified and may be incomplete",
            trace.display()
        );
        return Ok(SourceState::NotFinalized);
    }
    match verify(trace) {
        Ok(_) => Ok(SourceState::Verified),
        Err(error) if allow_unverified => {
            eprintln!(
                "warning: {} failed verification ({error:#}); reading it anyway because --allow-unverified was given",
                trace.display()
            );
            Ok(SourceState::Failed)
        }
        Err(error) => bail!(
            "trace {} failed verification: {error:#}. Its evidence may have been altered or truncated; pass --allow-unverified to read it anyway",
            trace.display()
        ),
    }
}

fn parse_query_limit(value: &str) -> std::result::Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| format!("limit must be an integer between 1 and {MAX_QUERY_LIMIT}"))?;
    if !(1..=MAX_QUERY_LIMIT).contains(&limit) {
        return Err(format!("limit must be between 1 and {MAX_QUERY_LIMIT}"));
    }
    Ok(limit)
}

fn parse_query_time(value: &str) -> std::result::Result<chrono::DateTime<Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| {
            "time must be RFC 3339 with an offset, for example 2026-07-15T12:00:00Z".to_owned()
        })
}

/// Read a `premier export` file and check its own digest, as `ensure_verified`
/// does for a trace. An export is a derived copy, so the reader is told.
fn load_export(path: &std::path::Path, allow_unverified: bool) -> Result<ExportDocument> {
    let bytes = fs::read(path).with_context(|| format!("cannot read export {}", path.display()))?;
    let export = ExportDocument::parse(&bytes)
        .with_context(|| format!("cannot read {} as an export", path.display()))?;
    match export.verify() {
        Ok(verified) => eprintln!(
            "note: {} is an export (digest sha256:{}): a derived, redacted copy of trace {}, not the sealed trace",
            path.display(),
            verified.digest,
            printable(&verified.source_trace_id)
        ),
        Err(error) if allow_unverified => eprintln!(
            "warning: export {} failed verification ({error:#}); reading it anyway because --allow-unverified was given",
            path.display()
        ),
        Err(error) => bail!(
            "export {} failed verification: {error:#}. Pass --allow-unverified to read it anyway",
            path.display()
        ),
    }
    Ok(export)
}

/// `premier verify <export.json>`: recompute the export's digest and say what
/// the export claims to be derived from.
fn verify_export(path: &std::path::Path, public_key: Option<&str>) -> Result<()> {
    let trusted_key = public_key
        .map(premier_trace::PublicKey::from_hex_or_file)
        .transpose()?;
    let bytes = fs::read(path).with_context(|| format!("cannot read export {}", path.display()))?;
    let verified = ExportDocument::parse(&bytes)
        .and_then(|export| export.verify())
        .with_context(|| format!("invalid: export {} failed verification", path.display()))?;
    if let Some(trusted) = &trusted_key {
        match &verified.source_signer {
            Some(signer) if signer == trusted => {}
            Some(signer) => bail!(
                "invalid: the export's source trace is signed by a different key ({}), not the supplied key {}",
                signer.fingerprint(),
                trusted.fingerprint()
            ),
            None => bail!(
                "invalid: the export's source block carries no signature, so nothing ties it to the supplied key"
            ),
        }
    }
    println!(
        "export consistent: {} ({} events, digest sha256:{})",
        path.display(),
        verified.event_count,
        verified.digest
    );
    let selection = match (verified.selection_applied, verified.source_events) {
        (true, Some(source)) => format!(
            "; a selection kept {} of the {source} source events",
            verified.event_count
        ),
        _ => String::new(),
    };
    println!(
        "derived from trace {} ({}, source verification when exported: {}){selection}",
        printable(&verified.source_trace_id),
        printable(&verified.source_protection),
        printable(&verified.source_verification),
    );
    match &verified.source_signer {
        Some(signer) if trusted_key.is_some() => println!(
            "source signature: valid for the source seal, by the supplied key {}",
            signer.fingerprint()
        ),
        Some(signer) => println!(
            "source signature: valid for the source seal, by an unknown key {} (pass --public-key with a key you trust)",
            signer.fingerprint()
        ),
        None => println!("source signature: none; the source trace was not signed"),
    }
    println!(
        "note: an export is a derived, redacted copy, not the sealed original. Its digest is stored in the file it covers, so this detects damage and careless edits; whoever can rewrite the file can recompute the digest. The source signature, when present, shows that the key's holder signed a trace with that seal; it does not cover the exported events. Verify the original trace for that"
    );
    Ok(())
}

fn parse_replay_speed(value: &str) -> std::result::Result<f64, String> {
    let speed = value
        .parse::<f64>()
        .map_err(|_| "speed must be a positive finite number".to_owned())?;
    if !speed.is_finite() || speed <= 0.0 {
        return Err("speed must be a positive finite number".into());
    }
    // Slower than this turns the 10 second gap cap into hours per event.
    if speed < MIN_REPLAY_SPEED {
        return Err(format!("speed must be at least {MIN_REPLAY_SPEED}"));
    }
    Ok(speed)
}

/// One-shot commands that print evidence end like any other Unix filter when
/// their reader goes away (`premier query ... | head -1`): killed by SIGPIPE,
/// which a shell reports as status 141, instead of panicking in `println!`.
/// Rust ignores SIGPIPE by default; `record`, `open`, and `serve` keep that,
/// because a closed terminal or client socket must not kill them.
fn die_quietly_on_broken_pipe() {
    #[cfg(unix)]
    // SAFETY: restoring the default disposition of SIGPIPE has no
    // preconditions; it runs before the command produces any output.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// `value` made safe for a terminal line: control characters (NUL, ESC, CR,
/// LF, ...) and invisible or direction-changing format characters are shown
/// as escapes, so recorded text can neither drive the terminal nor forge
/// extra output lines. JSON output never passes through here and stays exact.
fn printable(value: &str) -> std::borrow::Cow<'_, str> {
    let unsafe_char = |c: char| {
        c.is_control()
            || matches!(
                c,
                '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{feff}'
            )
    };
    if !value.contains(unsafe_char) {
        return value.into();
    }
    let mut escaped = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if unsafe_char(c) {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    escaped.into()
}

fn print_json(value: &impl Serialize) -> Result<()> {
    // Unbuffered, every token the serializer emits is its own write call.
    let mut output = BufWriter::new(std::io::stdout().lock());
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn query_trace(
    trace: PathBuf,
    options: QueryOptions,
    json_output: bool,
    allow_unverified: bool,
) -> Result<()> {
    // Only the matches up to the limit are kept while the events go by.
    let mut matcher = QueryMatcher::new(&options);
    let source = if trace.is_file() {
        let export = load_export(&trace, allow_unverified)?;
        let verification = match export.verify() {
            Ok(_) => "verified",
            Err(_) => "failed",
        };
        for event in export.events {
            matcher.push(event);
        }
        QuerySource {
            kind: "export",
            finalized: export.document["source"]["finalized"]
                .as_bool()
                .unwrap_or(true),
            verification,
        }
    } else {
        let state = ensure_verified(&trace, allow_unverified)?;
        let mut events = stream_events(&trace)?;
        for event in &mut events {
            matcher.push(event?);
        }
        events.ensure_intact()?;
        QuerySource {
            kind: "trace",
            finalized: state != SourceState::NotFinalized,
            verification: match state {
                SourceState::NotFinalized => "not_finalized",
                SourceState::Failed => "failed",
                _ => "verified",
            },
        }
    };
    let mut result = matcher.finish();
    result.source = Some(source);
    if json_output {
        return print_json(&result);
    }
    let mut output = BufWriter::new(std::io::stdout().lock());
    for event in &result.events {
        writeln!(
            output,
            "{:>6}  {}  {:<24} {:<18} {}",
            event.sequence,
            printable(&event.timestamp),
            printable(&event.kind),
            // An event without an actor is unattributed, not the root process.
            if event.actor_id.is_empty() {
                "-".into()
            } else {
                printable(&event.actor_id)
            },
            printable(&event.status)
        )?;
    }
    output.flush()?;
    eprintln!(
        "{} matched; {} returned{}",
        result.matched,
        result.returned,
        match result.next_after_sequence {
            Some(sequence) =>
                format!(" (limit reached; continue with --after-sequence {sequence})"),
            None if result.truncated => " (limit reached)".to_owned(),
            None => String::new(),
        }
    );
    Ok(())
}

fn export_trace(trace: PathBuf, output: Option<PathBuf>, options: ExportOptions) -> Result<()> {
    let manifest =
        read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    if let Some(output) = &output {
        refuse_export_into_a_trace(output)?;
    }
    let mut events = stream_events(&trace)?;
    if manifest.encryption.is_some() {
        eprintln!(
            "warning: {} is encrypted, but this export is plaintext; protect or delete it accordingly",
            trace.display()
        );
    }
    // Events are redacted and written one at a time; the export is never
    // held in memory.
    let Some(output) = output else {
        let mut stdout = BufWriter::new(std::io::stdout().lock());
        write_portable_evidence_with(&mut stdout, &manifest, &mut events, &options)?;
        writeln!(stdout)?;
        stdout.flush()?;
        return events.ensure_intact();
    };
    let temporary = output.with_file_name(format!(
        ".{}.tmp-{}",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("premier-export"),
        std::process::id()
    ));
    let written = write_export_file(&temporary, &output, &manifest, &mut events, &options);
    let summary = match written {
        Ok(summary) => summary,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    println!(
        "exported redacted evidence to {} ({} value(s) redacted by this export, {} already redacted when recorded)",
        output.display(),
        summary.redacted.total + summary.custom.fields + summary.custom.literals,
        summary.redacted.already_redacted
    );
    if summary.exported_events != summary.source_events {
        println!(
            "selection: {} of {} events exported",
            summary.exported_events, summary.source_events
        );
    }
    println!(
        "export digest: sha256:{} (check with `premier verify {}`)",
        summary.digest,
        output.display()
    );
    Ok(())
}

/// An export written into a trace directory would replace one of the trace's
/// own files (`-o run.atrace/manifest.json`) or leave a stray file in it.
fn refuse_export_into_a_trace(output: &std::path::Path) -> Result<()> {
    if output.is_dir() {
        bail!(
            "refusing to export to {}: it is a directory; name a JSON file",
            output.display()
        )
    }
    let mut directory = Some(trace_parent_dir(output));
    while let Some(candidate) = directory {
        if candidate.join("manifest.json").is_file() && candidate.join("events").is_dir() {
            bail!(
                "refusing to export to {}: {} is a trace directory, and an export must not be written into a trace",
                output.display(),
                candidate.display()
            )
        }
        directory = candidate
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf);
    }
    Ok(())
}

/// Write the export next to its destination, then publish it atomically.
fn write_export_file(
    temporary: &std::path::Path,
    output: &std::path::Path,
    manifest: &premier_trace::TraceManifest,
    events: &mut premier_trace::EventStream,
    options: &ExportOptions,
) -> Result<premier_cli::evidence::ExportSummary> {
    let mut file = BufWriter::new(
        create_private(temporary)
            .with_context(|| format!("cannot write export {}", temporary.display()))?,
    );
    let summary = write_portable_evidence_with(&mut file, manifest, &mut *events, options)?;
    events.ensure_intact()?;
    writeln!(file)?;
    file.into_inner()
        .map_err(|error| error.into_error())
        .and_then(|file| file.sync_all())
        .with_context(|| format!("cannot write export {}", temporary.display()))?;
    fs::rename(temporary, output)
        .with_context(|| format!("cannot publish export {}", output.display()))?;
    Ok(summary)
}

/// Create `path` readable and writable by its owner only (0600 on Unix): an
/// export holds the trace's evidence in plaintext.
fn create_private(path: &std::path::Path) -> std::io::Result<fs::File> {
    // A leftover file would keep its own, possibly wider, permissions.
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// One side of a diff: its manifest as JSON and its events, from a trace
/// directory or from an export file.
fn diff_side(
    path: &std::path::Path,
    role: &str,
    allow_unverified: bool,
) -> Result<(serde_json::Value, Vec<premier_trace::TraceEvent>)> {
    if path.is_file() {
        let export = load_export(path, allow_unverified)?;
        return Ok((export.manifest().clone(), export.events));
    }
    ensure_verified(path, allow_unverified)?;
    let manifest = read_manifest(path)
        .with_context(|| format!("cannot read {role} trace {}", path.display()))?;
    Ok((serde_json::to_value(&manifest)?, read_events(path)?))
}

/// A diff value on one terminal line.
fn diff_value(value: &serde_json::Value) -> String {
    const MAX_CHARS: usize = 120;
    let text = match value {
        serde_json::Value::String(text) => format!("{text:?}"),
        other => other.to_string(),
    };
    let text = printable(&text);
    if text.chars().count() <= MAX_CHARS {
        return text.into_owned();
    }
    let mut shortened: String = text.chars().take(MAX_CHARS).collect();
    shortened.push('…');
    shortened
}

fn diff_position(baseline: Option<u64>, current: Option<u64>) -> String {
    match (baseline, current) {
        (Some(baseline), Some(current)) => {
            format!("baseline #{baseline}, current #{current}")
        }
        (Some(baseline), None) => format!("baseline #{baseline}"),
        (None, Some(current)) => format!("current #{current}"),
        (None, None) => String::new(),
    }
}

fn diff_traces(
    baseline: PathBuf,
    current: PathBuf,
    json_output: bool,
    exit_code: bool,
    allow_unverified: bool,
) -> Result<()> {
    let (baseline_manifest, baseline_events) = diff_side(&baseline, "baseline", allow_unverified)?;
    let (current_manifest, current_events) = diff_side(&current, "current", allow_unverified)?;
    let diff = compare_traces(
        &baseline_manifest,
        &baseline_events,
        &current_manifest,
        &current_events,
    );
    if json_output {
        print_json(&diff)?;
    } else {
        print_diff(&diff)?;
    }
    if exit_code && !diff.identical {
        // The comparison itself succeeded; the status reports its result.
        std::io::stdout().flush()?;
        std::process::exit(1);
    }
    Ok(())
}

fn print_diff(diff: &premier_cli::evidence::TraceDiff) -> Result<()> {
    let mut output = BufWriter::new(std::io::stdout().lock());
    writeln!(
        output,
        "{} added · {} removed · {} changed · {} moved · {} unchanged",
        diff.counts.added,
        diff.counts.removed,
        diff.counts.changed,
        diff.counts.moved,
        diff.counts.unchanged
    )?;
    match &diff.first_divergence {
        None if diff.manifest.is_empty() => writeln!(output, "no differences")?,
        None => writeln!(output, "events do not differ; the manifests do")?,
        Some(first) => {
            writeln!(
                output,
                "first divergence: {} {} ({})",
                format!("{:?}", first.status).to_lowercase(),
                printable(&first.key),
                diff_position(first.baseline_sequence, first.current_sequence)
            )?;
            if let Some(change) = &first.change {
                writeln!(
                    output,
                    "    {}: {} → {}",
                    printable(&change.field),
                    diff_value(&change.before),
                    diff_value(&change.after)
                )?;
            }
        }
    }
    if diff.alignment != "ordered" {
        writeln!(
            output,
            "note: the traces differ in too many places to align in order; events were paired per kind and actor, and order was not compared"
        )?;
    }
    for change in &diff.manifest {
        writeln!(
            output,
            "manifest\t{}: {} → {}",
            printable(&change.field),
            diff_value(&change.before),
            diff_value(&change.after)
        )?;
    }
    for item in diff
        .items
        .iter()
        .filter(|item| item.status != DiffStatus::Unchanged)
    {
        writeln!(
            output,
            "{:?}\t{}\t{}\t{} field change{}",
            item.status,
            printable(&item.key),
            diff_position(item.baseline_sequence, item.current_sequence),
            item.changes.len(),
            if item.changes.len() == 1 { "" } else { "s" }
        )?;
        for change in &item.changes {
            writeln!(
                output,
                "    {}: {} → {}",
                printable(&change.field),
                diff_value(&change.before),
                diff_value(&change.after)
            )?;
        }
    }
    output.flush()?;
    Ok(())
}

/// Longest recorded gap between two events that replay waits out (before
/// `--speed` scaling). Timestamps are recorded evidence, not trusted input: a
/// wrong clock or a forged timestamp must not make replay sleep for years.
const MAX_REPLAY_GAP: StdDuration = StdDuration::from_secs(10);
/// Slowest accepted `--speed`.
const MIN_REPLAY_SPEED: f64 = 0.001;

fn replay_trace(trace: PathBuf, speed: f64, no_sleep: bool) -> Result<()> {
    let manifest =
        read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    // Events are emitted in journal order as they are decoded. An unfinalized
    // journal has no recorded count, so it is counted first.
    let event_count = match manifest.journal.as_ref() {
        Some(journal) => journal.event_count,
        None => {
            let mut events = stream_events(&trace)?;
            for event in &mut events {
                event?;
            }
            events.ensure_intact()?;
            events.events_read()
        }
    };
    eprintln!(
        "NON-EXECUTION evidence replay: emitting {event_count} recorded events at {speed}x; no commands, tools, or models will run"
    );
    let mut previous = None;
    let mut output = BufWriter::new(std::io::stdout().lock());
    let mut events = stream_events(&trace)?;
    for event in &mut events {
        let event = event?;
        if !no_sleep && let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(&event.timestamp) {
            if let Some(previous) = previous {
                let delay = timestamp.signed_duration_since(previous);
                if let Ok(delay) = delay.to_std()
                    && !delay.is_zero()
                {
                    let delay = delay.min(MAX_REPLAY_GAP);
                    // Everything emitted so far is visible while waiting.
                    output.flush()?;
                    // Never the panicking conversion: the quotient is
                    // bounded by the speed limit, but it is still arithmetic
                    // on recorded input.
                    thread::sleep(
                        StdDuration::try_from_secs_f64(delay.as_secs_f64() / speed)
                            .unwrap_or(MAX_REPLAY_GAP),
                    );
                }
            }
            previous = Some(timestamp);
        }
        serde_json::to_writer(&mut output, &event)?;
        writeln!(output)?;
        if !no_sleep {
            output.flush()?;
        }
    }
    output.flush()?;
    events.ensure_intact()
}

fn resolve_viewer_dir(viewer_dir: Option<PathBuf>) -> Result<Option<PathBuf>> {
    match viewer_dir {
        Some(dir) => {
            if !dir.join("index.html").is_file() {
                bail!(
                    "viewer build not found at {}; omit --viewer-dir to use the embedded viewer, or run `npm run build`",
                    dir.display()
                );
            }
            Ok(Some(dir))
        }
        None => {
            if !embedded_viewer_ready() {
                bail!(
                    "this premier binary was built without the full viewer; reinstall with `./scripts/install.sh` or pass --viewer-dir apps/viewer/dist after `npm run build`"
                );
            }
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_viewer(
    trace_dir: PathBuf,
    viewer_dir: Option<PathBuf>,
    bind: SocketAddr,
    auth: AuthPolicy,
    options: ServerOptions,
    focus_trace: Option<String>,
    launch_browser: bool,
    tls: Option<TlsFiles>,
) -> Result<()> {
    let tls_enabled = tls.is_some();
    validate_bind(bind.ip(), &auth, tls_enabled)?;
    let viewer = resolve_viewer_dir(viewer_dir)?;
    tokio::fs::create_dir_all(&trace_dir).await?;
    if !bind.ip().is_loopback() {
        validate_remote_trace_store(&trace_dir)?;
    }
    // Listen before anything is announced: with the port taken, a browser
    // sent to the URL would land on whatever already owns it.
    let listener = std::net::TcpListener::bind(bind).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "cannot start the viewer: {bind} is already in use, perhaps by another `premier open` or `premier serve`. Stop that process or choose another address with --bind (for example --bind 127.0.0.1:0 for any free port)"
            )
        } else {
            anyhow::anyhow!("cannot start the viewer: cannot listen on {bind}: {error}")
        }
    })?;
    listener.set_nonblocking(true)?;
    // With port 0 the system chose the port.
    let bind = listener.local_addr()?;
    let router = app_with_options(trace_dir, viewer, auth, options);
    let scheme = if tls_enabled { "https" } else { "http" };
    let url = focus_trace
        .map(|trace| format!("{scheme}://{bind}/?trace={}", url_component(&trace)))
        .unwrap_or_else(|| format!("{scheme}://{bind}"));
    println!("Premier viewer: {url}");
    if launch_browser && let Err(error) = open_browser(&url) {
        tracing::warn!("could not open browser: {error}");
    }
    // Ctrl-C and SIGTERM stop the server: it stops accepting, lets requests
    // in flight finish, and gives up on the rest (an open event stream)
    // after `VIEWER_SHUTDOWN_DEADLINE`.
    let (stop_sender, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        stop_requested().await;
        let _ = stop_sender.send(true);
    });
    let stopped = |mut stop: tokio::sync::watch::Receiver<bool>| async move {
        if stop.wait_for(|stop| *stop).await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    let serving = async {
        if let Some(tls) = tls {
            let config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(tls.cert, tls.key).await?;
            let handle = axum_server::Handle::new();
            let shutdown = handle.clone();
            let requested = stopped(stop.clone());
            tokio::spawn(async move {
                requested.await;
                shutdown.graceful_shutdown(Some(VIEWER_SHUTDOWN_DEADLINE));
            });
            axum_server::from_tcp_rustls(listener, config)?
                .handle(handle)
                .serve(router.into_make_service())
                .await?;
        } else {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            axum::serve(listener, router)
                .with_graceful_shutdown(stopped(stop.clone()))
                .await?;
        }
        anyhow::Ok(())
    };
    tokio::select! {
        served = serving => served?,
        () = async {
            stopped(stop.clone()).await;
            tokio::time::sleep(VIEWER_SHUTDOWN_DEADLINE).await;
        } => {}
    }
    if *stop.borrow() {
        eprintln!("premier: viewer stopped");
    }
    Ok(())
}

/// `value` percent-encoded for use as a URL query value.
fn url_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// How long the viewer server waits for open connections after it was asked
/// to stop.
const VIEWER_SHUTDOWN_DEADLINE: StdDuration = StdDuration::from_secs(2);

/// Completes when the process is asked to stop: Ctrl-C (SIGINT) or SIGTERM.
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut terminate) = signal(SignalKind::terminate()) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

struct TlsFiles {
    cert: PathBuf,
    key: PathBuf,
}

impl TlsFiles {
    fn from_options(cert: Option<PathBuf>, key: Option<PathBuf>) -> Result<Option<Self>> {
        match (cert, key) {
            (Some(cert), Some(key)) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(&key)?.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        bail!("TLS private key must not be accessible by group or other users")
                    }
                }
                Ok(Some(Self { cert, key }))
            }
            (None, None) => Ok(None),
            _ => bail!("--tls-cert and --tls-key must be provided together"),
        }
    }
}

struct EmitArgs {
    json: Option<String>,
    kind: Option<String>,
    actor: Option<String>,
    actor_type: String,
    span: Option<String>,
    parent_span: Option<String>,
    status: Option<String>,
    payload: Option<String>,
    source: String,
}

async fn emit_event(args: EmitArgs) -> Result<()> {
    let url = std::env::var("PREMIER_COLLECTOR_URL").context(
        "PREMIER_COLLECTOR_URL is not set; run your agent under `premier record -- <command>` so the collector is injected",
    )?;
    let token = std::env::var("PREMIER_COLLECTOR_TOKEN")
        .context("PREMIER_COLLECTOR_TOKEN is not set; run under `premier record -- <command>`")?;

    let body = if let Some(raw) = args.json {
        let text = if raw == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            raw
        };
        serde_json::from_str::<serde_json::Value>(&text).context("invalid JSON for --json")?
    } else {
        let kind = args.kind.context("provide --json or --kind")?;
        let mut event = json!({
            "kind": kind,
            "source": args.source,
            "actor_type": args.actor_type,
        });
        if let Some(actor) = args.actor {
            event["actor_id"] = json!(actor);
        }
        if let Some(span) = args.span {
            event["span_id"] = json!(span);
        }
        if let Some(parent_span) = args.parent_span {
            event["parent_span_id"] = json!(parent_span);
        }
        if let Some(status) = args.status {
            event["status"] = json!(status);
        }
        if let Some(payload) = args.payload {
            event["payload"] =
                serde_json::from_str(&payload).context("invalid JSON for --payload")?;
        }
        event
    };

    // Seconds to wait for the collector (PREMIER_EMIT_TIMEOUT, default 10), so
    // a stalled collector cannot hang the agent that shells out to `emit`.
    let timeout = std::env::var("PREMIER_EMIT_TIMEOUT")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|seconds| *seconds > 0.0)
        .and_then(|seconds| std::time::Duration::try_from_secs_f64(seconds).ok())
        .unwrap_or(std::time::Duration::from_secs(10));
    // A loopback collector is authenticated only by its bearer token: never
    // route that token or the payload through HTTP(S)_PROXY / ALL_PROXY. A
    // remote collector keeps the environment's proxy settings, because a
    // mandatory egress proxy may be the only route to it.
    let mut client = reqwest::Client::builder().timeout(timeout);
    if collector_is_loopback(&url) {
        client = client.no_proxy();
    }
    let client = client
        .build()
        .context("failed to build the collector HTTP client")?;
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed to POST event to {url}"))?;
    let status_code = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status_code.is_success() {
        bail!("collector rejected event ({status_code}): {text}");
    }
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(event_id) = parsed.get("event_id").and_then(|v| v.as_str())
    {
        println!("{event_id}");
    } else {
        println!("ok");
    }
    Ok(())
}

/// Whether a collector URL names this machine: `localhost` (or a
/// `.localhost` name), 127.0.0.0/8, or ::1. An unparsable URL is not loopback.
fn collector_is_loopback(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    // `host_str` keeps the brackets of an IPv6 literal.
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return address.is_loopback();
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("cmd");
        command.args(["/C", "start"]);
        command
    };
    command.arg(url).spawn()?.wait()?;
    Ok(())
}

/// `demo` replaces a trace already at its output path, but not one that is
/// being recorded: deleting the directory under a running recorder destroys
/// its evidence and leaves it writing to files nobody can open.
fn refuse_to_replace_a_recording(output: &std::path::Path) -> Result<()> {
    let Ok(manifest) = read_manifest(output) else {
        return Ok(());
    };
    match unfinalized_state(output, &manifest) {
        Some(UnfinalizedState::Recording) => bail!(
            "refusing to replace {}: it is being recorded right now; choose another --output or wait for that recording to finish",
            output.display()
        ),
        Some(UnfinalizedState::Abandoned { needs_force: true }) => bail!(
            "refusing to replace {}: it is an unfinalized recording that was written to moments ago and may still be running; choose another --output, or finalize it with `premier recover --force {}`",
            output.display(),
            output.display()
        ),
        _ => Ok(()),
    }
}

/// The command recorded in a demo trace's manifest.
const DEMO_COMMAND: [&str; 2] = ["premier", "demo"];

/// `demo` only ever replaces an earlier demo. Anything else at the output
/// path is somebody's recording.
fn refuse_to_replace_a_real_trace(output: &std::path::Path, force: bool) -> Result<()> {
    let Ok(manifest) = read_manifest(output) else {
        // Unreadable or not a trace: `prepare_trace_output` decides.
        return Ok(());
    };
    if force || manifest.command == DEMO_COMMAND {
        return Ok(());
    }
    bail!(
        "refusing to replace {}: it is a recorded trace ({}), not an earlier demo; choose another --output, or pass --force to replace it",
        output.display(),
        printable(&manifest.name.unwrap_or_else(|| manifest.command.join(" ")))
    )
}

fn demo(output: PathBuf, force: bool) -> Result<()> {
    // Everything that can refuse the output path is asked first, before
    // anything is written.
    premier_trace::check_trace_output(&output)?;
    refuse_to_replace_a_recording(&output)?;
    refuse_to_replace_a_real_trace(&output, force)?;
    // The demo is written beside its destination and moved into place once
    // it is complete, so a failure (an unusable key file, a full disk) leaves
    // whatever was at the output path untouched.
    let staging = output.with_file_name(format!(
        ".{}.demo-{}.tmp",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .context("the demo output path has no file name")?,
        std::process::id()
    ));
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_dir_all(&staging);
    let written = write_demo(&staging).and_then(|manifest| {
        prepare_trace_output(&output)?;
        fs::rename(&staging, &output)
            .with_context(|| format!("cannot move the demo trace to {}", output.display()))?;
        Ok(manifest)
    });
    let manifest = match written {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    println!("demo trace {} → {}", manifest.trace_id, output.display());
    println!("next: premier open {}", output.display());
    Ok(())
}

fn write_demo(output: &std::path::Path) -> Result<premier_trace::TraceManifest> {
    let mut writer = TraceWriter::create_named(
        output,
        DEMO_COMMAND.iter().map(|word| (*word).to_owned()).collect(),
        Some("Multi-agent failure investigation".into()),
    )?;
    // Stagger producer times so actor lanes show realistic starts (not wall-clock receipt pile-up).
    let origin = Utc::now() - Duration::seconds(45);
    let at = |offset_ms: i64| (origin + Duration::milliseconds(offset_ms)).to_rfc3339();
    let root = writer.append_input(event(
        0,
        "session.start",
        "coordinator",
        "agent",
        "run",
        "",
        "running",
        json!({"goal": "Ship a verified billing repair", "model": "frontier-large"}),
        at,
    ))?;
    let delegation = writer.append_input(EventInput {
        parent_event_id: root.event_id.clone(),
        correlation_id: "workstream-repair".into(),
        ..event(
            400,
            "agent.delegation",
            "coordinator",
            "agent",
            "delegate",
            "run",
            "running",
            json!({"delegates": ["researcher", "coder"], "scope": "inspect and patch billing ledger"}),
            at,
        )
    })?;
    let researcher = writer.append_input(EventInput {
        parent_event_id: delegation.event_id.clone(),
        links: vec![delegation.event_id.clone()],
        ..event(
            1_200,
            "agent.spawn",
            "researcher",
            "subagent",
            "research",
            "delegate",
            "running",
            json!({"parent_actor": "coordinator", "task": "find the first divergence"}),
            at,
        )
    })?;
    let coder = writer.append_input(EventInput {
        parent_event_id: delegation.event_id.clone(),
        links: vec![delegation.event_id.clone()],
        ..event(
            2_400,
            "agent.spawn",
            "coder",
            "subagent",
            "implementation",
            "delegate",
            "running",
            json!({"parent_actor": "coordinator", "task": "prepare a minimal scoped patch"}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: researcher.event_id.clone(),
        duration_ms: 1240,
        ..event(
            3_100,
            "model.response",
            "researcher",
            "subagent",
            "research-model",
            "research",
            "ok",
            json!({
                "provider": "premier-demo",
                "model": "frontier-mini",
                "system_prompt": "You are the billing investigation agent. Preserve evidence, do not mutate files, and cite the event or source behind every conclusion.",
                "developer_prompt": "Inspect the reconciliation path and identify the first causal divergence. Return a concise finding for the coordinator.",
                "messages": [
                    {"role": "user", "content": "Find why negative credits differ by one cent after the ledger repair."}
                ],
                "tools": [
                    {"name": "repo_search", "description": "Search repository text", "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}
                ],
                "usage": {
                    "input_tokens": 1296,
                    "output_tokens": 546,
                    "total_tokens": 1842,
                    "input_tokens_details": {"cached_tokens": 384},
                    "output_tokens_details": {"reasoning_tokens": 212},
                    "input_tokens_by_role": {"system": 302, "developer": 238, "user": 148, "tool": 608},
                    "cost_usd": 0.0047
                },
                "response": "The first divergence occurs after the ledger lock: the patched path rounds the negative credit after locking, producing -12.39 instead of -12.40.",
                "summary": "rounding occurs after ledger lock"
            }),
            at,
        )
    })?;
    let evidence = writer.append_input(EventInput {
        parent_event_id: researcher.event_id.clone(),
        duration_ms: 83,
        ..event(
            4_500,
            "tool.execution",
            "researcher",
            "subagent",
            "repo-search",
            "research",
            "ok",
            json!({"tool": "rg", "query": "reconcileInvoice", "matches": 7, "files": ["src/billing/ledger.ts", "tests/billing.test.ts"]}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: evidence.event_id.clone(),
        links: vec![evidence.event_id.clone(), coder.event_id.clone()],
        ..event(
            5_200,
            "agent.message",
            "researcher",
            "subagent",
            "research-result",
            "research",
            "ok",
            json!({"to": ["coordinator", "coder"], "finding": "round before lock; regression introduced in 9f43c7a"}),
            at,
        )
    })?;
    let approval = writer.append_input(EventInput {
        parent_event_id: coder.event_id.clone(),
        correlation_id: "approval-patch-01".into(),
        ..event(
            7_800,
            "approval.request",
            "coder",
            "subagent",
            "patch-approval",
            "implementation",
            "pending",
            json!({"operation": "write", "files": ["src/billing/ledger.ts"], "reason": "apply scoped ordering repair"}),
            at,
        )
    })?;
    let decision = writer.append_input(EventInput {
        parent_event_id: approval.event_id.clone(),
        correlation_id: "approval-patch-01".into(),
        ..event(
            12_400,
            "approval.decision",
            "brad",
            "human",
            "approval-decision",
            "patch-approval",
            "approved",
            json!({"scope": "src/billing/ledger.ts only", "expires_after": "single mutation", "receipt": "apr_01J"}),
            at,
        )
    })?;
    let patch = writer.append_input(EventInput {
        parent_event_id: decision.event_id.clone(),
        correlation_id: "approval-patch-01".into(),
        links: vec![evidence.event_id.clone(), decision.event_id.clone()],
        duration_ms: 176,
        ..event(
            13_100,
            "tool.execution",
            "coder",
            "subagent",
            "apply-patch",
            "implementation",
            "ok",
            json!({"tool": "apply_patch", "files_changed": 1, "additions": 8, "deletions": 3, "approval_receipt": "apr_01J"}),
            at,
        )
    })?;
    // The coordinator spawns the reviewer (as its payload says); the patch
    // under review is what the spawn refers to, not what caused it.
    let reviewer = writer.append_input(EventInput {
        parent_event_id: root.event_id.clone(),
        links: vec![patch.event_id.clone()],
        ..event(
            16_000,
            "agent.spawn",
            "reviewer",
            "subagent",
            "review",
            "run",
            "running",
            json!({"parent_actor": "coordinator", "task": "verify patch and scope"}),
            at,
        )
    })?;
    let failed_test = writer.append_input(EventInput {
        parent_event_id: reviewer.event_id.clone(),
        links: vec![patch.event_id.clone()],
        duration_ms: 912,
        ..event(
            17_200,
            "tool.error",
            "reviewer",
            "subagent",
            "test-suite",
            "review",
            "error",
            json!({"tool": "cargo test", "failed": "rounds_negative_credit", "expected": "-12.40", "actual": "-12.39"}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: failed_test.event_id.clone(),
        links: vec![failed_test.event_id.clone(), patch.event_id.clone()],
        ..event(
            18_400,
            "agent.message",
            "reviewer",
            "subagent",
            "review-result",
            "review",
            "error",
            json!({"to": ["coordinator", "coder"], "finding": "negative credit rounding still diverges", "action": "repair before merge"}),
            at,
        )
    })?;
    writer.append_input(EventInput {
        parent_event_id: root.event_id,
        links: vec![researcher.event_id, coder.event_id, reviewer.event_id],
        ..event(
            20_000,
            "agent.join",
            "coordinator",
            "agent",
            "join",
            "run",
            "error",
            json!({"joined": ["researcher", "coder", "reviewer"], "outcome": "repair required", "open_failures": 1}),
            at,
        )
    })?;
    writer.finish(1)
}

#[allow(clippy::too_many_arguments)]
fn event(
    offset_ms: i64,
    kind: &str,
    actor_id: &str,
    actor_type: &str,
    span_id: &str,
    parent_span_id: &str,
    status: &str,
    payload: serde_json::Value,
    at: impl Fn(i64) -> String,
) -> EventInput {
    EventInput {
        kind: kind.into(),
        source: "premier-demo".into(),
        actor_id: actor_id.into(),
        actor_type: actor_type.into(),
        span_id: span_id.into(),
        parent_span_id: parent_span_id.into(),
        status: status.into(),
        payload,
        timestamp: Some(at(offset_ms)),
        ..EventInput::default()
    }
}

struct RecordOptions {
    output: Option<PathBuf>,
    name: Option<String>,
    tenant: String,
    command: Vec<String>,
    open_viewer: bool,
    pty: bool,
    adapter: AdapterChoice,
    viewer_dir: Option<PathBuf>,
    bind: SocketAddr,
    redaction: RedactionConfig,
    sign_key: Option<premier_trace::SigningKey>,
}

async fn record(options: RecordOptions) -> Result<()> {
    let RecordOptions {
        output,
        name,
        tenant,
        command,
        open_viewer,
        pty,
        adapter,
        viewer_dir,
        bind,
        redaction,
        sign_key,
    } = options;
    #[cfg(not(unix))]
    if pty {
        bail!("--pty is currently supported only on Unix; use pipe capture without --pty")
    }
    let executable = command.first().context("a command is required")?;
    if pty && adapter.is_explicit() {
        bail!("native adapters require pipe capture with structured JSONL; omit --pty")
    }
    if open_viewer && tenant != premier_trace::LOCAL_TENANT {
        bail!(
            "--open serves the local viewer identity, which cannot see a trace owned by tenant '{tenant}'; record without --open. {TENANT_TRACE_HINT}"
        )
    }
    if open_viewer {
        // Found now, not after the command has run and been recorded.
        validate_bind(bind.ip(), &AuthPolicy::default(), false)?;
        resolve_viewer_dir(viewer_dir.clone())?;
    }
    let native_provider = adapter.resolve(executable, &command[1..], pty);
    if pty
        && adapter == AdapterChoice::Auto
        && let Some(provider) = adapter.detect(executable, &command[1..])
    {
        eprintln!(
            "premier: structured capture for {} is unavailable in PTY mode; recording terminal output only (omit --pty for model and tool events)",
            provider.id()
        );
    }
    // The child receives this token in its environment and may print it
    // (`env`), so the recorder redacts it from everything it stores. It is
    // 256 bits from the system random number generator and shares nothing
    // with the (time-ordered, public) event ids.
    let collector_token = premier_trace::random_secret_hex()?;
    let redaction = redaction.implicit_literal("collector-token", &collector_token);
    let (output, mut trace_writer) = match output {
        Some(output) => {
            let writer = TraceWriter::create_named_for_tenant_with_redaction(
                &output,
                command.clone(),
                name,
                &tenant,
                redaction,
            )?;
            (output, writer)
        }
        // The trace directory is created exclusively, so recorders started
        // in the same instant can never share one; a name that is already
        // taken is simply drawn again.
        None => {
            let mut attempts = 0;
            loop {
                let output = default_trace_path();
                match TraceWriter::create_named_for_tenant_with_redaction(
                    &output,
                    command.clone(),
                    name.clone(),
                    &tenant,
                    redaction.clone(),
                ) {
                    Ok(writer) => break (output, writer),
                    Err(error)
                        if attempts < 16
                            && error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                io.kind() == std::io::ErrorKind::AlreadyExists
                            }) =>
                    {
                        attempts += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    };
    if let Some(key) = sign_key {
        trace_writer.set_signing_key(key);
    }
    if let Some(provider) = native_provider {
        trace_writer.set_adapter(premier_trace::AdapterProvenance {
            provider: provider.id().into(),
            schema_version: ADAPTER_SCHEMA_VERSION,
            transport: "stdout-jsonl".into(),
            completeness: "provider-native-best-effort".into(),
        })?;
    }
    if pty {
        trace_writer.add_capability("terminal.pty")?;
        trace_writer.add_capability("terminal.merged-output")?;
    }
    let writer = Arc::new(Mutex::new(trace_writer));
    let recorder_lease = RecorderLease::start(&output)?;
    let trace_id = writer.lock().unwrap().trace_id().to_owned();
    let collector_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    collector_listener.set_nonblocking(true)?;
    let collector_address = collector_listener.local_addr()?;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let collector_writer = writer.clone();
    let collector_token_for_server = collector_token.clone();
    // The collector gets a runtime of its own so that finalization can tear
    // it down, connections included, without waiting on its clients.
    let collector_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("premier-collector")
        .enable_all()
        .build()?;
    let collector_task = collector_runtime.spawn(async move {
        axum::serve(
            tokio::net::TcpListener::from_std(collector_listener)?,
            instrumentation_app(collector_writer, collector_token_for_server),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_receiver.await;
        })
        .await
    });
    let collector = Collector {
        runtime: Some(collector_runtime),
        shutdown: Some(shutdown_sender),
        task: collector_task,
    };
    #[cfg(unix)]
    let terminal = pty.then(terminal_size);
    #[cfg(not(unix))]
    let terminal: Option<()> = None;
    let mut session_payload = json!({
        "cwd": std::env::current_dir()?.to_string_lossy(),
        "command": command,
        "instrumentation": format!("http://{collector_address}/v1/events"),
        "capture_mode": if pty { "pty" } else { "pipes" },
        "adapter": native_provider.map(|provider| json!({
            "provider": provider.id(),
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "transport": "stdout-jsonl",
            "completeness": "provider-native-best-effort",
        })),
    });
    #[cfg(unix)]
    if let Some(size) = terminal {
        session_payload["terminal"] = json!({
            "mode": "pty",
            "rows": size.rows,
            "cols": size.cols,
            "pixel_width": size.pixel_width,
            "pixel_height": size.pixel_height,
            "streams": "merged",
        });
    }
    writer.lock().unwrap().append_input(EventInput {
        kind: "session.start".into(),
        source: "premier".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "session".into(),
        status: "running".into(),
        payload: session_payload,
        ..EventInput::default()
    })?;

    let collector_url = format!("http://{collector_address}/v1/events");
    let capture_environment = CaptureEnvironment {
        trace_id: &trace_id,
        collector_url: &collector_url,
        collector_token: &collector_token,
        native_provider,
    };
    let capture = if pty {
        #[cfg(unix)]
        {
            capture_pty(
                executable,
                &command[1..],
                terminal.expect("PTY terminal size"),
                capture_environment,
                &writer,
            )
        }
        #[cfg(not(unix))]
        unreachable!("non-Unix PTY request rejected before trace creation")
    } else {
        capture_pipes(executable, &command[1..], capture_environment, &writer)
    };
    recorder_lease.stop()?;
    let capture = match capture {
        Ok(capture) => capture,
        Err(error) => {
            let failure = error.downcast::<SpawnFailure>()?;
            // Nothing ran, but the trace directory already exists: finalize
            // it as evidence of the failed start instead of leaving an
            // unfinalized trace that looks like an interrupted recording.
            let appended = writer
                .lock()
                .unwrap()
                .append_input(EventInput {
                    kind: "process.spawn_failed".into(),
                    source: "premier".into(),
                    actor_id: "root".into(),
                    actor_type: "process".into(),
                    span_id: "command".into(),
                    parent_span_id: "session".into(),
                    status: "error".into(),
                    payload: json!({
                        "executable": failure.executable,
                        "error": failure.reason,
                        "exit_code": failure.exit_code,
                        "success": false,
                    }),
                    ..EventInput::default()
                })
                .map(drop);
            let finalized = match appended {
                Ok(()) => {
                    finalize_recording(
                        writer,
                        collector,
                        ProcessTermination::exited(failure.exit_code),
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            eprintln!("premier: {failure}");
            match finalized {
                Ok(manifest) => {
                    eprintln!("trace {} → {}", manifest.trace_id, output.display());
                    eprintln!("{}", protection_summary(&manifest));
                }
                Err(error) => eprintln!(
                    "premier: the trace of the failed start could not be finalized: {error:#}\npremier: finalize it with `premier recover --force {}`",
                    output.display()
                ),
            }
            std::process::exit(failure.exit_code)
        }
    };
    let termination = capture.termination;
    let recorder_signals = capture.recorder_signals;
    let mut faults = capture.faults;
    // The manifest was told an adapter would normalize this run before the
    // command started. Where its output was not (all) native events, the
    // manifest and the user are told what was actually captured.
    if let (Some(provider), Some(summary)) = (native_provider, capture.adapter_summary)
        && summary.needs_report()
    {
        faults.note(
            writer
                .lock()
                .unwrap()
                .set_adapter(premier_trace::AdapterProvenance {
                    provider: provider.id().into(),
                    schema_version: ADAPTER_SCHEMA_VERSION,
                    transport: "stdout-jsonl".into(),
                    completeness: summary.completeness().into(),
                }),
        );
        if summary.normalized_lines == 0 {
            eprintln!(
                "premier: the {} adapter found no native JSONL events in {} line(s) of output; the trace holds terminal output only. Run the CLI with its structured output flag, or record with --adapter none",
                provider.id(),
                summary.lines
            );
        } else {
            eprintln!(
                "premier: the {} adapter could not read {} of {} output line(s) as native JSONL events; see the adapter.diagnostic and adapter.summary events",
                provider.id(),
                summary.rejected_lines,
                summary.lines
            );
        }
    }
    let code = termination.shell_exit_code();
    let command_success = code == 0;
    let mut exit_payload = json!({
        "exit_code": code,
        "success": command_success,
        "termination": match termination.kind {
            TerminationKind::Exit => "exit",
            TerminationKind::Signal => "signal",
            TerminationKind::Interrupted => "interrupted",
        },
    });
    if let Some(signal) = termination.signal {
        exit_payload["signal"] = json!(signal);
    }
    if let Some(signal_name) = termination.signal_name.as_deref() {
        exit_payload["signal_name"] = json!(signal_name);
    }
    // The termination above is always the child's own wait status. A stop
    // request received by the recorder is separate evidence: the child may
    // have handled it and exited normally.
    if let Some(signal) = recorder_signals.received {
        exit_payload["forwarded_by_recorder"] = json!(true);
        exit_payload["recorder_signal"] = json!(signal);
        if let Some(name) = signal_name(signal) {
            exit_payload["recorder_signal_name"] = json!(name);
        }
    }
    if recorder_signals.killed_child {
        exit_payload["killed_by_recorder"] = json!(true);
    }
    if capture.core_dumped {
        exit_payload["core_dumped"] = json!(true);
    }
    if capture.output_open_at_exit {
        exit_payload["output_open_at_exit"] = json!(true);
    }
    faults.note(
        writer
            .lock()
            .unwrap()
            .append_input(EventInput {
                kind: "process.exit".into(),
                source: "command".into(),
                actor_id: "root".into(),
                actor_type: "process".into(),
                span_id: "command".into(),
                parent_span_id: "session".into(),
                status: if command_success { "ok" } else { "error" }.into(),
                payload: exit_payload,
                ..EventInput::default()
            })
            .map(drop),
    );
    // From here on a recorder failure must not replace the command's own
    // exit status, so finalization errors are reported instead of returned.
    let finalized = finalize_recording(writer, collector, termination.clone()).await;
    match &finalized {
        Ok(manifest) => {
            eprintln!("\ntrace {} → {}", manifest.trace_id, output.display());
            eprintln!("{}", protection_summary(manifest));
        }
        Err(error) => eprintln!(
            "\npremier: recording failed: the trace could not be finalized: {error:#}\npremier: salvage what was captured with `premier recover --force {}`",
            output.display()
        ),
    }
    if let Some(first) = faults.first.as_deref() {
        eprintln!(
            "premier: recording failed: {} event(s) are missing from the trace (first error: {first})",
            faults.dropped
        );
    }
    if !command_success {
        match (
            &termination.kind,
            termination.signal,
            termination.signal_name.as_deref(),
        ) {
            (TerminationKind::Signal, Some(signal), Some(name)) => {
                eprintln!("recorded command terminated by {name} (signal {signal})");
            }
            (TerminationKind::Signal, Some(signal), None) => {
                eprintln!("recorded command terminated by signal {signal}");
            }
            _ => eprintln!("recorded command exited with status {code}"),
        }
    }
    if let Ok(manifest) = finalized {
        if manifest.tenant_id == premier_trace::LOCAL_TENANT {
            eprintln!("next: premier open {}", output.display());
        } else {
            // `premier open` could not show it.
            eprintln!(
                "next: this trace is owned by tenant '{}'. {TENANT_TRACE_HINT}",
                manifest.tenant_id
            );
        }
        if open_viewer && recorder_signals.received.is_none() {
            // Like `premier open <trace>`: publish this recording only, not
            // every other trace that happens to share its directory.
            let (trace_dir, only_artifact) = single_trace_scope(&output)?;
            let only_artifact_name = only_artifact.to_string_lossy().into_owned();
            let mut options = server_options(false);
            options.only_artifact = Some(only_artifact);
            // The recorder's forwarding handlers are still installed and now
            // do nothing. The viewer handles SIGINT and SIGTERM itself; a
            // closed terminal (SIGHUP) or Ctrl-\ must end it as they would
            // any other program.
            #[cfg(unix)]
            for signal in [libc::SIGHUP, libc::SIGQUIT] {
                // SAFETY: restoring a default disposition has no
                // preconditions; no forwarder is running any more.
                unsafe {
                    libc::signal(signal, libc::SIG_DFL);
                }
            }
            return serve_viewer(
                trace_dir,
                viewer_dir,
                bind,
                AuthPolicy::default(),
                options,
                Some(only_artifact_name),
                true,
                None,
            )
            .await;
        }
    }
    if command_success {
        Ok(())
    } else {
        std::process::exit(code.clamp(1, 255))
    }
}

/// How the trace just written is protected, for the end-of-run summary: a
/// mistyped key variable must not pass for an encrypted recording.
fn protection_summary(manifest: &premier_trace::TraceManifest) -> String {
    let encryption = match manifest.encryption.as_ref() {
        Some(metadata) => format!("encrypted at rest (key {})", metadata.key_id),
        None => "NOT encrypted (plaintext on disk; pass --key-file to encrypt)".to_owned(),
    };
    let signer = manifest
        .seal
        .as_ref()
        .and_then(|seal| seal.signature.as_ref())
        .map(|signature| {
            premier_trace::PublicKey::from_hex(&signature.public_key)
                .map_or_else(|_| "unknown".to_owned(), |key| key.fingerprint())
        });
    let signature = match signer {
        Some(fingerprint) => format!("signed (key {fingerprint})"),
        None => "unsigned (pass --sign-key for tamper evidence)".to_owned(),
    };
    format!("protection: {encryption}; {signature}")
}

/// The local collector server and the runtime that owns its connections.
struct Collector {
    runtime: Option<tokio::runtime::Runtime>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Collector {
    /// Reached without `stop` only when recording fails early. A runtime may
    /// not be dropped inside an async context, so detach it instead.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// How long in-flight collector requests get to finish once the recorded
/// command has exited. A request still open after this (a detached descendant
/// that sent half a body and went to sleep) is dropped, not waited for.
const COLLECTOR_SHUTDOWN_DEADLINE: StdDuration = StdDuration::from_secs(2);

impl Collector {
    /// Stop accepting events and release every reference to the trace writer.
    async fn stop(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let served = tokio::time::timeout(COLLECTOR_SHUTDOWN_DEADLINE, &mut self.task).await;
        // Shutting the runtime down drops its tasks, which closes whatever
        // connections remain. That blocks, so it runs off the async threads.
        if let Some(runtime) = self.runtime.take() {
            tokio::task::spawn_blocking(move || {
                runtime.shutdown_timeout(COLLECTOR_SHUTDOWN_DEADLINE)
            })
            .await?;
        }
        match served {
            Ok(result) => Ok(result??),
            Err(_) => Ok(()),
        }
    }
}

/// Stop the collector, reclaim the trace writer from it, and finalize.
async fn finalize_recording(
    writer: Arc<Mutex<TraceWriter>>,
    collector: Collector,
    termination: ProcessTermination,
) -> Result<premier_trace::TraceManifest> {
    collector.stop().await?;
    let writer = Arc::try_unwrap(writer)
        .map_err(|_| anyhow::anyhow!("collector still owns the trace writer"))?
        .into_inner()
        .map_err(|_| anyhow::anyhow!("trace writer lock was poisoned"))?;
    writer.finish_termination(termination)
}

/// The recorded command could not be started, so there is no child status.
/// `exit_code` follows the shell convention: 127 when the command was not
/// found, 126 when it was found but could not be executed.
#[derive(Debug)]
struct SpawnFailure {
    executable: String,
    reason: String,
    exit_code: i32,
}

const EXIT_COMMAND_NOT_FOUND: i32 = 127;
const EXIT_COMMAND_NOT_EXECUTABLE: i32 = 126;

impl std::fmt::Display for SpawnFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            executable,
            reason,
            exit_code,
        } = self;
        let summary = if *exit_code == EXIT_COMMAND_NOT_FOUND {
            "command not found"
        } else {
            "command could not be executed"
        };
        write!(
            formatter,
            "failed to start {executable}: {summary} ({reason}); nothing was run (exit status {exit_code})"
        )
    }
}

impl std::error::Error for SpawnFailure {}

#[derive(Clone, Copy)]
struct CaptureEnvironment<'a> {
    trace_id: &'a str,
    collector_url: &'a str,
    collector_token: &'a str,
    native_provider: Option<Provider>,
}

struct CaptureOutcome {
    termination: ProcessTermination,
    recorder_signals: RecorderSignals,
    core_dumped: bool,
    /// A descendant still held the output stream after the child exited.
    output_open_at_exit: bool,
    faults: RecordingFaults,
    /// What the native adapter made of the command's output, when one ran.
    adapter_summary: Option<adapters::AdapterSummary>,
}

/// Stop requests the recorder itself received while the child was running.
#[derive(Clone, Copy, Default)]
struct RecorderSignals {
    received: Option<i32>,
    killed_child: bool,
}

/// Journal failures seen while capturing. Evidence capture must never take
/// the recorded command down, so they are reported and counted instead of
/// ending the run.
#[derive(Default)]
struct RecordingFaults {
    first: Option<String>,
    dropped: u64,
}

impl RecordingFaults {
    fn note(&mut self, result: Result<()>) {
        let Err(error) = result else { return };
        if self.first.is_none() {
            // `\r` keeps the notice readable while a PTY capture holds the
            // terminal in raw mode.
            eprintln!(
                "\r\npremier: recording failed: {error:#}\r\npremier: the command keeps running, but its trace is incomplete\r"
            );
            self.first = Some(format!("{error:#}"));
        }
        self.dropped += 1;
    }
}

/// How often the capture loop checks whether the child has exited.
const CHILD_POLL_INTERVAL: StdDuration = StdDuration::from_millis(50);
/// After the child exits, a stream held open by a descendant is considered
/// drained once it has been quiet this long.
const OUTPUT_QUIET_AFTER_EXIT: StdDuration = StdDuration::from_millis(250);
/// Upper bound on draining after exit when a descendant keeps writing.
const OUTPUT_DRAIN_LIMIT: StdDuration = StdDuration::from_secs(5);
/// A partial line held back for a redaction rule (for example an interactive
/// prompt) is journaled once its stream has been quiet this long, so it is
/// not lost if the recorder is killed before the line ends.
const DEFAULT_HELD_OUTPUT_IDLE_FLUSH: StdDuration = StdDuration::from_secs(1);
/// Overrides [`DEFAULT_HELD_OUTPUT_IDLE_FLUSH`], in milliseconds. A longer
/// period keeps a rule from being split by output that pauses mid-secret; a
/// shorter one journals prompts sooner.
const HELD_OUTPUT_IDLE_FLUSH_ENV: &str = "PREMIER_REDACTION_IDLE_FLUSH_MS";

/// The idle period after which held output is journaled, read once.
fn held_output_idle_flush() -> StdDuration {
    static PERIOD: std::sync::OnceLock<StdDuration> = std::sync::OnceLock::new();
    *PERIOD.get_or_init(|| {
        std::env::var(HELD_OUTPUT_IDLE_FLUSH_ENV)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .map_or(DEFAULT_HELD_OUTPUT_IDLE_FLUSH, StdDuration::from_millis)
    })
}

/// What the capture loop hands its callback.
enum Captured<'a> {
    Output(&'static str, &'a [u8]),
    /// Periodic wake-up with no new output, used to flush idle held text.
    Tick,
}

/// Hand captured output to `on_output` until the child has exited and its
/// streams are drained. Finalization must not wait for end-of-file: a
/// descendant can hold the pipe or PTY open long after the child is gone.
/// Returns the status if the exit was observed here, and whether a stream
/// was still open when draining stopped.
fn drain_child_output(
    receiver: mpsc::Receiver<(&'static str, Vec<u8>)>,
    mut try_wait: impl FnMut() -> std::io::Result<Option<std::process::ExitStatus>>,
    mut on_output: impl FnMut(Captured<'_>),
) -> std::io::Result<(Option<std::process::ExitStatus>, bool)> {
    let mut status = None;
    let mut exited_at = None;
    let mut last_output = Instant::now();
    let mut next_poll = Instant::now();
    let mut next_tick = Instant::now() + CHILD_POLL_INTERVAL;
    loop {
        let now = Instant::now();
        if now >= next_tick {
            on_output(Captured::Tick);
            next_tick = now + CHILD_POLL_INTERVAL;
        }
        if status.is_none() && now >= next_poll {
            status = try_wait()?;
            next_poll = now + CHILD_POLL_INTERVAL;
            if status.is_some() {
                exited_at = Some(now);
                last_output = now;
            }
        }
        if let Some(exited_at) = exited_at
            && (now.duration_since(last_output) >= OUTPUT_QUIET_AFTER_EXIT
                || now.duration_since(exited_at) >= OUTPUT_DRAIN_LIMIT)
        {
            return Ok((status, true));
        }
        match receiver.recv_timeout(CHILD_POLL_INTERVAL) {
            Ok((stream, bytes)) => {
                on_output(Captured::Output(stream, &bytes));
                last_output = Instant::now();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok((status, false)),
        }
    }
}

fn capture_pipes(
    executable: &str,
    args: &[String],
    environment: CaptureEnvironment<'_>,
    writer: &Arc<Mutex<TraceWriter>>,
) -> Result<CaptureOutcome> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PREMIER_TRACE_ID", environment.trace_id)
        .env("PREMIER_COLLECTOR_URL", environment.collector_url)
        .env("PREMIER_COLLECTOR_TOKEN", environment.collector_token)
        .spawn()
        .map_err(|error| SpawnFailure {
            executable: executable.to_owned(),
            exit_code: if error.kind() == std::io::ErrorKind::NotFound {
                EXIT_COMMAND_NOT_FOUND
            } else {
                EXIT_COMMAND_NOT_EXECUTABLE
            },
            reason: error.to_string(),
        })?;

    #[cfg(unix)]
    let signal_forwarder = UnixSignalForwarder::start(child.id())?;

    // Bounded so a fast child is throttled by journal writes instead of
    // growing an in-memory queue without limit.
    let (sender, receiver) = mpsc::sync_channel::<(&'static str, Vec<u8>)>(256);
    pump(child.stdout.take().unwrap(), sender.clone(), "stdout");
    pump(child.stderr.take().unwrap(), sender, "stderr");
    let mut stdout_pending = PendingOutput::new(writer, "process.stdout");
    let mut stderr_pending = PendingOutput::new(writer, "process.stderr");
    let mut mirror_stdout = true;
    let mut mirror_stderr = true;
    let mut native_adapter = environment.native_provider.map(NativeAdapter::new);
    let mut faults = RecordingFaults::default();
    let drained = drain_child_output(
        receiver,
        || {
            let status = child.try_wait()?;
            #[cfg(unix)]
            if status.is_some() {
                signal_forwarder.child_exited();
            }
            Ok(status)
        },
        |captured| {
            let Captured::Output(stream, bytes) = captured else {
                for (kind, pending) in [
                    ("process.stdout", &mut stdout_pending),
                    ("process.stderr", &mut stderr_pending),
                ] {
                    faults.note(append_idle_output(writer, kind, pending));
                }
                return;
            };
            // A closed recorder stdout/stderr (for example `premier record -- cmd | head`)
            // stops mirroring but must never abort evidence capture.
            if stream == "stdout" {
                if mirror_stdout {
                    mirror_stdout = std::io::stdout()
                        .write_all(bytes)
                        .and_then(|()| std::io::stdout().flush())
                        .is_ok();
                }
            } else if mirror_stderr {
                mirror_stderr = std::io::stderr()
                    .write_all(bytes)
                    .and_then(|()| std::io::stderr().flush())
                    .is_ok();
            }
            let pending = if stream == "stdout" {
                &mut stdout_pending
            } else {
                &mut stderr_pending
            };
            // Passthrough above already happened; a journal failure only
            // costs evidence, never the command's output or exit status.
            faults.note(append_process_bytes(
                writer,
                &format!("process.{stream}"),
                pending,
                bytes,
            ));
            if stream == "stdout"
                && let Some(adapter) = native_adapter.as_mut()
            {
                let events = adapter.push(bytes);
                faults.note(append_adapter_events(writer, adapter, events));
            }
        },
    );
    // Held text is journaled before a capture error can end the run.
    for (stream, pending) in [
        ("stdout", &mut stdout_pending),
        ("stderr", &mut stderr_pending),
    ] {
        faults.note(append_pending_utf8(
            writer,
            &format!("process.{stream}"),
            pending,
        ));
    }
    let mut adapter_summary = None;
    if let Some(adapter) = native_adapter.as_mut() {
        let mut events = adapter.finish();
        // Says so in the trace when the lines were not (all) native events.
        events.extend(adapter.summary_event());
        faults.note(append_adapter_events(writer, adapter, events));
        adapter_summary = Some(adapter.summary());
    }
    let (status, output_open_at_exit) = drained?;
    let status = match status {
        Some(status) => status,
        None => child.wait()?,
    };
    #[cfg(unix)]
    let recorder_signals = {
        signal_forwarder.child_exited();
        signal_forwarder.finish()?
    };
    #[cfg(not(unix))]
    let recorder_signals = RecorderSignals::default();
    #[cfg(unix)]
    let core_dumped = {
        use std::os::unix::process::ExitStatusExt;
        status.core_dumped()
    };
    #[cfg(not(unix))]
    let core_dumped = false;
    Ok(CaptureOutcome {
        termination: process_termination(&status),
        recorder_signals,
        core_dumped,
        output_open_at_exit,
        faults,
        adapter_summary,
    })
}

#[cfg(unix)]
fn capture_pty(
    executable: &str,
    args: &[String],
    size: portable_pty::PtySize,
    environment: CaptureEnvironment<'_>,
    writer: &Arc<Mutex<TraceWriter>>,
) -> Result<CaptureOutcome> {
    use portable_pty::{CommandBuilder, native_pty_system};
    use std::os::unix::process::ExitStatusExt;

    let pair = native_pty_system()
        .openpty(size)
        .context("failed to allocate pseudo-terminal")?;
    // SAFETY: isatty only inspects the descriptor.
    let stdin_is_terminal = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    if !stdin_is_terminal && let Some(master) = pair.master.as_raw_fd() {
        // Redirected input is forwarded as data, not typed: without a
        // terminal in front, the PTY's echo would copy every input byte
        // (and the end-of-input character) into the captured output.
        disable_pty_echo(master);
    }
    let mut command = CommandBuilder::new(executable);
    command.args(args);
    // portable-pty starts children in $HOME unless told otherwise.
    command.cwd(std::env::current_dir()?);
    command.env("PREMIER_TRACE_ID", environment.trace_id);
    command.env("PREMIER_COLLECTOR_URL", environment.collector_url);
    command.env("PREMIER_COLLECTOR_TOKEN", environment.collector_token);
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| SpawnFailure {
            executable: executable.to_owned(),
            exit_code: if command_exists(executable) {
                EXIT_COMMAND_NOT_EXECUTABLE
            } else {
                EXIT_COMMAND_NOT_FOUND
            },
            // portable-pty lists every PATH entry it tried, one per line.
            reason: format!("{error:#}").replace('\n', " "),
        })?;
    drop(pair.slave);
    let child_pid = child
        .process_id()
        .context("PTY child process id is unavailable")?;
    let signal_forwarder = UnixSignalForwarder::start_process_group(child_pid)?;
    let child_pid = i32::try_from(child_pid).context("child process id exceeds i32")?;
    let reader = pair.master.try_clone_reader()?;
    let mut terminal_writer = pair.master.take_writer()?;
    let _raw_terminal = ParentTerminalMode::raw_if_interactive()?;
    let (release_stdin, wait_for_release) = mpsc::channel::<()>();
    thread::spawn(move || {
        let mut input = std::io::stdin();
        if stdin_is_terminal {
            let _ = std::io::copy(&mut input, &mut terminal_writer);
        } else {
            // A file or pipe ends; the child must see that end, or a
            // command that reads its input to completion never finishes.
            let _ = forward_redirected_stdin(&mut input, &mut terminal_writer);
        }
        // portable-pty sends a newline and EOT when its writer is dropped.
        // Keep the writer alive until the child is gone so nothing more is
        // typed into the terminal behind the input that was forwarded.
        let _ = wait_for_release.recv();
    });
    // A resize of the recorder's terminal is passed on to the PTY and
    // recorded, so full-screen programs redraw for the size that is shown.
    let resized = Arc::new(AtomicBool::new(false));
    let resize_hook = signal_hook::flag::register(libc::SIGWINCH, resized.clone())
        .context("cannot watch for terminal resizes")?;
    let mut current_size = size;

    // The reader runs on its own thread so a descendant that keeps the
    // terminal open cannot block finalization after the child has exited.
    // Unix PTY masters commonly report EIO after the final slave closes;
    // the pump treats any read error as end of output.
    let (sender, receiver) = mpsc::sync_channel::<(&'static str, Vec<u8>)>(256);
    pump(reader, sender, "terminal");
    let mut pending = PendingOutput::new(writer, "process.terminal");
    let mut mirror = true;
    let mut faults = RecordingFaults::default();
    let drained = drain_child_output(
        receiver,
        || {
            let status = wait_for_pid(child_pid, false)?;
            if status.is_some() {
                signal_forwarder.child_exited();
            }
            Ok(status)
        },
        |captured| {
            let Captured::Output(_, bytes) = captured else {
                faults.note(append_idle_output(writer, "process.terminal", &mut pending));
                if resized.swap(false, Ordering::SeqCst)
                    && let Some(new_size) = tty_size()
                    && new_size != current_size
                    && pair.master.resize(new_size).is_ok()
                {
                    current_size = new_size;
                    faults.note(append_resize_event(writer, new_size));
                }
                return;
            };
            if mirror {
                mirror = std::io::stdout()
                    .write_all(bytes)
                    .and_then(|()| std::io::stdout().flush())
                    .is_ok();
            }
            faults.note(append_process_bytes(
                writer,
                "process.terminal",
                &mut pending,
                bytes,
            ));
        },
    );
    // Held text is journaled before a capture error can end the run.
    faults.note(append_pending_utf8(
        writer,
        "process.terminal",
        &mut pending,
    ));
    let (status, output_open_at_exit) = drained?;
    let status = match status {
        Some(status) => status,
        None => loop {
            if let Some(status) = wait_for_pid(child_pid, true)? {
                break status;
            }
        },
    };
    signal_forwarder.child_exited();
    signal_hook::low_level::unregister(resize_hook);
    let _ = release_stdin.send(());
    let recorder_signals = signal_forwarder.finish()?;
    Ok(CaptureOutcome {
        termination: process_termination(&status),
        recorder_signals,
        core_dumped: status.core_dumped(),
        output_open_at_exit,
        faults,
        adapter_summary: None,
    })
}

/// Forward redirected (non-terminal) standard input to the PTY, then signal
/// end of input the way a terminal does: the end-of-file character (Ctrl-D),
/// which ends input only at the start of a line, so it is sent twice when the
/// input did not end with a newline (the first then delivers the unfinished
/// line). A child that has put its terminal into raw mode reads the
/// character as data instead; that is what a terminal would give it too.
#[cfg(unix)]
fn forward_redirected_stdin(
    input: &mut impl Read,
    terminal: &mut impl Write,
) -> std::io::Result<()> {
    const END_OF_FILE: u8 = 0x04;
    let mut buffer = [0_u8; 8192];
    let mut at_line_start = true;
    loop {
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                terminal.write_all(&buffer[..count])?;
                at_line_start = buffer[count - 1] == b'\n';
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let end: &[u8] = if at_line_start {
        &[END_OF_FILE]
    } else {
        &[END_OF_FILE, END_OF_FILE]
    };
    terminal.write_all(end)?;
    terminal.flush()
}

/// Turn off input echo on a PTY, given its master side.
#[cfg(unix)]
fn disable_pty_echo(master: std::os::fd::RawFd) {
    // SAFETY: termios is a plain C structure filled in by tcgetattr; both
    // calls only touch the terminal behind a descriptor this process owns.
    unsafe {
        let mut attributes: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(master, &mut attributes) == 0 {
            attributes.c_lflag &=
                !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::ECHOCTL);
            libc::tcsetattr(master, libc::TCSANOW, &attributes);
        }
    }
}

/// Record that the PTY was resized to follow the recorder's terminal.
#[cfg(unix)]
fn append_resize_event(
    writer: &Arc<Mutex<TraceWriter>>,
    size: portable_pty::PtySize,
) -> Result<()> {
    writer.lock().unwrap().append_input(EventInput {
        kind: "process.resize".into(),
        source: "premier".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "command".into(),
        parent_span_id: "session".into(),
        status: "running".into(),
        payload: json!({
            "rows": size.rows,
            "cols": size.cols,
            "pixel_width": size.pixel_width,
            "pixel_height": size.pixel_height,
        }),
        ..EventInput::default()
    })?;
    Ok(())
}

/// Whether `executable` names an existing file, looked up the way a spawn
/// does: as a path when it contains a separator, otherwise through `PATH`.
/// portable-pty reports a failed start only as text, so this tells "not
/// found" apart from "found but not executable".
#[cfg(unix)]
fn command_exists(executable: &str) -> bool {
    let path = std::path::Path::new(executable);
    if executable.contains('/') {
        return path.exists();
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(path).exists()))
}

/// Reap the PTY child with `waitpid` directly. portable-pty's own exit status
/// keeps only a `strsignal` description, which loses the signal number and
/// the core-dump flag; the raw wait status preserves both exactly.
#[cfg(unix)]
fn wait_for_pid(pid: i32, block: bool) -> std::io::Result<Option<std::process::ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;

    let options = if block { 0 } else { libc::WNOHANG };
    loop {
        let mut status = 0;
        // SAFETY: `pid` is our own unreaped child and `status` is a valid
        // out-pointer for the duration of the call.
        match unsafe { libc::waitpid(pid, &mut status, options) } {
            0 => return Ok(None),
            -1 => {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            _ => return Ok(Some(std::process::ExitStatus::from_raw(status))),
        }
    }
}

/// Captured output of one stream that is not yet journaled: an incomplete
/// UTF-8 sequence, plus text held back so a redaction rule cannot be defeated
/// by a secret that arrives split across reads. Mirroring is never delayed.
struct PendingOutput {
    utf8: Vec<u8>,
    redaction: premier_trace::TerminalRedactionBuffer,
    /// When this stream last produced output.
    last_output: Instant,
    /// Invalid UTF-8 sequences replaced with U+FFFD and not yet reported on
    /// a stored event.
    replaced_sequences: usize,
}

impl PendingOutput {
    fn new(writer: &Arc<Mutex<TraceWriter>>, kind: &str) -> Self {
        Self {
            utf8: Vec::new(),
            redaction: writer.lock().unwrap().terminal_redaction_buffer(kind),
            last_output: Instant::now(),
            replaced_sequences: 0,
        }
    }
}

/// Journal the partial line a redaction rule is holding back once its stream
/// has been quiet for [`held_output_idle_flush`]. The rules still apply to it.
fn append_idle_output(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    pending: &mut PendingOutput,
) -> Result<()> {
    if pending.last_output.elapsed() < held_output_idle_flush() {
        return Ok(());
    }
    match pending.redaction.flush_idle() {
        Some((text, byte_length)) => append_process_event(writer, kind, text, byte_length, pending),
        None => Ok(()),
    }
}

fn append_process_bytes(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    pending: &mut PendingOutput,
    bytes: &[u8],
) -> Result<()> {
    pending.last_output = Instant::now();
    let (text, replaced) = decode_utf8_chunk_lossy(&mut pending.utf8, bytes);
    pending.replaced_sequences += replaced;
    match pending.redaction.push(&text, bytes.len()) {
        Some((text, byte_length)) => append_process_event(writer, kind, text, byte_length, pending),
        None => Ok(()),
    }
}

/// Journal one piece of captured output. The stored `text` is not always
/// the bytes the command wrote: output that is not valid UTF-8 has each
/// invalid sequence replaced with U+FFFD, which cannot be undone. Such an
/// event is marked `lossy: true` with the number of replaced sequences, so a
/// reader can tell a replacement from a U+FFFD the command really printed.
/// (When a redaction rule holds text back, the mark lands on the first event
/// stored after the replacement that contains a U+FFFD.)
fn append_process_event(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    text: String,
    byte_length: usize,
    pending: &mut PendingOutput,
) -> Result<()> {
    let mut payload = json!({
        "byte_length": byte_length,
        "stream": if kind == "process.terminal" { "pty" } else { kind.trim_start_matches("process.") },
    });
    if pending.replaced_sequences > 0 && text.contains('\u{FFFD}') {
        payload["lossy"] = json!(true);
        payload["replaced_sequences"] = json!(pending.replaced_sequences);
        pending.replaced_sequences = 0;
    }
    payload["text"] = json!(text);
    writer.lock().unwrap().append_input(EventInput {
        kind: kind.into(),
        source: "command".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "command".into(),
        parent_span_id: "session".into(),
        status: "running".into(),
        payload,
        ..EventInput::default()
    })?;
    Ok(())
}

fn append_pending_utf8(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    pending: &mut PendingOutput,
) -> Result<()> {
    let byte_length = pending.utf8.len();
    let (text, replaced) = finish_utf8_lossy(&mut pending.utf8);
    pending.replaced_sequences += replaced;
    let released = pending.redaction.push(&text, byte_length);
    let finished = pending.redaction.finish();
    for (text, byte_length) in released.into_iter().chain(finished) {
        append_process_event(writer, kind, text, byte_length, pending)?;
    }
    Ok(())
}

/// Stores adapter events in order. The adapter learns each stored event id as it is assigned,
/// which is how later events get their `parent_event_id` and `links`.
fn append_adapter_events(
    writer: &Arc<Mutex<TraceWriter>>,
    adapter: &mut NativeAdapter,
    events: Vec<AdapterEvent>,
) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let mut writer = writer.lock().unwrap();
    adapter.commit(events, |event| {
        writer.append_input(event).map(|stored| stored.event_id)
    })
}

/// The size of the terminal the recorder itself runs in, when one of its
/// standard streams is a terminal.
#[cfg(unix)]
fn tty_size() -> Option<portable_pty::PtySize> {
    for file_descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: winsize is a plain C data structure and each descriptor is a
        // process-owned standard stream. ioctl only writes to this local value.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(file_descriptor, libc::TIOCGWINSZ, &mut size) } == 0
            && size.ws_row > 0
            && size.ws_col > 0
        {
            return Some(portable_pty::PtySize {
                rows: size.ws_row,
                cols: size.ws_col,
                pixel_width: size.ws_xpixel,
                pixel_height: size.ws_ypixel,
            });
        }
    }
    None
}

#[cfg(unix)]
fn terminal_size() -> portable_pty::PtySize {
    if let Some(size) = tty_size() {
        return size;
    }
    let rows = std::env::var("LINES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(24);
    let cols = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(80);
    portable_pty::PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[cfg(unix)]
struct ParentTerminalMode(Option<libc::termios>);

#[cfg(unix)]
impl ParentTerminalMode {
    fn raw_if_interactive() -> Result<Self> {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(Self(None));
        }
        // SAFETY: tcgetattr/tcsetattr operate on our standard input terminal;
        // the original attributes are retained and restored by Drop.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cannot read terminal mode");
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cannot enter raw terminal mode");
        }
        Ok(Self(Some(original)))
    }
}

#[cfg(unix)]
impl Drop for ParentTerminalMode {
    fn drop(&mut self) {
        if let Some(original) = &self.0 {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original);
            }
        }
    }
}

struct RecorderLease {
    stop: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl RecorderLease {
    fn start(trace_root: &std::path::Path) -> Result<Self> {
        let path = trace_root.join(RECORDER_LEASE);
        // The lease names this process by id and start time, so a suspended
        // recorder is not mistaken for a reused process id.
        let contents = premier_cli::liveness::lease_contents();
        std::fs::write(&path, &contents)?;
        let (stop, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            loop {
                match receiver.recv_timeout(StdDuration::from_secs(2)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Refresh only a lease that still exists: once
                        // `premier recover --force` has removed it, it must
                        // not reappear beside the finalized trace.
                        let refreshed = fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&path)
                            .and_then(|mut lease| lease.write_all(contents.as_bytes()));
                        if refreshed.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Self { stop, thread })
    }

    fn stop(self) -> Result<()> {
        let _ = self.stop.send(());
        self.thread
            .join()
            .map_err(|_| anyhow::anyhow!("recorder lease thread panicked"))
    }
}

/// Overrides how long a child may outlive a SIGTERM, SIGHUP, or SIGQUIT sent
/// to the recorder, in milliseconds, for supervisors that enforce their own
/// shutdown deadline.
#[cfg(unix)]
const STOP_GRACE_ENV: &str = "PREMIER_STOP_GRACE_MS";
#[cfg(unix)]
const DEFAULT_STOP_GRACE: StdDuration = StdDuration::from_secs(10);
/// Interrupts no further apart than this count as one insistent request.
#[cfg(unix)]
const RAPID_INTERRUPT_WINDOW: StdDuration = StdDuration::from_secs(2);
#[cfg(unix)]
const RAPID_INTERRUPTS_TO_KILL: u32 = 3;

/// Relays SIGINT/SIGTERM/SIGHUP/SIGQUIT received by the recorder to the child
/// and escalates to SIGKILL when the child will not stop, so the recorder can
/// always be stopped and the trace finalized:
/// - SIGTERM, SIGHUP (terminal or session closed), and SIGQUIT are forwarded
///   as the same signal, and the child is killed if it is still running after
///   the stop grace period.
/// - SIGINT is forwarded without a deadline, because interactive agents
///   handle an interrupt and keep running; the third interrupt in quick
///   succession kills the child instead.
#[cfg(unix)]
struct UnixSignalForwarder {
    handle: signal_hook::iterator::Handle,
    listener: thread::JoinHandle<()>,
    supervisor: thread::JoinHandle<()>,
    state: Arc<ForwarderState>,
}

#[cfg(unix)]
#[derive(Default)]
struct ForwarderState {
    received: AtomicI32,
    killed_child: AtomicBool,
    child_exited: AtomicBool,
}

#[cfg(unix)]
impl ForwarderState {
    /// Signal the child unless it has already been reaped, so a late signal
    /// can never reach an unrelated process that reused its id.
    fn signal_child(&self, target: i32, signal: i32) -> bool {
        if self.child_exited.load(Ordering::SeqCst) {
            return false;
        }
        // SAFETY: `target` names the live child (or its process group)
        // spawned by this recorder and `signal` is a valid signal number.
        // This runs on an ordinary thread, not inside the OS signal handler.
        unsafe {
            libc::kill(target, signal);
        }
        true
    }

    fn kill_child(&self, target: i32) {
        if self.signal_child(target, libc::SIGKILL) {
            self.killed_child.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(unix)]
impl UnixSignalForwarder {
    fn start(child_pid: u32) -> Result<Self> {
        Self::start_target(child_pid, false)
    }

    fn start_process_group(child_pid: u32) -> Result<Self> {
        Self::start_target(child_pid, true)
    }

    fn start_target(child_pid: u32, process_group: bool) -> Result<Self> {
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        use signal_hook::iterator::SignalsInfo;
        use signal_hook::iterator::exfiltrator::WithOrigin;

        let child_pid = i32::try_from(child_pid).context("child process id exceeds i32")?;
        let signal_target = if process_group { -child_pid } else { child_pid };
        let mut signals = SignalsInfo::<WithOrigin>::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])?;
        let handle = signals.handle();
        let state = Arc::new(ForwarderState::default());
        let (sender, receiver) = mpsc::channel::<(i32, bool)>();
        let listener = thread::spawn(move || {
            for origin in signals.forever() {
                if sender
                    .send((origin.signal, origin.process.is_some()))
                    .is_err()
                {
                    break;
                }
            }
        });
        let supervisor_state = state.clone();
        let stop_grace = std::env::var(STOP_GRACE_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .map_or(DEFAULT_STOP_GRACE, StdDuration::from_millis);
        let supervisor = thread::spawn(move || {
            let state = supervisor_state;
            let mut kill_deadline: Option<Instant> = None;
            let mut interrupts = 0_u32;
            let mut last_interrupt: Option<Instant> = None;
            loop {
                let message = match kill_deadline {
                    Some(deadline) => {
                        let wait = deadline.saturating_duration_since(Instant::now());
                        match receiver.recv_timeout(wait) {
                            Ok(message) => message,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                kill_deadline = None;
                                state.kill_child(signal_target);
                                continue;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    None => match receiver.recv() {
                        Ok(message) => message,
                        Err(mpsc::RecvError) => break,
                    },
                };
                let (signal, sent_by_process) = message;
                state
                    .received
                    .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst)
                    .ok();
                if signal == SIGINT {
                    let now = Instant::now();
                    let rapid = last_interrupt.is_some_and(|previous| {
                        now.duration_since(previous) <= RAPID_INTERRUPT_WINDOW
                    });
                    interrupts = if rapid { interrupts + 1 } else { 1 };
                    last_interrupt = Some(now);
                    if interrupts >= RAPID_INTERRUPTS_TO_KILL {
                        state.kill_child(signal_target);
                        continue;
                    }
                    // A pipe-mode child shares the recorder's foreground
                    // process group, so a terminal Ctrl-C has already
                    // reached it. Forwarding it again would deliver one
                    // keypress twice.
                    if !process_group && interrupt_is_from_terminal(sent_by_process) {
                        continue;
                    }
                } else {
                    if kill_deadline.is_none() {
                        kill_deadline = Some(Instant::now() + stop_grace);
                    }
                    // Ctrl-\ reaches a pipe-mode child directly, exactly as
                    // Ctrl-C does; the deadline above still applies.
                    if signal == SIGQUIT
                        && !process_group
                        && interrupt_is_from_terminal(sent_by_process)
                    {
                        continue;
                    }
                }
                state.signal_child(signal_target, signal);
            }
        });
        Ok(Self {
            handle,
            listener,
            supervisor,
            state,
        })
    }

    /// Tell the forwarder the child has been reaped and must not be signalled.
    fn child_exited(&self) {
        self.state.child_exited.store(true, Ordering::SeqCst);
    }

    fn finish(self) -> Result<RecorderSignals> {
        self.handle.close();
        for thread in [self.listener, self.supervisor] {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("signal forwarding thread panicked"))?;
        }
        Ok(RecorderSignals {
            received: match self.state.received.load(Ordering::SeqCst) {
                0 => None,
                signal => Some(signal),
            },
            killed_child: self.state.killed_child.load(Ordering::SeqCst),
        })
    }
}

/// Whether a SIGINT or SIGQUIT received by the recorder was generated by its
/// terminal (Ctrl-C, Ctrl-\) rather than sent to the recorder alone.
#[cfg(unix)]
fn interrupt_is_from_terminal(sent_by_process: bool) -> bool {
    // Linux marks terminal-generated signals as sent by the kernel, with no
    // sending process, which identifies them exactly.
    if cfg!(any(target_os = "linux", target_os = "android")) {
        return !sent_by_process;
    }
    // Other systems (macOS names the terminal emulator as the sender) give
    // no such marker, so assume the terminal whenever the recorder is in the
    // foreground process group of its controlling terminal. A `kill -INT`
    // aimed at a foreground recorder is then not relayed; repeating it, or
    // SIGTERM, still stops the child.
    use std::os::fd::AsRawFd;
    let Ok(terminal) = fs::File::open("/dev/tty") else {
        return false;
    };
    // SAFETY: both calls only query process-group ids; the descriptor is a
    // terminal opened above and stays open for the duration of the call.
    unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) == libc::getpgrp() }
}

fn process_termination(status: &std::process::ExitStatus) -> ProcessTermination {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ProcessTermination::signaled(signal, signal_name(signal).map(str::to_owned));
        }
    }
    ProcessTermination::exited(status.code().unwrap_or(1))
}

/// Signal numbers differ between platforms (SIGBUS is 7 on Linux and 10 on
/// macOS), so names are resolved through the target's libc constants.
#[cfg(unix)]
fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGVTALRM => "SIGVTALRM",
        libc::SIGPROF => "SIGPROF",
        libc::SIGSYS => "SIGSYS",
        _ => return None,
    })
}

#[cfg(not(unix))]
fn signal_name(_signal: i32) -> Option<&'static str> {
    None
}

fn pump(
    mut reader: impl Read + Send + 'static,
    sender: mpsc::SyncSender<(&'static str, Vec<u8>)>,
    stream: &'static str,
) {
    thread::spawn(move || {
        let mut buffer = vec![0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send((stream, buffer[..count].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn list(trace_dir: PathBuf) -> Result<()> {
    if !trace_dir.exists() {
        return Ok(());
    }
    let mut manifests = Vec::new();
    // A trace that cannot be opened (encrypted without its key, written in
    // a later format, or with a damaged manifest) is still listed, from
    // whatever its manifest shows, instead of silently vanishing.
    let mut unopened = Vec::new();
    for entry in std::fs::read_dir(trace_dir)? {
        let entry = entry?;
        // Dot-prefixed directories are working copies of `encrypt` and
        // `demo`, not traces.
        if !entry.file_type()?.is_dir() || entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        match read_manifest(entry.path()) {
            Ok(manifest) => manifests.push((entry.path(), manifest)),
            // A directory without a manifest is not a trace.
            Err(_) if !entry.path().join("manifest.json").is_file() => {}
            Err(error) => unopened.push(unopened_list_line(&entry.path(), &error)),
        }
    }
    manifests.sort_by_key(|(_, manifest)| std::cmp::Reverse(manifest.started_at));
    for (path, manifest) in manifests {
        let state = match unfinalized_state(&path, &manifest) {
            // How a finished run ended, when it did not end cleanly.
            None => match (&manifest.termination, manifest.exit_code) {
                (Some(termination), _) if termination.kind == TerminationKind::Signal => format!(
                    "  [{}]",
                    termination
                        .signal_name
                        .clone()
                        .or(termination.signal.map(|signal| format!("signal {signal}")))
                        .unwrap_or_else(|| "signal".into())
                ),
                (Some(termination), _) if termination.kind == TerminationKind::Interrupted => {
                    "  [interrupted]".into()
                }
                (_, Some(code)) if code != 0 => format!("  [exit {code}]"),
                _ => String::new(),
            },
            Some(UnfinalizedState::Recording) => "  [recording]".into(),
            Some(state) => format!("  [{}]", state.describe(&path)),
        };
        println!(
            "{}  {}  {}{}  ({})",
            printable(&manifest.trace_id),
            manifest.started_at,
            printable(&manifest.name.unwrap_or_else(|| manifest.command.join(" "))),
            printable(&state),
            printable(&path.file_name().unwrap_or_default().to_string_lossy())
        );
    }
    unopened.sort();
    for (_, line) in unopened.iter().rev() {
        println!("{line}");
    }
    Ok(())
}

/// The `list` line for a trace whose manifest could not be read, with its
/// start time (when known) as the sort key. Its name and command are sealed
/// or unreadable, so the directory name stands in for them.
fn unopened_list_line(
    path: &std::path::Path,
    error: &anyhow::Error,
) -> (Option<chrono::DateTime<Utc>>, String) {
    let public = fs::read(path.join("manifest.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or_default();
    let unsupported = error.downcast_ref::<premier_trace::UnsupportedFormatVersion>();
    let reason = if let Some(unsupported) = unsupported.filter(|unsupported| unsupported.is_newer())
    {
        format!(
            "needs a newer premier: format version {}",
            unsupported.found
        )
    } else if unsupported.is_some() {
        format!("unreadable: {error:#}")
    } else if premier_trace::trace_is_encrypted(path).unwrap_or(false) {
        if premier_trace::key_file_configured() {
            format!("encrypted: {error:#}")
        } else {
            "encrypted: key required".to_owned()
        }
    } else {
        format!("unreadable: {error:#}")
    };
    // The same rendering as a readable trace's start time.
    let started_at = public["started_at"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let line = format!(
        "{}  {}  {}  [{}]",
        printable(public["trace_id"].as_str().unwrap_or("unknown")),
        started_at.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        printable(&path.file_name().unwrap_or_default().to_string_lossy()),
        printable(&reason)
    );
    (started_at, line)
}

/// Directory that contains `trace`, treating the empty parent of a bare
/// relative path (`foo.atrace`) as the current directory so the viewer can
/// list and resolve it.
fn trace_parent_dir(trace: &std::path::Path) -> PathBuf {
    match trace.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Default output of `premier record`:
/// `.premier/traces/trace-<unix milliseconds>-<8 random hex digits>.atrace`.
/// The timestamp keeps a directory listing in recording order; the suffix
/// keeps recorders started in the same millisecond apart.
fn default_trace_path() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    // The low 32 bits of a version 7 UUID are random.
    let suffix = uuid::Uuid::now_v7().as_u128() as u32;
    PathBuf::from(format!(
        ".premier/traces/trace-{millis}-{suffix:08x}.atrace"
    ))
}
