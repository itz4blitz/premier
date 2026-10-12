use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use premier_cli::evidence::{
    DiffStatus, QueryOptions, diff_events, portable_evidence, query_events,
};
use premier_cli::{
    AuthPolicy, ServerOptions, app_with_options, embedded_viewer_ready, instrumentation_app,
    validate_bind, validate_remote_trace_store,
};
use premier_trace::{
    EventInput, ProcessTermination, RECORDER_LEASE, RecoveryOptions, RedactionConfig,
    TerminationKind, TraceWriter, decode_utf8_chunk, finish_utf8, prepare_trace_output,
    read_events, read_manifest, recover_interrupted_trace, verify,
};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
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
use adapters::{ADAPTER_SCHEMA_VERSION, AdapterChoice, NativeAdapter, Provider};

#[derive(Parser)]
#[command(
    name = "premier",
    version,
    about = "Local-first agent trace recorder and viewer"
)]
struct Cli {
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
        /// Normalize a provider's native JSONL stream into typed evidence.
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
        /// recorded command line (terminal display stays raw). Matched per line.
        #[arg(long = "redact-regex")]
        redact_regexes: Vec<String>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Generate a rich local multi-agent trace for product evaluation and onboarding.
    Demo {
        #[arg(short, long, default_value = ".premier/traces/multi-agent-demo.atrace")]
        output: PathBuf,
    },
    /// Emit a typed agent event to the active local collector (`PREMIER_COLLECTOR_*`).
    Emit {
        /// Full JSON event body. Use `-` to read from stdin.
        #[arg(long)]
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
    /// Verify a finalized trace's digest, framing, event count, and identity.
    Verify { trace: PathBuf },
    /// Safely finalize an abandoned active trace, discarding only a torn trailing frame.
    Recover {
        trace: PathBuf,
        /// Minimum journal idle time required before recovery.
        #[arg(long, default_value_t = 300)]
        stale_after_seconds: u64,
        /// Recover even when the journal was modified recently.
        #[arg(long)]
        force: bool,
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
    },
    /// Filter local trace evidence without starting the viewer.
    Query {
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
        /// Case-insensitive search across event metadata and payload JSON.
        #[arg(long)]
        search: Option<String>,
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
    Export {
        trace: PathBuf,
        /// Destination JSON file. Omit to write JSON to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Export a finalized trace even though it fails `premier verify`.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// Compare two traces by semantic event structure, ignoring generated identity noise.
    Diff {
        baseline: PathBuf,
        current: PathBuf,
        /// Emit the complete structural comparison as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Replay recorded evidence timing only; this never re-executes the traced command.
    Replay {
        trace: PathBuf,
        /// Playback speed multiplier (for example 2 replays twice as fast).
        #[arg(long, default_value_t = 1.0, value_parser = parse_replay_speed)]
        speed: f64,
        /// Emit evidence immediately while preserving recorded order.
        #[arg(long)]
        no_sleep: bool,
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
    match Cli::parse().command {
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
            command,
        } => {
            let redaction = RedactionConfig::new(redact_fields, redact_literals, redact_regexes)?;
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
            })
            .await
        }
        Commands::Demo { output } => demo(output),
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
        Commands::Verify { trace } => {
            if let Ok(manifest) = read_manifest(&trace)
                && let Some(state) = unfinalized_state(&trace, &manifest)
            {
                bail!("trace is not finalized ({})", state.describe(&trace))
            }
            let mut manifest = verify(&trace)?;
            if manifest.diagnostics.is_empty() {
                manifest.diagnostics =
                    premier_trace::validate_events(&premier_trace::read_events(&trace)?);
            }
            println!(
                "verified {} ({} events, {} semantic diagnostics)",
                manifest.trace_id,
                manifest
                    .journal
                    .as_ref()
                    .map_or(0, |journal| journal.event_count),
                manifest.diagnostics.len(),
            );
            for diagnostic in &manifest.diagnostics {
                println!(
                    "warning {} at sequence {}: {}",
                    diagnostic.code,
                    diagnostic.sequence.unwrap_or(0),
                    diagnostic.message
                );
            }
            Ok(())
        }
        Commands::Recover {
            trace,
            stale_after_seconds,
            force,
        } => {
            let manifest = recover_interrupted_trace(
                &trace,
                RecoveryOptions {
                    minimum_idle: StdDuration::from_secs(stale_after_seconds),
                    force,
                },
            )?;
            println!(
                "recovered {} ({} events, exit {})",
                manifest.trace_id,
                manifest
                    .journal
                    .as_ref()
                    .map_or(0, |journal| journal.event_count),
                manifest.exit_code.unwrap_or(130)
            );
            Ok(())
        }
        Commands::Claim { trace, tenant } => {
            let manifest = premier_trace::claim_local_trace(&trace, &tenant)?;
            println!(
                "claimed {} for tenant {}",
                manifest.trace_id, manifest.tenant_id
            );
            Ok(())
        }
        Commands::Encrypt {
            trace,
            new_key_file,
        } => {
            let key = premier_trace::EncryptionKey::from_file(&new_key_file)?;
            let manifest = premier_trace::reencrypt_finalized_trace(&trace, key)?;
            println!("encrypted {} ({})", manifest.trace_id, trace.display());
            Ok(())
        }
        Commands::Query {
            trace,
            kind,
            actor,
            status,
            search,
            limit,
            json,
            allow_unverified,
        } => {
            ensure_verified(&trace, allow_unverified)?;
            query_trace(
                trace,
                QueryOptions {
                    kind,
                    actor,
                    status,
                    search,
                    limit,
                },
                json,
            )
        }
        Commands::Export {
            trace,
            output,
            allow_unverified,
        } => {
            ensure_verified(&trace, allow_unverified)?;
            export_trace(trace, output)
        }
        Commands::Diff {
            baseline,
            current,
            json,
        } => diff_traces(baseline, current, json),
        Commands::Replay {
            trace,
            speed,
            no_sleep,
        } => replay_trace(trace, speed, no_sleep),
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
                let manifest = read_manifest(&trace)?;
                // Canonical so `.` and `dir/..` still name one directory entry:
                // opening a trace must not publish its siblings.
                let trace = fs::canonicalize(&trace)?;
                options.only_artifact = Some(
                    trace
                        .file_name()
                        .context("trace path has no directory name")?
                        .to_owned(),
                );
                (trace_parent_dir(&trace), Some(manifest.trace_id))
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
            let auth = AuthPolicy::from_sources(password, auth_config.as_deref())?;
            let tls = TlsFiles::from_options(tls_cert, tls_key)?;
            let options = server_options(no_assistant);
            serve_viewer(trace_dir, viewer_dir, bind, auth, options, None, false, tls).await
        }
    }
}

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

/// Gate evidence-reading commands on the same checks as `premier verify`.
/// A live trace has no digest yet, so it is readable with a note; a finalized
/// trace that fails verification is refused unless explicitly allowed.
fn ensure_verified(trace: &std::path::Path, allow_unverified: bool) -> Result<()> {
    let manifest =
        read_manifest(trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    if manifest.journal.is_none() {
        eprintln!(
            "note: {} is not finalized (still recording or interrupted); its events are unverified and may be incomplete",
            trace.display()
        );
        return Ok(());
    }
    match verify(trace) {
        Ok(_) => Ok(()),
        Err(error) if allow_unverified => {
            eprintln!(
                "warning: {} failed verification ({error:#}); reading it anyway because --allow-unverified was given",
                trace.display()
            );
            Ok(())
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
        .map_err(|_| "limit must be an integer between 1 and 1000".to_owned())?;
    if !(1..=1_000).contains(&limit) {
        return Err("limit must be between 1 and 1000".into());
    }
    Ok(limit)
}

fn parse_replay_speed(value: &str) -> std::result::Result<f64, String> {
    let speed = value
        .parse::<f64>()
        .map_err(|_| "speed must be a positive finite number".to_owned())?;
    if !speed.is_finite() || speed <= 0.0 {
        return Err("speed must be a positive finite number".into());
    }
    Ok(speed)
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

fn query_trace(trace: PathBuf, options: QueryOptions, json_output: bool) -> Result<()> {
    read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    let result = query_events(&read_events(&trace)?, &options);
    if json_output {
        return print_json(&result);
    }
    for event in &result.events {
        println!(
            "{:>6}  {}  {:<24} {:<18} {}",
            event.sequence,
            event.timestamp,
            event.kind,
            if event.actor_id.is_empty() {
                "root"
            } else {
                &event.actor_id
            },
            event.status
        );
    }
    eprintln!(
        "{} matched; {} returned{}",
        result.matched,
        result.returned,
        if result.truncated {
            " (limit reached)"
        } else {
            ""
        }
    );
    Ok(())
}

fn export_trace(trace: PathBuf, output: Option<PathBuf>) -> Result<()> {
    let manifest =
        read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    let export = portable_evidence(&manifest, &read_events(&trace)?);
    if let Some(output) = output {
        let mut bytes = serde_json::to_vec_pretty(&export)?;
        bytes.push(b'\n');
        let temporary = output.with_file_name(format!(
            ".{}.tmp-{}",
            output
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("premier-export"),
            std::process::id()
        ));
        fs::write(&temporary, bytes)
            .with_context(|| format!("cannot write export {}", temporary.display()))?;
        if let Err(error) = fs::rename(&temporary, &output) {
            let _ = fs::remove_file(&temporary);
            return Err(error)
                .with_context(|| format!("cannot publish export {}", output.display()));
        }
        println!("exported redacted evidence to {}", output.display());
        Ok(())
    } else {
        print_json(&export)
    }
}

fn diff_traces(baseline: PathBuf, current: PathBuf, json_output: bool) -> Result<()> {
    read_manifest(&baseline)
        .with_context(|| format!("cannot read baseline trace {}", baseline.display()))?;
    read_manifest(&current)
        .with_context(|| format!("cannot read current trace {}", current.display()))?;
    let diff = diff_events(&read_events(&baseline)?, &read_events(&current)?);
    if json_output {
        return print_json(&diff);
    }
    println!(
        "{} added · {} removed · {} changed · {} unchanged",
        diff.counts.added, diff.counts.removed, diff.counts.changed, diff.counts.unchanged
    );
    for item in diff
        .items
        .iter()
        .filter(|item| item.status != DiffStatus::Unchanged)
    {
        println!(
            "{:?}\t{}\t{} field change{}",
            item.status,
            item.key,
            item.changes.len(),
            if item.changes.len() == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

fn replay_trace(trace: PathBuf, speed: f64, no_sleep: bool) -> Result<()> {
    read_manifest(&trace).with_context(|| format!("cannot read trace {}", trace.display()))?;
    let mut events = read_events(&trace)?;
    events.sort_by_key(|event| event.sequence);
    eprintln!(
        "NON-EXECUTION evidence replay: emitting {} recorded events at {speed}x; no commands, tools, or models will run",
        events.len()
    );
    let mut previous = None;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for event in events {
        if !no_sleep && let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(&event.timestamp) {
            if let Some(previous) = previous {
                let delay = timestamp.signed_duration_since(previous);
                if let Ok(delay) = delay.to_std()
                    && !delay.is_zero()
                {
                    thread::sleep(StdDuration::from_secs_f64(delay.as_secs_f64() / speed));
                }
            }
            previous = Some(timestamp);
        }
        serde_json::to_writer(&mut output, &event)?;
        writeln!(output)?;
        output.flush()?;
    }
    Ok(())
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
    let scheme = if tls_enabled { "https" } else { "http" };
    let url = focus_trace
        .map(|trace_id| format!("{scheme}://{bind}/?trace={trace_id}"))
        .unwrap_or_else(|| format!("{scheme}://{bind}"));
    println!("Premier viewer: {url}");
    if launch_browser && let Err(error) = open_browser(&url) {
        tracing::warn!("could not open browser: {error}");
    }
    let router = app_with_options(trace_dir, viewer, auth, options);
    if let Some(tls) = tls {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(tls.cert, tls.key).await?;
        axum_server::bind_rustls(bind, config)
            .serve(router.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        axum::serve(listener, router).await?;
    }
    Ok(())
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
    // The collector is a loopback endpoint authenticated by a bearer token:
    // never route the token or payload through HTTP(S)_PROXY / ALL_PROXY.
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
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

fn demo(output: PathBuf) -> Result<()> {
    prepare_trace_output(&output)?;
    let mut writer = TraceWriter::create_named(
        &output,
        vec!["premier".into(), "demo".into()],
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
    let reviewer = writer.append_input(EventInput {
        parent_event_id: patch.event_id.clone(),
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
    let manifest = writer.finish(1)?;
    println!("demo trace {} → {}", manifest.trace_id, output.display());
    println!("next: premier open {}", output.display());
    Ok(())
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
            "--open serves the default local viewer identity, which cannot see a trace owned by tenant '{tenant}'; record without --open, then use `premier serve --auth-config` to view it"
        )
    }
    let native_provider = adapter.resolve(executable, &command[1..], pty);
    let output = output.unwrap_or_else(|| {
        let id = uuid_like_timestamp();
        PathBuf::from(format!(".premier/traces/{id}.atrace"))
    });
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut trace_writer = TraceWriter::create_named_for_tenant_with_redaction(
        &output,
        command.clone(),
        name,
        &tenant,
        redaction,
    )?;
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
    let collector_token = uuid::Uuid::now_v7().to_string();
    let collector_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let collector_address = collector_listener.local_addr()?;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let collector_writer = writer.clone();
    let collector_token_for_server = collector_token.clone();
    let collector_task = tokio::spawn(async move {
        axum::serve(
            collector_listener,
            instrumentation_app(collector_writer, collector_token_for_server),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_receiver.await;
        })
        .await
    });
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
            )?
        }
        #[cfg(not(unix))]
        unreachable!("non-Unix PTY request rejected before trace creation")
    } else {
        capture_pipes(executable, &command[1..], capture_environment, &writer)?
    };
    recorder_lease.stop()?;
    let termination = capture.termination;
    let recorder_signals = capture.recorder_signals;
    let mut faults = capture.faults;
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
    let finalized: Result<premier_trace::TraceManifest> = async {
        let _ = shutdown_sender.send(());
        collector_task.await??;
        let writer = Arc::try_unwrap(writer)
            .map_err(|_| anyhow::anyhow!("collector still owns the trace writer"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("trace writer lock was poisoned"))?;
        writer.finish_termination(termination.clone())
    }
    .await;
    match &finalized {
        Ok(manifest) => eprintln!("\ntrace {} → {}", manifest.trace_id, output.display()),
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
        eprintln!("next: premier open {}", output.display());
        if open_viewer && recorder_signals.received.is_none() {
            return serve_viewer(
                trace_parent_dir(&output),
                viewer_dir,
                bind,
                AuthPolicy::default(),
                server_options(false),
                Some(manifest.trace_id),
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

/// Hand captured output to `on_output` until the child has exited and its
/// streams are drained. Finalization must not wait for end-of-file: a
/// descendant can hold the pipe or PTY open long after the child is gone.
/// Returns the status if the exit was observed here, and whether a stream
/// was still open when draining stopped.
fn drain_child_output(
    receiver: mpsc::Receiver<(&'static str, Vec<u8>)>,
    mut try_wait: impl FnMut() -> std::io::Result<Option<std::process::ExitStatus>>,
    mut on_output: impl FnMut(&'static str, &[u8]),
) -> std::io::Result<(Option<std::process::ExitStatus>, bool)> {
    let mut status = None;
    let mut exited_at = None;
    let mut last_output = Instant::now();
    let mut next_poll = Instant::now();
    loop {
        let now = Instant::now();
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
                on_output(stream, &bytes);
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
        .with_context(|| format!("failed to start {executable}"))?;

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
    let (status, output_open_at_exit) = drain_child_output(
        receiver,
        || {
            let status = child.try_wait()?;
            #[cfg(unix)]
            if status.is_some() {
                signal_forwarder.child_exited();
            }
            Ok(status)
        },
        |stream, bytes| {
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
                faults.note(append_adapter_events(writer, adapter.push(bytes)));
            }
        },
    )?;
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
    if let Some(adapter) = native_adapter.as_mut() {
        faults.note(append_adapter_events(writer, adapter.finish()));
    }
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
        .with_context(|| format!("failed to start {executable} in pseudo-terminal"))?;
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
        let _ = std::io::copy(&mut input, &mut terminal_writer);
        // portable-pty deliberately sends EOT when its writer is dropped.
        // Keep the writer alive after redirected stdin reaches EOF so that EOT
        // is not echoed into the captured stream ahead of the child output.
        let _ = wait_for_release.recv();
    });

    // The reader runs on its own thread so a descendant that keeps the
    // terminal open cannot block finalization after the child has exited.
    // Unix PTY masters commonly report EIO after the final slave closes;
    // the pump treats any read error as end of output.
    let (sender, receiver) = mpsc::sync_channel::<(&'static str, Vec<u8>)>(256);
    pump(reader, sender, "terminal");
    let mut pending = PendingOutput::new(writer, "process.terminal");
    let mut mirror = true;
    let mut faults = RecordingFaults::default();
    let (status, output_open_at_exit) = drain_child_output(
        receiver,
        || {
            let status = wait_for_pid(child_pid, false)?;
            if status.is_some() {
                signal_forwarder.child_exited();
            }
            Ok(status)
        },
        |_, bytes| {
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
    )?;
    faults.note(append_pending_utf8(
        writer,
        "process.terminal",
        &mut pending,
    ));
    let status = match status {
        Some(status) => status,
        None => loop {
            if let Some(status) = wait_for_pid(child_pid, true)? {
                break status;
            }
        },
    };
    signal_forwarder.child_exited();
    let _ = release_stdin.send(());
    let recorder_signals = signal_forwarder.finish()?;
    Ok(CaptureOutcome {
        termination: process_termination(&status),
        recorder_signals,
        core_dumped: status.core_dumped(),
        output_open_at_exit,
        faults,
    })
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
}

impl PendingOutput {
    fn new(writer: &Arc<Mutex<TraceWriter>>, kind: &str) -> Self {
        Self {
            utf8: Vec::new(),
            redaction: writer.lock().unwrap().terminal_redaction_buffer(kind),
        }
    }
}

fn append_process_bytes(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    pending: &mut PendingOutput,
    bytes: &[u8],
) -> Result<()> {
    let text = decode_utf8_chunk(&mut pending.utf8, bytes);
    match pending.redaction.push(&text, bytes.len()) {
        Some((text, byte_length)) => append_process_event(writer, kind, text, byte_length),
        None => Ok(()),
    }
}

fn append_process_event(
    writer: &Arc<Mutex<TraceWriter>>,
    kind: &str,
    text: String,
    byte_length: usize,
) -> Result<()> {
    writer.lock().unwrap().append_input(EventInput {
        kind: kind.into(),
        source: "command".into(),
        actor_id: "root".into(),
        actor_type: "process".into(),
        span_id: "command".into(),
        parent_span_id: "session".into(),
        status: "running".into(),
        payload: json!({
            "text": text,
            "byte_length": byte_length,
            "stream": if kind == "process.terminal" { "pty" } else { kind.trim_start_matches("process.") },
        }),
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
    let text = finish_utf8(&mut pending.utf8);
    let released = pending.redaction.push(&text, byte_length);
    for (text, byte_length) in released.into_iter().chain(pending.redaction.finish()) {
        append_process_event(writer, kind, text, byte_length)?;
    }
    Ok(())
}

fn append_adapter_events(writer: &Arc<Mutex<TraceWriter>>, events: Vec<EventInput>) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let mut writer = writer.lock().unwrap();
    for event in events {
        writer.append_input(event)?;
    }
    Ok(())
}

#[cfg(unix)]
fn terminal_size() -> portable_pty::PtySize {
    for file_descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: winsize is a plain C data structure and each descriptor is a
        // process-owned standard stream. ioctl only writes to this local value.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(file_descriptor, libc::TIOCGWINSZ, &mut size) } == 0
            && size.ws_row > 0
            && size.ws_col > 0
        {
            return portable_pty::PtySize {
                rows: size.ws_row,
                cols: size.ws_col,
                pixel_width: size.ws_xpixel,
                pixel_height: size.ws_ypixel,
            };
        }
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
        std::fs::write(&path, std::process::id().to_string())?;
        let (stop, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            loop {
                match receiver.recv_timeout(StdDuration::from_secs(2)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if std::fs::write(&path, std::process::id().to_string()).is_err() {
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

/// Overrides how long a child may outlive a SIGTERM sent to the recorder, in
/// milliseconds, for supervisors that enforce their own shutdown deadline.
#[cfg(unix)]
const STOP_GRACE_ENV: &str = "PREMIER_STOP_GRACE_MS";
#[cfg(unix)]
const DEFAULT_STOP_GRACE: StdDuration = StdDuration::from_secs(10);
/// Interrupts no further apart than this count as one insistent request.
#[cfg(unix)]
const RAPID_INTERRUPT_WINDOW: StdDuration = StdDuration::from_secs(2);
#[cfg(unix)]
const RAPID_INTERRUPTS_TO_KILL: u32 = 3;

/// Relays SIGINT/SIGTERM received by the recorder to the child and escalates
/// to SIGKILL when the child will not stop, so the recorder can always be
/// stopped and the trace finalized:
/// - SIGTERM is forwarded, and the child is killed if it is still running
///   after the stop grace period.
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
        use signal_hook::consts::signal::{SIGINT, SIGTERM};
        use signal_hook::iterator::SignalsInfo;
        use signal_hook::iterator::exfiltrator::WithOrigin;

        let child_pid = i32::try_from(child_pid).context("child process id exceeds i32")?;
        let signal_target = if process_group { -child_pid } else { child_pid };
        let mut signals = SignalsInfo::<WithOrigin>::new([SIGINT, SIGTERM])?;
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
                } else if kill_deadline.is_none() {
                    kill_deadline = Some(Instant::now() + stop_grace);
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

/// Whether a SIGINT received by the recorder was generated by its terminal
/// (Ctrl-C) rather than sent to the recorder alone.
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
    for entry in std::fs::read_dir(trace_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && let Ok(manifest) = read_manifest(entry.path())
        {
            manifests.push((entry.path(), manifest));
        }
    }
    manifests.sort_by_key(|(_, manifest)| std::cmp::Reverse(manifest.started_at));
    for (path, manifest) in manifests {
        let state = match unfinalized_state(&path, &manifest) {
            None => String::new(),
            Some(UnfinalizedState::Recording) => "  [recording]".into(),
            Some(state) => format!("  [{}]", state.describe(&path)),
        };
        println!(
            "{}  {}  {}{state}",
            manifest.trace_id,
            manifest.started_at,
            manifest.name.unwrap_or_else(|| manifest.command.join(" "))
        );
    }
    Ok(())
}

/// Why a trace without a finalized journal is in that state.
enum UnfinalizedState {
    /// The recorder named in the lease is alive and heartbeating.
    Recording,
    /// The recorder is gone; `recover` needs `--force` only while the
    /// journal is still inside its idle guard.
    Abandoned { needs_force: bool },
}

impl UnfinalizedState {
    fn describe(&self, trace: &std::path::Path) -> String {
        match self {
            Self::Recording => "still recording".into(),
            Self::Abandoned { needs_force } => format!(
                "abandoned: the recorder is no longer running — run `premier recover {}{}`",
                if *needs_force { "--force " } else { "" },
                trace.display()
            ),
        }
    }
}

/// Classify an unfinalized trace from its recorder lease: the lease holds the
/// recorder's process id and is rewritten every two seconds while it runs.
fn unfinalized_state(
    trace: &std::path::Path,
    manifest: &premier_trace::TraceManifest,
) -> Option<UnfinalizedState> {
    if manifest.journal.is_some() {
        return None;
    }
    let stale_after = RecoveryOptions::default().minimum_idle;
    let lease = trace.join(RECORDER_LEASE);
    let idle = |path: &std::path::Path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
    };
    let recorder_pid = fs::read_to_string(&lease)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok());
    let lease_idle = idle(&lease);
    let heartbeating = lease_idle.is_some_and(|idle| idle < stale_after);
    if recorder_pid.is_some_and(process_is_alive) && heartbeating {
        return Some(UnfinalizedState::Recording);
    }
    // `premier recover` guards on the newer of the journal and the lease.
    let journal_idle = idle(&trace.join("events").join(premier_trace::ACTIVE_JOURNAL));
    let needs_force = [lease_idle, journal_idle]
        .into_iter()
        .flatten()
        .any(|idle| idle < stale_after);
    Some(UnfinalizedState::Abandoned { needs_force })
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 performs only the existence and permission check.
    // EPERM still means a process with this id exists.
    pid > 0
        && (unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

/// Without a portable liveness probe, rely on the lease heartbeat alone.
#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    true
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

fn uuid_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "trace-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )
}
