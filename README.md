<p align="center">
  <img src="docs/assets/premier-hero.png" alt="Premier agent traces converging into verified evidence" width="100%" />
</p>

<h1 align="center">Premier</h1>

<p align="center">
  <strong>The flight recorder for AI agents.</strong><br />
  Record what your agents did, inspect why they did it, and keep the evidence.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@premierstudio/premier"><img src="https://img.shields.io/npm/v/%40premierstudio%2Fpremier?style=flat-square&color=7c83ff" alt="npm version" /></a>
  <a href="https://github.com/PremierStudio/premier/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/PremierStudio/premier/ci.yml?branch=main&style=flat-square&label=build" alt="build status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-6d7cff?style=flat-square" alt="Apache 2.0 license" /></a>
  <img src="https://img.shields.io/badge/macOS%20%7C%20Linux-supported-111827?style=flat-square" alt="macOS and Linux" />
</p>

<p align="center">
  <a href="https://premier.dev/docs"><strong>Documentation</strong></a> ·
  <a href="https://premier.dev/docs/install">Installation</a> ·
  <a href="https://premier.dev/docs/adapters">Agent integrations</a> ·
  <a href="https://premier.dev/docs/record">Audit your agents</a>
</p>

---

## See the whole run

Agents make decisions across models, tools, terminals, subagents, approvals, and handoffs. Premier turns that activity into a portable, verifiable trace you can investigate locally.

<p align="center">
  <img src="docs/assets/premier-agent-trace-viewer.png" alt="Premier investigating a multi-agent failure" width="100%" />
</p>

## Start in thirty seconds

```sh
npm install --global @premierstudio/premier
premier record -- your-agent run
premier open
```

Or pin Premier inside a project:

```sh
npm install --save-dev @premierstudio/premier
npx premier record -- npm test
```

Premier is script-free: installation does not run lifecycle scripts or download executables from arbitrary URLs. The npm launcher selects the native package for your platform, published through npm trusted publishing with provenance.

## Works with the agents you already use

| Agent | Native structured capture when run with |
| --- | --- |
| Claude Code | `claude ... --output-format stream-json` |
| OpenAI Codex | `codex ... --json` |
| Gemini CLI | `gemini ... --output-format stream-json` |
| Grok | `grok ... --output-format streaming-json` |
| Kimi | `kimi ... --output-format stream-json` |
| OpenCode | `opencode ... --format json` |
| Droid | `droid ... --output-format json` |

"Native structured capture" means Premier reads the JSON lines the CLI prints in that output mode and adds typed model, tool, and approval events next to the raw output. It is heuristic and best effort, and it only sees what the CLI prints. An interactive session, or any run under `--pty`, is recorded as terminal output and exit status only. [How adapters work and where they stop →](docs/adapters.md)

```sh
premier record --adapter auto -- codex exec --json "review this repository"
premier record --adapter claude -- claude -p --output-format stream-json "fix the failing test"
premier record --pty -- your-interactive-agent
```

Unknown harness? Premier can record any process immediately, then accept typed evidence through its JavaScript SDK, CLI emitter, shell helper, or local HTTP collector.

## Evidence, not vibes

- **Reconstruct the run** — terminal output, timing, and exit semantics for any command; model calls, tools, approvals, delegation, messages, and joins when an adapter or your harness reports them.
- **Follow causality** — the actor identity, parent events, spans, correlations, and cross-links that producers report stay attached to the evidence.
- **Find the failure** — filter issues, compare runs, inspect topology, query locally, and export a redacted evidence package for review.
- **Keep control** — traces are local-first, portable, integrity-checked, redactable, and optionally encrypted.

## Ask a local assistant

The viewer can put questions about a trace to an agent CLI already installed on your machine (Claude, Codex, Grok, or Gemini), run in an empty directory with its tools disabled or restricted to read-only.

Asking a question sends redacted trace content to the model provider behind the CLI you pick; turn the assistant off with `premier open --no-assistant` or `PREMIER_DISABLE_ASSISTANT=1`. [What is sent and how it is confined →](docs/security.md#the-local-assistant)

## Instrument your own harness

Install the tiny emitter:

```sh
npm install @premierstudio/trace
```

```ts
import { premier } from "@premierstudio/trace";

await premier.spawn("researcher", { task: "find the first divergence" });
await premier.model("researcher", {
  provider: "openai",
  model: "gpt-5",
  usage: { input_tokens: 1200, output_tokens: 400, total_tokens: 1600 },
});
```

Premier injects a loopback collector URL and per-run bearer token into every recorded process. Your harness emits the facts it knows; Premier handles storage, integrity, redaction, recovery, and investigation.

[Read the instrumentation guide →](https://premier.dev/docs/sdk)

## Built for sensitive evidence

- Loopback-only collector with a per-run bearer token
- Secret-named fields and well-known credential shapes redacted from structured events and the recorded command line before journal writes
- Terminal output stored as printed unless you add literal, regex, or known-secret redaction rules
- Optional XChaCha20-Poly1305 encryption at rest, enabled with a key file
- Journal digest verification, and recovery of interrupted runs
- Local viewer that refuses non-loopback hosts and cross-origin API requests
- Signed release archives and npm trusted publishing with provenance
- No npm install scripts

Review every trace before sharing it. Premier cannot reliably identify secrets hidden inside arbitrary unlabelled terminal text. Verification detects a corrupted, truncated, or edited journal; it does not prove who recorded a trace, and it cannot detect someone who rewrites an unencrypted trace's manifest along with its journal. [Security model →](docs/security.md)

## Documentation

Guides live at [premier.dev/docs](https://premier.dev/docs). The reference for this repository's code lives next to it:

| Reference | Covers |
| --- | --- |
| [CLI](docs/cli.md) | Every command, flag, environment variable, and exit code; signals; recovery. |
| [Redaction](docs/redaction.md) | What is removed when, the built-in patterns, export, and what is not caught. |
| [Collector](docs/collector.md) | The local HTTP contract for emitting events from any language. |
| [Events](docs/events.md) | Event kinds, statuses, causality fields, validation, and what counts as an issue. |
| [Adapters](docs/adapters.md) | Per-agent detection, what is extracted, and the limits. |
| [Security](docs/security.md) | Collector, viewer server, local assistant, encryption, and verification. |
| [JavaScript SDK](sdk/js/README.md) | `@premierstudio/trace` helpers and options. |
| [Changelog](CHANGELOG.md) | Behaviour changes by release. |

## Explore

| Guide | What you will do |
| --- | --- |
| [Install Premier](https://premier.dev/docs/install) | Choose global, project-local, or signed archive installation. |
| [Connect an agent](https://premier.dev/docs/adapters) | Capture Claude, Codex, Gemini, Grok, Kimi, OpenCode, and Droid. |
| [Audit local sessions](https://premier.dev/docs/record) | Record and investigate real agent activity on your machine. |
| [Instrument a harness](https://premier.dev/docs/sdk) | Emit typed agent, model, tool, approval, and delegation evidence. |
| [Release security](docs/releasing.md) | Verify signatures, checksums, SBOMs, and provenance. |

## Build from source

```sh
npm install
npm run build
cargo test --workspace
cargo run -p premier-cli --bin premier -- demo
```

Premier is open source under the [Apache License 2.0](LICENSE).
