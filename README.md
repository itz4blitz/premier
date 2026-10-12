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
  <img src="https://img.shields.io/badge/macOS%20%7C%20Linux%20(glibc)-supported-111827?style=flat-square" alt="macOS and glibc Linux" />
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

Native packages are published for macOS (Apple silicon and Intel) and glibc Linux (x64 and arm64). Alpine (musl) and Windows are not: there `premier` says so and exits; use a glibc image, WSL 2, or [build from source](CONTRIBUTING.md#build-order). [Platforms and what the launcher checks →](packages/premier-cli/README.md#supported-platforms)

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

"Native structured capture" means Premier reads the JSON lines the CLI prints in that output mode and adds typed session, turn, model, tool, and approval events next to the raw output. It is heuristic and best effort, and it only sees what the CLI prints. `--adapter auto` also finds the agent behind `env`, `npx` and other package runners, and a simple `sh -c` command. An interactive session, or any run under `--pty`, is recorded as terminal output and exit status only. [How adapters work and where they stop →](docs/adapters.md)

```sh
premier record --adapter auto -- codex exec --json "review this repository"
premier record --adapter claude -- claude -p --output-format stream-json "fix the failing test"
premier record --pty -- your-interactive-agent
```

Unknown harness? Premier can record any process immediately, then accept typed evidence through its JavaScript SDK, CLI emitter (`premier emit`), local HTTP collector, or, where only `bash` and `curl` are available, the [`premier-emit.sh` helper](docs/collector.md#sdkshellpremier-emitsh) shipped in every release archive.

## Evidence, not vibes

- **Reconstruct the run** — terminal output, timing, and exit semantics for any command; model calls, tools, approvals, delegation, messages, and joins when an adapter or your harness reports them.
- **Follow causality** — the actor identity, parent events, spans, correlations, and cross-links that producers report stay attached to the evidence.
- **Find the failure** — filter issues, compare runs, inspect topology, query locally, and export a redacted evidence package for review.
- **Keep control** — traces are local-first, portable, redactable, and optionally encrypted. Each one is hash-chained and sealed so that damage and careless edits show up, and can be signed so that a deliberate rewrite does too.

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

Premier injects a loopback collector URL and per-run bearer token into every recorded process. Your harness emits the facts it knows; Premier validates and timestamps them, and handles storage, chaining and sealing, redaction, recovery, and investigation.

[Read the instrumentation guide →](https://premier.dev/docs/sdk)

## Built for sensitive evidence

- Loopback-only collector with a per-run bearer token, strict field validation, and recorder-assigned timestamps
- Secret-named fields (including header pairs, argument lists, and JSON inside strings), well-known credential shapes, and the run's own collector token redacted from structured events and the recorded command line before journal writes
- Terminal output stored as printed unless you add literal, regex, or known-secret redaction rules
- Optional XChaCha20-Poly1305 encryption at rest, enabled with a key file (`--key-file`)
- An event hash chain and a manifest seal on every trace, an optional Ed25519 signature (`premier keygen`, `record --sign-key`, `premier sign`), and recovery of interrupted runs
- Local viewer that refuses non-loopback hosts and cross-origin API requests
- Signed release archives and npm trusted publishing with provenance
- No npm install scripts

Review every trace before sharing it. Premier cannot reliably identify secrets hidden inside arbitrary unlabelled terminal text.

What `premier verify` tells you depends on the trace. The chain and seal detect a corrupted or truncated journal, an edited, inserted, removed, or reordered event, and an edit to any manifest field. On their own they make a trace self-consistent, nothing more: an unsigned trace can be rewritten, re-chained, and re-sealed by anyone who can write to it, and `premier verify` reports it as `consistent`, not `verified`. Tamper evidence needs a signature, checked with `premier verify --public-key` against a key you trust, and it is only as good as the secrecy of the signing key. No level proves that the recorded events are true or when they happened. [Security model →](docs/security.md#what-verification-proves) · [Trace format →](docs/trace-format.md)

## Documentation

Guides live at [premier.dev/docs](https://premier.dev/docs). The reference for this repository's code lives next to it:

| Reference | Covers |
| --- | --- |
| [Index](docs/README.md) | Where to find what. |
| [CLI](docs/cli.md) | Every command, flag, environment variable, and exit code; signals; recovery; signing; the viewer API. |
| [Redaction](docs/redaction.md) | What is removed when, the built-in patterns, export, and what is not caught. |
| [Collector](docs/collector.md) | The local HTTP contract for emitting events from any language: fields, limits, status codes. |
| [Events](docs/events.md) | Event kinds, statuses, causality fields, validation, and what counts as an issue. |
| [Adapters](docs/adapters.md) | Per-agent detection, what is extracted, and the limits. |
| [Security](docs/security.md) | Collector, viewer server, local assistant, encryption, signing, and what verification proves. |
| [Trace format](docs/trace-format.md) | The on-disk format: frames, the event hash chain, the manifest seal, signatures. |
| [JavaScript SDK](sdk/js/README.md) | `@premierstudio/trace` helpers and options. |
| [Changelog](CHANGELOG.md) | Behaviour changes by release. |
| [Contributing](CONTRIBUTING.md) | Build order, test suites, and the secret-scan rule for fixtures. |

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
npm ci
npm run build
cargo build
cargo run -p premier-cli --bin premier -- demo
```

Build the viewer before the binary: a `cargo build` without the viewer bundle embeds a stub page instead of the viewer. [CONTRIBUTING.md](CONTRIBUTING.md) covers the build order and the test suites.

Premier is open source under the [Apache License 2.0](LICENSE).
