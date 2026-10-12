# Contributing to Premier

This page covers what you need to build the repository, run its tests, and
keep the secret scan green. The reference documentation is indexed in
[docs/README.md](docs/README.md).

## Layout

| Path | What it is |
| --- | --- |
| `crates/premier-trace` | The trace format library: writer, reader, redaction, encryption, chain, seal, signatures. |
| `crates/premier-cli` | The `premier` binary: recorder, collector, adapters, viewer server, and the other commands. |
| `apps/viewer` | The viewer UI (Svelte, built with Vite). Its build output is embedded in the binary. |
| `sdk/js` | `@premierstudio/trace`, the JavaScript SDK. |
| `sdk/shell` | `premier-emit.sh`, the shell helper. |
| `packages/premier-cli` | The npm launcher package. |
| `scripts` | Check, packaging, install, and security scripts. |
| `tests` | Playwright end-to-end tests for the viewer. |

## Requirements

- Node.js 22.12 or later (`engines` in `package.json`; CI uses Node 24).
- The Rust toolchain pinned in `rust-toolchain.toml`; `rustup` installs it on
  the first `cargo` command. CI and the release workflow install the same
  version, so raise all three together.
- For the end-to-end tests, Playwright's Chromium:
  `npx playwright install chromium`.

## Build order

```sh
npm ci
npm run build
cargo build
```

The order matters:

1. `npm ci` installs the workspace dependencies.
2. `npm run build` builds the viewer into `apps/viewer/dist` and then the
   SDK into `sdk/js/dist`.
3. `cargo build` compiles the workspace. The build script of `premier-cli`
   copies `apps/viewer/dist` into `crates/premier-cli/assets/viewer`
   (git-ignored), and that directory is embedded in the binary.

**A `cargo build` without the viewer bundle embeds a stub page.** If
`apps/viewer/dist/index.html` does not exist and nothing has been embedded
before, the build script writes a placeholder page ("Premier viewer assets
missing") and prints a `cargo:warning` saying so. The binary still builds and
every command that does not need the viewer works, but `premier open`,
`premier serve`, and `premier record --open` refuse to start without
`--viewer-dir`. Run `npm run build` and build again; the build script reruns
when `apps/viewer/dist` changes.

A release never ships that page: with `PREMIER_REQUIRE_VIEWER=1` the build
script fails instead of embedding it, and `scripts/package-release.sh` runs
`premier build-info` (hidden; prints `version=`, `target=`, and
`viewer=embedded` or `viewer=placeholder`) and refuses a placeholder. See
[docs/releasing.md](docs/releasing.md#what-packaging-checks-first).

To work on the viewer without rebuilding the binary, serve it from disk:

```sh
npm run build --workspace @premier/viewer
cargo run -p premier-cli --bin premier -- serve --viewer-dir apps/viewer/dist
```

## Tests

`npm run test:all` runs everything CI's main step runs, in order, and stops at
the first failure (`scripts/check.mjs`):

| Step | Command |
| --- | --- |
| Rust formatting | `cargo fmt --all -- --check` |
| Rust lints, warnings as errors | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace` |
| Viewer type check | `npm run check --workspace @premier/viewer` |
| Viewer component tests | `npm run test --workspace @premier/viewer` |
| Viewer coverage | `npm run test:coverage --workspace @premier/viewer` |
| Viewer build | `npm run build --workspace @premier/viewer` |
| SDK build | `npm run build --workspace @premierstudio/trace` |
| SDK tests | `npm run test --workspace @premierstudio/trace` |
| npm launcher tests | `node --test packages/premier-cli/test/*.test.js` |
| npm distribution test | `npm run test:npm-distribution` |
| End-to-end tests | `npx playwright test` |

Each suite on its own:

| Suite | Command | Notes |
| --- | --- | --- |
| Rust | `npm run test:rust` | `cargo test --workspace`. Unit tests live beside the code; integration tests are in `crates/premier-cli/tests` and run the built binary. |
| Viewer components | `npm run test:components` | Vitest. |
| Viewer coverage | `npm run test:coverage` | Vitest with coverage. `types.ts`, `traceLoad.ts`, `api.ts`, `deepLink.ts`, and `causal.ts` in `apps/viewer/src/lib` are held to 100% lines, functions, branches, and statements. |
| Type checks and launcher | `npm run check` | `svelte-check` for the viewer, `tsc --noEmit` for the SDK, then the launcher tests. |
| SDK | `npm run test:sdk` | Builds the SDK first; the tests import `dist`. `test/readme.test.js` runs every example in `sdk/js/README.md`, and the SDK and `premier emit` examples in `README.md`, `docs/collector.md` and `docs/cli.md`, under `premier record`, and requires `premier verify` to report no diagnostics. It needs a built binary (`PREMIER_BIN`, or `target/debug/premier` under `CARGO_TARGET_DIR` or the repository root) and skips those cases without one; CI sets `PREMIER_REQUIRE_CLI=1`, which turns the skip into a failure. |
| npm launcher | `npm run test:launcher` | `node --test` on `packages/premier-cli/test`. |
| npm distribution | `npm run test:npm-distribution` | `scripts/test-npm-distribution.mjs`. |
| End to end | `npm run test:e2e` | Runs `npm run build`, then Playwright. Playwright starts `scripts/e2e-server.mjs`, which builds the viewer and the CLI, records seven traces into `.tmp/e2e-traces` (passing, failing, recorded through the Claude adapter fixture, signed, encrypted, a tampered copy, and the demo; the file's header describes each), and serves them without the encryption key on `127.0.0.1:4318` (`PREMIER_E2E_PORT` changes the port; `PREMIER_E2E_SERVER_TIMEOUT_MS` the ten-minute start budget). Set `CARGO_TARGET_DIR` if cargo does not build into `./target`. |

CI also runs these, which `npm run test:all` does not:

```sh
npm audit --audit-level=low
cargo audit
npm run security:secrets
node scripts/check-release-versions.mjs
shellcheck -x scripts/*.sh scripts/lib/*.sh scripts/tests/*.sh sdk/shell/premier-emit.sh
./scripts/tests/distribution.sh
./scripts/tests/premier-emit.sh
node scripts/tests/preflight-npm-trusted-publishing.test.mjs
node --test scripts/tests/release-config.test.mjs scripts/tests/npm-staging.test.mjs
```

| Command | Covers |
| --- | --- |
| `scripts/check-release-versions.mjs` | One version in `Cargo.toml`, `Cargo.lock`, every `package.json`, and the launcher's platform pins. |
| `scripts/tests/distribution.sh` | Packaging, the installer and its standalone form, update, uninstall, version check, and release verification, with a stand-in `cosign`. |
| `scripts/tests/premier-emit.sh` | The shell helper's `curl` mode against stub collectors. |
| `scripts/tests/release-config.test.mjs` | The workflows' pins and the order of the release build. The workflows themselves cannot be run locally. |
| `scripts/tests/npm-staging.test.mjs` | `stage-npm-packages.sh` and `verify-staged-npm.mjs`. Needs `npm` on `PATH`. |

CI also has a macOS job that runs the Rust suite, the launcher tests, and the
two shell suites, because the recorder's PTY and signal handling differ by
platform.

`npm run security:audit` runs the first three together. `cargo audit` needs
`cargo install cargo-audit`.

Tests must not run a real agent CLI. The adapter tests use the hand-written
fixtures in `crates/premier-cli/tests/fixtures/adapters`; see the
[README](crates/premier-cli/tests/fixtures/adapters/README.md) there.

## The secret scan

`npm run security:secrets` (`scripts/security-scan.mjs`) fails the build when
any file contains a string shaped like a credential. It reads every file git
tracks plus every untracked file that is not ignored, skips binary files, and
matches these shapes:

| Shape | Pattern |
| --- | --- |
| Private key | `-----BEGIN` followed by an optional `RSA`, `EC`, `OPENSSH`, or `DSA` and `PRIVATE KEY-----` |
| GitHub token | `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by 30 or more letters, digits, or `_` |
| Stripe secret key | `sk_` or `rk_`, then `live_` or `test_`, then 20 or more letters or digits |
| AWS access key | `AKIA` followed by 16 uppercase letters or digits |
| npm token | `npm_` followed by 30 or more letters or digits |
| Slack token | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, or `xoxs-` followed by 20 or more letters, digits, or `-` |
| Slack webhook | A `hooks.slack.com/services/...` URL |

The scan cannot tell a real secret from a made-up one, and it has no
allowlist. So:

**Test fixtures, tests, and documentation must not contain a literal
secret-shaped string**, not even an obviously fake one.

Premier's own redaction tests need such strings as input. Build them at run
time instead, so the source never holds the whole shape. The tests in
`crates/premier-trace/src/lib.rs` do it like this, with `body` a generated
string:

```rust
("github-token", format!("ghp_{body}")),
("aws-access-key-id", format!("AKIA{}", "IOSFODNN7EXAMPLE")),
("slack-token", format!("xoxb-1234567890-{body}")),
```

The same goes for fixture files (`.jsonl`, `.json`) and for examples in
Markdown: describe the shape in words, or shorten the example below the
length the pattern needs.

## Documentation

- The pages under `docs/` describe what the code does. When behaviour
  changes, change the page in the same commit, and add an entry to the
  `Unreleased` section of [CHANGELOG.md](CHANGELOG.md). Mark an entry
  **Breaking** when a script or integration could depend on the old
  behaviour.
- `--help` blocks in [docs/cli.md](docs/cli.md) are pasted from the binary.
  Paste them again when a flag or its help text changes.
- State only what you checked in the source or by running the binary.
