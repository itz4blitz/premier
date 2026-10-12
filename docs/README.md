# Premier reference documentation

These pages describe the code in this repository. Guides and tutorials live
at [premier.dev/docs](https://premier.dev/docs).

| Page | Read it for |
| --- | --- |
| [cli.md](cli.md) | Every `premier` command, flag, environment variable, and exit code. Recording, signals, recovery, signing (`keygen`, `sign`), the global `--key-file` option, querying and paging, what `diff` compares and how it aligns events, verifying an export, and the viewer's HTTP API (including how a trace is addressed). |
| [collector.md](collector.md) | The local HTTP endpoint a recorded process posts events to: fields, validation rules and limits, timestamps, status codes, lifetime. |
| [events.md](events.md) | Event fields and kinds, statuses, causality fields, lifecycle validation, and what counts as an issue. |
| [adapters.md](adapters.md) | Native adapters for agent CLIs: when they run, how lines are classified, parents and links, synthesized subagent events, and the limits. |
| [redaction.md](redaction.md) | What is redacted when, the built-in patterns, literal, regex, and multi-line regex rules, `premier export` (selection, export-time rules, and the export's own digest), and what is not caught. |
| [security.md](security.md) | The security model: collector, viewer server, local assistant, encryption at rest, signing, and what verification proves. |
| [trace-format.md](trace-format.md) | The on-disk trace format: layout, frames, the event hash chain, the manifest seal, signatures, version 1 compatibility, and the threat model. |
| [releasing.md](releasing.md) | How releases are built, signed, and verified: supported platforms and the glibc requirement, what packaging checks, the release workflow, macOS signing, installing from a signed archive, and the update, version-check, and uninstall scripts. |

Elsewhere in the repository:

| Page | Read it for |
| --- | --- |
| [../README.md](../README.md) | Overview and quick start. |
| [../CHANGELOG.md](../CHANGELOG.md) | Behaviour changes by release, with breaking changes marked. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Build order, test suites, and the secret-scan rule for fixtures. |
| [../sdk/js/README.md](../sdk/js/README.md) | The `@premierstudio/trace` JavaScript SDK. |
| [../packages/premier-cli/README.md](../packages/premier-cli/README.md) | The npm launcher: supported platforms, what it checks before running the binary, and signal forwarding. |
| [../crates/premier-cli/tests/fixtures/adapters/README.md](../crates/premier-cli/tests/fixtures/adapters/README.md) | The adapter test fixtures, which are hand-written. |

## Where to start

- Recording a command and reading the trace: [cli.md](cli.md).
- Emitting events from your own harness: [collector.md](collector.md), then
  [events.md](events.md).
- Deciding whether a trace can be shared: [redaction.md](redaction.md).
- Deciding what a verified trace is worth:
  [security.md](security.md#what-verification-proves), then
  [trace-format.md](trace-format.md#threat-model).
