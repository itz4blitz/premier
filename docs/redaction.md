# Redaction

Premier redacts in two places:

- **At record time**, before an event is written to the journal. What is
  removed here never reaches disk and cannot be recovered.
- **At export time**, when `premier export` builds a portable JSON copy. The
  trace itself is not changed.

Every replacement is the literal string `[REDACTED]`. The marker is fixed.

Redaction is pattern-based. It reduces how much sensitive material a trace
holds; it does not make a trace safe to publish. Read
[What this does not catch](#what-this-does-not-catch) before sharing one.

## What is redacted when

| Rule | Structured payloads | Recorded command line and run name | Stored terminal output |
| --- | --- | --- | --- |
| Secret field names (built-in list plus `--redact-field`) | Yes | Yes, for flag, assignment, and header names | No, except JSON lines of an adapter's stdout |
| `--redact-literal` | Yes | Yes | Yes |
| `--redact-regex` | Yes | Yes | Yes, line-scoped |
| `--redact-regex-multiline` | Yes | Yes | Yes, over a 16 KiB sliding window |
| Built-in value patterns | Yes, unless `--no-default-secret-patterns` | Yes, unless `--no-default-secret-patterns` | Only with `--redact-known-secrets` |
| The collector token of the run (implicit) | Yes | Yes | Yes |

"Structured payloads" means the `payload` of every event that is not terminal
output: events received by the collector, events produced by a native adapter,
and the recorder's own `session.start` and `process.exit`.

The event fields outside the payload (`kind`, `source`, `actor_id`,
`actor_type`, `span_id`, `parent_span_id`, `correlation_id`, `status`) are
covered by `--redact-literal`, `--redact-regex`, and
`--redact-regex-multiline` only. Secret field names and the built-in value
patterns do not apply to them, and `parent_event_id` and `links` are stored as
given. A rule that matches part of an identifier rewrites it the same way
everywhere, so events that shared an id still share it. Object keys are never
rewritten, only values.

The output you see in your terminal is never redacted. Redaction applies to
the stored copy only.

## Secret field names

A payload value is replaced when its key is a secret name. Keys are compared
after dropping everything except letters and digits and lowercasing, so
`apiKey`, `api_key`, and `X-API-Key` are the same name. A key matches when it
**equals or ends with** one of:

```text
password        passwd          secret           clientsecret
apikey          accesstoken     refreshtoken     token
authorization   proxyauthorization               cookie
setcookie       secretaccesskey privatekey       credential
credentials     bearer          auth             jwt
passphrase      secretkey       signingkey       privatekeypem
accesskey       accesskeyid
```

This one list is shared by record-time redaction, command-line redaction,
`premier export`, the assistant prompt, and the viewer's export button. The
Rust list and the viewer's copy are both tested against
`crates/premier-trace/tests/fixtures/redaction-cases.json`.

- Matching is recursive through nested objects and arrays.
- The whole value is replaced, whatever its type, including an object or
  array under a secret key.
- Suffix matching means `db_password`, `GITHUB_TOKEN`, `session_token`,
  `x-auth-token`, `webhook_secret`, `basic_auth`, and `next_page_token` all
  match. A name that only starts with or contains a listed word does not:
  `input_tokens`, `max_tokens`, `token_count`, `tokens`, `tokenizer`,
  `author`, `authority`, `authorized_by`, `auth_method`, `public_key`.

### Structured shapes

Besides plain object keys, the same names are recognised in these shapes.
The recorder applies them before the journal write; `premier export` applies
them again, for traces recorded before this was the case.

- **Header-style pairs.** An object whose `name`, `key`, or `header` is a
  secret name has its `value` / `values` replaced
  (`{"name": "Authorization", "value": "..."}`), and so does the second
  element of a two-string array such as `["Cookie", "..."]`.
- **Argument lists.** An array of strings is read as a command line, with the
  rules in [The recorded command line](#the-recorded-command-line):
  `["deploy", "--api-key", "..."]`, `["API_KEY=..."]`,
  `["Authorization: Bearer ..."]`.
- **JSON inside a string.** A string that holds a JSON document is decoded and
  redacted field by field. So is each line of a multi-line string that is a
  JSON object on its own, which makes the result independent of how output
  was split into events. A document or line is re-serialized only if
  something in it changed, so its key order and spacing may then differ;
  untouched text keeps its exact bytes.

Stored terminal text is the exception: at record time it is not read as
structured data unless a native adapter is active (see
[Adapter runs](#adapter-runs)).

`--redact-field <name>` adds a name for one recording, with the same
normalization and suffix rule. It is repeatable. A name with no letter or
digit is rejected, because it would match every field.

```sh
premier record --redact-field session_ref --redact-field tenantPin -- ./agent
```

## Built-in value patterns

These match on the shape of a value rather than its key. They are on by
default for structured payloads and the command line, and off for terminal
output.

| Name | Matches | Replaced |
| --- | --- | --- |
| `pem-private-key` | `-----BEGIN ... PRIVATE KEY-----` through the matching `END` line. An unterminated block is redacted to the end of the text. | The whole block |
| `authorization-header` | `Authorization` or `Proxy-Authorization`, then `:` or `=`, then `Bearer` or `Basic` and at least 8 credential characters | The credential |
| `bearer-token` | `Bearer` followed by at least 20 credential characters that include a digit | The credential |
| `url-credentials` | `scheme://user:password@` | The password |
| `url-query-credentials` | A query parameter directly after `?` or `&` named `token`, `access_token`, `refresh_token`, `id_token`, `auth_token`, `api_key` / `apikey` / `api-key`, `client_secret`, `secret`, `password`, `passwd`, `signature`, `sig`, `X-Amz-Signature`, `X-Amz-Security-Token`, or `X-Goog-Signature` (any case), followed by `=` and a value | The value, up to the next `&`, `#`, quote, or whitespace |
| `sk-api-key` | `sk-` followed by at least 20 letters, digits, `_`, or `-`, including a digit | The whole key |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by at least 36 letters or digits | The whole token |
| `github-fine-grained-pat` | `github_pat_` followed by at least 22 letters, digits, or `_` | The whole token |
| `aws-access-key-id` | `AKIA` or `ASIA` followed by 16 uppercase letters or digits | The whole id |
| `slack-token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, or `xoxs-` followed by at least 10 letters, digits, or `-`, including a digit | The whole token |
| `jwt` | Three dot-separated base64url segments, the first two starting `eyJ` followed by at least 8 more characters, the third at least 8 characters | The whole token |

The patterns are deliberately narrow so that token counts, UUIDs, and git
SHAs are left alone. `url-query-credentials` needs the parameter name to
start right after `?` or `&`, so `?max_tokens=4096`, `?q=token`, and
`token=abc` in prose are not matched.

- `--no-default-secret-patterns` switches them off for structured payloads
  and the command line.
- `--redact-known-secrets` also applies them to stored terminal output.

The two flags are independent, and both exist on `record` and `export`.

## `--redact-literal`

Replaces every occurrence of an exact string in stored terminal output, in
every string value of every event payload, in the recorded command line, and
in the run name. Repeatable. An empty literal is ignored.

```sh
premier record --redact-literal "$DEPLOY_PASSWORD" -- ./deploy.sh
```

Literal rules are safe against chunking: output is held back just long enough
that a literal split across two reads is still matched whole. This is the
most reliable rule for a secret whose value you know.

The literal is itself an argument to `premier`, so it is visible to other
local users in the process list while the recorder runs. It is not stored in
the trace; the manifest records only how many literal rules were active.

## `--redact-regex`

Replaces every match of a regular expression in the same places as a literal
rule. Repeatable. The syntax is that of the Rust `regex` crate, which has no
look-around and no backreferences. An invalid pattern stops `record` before
the command starts.

```sh
premier record --redact-regex 'session-[0-9a-f]{32}' -- ./agent
```

In terminal output, regex rules have limits:

- **Line-scoped.** Output is held until the end of a line and then matched.
  A match is guaranteed only within one line, never across a line break.
  Write one rule per line of a multi-line secret, or use
  [`--redact-regex-multiline`](#--redact-regex-multiline).
- **256 KiB hold limit.** A line longer than 256 KiB with no line break is
  stored in pieces. The last 16 KiB is kept back at each forced cut, and a cut
  is moved so that it does not fall inside a match. A match of up to 16 KiB
  therefore cannot straddle a cut. A longer single match is split, and only
  part of it may be redacted.
- **Idle flush.** A partial line, such as a prompt with no trailing newline,
  is stored after its stream has been quiet for 1 second. See
  [Idle flush](#idle-flush).

For a secret you can name exactly, prefer `--redact-literal`.

## `--redact-regex-multiline`

A regex rule that may match across line breaks, for a multi-line token or key
block. Repeatable. It applies to the same places as `--redact-regex` and uses
the same syntax, and an invalid pattern stops `record` before the command
starts. The option does not change how the pattern is compiled: `.` crosses a
line break only if the pattern says so with `(?s)`, while `\n`, `\s`, and
`[\s\S]` always can.

```text
$ premier record --redact-regex-multiline 'BEGIN[\s\S]*?END' -- sh -c 'printf "a BEGIN one\ntwo END b\n"'
a BEGIN one
two END b
```

Stored stdout for that run: `a [REDACTED] b`.

How it is matched:

- **Terminal output: a 16 KiB sliding window.** While a multi-line rule is
  active, the most recent 16 KiB (16,384 bytes) of each stream stay held, and
  text is released only up to a point that no complete match extends across.
  A match of up to 16 KiB is therefore redacted however the output was split
  into lines and writes.
- **A longer match may be stored in part.** A single match longer than the
  window can be cut, and the part already released is stored as printed.
- **Structured payloads and the command line.** The rule is matched over each
  whole string value.
- **Idle flush still applies.** Output held for the window is stored once the
  stream has been quiet for the idle period, so a match the output pauses
  inside can be split. See [Idle flush](#idle-flush).
- While line-scoped rules (`--redact-regex`, `--redact-known-secrets`) are
  also active, text is still released only at line ends.

The manifest counts these rules in
`redaction.terminal_multiline_regex_count`.

## Idle flush

Output that a rule is holding back (a partial line, or the multi-line window)
is stored once its stream has been quiet for the idle period, so that an
unterminated line such as an interactive prompt is not lost if the recorder is
killed before the line ends.

- The idle period is 1 second. `PREMIER_REDACTION_IDLE_FLUSH_MS` sets it, in
  milliseconds, for a recording. It is read once when the recorder first
  needs it; a value that is not a non-negative integer is ignored.
- The rules still apply to what is flushed. But a regex match (line-scoped or
  multi-line) that the output pauses in the middle of for longer than the
  idle period can be split across the two stored pieces and missed. A longer
  period makes that less likely; a shorter one stores prompts sooner.
- Literal rules are not affected: text that could still complete a literal
  stays held. An open PEM private key block under `--redact-known-secrets`
  stays held too.
- A partial JSON line of an adapter run's stdout is never flushed early; it
  is held until the line is complete.

```sh
PREMIER_REDACTION_IDLE_FLUSH_MS=5000 premier record --redact-regex 'token=\S+' -- ./slow-printer
```

## The collector token

`premier record` gives the recorded command a per-run token in
`PREMIER_COLLECTOR_TOKEN` (see [collector.md](collector.md)). A command that
prints its environment would put it in the trace, so the recorder always
treats that one value as a literal rule: it is replaced in stored terminal
output, payloads, event fields, the command line, and the run name. The token
only works while the recording runs, on loopback.

The manifest names the rule without its value, as
`redaction.implicit_rules: ["collector-token"]`. It is not counted in
`terminal_literal_count` and does not add the `terminal-redaction`
capability, because it is not a rule you configured.

## Terminal output

Stored stdout, stderr, and PTY output is raw by default. Apart from the
collector token, nothing is removed from it unless you ask:

- `--redact-literal`, `--redact-regex`, and `--redact-regex-multiline` apply
  to it.
- `--redact-known-secrets` applies the built-in value patterns to it. A PEM
  private key block is held until its end marker arrives so that it is
  redacted as one block.

When any of these is active the manifest gains the `terminal-redaction`
capability.

Secret field names do not apply to free terminal text. A line such as
`password=hunter2` printed by the recorded command is stored as printed
unless a literal or regex rule matches it.

## The recorded command line

The command line is stored in the manifest (`command`) and in the
`session.start` event. Both copies are redacted the same way:

1. An argument of the form `NAME=VALUE` or `NAME: VALUE`, where `NAME` has no
   whitespace and is a secret name, becomes `NAME=[REDACTED]`. This covers
   `--api-key=abc`, `--password=abc`, `API_KEY=abc`,
   `Authorization: Bearer abc`, and a header given to `-H` / `--header` such
   as `X-Api-Key: abc`.
2. An argument that starts with `-` and is a secret name redacts the next
   argument, unless that one also starts with `-`. This covers `--token abc`,
   `--password abc`, `--passwd abc`, `--secret abc`, and `--api-key abc`.
3. After a word whose file name is `curl`, the password of `-u user:pass`,
   `-uuser:pass`, `--user user:pass`, `--user=user:pass`, and the same forms
   of `-U` / `--proxy-user` is replaced; the user name is kept.
4. After a word whose file name is `mysql`, `mysqldump`, `mysqladmin`,
   `mysqlimport`, `mysqlshow`, `mysqlcheck`, `mariadb`, or `mariadb-dump`, an
   argument `-p<value>` becomes `-p[REDACTED]`. A separate `-p` followed by
   another argument is left alone: for these tools that argument is the
   database name, and the password is prompted for.
5. The literal rules, regex rules, and built-in value patterns are then
   applied to each argument. `url-query-credentials` covers
   `https://host/path?token=...`.

Rules 3 and 4 are tied to a tool name on purpose. A password glued to a
short flag cannot be recognised in general: `-p5432` is a port for `psql`,
`-p2222` a port for `ssh`, `-pv` two flags for `mkdir`, and `-u` means
"unique", "upstream", or a numeric user id elsewhere. Nothing in the argument
itself says which, so the form is only redacted where `-p<value>` is known to
mean a password. `psql` is not such a tool; its `-p` is the port.

```text
$ premier record --redact-literal hunter2 -- sh -c 'echo "pw is hunter2 ok"' --api-key=abc123 --token zzz API_KEY=qq
pw is hunter2 ok
```

Recorded `command`:

```json
["sh", "-c", "echo \"pw is [REDACTED] ok\"", "--api-key=[REDACTED]", "--token", "[REDACTED]", "API_KEY=[REDACTED]"]
```

The stored stdout for that run is `pw is [REDACTED] ok`; the terminal showed
the real text.

## Adapter runs

When a native adapter is active (see [adapters.md](adapters.md)) the same
provider output is stored twice, and both copies are redacted:

- **The normalized events.** The adapter keeps the provider's JSON object
  under `payload.native`. It is a structured payload, so secret field names,
  literal and regex rules, and the built-in value patterns apply to it.
- **The raw stdout copy** (`process.stdout`). Each line that is a JSON object
  is redacted as structured data: secret field names in every
  [structured shape](#structured-shapes), plus the built-in value patterns
  unless `--no-default-secret-patterns` is given. A line that needs
  no redaction keeps its exact bytes. A line that is changed is re-serialized,
  so its key order and spacing may differ from what the provider printed.
  Literal and regex rules apply as for any terminal output.

stderr of an adapter run is ordinary terminal output.

## Redaction provenance in the manifest

Every manifest written by the recorder has a `redaction` block describing
which rules were active:

```json
"redaction": {
  "structured_defaults": true,
  "custom_fields": ["session_ref"],
  "terminal_literal_count": 1,
  "terminal_regex_count": 0,
  "terminal_multiline_regex_count": 1,
  "implicit_rules": ["collector-token"],
  "builtin_patterns": ["pem-private-key", "authorization-header", "bearer-token", "url-credentials", "url-query-credentials", "sk-api-key", "github-token", "github-fine-grained-pat", "aws-access-key-id", "slack-token", "jwt"],
  "builtin_patterns_structured": true,
  "builtin_patterns_terminal": false
}
```

| Field | Meaning |
| --- | --- |
| `structured_defaults` | The built-in secret field names were applied. Always `true`. |
| `custom_fields` | Names given with `--redact-field`. Omitted when there are none. |
| `terminal_literal_count`, `terminal_regex_count` | How many `--redact-literal` and `--redact-regex` rules were given. The rules themselves are not stored. |
| `terminal_multiline_regex_count` | How many `--redact-regex-multiline` rules were given. Omitted when there are none. |
| `implicit_rules` | Names of literal rules the recorder added by itself; today only `collector-token`. The values are not stored, and the rules are not counted in `terminal_literal_count`. Omitted when there are none, as in traces written through the library without a collector. |
| `builtin_patterns` | Names of the built-in value patterns that were active. Omitted when they were off everywhere. |
| `builtin_patterns_structured` | They applied to structured payloads and the command line. |
| `builtin_patterns_terminal` | They applied to stored terminal output. |

The block records which rules ran. It does not record what, or how much, was
removed. In an encrypted trace it is part of the encrypted manifest. In a
format version 2 trace it is covered by the manifest seal, so editing it
afterwards makes `premier verify` fail; see
[trace-format.md](trace-format.md#seal).

## `premier export`

```sh
premier export run.atrace -o run.evidence.json
premier export run.atrace --redact-known-secrets > run.evidence.json
```

`export` reads a trace and writes one JSON document:

```json
{
  "format": "premier.portable-evidence.v1",
  "exporter": { "name": "premier", "version": "0.1.0" },
  "source": { "...": "see below" },
  "manifest": { "...": "the trace manifest" },
  "events": [ { "...": "each event, with `payload` decoded from `payload_json`" } ],
  "selection": { "...": "which events were exported; see below" },
  "redaction": { "...": "see below" },
  "integrity": { "...": "the export's own digest; see below" }
}
```

Three things to know before sharing the file:

- **It is a derived copy, not the sealed original.** The events are redacted
  and may be a selection, so the trace's seal and signature do not cover the
  file. It carries a digest of its own instead, which
  `premier verify <file>` recomputes; see [The `integrity`
  block](#the-integrity-block).
- **It is plaintext, also when the trace is encrypted.** `export` decrypts
  the trace and writes ordinary JSON. For an encrypted trace it warns on
  stderr: `warning: <trace> is encrypted, but this export is plaintext;
  protect or delete it accordingly`.
- **With `--output`, the file is private.** On Unix it is created with mode
  `0600` whatever the umask, for every export. Output written to stdout gets
  whatever permissions your redirection gives it.

It runs its own redaction pass over the manifest and every event, with the
same code the recorder uses. For a trace from a current recorder this mostly
finds markers that are already there; for an older trace it removes what that
recorder did not:

- Values under secret field names (the built-in list), in every
  [structured shape](#structured-shapes): plain keys, header-style pairs,
  argument lists, and JSON inside strings.
- The built-in value patterns on every other string, unless
  `--no-default-secret-patterns` is given.
- Stored terminal text: a line that is a JSON object is redacted by field
  name, whether it was stored as one event or as part of a larger chunk. The
  built-in value patterns are applied to terminal text only with
  `--redact-known-secrets`.

`export` has two rules of its own for what a review turned up:

- `--redact-field <name>` replaces the value of that field wherever it
  appears in the exported manifest and events. Names are compared ignoring
  case and punctuation, as an exact name (not as a suffix).
- `--redact-literal <text>` replaces that exact text in every string of the
  exported manifest and events, captured output included.

Both may be repeated. `export` has no regex option. It does not know the
literal, regex, multi-line regex, or `--redact-field` rules a trace was
recorded with, nor the collector token: whatever those rules removed at
record time is already `[REDACTED]` in the trace.

### Selecting events

`--kind` and `--actor` (repeatable, exact, ignoring case),
`--after-sequence`, and `--before-sequence` limit the export to matching
events; an event must satisfy every option given. The `selection` block
records what was applied:

```json
"selection": {
  "applied": true,
  "filters": { "kind": ["tool.result"], "after_sequence": 10 },
  "source_events": 240,
  "exported_events": 12
}
```

Without selection options `applied` is `false`, `filters` is `{}`, and the two
counts are equal. Selected events keep their `parent_event_id` and `links`,
which may name events that were left out.

### The `redaction` report

```json
"redaction": {
  "applied": false,
  "replacement": "[REDACTED]",
  "policy": "recursive common secret field names, including JSON strings and header or argument lists, plus built-in secret value patterns",
  "rules": {
    "secret_field_names": ["password", "passwd", "secret", "..."],
    "builtin_patterns": ["pem-private-key", "authorization-header", "..."],
    "builtin_patterns_structured": true,
    "builtin_patterns_terminal": false
  },
  "redacted": {
    "total": 0,
    "field_names": 0,
    "value_patterns": {},
    "already_redacted": 9
  }
}
```

| Field | Meaning |
| --- | --- |
| `redaction.applied` | `true` when this export replaced at least one value. `false` means the rules ran and found nothing left to replace. It does not mean redaction was skipped, and it says nothing about what was redacted at record time. |
| `redaction.replacement` | The marker, `[REDACTED]`. |
| `redaction.rules.secret_field_names` | The secret field names that were applied. |
| `redaction.rules.builtin_patterns` | The built-in value patterns that were active for this export. Empty when they were off. |
| `redaction.rules.builtin_patterns_structured` / `_terminal` | Where those patterns were applied. |
| `redaction.redacted.total` | Values replaced by this export: `field_names` plus every `value_patterns` count. |
| `redaction.redacted.field_names` | Values replaced because of a secret name (key, flag, or header). |
| `redaction.redacted.value_patterns` | Count per built-in pattern name. |
| `redaction.redacted.already_redacted` | `[REDACTED]` markers that were already in the trace. Not included in `total`. |

With `--output`, `export` also prints a one-line summary:

```text
exported redacted evidence to export.json (0 value(s) redacted by this export, 9 already redacted when recorded)
```

`export` refuses a finalized trace that fails verification unless
`--allow-unverified` is given; see [cli.md](cli.md#--allow-unverified).

The report gains two entries when the export was given rules of its own:
`rules.custom_fields` (the `--redact-field` names) and `rules.literal_count`
(how many `--redact-literal` texts; the texts are not written), and a
`custom` block, `{"fields": <n>, "literals": <n>}`, counting what they
replaced. `applied` is `true` when either these or the built-in rules removed
something.

### The `source` block

`source` states which trace the export was derived from, by copying the
tamper-evidence values out of its manifest:

```json
"source": {
  "trace_id": "01a130a6-51e5-7a93-bfc3-9903396ca127",
  "format_version": 2,
  "protection": "signed",
  "journal_sha256": "80d14ef2673d327854d597d4f67faabd432544538c4643b58e623e675180135b",
  "chain_head": "3499074128a0ea815ffebad0b6269469f79d3b1ab1a816589aa7a42a31229991",
  "event_count": 3,
  "seal": "9ddcee41a50484e619a48fe76931e351c931e11f99c88b8d793eb2099dfe8385",
  "signature": "ab43ea1eefde62d3...",
  "public_key": "e5f5b4620cbcf6becd1534a20bf456582509028c5763fa12360247d1071ea926",
  "public_key_fingerprint": "sha256:6f993d9bfe2cbf04ba8e18f506675153",
  "finalized": true,
  "verification": "verified",
  "note": "Copied from the source manifest. This export is a derived, redacted copy: the source's seal and signature do not cover it. `integrity` below is the export's own digest; verify the original trace with `premier verify`."
}
```

| Field | Meaning |
| --- | --- |
| `trace_id`, `format_version` | Of the source trace. |
| `protection` | `digest_only` (version 1, no seal), `sealed` (version 2, unsigned), or `signed`. |
| `journal_sha256` | The journal digest. Absent for a trace that is not finalized. |
| `chain_head`, `event_count`, `seal` | The seal's chain head, event count, and digest. Absent without a seal. |
| `signature`, `public_key`, `public_key_fingerprint` | The signature (128 hexadecimal characters, shortened above), and the signer's key and fingerprint. Absent for an unsigned trace. |
| `finalized` | `false` when the trace was still being recorded or had been interrupted: the events may be incomplete. |
| `verification` | What `export` established about the source: `verified`, `failed` (exported with `--allow-unverified`), or `not_finalized`. |
| `note` | The fixed sentence above. |

The values are copied, not checked against a key you trust: `protection:
"signed"` means the source manifest carries a signature. The export is a
copy, and redaction changes the events, so the export is not covered by the
seal or the signature. To rely on the evidence, verify the original trace.

### The `integrity` block

```json
"integrity": {
  "algorithm": "sha256",
  "event_count": 12,
  "events_sha256": "5c1e...",
  "digest": "52b3c723bc5c1e0a3f93775d64e9ab3c158795e83170f892218a3de2908da9ca",
  "note": "Recomputed by `premier verify <export.json>`. ..."
}
```

| Field | Covers |
| --- | --- |
| `events_sha256` | SHA-256 over the exported events in order, each as compact JSON with its keys sorted, followed by a line feed. |
| `digest` | SHA-256 over the compact, sorted-key JSON of one object holding `format`, `exporter`, `source`, `manifest`, `selection`, `redaction`, `event_count`, and `events_sha256`. This is the export's identity; `export --output` prints it. |

`premier verify <file>` parses the file, recomputes both, and compares them
and the event count with the block. It also checks that a signature copied
into `source` is a valid signature over the copied seal digest by the copied
public key, and `--public-key` requires that key to be yours. See
[cli.md](cli.md#verifying-an-export).

What this gives, and what it does not:

- A changed, added, removed, or reordered event, or a changed block, is
  detected, as long as the digest was not recomputed.
- **The digest is in the file it covers.** Whoever can rewrite the file can
  recompute it. Record the digest somewhere else (a ticket, a signed message)
  if a deliberate rewrite has to be noticed.
- The source signature shows that the key's holder signed a trace with that
  seal digest. It does not show that these events came from that trace.
- The same trace exported with the same options gives the same file and the
  same digest. The export holds no timestamp of its own.
- An export written before this block existed has none, and fails
  `premier verify`.

### Other outputs

- `premier query` and `premier replay` print events exactly as stored.
  `query` and `diff` also read an export file; what they then show is the
  export's redacted copy.
- The viewer's export button builds a different document in the browser
  (`format: "premier.viewer-export.v1"`). It uses the same secret field names
  and masks every value shape in the built-in pattern table (both are tested
  against the shared fixture named above), plus looser heuristics of its own
  for `key=value` text and cookie headers. It decodes a string that is one
  JSON document, but does not read header-style pairs, argument lists, or
  JSON lines as structure; those are covered only as far as the text
  heuristics match. It leaves a number or boolean under a `token`-suffixed
  key alone, where the recorder replaces it. It is still best-effort masking
  and not a substitute for `premier export`.
- The local assistant prompt is redacted with the `premier export` rules,
  with the built-in value patterns applied to every string including terminal
  text. See [security.md](security.md#the-local-assistant).

## What this does not catch

- **Terminal output, by default.** Stored stdout, stderr, and PTY output is
  raw (apart from the collector token) unless you pass a literal rule, a
  regex rule, or `--redact-known-secrets`. A secret an agent prints is in the
  trace.
- **Secrets with no recognisable name or shape.** A password in prose, a
  random hex or base64 token, a database connection string without
  `user:password@`, an internal key format. The built-in patterns cover the
  shapes listed above and nothing else. Examples that are not matched:
  keys that start `sk_` rather than `sk-`, an AWS secret access key value on
  its own, a bearer token outside an `Authorization` header that is shorter
  than 20 characters or has no digit.
- **Unnamed command-line secrets.** A password glued to a short flag of a
  tool other than `curl` and the MySQL clients listed above, a positional
  password, and anything inside a `sh -c '...'` script (the script is one
  argument and is not parsed, so `sh -c 'mysql -phunter2'` and
  `sh -c 'curl -u u:pw ...'` are stored as written). Only a literal rule, a
  regex rule, or a built-in pattern can catch them.
- **Query parameters with other names.** `?key=...`, `?code=...`, or a
  vendor-specific name is not in the `url-query-credentials` list.
- **Regex matches split by the limits above**: for `--redact-regex`, across a
  line break, or across a forced cut in a line longer than 256 KiB when the
  match exceeds 16 KiB; for `--redact-regex-multiline`, a match longer than
  16 KiB; for both, across a pause in the output longer than the idle period
  (1 second unless `PREMIER_REDACTION_IDLE_FLUSH_MS` says otherwise).
- **Secret names and value patterns in event fields outside the payload.**
  Only literal and regex rules reach those fields. `parent_event_id`,
  `links`, and object keys are never rewritten.
- **Non-secret fields with secret-sounding names.** Suffix matching replaces
  them too, for example a boolean `is_secret` or a pagination `next_token`.
  This loses evidence rather than leaking it, but it is not reversible.
- **What you see live.** The terminal mirror is never redacted, and neither is
  anything the recorded command writes elsewhere (files, network, its own
  logs).
- **Traces recorded earlier.** Record-time rules apply only to the recording
  they were given to. `premier export` can remove more from a copy; it cannot
  change the trace.
- **Personal data.** Nothing here looks for names, emails, addresses, or file
  contents.

Encryption protects a trace at rest but does not redact it: anyone with the
key reads everything that was stored. See
[security.md](security.md#encryption-at-rest).
