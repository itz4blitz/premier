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
| Built-in value patterns | Yes, unless `--no-default-secret-patterns` | Yes, unless `--no-default-secret-patterns` | Only with `--redact-known-secrets` |

"Structured payloads" means the `payload` of every event that is not terminal
output: events received by the collector, events produced by a native adapter,
and the recorder's own `session.start` and `process.exit`.

Only payloads, the recorded command line, and the run name are redacted. The
other event fields (`kind`, `source`, `actor_id`, `span_id`, `parent_span_id`,
`correlation_id`, `status`, `links`) are stored as given. Do not put secrets in
them. Object keys are never rewritten, only values.

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
credentials     bearer
```

This one list is shared by record-time redaction, command-line redaction,
`premier export`, and the assistant prompt.

- Matching is recursive through nested objects and arrays.
- The whole value is replaced, whatever its type, including an object or
  array under a secret key.
- Suffix matching means `db_password`, `GITHUB_TOKEN`, and `next_page_token`
  all match. `input_tokens`, `token_count`, and `tokenizer` do not.

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
| `sk-api-key` | `sk-` followed by at least 20 letters, digits, `_`, or `-`, including a digit | The whole key |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by at least 36 letters or digits | The whole token |
| `github-fine-grained-pat` | `github_pat_` followed by at least 22 letters, digits, or `_` | The whole token |
| `aws-access-key-id` | `AKIA` or `ASIA` followed by 16 uppercase letters or digits | The whole id |
| `slack-token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, or `xoxs-` followed by at least 10 letters, digits, or `-`, including a digit | The whole token |
| `jwt` | Three dot-separated base64url segments, the first two starting `eyJ` followed by at least 8 more characters, the third at least 8 characters | The whole token |

The patterns are deliberately narrow so that token counts, UUIDs, and git
SHAs are left alone.

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
  Write one rule per line of a multi-line secret.
- **256 KiB hold limit.** A line longer than 256 KiB with no line break is
  stored in pieces. The last 16 KiB is kept back at each forced cut, and a cut
  is moved so that it does not fall inside a match. A match of up to 16 KiB
  therefore cannot straddle a cut. A longer single match is split, and only
  part of it may be redacted.
- **Idle flush.** A partial line, such as a prompt with no trailing newline,
  is stored after its stream has been quiet for 1 second, so it is not lost if
  the recorder is killed. The rules still apply to what is flushed, but a
  match that the output pauses in the middle of can be split across the two
  stored pieces and missed. Literal rules are not affected: text that could
  still complete a literal stays held.

For a secret you can name exactly, prefer `--redact-literal`.

## Terminal output

Stored stdout, stderr, and PTY output is raw by default. Nothing is removed
from it unless you ask:

- `--redact-literal` and `--redact-regex` apply to it.
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
   `--api-key=abc`, `API_KEY=abc`, and `Authorization: Bearer abc`.
2. An argument that starts with `-` and is a secret name redacts the next
   argument, unless that one also starts with `-`. This covers `--token abc`.
3. The literal rules, regex rules, and built-in value patterns are then
   applied to each argument.

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
  is redacted as structured data: secret field names, plus the built-in value
  patterns unless `--no-default-secret-patterns` is given. A line that needs
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
  "builtin_patterns": ["pem-private-key", "authorization-header", "bearer-token", "url-credentials", "sk-api-key", "github-token", "github-fine-grained-pat", "aws-access-key-id", "slack-token", "jwt"],
  "builtin_patterns_structured": true,
  "builtin_patterns_terminal": false
}
```

| Field | Meaning |
| --- | --- |
| `structured_defaults` | The built-in secret field names were applied. Always `true`. |
| `custom_fields` | Names given with `--redact-field`. Omitted when there are none. |
| `terminal_literal_count`, `terminal_regex_count` | How many literal and regex rules were given. The rules themselves are not stored. |
| `builtin_patterns` | Names of the built-in value patterns that were active. Omitted when they were off everywhere. |
| `builtin_patterns_structured` | They applied to structured payloads and the command line. |
| `builtin_patterns_terminal` | They applied to stored terminal output. |

The block records which rules ran. It does not record what, or how much, was
removed. In an encrypted trace it is part of the encrypted manifest.

## `premier export`

```sh
premier export run.atrace -o run.evidence.json
premier export run.atrace --redact-known-secrets > run.evidence.json
```

`export` reads a trace and writes one JSON document:

```json
{
  "format": "premier.portable-evidence.v1",
  "redaction": { "...": "see below" },
  "manifest": { "...": "the trace manifest" },
  "events": [ { "...": "each event, with `payload` decoded from `payload_json`" } ]
}
```

It runs its own redaction pass over the manifest and every event:

- Values under secret field names (the built-in list).
- Header-style pairs: an object whose `name`, `key`, or `header` is a secret
  name has its `value` / `values` replaced, and so does the second element of
  a two-string array such as `["Cookie", "..."]`.
- Arrays of strings are treated as argument lists, with the command-line
  rules above.
- A string that holds a JSON document is decoded and redacted field by field.
  It is re-serialized only if something in it changed.
- The built-in value patterns on every other string, unless
  `--no-default-secret-patterns` is given.
- Stored terminal text is exported as recorded unless
  `--redact-known-secrets` is given.

`export` has no literal or regex options, and does not know the literal,
regex, or `--redact-field` rules a trace was recorded with. Whatever those
rules removed at record time is already `[REDACTED]` in the trace.

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
`--allow-unverified` is given; see [cli.md](cli.md#--allow-unverified). The
exported document is a copy. It carries the manifest's digest but cannot
itself be verified with `premier verify`.

### Other outputs

- `premier query` and `premier replay` print events exactly as stored.
- The viewer's export button builds a different document in the browser
  (`format: "premier.viewer-export.v1"`) with its own best-effort masking. It
  is not the same rule set as `premier export`.
- The local assistant prompt is redacted with the `premier export` rules,
  with the built-in value patterns applied to every string including terminal
  text. See [security.md](security.md#the-local-assistant).

## What this does not catch

- **Terminal output, by default.** Stored stdout, stderr, and PTY output is
  raw unless you pass a literal rule, a regex rule, or
  `--redact-known-secrets`. A secret an agent prints is in the trace.
- **Secrets with no recognisable name or shape.** A password in prose, a
  random hex or base64 token, a database connection string without
  `user:password@`, an internal key format. The built-in patterns cover the
  ten shapes listed above and nothing else. Examples that are not matched:
  keys that start `sk_` rather than `sk-`, an AWS secret access key value on
  its own, a bearer token outside an `Authorization` header that is shorter
  than 20 characters or has no digit.
- **Unnamed command-line secrets.** `mysql -phunter2`, `curl -u user:hunter2`,
  and a secret inside a `sh -c '...'` script are not recognised by name. Only
  a literal rule, a regex rule, or a built-in pattern can catch them.
- **Regex matches split by the limits above**: across a line break, across a
  forced cut in a line longer than 256 KiB when the match exceeds 16 KiB, or
  across a 1-second pause in a partial line.
- **Event fields outside the payload**, and object keys.
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
