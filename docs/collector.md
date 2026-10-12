# The local collector

`premier record` runs a small HTTP server for the duration of a recording.
Any process started under the recorder can POST typed events to it, in any
language. The JavaScript SDK, `premier emit`, and the shell helper are thin
clients of this one endpoint.

The event vocabulary is described in [events.md](events.md).

## Environment

`premier record` adds three variables to the recorded command's environment.
Child processes inherit them in the usual way.

| Variable | Value |
| --- | --- |
| `PREMIER_COLLECTOR_URL` | `http://127.0.0.1:<port>/v1/events`. The port is chosen by the OS for each recording. |
| `PREMIER_COLLECTOR_TOKEN` | A bearer token generated for this recording. |
| `PREMIER_TRACE_ID` | The id of the trace being recorded. |

If `PREMIER_COLLECTOR_URL` and `PREMIER_COLLECTOR_TOKEN` are not set, the
process is not being recorded and there is nothing to send to.

## Endpoint

```text
POST /v1/events
Authorization: Bearer <PREMIER_COLLECTOR_TOKEN>
Content-Type: application/json

<one JSON event>
```

One request carries one event. There is no batch form.

```sh
curl -sS -X POST "$PREMIER_COLLECTOR_URL" \
  -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "kind": "tool.execution",
    "actor_id": "coder",
    "actor_type": "agent",
    "status": "ok",
    "span_id": "apply-patch",
    "parent_span_id": "implementation",
    "duration_ms": 176,
    "payload": {"tool": "apply_patch", "files_changed": 1}
  }'
```

`GET /health` on the same port answers `{"service":"premier-collector","status":"ok"}`
without authentication.

## Authentication

The `Authorization` header must be `Bearer ` followed by the exact token. The
comparison is constant-time. A missing or wrong token is rejected with `401`
before the body is read.

The collector listens on `127.0.0.1` only, and the token is the only
credential. Any local process that learns the port and token can append events
to the trace while it is being recorded. See [security.md](security.md#the-collector).

## Request body

A JSON object. Unknown fields are ignored.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `kind` | string | yes | | A name; see [Field rules](#field-rules). Some kinds are reserved; see below. |
| `source` | string | no | `"sdk"` | A name labelling the producer. The default applies only when the field is absent; an empty string is rejected. Some sources are reserved. |
| `actor_id` | string | no | `""` | Who did it. An empty actor is unattributed: `premier query` prints it as `-`, and the viewer groups it under `root`. |
| `actor_type` | string | no | `""` | A name: `agent`, `subagent`, `human`, `process`, or `system`. |
| `status` | string | no | `""` | See [events.md](events.md#statuses). |
| `span_id` | string | no | `""` | |
| `parent_span_id` | string | no | `""` | |
| `parent_event_id` | string | no | `""` | The `event_id` of an earlier event. |
| `correlation_id` | string | no | `""` | |
| `links` | array of strings | no | `[]` | Event ids or span ids. |
| `duration_ms` | unsigned integer | no | `0` | A fractional or negative number is rejected with `400`. |
| `payload` | any JSON value | no | `null` | Should be an object, and must be one (or absent) when `timestamp` is sent. |
| `timestamp` | string or null | no | | The producer's own time, RFC 3339. It does not set the event's timestamp; see [Timestamps](#timestamps). |

The recorder assigns `event_id`, `trace_id`, `sequence`, `timestamp`, and
`prev_hash`. A client cannot set them.

### Field rules

Every field is validated before the event is stored. A violation is rejected
with `400` and a message naming the field.

| Fields | Rule | Limit |
| --- | --- | --- |
| `kind`, `source`, `actor_type` | Names. Only ASCII letters, digits, `.`, `_`, `:`, and `-`. No spaces and no other Unicode, so nothing can be made to look like a recorder-owned name. `kind` and `source` must not be empty; `actor_type` may be. | 128 bytes |
| `actor_id`, `span_id`, `parent_span_id`, `correlation_id`, `status`, `parent_event_id`, and each entry of `links` | Free text. Any Unicode, but no control characters (newline, tab, escape, NUL, ...). May be empty. | 256 bytes each |
| `timestamp` | Empty or all whitespace is ignored. Otherwise it must parse as an RFC 3339 date-time. | 64 bytes |
| whole body | | 2 MiB; see [Size limit](#size-limit) |

Request bodies and the collector's answers:

```text
{"kind":""}                              400 {"error":"event kind cannot be empty"}
{"kind":"agent message"}                 400 {"error":"event kind may only contain ASCII letters, digits, and `.`, `_`, `:`, `-`"}
{"kind":"a.b","source":""}               400 {"error":"event source cannot be empty"}
{"kind":"a.b","actor_id":"a\u001bb"}     400 {"error":"event actor_id contains a control character"}
{"kind":"a.b","status":"ok\nx"}          400 {"error":"event status contains a control character"}
{"kind":"a.b","actor_id":"<257 bytes>"}  400 {"error":"event actor_id exceeds 256 bytes"}
```

The reserved-name check runs before these rules, so a reserved kind or source
gets `422`, not `400`.

### Timestamps

The `timestamp` of a stored event is always the time the recorder received
it. It is the only clock the recorder can vouch for, it keeps timestamps in
journal order, and a producer cannot back-date or forward-date evidence.

A `timestamp` in the request body is treated as a claim by the producer and
kept as evidence:

- It must be RFC 3339 (for example `2026-01-31T12:00:00Z`). Anything else is
  rejected with `400`.
- It is stored, trimmed but otherwise verbatim, as
  `payload.producer_timestamp`. An absent or `null` payload becomes an object
  to hold it.
- If the payload is any other non-object value (an array, a string, a number)
  the event is rejected with `400`, because there is nowhere to keep the
  producer time.

```text
$ curl ... -d '{"kind":"agent.message","actor_id":"a","status":"ok","payload":{"x":1},"timestamp":"2020-01-01T00:00:00Z"}'
{"event_id":"01a130a6-c342-78e3-9865-71d74e733256", ... "timestamp":"2026-10-12T15:06:37.762336+00:00", ... "payload_json":"{\"producer_timestamp\":\"2020-01-01T00:00:00Z\",\"x\":1}", ...}
```

Two things pass these rules but are flagged later. For the kinds listed under
[lifecycle validation](events.md#lifecycle-validation), an event with no
`status`, or with a `payload` that is not a JSON object, produces a diagnostic
when the trace is finalized. Send `"payload": {}` rather than omitting it.

The redaction rules of the recording are applied before the event is stored.
All of them apply to `payload`: secret field names (as object keys, in
header-style pairs such as `{"name": "Authorization", "value": "..."}`, in
argument lists, and in JSON held inside a string), the built-in value
patterns, and the literal and regex rules. The literal and regex rules, and
the collector token itself, are also replaced in `kind`, `source`,
`actor_id`, `actor_type`, `span_id`, `parent_span_id`, `correlation_id`, and
`status`. See [redaction.md](redaction.md).

## Response

`200` with the stored event as JSON:

```json
{
  "event_id": "01a13085-0ad7-7370-b9cc-2c65d8e04137",
  "trace_id": "01a13085-0a02-7830-add6-0eae8a599cc9",
  "sequence": 5,
  "timestamp": "2026-10-12T14:29:47.863118+00:00",
  "kind": "agent.spawn",
  "source": "sdk",
  "payload_json": "{\"task\":\"t\"}",
  "actor_id": "researcher",
  "actor_type": "subagent",
  "parent_event_id": "",
  "span_id": "research",
  "parent_span_id": "",
  "correlation_id": "",
  "status": "running",
  "duration_ms": 0,
  "links": [],
  "prev_hash": "2575dce8d2afbb2f..."
}
```

`timestamp` is the recorder's receipt time. `prev_hash` is the hash of the
previous event in the journal (64 hexadecimal characters, shortened here); see
[trace-format.md](trace-format.md#event-hash-chain).

`payload_json` is the payload as stored, serialized to a string, after
redaction; the other fields are also shown as stored. Keep `event_id` if later events should name this one as their
parent.

Errors have the body `{"error": "<message>"}`.

## Status codes

| Status | When |
| --- | --- |
| `200` | The event was stored. |
| `400` | The body is not valid JSON, `kind` is missing, a field has the wrong type, a field breaks the [field rules](#field-rules) (empty `kind` or `source`, a disallowed character, too long), or `timestamp` is not RFC 3339 or comes with a non-object payload. |
| `401` | The bearer token is missing or wrong. Checked before the body is read. |
| `405` | Any method other than `POST` on `/v1/events`. |
| `408` | The body did not arrive within 10 seconds. `{"error":"event body was not received in time"}`. |
| `413` | The body is larger than the size limit. |
| `422` | The event claims a kind or source that only the recorder may write. |
| `500` | The journal write failed. |

The checks run in this order: token (`401`), declared size (`413`), body read
(`408`, `413`), JSON (`400`), reserved names (`422`), field rules and
timestamp (`400`).

### Size limit

The request body may be at most 2 MiB (2,097,152 bytes). A larger body is
rejected with `413` and `{"error":"event body exceeds 2097152 bytes"}`. A
request whose `Content-Length` already exceeds the limit is rejected before
any of the body is read.

### Reserved kinds and sources

The recorded process holds the collector token, so the collector refuses
events that would let it forge what only the recorder can observe: its own
exit status, its terminal output, or adapter-normalized provider events.

Rejected with `422`, compared case-insensitively after trimming whitespace:

| | Reserved values |
| --- | --- |
| `kind` | `session.start`, `session.interrupted`, and anything starting with `process.` (`process.exit`, `process.stdout`, `process.stderr`, `process.terminal`, `process.spawn_failed`, ...) |
| `source` | `premier`, `command`, `process`, `recorder`, `premier-recovery`, and anything starting with `adapter.` |

```text
$ curl -sS -X POST "$PREMIER_COLLECTOR_URL" \
    -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" -H "Content-Type: application/json" \
    -d '{"kind":"process.exit","payload":{"exit_code":0}}'
{"error":"event kind `process.exit` is recorded by Premier itself and cannot be emitted through the collector"}
```

Every other kind and source is accepted, including kinds Premier has never
heard of.

## Lifetime

- The collector starts before the recorded command and is reachable for as
  long as the recorder is capturing.
- It stops when the recorder finalizes the trace: after the recorded command
  has exited and its output has been drained.
- **Shutdown deadline.** Requests in flight at that moment get 2 seconds to
  finish. A request still open after that, such as a detached descendant that
  sent half a body and went to sleep, is dropped with its connection, and its
  event is not stored. Finalization does not wait for it.
- At any time, a request whose body stalls is given up on after 10 seconds
  (`408`).
- After that the port is closed. A late event from a process that outlived the
  recorded command gets a connection error and is lost. Nothing is queued or
  retried by the collector, and the port and token are not reused.
- An event that arrives after the command has exited but before the collector
  stops is stored after `process.exit`.
- Events are stored in arrival order. `sequence` is that order.

If a harness detaches background workers, have the recorded command wait for
them before it exits.

## `premier emit`

`premier emit` posts one event using the environment above.

```sh
premier emit --kind agent.spawn --actor researcher --actor-type subagent \
  --status running --span research --payload '{"task":"find the first divergence"}'

premier emit --json '{"kind":"agent.message","actor_id":"researcher","status":"ok","payload":{"to":["coder"]}}'

jq -n '{kind:"tool.execution",actor_id:"coder",status:"ok",payload:{tool:"rg"}}' | premier emit --json -
```

- Flag form: `--kind` is required. `--actor-type` defaults to `agent` and
  `--source` to `premier-emit`. `--payload` must be valid JSON. If `--status`
  or `--payload` is omitted the field is not sent, which triggers the
  diagnostics described above for the validated kinds.
- `--json` sends the given body unchanged; the other flags are ignored. The
  collector's default `source` (`sdk`) applies if the body has none.
- On success it prints the new `event_id` and exits `0`.
- It exits `1` when the collector variables are not set, the collector cannot
  be reached, it does not answer within `PREMIER_EMIT_TIMEOUT` seconds
  (default `10`), or it rejects the event. Decide in your harness whether that
  should fail the step: `premier emit ... || true` keeps telemetry optional.
- When the collector URL is loopback, `HTTP_PROXY`, `HTTPS_PROXY`, and
  `ALL_PROXY` are ignored.

The full flag list is in [cli.md](cli.md#emit).

## `sdk/shell/premier-emit.sh`

A bash fallback for environments where the `premier` binary may not be on
`PATH` inside the recorded process.

```sh
sdk/shell/premier-emit.sh '{"kind":"agent.spawn","actor_id":"researcher","status":"running","payload":{}}'
echo '{"kind":"agent.result","actor_id":"researcher","status":"ok","payload":{}}' | sdk/shell/premier-emit.sh -
```

- If `premier` is on `PATH`, the script runs `premier emit`: a first argument
  starting with `{` is passed as `--json`, no argument or `-` reads JSON from
  stdin, and anything else is passed through as `premier emit` flags.
- Otherwise it uses `curl` and accepts only a JSON body, as the first argument
  or on stdin. Flags are not supported in this mode.
- In `curl` mode it prints the collector's response body on success.

Failure behaviour, in both modes:

| Situation | Result |
| --- | --- |
| Collector variables not set | Message on stderr, exit `1` |
| Collector unreachable, or no answer within `PREMIER_EMIT_TIMEOUT` seconds (default `10`) | Message on stderr, exit `1` |
| Collector answers with a non-2xx status | `premier-emit: collector rejected event (<status>): <body>` on stderr, exit `1` |

For a loopback collector URL the script passes `--noproxy '*'` to `curl`, so
the token is not sent through a proxy configured in the environment.

## JavaScript

`@premierstudio/trace` wraps this endpoint with typed helpers, a timeout, and
non-throwing delivery. See [sdk/js/README.md](../sdk/js/README.md).
