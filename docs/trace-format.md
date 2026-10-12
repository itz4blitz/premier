# Premier trace format

This is the on-disk format written by `premier-trace` (`FORMAT_VERSION = 2`) and
what `premier verify` checks. Version 1 traces remain readable; see
[Version 1 compatibility](#version-1-compatibility). Readers reject any other
version with an error naming the versions they support.

All hashes are SHA-256. Hex is lowercase. `||` is byte concatenation and `\0` is
a single zero byte.

## Layout

A trace is a directory, conventionally named `<name>.atrace`:

| Path | Present | Content |
| --- | --- | --- |
| `manifest.json` | always | Trace metadata, journal digest, seal. Replaced atomically. |
| `events/active.events.pb` | while recording | Uncompressed frame stream, appended to. |
| `events/000001.events.pb.zst` | once finalized | The same frame stream, zstd-compressed. |
| `recorder.lease` | while recording | Recorder process id, rewritten as a heartbeat. |
| `blobs/sha256/`, `indexes/` | always | Reserved, empty. |

Directories are created `0700` and files `0600`. A trace is *finalized* when
`manifest.json` has a `journal` object; finalization compresses the active
journal, writes the manifest, then removes the active journal and the lease.

## Frames

The journal is a sequence of frames with no header or trailer:

```
frame  = length body
length = u32, little-endian, byte length of body, at most 64 MiB
```

In a plaintext trace `body` is one protobuf-encoded event. In an encrypted
trace `body` is the event's `sequence` as a u64 little-endian, followed by the
standard base64 text of `nonce (24 bytes) || XChaCha20-Poly1305 ciphertext and
tag` of the protobuf-encoded event. The associated data is
`premier:journal-frame:v1:<trace_id>:<sequence>`, and the per-trace key is
HKDF-SHA256 of the master key with salt `premier-trace-v1` and info
`<trace_id>`. This envelope is unchanged from version 1.

An event is a proto3 message:

| Tag | Field | Type |
| --- | --- | --- |
| 1 | `event_id` | string |
| 2 | `trace_id` | string |
| 3 | `sequence` | uint64, starting at 1, contiguous |
| 4 | `timestamp` | string (RFC 3339) |
| 5 | `kind` | string |
| 6 | `source` | string |
| 7 | `payload_json` | string |
| 8 | `actor_id` | string |
| 9 | `actor_type` | string |
| 10 | `parent_event_id` | string |
| 11 | `span_id` | string |
| 12 | `parent_span_id` | string |
| 13 | `correlation_id` | string |
| 14 | `status` | string |
| 15 | `duration_ms` | uint64 |
| 16 | `links` | repeated string |
| 17 | `prev_hash` | string, 64 hex characters (version 2) |

## Event hash chain

Every version 2 event names the hash of the event before it:

```
genesis        = hex(SHA-256("premier:chain-genesis:v2\0" || trace_id))
hash(event)    = hex(SHA-256("premier:chain-event:v2\0" || canonical(event)))
event[1].prev_hash = genesis
event[n].prev_hash = hash(event[n-1])
chain head     = hash(last event), or genesis for an empty journal
```

`canonical(event)` is the proto3 encoding of the fields above, including
`prev_hash`: fields in ascending tag order, fields holding their default value
omitted, `links` as one entry per element, no unknown fields. It is the event
as decoded and re-encoded, not the raw frame bytes, so the chain is the same
for plaintext and encrypted journals and is preserved when a trace is
encrypted or its key rotated. Protobuf fields a reader does not know are not
covered and are not surfaced by any reader.

The genesis value ties the chain to the trace id, so events cannot be moved
between traces. Verification walks the chain from genesis and fails at the
first event whose `prev_hash` is not the hash of its predecessor.

## Manifest

`manifest.json` is one JSON object:

| Field | Notes |
| --- | --- |
| `format_version` | `2` |
| `trace_id`, `tenant_id` | |
| `name`, `command` | |
| `started_at`, `ended_at` | RFC 3339, UTC |
| `exit_code`, `termination` | |
| `journal` | `{ path, sha256, event_count }`; `sha256` is of the compressed journal file |
| `diagnostics`, `capabilities`, `redaction`, `adapter` | |
| `seal` | see below; present once finalized |
| `encryption` | `{ algorithm, key_id, private_manifest }`, encrypted traces only |

```json
"seal": {
  "chain_head": "<64 hex>",
  "event_count": 3,
  "recovered": true,
  "digest": "<64 hex>",
  "signature": {
    "algorithm": "ed25519",
    "public_key": "<64 hex>",
    "signature": "<128 hex>"
  }
}
```

`recovered` is written only when true, `signature` only when the trace is
signed. `event_count` must equal the number of events in the journal.

### Seal

```
digest = hex(SHA-256("premier:manifest-seal:v2\0" || canonical(manifest)))
```

`canonical(manifest)` covers every manifest field, including `journal`,
`seal.chain_head`, `seal.event_count` and `seal.recovered`, with exactly three
members removed: `seal.digest`, `seal.signature` and
`encryption.private_manifest` (ciphertext with a fresh nonce on every write;
`encryption.algorithm` and `encryption.key_id` are covered). It is JSON with:

- object members sorted by the bytes of their UTF-8 key;
- members whose value is `null` omitted, so an absent optional field and an
  explicit `null` are the same;
- arrays in their stored order;
- no whitespace;
- integers in plain decimal (the manifest holds no fractional numbers);
- strings as UTF-8 with only `"`, `\` and the control characters below U+0020
  escaped (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, otherwise `\u00xx` with
  lowercase hex).

The digest is computed over the manifest as parsed, so formatting of
`manifest.json` does not matter, and JSON members a reader does not know are
not covered. Parsing normalizes a few fields before they are hashed: a missing
`tenant_id` is `"local"`, a missing `capabilities` is `[]`, missing
`redaction.terminal_literal_count` and `terminal_regex_count` are `0`; and
`diagnostics` and `redaction.custom_fields` are omitted when empty, as is
`seal.recovered` when false. Every other field is hashed as stored.

### Signature

A signature is optional. It is Ed25519 over

```
"premier:manifest-signature:v2\0" || digest (the 32 raw bytes)
```

and verified strictly (RFC 8032, rejecting small-order keys and non-canonical
signatures). Because the digest covers the chain head, the signature covers
every event and every manifest field.

`public_key` is stored for convenience only and is not trusted: a valid
signature shows that the holder of *that* key sealed the trace, and nothing
else. A verifier has to bring the public key it expects.

Keys are files of hex text. A private key is the 32-byte Ed25519 seed as 64
hex characters, and must not be readable by group or others; a public key is
64 hex characters. A key's fingerprint is `sha256:` followed by the first 16
bytes of the SHA-256 of the raw public key, in hex.

```
premier keygen <path>                     # writes <path> (0600) and <path>.pub
premier record --sign-key <path> -- ...   # or PREMIER_SIGN_KEY_FILE=<path>
premier sign <trace> --sign-key <path>    # an already finalized trace
premier verify <trace> [--public-key <path-or-hex>]
```

### Encrypted traces

In an encrypted trace only `format_version`, `trace_id`, `tenant_id`,
`started_at` and `encryption` are stored in the clear. Every other field,
including `journal` and the whole `seal`, is in `encryption.private_manifest`:
XChaCha20-Poly1305 with associated data
`premier:manifest:v<format_version>:<trace_id>:<tenant_id>`. The seal is kept
inside the ciphertext because its digest is a hash of plaintext fields and its
signature names the signer.

The chain, seal and signature are computed exactly as for a plaintext trace,
over the decrypted events and the decrypted manifest. Verifying, signing or
checking a signature on an encrypted trace therefore needs the encryption key
(`PREMIER_TRACE_KEY_FILE`).

## Verification

`premier verify` on a finalized trace checks, in order:

1. the manifest parses and its version is supported;
2. the compressed journal matches `journal.sha256`;
3. every frame decodes (and, if encrypted, authenticates);
4. the event count matches, every event carries the manifest's `trace_id`,
   sequences are `1..n` and event ids are unique;
5. the event chain, from genesis to `seal.chain_head`;
6. the seal digest;
7. the signature, when present;
8. with `--public-key`, that the signer is that key.

It exits non-zero with `invalid` and the failed check, or zero with one of:

| Output | Meaning |
| --- | --- |
| `verified: ... signed by the supplied key <fingerprint>` | All checks pass and the signature is by the key given with `--public-key`. |
| `consistent: ... signed by an unknown key <fingerprint>` | All checks pass; the signature is valid for the key stored in the trace, and no key was supplied to compare against. |
| `consistent: ... unsigned` | Checks 1 to 6 pass. |
| `consistent (v1: digest only)` | Version 1: checks 1 to 4 only. |

With `--public-key`, an unsigned trace, a version 1 trace and a trace signed by
any other key are all failures.

The viewer API reports the same thing per trace as `integrity`
(`live`, `verified`, `invalid`), `integrity_protection` (`digest_only`,
`sealed`, `signed`) and `integrity_signer` (the fingerprint). The server has no
list of trusted keys, so `signed` there means "signed by the key in the trace".

## Operations that rewrite a trace

- **`premier recover`** finalizes an abandoned active journal. It verifies the
  chain over the complete frames and refuses a journal whose chain is broken,
  drops a torn trailing frame, appends a `session.interrupted` event that
  continues the chain, and seals with `seal.recovered = true`. It signs if
  `PREMIER_SIGN_KEY_FILE` is set; that signature is the recovering party's
  statement about what it found, not the recorder's.
- **`premier encrypt`** (encrypt or rotate) re-encrypts the events unchanged,
  so the chain and its head are preserved. `journal.sha256` and `encryption`
  change, so the seal digest is recomputed and an existing signature no longer
  applies. It is re-applied when `--sign-key` or `PREMIER_SIGN_KEY_FILE` is
  given; otherwise it is dropped and the command says so.
- **`premier claim`** changes `tenant_id`, a sealed field, and handles the seal
  and signature the same way.
- **`premier sign`** verifies the trace, then adds or replaces the signature.
  It changes nothing else.
- **`premier export`** writes a redacted JSON copy. Its `source` object records
  the source trace's `format_version`, `protection`, `journal_sha256`,
  `chain_head`, `event_count`, `seal`, `signature`, `public_key` and
  `public_key_fingerprint`. The export itself is not covered by the seal or the
  signature, because redaction changes the events.

## Version 1 compatibility

Version 1 manifests have `format_version: 1` and no `seal`; version 1 events
have no `prev_hash`. They are read and verified exactly as before (checks 1 to
4 above) and reported as `v1: digest only`. They are not upgraded in place:
recovering, encrypting or claiming a version 1 trace leaves it version 1, and
`premier sign` refuses it. New recordings are always version 2.

## Threat model

What each level protects against, assuming SHA-256 and Ed25519 hold.

**Version 1 (digest only).** Detects corruption of the journal: bit rot, a
truncated copy, a partial write. It detects no deliberate change. The digest
sits in the same unsigned manifest, so anyone who can rewrite the journal can
recompute it, and most manifest fields are covered by nothing.

**Version 2, unsigned.** Additionally detects any change that is not carried
through consistently: an edited, inserted, removed or reordered event, a
truncated journal, or an edit to any manifest field (name, command, exit code,
termination, timestamps, capabilities, adapter, redaction provenance,
diagnostics, owner). This catches accidental damage and careless edits.
**It does not stop someone with write access to the trace.** They can re-chain
the events and recompute the chain head, the journal digest and the seal, and
the result verifies. They can also rewrite it as a version 1 trace. An
unsigned trace is internally consistent, not evidence of anything, and
`premier verify` and the viewer say so.

**Version 2, signed, verified with `--public-key`.** Any change to any event or
any manifest field after signing is detected unless the attacker has the
private key. Removing the signature, re-signing with another key, or
downgrading to version 1 all fail verification against the expected key.
Without `--public-key` a signed trace is no stronger than an unsigned one,
since the attacker can substitute their own key.

**Encrypted traces.** Without the encryption key an attacker cannot read or
undetectably alter events or private manifest fields, and cannot downgrade the
version (it is bound into the associated data). Someone who holds the
encryption key has the same power over an unsigned encrypted trace as over an
unsigned plaintext one; only a signature constrains them.

Limits that apply at every level:

- A signature says the key holder sealed these bytes. It does not say the
  recorded events are true. The recorder, the recorded process and anything
  that could write to the journal before finalization are trusted.
- A signing key stored next to the traces it signs protects against nobody who
  can read both. Keep it elsewhere, or sign on another host with `premier sign`.
- Timestamps are the recording host's clock and are not attested. Nothing
  proves when a trace was signed.
- An unfinalized journal has no recorded chain head. Its chain exposes a
  careless edit among complete frames, but trailing events can be removed at a
  frame boundary without trace, exactly as a crash would, and a full re-chain
  is undetectable. `seal.recovered` marks traces sealed from such a journal.
- Deleting a trace, or replacing it with a different validly sealed or signed
  trace, is outside what a per-trace format can detect.
