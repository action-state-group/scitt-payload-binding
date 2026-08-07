# CPB Conformance Vector Suite

Conformance vectors for **draft-mih-sokolov-scitt-payload-binding-00**
(d23a936 lineage). Implementors of the Canonical Payload Binding (CPB)
construction MUST pass all cases not marked `must_fail: true` and MUST
reject all cases marked `must_fail: true`.

The suite is spec-derived and payload-neutral. No domain vocabulary from
any specific payload profile appears in these vectors; examples use synthetic
payload classes (`temperature-record`, `authorization-doc`, `decision-record`,
`artifact-a`, `artifact-b`, `example-action-record`).

## Layout

```
vectors/
  jcs-n/kats/           Known-Answer Tests for Algorithm jcs-n (§3.1)
  jcs-n/derived-id/     Derived identifier construction (§4)
  jcs-n/assembled-preimage/    Assembled pre-images: member mapping (§4, §13.2)
  typed-refs/pass/      Typed digest reference verification — PASS cases (§6)
  typed-refs/fail/      Typed digest reference verification — MUST-FAIL cases (§6)
  profile-independence/pass/   Profile independence — conforming cases (§8)
  profile-independence/fail/   Profile independence — non-conforming MUST-FAIL cases (§8)
```

## Assembled pre-images — family summary

Some payload classes bind neither the payload nor the payload minus an
exclusion set, but an object **assembled** from selected source fields. For
those, the algorithm plus the selected field set does not determine the
pre-image: the assembled object's member names and nesting are chosen by the
producer and are part of the bytes.

| ID | What it pins | Digest |
|---|---|---|
| jcs-n-assembled-01 | MUST-FAIL: two conforming readings of one declared field set produce different pre-images, differing only in one member name | `9707290f…` vs `7dd1096d…` |
| jcs-n-assembled-02 | The sufficient declaration: a `member_mapping` from source paths to pre-image paths, plus declared constants, from which exactly one pre-image is derivable | `9a43989d…` |

`jcs-n-assembled-02` is executed, not asserted: Category J in
`.github/check_vectors.py` applies the declared mapping to the source object and
requires the result to equal the vector's `input` exactly.

## Vector format

Each vector is a self-contained JSON object. Common fields:

| Field | Meaning |
|---|---|
| `id` | Unique vector identifier |
| `description` | What the vector exercises |
| `algorithm` | Canonicalization algorithm name (from Algorithm Registry) |
| `spec_ref` | Section of the draft that defines the tested behavior |
| `must_fail` | If `true`, a conforming implementation MUST reject this input |
| `failure_reason` | For MUST-FAIL: machine-readable reason token |
| `pre_image` | UTF-8 string of the JCS canonical bytes (the SHA-256 pre-image) |
| `pre_image_bytes_hex` | Hex encoding of the pre-image bytes |
| `digest` | Expected CANONICAL-DIGEST output (64-char lowercase hex for jcs-n) |

## Algorithm jcs-n — KAT summary

| ID | Input | Digest |
|---|---|---|
| jcs-n-kat-01 | `{"b":"x","a":"y"}` | `7951deff...` |
| jcs-n-kat-02 | `{"a":null,"b":"x"}` | `b00eaa75...` |
| jcs-n-kat-03 | `{"a":[],"b":"x"}` | `b00eaa75...` |
| jcs-n-kat-04 | `{"a":{},"b":"x"}` | `b00eaa75...` |
| jcs-n-kat-05 | `{"b":"x"}` | `b00eaa75...` |
| jcs-n-kat-06 | `{"a":{"c":null},"b":"x"}` | `b00eaa75...` |
| jcs-n-kat-07 | `{"a":{"c":[]},"b":"x"}` | `b00eaa75...` |
| jcs-n-kat-08 | `{"id":"abc123","b":"x","a":"y"}` excl `{id}` | `7951deff...` |
| jcs-n-kat-09 | `{"id":null,"b":"x","a":"y"}` excl `{id}` | `7951deff...` |
| jcs-n-kat-10 | MUST-FAIL: float in digest-bearing field | — |
| jcs-n-kat-11 | `{"amount":"12.50","currency":"USD"}` | `3470d8bf...` |
| jcs-n-kat-12 | `{"Å":"v1","B":"v2"}` (key is NFD-decomposed `A`+combining-ring) | `0b985be8...` |
| jcs-n-nfc-contrast-01 | MUST-FAIL: same input as kat-12 under an NFC-normalising construction — different member order and digest | — |
| jcs-n-kat-14 | `{"outer":[{"x":null}]}` (array elements are not object members; E3 does not prune into arrays) | `0a6882b6...` |
| jcs-n-kat-15 | MUST-FAIL: float nested inside an array | — |
| jcs-n-kat-16 | MUST-FAIL: unsafe integer (2^53) nested inside an array | — |
| jcs-n-kat-17 | MUST-FAIL: integer ≥ 10^21 nested inside an array | — |
| jcs-n-kat-18 | `{"😀":1,"דּ":2}` (UTF-16 code-unit sort order, minimal pair) | `2aa3f508...` |
| jcs-n-kat-19 | RFC 8785 §3.2.3's seven-member sorting example, verbatim | `5e321556...` |
| jcs-n-kat-20 | MUST-FAIL: typed-ref digest with a trailing newline (representation mismatch) | — |
| jcs-n-kat-21 | MUST-FAIL: typed-ref digest with surrounding whitespace (representation mismatch) | — |
| jcs-n-kat-22 | `{"id":"x","sub":{"id":"y"}}` excl `{id}` — exclusion-set matching is top-level only | `1fa18622...` |

**E3 boundary group** (KATs 02–07): null, empty array, empty object, absent
field, nested-null, and nested-empty-array (bottom-up) all produce the same
canonical form `{"b":"x"}` and the same digest `b00eaa75...`. This
demonstrates the byte construction the spec states in §3.1: jcs-n defines the
byte outcome after absent-field normalization; the semantic equivalence
decision belongs to the payload class.

**NFC boundary pair** (KAT 12 / nfc-contrast-01): the key in both vectors is
the NFD-decomposed sequence `A` (U+0041) + COMBINING RING ABOVE (U+030A),
which Unicode NFC normalization would fold into the precomposed `Å`
(U+00C5). `jcs-n` performs no NFC normalization, so kat-12 pins the digest
for the decomposed key as-is. nfc-contrast-01 is a MUST-FAIL vector: it pins
the different digest (and different member order, since normalization also
changes the UTF-16 sort key) that a would-be NFC-normalizing implementation
would produce for the same input, so that class of deviation is caught.

**Exclusion-set depth** (KAT 22): `canonical_digest` matches exclusion-set
field names against the top-level members of the payload only (§4); a field
of the same name nested inside a member's value is not removed. KAT 22 pins
this behavior for `{"id":"x","sub":{"id":"y"}}` excluding `{id}` — the
top-level `id` is stripped but `sub.id` survives. A recursive-stripping
implementation forks on this vector.

## Derived identifier summary

| ID | What it shows |
|---|---|
| derived-id-01 | Appendix A walkthrough: `temperature-record`, exclusion set `{record_id}` |
| derived-id-02 | MUST-FAIL: carried `record_id` does not match recomputed value |
| derived-id-03 | SD-encoded form hook: derived id computed over SD form, not plaintext |

## Typed reference summary

| ID | Result | What it tests |
|---|---|---|
| typed-ref-pass-01 | PASS | Matching digest under declared context |
| typed-ref-fail-01 | MUST-FAIL | Digest context mismatch (wrong exclusion set) |
| typed-ref-fail-02 | MUST-FAIL | Textual equality trap (same hex, incompatible contexts) |
| typed-ref-fail-03 | MUST-FAIL | Representation mismatch (prefixed vs bare hex) |
| typed-ref-fail-04 | MUST-FAIL | Identifier inconsistent with context (digest produced without exclusion set) |

## Profile independence summary

| ID | Result | What it tests |
|---|---|---|
| profile-independence-pass-01 | PASS | Conforming: Profile A cites Profile B via typed ref only |
| profile-independence-fail-01 | MUST-FAIL | Non-conforming: Profile A reads inside Profile B fields |

## Historical evidence — cited but not suite members

The following artifacts from the IETF 126 Vienna hackathon are cited here as
historical evidence for the interoperability of `jcs-n` across independently
written implementations. They are **not** conformance suite members; they remain
under their own declared digest contexts and owners.

- **Glyphzero `subject_digest` `0b4da06b...`** — two independent RFC 8785 JCS
  implementations (Rampalli/Glyphzero and AAC reference) produced byte-identical
  digests for the same PEDIGREE delegation record payload. Owner: Karthik Rampalli
  (Glyphzero). Source: Glyphzero PEDIGREE hackathon record (owner repo +
  pinned commit; coordinates confirmed 2026-07-25).

- **EP three-computation single digest `8cf0c36e...`** — three independent
  codebases produced byte-identical digests. Owner: Iman Schrock (EMILIA/EP).
  Source: EMILIA/EP hackathon record (confirmed 2026-07-24).

- **ORPRG canonical bytes** — retained under CP-JSON-2 digest context; cited
  via typed reference in the AAC interop record, not relabeled as `jcs-n`.
  Owner: Yong Bok Lee (Scott Lee), Meridian Verity Group. Source:
  ORPRG/Meridian hackathon record (confirmed 2026-07-24).

- **GAR CT leaf 166** — leaf constructed as SHA-256 of raw bytes of derived
  identifier (`bytes.fromhex(id)`, not `id.encode("utf-8")`). Owner: Tom Sato
  (GAR/SOOS). Source: gar-core.ts commit fe18f24 (confirmed 2026-07-25).

These are referenced by owner repo and pinned commit per the interop record
maintained in [agent-action-capsule/INTEROP.md](https://github.com/action-state-group/agent-action-capsule/blob/main/INTEROP.md).

## Registry coupling

On merge of this vector suite, the `jcs-n` entry in
[`REGISTRY.md`](../REGISTRY.md) gains a "Conformance vectors:" field citing
`vectors/jcs-n/` as the canonical test suite for the algorithm. This is a
single follow-up commit per the task specification.
