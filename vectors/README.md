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
  CANONICALIZATION_DECLARATION.md   Versioned declaration of all transforms and domains
  generate.py                       One-command validation / regeneration / mutation check
  harness.py                        Cross-language conformance harness (both directions)
  jcs-n/kats/                       Known-Answer Tests for Algorithm jcs-n (§3.1)
  jcs-n/derived-id/                 Derived identifier construction (§4)
  typed-refs/pass/                  Typed digest reference verification — PASS cases (§6)
  typed-refs/fail/                  Typed digest reference verification — MUST-FAIL cases (§6)
  profile-independence/pass/        Profile independence — conforming cases (§8)
  profile-independence/fail/        Profile independence — non-conforming MUST-FAIL cases (§8)
  domain-transforms/pass/           Domain transform PASS cases — stream reassembly (§3.1 + Declaration §6)
  domain-transforms/fail/           Domain transform MUST-FAIL cases — truncated stream
  multimodal/pass/                  Binary/multimodal content as base64 string (§3.1 + Declaration §7)
```

## One command

```sh
# Validate all pinned digests from inputs:
python3 vectors/generate.py vectors/

# Mutation check (flip one byte, verify digest changes):
python3 vectors/generate.py --mutate vectors/

# Test an external implementation against the full suite:
python3 vectors/harness.py verify-impl "<your-command>" vectors/

# Use our reference impl as the command in an external harness:
python3 vectors/harness.py reference-impl

# Run the standalone checker (no library dependencies):
python3 .github/check_vectors.py vectors/
```

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
| jcs-n-kat-23 | ESC character (U+001B) in a value — canonical form uses `\u001b` (lowercase) | `f5d570fa...` |
| jcs-n-kat-24 | TAB character (U+0009) in a value — canonical form uses `\t` (short form, not `\u0009`) | `7ac9c6bd...` |
| jcs-n-kat-25 | Full control-character taxonomy: NUL, SOH, BEL, BS, TAB, LF, FF, CR, ESC, US in one value | `ed3c5000...` |
| jcs-n-kat-26 | Control character in a KEY: sort is by code unit (U+001F < U+0020), not by escaped bytes | `64e35d3d...` |
| jcs-n-esc-uppercase-contrast | MUST-FAIL: `\u001B` (uppercase B) is non-conforming; pins correct and wrong digests for harness check | — |
| jcs-n-tab-long-form-contrast | MUST-FAIL: `\u0009` instead of `\t` is non-conforming; pins correct and wrong digests | — |
| jcs-n-control-key-escaped-sort-contrast | MUST-FAIL: sorting keys by escaped bytes is wrong; pins correct (code-unit) and wrong (escaped) digests | — |
| jcs-n-kat-30 | 4-level deep nesting | `27e20f85...` |
| jcs-n-kat-31 | Nested tool schema (JSON Schema vocabulary) | `ca37149a...` |
| jcs-n-kat-32 | MUST-FAIL: exponent notation (`1e2`) | — |
| jcs-n-kat-33 | `{"count":9007199254740991,"limit":-9007199254740991}` — max safe integer boundary | `00eac020...` |
| jcs-n-kat-34 | 13-field mixed-type payload | `cb6f355c...` |
| jcs-n-kat-35 | MUST-FAIL: `-0` token rejected by the wire rule `(0|-?[1-9][0-9]*)` | — |
| jcs-n-kat-36 | `{"count":0}` — integer zero (token `0`) is a valid wire value | `618de7d9...` |
| jcs-n-kat-37 | MUST-FAIL: duplicate key `a` after NFC normalization | — |
| jcs-n-kat-38 | Control characters ESC (U+001B) and HT (U+0009) escaped as `\u001b` / `\t` | `d149a22a...` |

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

**String-escape group** (KATs 23–26 + contrast vectors 27–29): JCS (RFC 8785
§3.2.2.2) defines two categories of string-character escaping:

1. **Named two-character escapes** for specific control characters: `\b`
   (U+0008), `\t` (U+0009), `\n` (U+000A), `\f` (U+000C), `\r` (U+000D),
   `\"` (U+0022), and `\\` (U+005C). These MUST be used where applicable;
   using the longer `\uXXXX` form for any of these characters is
   non-conforming and produces a different pre-image.

2. **Lowercase `\uXXXX` escapes** for all other control characters in
   U+0000–U+001F. The four hexadecimal digits MUST be lowercase (e.g.,
   `\u001b` for ESC, not `\u001B`). An uppercase hex digit changes the
   byte sequence and therefore the digest.

Characters above U+001F (other than `"` and `\`) are output as UTF-8 without
escaping, even if the source JSON used `\uXXXX` for them.

Key escaping follows the same rules: member names (keys) containing control
characters are escaped per RFC 8785 §3.2.2.2, and their sort order is
determined by the UTF-16 code units of the **unescaped** key string (RFC 8785
§3.2.3) — not by the byte sequence of the escaped serialization. KATs 23–26
pin the correct canonical bytes for each case. The three contrast vectors
(27–29) pin both the conforming digest and the non-conforming digest that a
miscapitalized, long-form, or escaped-sort implementation would produce, so
that a test harness can assert the library produces one and not the other.

🔴 **Cross-linked from `REGISTRY.md` §jcs-n implementation note** — this
group was added explicitly because prior vector sets had zero escaping coverage,
leaving a third-party Rust implementer with no KAT to build against for this
rule.

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
| typed-ref-fail-05 | MUST-FAIL | digest_alg inconsistent with the registered context (-01 §7.1) — SHA-512, MD5, an unregistered name, and the empty string, each carrying the otherwise-correct digest |
| typed-ref-cpb01-01 | PASS | ARP conformance baseline (-01 §7, §7.1) — folded byte-for-byte from Joel Hillier's `arp-typed-ref-cpb01-v0.1.json` (`88153dd1…673d`), vector 1 of 5 |
| typed-ref-cpb01-02 | MUST-FAIL | digest_alg inconsistent with the registered context (-01 §7.1) — ARP's independent exercise of the same gap as typed-ref-fail-05; folded byte-for-byte from the same source, vector 2 of 5. Vectors 3 (specification question, withdrawn per PM ruling), 4 (not applicable — this library constructs no log leaf) and 5 (ARP/CAID-side, not a CPB finding) were not folded |

## Profile independence summary

| ID | Result | What it tests |
|---|---|---|
| profile-independence-pass-01 | PASS | Conforming: Profile A cites Profile B via typed ref only |
| profile-independence-fail-01 | MUST-FAIL | Non-conforming: Profile A reads inside Profile B fields |

## Domain transform summary

| ID | Result | What it tests |
|---|---|---|
| domain-transform-pass-01 | PASS | Streaming API response reassembled from SSE delta chunks; digest over reassembled form |
| domain-transform-fail-01 | MUST-FAIL | Stream truncated before terminal chunk; `stream_incomplete` |

See `CANONICALIZATION_DECLARATION.md §5–6` for the domain and transform table.

## Multimodal summary

| ID | Result | What it tests |
|---|---|---|
| multimodal-pass-01 | PASS | Binary content carried as base64-encoded string; digest over the base64 string, not decoded bytes |

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
