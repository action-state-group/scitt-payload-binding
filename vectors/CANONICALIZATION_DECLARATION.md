# Canonicalization Declaration for Algorithm `jcs-n`

**Versioned algorithm identifier:** `jcs-n`  
**Defined in:** draft-mih-sokolov-scitt-payload-binding-00 §3.1  
**Status:** This declaration is authoritative for the vector suite in this directory.  
**Recorded in each record as:** the `algorithm` field of the record's digest context.

A verifier holding two digests that were computed under different algorithm identifiers
MUST NOT compare them.  The algorithm identifier gates all conformance claims.

---

## 1. Algorithm steps

Given a JSON-serializable object `P` and an exclusion set `E` (a set of top-level
field names, which may be empty):

1. **Exclusion** — Remove every top-level member whose name appears in `E`.  
   Exclusion is top-level only; `E` names top-level members of `P`, not paths into
   nested structures.

2. **Absent-field normalization** — Remove, bottom-up and recursively, every object
   member whose value is JSON `null`, an empty array (`[]`), or an empty object (`{}`).
   "Bottom-up" means inner objects are normalized before their parents; an object that
   becomes empty only after its own null/empty members are removed is itself eligible
   for removal by its parent.  Array elements are not object members and are not
   removed by this step, but normalization recurses into elements so that their
   member structure is normalized.

3. **JCS serialization** — Apply RFC 8785 JSON Canonicalization Scheme to the
   normalized value, producing a UTF-8 octet string.  Key ordering: lexicographic on
   UTF-16-BE code units of the member name string (no length-first rule).  Escaping:
   minimal — only characters that RFC 8785 §3.2.2.2 requires to be escaped (the
   two-character shortcut sequences `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, and
   `\uXXXX` for code points below U+0020).  The `/` character is not escaped.

4. **Digest** — Compute the SHA-256 hash of the UTF-8 octet string from step 3.

5. **Encoding** — Encode the 32-byte digest as 64 lowercase hexadecimal characters.
   This is the `bare_hex` representation.  Representations are distinct and not
   interchangeable (§4.1): `bare_hex`, `sha256:`-prefixed hex, and raw bytes are three
   different representations and a verifier MUST NOT silently coerce between them.

**Notation:** CANONICAL-DIGEST(`jcs-n`, P, E) = lowercase_hex(SHA-256(JCS(normalize(P\E))))

---

## 2. Numeric encoding rules

These rules exist because two conforming implementations must produce identical bytes
from the same semantic value.  JSON's numeric encoding is ambiguous for non-integer
values, and some JSON parsers silently coerce integers and floats.

| Value type | Rule | Rationale |
|---|---|---|
| Integer in `[-(2^53-1), 2^53-1]` | MUST be a JSON integer literal | Exactly representable in IEEE 754 double; round-trips through ECMAScript `Number` |
| Integer outside that range | MUST be an exact decimal string, not a JSON integer | Cannot round-trip through ECMAScript `Number`; two implementations may read different integer values |
| Decimal / monetary | MUST be an exact decimal string (e.g. `"12.50"`) | A JSON float may be rounded differently by different parsers |
| Exponent notation (`1e2`) | PROHIBITED in digest-bearing fields | A JSON float, same as above |
| Float in general | PROHIBITED in digest-bearing fields | Non-reproducible across implementations |
| `null` | Removed by absent-field normalization | After normalization, no `null` appears in the pre-image |

---

## 3. Unicode rules

JCS serialization (step 3 above) produces UTF-8 bytes.  The algorithm makes no Unicode
normalization assumption: `jcs-n` does **not** apply NFC or any other normalization form
before serialization.  The pre-image bytes are exactly the UTF-8 encoding of the JCS
string; a verifier that applies NFC (or any other normalization) before hashing
produces a different digest and is non-conforming.

Key ordering is by UTF-16-BE code unit sequence, not Unicode code-point order or
UTF-8 byte order.  For names in the Basic Multilingual Plane these coincide, but for
names containing supplementary characters (code points above U+FFFF) they diverge.
The UTF-16 key ordering is defined by RFC 8785 §3.2.3.

---

## 4. Absent-versus-null; empty collections

The following inputs produce identical pre-images and therefore identical digests:
- `{"a": null, "b": "x"}` (step 2 removes the `null` member)
- `{"a": [], "b": "x"}` (step 2 removes the empty array)
- `{"a": {}, "b": "x"}` (step 2 removes the empty object)
- `{"b": "x"}` (member `a` is absent)

This is intentional: absent-field normalization is the mechanism by which the canonical
form is stable across records that represent the same logical content with different
sparseness.  The pre-image for all four of the above is `{"b":"x"}`.

This equivalence is a *byte construction rule*, not a semantic rule.  Whether two
payloads that normalize to the same pre-image are "the same record" is a payload-class
decision that `jcs-n` does not make.

---

## 5. Digest domains

A digest is always relative to a **domain** — the logical point at which the bytes
were fixed.  Two digests computed over the same logical object at different domains
are not comparable and MUST NOT be treated as interchangeable.

The following domains are defined for this algorithm:

| Domain identifier | Definition |
|---|---|
| `model-produced` | The JSON object as produced by the model or agent, before any transport encoding, serialization, or routing modification. This is the canonical domain: the pre-image for `jcs-n` is always derived from an object in this domain. |
| `transport-delivered` | Bytes as received at the consumer or verifier after traversing a transport layer. The transport may fragment, chunk, or reorder the bytes relative to the model-produced form. A digest over transport-delivered bytes is not reproducible by a third party without replaying the exact transport. |

**Rule:** A CPB digest is always computed over an object in the `model-produced` domain.
A verifier that receives `transport-delivered` bytes MUST apply the declared transforms
to recover the `model-produced` object before computing or verifying the digest.

---

## 6. Declared transforms between domains

Where the same logical object exists in both the `model-produced` domain and the
`transport-delivered` domain, the transforms applied between them MUST be listed, in
order, each with a stable identifier.  Without this listing, a verifier holding two
differing digests cannot tell a declared transformation from a substitution — which is
the exact question the digests exist to answer.

A transform that injects a wall-clock timestamp or a freshly minted identifier is
non-reproducible by construction; naming it makes the non-reproducibility legible
rather than opaque.

### 6.1 Registered transforms

| Transform identifier | Version | Input domain | Output domain | Description |
|---|---|---|---|---|
| `stream-reassemble` | 1 | `transport-delivered` (list of SSE delta chunks, each with `"chunk"` field; terminal chunk has `"done": true`) | `model-produced` (a single JSON object) | Concatenate the `"chunk"` fields of all items in arrival order; parse the concatenated string as JSON. The pre-image is the parsed object. Requires a terminal chunk; a truncated stream (no `"done": true`) MUST signal `stream_incomplete`. |
| `identity` | 1 | any | same | No transformation; bytes pass through unchanged. Declared explicitly where the source and target domains coincide. |

Transforms not in this table MUST NOT be cited by a conforming implementation.  A
verifier that encounters an unknown transform identifier MUST treat it as an error.

### 6.2 Non-reproducibility markers

| Transform | Reproducible by third party? | Reason |
|---|---|---|
| `stream-reassemble` | Yes, given a complete stream | The reassembly is deterministic from the chunk sequence |
| `identity` | Yes | No transformation |
| Any transform citing a wall-clock value | No | The timestamp is unique to the generation event |
| Any transform generating a random nonce | No | The nonce cannot be derived from the logical content |

---

## 7. Binary and multimodal content

`jcs-n` operates on JSON objects.  Binary content (images, audio, files) that appears
in a payload MUST be base64-encoded and carried as a JSON string.  The digest is
computed over the base64 string as a JSON string literal — that is, over the base64
characters as they appear in the JCS pre-image, not over the decoded binary bytes.

An implementation that decodes the base64 before hashing produces a different pre-image
and a different digest and is non-conforming.

The `"encoding": "base64"` field (or equivalent) is part of the payload and is
included in the pre-image unless it appears in the exclusion set.

---

## 8. Version migration

The algorithm identifier `jcs-n` is stable.  If the algorithm must change — for
example, to use SHA-512 instead of SHA-256, or to apply a different key-ordering rule —
a new identifier MUST be registered (e.g. `jcs-n-2` or `jcs-sha512`).  The existing
`jcs-n` identifier MUST NOT be redefined; existing implementations and records remain
valid indefinitely under `jcs-n`.

Migrating a record set to a new algorithm requires recomputing every digest and
publishing the new algorithm identifier alongside or instead of the old one.  There is
no upgrade path that preserves digest values.

---

## 9. Verification: what must fail

A conforming test suite MUST demonstrate that each of the following inputs is rejected:

1. **Single-byte mutation** — Mutate one byte of a PASS vector's `input` and recompute
   the digest.  The result MUST NOT equal the pinned digest.  (`generate.py --mutate`
   demonstrates this for every KAT in the suite.)

2. **Float in a digest-bearing field** — A JSON float (e.g. `12.50`, `1e2`) in any
   member of the input MUST cause the implementation to signal an error rather than
   produce a digest.  (Vectors `jcs-n-kat-10`, `jcs-n-kat-24`.)

3. **Missing algorithm identifier** — A digest that is not accompanied by an algorithm
   identifier is ambiguous: a second implementation cannot reproduce the pre-image
   without knowing which normalization and serialization steps were applied.  The vector
   suite pins the algorithm identifier in every vector; a vector without it is a
   conformance gap, not a simplification.

4. **Truncated stream** — A stream with no terminal chunk MUST be rejected as
   `stream_incomplete`.  (Vector `domain-transform-fail-01`.)

5. **Representation mismatch** — A digest with trailing whitespace, surrounding spaces,
   or a `sha256:` prefix where `bare_hex` is declared MUST be rejected.  (Vectors
   `jcs-n-kat-20`, `jcs-n-kat-21`, `typed-ref-fail-03`.)

---

## 10. One-command regeneration

```
# Recompute all PASS vector digests from their 'input' fields and validate them:
python3 vectors/generate.py vectors/

# Run the standalone checker (no library dependencies):
python3 .github/check_vectors.py vectors/

# Run the full library test suite:
python3 -m pytest lib/tests/
```

See `vectors/harness.py` for testing an external implementation against this suite.
