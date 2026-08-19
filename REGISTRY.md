# Registries of record — Canonical Payload Binding

**Status.** This document is the **interim registry of record** for the two
Canonical Payload Binding (CPB) registries, until RFC publication establishes the
corresponding IANA registries. The registries and their normative definitions are
in the Internet-Draft (`draft-mih-sokolov-scitt-payload-binding`, this
repository's `spec/`), **§13 (IANA Considerations)**. Registration policy:
**Specification Required** per [RFC 8126 §4.6]; a Designated Expert is required
for each registration. **Entries are immutable** — if a behavior change is
needed, a new entry MUST be registered; existing entries MUST NOT be modified
retroactively.

Change controller: **Action State Group, Inc.** (interim) → **IETF** on
publication. On working-group adoption, the provisional registry **moves with the
document** to a repository of the working group's choosing (draft §11).

**One registry home for the CPB document family.** These registries serve the
entire CPB family — this document and its companions — and this is the single
place any of them registers. Companion **mechanisms** stay in the companion
documents as normative text and are never registry entries: selective
disclosure, for example, is a transform that composes with any registered
canonicalization algorithm, so it adds no algorithm entry; countersignature
machinery likewise lives in its companion. A companion that introduces a new
controlled **vocabulary** adds a **new registry here** — same home, same
Specification-Required / PR-as-consent rule, same migration clause — rather than
scattering per-companion registries (e.g. a future Relation Types registry for
record relations: supersedes / confirms / corrects). A companion whose need is
simply a new **artifact type** registers in the existing Artifact Type Registry
(e.g. an erasure tombstone), adding no new structure. Per-companion registry
scattering would break decomposable verification the same way per-profile
invention of these facilities would — one registry home is the structural
guarantee. The home moves **as a unit** through adoption: this repository today →
the working group's repository on adoption → IANA at RFC publication.

**How entries change — PR as consent.** The tables below change **only** by pull
request with the named owner's approval. A canonicalization-algorithm or
artifact-type entry enters the record only once its semantics are pinned in a
publicly available specification and the owner confirms every owner-supplied
field. CPB editors MUST NOT fill in an owner's digest-context parameters on their
behalf. Proposed entries under discussion with their owners are tracked
separately in [`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md)
until confirmed; they enter the tables here on merge.

**Registration rules for new entries.** Two requirements apply to every entry
regardless of registration type:

1. **A new entry MUST resolve to a specific normative reference.** Naming an
   algorithm family is not declaring a digest context: the cited text must pin the
   exact algorithm version and encoding. (Motivation: RFC 8785 §3 is the minimum
   required specificity for a JCS-based algorithm; citing only "JCS" leaves the
   hash, encoding, and normalization steps undeclared.)

2. **A required conformance vector set MUST be two-sided — positive vectors with
   pinned expected values AND negative (MUST-FAIL) vectors.** Negatives-only
   cannot detect an implementation that is too strict (rejecting valid inputs);
   positives-only cannot detect an implementation that accepts malformed inputs.
   Both sides are required to make a conformance claim.

**Descriptive, not generative.** This file is DESCRIPTIVE of the registries
defined normatively in the Internet-Draft; it never generates new semantics. The
draft (§11) is normative; this file is the living interim record.

[RFC 8126 §4.6]: https://www.rfc-editor.org/rfc/rfc8126#section-4.6

---

## Payload Canonicalization Algorithm Registry

Records the canonicalization algorithms that may be used to compute
CANONICAL-DIGEST values. Registration template: **Name**, **Description**,
**Reference** (draft §13.1).

| Name | Description | Reference | Status |
|---|---|---|---|
| `jcs-n` | RFC 8785 JCS over a normalized JSON object (null, empty-array, and empty-object members removed bottom-up); SHA-256; lowercase hex | draft-mih-sokolov-scitt-payload-binding | Registered |
| `jcs` | RFC 8785 JCS over a JSON object (no normalization pass; null, empty-array, and empty-object members are retained as-is); SHA-256; lowercase hex | RFC 8785 | **Provisional** — pending Designated Expert review; not Registered until this entry merges |
| `cde-n` | Deterministic CBOR canonicalization profile; SHA-256 | draft-mih-sokolov-scitt-payload-binding | **Reserved** (defined in a subsequent revision) |
| `as-transmitted` | No canonicalization: the pre-image is the exact octet sequence identified by a cited named production in the container format (e.g., a signature's signing input); an artifact type entry using this algorithm states a byte-boundary selector in place of a field set; SHA-256; 64-character lowercase hex | draft-mih-sokolov-scitt-payload-binding | Registered |

**as-transmitted — byte-boundary selector is mandatory, not descriptive.**
`as-transmitted` performs no canonicalization: the digest is computed over a
byte sequence already fixed by a signature or container format, where
re-canonicalizing would break the very binding that makes those bytes
authoritative. Because there is no canonicalization, there is also no field
set and no exclusion set — an Artifact Type entry that declares
`as-transmitted` MUST instead state a byte-boundary selector: a normative
reference plus the name that referenced specification gives to the exact
byte sequence (e.g., `RFC 7515 §5.1, JWS Signing Input`; `RFC 9052 §4.4,
ToBeSigned`). A selector that is not a cited named production is prose,
not a selector, and says nothing. If the container specification carrying
the artifact does not itself name the byte sequence as a discrete
production, the artifact type MUST NOT use `as-transmitted` — it registers a
canonicalization algorithm instead.

**jcs-n implementation note — Unicode normalisation boundary.** jcs-n applies
no Unicode normalisation. An object whose key contains decomposed code points
(e.g., U+0041 U+030A, Latin A + combining ring above) produces a different
canonical byte sequence than the same key in NFC form (U+00C5, precomposed
Å), and therefore a different digest. A profile that applies NFC normalisation
before or after member-sort MUST declare the normalisation step explicitly;
the digest context it registers will differ from jcs-n's. This boundary is
exercised by conformance vectors `jcs-n-kat-12` (PASS) and
`jcs-n-nfc-contrast-01` (informative contrast); no previously published test
corpus covers this case (Joel Hillier, SCITT list, 2026-07-27).

**jcs-n implementation note — string-escape encoding.** JCS (RFC 8785
§3.2.2.2) prescribes exactly two escape categories for string characters:
(1) named two-character escapes (`\b`, `\t`, `\n`, `\f`, `\r`, `\"`, `\\`)
for the specific control characters they name — these MUST be used where
applicable; and (2) `\uXXXX` with **lowercase hexadecimal digits** for all
other characters in U+0000–U+001F. An implementation that outputs uppercase
hex digits (e.g., `\u001B` instead of `\u001b`) or the long form `\u0009`
instead of `\t` produces a different byte sequence and therefore a different
digest. Key strings (member names) obey the same escaping rules, and their
sort order is determined by the code units of the **unescaped** key string,
not by the bytes of the escaped form (RFC 8785 §3.2.3). Prior to this note,
the vector suite had zero coverage of these rules; a third-party Rust
implementer would have had no KAT to build against. Coverage added by vectors
`jcs-n-kat-23` through `jcs-n-kat-26` (PASS) and `jcs-n-esc-uppercase-contrast`,
`jcs-n-tab-long-form-contrast`, `jcs-n-control-key-escaped-sort-contrast`
(both-directions contrast); see [`vectors/README.md`](vectors/README.md)
§String-escape group for the rule stated in prose and the contrast digests.

Conformance vectors: [`vectors/jcs-n/`](vectors/jcs-n/) — the canonical test suite
for algorithm `jcs-n`, covering Known-Answer Tests (including the E3 boundary
group: null, empty-array, empty-object, and absent field all normalize to the
same canonical form), string-escape encoding (including both-directions contrast
vectors for uppercase-hex, long-form, and escaped-sort deviations),
derived-identifier construction, and typed-reference verification cases
including MUST-FAIL cases.

**jcs — plain RFC 8785 with no normalization pass.** `jcs` applies RFC 8785 JCS
directly to the input object without removing null, empty-array, or empty-object
members first. This construction is byte-distinct from `jcs-n`'s normalized form;
the distinction is exercised, and retained as a differential record, by the
discriminating vectors in
[`vectors/subject-binding-diff/`](vectors/subject-binding-diff/):

- **Null and empty-member retention (Direction A).** An object member whose value
  is JSON null, `[]`, or `{}` survives into the canonical form under `jcs`. The
  `jcs-n` construction removes the same member, so the same action object yields
  different pre-images and different SHA-256 digests under the two constructions.
  A verifier that treats a `jcs` digest as interchangeable with a `jcs-n` digest
  MUST fail — the digests are not the same bytes.
- **Float acceptance (Direction B).** `jcs` accepts floating-point JSON numbers and
  serializes them per RFC 8785 §3.2.2.3 (shortest-decimal IEEE 754). The `jcs-n`
  construction MUST-FAIL on the same input under the blanket float prohibition
  (draft §11.3: JSON floating-point numbers MUST NOT appear in any field from which
  a digest is computed — not the narrower §3.1 monetary/quantity decimal-string
  constraint). An action record carrying a float member therefore produces a valid
  `jcs` digest and no `jcs-n` digest — the two constructions diverge categorically,
  not just numerically.

**jcs — named consuming profile.** The registered consuming profile for `jcs` is
**composition subject binding** (`draft-mih-sato-agent-accountability-composition
§6.3.2`). That section specifies the composition subject binding digest as
`SHA-256(JCS(action))` where JCS is plain RFC 8785 — the construction this entry
names and pins. Registering `jcs` closes the registry gap: §6.3.2 was written against
an un-registered algorithm token; `jcs` is now the registry entry that token resolves
to, and a verifier can perform an O(1) lookup rather than re-deriving the algorithm
from the prose. No other registered consuming profile is known at this time; additional
profiles MUST be added by pull request under the standard registration rules above.

Discriminating vectors: [`vectors/subject-binding-diff/`](vectors/subject-binding-diff/)
— four vectors demonstrating the byte-level divergence between `jcs` and `jcs-n` in
both directions (Direction A: different digests for null/empty members; Direction B:
float accepted by `jcs`, MUST-FAIL under `jcs-n`). Category J of `check_vectors.py`
exercises all four, including mutation probes, without external dependencies.

## Artifact Type Registry

Records the artifact types that may appear in the `type` field of a typed digest
reference. Registration template (draft §13.2): **Name**; **Digest Contexts** —
one or more, each stating a **purpose** label, a **profile version**, a
**canonicalization algorithm** (from the Algorithm Registry above; MAY be
`as-transmitted`), a **field set** (or, under `as-transmitted`, the
byte-boundary selector that algorithm requires in place of a field set), an
**exclusion set**, any **domain separation**, the **pre-image encoding**, and
the **representation** of the output; **Reference**. A single-context entry is
the degenerate case of this template, not a different one. Every digest
context's purpose label is drawn from one vocabulary shared across this whole
registry (initial contents: `identifier`, `equivalence` — see draft §13.2), so
a companion introducing digest bindings at another layer has one namespace to
adopt rather than a second, incompatible one. This purpose label is orthogonal
to, and independent of, any digest role a composition profile assigns within a
cross-document join — see draft §13.2 for the axis distinction.

**Where a citing composition profile's protocol inputs come from.** The
registered **Name** above IS the profile label a composition profile treats as
a protocol input — CPB takes no separate IANA action to register profile
labels. The digest context's **profile version**, when the profile is
versioned, is stated per digest context (`N/A` when the artifact type's own
reference does not distinguish versions). The digest context's **hash
algorithm** and output representation are pinned by the cited
canonicalization-algorithm token, recorded once in that token's Payload
Canonicalization Algorithm Registry entry above rather than restated per
artifact type.

### `agent-action-capsule`

**Reference:** draft-mih-scitt-agent-action-capsule
**Status:** Registered — first payload profile

| Purpose | Profile version | Algorithm | Field set | Exclusion set | Domain separation | Pre-image encoding | Representation |
|---|---|---|---|---|---|---|---|
| `identifier` | N/A (no versioned profile registered yet) | `jcs-n` | all capsule fields | `{capsule_id, chain}` | none | JCS UTF-8 octets (per `jcs-n`) | 64-char lowercase hex |

Content unchanged from the prior 3-element shape — only the shape changed to the
full digest-context template above. Domain separation and pre-image encoding are
not new owner-supplied parameters: both are stated directly by `jcs-n`'s own
normative definition, not invented for this row.

Proposed Artifact Type entries awaiting their owners' confirmation are listed in
[`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md).
