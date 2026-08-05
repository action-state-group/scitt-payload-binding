# Registries of record — Canonical Payload Binding

**Status.** This document is the **interim registry of record** for the two
Canonical Payload Binding (CPB) registries, until RFC publication establishes the
corresponding IANA registries. The registries and their normative definitions are
in the Internet-Draft (`draft-mih-sokolov-scitt-payload-binding`, this
repository's `spec/`), **§11 (IANA Considerations)**. Registration policy:
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
**Reference** (draft §11.1).

| Name | Description | Reference | Status |
|---|---|---|---|
| `jcs-n` | RFC 8785 JCS over a normalized JSON object (null, empty-array, and empty-object members removed bottom-up); SHA-256; lowercase hex | draft-mih-sokolov-scitt-payload-binding | Registered |
| `cde-n` | CDE/dCBOR normalization; SHA-256 | draft-mih-sokolov-scitt-payload-binding | **Reserved** (defined in a subsequent revision) |

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

Conformance vectors: [`vectors/jcs-n/`](vectors/jcs-n/) — the canonical test suite
for algorithm `jcs-n`, covering Known-Answer Tests (including the E3 boundary
group: null, empty-array, empty-object, and absent field all normalize to the
same canonical form), derived-identifier construction, and typed-reference
verification cases including MUST-FAIL cases.

## Artifact Type Registry

Records the artifact types that may appear in the `type` field of a typed digest
reference. Registration template: **Name**, **Digest Context** (the preimage rule
— field set selected, exclusion set applied — the canonicalization algorithm name
from the Algorithm Registry, and the output representation), **Reference** (draft
§11.2).

| Name | Digest Context | Reference | Status |
|---|---|---|---|
| `agent-action-capsule` | `jcs-n`; exclusion set `{capsule_id, chain}`; 64-char lowercase hex | draft-mih-scitt-agent-action-capsule | Registered — first payload profile |

Proposed Artifact Type entries awaiting their owners' confirmation are listed in
[`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md).
