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


---

## Entry Status Vocabulary

Every registry entry carries a `status` field drawn from the following controlled vocabulary.
These values are the authoritative terms; registrars MUST use them verbatim.

| Status | Meaning |
|---|---|
| `owner-confirmed` | The profile's author or owner approved the entry text (via PR approval, email ack, or equivalent on-record confirmation). Highest-provenance status. |
| `third-party-documented` | Registered by someone other than the owner, from publicly pinned artifacts (spec revision + repo commit). Registrant is named in the entry. Owner has been notified and invited to review. Not yet confirmed by owner. |
| `provisional` | A reference resolves but the vector set is incomplete or the specification is insufficiently pinned. Entry is held in [`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md) until vectors and pinning are complete. |

Statuses are not permanent — see [Entry Lifecycle](#entry-lifecycle) below.

---

## Registration Ladder

Three rungs of provenance, from cleanest to minimum-viable:

**Rung 1 — Owner-authored.**
The profile's owner opens the PR and supplies all fields directly.
The registrar (CPB editor) reviews for completeness and correctness, then merges.
Entry enters the live tables with status `owner-confirmed`.
This is the cleanest provenance and the preferred path.

**Rung 2 — Third-party-documented.**
A third party (not the owner) registers from publicly available artifacts.
The third party MUST satisfy all [Third-Party Registration Rules](#third-party-registration-rules).
Entry enters the live tables with status `third-party-documented`.
Owner is notified by the registrar (via issue or direct contact) and invited to review.
Status upgrades to `owner-confirmed` upon any owner acknowledgment (PR approval or email on record).

**Rung 3 — Provisional.**
A reference exists but the vector set is incomplete, or the specification is insufficiently
pinned to support a complete Digest Context description.
Entry is tracked in [`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md),
not in the live tables, until the missing material lands.
Status is `provisional` until vectors and pinning are complete; then the entry may be
promoted to Rung 1 or Rung 2.

---

## Third-Party Registration Rules

Third-party registration (Rung 2) is permitted when the construction is publicly documented.
A third-party entry MUST:

1. **Pin its sources.** Name the exact specification revision (draft version or RFC number)
   and the repository commit hash from which the entry was derived.
   Example: "registered from `draft-example-foo-01`, commit `abc1234`."

2. **Name the registrant.** Include a self-attestation in the `Registrant` field.
   Example: "Registered by Action State Group from public documentation at
   `draft-example-foo-01` / commit `abc1234`."

3. **Make no conformance or endorsement claims about the owner.**
   The entry MUST NOT imply that the owner endorses this registry, vouches for the
   implementation, or has verified the entry.

4. **Cite only the owner's published vector sets.**
   Registrants MUST NOT fabricate test vectors for someone else's construction.
   If the owner has published no vectors, the entry is `provisional` (Rung 3), not Rung 2.

5. **Acknowledge the standing removal policy.**
   Owner objection removes or amends the entry, no questions asked.
   See [Removal and Correction](#removal-and-correction).

6. **Accept upgrade to `owner-confirmed` on any owner acknowledgment.**
   PR approval, email on record, or any other unambiguous owner ack upgrades the entry.

CPB editors MUST NOT fill in owner-supplied fields (Digest Context, vector references) on the
owner's behalf. If a required field cannot be sourced from public artifacts, the entry is
`provisional`.

---

## How to Register

### Step-by-step

1. **Fork** `action-state-group/scitt-payload-binding` on GitHub.
2. **Fill in the entry template** (see [Entry Template](#entry-template) below) for each
   registry table your entry appears in.
   - Owner-authored entries: fill all fields directly.
   - Third-party entries: fill all fields from public artifacts and complete the `Registrant`
     field with the self-attestation.
   - Provisional entries: file in `spec/cpb-provisional-registry.md`, not in the live tables.
3. **Open a pull request** against `main` on the upstream repository.
   PR title convention: `registry: add <name> to <Registry Name>`.
4. **CI must pass.** The repository CI gate checks structural validity of the registry tables.
   A PR with failing CI will not be merged.
5. **Maintainer review.** A CPB editor reviews for completeness, accuracy, and policy
   compliance. For third-party entries, the editor notifies the owner.
6. **Merge.** On approval, the entry moves into the live tables in `REGISTRY.md`.

### Entry Template

Add one row to the appropriate registry table per entry.
For new entries that are third-party or provisional, also add the `Registrant` column.

**Payload Canonicalization Algorithm Registry — new row:**

```
| `<name>` | <description of normalization algorithm, hash, and output format> | <draft or RFC reference> | `<status>` |
```

**Artifact Type Registry — new row (owner-authored or owner-confirmed):**

```
| `<name>` | `<algorithm>`; exclusion set `{<fields>}`; <output format> | <draft or RFC reference> | `<status>` |
```

**Artifact Type Registry — new row (third-party-documented), with Registrant column:**

```
| `<name>` | `<algorithm>`; exclusion set `{<fields>}`; <output format> | <draft or RFC reference> | `third-party-documented` | Registered by <registrant> from <spec-rev> / commit `<hash>` |
```

**Required fields for all entries:**

| Field | Required | Notes |
|---|---|---|
| Name | Yes | The controlled identifier used in the `type` field or algorithm name. |
| Description / Digest Context | Yes | For algorithms: normalization + hash + output. For artifact types: algorithm, exclusion set, output format. |
| Reference | Yes | Publicly available specification (Internet-Draft or RFC). |
| Status | Yes | One of `owner-confirmed`, `third-party-documented`, `provisional`. |
| Registrant | Third-party only | Self-attestation: "Registered by X from Y at commit Z." |
| Vectors | Third-party/provisional | Link to owner's published vector set, or state "none published — entry is provisional." |

---

## Entry Lifecycle

Entries move through statuses in one direction only (toward higher provenance):

```
provisional  →  third-party-documented  →  owner-confirmed
```

- **`provisional` → `third-party-documented`:** vectors land and source artifacts are
  sufficiently pinned; registrant opens a PR updating the status and moving the entry
  from `spec/cpb-provisional-registry.md` into the live tables.
- **`third-party-documented` → `owner-confirmed`:** owner acknowledges the entry (PR
  approval or email on record); registrar updates the status field and removes the
  `Registrant` self-attestation note (or retains it for provenance, per owner preference).
- **`owner-confirmed`:** terminal state for a live entry. Entries are immutable once
  owner-confirmed (see "Entries are immutable" in the policy header above). If behavior
  changes, a new entry MUST be registered rather than modifying the existing one.

No backward transitions. A `third-party-documented` entry does not revert to `provisional`
if new concerns arise — the registrant opens a correction PR instead (see below).

---

## Removal and Correction

### Owner-requested removal

An entry owner may request removal at any time, for any reason, by opening a pull request
or filing an issue. Removal is unconditional — no justification required.
The registrar will merge a removal PR promptly (within one working day if the request is
clearly from the owner).

Removed entries are not deleted from git history; they are moved to a `## Removed` section
at the bottom of the registry with a removal date and brief note (e.g. "removed at owner
request, 2026-07-28").

### Owner-requested correction

An owner who finds an error in their entry may open a correction PR at any time.
Corrections are an exception to the immutability rule — factual errors (wrong reference,
typo in name, incorrect Digest Context) may be corrected in place.
Behavioral changes (different canonicalization algorithm, different exclusion set) require
a new entry, not a correction.

### Third-party entry corrections

If a third-party entry contains an error, any party (owner, registrant, or CPB editor)
may open a correction PR. The same factual-vs-behavioral distinction applies.

### Upgrade to `owner-confirmed`

Any unambiguous owner acknowledgment — a PR approval, an email to the CPB editors list,
or a public statement by the owner that the entry is correct — upgrades the entry from
`third-party-documented` to `owner-confirmed`. The registrar updates the status field and
notes the acknowledgment (date and form).
