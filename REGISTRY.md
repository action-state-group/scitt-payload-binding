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

**Vector-backed means: shared core suite PLUS a mutation probe on every
profile-specific check.** A profile's own vectors REUSE the shared CPB core
conformance suite for the binding layer — canonicalization, derived-id,
typed-ref, and representation are profile-agnostic and are exercised by the same
core cases for every entry. Any PROFILE-SPECIFIC check a profile adds MUST ride
the mutation-probe discipline institutionalized in
[`.github/check_vectors.py`](.github/check_vectors.py): every new check family
registers a condition-removed mutant generator (or is declared exempt), or the
suite refuses to count that family as exercised — an assertion-free check (one
whose condition-removed mutant still passes) fails CI. Therefore "vector-backed"
for a new registry entry means BOTH: the entry passes the shared CPB core suite,
AND each of its own profile-specific checks carries a mutation probe. This is
what makes every future registry slot inherit the same rigor automatically — a
registered profile cannot ship a weak or assertion-free check, because the suite
will not certify a check family it cannot flip.

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

This controlled vocabulary applies to **new entries registered going forward**.
Every new registry entry carries a `status` field drawn from the following terms;
registrars MUST use them verbatim.

| Status | Meaning |
|---|---|
| `owner-confirmed` | The profile's author or owner approved the entry text (via PR approval, email ack, or equivalent on-record confirmation). Highest-provenance status. |
| `third-party-documented` | Registered by someone other than the owner, from publicly pinned artifacts (spec revision + repo commit). Registrant is named in the entry. Owner has been notified and invited to review. Not yet confirmed by owner. |
| `provisional` | A reference resolves but the vector set is incomplete or the specification is insufficiently pinned. Entry is held in [`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md) until vectors and pinning are complete. |

Statuses are not permanent — see [Entry Lifecycle](#entry-lifecycle) below.

**Legacy mapping for pre-existing rows.** The live tables above predate this
vocabulary and are NOT rewritten to it; they are read through the following
mapping so policy and record do not contradict:

- An existing **`Registered`** status (the Payload Canonicalization Algorithm
  Registry Status column, and the prose "Status: Registered" line on the
  `agent-action-capsule` Artifact Type entry) maps to **`owner-confirmed`** — it
  denotes an owner-confirmed, live entry.
- **`Reserved`** is NOT a lifecycle status. It marks a pre-registration hold on a
  name (e.g. `cde-n`, defined in a subsequent revision) and sits outside this
  vocabulary entirely; it is neither `owner-confirmed`, `third-party-documented`,
  nor `provisional`, and does not transition along the lifecycle until it is
  registered as a live entry.

Existing rows keep their current wording; the mapping above is the reconciliation,
not a relabeling.

---

## Registration Ladder

Three rungs of provenance, from cleanest to minimum-viable:

**Rung 1 — Owner-authored.**
The profile's owner opens the PR and supplies all fields directly.
The registrar (CPB editor) reviews for completeness and correctness, then merges.
Entry enters the live tables with status `owner-confirmed`.
This is the cleanest provenance and the preferred path — **except** where the owner
also holds a registry-editor or CPB draft co-author role. In that case the entry is
owner-authored and is not independent or third-party validation: the same party authored
the construction, wrote the registry policy, and confirmed the row. A `Disclosure` field
is required (see [Required fields](#entry-template)); the disclosure is the mechanism
that makes the independence posture of the entry computable from the record rather than
asserted by whoever reads it. The consequence of omitting it is that `owner-confirmed`
entries from registry editors are indistinguishable in the record from entries confirmed
by parties with no shared authorship, which is the property the field exists to preserve.

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
promoted directly to `owner-confirmed` (owner-direct path, see [Entry Lifecycle](#entry-lifecycle))
or to `third-party-documented` (Rung 2).

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
   **Note:** a structural registry-table checker (template conformance, column counts,
   required-field presence) is not yet implemented. Until it exists, the CPB editor is
   the only gate — a conforming-looking PR that omits a required field (e.g. `Disclosure`,
   `Vectors`) will merge without complaint. A checker is planned; track progress on the
   open issue. Until the checker lands, reviewers MUST verify required fields manually
   against this template.
5. **Maintainer review.** A CPB editor reviews for completeness, accuracy, and policy
   compliance. For third-party entries, the editor notifies the owner.
6. **Merge.** On approval, the entry moves into the live tables in `REGISTRY.md`.

### Entry Template

The flat single-row templates below are the shape for the Payload Canonicalization
Algorithm Registry, and for simple Artifact Type entries. They are **not the only
shape.** An Artifact Type entry MAY instead take the form the live
`agent-action-capsule` entry uses: a **named subsection** (`### <name>`) carrying a
multi-column **Digest Context** sub-table (one row per digest context) plus a
`Reference:` line, with the entry's **Status expressed as a prose
`Status:` line** rather than a per-row Status column. Use the flat row for a simple
one-context artifact type; use the named-subsection form when an entry has multiple
digest contexts or otherwise does not fit a single flat row. In both shapes the
same required fields (below) and the same status vocabulary apply.

For a flat-row entry, add one row to the appropriate registry table per entry.
For new entries that are third-party or provisional, also add the `Registrant` column
(or, in the named-subsection form, a `Registrant:` prose line).

**Payload Canonicalization Algorithm Registry — new row (owner-authored):**

```
| `<name>` | <description of normalization algorithm, hash, and output format> | <draft or RFC reference> | `<status>` |
```

**Payload Canonicalization Algorithm Registry — new row (third-party-documented):**
A third-party algorithm entry uses the same four-column flat row as above, and appends
a `Registrant:` prose line immediately following the table row (not a fifth column — the
Algorithm Registry table is four columns; a fifth column makes it ragged):

```
| `<name>` | <description> | <draft or RFC reference> | `third-party-documented` |

⌙ Registrant: Registered by <registrant> from <spec-rev> / commit `<hash>`.
```

**Artifact Type Registry — new row (owner-authored or owner-confirmed):**

```
| `<name>` | `<algorithm>`; exclusion set `{<fields>}`; <output format> | <draft or RFC reference> | `<status>` |
```

**Artifact Type Registry — new row (third-party-documented):**
Use the named-subsection form (`### <name>`) to accommodate the `Registrant:` and any
`Disclosure:` prose lines without adding a fifth column to a four-column table:

```
### `<name>`
**Reference:** <draft or RFC reference>
**Status:** third-party-documented
**Registrant:** Registered by <registrant> from <spec-rev> / commit `<hash>`.

| Purpose | Profile version | Algorithm | Field set | Exclusion set | Domain separation | Pre-image encoding | Representation |
|---|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... | ... |
```

**Required fields for all entries:**

| Field | Required | Notes |
|---|---|---|
| Name | Yes | The controlled identifier used in the `type` field or algorithm name. |
| Description / Digest Context | Yes | For algorithms: normalization + hash + output. For artifact types: algorithm, exclusion set, output format. |
| Reference | Yes | Publicly available specification (Internet-Draft, RFC, or a pinned repository revision). When citing a repository, a commit hash is mandatory — a branch or tag alone is not a pin, since both can move after the fact. |
| Status | Yes | For new entries: one of `owner-confirmed`, `third-party-documented`, `provisional` (expressed as a Status column or, in the named-subsection form, a prose `Status:` line). Legacy `Registered`/`Reserved` rows are read via the mapping in [Entry Status Vocabulary](#entry-status-vocabulary). |
| Registrant | Third-party only | Self-attestation: "Registered by X from Y at commit Z." Retained on upgrade to `owner-confirmed` when a `Disclosure` is also present — dropping it would destroy the provenance the disclosure exists to preserve. |
| Vectors | Yes — all entries | Link to the vector set (owner's published set, or the entry's own if the owner produced it). Third-party entries MUST cite the owner's published vector set and MUST NOT fabricate one. Owner-authored entries that have not yet published a two-sided vector set are `provisional`. |
| Disclosure | When owner or confirmer holds a CPB editor or draft co-author role | Required prose statement in the entry. Take the disclosing party's own wording verbatim — it is their name and their role. Model text from the first instance: "Disclosure: the owner is a co-author of the CPB draft and a co-editor of this registry; this entry is owner-authored and is not independent or third-party validation." A `Disclosure` field makes independence computable from the record rather than remembered by the reader. |

---

## Entry Lifecycle

Entries move through statuses in one direction only (toward higher provenance):

```
provisional  →  third-party-documented  →  owner-confirmed
             ↘                                             ↗
                     (owner-direct, skipping Rung 2)
```

- **`provisional` → `third-party-documented`:** vectors land and source artifacts are
  sufficiently pinned; registrant opens a PR updating the status and moving the entry
  from `spec/cpb-provisional-registry.md` into the live tables.
- **`provisional` → `owner-confirmed` (direct, skipping `third-party-documented`):**
  the entry's own author or owner supplies the missing fields and vectors, opens or
  takes over the PR; registrar merges. Skipping the middle rung is legitimate here
  precisely because no third-party representation is made — the confirmer IS the owner,
  so there is no registrant to name and no third-party claim to validate. The entry
  carries no `Registrant` line and enters as `owner-confirmed`. If a `Disclosure` is
  required (see [Required fields](#entry-template)), it is included in the same PR.
- **`third-party-documented` → `owner-confirmed`:** owner acknowledges the entry (PR
  approval or email on record); registrar updates the status field. The `Registrant`
  self-attestation note is retained when a `Disclosure` is also present (dropping it
  would destroy the provenance the disclosure exists to preserve); otherwise it may be
  removed or retained, per owner preference.
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
