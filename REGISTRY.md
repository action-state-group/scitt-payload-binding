# Registries of record — Canonical Payload Binding

**Status.** This document is the **interim registry of record** for the two
Canonical Payload Binding (CPB) registries, until RFC publication establishes the
corresponding IANA registries. The registries and their normative definitions are
in the Internet-Draft (`draft-mih-sokolov-scitt-payload-binding`, this
repository's `spec/`), **§13 (IANA Considerations)**. Registration policy:
**Specification Required** per [RFC 8126 §4.6]; a Designated Expert is required
for each registration. **Entries are immutable in behavior** — if a behavior
change is needed (a different canonicalization algorithm, field set, or
exclusion set), a new entry MUST be registered; an entry's registered behavior
MUST NOT be modified retroactively. This does not bar the two narrower edits
described below, neither of which changes what the entry specifies: a factual
correction to bibliographic detail (see [Removal and Correction](#removal-and-correction))
or a status transition along the [Entry Lifecycle](#entry-lifecycle) (e.g.
`third-party-documented` → `owner-confirmed`).

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
| `jcs-n` | Withdrawn — never carried to IANA (2026-08-18). RFC 8785 JCS over a normalized JSON object (null, empty-array, and empty-object members removed bottom-up); SHA-256; lowercase hex — the construction this entry named. See [`docs/audits/jcsn-withdrawal-audit-2026-08-18.md`](docs/audits/jcsn-withdrawal-audit-2026-08-18.md) for the withdrawal rationale. | draft-mih-sokolov-scitt-payload-binding | `withdrawn` |
| `jcs` | RFC 8785 JCS over a JSON object (no normalization pass; null, empty-array, and empty-object members are retained as-is); SHA-256; lowercase hex | RFC 8785 §3 | `standards-referenced` |
| `cde-n` | Withdrawn — the token was reserved for a deterministic CBOR canonicalization profile and never assigned a definition | draft-mih-sokolov-scitt-payload-binding | `withdrawn` |
| `as-transmitted` | No canonicalization: the pre-image is the exact octet sequence identified by a cited named production in the container format (e.g., a signature's signing input); an artifact type entry using this algorithm states a byte-boundary selector in place of a field set; SHA-256; 64-character lowercase hex | draft-mih-sokolov-scitt-payload-binding | Registered |

**jcs-n — withdrawal disposition (2026-08-18).** `jcs-n` is withdrawn entirely, the
same disposition as `cde-n`: a recorded terminal state, not a deletion. The token
stays bound and is never reassigned. This row, the two implementation notes below
it, and the `vectors/jcs-n/` conformance suite are **retained exactly as
registered** — nothing here is edited retroactively — because
`draft-mih-sokolov-scitt-payload-binding-00` cites them as the permanent record of
the construction IETF-126-era implementations actually built. Existing records
committed under `jcs-n` (see the `agent-action-capsule` Artifact Type entry below)
remain verifiable against it by vintage. No new record may declare `jcs-n`; a
tolerant-ingest use case, if one ever materializes, registers a fresh entry with
domain separation designed in rather than reviving this token. The full
rationale — implementer census, byte-audit result, and the admission-bar test the
entry failed — is in
[`docs/audits/jcsn-withdrawal-audit-2026-08-18.md`](docs/audits/jcsn-withdrawal-audit-2026-08-18.md).

**Why `machine-mandate` does not register an algorithm of its own.** An earlier
revision of this entry registered `json-sk-cp` — RFC 8785 with no member removal,
code-point key ordering, and integers only. Since `jcs` was registered, that name
would differ from it on exactly two points: the number restriction, and code-point
rather than UTF-16 key ordering, which diverge only for non-BMP keys. Recomputed
against the owner's own pinned vector set, every input produces a **byte-identical
pre-image and an identical digest** under `jcs`. A second registered name for the
same bytes buys nothing and costs an entry that cannot be told apart from its
neighbour, so the constraints now live where they belong: in the digest context of
the artifact type that relies on them, below.

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
| `identifier` | `draft-mih-scitt-agent-action-capsule-04` | `jcs` | all capsule fields | `{capsule_id}` | none | JCS UTF-8 octets (per `jcs`) | 64-char lowercase hex |

Content unchanged from the prior 3-element shape — only the shape changed to the
full digest-context template above. Domain separation and pre-image encoding are
not new owner-supplied parameters: both are stated directly by `jcs-n`'s own
normative definition, not invented for this row.

**Second digest context (`jcs`, profile version -04).** `jcs-n` was withdrawn on
2026-08-18 and nothing verifies against it — see its `withdrawn` row in the Payload
Canonicalization Algorithm Registry above — so the first row is a vintage
verification path and **no live digest context remained for this artifact type**.
Profile version -04 supplies one: capsules declare `canonicalization_id: "jcs"` and
the identifier is SHA-256 over plain JCS of the capsule with **only `capsule_id`**
removed. The `canonicalization_id` declaration and the `chain` block **participate**.
That exclusion set is the whole difference from the vintage row, and it is why this
is a separate digest context rather than an edit of the existing one: the registered
behavior of the `jcs-n` row is untouched, as the immutability rule in the policy
header requires. Two rows under one entry is exactly what the registration template
anticipates — one entry, one row per digest context, profile version stated per
context.

⌙ Registrant: added by Anton Sokolov, read from the `spec_version`,
  `format_version`, `canonicalization_id` and `capsule_id` rows of the Capsule field
  table in `draft-mih-scitt-agent-action-capsule-04`, at
  `action-state-group/agent-action-capsule` commit
  `8ccf345731360bbaa421141e0936e6b189053d0f`.
⌙ Disclosure: the registrant is a co-author of the CPB draft and a co-editor of this
  registry, and is **not** the owner of this artifact type. This row is a third-party
  reading of the owner's own specification text and is **pending owner confirmation**
  before it is treated as owner-confirmed.
⌙ Discriminating-vector: `test-vectors/pos-v4-jcs-chain-committed/` in the artifact
  type's own repository — *"Format 4 plain JCS commits the chain block and a present
  empty array to capsule_id"*, recomputed identifier
  `862024869f00481bb4f59d9528a45c2d4885f64c5222a9324a38ac2c2cd119f2`. Recomputed
  from that vector's input with the artifact type's own JCS implementation, the two
  exclusion sets do not agree, and the difference is stated here rather than
  asserted:

  | Exclusion set | SHA-256 over JCS of the remainder |
  |---|---|
  | `{capsule_id}` (this row) | `862024869f00481bb4f59d9528a45c2d4885f64c5222a9324a38ac2c2cd119f2` — matches the vector |
  | `{capsule_id, chain}` (vintage row) | `1164b5696cf27d9c13965de1929b8e2b14097b7824f25e63f9ac7e954369d886` — does not |

  The two contexts are therefore not interchangeable on a record that carries a
  `chain` block, which is what makes this a distinct digest context and not a
  restatement of the vintage one.

### `machine-mandate`

**Owner:** Anton Sokolov, Tyche Institute
**Reference:** `tyche-institute/machine-mandate` @ `524e6a3129b7f1ab850dd9471967458d3cb6f4cd`
**Status:** owner-confirmed
**Provenance:** confirmed by the owner in the PR #4 thread (2026-08-09 and 2026-08-13); the second Artifact Type Registry entry.
**Disclosure:** the owner is a co-author of the CPB draft and a co-editor of this registry; this entry is owner-authored and is not independent or third-party validation.
**Discriminating-vector:** `mm-fail-04-representation-confusion` — pins that this
type's two representations are not interchangeable (the derived identifier is bare
hex; the in-document `action_hash` carries the `sha256:` prefix). `agent-action-capsule`,
the only other registered artifact type, declares a single context in bare hex, so a
verifier that accepted either form for either context would pass its cases and fail
these. Cited at the commit-pinned URL below, not committed here — this entry's vectors
are the owner's own published set.
**Consuming-profile:** `action-state-group/scitt-cose` @ `04cf97a8d143459b7dd4193ba4d8c065c3783071`
— the hosted verification surface at `verify.agentactioncapsule.org`. It parses and
renders this type under the name `machine-mandate` (`hosted_profiles/machine_mandate.py`,
`PROFILE_PARSERS["machine-mandate"]`), against fixtures copied byte-verbatim from
`tyche-institute/machine-mandate@524e6a3` — the same commit this entry's Reference pins.
**What it does not do, stated plainly so the Designated Expert can weigh it:** it detects
the profile by the owner-controlled VCT URI and by pinned fixture digests, not by resolving
the type through this registry, and its own module text disclaims endorsement. Whether a
deployment that consumes the vocabulary without resolving the artifact type satisfies Gate B
is the DE's call, not the registrant's — and the registrant is the owner, which is why it is
put this way rather than asserted.
**Vectors:** the conformance-vector set pinned below.

| Purpose | Profile version | Algorithm | Field set | Exclusion set | Domain separation | Pre-image encoding | Representation |
|---|---|---|---|---|---|---|---|
| `identifier` | N/A | `as-transmitted` | byte-boundary selector — the issuer-signed JWS component of the SD-JWT (RFC 7515 §7.1 compact serialization; the first `~`-separated component exactly as transmitted); everything after the first `~` is outside the pre-image | N/A (`as-transmitted` has no field set) | none | N/A (no separate encoding step) | bare 64-char lowercase hex |
| `equivalence` | N/A | `jcs` | `{action_id, outcome}`, closed — every member is a string; a floating-point value is rejected rather than digested, and an integer whose magnitude exceeds 2^53−1 (the ECMAScript safe-integer bound) is rejected as a typed error rather than serialized | none | none | JCS UTF-8 octets (per `jcs`) | `sha256:` + 64-char lowercase hex, as carried in the in-document `action_hash` claim |

**Key ordering, for the record.** `jcs` sorts member names by UTF-16 code unit
(RFC 8785 §3.2.3); the retired `json-sk-cp` sorted by Unicode code point. The two
orders differ only when a member name contains a non-BMP character. This entry's
field set is closed to `{action_id, outcome}`, so the case cannot arise here — and
the pinned vectors were recomputed under `jcs` before this entry moved to it: every
pre-image and digest is byte-identical to the values pinned below.

**Conformance vectors:** `tyche-institute/machine-mandate`, branch
`feat/cpb-registry-vectors-v0.1`, commit `5605783a` (supersedes
`640f2a668cfc4a357f9b34ecb0add5faf8bbdda1`),
`vectors/cpb-registry/machine-mandate-vectors-v0.1.json`, file SHA-256
`06572fccb7afa3eda4c68604221a83476faac8f8509b7165724553d58384d816`.
Independently reproduced byte-for-byte, including condition-removed
mutants confirming each of the five negatives discriminates rather than
pattern-matches (PR #4 thread, 2026-08-11).

Proposed Artifact Type entries awaiting their owners' confirmation are listed in
[`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md).


---

## Entry Status Vocabulary

This controlled vocabulary applies to **new entries registered going forward**.
Every new registry entry carries a `status` field drawn from the following terms;
registrars MUST use them verbatim.

| Status | Meaning |
|---|---|
| `owner-confirmed` | The profile's author or owner approved the entry text. Highest-provenance status; see [Designated Expert Admission Checklist](#designated-expert-admission-checklist), Gate C for the acknowledgment forms accepted and when a consuming-profile ACK is also required. |
| `third-party-documented` | Registered by someone other than the owner, from publicly pinned artifacts (spec revision + repo commit). Registrant is named in the entry. Owner has been notified and invited to review. Not yet confirmed by owner. |
| `provisional` | A reference resolves but the vector set is incomplete or the specification is insufficiently pinned. Entry is held in [`spec/cpb-provisional-registry.md`](spec/cpb-provisional-registry.md) until vectors and pinning are complete. |
| `standards-referenced` | The entry's construction is fully specified by a published standard (RFC, ISO, or equivalent) rather than by a party who can acknowledge anything. There is no owner to ack, so `owner-confirmed` is unreachable by construction and its absence is not a provenance gap. Gates A and B still apply, and the Reference row MUST cite the standard to section precision. |
| `withdrawn` | The token stays bound but will never (again) be carried forward to a live registration — whether it was a reserved token never assigned a definition, or a previously-registered entry whose definition is retired. A terminal state, not a deletion: the name is not reassigned, any definitional text already written is retained unedited as the historical record of the construction, and a later construction of the same kind registers under a different token. Nothing verifies against it — a verifier meeting it MUST fail closed. |

Statuses are not permanent — see [Entry Lifecycle](#entry-lifecycle) below.

**Designated Expert review is a merge precondition, not a status.** An entry in the
live tables has, by definition, passed the gates required for its rung — that is what
admission means. Pending DE review is therefore a state of the *pull request*, not of
the entry, and MUST NOT be written into a Status cell: a merged entry whose status says
"pending review" states a condition that merging already discharged. Statuses in the
live tables are the vocabulary terms above, used verbatim.

**Legacy mapping for pre-existing rows.** The live tables above predate this
vocabulary and are NOT rewritten to it; they are read through the following
mapping so policy and record do not contradict:

- An existing **`Registered`** status (the Payload Canonicalization Algorithm
  Registry Status column, and the prose "Status: Registered" line on the
  `agent-action-capsule` Artifact Type entry) maps to **`owner-confirmed`** — it
  denotes an owner-confirmed, live entry.
- **`Reserved`** is NOT a lifecycle status. It marks a pre-registration hold on a
  name whose definition is deferred to a subsequent revision, and sits outside this
  vocabulary entirely; it is neither `owner-confirmed`, `third-party-documented`,
  nor `provisional`, and does not transition along the lifecycle until it is
  registered as a live entry.

**The legacy spellings are closed to new entries, and the list is finite.** Exactly
two rows predate this vocabulary and keep a legacy spelling: the algorithm entry
`as-transmitted` and the artifact type `agent-action-capsule`. (`jcs-n` and `cde-n`
predate it too, but both now carry the vocabulary term `withdrawn` rather than a
legacy spelling.) No other entry may
carry `Registered` or `Reserved`. Naming them here rather than describing them is
deliberate: the generator has no history to consult, so without a closed list it
cannot tell a pre-existing row from a new one writing a legacy spelling — and a new
entry spelled `Registered — owner-confirmed (…)` would pass validation while
violating the verbatim rule two paragraphs above.

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
Status upgrades to `owner-confirmed` once the acknowledgments
[Gate C](#designated-expert-admission-checklist) requires are complete — the owner ACK,
plus the consuming-profile ACK that Rung 1 admission requires and Rung 2 admission does
not, unless the owner and the consuming-profile maintainer are the same party. A Rung 2
entry does not reach `owner-confirmed` on owner ACK alone if that consuming-profile ACK
was never obtained; see Gate C for the full requirement and why.

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

6. **Accept upgrade to `owner-confirmed` on the acknowledgments
   [Gate C](#designated-expert-admission-checklist) requires for this rung.** For a
   Rung 2 entry this is the owner ACK plus, if not already given, the consuming-profile
   ACK — see Gate C's upgrade checkbox for the accepted forms and the reason a Rung 2
   entry cannot skip the consuming-profile ACK that Rung 1 requires at admission.

CPB editors MUST NOT fill in owner-supplied fields (Digest Context, vector references) on the
owner's behalf. If a required field cannot be sourced from public artifacts, the entry is
`provisional`.

---

## Designated Expert Admission Checklist

**What the DE checks before admitting any entry to the live tables.** An entry that fails a
gate required for its rung is returned for correction and does not enter the live tables until
every gate required for that rung passes. Gates A and B apply to every entry regardless of
rung. Gate C's admission requirement differs by rung — see the rung-specific checkboxes within
Gate C below: a Rung 1 entry needs the owner ACK (satisfied by the PR itself) plus a
consuming-profile maintainer ACK, unless owner and maintainer are the same party; a Rung 2
entry needs neither ACK at admission and is admitted as `third-party-documented` once it
satisfies the [Third-Party Registration Rules](#third-party-registration-rules) — no ACK is
required of it, but Gates A and B bind it exactly as they bind every other entry. These
are the DE's verification steps; the [Required fields](#entry-template) table is the
corresponding author-side declaration.

**Gate A — Discriminating Vector**

- [ ] The entry's `Discriminating-vector` field names a committed conformance test case (positive
  or MUST-FAIL) in `vectors/<name>/` in the same PR, or cites a commit-pinned external URL.
  **The "in the same PR" branch is closed to Rung 2 entries** by Third-Party Registration
  [Rule 4](#third-party-registration-rules): a Rung 2 registrant cannot commit a fresh vector
  for someone else's construction without fabricating it, so a Rung 2 entry MUST use the
  commit-pinned external URL branch, citing the owner's already-published vector set.
- [ ] The vector passes for this entry and does NOT pass (or is not applicable) for at least one
  currently registered neighbour in the same registry table — tested in both directions.
- [ ] No currently registered neighbour's own discriminating vector passes for this entry.

A vector that is shared with or identical to an existing entry's discriminating vector does NOT
satisfy Gate A — it demonstrates compatibility, not distinguishability.

**Gate B — Named Consuming Profile**

- [ ] The entry's `Consuming-profile` field names at least one consuming profile: a distinct
  specification or deployment that uses this registered name in a normatively stated way.
- [ ] Every named consuming profile is cited with a spec-revision pin: Internet-Draft version,
  RFC number, or commit hash. A project name or bare URL alone is not a pin.
- [ ] The entry's own specification is NOT counted as a consuming profile.

**Gate C — Owner and Consuming-Profile ACK**

- [ ] **Rung 1 (owner-authored) admission:** the PR itself constitutes the owner ACK. At least
  one maintainer of each named consuming profile must also acknowledge, via PR approval,
  on-record email, or a GitHub comment on the PR from a confirmed identity, that their profile
  is correctly named as a consumer — unless the owner and consuming-profile maintainer are the
  same party.
- [ ] **Rung 2 (third-party-documented) admission:** neither the owner ACK nor the
  consuming-profile ACK is required. The entry enters the live tables as
  `third-party-documented` once it satisfies the
  [Third-Party Registration Rules](#third-party-registration-rules). No ACK is required
  of a Rung 2 entry; Gates A and B still bind it.
- [ ] **Upgrade to `owner-confirmed` (either rung):** any unambiguous acknowledgment from the
  entry's owner (or a named authorized delegate) — via PR approval, on-record email, or a
  GitHub comment on the PR from a confirmed owner identity — upgrades the entry, provided the
  consuming-profile ACK that Rung 1 admission requires (above) has also been obtained by this
  point, unless the owner and the consuming-profile maintainer are the same party. This closes
  a bypass: without this proviso, an owner could avoid the Rung 1 consuming-profile ACK simply
  by having a third party file the entry at Rung 2 (no ACK required at admission) and then
  acking it themselves — reaching `owner-confirmed` without ever clearing the bar a Rung 1
  entry clears at admission. The registrar solicits any outstanding consuming-profile ACK at
  the same time as the owner ACK.

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
4. **CI must pass.** The repository CI gate runs five workflows (`dco`, `neutrality`,
   `python`, `spec`, `vectors`); of these, `dco` and `neutrality` have no path filter and run
   on every PR, while `python`, `spec`, and `vectors` are scoped to `lib/**`, `spec/**`, and
   `vectors/**` respectively and do not run on a `REGISTRY.md`-only change. **None of these
   checks structural validity of the registry tables** — no CI job verifies template
   conformance, column counts, or required-field presence in `REGISTRY.md`. A PR with failing
   CI will not be merged, but a green CI run is not evidence the registry-table edit itself is
   well-formed. A structural registry-table checker is planned; track progress on the open
   issue. Until it lands, the CPB editor and Designated Expert are the only gates — a
   conforming-looking PR that omits a required field (e.g. `Discriminating-vector`,
   `Consuming-profile`, `Disclosure`, `Vectors`) will merge without automated complaint.
   Reviewers MUST verify required fields manually against this template, and the DE MUST
   verify all three gates in the
   [Designated Expert Admission Checklist](#designated-expert-admission-checklist).
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

**Algorithm Registry — new row (any status):**

```
| `<name>` | <description: construction; digest; representation> | <draft or RFC reference> | `<status>` |
```

An Artifact Type entry is never a bare table row: every artifact type states one or
more digest contexts, and every digest context states all eight parameters of the
[digest-context template](#artifact-type-registry). Use the named-subsection forms
below — a single-context entry is the degenerate case of that template, not a
shorter one.

**Artifact Type Registry — new entry (third-party-documented):**
Use the named-subsection form (`### <name>`) to accommodate the `Registrant:` and any
`Disclosure:` prose lines without adding a fifth column to a four-column table:

```
### `<name>`
**Reference:** <draft or RFC reference>
**Status:** third-party-documented
**Registrant:** Registered by <registrant> from <spec-rev> / commit `<hash>`.
**Discriminating-vector:** vectors/<name>/<case-id>.json — <one-line description of what it distinguishes>
**Consuming-profile:** <spec-rev or RFC number of the consuming specification>

| Purpose | Profile version | Algorithm | Field set | Exclusion set | Domain separation | Pre-image encoding | Representation |
|---|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... | ... |
```

**Artifact Type Registry — new entry (owner-authored or owner-confirmed):**
Use the same named-subsection form, with one digest-context row per context. Add
`Discriminating-vector:` and `Consuming-profile:` prose lines; omit `Registrant:` for
owner-authored entries:

```
### `<name>`
**Reference:** <draft or RFC reference>
**Status:** owner-confirmed
**Discriminating-vector:** vectors/<name>/<case-id>.json — <one-line description of what it distinguishes>
**Consuming-profile:** <spec-rev or RFC number of the consuming specification>

| Purpose | Profile version | Algorithm | Field set | Exclusion set | Domain separation | Pre-image encoding | Representation |
|---|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... | ... |
```

For flat-row Algorithm Registry entries, append `Discriminating-vector:` and `Consuming-profile:`
as prose lines immediately following the table row (matching the pattern used by the third-party
`Registrant:` line):

```
| `<name>` | <description> | <reference> | `<status>` |

⌙ Discriminating-vector: vectors/<name>/<case-id>.json — <one-line description>
⌙ Consuming-profile: <spec-rev or RFC number>
```

**Required fields for new entries.** These fields apply to entries registered under
this template going forward. The live rows that predate it — `jcs-n`, `cde-n`,
`as-transmitted`, and `agent-action-capsule` — are read through the same legacy
treatment [Entry Status Vocabulary](#entry-status-vocabulary) gives their Status: they
are not retroactively required to backfill Discriminating-vector, Consuming-profile, or
a Vectors field.

| Field | Required | Notes |
|---|---|---|
| Name | Yes | The controlled identifier used in the `type` field or algorithm name. |
| Description / Digest Context | Yes | For algorithms: normalization + hash + output. For artifact types: algorithm, exclusion set, output format. |
| Reference | Yes | Publicly available specification (Internet-Draft, RFC, or a pinned repository revision). When citing a repository, a commit hash is mandatory — a branch or tag alone is not a pin, since both can move after the fact. |
| Status | Yes | For new entries: one of `owner-confirmed`, `third-party-documented`, `provisional`, `standards-referenced`, used verbatim (expressed as a Status column or, in the named-subsection form, a prose `Status:` line). No qualifier text — see [Entry Status Vocabulary](#entry-status-vocabulary) on why "pending review" is not a status. Legacy `Registered`/`Reserved` rows are read via the mapping there. |
| Registrant | Third-party only | Self-attestation: "Registered by X from Y at commit Z." Retained on upgrade to `owner-confirmed` when a `Disclosure` is also present — dropping it would destroy the provenance the disclosure exists to preserve. |
| Vectors | Yes — new entries | Link to the vector set (owner's published set, or the entry's own if the owner produced it). Third-party entries MUST cite the owner's published vector set and MUST NOT fabricate one. Owner-authored entries that have not yet published a two-sided vector set are `provisional`. |
| Discriminating-vector | Yes — new entries | A conformance test case (positive or MUST-FAIL) that distinguishes this entry's construction from every currently registered neighbour in the same registry table, both directions. Committed to `vectors/<name>/` in the same PR, or cited at a commit-pinned external URL — Rung 2 (third-party) entries MUST use the external-URL branch (the "same PR" branch is closed to them by Third-Party Registration Rule 4, which forbids fabricating vectors for someone else's construction). A vector identical to or shared with an existing entry does not satisfy this field. See [Designated Expert Admission Checklist](#designated-expert-admission-checklist), Gate A. |
| Consuming-profile | Yes — new entries | At least one spec-revision-pinned reference (Internet-Draft version, RFC number, or commit hash) to a specification or deployment that uses this registered name in a normatively stated way. The entry's own specification does not count. See [Designated Expert Admission Checklist](#designated-expert-admission-checklist), Gate B. |
| Disclosure | When owner or confirmer holds a CPB editor or draft co-author role | Required prose statement in the entry. Take the disclosing party's own wording verbatim — it is their name and their role. Illustrative text, not a citation of a prior entry (none has filed this field yet): "Disclosure: the owner is a co-author of the CPB draft and a co-editor of this registry; this entry is owner-authored and is not independent or third-party validation." A `Disclosure` field makes independence computable from the record rather than remembered by the reader. |

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
- **`third-party-documented` → `owner-confirmed`:** the acknowledgments
  [Gate C](#designated-expert-admission-checklist) requires are complete — owner ACK,
  plus the consuming-profile ACK unless owner and consuming-profile maintainer are the
  same party; registrar updates the status field. The `Registrant` self-attestation
  note is retained when a `Disclosure` is also present (dropping it would destroy the
  provenance the disclosure exists to preserve); otherwise it may be removed or
  retained, per owner preference.
- **`owner-confirmed`:** terminal state for a live entry — no further status transition.
  The entry's behavior is immutable once owner-confirmed (see "Entries are immutable in
  behavior" in the policy header above). If behavior changes, a new entry MUST be
  registered rather than modifying the existing one; factual corrections remain possible
  under [Removal and Correction](#removal-and-correction).

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
`third-party-documented` to `owner-confirmed`, provided the consuming-profile ACK
[Gate C](#designated-expert-admission-checklist) requires has also been given, unless
the owner and the consuming-profile maintainer are the same party. The registrar
updates the status field and notes both acknowledgments (date and form).
