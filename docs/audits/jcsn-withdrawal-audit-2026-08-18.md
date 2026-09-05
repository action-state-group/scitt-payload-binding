# `jcs-n` withdrawal audit — 2026-08-18

**Status.** This is the inspectable record behind the `jcs-n` withdrawal
marked in [`REGISTRY.md`](../../REGISTRY.md) (Payload Canonicalization
Algorithm Registry) and in
[`spec/draft-mih-sokolov-scitt-payload-binding-01.md`](../../spec/draft-mih-sokolov-scitt-payload-binding-01.md)
§13.1 (IANA Considerations). It is committed here — not merely referenced —
so the audit is available to any reader without a side channel.

**Disposition.** `jcs-n` is withdrawn entirely (2026-08-18): a recorded
terminal state, not a deletion. The registry definition, its two implementation
notes, and its `vectors/jcs-n/` conformance suite remain the historical record;
later editorial clarifications do not change the byte construction. The token
stays bound and is never reassigned;
`draft-mih-sokolov-scitt-payload-binding-00` remains the permanent record of
the construction IETF-126-era implementations built. Same disposition as
`cde-n`.

## Withdrawal rationale

**1. Implementer census.** `jcs-n`'s implementer population was exactly
one: Action State. The capsule reference implementation and `capsule-emit`
are the only code that ever computed `jcs-n`, and the `agent-action-capsule`
profile is moving to plain `jcs` regardless of this decision. No independent
party ever implemented the normalization step.

**2. Byte audit result.** A byte audit recomputed every record this project
holds under plain RFC 8785 (`jcs`, no normalization) and compared the
result to the digest actually stored, on the identity that normalization
changes bytes only when a record carries a null, empty-array, or
empty-object member. Executed 2026-08-18: **191 of 203 evaluated records
match byte-for-byte under plain `jcs`** — the production and reference
corpora are clean, exactly as the identity predicts. The 12 records that
diverge are enumerated below; all 12 are mesh sidecar proof-of-concept
demo artefacts, not evidentiary records. Their stored digests remain
reproducible under `jcs-n`; a verification verdict additionally requires
profile-defined cryptographic evidence binding the record or digest to a time
before the withdrawal cutoff. See [Per-record-set table](#per-record-set-table)
for the full breakdown, including the non-evaluated (skip/error/sanity-fail)
rows.

**3. Admission bar.** This project's own admission bar — no algorithm entry
registers without a named consuming profile — is a bar `jcs-n`, read as a
prospective tolerant-ingest algorithm, fails today: it names zero consuming
profiles. Nothing outside this project's own reference implementation
declares or depends on `jcs-n`.

**4. Forward rule.** If a tolerant-ingest use case for absent-field
normalization ever materializes, it registers as a **fresh entry** —
better-specified, with domain separation designed in from the start rather
than bolted on after the fact — never by reviving or redefining `jcs-n`.

These three findings were also the basis for withdrawing `jcs-n` in the
*stronger* form (full withdrawal) rather than the grandfather-clause form
originally proposed. Anton Sokolov re-concurred to the stronger form on
these facts (email, 2026-08-18 20:34 PDT: "Withdraw it entirely — you have
my yes on the stronger form, asked fresh as you did").

## Per-record-set table

A **match** confirms normalization was a no-op for that record (no null,
empty-array, or empty-object member); a **mismatch** confirms normalization
changed the bytes. See [Method](#method) below for how each figure was
produced and self-verified.

**Scrub note.** Two record sets below are internal (operator-side) and are
not identified by repository, filename, or engagement name in this
public document — only by a generic label and the aggregate counts. All
other sets are public repositories already named in this project's own
`CLAUDE.md`/README (the reference library, the producer-library examples,
the mesh sidecar proof-of-concept, and the IETF conformance vectors) and
carry no internal naming.

| Record set | N | Match | Mismatch | Skip | Error | Sanity-fail |
|---|---:|---:|---:|---:|---:|---:|
| Reference-library test fixtures (public repo) | 59 | 59 | – | – | – | – |
| Producer-library example records (public repo) | 105 | 105 | – | – | – | – |
| Mesh sidecar proof-of-concept ledger (public repo) | 12 | 0 | 12 | – | – | – |
| IETF conformance vectors (public repo) | 29 | 26 | – | 2 | – | 1 |
| Reference profile's own ledger (public repo) | 1 | 1 | – | – | – | – |
| Operator-internal corpus A (private engine's own demo ledger — non-production fixture; repository, path, and per-record identifiers withheld) | 18 | 0 | – | – | 6 | 12 |
| Operator-internal corpus B (a paused external engagement; no scoped read path was ever established for it — 0 records is a documented gap, not a failure of the audit) | 0 | 0 | – | – | – | – |
| **Total** | **224** | **191** | **12** | **2** | **6** | **13** |

**Verdict: 12/203 evaluated records (match + mismatch) diverge under
normalization.** All 12 are accounted for below. The 2 skipped and 13
sanity-fail records are negative/non-`jcs-n` test material by design (see
notes below the table); the 6 error records are pre-existing
spec-violations in Operator-internal corpus A unrelated to the `jcs`/`jcs-n`
distinction (a JSON floating-point value in a digest-bearing field, which
§5.1 of the CPB draft requires as an exact decimal string). None of the 21
non-evaluated records bears on the production-corpus-clean finding, since
none of them was ever a valid `jcs-n` computation to begin with.

**Skip / sanity-fail notes:**

- IETF conformance vectors: 2 records use sentinel identifiers and were
  skipped by design; 1 (`neg-capsule-id-mismatch`) is itself a negative
  test vector — its stored id is *supposed* to disagree with a fresh
  recomputation, so a "sanity-fail" here is the expected, correct result,
  not a defect.
- Operator-internal corpus A: all 12 sanity-fail records were never
  committed under `jcs-n` in the first place (their stored identifiers do
  not match a `jcs-n` recomputation either), so they are outside the scope
  of a `jcs`-vs-`jcs-n` byte-identity claim and are not evidence either
  way.

## MISMATCH records (12) — mesh sidecar proof-of-concept, documented-historical

All 12 mismatches are in the public `capsule-emit-mesh` repository, under
`ledger/capsules.jsonl`, `ledger-live/capsules.jsonl`, and
`ledger-supported-port/capsules.jsonl`. In every case, the stored digest
**matches** a `jcs-n` recomputation (confirming the record was in fact
committed under `jcs-n` as declared) and **differs** from a plain-`jcs`
recomputation, because `normalize()` strips one or more of the following
member paths that are present as `null`, `[]`, or `{}` placeholders:

- `model_attestation.compute_attestation.x-mesh-poc-v1.evidence_refs.statistical_fingerprint.context` / `.digest`
- `model_attestation.compute_attestation.x-mesh-poc-v1.evidence_refs.tee_attestation.context` / `.digest`
- `model_attestation.compute_attestation.x-mesh-poc-v1.forwarded_copy.transforms` / `.upstream_tool_call_ids`
- `model_attestation.compute_attestation.x-mesh-poc-v1.generation_parameters`

**Disposition: accept-as-documented-historical.** These null/empty
placeholders are intentional proof-of-concept scaffolding for fields the
mesh sidecar does not yet populate (`capsule_sidecar.py` §402–406: "steps
4/5 … are future work") — not evidentiary production records. No
re-anchoring is needed. All 12 stored digests remain reproducible under
`jcs-n`. That byte agreement alone is not a verification verdict: each record
is eligible for historical verification only when profile-defined
cryptographic evidence binds that exact record or digest to a time before
2026-08-18 UTC. Without such evidence a verifier fails closed.

## Method

Every record's canonicalization was independently recomputed under plain
RFC 8785 (`jcs`, no normalization pass) and compared to the digest actually
stored at commit time, against the identity that normalization changes
bytes only when a record carries a null, empty-array, or empty-object
member. Two mutant self-tests were run before any result above was
trusted: a hand-broken record with a null/empty member was confirmed to
report MISMATCH, and a clean record was confirmed to report MATCH. A
sanity check separately confirmed a `jcs-n` recomputation reproduces a
known-good stored capsule id. Executed 2026-08-18.
