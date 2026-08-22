# CPB Provisional Artifact Type Registry

**Status.** This file tracks proposed entries for the CPB Artifact Type
Registry (§11.2 of `draft-mih-sokolov-scitt-payload-binding-00`) that are
under discussion with artifact-type owners. Entries here target **CPB -01 or
later**; none enter the -00 text. An entry merges only when the owner
confirms all `[OWNER TO CONFIRM]` fields, at which point it moves into the
normative registry table in §11.2 of the next CPB revision.

**Rule for every entry.** Text is QUOTED from the named owner draft wherever
possible. Fields not stated in the owner's draft are marked
`[OWNER TO CONFIRM]` literally. CPB editors MUST NOT fill in digest-context
parameters on behalf of an owner.

---

## Proposed: `verifiable-agent-conversation`

**Owner draft:** `draft-birkholz-verifiable-agent-conversations-00`
**Proposed by:** CPB provisional registry (this PR)
**Owner reviewer:** Henk Birkholz — merges only on your approval; edit or
close freely.

### Proposed registry row

| Field | Value |
|---|---|
| Name | `verifiable-agent-conversation` \[OWNER TO CONFIRM: preferred name\] |
| Digest Context | \[OWNER TO CONFIRM — see fields below\] |
| Reference | draft-birkholz-verifiable-agent-conversations-00 |

### Quoted from draft-birkholz-verifiable-agent-conversations-00

The draft defines the following structures relevant to a CPB Artifact Type
entry:

**`verifiable-agent-record`** (§3.2): top-level CDDL map, JSON and CBOR
representations supported:

```
verifiable-agent-record = {
    version: tstr
    id: tstr
    session: session-trace
    ? created: abstract-timestamp
    ? file-attribution: file-attribution-record
    ? vcs: vcs-context
    ? recording-agent: recording-agent
    * tstr => any
}
```

**`signed-agent-record`** (§3.11.1): COSE_Sign1 envelope (CBOR Tag 18)
wrapping the `verifiable-agent-record` payload. The payload may be included
or detached (null).

**`trace-metadata`** (§3.11.2): carried in the COSE_Sign1 unprotected
header at label 100. Includes an optional `content-hash` ("SHA-256 hex digest
of the payload bytes") and `content-hash-alg` (default: "sha-256").
`trace-format` identifies the payload format; known value `"ietf-vac-v3.0"`
denotes canonical records.

### Fields requiring owner confirmation

The following fields are `[OWNER TO CONFIRM]` because draft -00 does not
specify a CPB-compatible canonicalization algorithm for
`verifiable-agent-record` payloads:

1. **Preferred artifact type name** — The draft does not define a CPB
   artifact type name. `verifiable-agent-conversation` is a suggested name.
   Please confirm or substitute.

2. **Canonicalization algorithm** — The `content-hash` in `trace-metadata`
   is described as "SHA-256 hex digest of the payload bytes" (§3.11.2), but
   "payload bytes" is not further normalized: no absent-field removal, key
   sorting, or encoding step is specified in -00. For CPB, the Digest Context
   requires a named canonicalization algorithm (from the CPB Canonicalization
   Algorithm Registry, §11.1) or a new one registered alongside this entry.
   Please specify which algorithm applies — for example: jcs-n, jcs (plain
   RFC 8785), as-transmitted, or a new entry you define. (`cde-n` appeared in
   an earlier version of this question; it has since been withdrawn and is not
   available.)

3. **Exclusion set** — Which fields (if any) of `verifiable-agent-record`
   are excluded from the canonical form before the derived identifier is
   computed? Not specified in -00.

4. **Representation** — The `content-hash` field is a `tstr`, consistent
   with CPB's lowercase hex output. Please confirm hex is the intended
   representation for the derived identifier.

### Notes for the CPB editor (non-normative)

- This entry targets CPB -01 / the provisional registry.
- The draft's COSE_Sign1 envelope (`signed-agent-record`) is a
  natural fit as the SCITT Signed Statement payload; CPB's derived
  identifier would be computed over the `verifiable-agent-record`
  payload bytes (after owner-specified canonicalization), not over
  the outer COSE envelope.
- §8 (Discovery Mirror) of CPB -00 notes alignment with §7.4 of
  this draft; the artifact type entry closes the technical loop by
  giving the `verifiable-agent-record` a stable CPB-addressable type.

---

**`machine-mandate` has graduated.** Formerly tracked here as
`third-party-documented, pending owner review`, it is now owner-confirmed
(Anton Sokolov, Tyche Institute; PR #4 thread, 2026-08-09 and 2026-08-13)
and registered in the normative Artifact Type Registry — see
[`draft-mih-sokolov-scitt-payload-binding-01.md`](draft-mih-sokolov-scitt-payload-binding-01.md)
§13.2 and [`REGISTRY.md`](../REGISTRY.md).

---

## Proposed: `mesh-inference-exchange`

**Owner:** Action State Group (`action-state-group/capsule-emit-mesh`)
**Reference:** `action-state-group/capsule-emit-mesh` @ `0304296` (`mesh_record_emitter.py`, `mesh_record_verifier.py`)
**Proposed by:** ASG (owner-authored — see Disclosure)
**DE reviewer:** Anton Sokolov — this entry promotes to the live Artifact Type
Registry only on your confirmation of the two open items below; edit or hold
freely.
**Disclosure:** the proposer is a co-editor of this registry; this entry is
owner-authored and is not independent or third-party validation.

### Why this is Rung 3 (provisional), not a live-table entry

Both Rung 3 conditions in `REGISTRY.md`'s Registration Ladder apply — the
reference exists and the fields are validated in running code, but:

1. **The identifier's serialization is not a registered algorithm yet.**
   The record bytes a verifier receives are produced by `capsule_to_bytes()`:
   `json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode("utf-8")`
   (`mesh_record_emitter.py:286-288`). This is deterministic, but it is
   neither `jcs-n`/`jcs` (RFC 8785 escaping and number-formatting rules
   differ from Python's `json.dumps` output) nor a byte-boundary selector in
   the `as-transmitted` sense (`REGISTRY.md`: "an artifact type entry using
   this algorithm states a byte-boundary selector... citing a named
   production" — `json.dumps(sort_keys=True)` is a Python convention, not a
   cited wire production of any container format). The DE needs to pick one
   of: (a) this record is already an `agent-action-capsule` instance, so no
   new algorithm is needed — the existing `agent-action-capsule` entry's
   `jcs-n` identifier context already covers it; (b) register
   `capsule_to_bytes()`'s exact construction as its own algorithm token; or
   (c) scope `as-transmitted` to only the sub-fields that are genuinely
   as-transmitted today — `request_digest`/`response_digest`, literally
   `sha256(raw_body)` with no canonicalization (`capsule_sidecar.py:231-238`)
   — rather than the whole record. The inbox item that proposed this entry
   named `as-transmitted` as the identifier context; this note is the
   DE-facing detail needed to pin exactly what that means before it is
   immutable.
2. **The one committed real-traffic example set predates the current block
   name.** The lifecycle vocabulary below (`terminal_state`,
   `observation_point`, `exchange_id`, `hop_id`, `transcript`) is carried in
   `model_attestation.compute_attestation["x-mesh-lifecycle-v1"]` in the
   current emitter/verifier. The only committed example set,
   `capsule-emit-mesh/ledger-live/capsules.jsonl` (four records,
   2026-08-11), predates this block and carries the earlier `x-mesh-poc-v1`
   shape instead — self-attested demo data per `ledger-live/README.md`, not
   yet an example of the type this entry registers. The DE should confirm
   whether a fresh `x-mesh-lifecycle-v1` `ledger-live/` example is needed
   before this can cite `ledger-live/` as its Gate-B consuming profile.

### What is settled (validated in code, not invented for this entry)

Digest Context (purpose: `identifier`) — as far as pinned:

| Field | Value |
|---|---|
| Algorithm | `as-transmitted` — provisionally; scope pending DE confirmation, item 1 above |
| Field set | the `x-mesh-lifecycle-v1` block: `terminal_state` (∈ eight-value closed set), `terminal_reason`, `observation_point` (∈ four-value closed set, nullable), `exchange_id`, `hop_id`, `attempt`, `local_peer_id`, `transcript.{event_count, expected_count, complete}` |
| Exclusion set | N/A pending item 1 above |
| Domain separation | none observed in code |
| Pre-image encoding | N/A pending item 1 above |
| Representation | `request_digest`/`response_digest` sub-fields: bare 64-char lowercase hex (SHA-256) |

**Vocabulary (closed sets, quoted from `mesh_record_verifier.py`):**
- `terminal_state` ∈ `{completed, policy_denied, request_invalid, backend_error, transport_error, client_cancelled, timed_out, evidence_unavailable}`
- `observation_point` ∈ `{gateway_ingress, serving_host_ingress, backend_dispatch, client_egress}` (nullable — absent when a record covers a whole exchange rather than one vantage point)

**Producer invariant (load-bearing, not owner-invented for this entry):**
`transcript.complete` MUST be `False` whenever `event_count < expected_count`
— enforced at emit time (`emit_lifecycle_record` raises unless the caller
explicitly names `_override_complete=True`) and independently re-checked at
verify time (`verify_transcript` raises `IncompleteTranscriptError` reading
only the record bytes). This is the property a discriminating vector for
this entry should exercise once promoted.

**Candidate discriminating vector (not yet committed in CPB vector format;
Rung 3 does not require one for provisional status):** a record asserting
`transcript.complete=true` with `event_count < expected_count` verifies as
failed under `mesh_record_verifier.verify_record_bytes` (raises
`IncompleteTranscriptError`) and would pass under a naive verifier that
trusts the flag (`verify_record_bytes_naive`) — this before/after pair is
already exercised in `tests/test_record_side_state_binding.py` (case 4,
"DELIBERATELY-BROKEN TRUNCATION") and is the natural Gate-A candidate once
promoted.

**Candidate consuming profile:** `capsule-emit-mesh` `ledger-live/`
(demo-grade, self-attested key — see `ledger-live/README.md`), pending the
block-name confirmation in item 2 above; the mesh-llm PoC gateway
(mesh-llm#1233) once that engagement's own documentation cites this
registered name.

### Notes for the CPB editor (non-normative)

- This entry targets the provisional track per Rung 3 of the Registration
  Ladder (`REGISTRY.md`). GO for filing recorded 2026-08-21
  (`action-state-strategy/docs/decisions-log.md`, same-day PM session).
- The fields are captured and validated in running code today (closed-set
  enforcement + the transcript-completeness invariant); what is missing is
  registry-level definition, not field design — see
  `_work/mesh-llm-capsule-architecture-2026-08-21.md` §1.
- Promotion path: once the DE resolves the algorithm scope (item 1) and a
  fresh `x-mesh-lifecycle-v1` `ledger-live/` example lands (item 2), this
  entry can move directly to `owner-confirmed` (Rung 3 → owner-direct,
  skipping Rung 2 — `REGISTRY.md` Entry Lifecycle) with a committed
  two-sided vector set built from the truncation-guard case above.

---

## Proposed: `mmr-checkpoint`

**Owner:** Action State Group (`action-state-group/capsule-ledger`)
**Reference:** `action-state-group/capsule-ledger` @ `0fef1b2` (`capsule_ledger/mmr/checkpoint.py`, `capsule_ledger/mmr/core.py`)
**Proposed by:** ASG (owner-authored — see Disclosure)
**DE reviewer:** Anton Sokolov — this entry promotes to the live Artifact Type
Registry only on your confirmation of the open item below; edit or hold
freely.
**Disclosure:** the proposer is a co-editor of this registry; this entry is
owner-authored and is not independent or third-party validation.

### Background: the shape this entry registers

`CheckpointRecord` (`checkpoint.py`) is a signed, tamper-evident snapshot of an
MMR's peak set at a given size. As of `0fef1b2` it carries exactly ONE
peak-set commitment (an unmerged sibling branch briefly carried a second,
functionally-inert `peaks_digest` field alongside it; that branch was fixed to
drop it — see `capsule-ledger` PR #71 — before this entry was drafted, so only
one construction is ever in scope here):

```
CheckpointRecord = {
    v: int, kind: str,                       # "1", "mmr_checkpoint"
    mmr_size: int, root: str,                # the peak-set commitment (hex)
    prev_size: int, prev_root: str,          # "" for the first checkpoint
    key_id: str, timestamp: str,             # ISO 8601 UTC
    signature: str,                          # hex HMAC-SHA256, covers the above
    witnesses: [WitnessRecord, ...]           # optional, populated post-registration
}
```

**Note for the DE — a shape correction against the task's own working
assumption.** The mesh integration doc that originally proposed this entry
(`_work/mesh-llm-capsule-architecture-2026-08-21.md` §4) sketches a
`{log_id, peer_id, mmr_root(32B), mmr_size, prev_size, timestamp}` "checkpoint
capsule" for posting a checkpoint off-node. `log_id` and `peer_id` are that
sketch's own transport-wrapper fields for a consuming profile (a peer may run
several logs; the wrapper needs to say which one) — they are NOT fields of the
shipped `CheckpointRecord` above, which has no log/peer identity field at all
(only `key_id`, the signer's key). This entry registers the artifact type as
`capsule-ledger` actually emits it; a future consuming-profile entry (e.g. a
mesh "checkpoint capsule" wrapper) would cite this entry's `root` construction
rather than duplicate it.

### Why this is Rung 3 (provisional), not a live-table entry

The reference exists and the field is validated in running code (property
tests, not a literal pinned-value KAT — see Construction below), but the
identifier's construction is not a registered algorithm yet, and picking the
wrong one now is a second DE round later (REGISTRY.md: entries are immutable
in behavior once owner-confirmed).

### What is settled (validated in code, not invented for this entry)

Digest Context (purpose: `identifier`) — the commitment that does the actual
verification work: `verify_checkpoint_consistency` and the rollback-detection
check in `emit_checkpoint` compare against `root`/`prev_root` exclusively
(`checkpoint.py`), never against the record's outer JSON envelope. That outer
envelope (`signing_body()`, `checkpoint.py:153-165`: `json.dumps(body,
sort_keys=True, separators=(",", ":"))` over the eight signing fields) is a
distinct, HMAC-covered integrity digest one layer up — out of scope for this
entry, which registers `root` itself:

| Field | Value |
|---|---|
| Algorithm | **\[OPEN — see identifier-construction question below\]** |
| Field set | N/A — not a JSON field set. The pre-image is the ordered list of MMR peak node hashes at `mmr_size` (`core.peaks()`, tallest-to-smallest), not a document's fields |
| Exclusion set | none — every live peak at `mmr_size` participates |
| Domain separation | **none**, by explicit design (`core.py` module docstring: "root = bagged peaks... NO domain-separator byte") — contrast with this same module's leaf/interior hashes, which ARE domain-separated (`leaf_hash = sha256(0x00 \|\| body_digest)`; `interior_hash = sha256(be64(position+1) \|\| left \|\| right)`). The root-bagging step alone omits it |
| Pre-image encoding | binary, not JSON/UTF-8: iterative `sha256(right \|\| left)`, popping the two rightmost peak hashes and pushing the result back, right-to-left, until one hash remains (`core.root_from_peaks()`, `core.py:141-168`) |
| Representation | bare 64-char lowercase hex |

### Identifier-construction question for the DE

`root`'s construction (`core.root_from_peaks()`) is a Merkle Mountain Range
peak-bagging accumulator — reference-source-verified against
`datatrails/go-datatrails-merklelog`'s `hashPeaksRHS` (MIT licensed;
`core.py:145-154`), but not independently KAT-pinned by a published literal
root value the way the leaf/interior hashes are (searched; none found —
treat its provenance as property/self-consistency-tested, not KAT-pinned).
It does not fit either registered algorithm cleanly:

- Not `jcs-n`/`jcs` — there is no JSON object here at all; the pre-image is
  raw concatenated binary hashes, not a serialized document.
- Not obviously `as-transmitted` either — `as-transmitted`'s definition
  (REGISTRY.md) is an octet sequence *selected* from an existing wire
  production (e.g., a JWS component "exactly as transmitted"); `root_from_peaks`
  instead *computes new bytes* by iteratively re-hashing, so there is no single
  cited byte range of an existing message to point at as the "byte-boundary
  selector" the algorithm requires.

**The DE needs to pick one of:** (a) treat the published MMR peak-bagging
construction itself as a sufficiently "named production" to qualify under
`as-transmitted` (stating the fold procedure in place of a byte-boundary
selector, since REGISTRY.md's existing text ties that field to "a cited named
production" without restricting it to octet-selection alone); or (b) register
a new Payload Canonicalization Algorithm Registry entry for this construction
(e.g. an `mmr-bagged-peaks` token), naming the fold order, the
no-domain-separator property, and the empty-MMR convention (32 zero bytes) as
its normative content. Option (b) matches how `jcs`/`jcs-n` each got their own
token for byte-distinct JSON constructions rather than being folded into one;
option (a) is the narrower reading of an existing token. This entry does not
propose either — REGISTRY.md is explicit that CPB editors must not fill in an
owner's digest-context parameters on the owner's behalf, and here ASG is the
artifact owner but the algorithm-registry decision is a DE call either way.

### Candidate discriminating vector (not yet committed in CPB vector format;
Rung 3 does not require one for provisional status)

A checkpoint whose `prev_root` does not match the actual MMR root recomputed
at `prev_size` verifies as failed under `verify_checkpoint_consistency`
(rollback / tamper detection — `checkpoint.py`) and would pass under a naive
verifier that checks only the HMAC signature and never re-derives `root` at
the referenced prior size. This before/after pair is already exercised in
`tests/test_checkpoint.py`'s `TestVerifyCheckpointConsistency` (`test_rollback_detected`,
`test_mmr_rollback_simulation`) and is the natural Gate-A candidate once
promoted.

### Candidate consuming profile

`capsule-ledger`'s own checkpoint emit/verify path (self-consuming, ships
today). The mesh-llm "checkpoint capsule" wrapper sketched in
`_work/mesh-llm-capsule-architecture-2026-08-21.md` §4 is a future candidate
once that engagement names this registered type rather than inventing its own
`mmr_root` digest context — see the shape-correction note above.

### Notes for the CPB editor (non-normative)

- This entry targets the provisional track per Rung 3 of the Registration
  Ladder (`REGISTRY.md`). Filed as the second entry of this pass, gated on
  `capsule-ledger` PR #71 (single-commitment `CheckpointRecord`, dropping the
  unused `peaks_digest` field) landing on `capsule-ledger` `main` first — it
  has (`0fef1b2`), so this entry describes exactly one construction, not two.
- The field is captured and validated in running code today (rollback/tamper
  detection over `root`); what is missing is registry-level algorithm
  definition, not field design.
- Promotion path: once the DE resolves the algorithm-token question above,
  this entry can move to `owner-confirmed` with a committed discriminating
  vector built from the rollback-detection case cited above.
