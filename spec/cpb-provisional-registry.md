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

## Proposed: `trace-trust-record`

**Owner:** Imran Siddique, Opaque Systems
**Owner draft:** `agentrust-io/trace-spec` @ `e0afe8eba628244afd591433014b182530a0c11c`
**Proposed by:** the owner (Rung 3, owner-authored)
**Why provisional rather than Rung 1:** the owner's published vector corpus at
the record-digest layer (`examples/canonicalization-boundary/`, four records) is
positive-only. [Required fields](../REGISTRY.md#entry-template) makes a
two-sided set the condition for `owner-confirmed`. Promotion is gated on the
MUST-FAIL vectors, not on any unsettled question about the construction, which
is fully pinned below.

### Proposed registry rows

| Purpose | Profile version | Algorithm | Field set | Exclusion set | Domain separation | Pre-image encoding | Representation |
|---|---|---|---|---|---|---|---|
| `identifier` | `tag:agentrust-io.com,2026:trace-v0.2` | `jcs` | all Trust Record members; closed at 16 by `schema/trace-claim.json` (`additionalProperties: false`) | `{signature}`, applied as "the member if present" | none | JCS UTF-8 octets (per `jcs`) | 64-char lowercase hex |
| `equivalence` | `tag:agentrust-io.com,2026:trace-v0.2` | `json-sk-ascii` (proposed, see the Algorithm Registry row below) | all Trust Record members, `signature` included; the anchored unit is the complete signed claim | none | single octet `0x00` prefixed to the canonical bytes (RFC 6962 leaf prefix) | sorted-key ASCII JSON octets, prefixed by `0x00` | raw 32 octets as consumed by the RFC 6962 tree; where surfaced in a checkpoint or inclusion proof (`merkle_root`, `audit_path`), `sha256:` + 64-char lowercase hex |

**Reference:** `agentrust-io/trace-spec` @ `e0afe8eba628244afd591433014b182530a0c11c`
— `spec/trace-v0.2.md` §3.2.2 (row 1), `spec/registry-anchor-v1.md` §1 and §2
(row 2), `schema/trace-claim.json` (the closed field set both rows range over).

File digests at that commit, so the pin is checkable rather than merely stated:

| Path | SHA-256 |
|---|---|
| `spec/trace-v0.2.md` | `6bd37be8dfc923747ceab37ceb711d1d16442fef7f13aa3949cf21d818569b8a` |
| `spec/registry-anchor-v1.md` | `61dc3f8971e6bb4ee87b3f7452d062c8933e788979ed50e462a89a9056e17edf` |
| `schema/trace-claim.json` | `852bde86eabab92338a843b6412eac52fc1cba0436657afdfa935344c5a24eb5` |

### Why this artifact type registers two digest contexts and not one

TRACE applies two different canonicalizations at two different layers, and they
are not interchangeable. This is stated normatively in §0 of
`spec/registry-anchor-v1.md`, a section that exists for this reason.

| Layer | Canonicalization | Row |
|---|---|---|
| Signing a Trust Record | RFC 8785 (JCS) | `identifier` |
| Hashing a record into a transparency-log leaf | sorted-key ASCII JSON | `equivalence` |

A single-row entry would be accurate about signing and silent about anchoring.
Given that a registered entry exists so a verifier recomputes a construction
from this registry rather than from the owner's source tree, silence is the
failure mode: a verifier resolving TRACE here, seeing one `jcs` row, and
reusing that canonicalizer at the leaf computes a root that never matches, with
no diagnostic to say why. Both rows, or the entry propagates the trap it should
close.

### Algorithm Registry row this entry depends on

`jcs` does not describe the anchor construction, and no currently registered
token does. Proposed for the Payload Canonicalization Algorithm Registry:

| Name | Description | Reference | Status |
|---|---|---|---|
| `json-sk-ascii` | Sorted-key ASCII JSON. Member names sorted by Unicode code point; separators `,` and `:` with no whitespace; non-ASCII characters escaped as `\uXXXX` with lowercase hex digits (non-BMP as a UTF-16 surrogate pair) and the result encoded as ASCII octets; no member removal; non-integer JSON numbers are outside the profile and are rejected rather than serialized; SHA-256; 64-character lowercase hex | `agentrust-io/trace-spec` @ `e0afe8e`, `spec/registry-anchor-v1.md` §1 | `provisional` |

**Why this is not `json-sk-cp` revived, and not `jcs` under another name.**
`json-sk-cp` was retired on the finding that it produced byte-identical
pre-images to `jcs` across the `machine-mandate` vector set, differing only on
non-BMP member names and an integer restriction. That finding does not carry
here. `json-sk-ascii` escapes non-ASCII where `jcs` emits literal UTF-8, so the
two pre-images diverge on **any** record containing a single non-ASCII
character anywhere, not only on a supplementary-plane member name. Measured on
`01-non-ascii-values.json`, holding the field set constant: 950 JCS octets
against 964. `01` contains no key-order divergence, so that difference is
escaping alone. The digests are below.

### Vectors

`agentrust-io/trace-spec` @ `e0afe8eba628244afd591433014b182530a0c11c`,
`examples/canonicalization-boundary/`. Four signed records, each schema-valid,
each carrying an Ed25519 signature that verifies against its JCS pre-image.

| Vector | File SHA-256 |
|---|---|
| `01-non-ascii-values.json` | `645124c89a915fbbf21f931b0ebcc96160669a4e5a23df1242ed606224f82767` |
| `02-non-bmp-values.json` | `a82798292f668656dff426d82b4f622fa9a97ffbd24bbbd05330c3e93db35782` |
| `03-utf16-key-order.json` | `bcbb5852b5331e9d40ab627c05576acf6115d1b1d72857a3875dd8d0507dbfa8` |
| `04-utf16-key-order-nested.json` | `db1d8eb1b4d2fd23d1efe1cd5d38b5add6426c8816888a3ca5b9dc0a4cc4d3ae` |

Positive-only at this layer, which is what makes this entry Rung 3. The
MUST-FAIL counterparts are in preparation and the owner will supply the commit.

### Discriminating vector

`03-utf16-key-order.json`, cited above at its commit-pinned URL and file digest.

It is the shallowest record in the corpus whose UTF-16 code-unit and Unicode
code-point member orderings disagree (at `cnf.jwk`); `04` exercises the same
divergence one level deeper. It therefore separates the two rows on key
ordering rather than on escaping alone.

Recomputed with the owner's own implementation (`rfc8785` for row 1, the §1
construction for row 2), from the bytes GitHub serves at the pinned commit:

| Construction | Digest |
|---|---|
| Row 1, `SHA-256(JCS(record minus signature))` | `2ca25edd4787b89ae2b539e913dc135525cc711ad238ec967f407e2a6f897868` |
| Row 2, `SHA-256(0x00 \|\| json-sk-ascii(record including signature))` | `a433eec73e4e25555aabe0b4787843b08a7e091b97aa2b8fc0022b18af6d4749` |
| Row 2 computed with `jcs` at the leaf, the failure this entry exists to prevent | `6863d4e40422b4faa05f89d9853e9aa53f7eaf607597ac03fe4483acf8e2fa5c` |

Against the registered neighbours in the Artifact Type Registry, both
directions:

- **`agent-action-capsule`** excludes `{capsule_id}`, or `{capsule_id, chain}`
  on the vintage row, from a capsule object. A TRACE Trust Record has no
  `capsule_id` and no `chain` member, and `schema/trace-claim.json` closes the
  object, so those rows are **not applicable** to this vector rather than
  merely disagreeing with it. Neither of that entry's own discriminating
  vectors is a TRACE record, so neither passes for this entry.
- **`machine-mandate`** row 1 is `as-transmitted` over an SD-JWT issuer-signed
  component, and row 2 is `jcs` over a closed two-member field set
  `{action_id, outcome}`. Neither production exists in a TRACE record. Its
  discriminating vector `mm-fail-04-representation-confusion` pins the bare-hex
  against `sha256:`-prefixed distinction for *its* two contexts and does not
  pass for this entry.
- No registered neighbour asserts a second canonicalization at a second layer,
  so no neighbour's vector exercises the divergence `03` exercises.

### Consuming profile

`agentrust-io/cmcp` @ `80d74397b98b4bb8f11c81c58401f87c684597f4`,
`src/cmcp_runtime/audit/trace_claim.py`. It pins `eat_profile` as a typed
literal at `tag:agentrust-io.com,2026:trace-v0.2` and implements the
`{signature}` exclusion directly when constructing the signing body. That is a
normative use, not a name-drop.

**Disclosure.** cMCP is an agentrust-io project. The artifact type owner and the
consuming-profile maintainer are the same party, which is the case Gate C waives
the consuming-profile ACK for, and which also means cMCP is **not** independent
third-party validation of this entry. Stated here rather than left for the
Designated Expert to discover. `ADOPTERS.md` in `trace-spec` is empty at the
pinned commit, so there is no independent consuming profile to cite today. The
PIC/TRACE authorization bridge v1 is explicitly informative and is not offered
as one.

### Scope of the owner's participation

Supplying these values registers a fact about TRACE. It is not an endorsement of
the CPB specification, of this registry's governance, or of any implementation
that consumes it, and the entry should not be read or cited as one.

TRACE is moving to Linux Foundation governance. On promotion the owner will
supply a reference URL at the governed specification location, and asks that the
promoted entry cite that rather than a commit in an Opaque-controlled tree.

### Notes for the CPB editor (non-normative)

- `agentrust-io/trace-spec#111` is closed. The anchor format is published at
  `spec/registry-anchor-v1.md` and its §0 already names both constructions and
  all three divergences. Please cite that section rather than restate the rule,
  so the two statements cannot drift apart.
- The `identifier` row's exclusion set is written "if present" on purpose.
  TRACE permits an embedded signature (top-level `signature` member) and three
  enveloping forms (JWS, COSE_Sign1, cMCP `RuntimeClaim`). An enveloping record
  carries no `signature` member, so the exclusion is a no-op and the pre-image
  is the whole record. The same record content therefore yields the same
  `identifier` regardless of which binding form transported it, which is the
  property the row exists to give. `cnf`, including `cnf.jwk`, participates in
  both rows.

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
Registry only on your confirmation of the two open items below, plus the
`role` field addition (issue #69, filed below); edit or hold freely.
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
| Field set | the `x-mesh-lifecycle-v1` block: `terminal_state` (∈ eight-value closed set), `terminal_reason`, `observation_point` (∈ four-value closed set, nullable), `role` (∈ two-value closed set, conditional — see Role field below), `exchange_id`, `hop_id`, `attempt`, `local_peer_id`, `transcript.{event_count, expected_count, complete}` |
| Exclusion set | N/A pending item 1 above |
| Domain separation | none observed in code |
| Pre-image encoding | N/A pending item 1 above |
| Representation | `request_digest`/`response_digest` sub-fields: bare 64-char lowercase hex (SHA-256) |

**Vocabulary (closed sets):**
- `terminal_state` ∈ `{completed, policy_denied, request_invalid, backend_error, transport_error, client_cancelled, timed_out, evidence_unavailable}` — quoted from `mesh_record_verifier.py`
- `observation_point` ∈ `{gateway_ingress, serving_host_ingress, backend_dispatch, client_egress}` (nullable — absent when a record covers a whole exchange rather than one vantage point) — quoted from `mesh_record_verifier.py`
- `role` ∈ `{requested, served}` — proposed, not yet in `mesh_record_verifier.py` at `0304296`; see Role field below

### Role field (added 2026-08-28, issue #69)

**Proposed alongside this entry, not yet implemented.** `role` is not present
in `mesh_record_emitter.py`/`mesh_record_verifier.py` at `0304296` — it is
filed here as registry mechanics ahead of implementation because the entry
becomes immutable once it moves to the live table (#69's stated timing
rationale). It is therefore not covered by "validated in running code" in
the section heading above; implementation lands before promotion.

`role` records *whose account a record is*, a second axis from
`observation_point`, which records *where* a record was observed. The two
axes are not cleanly interchangeable — `gateway_ingress` has no role, and a
vantage-to-role mapping would have to be re-derived by every consumer as
vantage points grow — so `role` is carried explicitly rather than derived.

- OPTIONAL overall.
- REQUIRED wherever the vantage carries a role: `observation_point =
  client_egress` → `role = requested`; `observation_point ∈
  {serving_host_ingress, backend_dispatch}` → `role = served`.
- MUST be ABSENT at `observation_point = gateway_ingress` — the one
  role-less vantage.

**Fail-closed consistency invariant (#69).** Where both `role` and
`observation_point` are present, they MUST form one of the pairings above;
an inconsistent pairing — including any `role` alongside `gateway_ingress`,
or an absent `role` at a vantage that requires one — MUST be rejected. A
verifier implementing this rule raises a named error,
`RoleObservationPointMismatchError`, kept distinct from
`IncompleteTranscriptError` below so the two invariants stay independently
diagnosable.

**Binary-domain note.** The coordinator never emits this artifact type — it
has its own coordinator-receipt entry — so `{requested, served}` is
exhaustive for every record `x-mesh-lifecycle-v1` actually carries; there is
no third role to reserve room for.

**Discriminating vectors (synthetic, illustrative — not yet a committed CPB
vector; Rung 3 does not require one, consistent with the
transcript-completeness candidate below).** Each row shows only the two
fields at issue; the rest of the block is elided as `…`.

| # | `observation_point` | `role` | Verdict | Why |
|---|---|---|---|---|
| 1 | `client_egress` | `requested` | PASS | consistent pair — the required mapping |
| 2 | `client_egress` | `served` | MUST-FAIL | contradictory pair — `client_egress` requires `requested`; mutating vector 1's `role` alone, holding every other byte constant, produces this vector, so the pairing check is what must flip the verdict |
| 3 | `gateway_ingress` | `requested` | MUST-FAIL | role present at the role-less vantage — `gateway_ingress` MUST carry no `role` at all |
| 4 | `backend_dispatch` | *(absent)* | MUST-FAIL | role absent at a vantage that requires one — `backend_dispatch` is a served-side vantage, so a missing `role` is itself the inconsistency |

Rows 2–4 each raise `RoleObservationPointMismatchError`.

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
- The `role` field and its consistency invariant (issue #69, "Role field"
  above) were filed on this same entry ahead of promotion, per the owner's
  timing rationale on #69: the entry is immutable once it moves to the live
  table. This addition does not resolve items 1–2 above; DE confirmation
  covers all three together, and the field lands in
  `mesh_record_emitter.py`/`mesh_record_verifier.py` before promotion.

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
    log_id: str,                             # "" for single-node; identifies the log in a multi-log/peer deployment
    mmr_size: int, root: str,                # the peak-set commitment (hex)
    prev_size: int, prev_root: str,          # "" for the first checkpoint
    key_id: str, timestamp: str,             # ISO 8601 UTC
    signature: str,                          # hex HMAC-SHA256, covers the above
    witnesses: [WitnessRecord, ...]           # optional, populated post-registration
}
```

**Note for the DE — a shape correction, corrected 2026-08-22.** The mesh
integration doc that originally proposed this entry
(`_work/mesh-llm-capsule-architecture-2026-08-21.md` §4) sketches a
`{log_id, peer_id, mmr_root(32B), mmr_size, prev_size, timestamp}` "checkpoint
capsule" for posting a checkpoint off-node. `peer_id` is that sketch's own
transport-wrapper field for a consuming profile (a peer may run several logs;
the wrapper needs to say which one) and is NOT a field of the shipped
`CheckpointRecord`. `log_id`, however, **is** a signed field of the canonical
CLL `CheckpointRecord` shape — see the published `capsule-emit` 0.4.0
(`capsule_emit/checkpoint/emit.py:204`, `CheckpointRecord.signing_body()`)
and `scitt-cose` 0.2.2 (`scitt_cose/cll.py:593`, `Checkpoint.signing_body()`),
both of which sign `{v, kind, log_id, mmr_size, root, prev_size, prev_root,
key_id, timestamp}` — nine fields. `log_id` is `""` for a single-node
deployment (`capsule-ledger` never multiplexes logs) and identifies the log
in a multi-log/multi-peer deployment. `capsule-ledger`'s own
`CheckpointRecord` (pinned at `0fef1b2` above) had drifted from this
canonical shape by omitting `log_id` entirely; a companion fix
(`ldg-fix-checkpoint-logid-divergence`) unifies it back to the 9-field
shape. This entry registers the artifact type as the canonical CLL
construction, not the drifted 8-field shape `capsule-ledger` emitted before
that fix; a future consuming-profile entry (e.g. a mesh "checkpoint capsule"
wrapper) would cite this entry's `root` construction rather than duplicate
it.

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
envelope (`signing_body()` — canonical construction published in
`capsule-emit` 0.4.0's `capsule_emit/checkpoint/emit.py:204` and mirrored in
`scitt-cose` 0.2.2's `scitt_cose/cll.py:593`: `json.dumps(body,
sort_keys=True, separators=(",", ":"))` over the **nine** signing fields,
including `log_id`) is a distinct, HMAC-covered integrity digest one layer
up — out of scope for this entry, which registers `root` itself:

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
