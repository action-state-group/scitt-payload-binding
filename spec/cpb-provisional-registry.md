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
