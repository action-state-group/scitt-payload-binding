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
   Please specify which algorithm applies — for example: jcs-n (CPB Suite 1),
   cde-n (CPB Suite 2, pending), or a new entry you define.

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

## Proposed: `machine-mandate` (third-party-documented, pending owner review)

**Owner:** Anton Sokolov, Tyche Institute
**Owner draft/repo:** tyche-institute/machine-mandate @ commit `524e6a3129b7f1ab850dd9471967458d3cb6f4cd`
**Proposed by:** Action State Group, from public documentation at the pinned commit.
**Registrant note:** Entry is `third-party-documented` — authored by the registrant from public artifacts; not yet owner-confirmed. Upgrades to `owner-confirmed` on Anton's PR approval or explicit ack. **Removal on owner objection, no questions asked.**

### Proposed registry row

| Field | Value |
|---|---|
| Name | `machine-mandate` \[OWNER TO CONFIRM: preferred artifact type name\] |
| Digest Context | \[OWNER TO CONFIRM — see fields below\] |
| Reference | tyche-institute/machine-mandate@524e6a3 |
| Status | `provisional` (no published vector set found at pinned commit) |

### Fields requiring owner confirmation

All digest-context fields are marked `[OWNER TO CONFIRM]` — the pinned commit does not publicly state a CPB-compatible canonicalization construction for MachineMandate payloads. CPB editors MUST NOT infer or fill these in:

1. **Preferred artifact type name** — `machine-mandate` is the registrant's suggestion. Please confirm or substitute.
2. **Canonicalization algorithm** — which CPB-registered algorithm (e.g. `jcs-n`, `cde-n`, or a new entry) applies to MachineMandate payloads (AEP tokens, EAR results, run credentials, mint records)?
3. **Field set and exclusion set** — which top-level fields are included in the canonical form, and which (if any) are excluded for the derived identifier?
4. **Representation** — output is assumed lowercase hex (64-char SHA-256); please confirm.

### Vector status

No published vector set found at tyche-institute/machine-mandate@524e6a3. Entry is `provisional`; a two-sided vector set (positive + negative) is required for full registration per REGISTRY.md policy.

### Notes (CPB editor, non-normative)

MachineMandate is a RATS-adjacent accountability token format produced by SPIRE-attested workloads. The `machine-mandate/v1` shape (AEP profile identifier, EAR status + trustworthiness vector, run credentials with scope/allowed_actions/max_spend, mint records with L1–L4 gate verdicts) is documented in the public tyche-institute repo. When the owner supplies digest-context parameters and vectors, this entry is immediately eligible for promotion to `owner-confirmed` and inclusion in CPB -01.
