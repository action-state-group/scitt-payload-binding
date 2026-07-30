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

---

## Proposed: `verifiable-telemetry-object` (third-party-documented, pending owner review)

**Owners:** Johanna Moran (Strategy & Operations Lead, libp2p) and Manu Sheel Gupta (Technical Lead, libp2p; GitHub `seetadev`; multiformats/IPLD contributor).
**Pinned source:** IETF 126 (Vienna) MAPRG session materials — "Towards a Common Measurement Framework for Large-Scale libp2p Deployments Using CBOR-based Verifiable Telemetry" (deck title: "From Operational Exhaust to Verifiable Evidence: A Common Measurement Framework for Large-Scale libp2p Deployments"), revision **-01**:
`https://datatracker.ietf.org/meeting/126/materials/slides-126-maprg-maprg-towards-a-common-measurement-framework-for-large-scale-libp2p-deployments-using-cbor-based-verifiable-telemetry--johanna-m-01`
SHA-256 of the pinned PDF (`slides-126-maprg-...-johanna-m-01.pdf`): `18fd8492d2ce82f0caa7b014c8d37be3b2935bc1e2239ba1887e357a6975aa31`. Every quotation below was checked against this exact file.
**Proposed by:** Action State Group, from the public IETF 126 materials at the pinned revision.
**Registrant note:** Entry is `third-party-documented` — authored by the registrant from public materials; not yet owner-confirmed. Upgrades to `owner-confirmed` on the owners' PR approval or explicit ack. **Removal on owner objection, no questions asked.**

**No stable specification pin exists.** Unlike the other entries in this file, the pinned source is a **conference presentation deck**, not an Internet-Draft or a versioned repository. There is no CDDL, no named canonicalization algorithm, and no test-vector set anywhere in the pinned material. The deck's own closing slide (Slide 14, "Resolving the remaining open research questions requires community action") lists **"Standardizing CBOR Schemas — Defining the canonical CBOR representations for baseline network and protocol events"** as an **open research question**, not a settled construction. Per the registry-entry HARD RULE for this task: **the whole entry is provisional pending the owners' confirmation**, more so than any prior entry in this file — there is nothing yet to promote without their input defining the digest context from scratch.

### Proposed registry row

| Field | Value |
|---|---|
| Name | `verifiable-telemetry-object` \[OWNER TO CONFIRM: preferred artifact type name\] |
| Digest Context | \[OWNER TO CONFIRM — nothing is pinned; see fields below\] |
| Reference | IETF 126 MAPRG slides-126-maprg-...-johanna-m-01 (informational; no Internet-Draft exists) |
| Status | `provisional` (no CDDL, no digest-context, no vector set found at the pinned revision) |

### Quoted from the pinned slide deck

**Slide 8** ("The Verifiable Telemetry Object (VTO) encapsulates independent observations.") defines the VTO as three parts:

> 1. Verification Shell: Optional cryptographic signatures, Content Identifiers (CIDs), and organizational attestations ensuring authenticity.
> 2. Provenance Metadata: Software implementation, protocol version, collection environment, and measurement methodology.
> 3. Measurement Payload: The actual standardized network observations, metric identifiers, timestamps, and intervals.

> Result: A reproducible scientific artifact, completely independent of the system that generated it.

**Slide 9** ("Content addressing requires deterministic binary encoding."):

> Why CBOR (RFC 8949) succeeds: ... Deterministic profiles (e.g., CBOR-42) guarantee exact byte matching for equivalent structures. Enables reproducible hashing, CIDs, and long-term archival preservation.

**Slide 10** ("Telemetry becomes a continuous loop of cryptographic artifacts"):

> [Serialize] Data is encoded into canonical, deterministic CBOR.
> [Hash & Sign] A Content Identifier (CID) is generated; provenance signatures are appended.

**Slide 14** ("Resolving the remaining open research questions requires community action"), listed as an open item, not a defined mechanism:

> Standardizing CBOR Schemas: Defining the canonical CBOR representations for baseline network and protocol events.

### Fields requiring owner confirmation

All digest-context fields are `[OWNER TO CONFIRM]` — nothing CPB-compatible is pinned at the reviewed revision:

1. **Preferred artifact type name** — `verifiable-telemetry-object` is the registrant's suggestion (from the deck's own "VTO" term). Please confirm or substitute.
2. **Canonicalization algorithm** — the deck names no specific deterministic-CBOR profile; "CBOR-42" (Slide 9) appears as a parenthetical example, not an adopted or defined identifier, and Slide 14 lists the canonical CBOR representation as unresolved. Which CPB-registered algorithm (e.g. `jcs-n`, `cde-n`, or a new entry) applies?
3. **Digest/hash algorithm** — no hash function is named in the pinned text. Slide 9's diagram labels an unspecified `HASH_X`; Slide 8's "Content Identifiers (CIDs)" implies a multiformats/multihash construction (self-describing, not fixed to one hash function), but this is not stated as text in the deck. Please confirm.
4. **Field set and exclusion set** — no CDDL or field-level schema for the VTO exists in the pinned material. Which fields of Provenance Metadata / Measurement Payload are included in, or excluded from, the canonical form for the derived identifier?
5. **Representation** — CIDs are conventionally a self-describing multibase-encoded multihash string, not CPB's default 64-char lowercase hex. Please confirm which representation applies to the CPB derived identifier, if any.

### Vector status

No published vector set exists — the pinned material is a presentation deck, not a spec artifact, and defines no test vectors. Entry is `provisional`; a two-sided vector set (positive + negative) is required for full registration per REGISTRY.md policy, in addition to a stable normative reference (Internet-Draft or equivalent) that does not yet exist.

### Notes (CPB editor, non-normative)

The VTO is presented as a libp2p-ecosystem measurement/telemetry artifact (three-part shell: verification, provenance, payload) aimed at cross-network scientific reproducibility, distinct in purpose from `machine-mandate` (accountability) and `verifiable-agent-conversation` (agent session records). Because the pinned source explicitly defers canonicalization to future work, this entry cannot advance past `third-party-documented` until the owners publish (or state in review) a concrete digest-context construction — at which point it is immediately eligible for promotion alongside a normative reference of their choosing.
