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
