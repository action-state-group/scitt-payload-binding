# Implementations & registrants

**Ordering note.** Independent registrants are listed first; Agent Action
Capsule is one registrant among peers.

## Independent registrants

### VTO (libp2p)
**Status:** reserved (name hold only). **Contact:** Manu Sheel Gupta, Johana.
The full artifact-type entry and a companion deterministic-CBOR
canonicalization-profile entry are filed as soon as the libp2p team's CDDL
schema, one real encoded VTO instance, and the float-bearing-field list land
— tracked as a separate sibling filing. VTO encodes telemetry through
CBOR with floating-point measurements, which is why it needs its own
canonicalization profile rather than reusing an existing JSON-oriented one.

### TRACE Trust Record
**Owner:** Imran Siddique, Opaque Systems (`agentrust-io/trace-spec`).
**Status:** provisional — two digest contexts (a JCS signing-layer digest and
a separate sorted-key-ASCII-JSON anchoring-layer digest for transparency-log
leaves), fully pinned; held at provisional because the owner's published
vector corpus is positive-only pending MUST-FAIL counterparts. Moving to
Linux Foundation governance; the promoted entry will cite that location once
it exists.

### Evidence Record / Evidence Appraisal
**Owner:** Empire Labs Pty Ltd (`narko4u`). **Status:** under review — an
owner-authored PR proposing both a producer artifact type (`evidence-record`)
and its verifier artifact (`evidence-appraisal`), following the
`machine-mandate` precedent for external owners. Not yet in the live
registry tables.

### `machine-mandate`
**Owner:** Anton Sokolov, Tyche Institute (`tyche-institute/machine-mandate`).
**Status:** owner-confirmed — live in the Artifact Type Registry. An
SD-JWT-carried construction with two digest contexts: an `as-transmitted`
identifier over the issuer-signed JWS component, and a `jcs` equivalence
digest over a closed two-member field set.

## Action State Group's own declarations

Action State Group currently has no entry in this repository's tables.

- **`agent-action-capsule`**: the declaration is owned and stated
  normatively by the Agent Action Capsule draft itself
  (`draft-mih-scitt-agent-action-capsule`, §2 and §5.1). Under the
  2026-09-15 ruling, artifact types live in their owning profiles. The former
  record here was removed on 2026-10-04.
- **`cll-checkpoint`**: registered in the Checkpointed Local Log draft's own
  IANA Considerations section, with digest token `as-transmitted` over the
  commitment claim.
- **`mesh-inference-exchange`**: removed by its owner on 2026-10-04. It was
  not withdrawn, so the name is not bound.

---

Full detail, digest contexts, and Designated Expert notes for every entry
above are in [`registry.md`](registry.md) and, for entries not yet promoted,
the source repository's `registry/entries/*.yaml` and
`spec/cpb-provisional-registry.md`.
