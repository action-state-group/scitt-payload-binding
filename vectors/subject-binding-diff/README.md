# Subject-Binding Algorithm Divergence Vectors

## Purpose

These vectors demonstrate the byte-level divergence between the two algorithm
constructions that a reader following composition §6.3.2 and CPB §13 (the
Canonicalization Algorithm Registry) must navigate:

- **Composition §6.3.2** defines the subject binding as `SHA-256(JCS(action))`,
  where JCS is plain RFC 8785 with no normalization pass.
- **CPB §13** (Canonicalization Algorithm Registry) carries `jcs` (RFC 8785, no
  normalization pass) alongside `jcs-n` (RFC 8785 applied to a
  null/empty-member-normalized object) and `cde-n` (reserved).

The two constructions are byte-identical for actions with no null, empty-array, or
empty-object members. They diverge in two distinct directions:

- **Direction A** — same input, different digests: an action with a null, empty-array,
  or empty-object member produces different pre-images under jcs (retains the member)
  and jcs-n (normalizes it away), yielding different SHA-256 digests.
- **Direction B** — acceptance vs rejection: an action with a floating-point member is
  accepted by plain RFC 8785 JCS (jcs) and produces a deterministic digest; jcs-n
  §3.1 prohibits floats and MUST-FAIL on the same input.

## Vector format

Each vector carries `"diverge": true` and three top-level objects:

- `action`: the input action object, read directly from the vector file on disk.
- `jcs`: the plain RFC 8785 result — pre_image, pre_image_bytes_hex, digest.
- `jcs_n`: for Direction A, the jcs-n result — pre_image, pre_image_bytes_hex,
  digest; for Direction B (`jcs_n_must_fail: true`), a must_fail record with
  failure_reason (no digest).

The harness (`check_vectors.py` category J) exercises each vector by direction:

**Direction A** (null/empty members — different digests):
1. Compute plain JCS via `_jcs(action)` (no normalization).
2. Assert computed pre_image and hex match the pinned `jcs` fields.
3. Compute jcs-n via `jcs_n_pre_image(action)` (normalize, then JCS).
4. Assert computed pre_image and hex match the pinned `jcs_n` fields.
5. Assert `jcs.digest != jcs_n.digest` (the divergence is real, not asserted).
Mutation probe: replace null/empty members with `"n/a"` → step 5 must flip to failure.

**Direction B** (`jcs_n_must_fail: true` — acceptance vs rejection):
1. Compute plain RFC 8785 JCS via `_jcs_rfc8785(action)` (floats allowed).
2. Assert computed pre_image and hex match the pinned `jcs` fields.
3. Assert `jcs_n_pre_image(action)` raises (float prohibition §3.1).
Mutation probe: replace float members with string equivalents → jcs-n no longer raises,
jcs.digest == jcs_n.digest → exerciser must flip to failure.

## Vectors

| ID | Diverging member | Direction | jcs.digest | jcs_n |
|---|---|---|---|---|
| subject-binding-diff-01 | `"notes": null` | A | `cb4c539a…` | `163468697d…` |
| subject-binding-diff-02 | `"tags": {}` (empty object) | A | `0fdd1225…` | `163468697d…` |
| subject-binding-diff-03 | `"tags": []` (empty array) | A | `6cbef10f…` | `163468697d…` |
| subject-binding-diff-04 | `"confidence": 0.95` (float) | B | `0fa3ccae…` | MUST-FAIL |

**Direction A cross-vector note:** diff-01, diff-02, and diff-03 produce the same
jcs-n digest (`163468697d…`) because all three normalize to the same two-member object
`{"device":"sensor-01","task":"write-report"}`. Their plain-JCS digests differ because
the pre-images differ. This confirms that null, empty-object, and empty-array are
independent divergence sources: any one of them suffices to fork the digests.

**Direction B note:** diff-04 shows the sharpest form of divergence — not merely a
different digest but a categorical split between acceptance and rejection. A composition
implementation following §6.3.2 literally produces a usable digest for
`{"confidence": 0.95, …}`; a CPB jcs-n verifier fails closed on the same input.

## Decision context

Source: external review by Imran Siddique (2026-08-17, #34) — the divergence between
composition §6.3.2's plain-JCS subject binding and CPB's registered `jcs-n`
construction. Anton Sokolov (2026-08-18) extended the vector suite with the
Direction B (float) pair and reviewed the registry resolution. Resolution recorded
in the `jcs` registry entry in REGISTRY.md.

The resolution adopted for CPB is:

**(a) Register `jcs` as an immutable Canonicalization Algorithm Registry entry,**
legitimizing composition §6.3.2 as written. The `jcs` entry is registered with
composition subject binding (§6.3.2) as its named consuming profile.

This closes the registry gap found by these vectors: the construction composition §6.3.2
specifies was not registered, so a verifier could not perform an O(1) algorithm lookup.
The `jcs` entry makes the algorithm token explicit and pins the digest context (plain
RFC 8785, no normalization, SHA-256, lowercase hex).
