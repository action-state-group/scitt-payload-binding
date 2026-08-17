# Subject-Binding Algorithm Divergence Vectors

## Purpose

These vectors demonstrate the byte-level divergence between the two algorithm
constructions that a reader following composition §6.3.2 and CPB §13 (the
Canonicalization Algorithm Registry) must navigate:

- **Composition §6.3.2** defines the subject binding as `SHA-256(JCS(action))`,
  where JCS is plain RFC 8785 with no normalization pass.
- **CPB §13** (Canonicalization Algorithm Registry) carries only `jcs-n` (RFC 8785
  applied to a null/empty-member-normalized object) and `cde-n` (reserved). Plain
  `jcs` is not registered.

The two constructions are byte-identical for actions with no null, empty-array, or
empty-object members. They diverge exactly when any such member is present, producing
different pre-images and different SHA-256 digests for the same action object.

## Vector format

Each vector carries `"diverge": true` and three top-level objects:

- `action`: the input action object, read directly from the vector file on disk.
- `jcs`: the plain RFC 8785 result — pre_image, pre_image_bytes_hex, digest.
- `jcs_n`: the jcs-n result (normalization pass applied first) — pre_image,
  pre_image_bytes_hex, digest.

The harness (`check_vectors.py` category J) exercises each vector by:
1. Computing plain JCS via `_jcs(action)` (no normalization).
2. Asserting the computed pre_image and its hex encoding match the pinned `jcs` fields.
3. Computing jcs-n via `jcs_n_pre_image(action)` (normalize, then JCS).
4. Asserting the computed pre_image and its hex encoding match the pinned `jcs_n` fields.
5. Asserting `jcs.digest != jcs_n.digest` (the divergence is real, not asserted).

The harness also runs a mutation probe: null/empty members in the action are replaced
with `"n/a"`, the pinned fields are recomputed for the non-diverging action, and the
inequality assertion at step 5 must flip to failure. This confirms the divergence check
can actually fail — it is not assertion-free.

## Vectors

| ID | Diverging member | jcs.digest | jcs_n.digest |
|---|---|---|---|
| subject-binding-diff-01 | `"notes": null` | `cb4c539a…` | `163468697d…` |
| subject-binding-diff-02 | `"tags": {}` (empty object) | `0fdd1225…` | `163468697d…` |

Note: both vectors produce the same jcs-n digest (`163468697d…`) because both
normalize to the same two-member object `{"device":"sensor-01","task":"write-report"}`.
Their plain-JCS digests differ because the pre-images differ (one retains `null`, the
other retains `{}`). This cross-vector relationship is informative: the same subject
would be computed for both normalized actions under jcs-n, but for neither under plain
JCS if the action carries either member.

## Decision context

Source: external review by Imran Siddique (2026-08-17). A public issue link will be
added to this README when it exists and will become the canonical citation.

The resolution options are:

**(a)** Register `jcs` as its own immutable Canonicalization Algorithm Registry entry
in CPB, legitimizing composition §6.3.2 as written.

**(b)** Amend composition §6.3.2 to name `jcs-n` and state the normalization pass,
making composition consistent with the CPB registry.

The choice is a spec-tier (Steven + Anton) decision. See the PR description for both
resolution texts.
