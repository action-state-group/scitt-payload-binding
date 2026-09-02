# CPB registry entries — the join-without-asking path

This directory is the machine-checkable half of the CPB registry submission
process. **REGISTRY.md remains the normative record** — its live tables are
where an entry ultimately lives once promoted (Rung 1/2), and
[`spec/cpb-provisional-registry.md`](../spec/cpb-provisional-registry.md)
remains the normative record of provisional (Rung 3) filings under discussion
with their owners. Nothing here changes that. What this directory adds is a
**structured, schema-validated filing format** so a new registrant does not
have to read and correctly reproduce ~800 lines of prose convention by hand
before their first PR can go green.

## The idea

1. Copy [`entries/TEMPLATE.yaml`](entries/TEMPLATE.yaml) to
   `entries/<name>.yaml`.
2. Answer the seven questions it asks — construction as data (digest-input
   bytes, exclusions, canonicalization profile, hash, representation),
   composite-or-not, and cross-language parity — plus the metadata REGISTRY.md
   already requires (owner, reference, rung/status, open questions).
3. If you have vectors, commit them under `vectors/<name>/` and point
   `fixtures.vectors_dir` at them.
4. Open a PR. [`.github/workflows/registry-entries.yml`](../.github/workflows/registry-entries.yml)
   runs [`.github/validate_registry_entries.py`](../.github/validate_registry_entries.py),
   which:
   - validates your file against [`entry.schema.json`](entry.schema.json);
   - if you declared `fixtures.vectors_dir`, runs
     [`.github/check_vectors.py`](../.github/check_vectors.py) against it and
     **rejects the entry** if any vector fails to execute, or if the set is
     not two-sided (Registration Rule 2) — unless you cited an owner's
     external, commit-pinned vector set instead
     (`fixtures.external_vector_set`), which this repo cannot execute and
     does not try to.
5. Green CI gets you a schema-valid, mechanically-checked filing — which is
   what "reach `provisional` without a conversation" means here. It does
   **not** skip Designated Expert review (REGISTRY.md's Registration Ladder
   and Admission Checklist, Gates A/B/C) for promotion past `provisional`, and
   it does not skip human review of required-field presence and content —
   REGISTRY.md is explicit that no CI job evaluates the DE gates, and this
   tooling does not change that. What it removes is the part that used to
   require reading the whole document to get the *shape* right.

## What this is not

- **Not a second source of truth.** `registry/entries/*.yaml` files are
  filings, not the registry. A promoted entry's normative text still lives in
  REGISTRY.md. Nothing here regenerates or overrides REGISTRY.md or
  `registry.json`; `.github/gen_registry.py` is unchanged and still owns that
  pipeline.
- **Not a policy change.** The Registration Ladder, the Status Vocabulary, the
  Designated Expert Admission Checklist, and the Third-Party Registration
  Rules are exactly as REGISTRY.md states them today. This directory is
  tooling built against that policy, not a proposal to change it. The
  registration **policy draft** under active ratification (lifecycle,
  immutability at promotion, ≥2-organization expert review, and the
  IANA-forwarding clause) is a separate document —
  [`spec/cpb-registry-policy.md`](../spec/cpb-registry-policy.md) — and is
  HELD pending Steven and Anton's sign-off; it is not merged policy and this
  tooling does not depend on it landing to be useful today.
- **Not a substitute for owner confirmation.** A `provisional` or
  `third-party-documented` filing here is exactly as provisional or
  third-party as the equivalent prose filing would be. Nothing in this schema
  lets a filer assert `owner-confirmed` for someone else's construction.

## Filed entries

| File | Registers | Rung / status |
|---|---|---|
| [`entries/agent-action-capsule.yaml`](entries/agent-action-capsule.yaml) | `agent-action-capsule` artifact type | owner_authored / owner-confirmed — conforms the existing live REGISTRY.md entry to this template; does not change its registered behavior |
| [`entries/cll-checkpoint.yaml`](entries/cll-checkpoint.yaml) | `cll-checkpoint` artifact type (capsule-ledger's `CheckpointRecord`) | provisional — carries forward the open identifier-construction question from the `mmr-checkpoint` filing in `spec/cpb-provisional-registry.md`; DE reviewer Anton Sokolov |
| [`entries/mesh-inference-exchange.yaml`](entries/mesh-inference-exchange.yaml) | `mesh-inference-exchange` artifact type | provisional — conforms the existing `spec/cpb-provisional-registry.md` filing (as revised for Anton's PR #70 review) to this template; open items unchanged |
| [`entries/vto.yaml`](entries/vto.yaml) | `vto` artifact type | reserved — a name hold only; the full entry (plus its CBOR canonicalization profile) is a separate, sibling filing (`[cpb-vto-provisional-entries]`) blocked on the libp2p team's CDDL/instance/float-field artifacts |

Each of these is a worked example of the template — read them alongside
`TEMPLATE.yaml` if a field's intent isn't obvious from the template comments
alone.
