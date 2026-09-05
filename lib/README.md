# CPB Reference Library

Python reference library for **Canonical Payload Binding**
(`draft-mih-sokolov-scitt-payload-binding-02`).

Live construction uses RFC 8785 `jcs`. The older `jcs-n` algorithm was withdrawn
on 2026-08-18: its byte construction remains for historical records, but it
cannot be used for new derived identifiers or typed references. Historical
verification requires raw JSON plus profile-defined cryptographic evidence of a
pre-cutoff vintage; digest equality alone is only an evaluation result.

Implements three CPB mechanisms with no payload-profile semantics:

| Module | Spec section | What it implements |
|---|---|---|
| `cpb.canonicalize` | §4 | Live `jcs` and historical `jcs-n`, including duplicate-preserving raw-JSON paths |
| `cpb.derive_id` | §5 | Raw-JSON identifier construction and verification, plus historical evaluation |
| `cpb.typed_ref` | §8 | Raw-JSON typed-reference construction and verification, plus historical evaluation |

## Install

```
pip install -e ".[dev]"   # from this directory
```

## 0.2 migration

Version 0.2 makes content-address changes explicit rather than silently
reinterpreting 0.1 calls:

- `canonical_digest(..., algorithm=...)` now requires the algorithm keyword.
- `ArtifactDigestContext` replaces the flattened registry-entry model;
  `ArtifactTypeRegistryEntry` remains a migration alias only.
- typed-reference construction and verification require an immutable
  `ArtifactTypeDefinition`, whose content address binds the complete context
  set. Bare context sequences are rejected, so a caller cannot accidentally
  pass only its selected row and mask missing-purpose ambiguity.
- `whole_object_exclusion_set=frozenset(...)` explicitly opts into the only
  generic field-selection mode this library executes. `None` is metadata-only
  and cannot accidentally hash a profile-specific subset as a whole object.

`ArtifactTypeDefinition.for_construction(...)` declares a producer's complete
local set and exposes its stable `context_set_sha256` for publication, but that
construction-only object cannot authorize a verification verdict. A verifier
must either pass the independently trusted published value as the required
`expected_context_set_sha256=` argument to `from_contexts`, or resolve the type
from a `RegistrySnapshot` loaded with an independently trusted snapshot pin.
The set's own hash detects truncation; it does not prove its origin.

## Live construction and verification

```python
from cpb import (
    ArtifactDigestContext,
    ArtifactTypeDefinition,
    make_typed_ref_json,
    verify_typed_ref,
)

raw = b'{"doc_id":null,"subject":"WS-42","scope":"temperature-write"}'
entry = ArtifactDigestContext(
    name="authorization-doc",
    algorithm="jcs",
    whole_object_exclusion_set=frozenset(["doc_id"]),
    representation="bare-hex",
)
producer_definition = ArtifactTypeDefinition.for_construction([entry])
# This constant is published by the profile and provisioned independently to
# the verifier; it is not recomputed from contexts received with the reference.
TRUSTED_CONTEXT_SET_SHA256 = "aacae53d98b6936b733ffc8a4f138c1320cbbd3041f396b7f28b25a6de0a524d"
assert producer_definition.context_set_sha256 == TRUSTED_CONTEXT_SET_SHA256
ref = make_typed_ref_json(raw, producer_definition)

verifier_definition = ArtifactTypeDefinition.from_contexts(
    [entry],
    expected_context_set_sha256=TRUSTED_CONTEXT_SET_SHA256,
)
verify_typed_ref(ref, raw, verifier_definition)
```

Construction and verification take raw JSON so duplicate members can be
rejected before a normal parser collapses them. Parsed-value helpers are
evaluation APIs only and do not claim wire conformance.

## Historical `jcs-n` verification

```python
from cpb import ArtifactDigestContext, ArtifactTypeDefinition, TypedRef, verify_typed_ref

raw = b'{"doc_id":null,"subject":"WS-42","scope":"temperature-write","issued_at":"2026-07-24T00:00:00Z"}'
entry = ArtifactDigestContext(
    name="authorization-doc",
    algorithm="jcs-n",
    whole_object_exclusion_set=frozenset(["doc_id"]),
    representation="bare-hex",
)
artifact_type = ArtifactTypeDefinition.from_contexts(
    [entry],
    # Independently provisioned from the historical profile, not derived from
    # the context sequence being checked.
    expected_context_set_sha256="5206e45c19b3256f3a450f63d973deaf34692d285d181cc5677d4184d81f82a1",
)
ref = TypedRef(
    type="authorization-doc",
    digest_alg="SHA-256",
    digest="0c837d01faa4106c63367f199af9bfa729d1917f36dc91f9dfeb6de6ec7c6bdb",
)

def verify_profile_timestamp(evidence, recomputed_digest):
    # `profile_timestamp_verifier` is supplied by the consuming profile. It
    # authenticates the proof, verifies the digest binding, and returns the
    # authenticated time; CPB does not define that proof format.
    return profile_timestamp_verifier.verify(
        evidence, expected_digest=recomputed_digest
    )

verify_typed_ref(
    ref,
    raw,
    artifact_type,
    vintage_evidence={"bound_digest": ref.digest, "proof": b"..."},
    verify_vintage_evidence=verify_profile_timestamp,
)
```

`evaluate_derived_id`, `canonical_digest`, and `evaluate_typed_ref_digest`
remain available for non-verifying inspection of retained historical fixtures.
Selecting `algorithm="jcs-n"` in `derive_id` or `make_typed_ref_json` rejects new
construction; `make_typed_ref` rejects every parsed construction input.
The JSON TypedRef wire form has a string-valued `digest`, so high-level
construction and verification reject a context whose representation is `raw`;
raw-byte comparison remains available only through the diagnostic evaluator.

## Pinned registry resolution

When a registry snapshot is the trust source, bind its complete artifact-type
row directly instead of flattening or preselecting one context:

```python
from cpb.registry import RegistrySnapshot

snapshot = RegistrySnapshot.load(
    "registry.json",
    expected_sha256=TRUSTED_REGISTRY_SNAPSHOT_SHA256,
)
artifact_type = snapshot.artifact_type_definition(
    "machine-mandate",
    # Supplied by verifier-owned profile code after checking the normative
    # field selection; omit this argument to retain metadata-only contexts.
    implementations=[profile_checked_equivalence_context],
)
```

The resolver retains every sibling context from the pinned registry entry.
Contexts without a supplied executable implementation remain metadata-only and
fail closed if selected. The registry stores field-selection prose, so the
consuming profile must independently check any supplied implementation against
its normative field-selection rules.

## Test suite

Tests are driven by the conformance vector suite in `../vectors/`:

```
pytest
```

All PASS vectors must produce the expected digest; all MUST-FAIL vectors must
raise the appropriate exception. The test suite is the vector suite itself.
