# SPDX-License-Identifier: BSD-3-Clause
"""Tests for typed digest reference verification driven by the conformance vectors."""
import pytest

from cpb import (
    ArtifactTypeRegistryEntry,
    ContextMismatchError,
    RepresentationMismatchError,
    TypedRef,
    TypedRefError,
    make_typed_ref,
    verify_typed_ref,
)
from cpb.canonicalize import canonical_digest
from .conftest import load_vectors


def _entry_from_cited(cited: dict) -> ArtifactTypeRegistryEntry:
    reg = cited.get("artifact_type_registry_entry") or cited.get("registry_entry") or {}
    return ArtifactTypeRegistryEntry(
        name=reg.get("name", cited.get("type", "unknown")),
        algorithm=reg.get("algorithm", "jcs-n"),
        exclusion_set=frozenset(reg.get("exclusion_set", [])),
        representation=reg.get("representation", "bare_hex"),
    )


def _typed_ref_fields(d: dict) -> dict:
    """Extract only the three required TypedRef fields from a vector dict."""
    return {k: d[k] for k in ("type", "digest_alg", "digest")}


def test_typed_ref_pass():
    """PASS vectors: verify_typed_ref must succeed."""
    vectors = load_vectors("typed-refs/pass")
    for v in vectors:
        cited = v["cited_artifact"]
        entry = _entry_from_cited(cited)
        ref = TypedRef(**_typed_ref_fields(v["typed_reference"]))
        recomputed = verify_typed_ref(ref, cited["payload"], entry)
        expected = v["verification"]["recomputed_digest"]
        assert recomputed == expected, f"{v['id']}: recomputed {recomputed!r} != {expected!r}"


def test_typed_ref_make_then_verify():
    """make_typed_ref produces a reference that verify_typed_ref accepts."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        exclusion_set=frozenset(["doc_id"]),
    )
    ref = make_typed_ref(payload, entry)
    assert ref.type == "authorization-doc"
    assert ref.digest_alg == "SHA-256"
    assert len(ref.digest) == 64
    verify_typed_ref(ref, payload, entry)


def test_typed_ref_representation_mismatch():
    """typed-ref-fail-03: sha256:-prefixed digest where bare hex is required."""
    vectors = load_vectors("typed-refs/fail")
    rep_mismatch = [v for v in vectors if v.get("failure_reason") == "representation_mismatch"]
    assert rep_mismatch
    for v in rep_mismatch:
        cited = v["cited_artifact"]
        entry = _entry_from_cited(cited)
        ref = TypedRef(**_typed_ref_fields(v["typed_reference_with_wrong_representation"]))
        with pytest.raises(RepresentationMismatchError):
            verify_typed_ref(ref, cited["payload"], entry)


def test_typed_ref_context_mismatch():
    """typed-ref-fail-04: digest computed without correct exclusion set."""
    vectors = load_vectors("typed-refs/fail")
    ctx_mismatch = [v for v in vectors if v.get("failure_reason") == "identifier_inconsistent_with_context"]
    assert ctx_mismatch
    for v in ctx_mismatch:
        cited = v["cited_artifact"]
        entry = _entry_from_cited(cited)
        ref = TypedRef(**_typed_ref_fields(v["typed_reference_with_wrong_digest"]))
        with pytest.raises(ContextMismatchError):
            verify_typed_ref(ref, cited["payload"], entry)


def test_typed_ref_textual_equality_trap():
    """typed-ref-fail-02: two artifact types coincidentally yield the same hex digest.

    The trap: a naive verifier might accept artifact-B bytes for a reference
    claiming artifact-A by observing equal hex strings. The spec prohibits this:
    'Bare hexadecimal equality alone is not a join.'

    This test demonstrates:
    1. Both artifact types produce the same common_digest (the trap precondition).
    2. A conforming verifier resolves the registry entry from the reference type
       field, not from the digest value. Using artifact-B's registry entry for a
       reference claiming artifact-A raises TypedRefError (name mismatch).
    3. A payload that differs from artifact-A bytes fails under artifact-A context.
    """
    vectors = load_vectors("typed-refs/fail")
    v = next(
        (x for x in vectors if x.get("failure_reason") == "digest_context_incompatible_equal_hex_is_not_a_join"),
        None,
    )
    assert v is not None

    # Step 1: verify both artifacts produce the same digest under their own contexts
    artifact_a = v["artifact_a"]
    artifact_b = v["artifact_b"]
    entry_a = ArtifactTypeRegistryEntry(
        name="artifact-a",
        exclusion_set=frozenset(["a_id"]),
    )
    entry_b = ArtifactTypeRegistryEntry(
        name="artifact-b",
        exclusion_set=frozenset(["b_id", "weight"]),
    )
    digest_a = canonical_digest(artifact_a["payload"], entry_a.exclusion_set)
    digest_b = canonical_digest(artifact_b["payload"], entry_b.exclusion_set)
    common = v["common_digest"]
    assert digest_a == common, "artifact-a must produce common_digest"
    assert digest_b == common, "artifact-b must produce common_digest"

    # Step 2: the typed reference claims artifact-A
    ref_a = TypedRef(type="artifact-a", digest_alg="SHA-256", digest=common)

    # Step 2a: correct verification — artifact-A bytes with artifact-A entry → PASS
    verify_typed_ref(ref_a, artifact_a["payload"], entry_a)

    # Step 2b: naive verifier tries artifact-B's registry entry for artifact-A reference
    # → TypedRefError because entry_b.name ('artifact-b') != ref_a.type ('artifact-a')
    with pytest.raises(TypedRefError):
        verify_typed_ref(ref_a, artifact_b["payload"], entry_b)

    # Step 3: a payload differing from artifact-A fails under artifact-A context
    different_payload = {"a_id": None, "color": "blue", "size": "99"}
    with pytest.raises(ContextMismatchError):
        verify_typed_ref(ref_a, different_payload, entry_a)
