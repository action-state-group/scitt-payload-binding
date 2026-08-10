# SPDX-License-Identifier: BSD-3-Clause
"""Tests for typed digest reference verification driven by the conformance vectors."""
import pytest

from cpb import (
    ArtifactTypeRegistryEntry,
    ContextMismatchError,
    DigestAlgorithmMismatchError,
    RepresentationMismatchError,
    TypedRef,
    TypedRefError,
    hex_to_raw,
    make_typed_ref,
    raw_to_hex,
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


def _entry_from_vector(v: dict) -> ArtifactTypeRegistryEntry:
    """Like _entry_from_cited, but also checks the vector's top level.

    typed-ref-cpb01-01 (ARP fold, folded byte-for-byte from Joel Hillier's
    arp-typed-ref-cpb01-v0.1.json) carries artifact_type_registry_entry as a
    sibling of cited_artifact rather than nested inside it.
    """
    cited = v["cited_artifact"]
    if cited.get("artifact_type_registry_entry") or cited.get("registry_entry"):
        return _entry_from_cited(cited)
    return _entry_from_cited({"artifact_type_registry_entry": v.get("artifact_type_registry_entry", {})})


def test_typed_ref_pass():
    """PASS vectors: verify_typed_ref must succeed.

    typed-ref-cpb01-01's expected digest lives under `expected`, not
    `verification`, per that vector's own field layout (see
    _entry_from_vector for the registry-entry counterpart).
    """
    vectors = load_vectors("typed-refs/pass")
    for v in vectors:
        cited = v["cited_artifact"]
        entry = _entry_from_vector(v)
        ref = TypedRef(**_typed_ref_fields(v["typed_reference"]))
        recomputed = verify_typed_ref(ref, cited["payload"], entry)
        result = v.get("verification") or v.get("expected") or {}
        expected = result["recomputed_digest"]
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


def test_typed_ref_recomputed_digest_mismatch_wrong_exclusion_set():
    """typed-ref-fail-01: a verifier that applies the WRONG exclusion set
    (omitting the registry-declared one) must not silently accept the
    resulting recomputation. Round-2 gap: this vector (failure_reason
    'recomputed_digest_mismatch') was loaded but never selected by any
    filter in this file, so it was never actually run against the library."""
    vectors = load_vectors("typed-refs/fail")
    v = next((x for x in vectors if x.get("failure_reason") == "recomputed_digest_mismatch"), None)
    assert v is not None, "typed-ref-fail-01 (recomputed_digest_mismatch) not found"

    cited = v["cited_artifact"]
    ref = TypedRef(**_typed_ref_fields(v["typed_reference"]))

    # The vector's carried digest verifies under the CORRECT (registry) context.
    correct_entry = _entry_from_cited(cited)
    assert verify_typed_ref(ref, cited["payload"], correct_entry) == cited["correct_derived_id"]

    # A verifier that applies the wrong exclusion set (per the vector's own
    # erroneous_verification.wrong_exclusion_set) must raise, not match.
    wrong_exclusion_set = frozenset(v["erroneous_verification"]["wrong_exclusion_set"])
    wrong_entry = ArtifactTypeRegistryEntry(
        name=cited["artifact_type_registry_entry"]["name"],
        exclusion_set=wrong_exclusion_set,
    )
    with pytest.raises(ContextMismatchError):
        verify_typed_ref(ref, cited["payload"], wrong_entry)


def test_typed_ref_digest_alg_mismatch_rejected():
    """Round-2 Blocker 1: verify_typed_ref must enforce digest_alg. A
    reference labeled with a hash algorithm other than the one this
    artifact type's registered canonicalization algorithm actually uses
    (jcs-n => SHA-256) must be rejected -- even when the digest value
    itself would otherwise match under the correct context."""
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
    correct_digest = canonical_digest(payload, entry.exclusion_set)

    # Positive: digest_alg matching the registered algorithm's hash (SHA-256) verifies.
    ref_correct = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=correct_digest)
    assert verify_typed_ref(ref_correct, payload, entry) == correct_digest

    # Negative: a SHA-512-labeled reference to the same digest value must NOT
    # verify under a jcs-n/SHA-256 context.
    ref_mislabeled = TypedRef(type="authorization-doc", digest_alg="SHA-512", digest=correct_digest)
    with pytest.raises(DigestAlgorithmMismatchError):
        verify_typed_ref(ref_mislabeled, payload, entry)


def test_typed_ref_digest_algorithm_inconsistent_with_context():
    """typed-ref-fail-05 (-01 §7.1): a verifier that recomputes and compares
    digest bytes without independently confirming digest_alg would wrongly
    accept every example below, since the carried digest is the correct
    SHA-256 value in each case. SHA-512, MD5, an unregistered name and the
    empty string must all be rejected against a jcs-n (SHA-256) context."""
    vectors = load_vectors("typed-refs/fail")
    v = next((x for x in vectors if x.get("failure_reason") == "digest_algorithm_inconsistent_with_context"), None)
    assert v is not None, "typed-ref-fail-05 (digest_algorithm_inconsistent_with_context) not found"

    cited = v["cited_artifact"]
    entry = _entry_from_cited(cited)
    assert canonical_digest(cited["payload"], entry.exclusion_set) == v["correct_recomputed_digest"]

    for example in v["typed_references_with_mislabeled_digest_alg"]:
        ref = TypedRef(type=cited["type"], digest_alg=example["digest_alg"], digest=example["digest"])
        with pytest.raises(DigestAlgorithmMismatchError):
            verify_typed_ref(ref, cited["payload"], entry)


def test_typed_ref_raw_representation_boundary():
    """Round-2 Blocker 2: raw octets and hex are distinct, non-interchangeable
    representations (§4.1) -- not two spellings of one 'bare_hex' concept.
    A hex string is REJECTED where 'raw' (bytes) is declared, and a bytes
    object is REJECTED where 'bare_hex' (str) is declared, even when one is
    exactly the decoding of the other."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    hex_entry = ArtifactTypeRegistryEntry(name="authorization-doc", exclusion_set=frozenset(["doc_id"]))
    raw_entry = ArtifactTypeRegistryEntry(
        name="authorization-doc", exclusion_set=frozenset(["doc_id"]), representation="raw",
    )
    digest_hex = canonical_digest(payload, hex_entry.exclusion_set)
    digest_raw = hex_to_raw(digest_hex)

    # Positive: raw bytes verify under a 'raw' registry entry.
    ref_raw = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_raw)
    assert verify_typed_ref(ref_raw, payload, raw_entry) == digest_hex

    # Positive: the hex str verifies under a 'bare_hex' registry entry.
    ref_hex = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_hex)
    assert verify_typed_ref(ref_hex, payload, hex_entry) == digest_hex

    # Boundary negative: the hex str of the CORRECT digest is rejected where
    # 'raw' is declared -- content is right, representation is wrong.
    ref_hex_as_raw = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_hex)
    with pytest.raises(RepresentationMismatchError):
        verify_typed_ref(ref_hex_as_raw, payload, raw_entry)

    # Boundary negative: the raw bytes of the CORRECT digest are rejected
    # where 'bare_hex' is declared.
    ref_raw_as_hex = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_raw)
    with pytest.raises(RepresentationMismatchError):
        verify_typed_ref(ref_raw_as_hex, payload, hex_entry)

    # Explicit conversions round-trip.
    assert hex_to_raw(raw_to_hex(digest_raw)) == digest_raw
    assert raw_to_hex(hex_to_raw(digest_hex)) == digest_hex
