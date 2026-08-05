# SPDX-License-Identifier: BSD-3-Clause
"""Completeness backstop: every must_fail:true vector in the tree is executed.

Round-2 gap (Anton): typed-ref-fail-01 and profile-independence-fail-01 sat
on disk, loaded by ``load_vectors``, but never actually selected by any
``failure_reason`` filter in the other test files -- so the suite silently
advertised full conformance while two must_fail vectors were dead weight.

This module is self-contained and does not depend on the other test
modules' filters or on pytest's execution order: it walks every
``vectors/**/*.json`` file directly, and for each ``must_fail: true``
vector dispatches by ``failure_reason`` to a real assertion against the
``cpb`` library. A ``failure_reason`` with no registered handler in
``_HANDLERS`` is a hard failure -- a vector cannot silently pass by going
unrecognized, and a newly added must_fail vector cannot silently ship
unexercised the way fail-01 and profile-independence-fail-01 did.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from cpb import (
    ArtifactTypeRegistryEntry,
    CarriedIdMismatch,
    ContextMismatchError,
    RepresentationMismatchError,
    TypedRef,
    UnsafeIntegerError,
    canonical_digest,
    verify_carried_id,
    verify_typed_ref,
)
from cpb.canonicalize import FloatInDigestError

VECTORS_DIR = pathlib.Path(__file__).parent.parent.parent / "vectors"


def _entry_from_registry_entry(reg: dict, fallback_name: str) -> ArtifactTypeRegistryEntry:
    return ArtifactTypeRegistryEntry(
        name=reg.get("name", fallback_name),
        algorithm=reg.get("algorithm", "jcs-n"),
        exclusion_set=frozenset(reg.get("exclusion_set", [])),
        representation=reg.get("representation", "bare_hex"),
    )


# ---------------------------------------------------------------------------
# Per-failure_reason handlers: each asserts a real rejection against the
# actual cpb library (not a reimplementation).
# ---------------------------------------------------------------------------

def _handle_float_in_digest_bearing_field(v: dict) -> None:
    excl = set(v.get("exclusion_set", []))
    with pytest.raises(FloatInDigestError):
        canonical_digest(v["input"], excl or None)


def _handle_unsafe_integer_in_digest_bearing_field(v: dict) -> None:
    excl = set(v.get("exclusion_set", []))
    with pytest.raises(UnsafeIntegerError):
        canonical_digest(v["input"], excl or None)


def _handle_integer_formatting_divergence(v: dict) -> None:
    # >= 1e21 is also outside the safe-integer bound, so the library's
    # single bound (§3.1) rejects it via the same UnsafeIntegerError path.
    excl = set(v.get("exclusion_set", []))
    with pytest.raises(UnsafeIntegerError):
        canonical_digest(v["input"], excl or None)


def _handle_carried_id_mismatch(v: dict) -> None:
    excl = set(v.get("exclusion_set", []))
    with pytest.raises(CarriedIdMismatch):
        verify_carried_id(v["full_payload"], carried_field="record_id", exclusion_set=excl or None)


def _handle_recomputed_digest_mismatch(v: dict) -> None:
    """typed-ref-fail-01: verifier applies the wrong exclusion set."""
    cited = v["cited_artifact"]
    ref = TypedRef(**{k: v["typed_reference"][k] for k in ("type", "digest_alg", "digest")})
    wrong_entry = ArtifactTypeRegistryEntry(
        name=cited["artifact_type_registry_entry"]["name"],
        exclusion_set=frozenset(v["erroneous_verification"]["wrong_exclusion_set"]),
    )
    with pytest.raises(ContextMismatchError):
        verify_typed_ref(ref, cited["payload"], wrong_entry)


def _handle_textual_equality_trap(v: dict) -> None:
    """typed-ref-fail-02: equal-looking hex under incompatible contexts is not a join."""
    entry_a = ArtifactTypeRegistryEntry(name="artifact-a", exclusion_set=frozenset(["a_id"]))
    ref_a = TypedRef(type="artifact-a", digest_alg="SHA-256", digest=v["common_digest"])
    different_payload = {"a_id": None, "color": "blue", "size": "99"}
    with pytest.raises(ContextMismatchError):
        verify_typed_ref(ref_a, different_payload, entry_a)


def _cited_registry_entry(cited: dict) -> dict:
    """Vector files spell this key differently ('registry_entry' vs
    'artifact_type_registry_entry') depending on which round they were
    authored in; accept either, matching test_typed_refs._entry_from_cited."""
    return cited.get("artifact_type_registry_entry") or cited.get("registry_entry") or {}


def _handle_representation_mismatch(v: dict) -> None:
    cited = v["cited_artifact"]
    reg = _cited_registry_entry(cited)
    entry = _entry_from_registry_entry(reg, cited.get("type", reg.get("name", "unknown")))
    ref = TypedRef(
        **{k: v["typed_reference_with_wrong_representation"][k] for k in ("type", "digest_alg", "digest")}
    )
    with pytest.raises(RepresentationMismatchError):
        verify_typed_ref(ref, cited["payload"], entry)


def _handle_identifier_inconsistent_with_context(v: dict) -> None:
    cited = v["cited_artifact"]
    reg = _cited_registry_entry(cited)
    entry = _entry_from_registry_entry(reg, cited.get("type", reg.get("name", "unknown")))
    ref = TypedRef(
        **{k: v["typed_reference_with_wrong_digest"][k] for k in ("type", "digest_alg", "digest")}
    )
    with pytest.raises(ContextMismatchError):
        verify_typed_ref(ref, cited["payload"], entry)


def _handle_nfc_normalisation_deviation(v: dict) -> None:
    """jcs-n-nfc-contrast-01: informative. jcs-n does NOT normalise; the
    library's actual output must land on the non-normalising (correct) side,
    never the nfc_contrast (would-be-normalised) side."""
    excl = set(v.get("exclusion_set", []))
    digest = canonical_digest(v["input"], excl or None)
    assert digest == v["jcs_n_correct_digest"]
    assert digest != v["nfc_contrast_digest"]


def _handle_profile_independence_violation(v: dict) -> None:
    """profile-independence-fail-01: informative/behavioral. The executable
    contract is the documented CONFORMING alternative -- see
    test_profile_independence.py for the full narrative test; here we just
    re-confirm the digest-only binding succeeds."""
    scenario = v["scenario"]
    auth_doc = scenario["authorization_doc"]
    ref_fields = scenario["decision_record"]["payload"]["authorization"]
    ref = TypedRef(
        type=ref_fields["type"], digest_alg=ref_fields["digest_alg"], digest=ref_fields["digest"]
    )
    entry = ArtifactTypeRegistryEntry(name="authorization-doc", exclusion_set=frozenset(["doc_id"]))
    recomputed = verify_typed_ref(ref, auth_doc["payload"], entry)
    assert recomputed == auth_doc["derived_id"]


_HANDLERS = {
    "float_in_digest_bearing_field": _handle_float_in_digest_bearing_field,
    "unsafe_integer_in_digest_bearing_field": _handle_unsafe_integer_in_digest_bearing_field,
    "integer_formatting_divergence": _handle_integer_formatting_divergence,
    "carried_id_mismatch": _handle_carried_id_mismatch,
    "recomputed_digest_mismatch": _handle_recomputed_digest_mismatch,
    "digest_context_incompatible_equal_hex_is_not_a_join": _handle_textual_equality_trap,
    "representation_mismatch": _handle_representation_mismatch,
    "identifier_inconsistent_with_context": _handle_identifier_inconsistent_with_context,
    "nfc_normalisation_deviation": _handle_nfc_normalisation_deviation,
    "profile_independence_violation": _handle_profile_independence_violation,
}


def _all_vectors() -> list[tuple[dict, pathlib.Path]]:
    return [(json.loads(f.read_text(encoding="utf-8")), f) for f in sorted(VECTORS_DIR.rglob("*.json"))]


def _must_fail_by_id() -> dict[str, tuple[dict, pathlib.Path]]:
    return {v["id"]: (v, path) for v, path in _all_vectors() if v.get("must_fail")}


_MUST_FAIL_BY_ID = _must_fail_by_id()


@pytest.mark.parametrize("vid", sorted(_MUST_FAIL_BY_ID))
def test_every_must_fail_vector_is_exercised(vid: str) -> None:
    vector, path = _MUST_FAIL_BY_ID[vid]
    reason = vector.get("failure_reason")
    handler = _HANDLERS.get(reason)
    assert handler is not None, (
        f"{vid} ({path}): failure_reason {reason!r} has no registered handler "
        f"in _HANDLERS -- every must_fail vector must be either executed here "
        f"or its failure_reason explicitly added to _HANDLERS; a vector cannot "
        f"silently pass conformance by going unrecognized"
    )
    handler(vector)


def test_no_must_fail_vector_missing_failure_reason() -> None:
    """Guard against a future must_fail vector added without a failure_reason,
    which would silently bypass dispatch above (KeyError-free but unexercised)."""
    for vid, (vector, path) in _MUST_FAIL_BY_ID.items():
        assert vector.get("failure_reason"), f"{vid} ({path}): must_fail vector missing failure_reason"


def test_handler_registry_covers_every_failure_reason_on_disk() -> None:
    """Self-check on the dispatcher itself: the set of failure_reason values
    actually present in the vector tree must be a subset of _HANDLERS' keys.
    (test_every_must_fail_vector_is_exercised already enforces this per-vector;
    this is a cheap second assertion so the gap shows up even if parametrize
    collection is ever filtered by test selection.)"""
    reasons_on_disk = {v.get("failure_reason") for v, _ in _MUST_FAIL_BY_ID.values()}
    missing = reasons_on_disk - set(_HANDLERS)
    assert not missing, f"failure_reason values with no handler: {missing}"
