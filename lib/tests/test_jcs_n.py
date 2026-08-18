# SPDX-License-Identifier: BSD-3-Clause
"""Tests for Algorithm jcs-n driven by the conformance vector suite.

Every PASS vector must produce the expected pre_image and digest.
Every MUST-FAIL vector must raise the appropriate error.
"""
import hashlib
import pytest

from cpb import FloatInDigestError, UnsafeIntegerError, canonical_digest, jcs, normalize
from .conftest import load_vectors


def _run_pass_vector(v: dict) -> None:
    payload = v["input"]
    excl = set(v.get("exclusion_set", []))
    expected_pre_image = v["pre_image"]
    expected_digest = v["digest"]
    expected_hex = v["pre_image_bytes_hex"]

    # Verify pre_image and digest are consistent
    assert (
        expected_pre_image.encode("utf-8").hex() == expected_hex
    ), f"{v['id']}: pre_image_bytes_hex mismatch"
    assert (
        hashlib.sha256(expected_pre_image.encode("utf-8")).hexdigest() == expected_digest
    ), f"{v['id']}: pre_image → digest mismatch (vector self-check)"

    # Verify the library produces the correct pre_image and digest
    if excl:
        payload = {k: val for k, val in payload.items() if k not in excl}
    normalized = normalize(payload)
    canon = jcs(normalized)
    assert (
        canon.decode("utf-8") == expected_pre_image
    ), f"{v['id']}: library pre_image mismatch"
    assert (
        canonical_digest(v["input"], excl or None) == expected_digest
    ), f"{v['id']}: canonical_digest mismatch"


def test_jcs_n_pass_vectors():
    """All non-must_fail jcs-n KAT vectors must pass."""
    vectors = load_vectors("jcs-n/kats")
    pass_vectors = [v for v in vectors if not v.get("must_fail")]
    assert pass_vectors, "no PASS vectors found"
    for v in pass_vectors:
        _run_pass_vector(v)


def test_jcs_n_e3_boundary_group():
    """E3 boundary group: null, empty-array, empty-object, absent, and
    nested-null-bottom-up all produce the same canonical form and digest."""
    vectors = load_vectors("jcs-n/kats")
    # KAT IDs 02 through 06 (and 07) are the E3 boundary group
    e3_ids = {
        "jcs-n-kat-02", "jcs-n-kat-03", "jcs-n-kat-04",
        "jcs-n-kat-05", "jcs-n-kat-06", "jcs-n-kat-07",
    }
    e3 = [v for v in vectors if v["id"] in e3_ids]
    assert len(e3) == 6, f"expected 6 E3 boundary vectors, got {len(e3)}"
    digests = {v["id"]: v["digest"] for v in e3}
    pre_images = {v["id"]: v["pre_image"] for v in e3}
    # All must produce the same canonical form
    unique_pre_images = set(pre_images.values())
    assert len(unique_pre_images) == 1, (
        f"E3 boundary group: expected all same pre_image, got {unique_pre_images}"
    )
    unique_digests = set(digests.values())
    assert len(unique_digests) == 1, (
        f"E3 boundary group: expected all same digest, got {unique_digests}"
    )


def test_jcs_n_float_rejected():
    """MUST-FAIL: float in digest-bearing field."""
    vectors = load_vectors("jcs-n/kats")
    float_vectors = [v for v in vectors if v.get("must_fail") and v.get("failure_reason") == "float_in_digest_bearing_field"]
    assert float_vectors, "no float MUST-FAIL vector found"
    for v in float_vectors:
        with pytest.raises(FloatInDigestError):
            canonical_digest(v["input"])


def test_jcs_n_exclusion_groups():
    """KATs 08 and 09 (exclusion set) should produce the same digest as KAT 01."""
    vectors = load_vectors("jcs-n/kats")
    by_id = {v["id"]: v for v in vectors}
    assert by_id["jcs-n-kat-08"]["digest"] == by_id["jcs-n-kat-01"]["digest"]
    assert by_id["jcs-n-kat-09"]["digest"] == by_id["jcs-n-kat-01"]["digest"]


def test_jcs_n_error_messages_name_path():
    """Defect-5 fix: error messages must name the JSON path to the offending field.

    The MUST in §3.1 is 'reject with an error naming the field'. Both
    FloatInDigestError and UnsafeIntegerError must include the dotted path
    so a caller can report which field to fix without inspecting every key.

    Mutant test: remove ``_path`` from ``_jcs_value`` — both assertions
    fail because the path string no longer appears in the message.
    """
    # Nested float: path must name the full dotted chain.
    with pytest.raises(FloatInDigestError) as exc_info:
        canonical_digest({"outer": {"inner": {"latency_ms": 1.25}}})
    assert "outer.inner.latency_ms" in str(exc_info.value), (
        f"path not in float error: {exc_info.value}"
    )

    # Top-level float: path is just the key name.
    with pytest.raises(FloatInDigestError) as exc_info:
        canonical_digest({"amount": 99.9})
    assert "amount" in str(exc_info.value), (
        f"path not in top-level float error: {exc_info.value}"
    )

    # Nested unsafe integer: same path requirement applies.
    with pytest.raises(UnsafeIntegerError) as exc_info:
        canonical_digest({"outer": {"seq": 2**53}})
    assert "outer.seq" in str(exc_info.value), (
        f"path not in unsafe-integer error: {exc_info.value}"
    )

    # Float inside an array: path uses bracket notation.
    with pytest.raises(FloatInDigestError) as exc_info:
        canonical_digest({"items": [1, 2.5, 3]})
    assert "items[1]" in str(exc_info.value), (
        f"array path not in float error: {exc_info.value}"
    )


def test_jcs_n_bottom_up_three_level_discriminator():
    """KAT-23: {a:{b:{c:null}}} → {} (bottom-up); top-down gives {a:{b:{}}}.

    The §0 survived-falsification claim that normalize() is genuinely bottom-up
    is verifiable: the three-level chain removes the deepest null first, which
    causes its parent to become empty, which causes its grandparent to become
    empty, which removes the top-level key. A top-down pass stops after removing
    c=null because it has already committed to keeping a and b before recursing.

    Mutant: replace normalize() with a top-down single-pass. The canonical
    digest changes from 44136fa3... (empty object) to the digest of '{"a":{"b":{}}}'.
    """
    vectors = load_vectors("jcs-n/kats")
    by_id = {v["id"]: v for v in vectors}
    v = by_id["jcs-n-kat-23"]
    assert canonical_digest(v["input"]) == v["digest"], (
        "bottom-up three-level normalization produced wrong digest"
    )
