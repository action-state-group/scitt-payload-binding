# SPDX-License-Identifier: BSD-3-Clause
"""Tests for derived identifier construction driven by the conformance vectors."""
import pytest

from cpb import derive_id, verify_carried_id, CarriedIdMismatch
from .conftest import load_vectors


def test_derived_id_pass_vectors():
    """All non-must_fail derived-id vectors must produce the correct derived_id."""
    vectors = load_vectors("jcs-n/derived-id")
    pass_vectors = [v for v in vectors if not v.get("must_fail")]
    assert pass_vectors
    for v in pass_vectors:
        excl = set(v.get("exclusion_set", []))
        payload = v["full_payload"] if "full_payload" in v else v.get("sd_encoded_payload", {})
        expected_id = v["derived_id"]
        computed = derive_id(payload, excl or None)
        assert computed == expected_id, (
            f"{v['id']}: derive_id mismatch: {computed!r} != {expected_id!r}"
        )


def test_carried_id_mismatch_raises():
    """derived-id-02: carried id does not match recomputed → CarriedIdMismatch."""
    vectors = load_vectors("jcs-n/derived-id")
    mismatch = [v for v in vectors if v.get("failure_reason") == "carried_id_mismatch"]
    assert mismatch
    for v in mismatch:
        excl = set(v.get("exclusion_set", []))
        payload = v["full_payload"]
        with pytest.raises(CarriedIdMismatch):
            verify_carried_id(payload, carried_field="record_id", exclusion_set=excl or None)


def test_sd_encoded_form_differs_from_plaintext():
    """derived-id-03: SD-encoded form produces a different digest than the plaintext."""
    vectors = load_vectors("jcs-n/derived-id")
    sd_v = next((v for v in vectors if v["id"] == "derived-id-03"), None)
    assert sd_v is not None
    excl = set(sd_v.get("exclusion_set", []))
    sd_payload = sd_v["sd_encoded_payload"]
    plaintext_payload = sd_v["plaintext_payload_for_reference"]
    sd_id = derive_id(sd_payload, excl or None)
    plaintext_id = derive_id(plaintext_payload, excl or None)
    assert sd_id == sd_v["derived_id"]
    assert sd_id != plaintext_id, (
        "SD-encoded form and plaintext should produce different derived identifiers"
    )
