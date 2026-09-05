# SPDX-License-Identifier: BSD-3-Clause
"""Tests for derived identifier construction driven by the conformance vectors."""
import json
from datetime import datetime, timezone

import pytest

from cpb import (
    CarriedIdMismatch,
    VintageEvidenceError,
    WithdrawnAlgorithmError,
    derive_id,
    evaluate_derived_id,
    verify_carried_id,
)
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
        computed = evaluate_derived_id(payload, excl or None)
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
            verify_carried_id(
                json.dumps(payload),
                carried_field="record_id",
                exclusion_set=excl or None,
                algorithm="jcs-n",
            )


def test_sd_encoded_form_differs_from_plaintext():
    """derived-id-03: SD-encoded form produces a different digest than the plaintext."""
    vectors = load_vectors("jcs-n/derived-id")
    sd_v = next((v for v in vectors if v["id"] == "derived-id-03"), None)
    assert sd_v is not None
    excl = set(sd_v.get("exclusion_set", []))
    sd_payload = sd_v["sd_encoded_payload"]
    plaintext_payload = sd_v["plaintext_payload_for_reference"]
    sd_id = evaluate_derived_id(sd_payload, excl or None)
    plaintext_id = evaluate_derived_id(plaintext_payload, excl or None)
    assert sd_id == sd_v["derived_id"]
    assert sd_id != plaintext_id, (
        "SD-encoded form and plaintext should produce different derived identifiers"
    )


def test_new_jcs_n_derived_identifier_construction_is_refused():
    with pytest.raises(TypeError, match="raw JSON"):
        derive_id({"value": "new-record"})
    with pytest.raises(WithdrawnAlgorithmError):
        derive_id('{"value":"new-record"}', algorithm="jcs-n")


def test_live_jcs_derived_identifier_construction_and_verification():
    digest = derive_id(
        '{"record_id":null,"value":"new-record"}',
        {"record_id"},
    )
    raw = f'{{"record_id":"{digest}","value":"new-record"}}'
    assert verify_carried_id(raw, "record_id", {"record_id"}) == digest


def test_present_null_carried_identifier_is_a_mismatch():
    """JSON null is a carried value, not the absence of the optional field."""
    with pytest.raises(CarriedIdMismatch):
        verify_carried_id(
            '{"record_id":null,"value":"new-record"}',
            "record_id",
            {"record_id"},
        )


def test_historical_carried_id_verify_requires_and_checks_vintage():
    vector = next(v for v in load_vectors("jcs-n/derived-id") if v["id"] == "derived-id-01")
    raw = json.dumps(vector["full_payload_with_carried_id"], separators=(",", ":"))
    expected = vector["derived_id"]
    evidence = {"bound_digest": expected, "proof": b"profile-proof"}

    with pytest.raises(VintageEvidenceError):
        verify_carried_id(
            raw,
            "record_id",
            {"record_id"},
            algorithm="jcs-n",
        )

    def verify_evidence(candidate, recomputed):
        assert candidate is evidence
        assert candidate["bound_digest"] == recomputed
        return datetime(2026, 7, 24, tzinfo=timezone.utc)

    assert verify_carried_id(
        raw,
        "record_id",
        {"record_id"},
        algorithm="jcs-n",
        vintage_evidence=evidence,
        verify_vintage_evidence=verify_evidence,
    ) == expected
