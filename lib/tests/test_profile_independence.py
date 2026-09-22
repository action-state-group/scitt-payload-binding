# SPDX-License-Identifier: BSD-3-Clause
"""Tests for profile independence (§8) driven by the conformance vectors.

Round-2 gap (Anton): vectors/profile-independence/ was never loaded by any
test in this suite -- neither the PASS vector nor the MUST-FAIL vector was
ever exercised against the library, despite both being on disk.
"""
from cpb import ArtifactTypeRegistryEntry, TypedRef, evaluate_typed_ref_digest

from .conftest import load_vectors


def test_profile_independence_pass():
    """profile-independence-pass-01: Profile A cites Profile B only through a
    typed reference. The historical digest evaluator resolves the binding using only
    type/digest_alg/digest -- it has no parameter through which it could read
    Profile B's internal fields (subject/scope/issued_at)."""
    vectors = load_vectors("profile-independence/pass")
    v = next((x for x in vectors if x["id"] == "profile-independence-pass-01"), None)
    assert v is not None

    profile_b = v["profile_b"]
    entry_b = ArtifactTypeRegistryEntry(
        name=profile_b["name"],
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(profile_b["exclusion_set"]),
    )
    ref_fields = v["profile_a"]["payload"]["authorization"]
    ref = TypedRef(
        type=ref_fields["type"], digest_alg=ref_fields["digest_alg"], digest=ref_fields["digest"]
    )

    recomputed = evaluate_typed_ref_digest(ref, profile_b["payload"], entry_b)
    assert recomputed == profile_b["derived_id"]


def test_profile_independence_violation_conforming_alternative():
    """profile-independence-fail-01: informative/behavioral -- the vector
    documents a verifier ANTI-PATTERN (a Profile-A verifier reaching inside
    Profile-B's internal fields) that cannot itself be invoked as a function
    call; there is no library entry point for "the wrong way." Its
    executable contract is therefore the vector's own documented CONFORMING
    alternative: digest evaluation resolves the decision-record's
    authorization binding using only the typed reference's digest, and
    succeeds without authorization_doc.subject/scope ever being read --
    those fields are never passed to it at all.
    """
    vectors = load_vectors("profile-independence/fail")
    v = next((x for x in vectors if x["id"] == "profile-independence-fail-01"), None)
    assert v is not None
    assert v.get("must_fail") is True
    assert v.get("failure_reason") == "profile_independence_violation"

    scenario = v["scenario"]
    auth_doc = scenario["authorization_doc"]
    decision = scenario["decision_record"]
    ref_fields = decision["payload"]["authorization"]
    ref = TypedRef(
        type=ref_fields["type"], digest_alg=ref_fields["digest_alg"], digest=ref_fields["digest"]
    )

    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    # Only auth_doc["payload"] is passed in; the digest evaluator never reads
    # subject/scope from it -- it only recomputes and compares digests.
    recomputed = evaluate_typed_ref_digest(ref, auth_doc["payload"], entry)
    assert recomputed == auth_doc["derived_id"]
