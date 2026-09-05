# SPDX-License-Identifier: BSD-3-Clause
"""Tests for historical digest evaluation and fail-closed verification."""
import json
from datetime import datetime, timezone

import pytest

from cpb import (
    ArtifactTypeDefinition,
    ArtifactTypeRegistryEntry,
    ContextMismatchError,
    DigestAlgorithmMismatchError,
    DigestContextResolutionError,
    JsonWireFormatError,
    PurposeMismatchError,
    PurposeRequiredError,
    RepresentationMismatchError,
    TypedRef,
    TypedRefError,
    UnsupportedDigestContextError,
    UnsupportedRepresentationError,
    VintageEvidenceError,
    WithdrawnAlgorithmError,
    evaluate_typed_ref_digest,
    hex_to_raw,
    make_typed_ref,
    make_typed_ref_json,
    raw_to_hex,
    verify_typed_ref,
)
from cpb.canonicalize import canonical_digest

from .conftest import load_vectors


def _definition(*contexts: ArtifactTypeRegistryEntry) -> ArtifactTypeDefinition:
    # Test fixtures stand in for a profile that publishes this independently
    # trusted complete-set pin. Production verifiers must not derive their pin
    # from the same untrusted context sequence they are checking.
    declared = ArtifactTypeDefinition.for_construction(contexts)
    return ArtifactTypeDefinition.from_contexts(
        contexts,
        expected_context_set_sha256=declared.context_set_sha256,
    )


def _entry_from_cited(cited: dict) -> ArtifactTypeRegistryEntry:
    reg = cited.get("artifact_type_registry_entry") or cited.get("registry_entry") or {}
    return ArtifactTypeRegistryEntry(
        name=reg.get("name", cited.get("type", "unknown")),
        algorithm=reg.get("algorithm", "jcs-n"),
        whole_object_exclusion_set=frozenset(reg.get("exclusion_set", [])),
        representation=reg.get("representation", "bare-hex"),
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


def test_typed_ref_historical_vectors_evaluate():
    """Historical PASS vectors retain digest agreement without claiming validity.

    typed-ref-cpb01-01's expected digest lives under `expected`, not
    `verification`, per that vector's own field layout (see
    _entry_from_vector for the registry-entry counterpart).
    """
    vectors = load_vectors("typed-refs/pass")
    for v in vectors:
        # COSE carrier fixtures are decoded from their pinned wire bytes and
        # verified in test_cose_refs; never certify them through a parallel
        # shadow object that could remain valid after the carrier is removed.
        if "cose_sign1_bytes_hex" in v:
            continue
        cited = v["cited_artifact"]
        entry = _entry_from_vector(v)
        ref = TypedRef(**_typed_ref_fields(v["typed_reference"]))
        recomputed = evaluate_typed_ref_digest(ref, cited["payload"], entry)
        result = v.get("digest_evaluation") or v.get("expected") or {}
        expected = result["recomputed_digest"]
        assert recomputed == expected, f"{v['id']}: recomputed {recomputed!r} != {expected!r}"


def test_typed_ref_new_jcs_n_construction_is_refused():
    """Neither parsed nor raw construction may revive withdrawn jcs-n."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    with pytest.raises(TypeError, match="raw JSON"):
        make_typed_ref(payload, entry)
    with pytest.raises(WithdrawnAlgorithmError):
        make_typed_ref_json(json.dumps(payload), _definition(entry))


def test_live_jcs_typed_ref_construction_and_verification():
    raw = (
        b'{"doc_id":null,"subject":"WS-42","scope":"temperature-write",'
        b'"issued_at":"2026-09-05T00:00:00Z"}'
    )
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    definition = _definition(entry)
    ref = make_typed_ref_json(raw, definition)
    assert ref.purpose == "identifier"
    assert verify_typed_ref(ref, raw, definition) == ref.digest


@pytest.mark.parametrize("algorithm", ["jcs", "jcs-n"])
def test_raw_construction_gate_rejects_duplicate_before_algorithm_use(algorithm):
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm=algorithm,
        whole_object_exclusion_set=frozenset(),
    )
    with pytest.raises(JsonWireFormatError) as exc_info:
        make_typed_ref_json(
            '{"subject":"first","subject":"second"}', _definition(entry)
        )
    assert any(v.code == "duplicate_key" for v in exc_info.value.violations)


def test_typed_ref_representation_mismatch():
    """typed-ref-fail-03: sha256-prefixed digest where bare-hex is required."""
    vectors = load_vectors("typed-refs/fail")
    rep_mismatch = [v for v in vectors if v.get("failure_reason") == "representation_mismatch"]
    assert rep_mismatch
    for v in rep_mismatch:
        cited = v["cited_artifact"]
        entry = _entry_from_cited(cited)
        ref = TypedRef(**_typed_ref_fields(v["typed_reference_with_wrong_representation"]))
        with pytest.raises(RepresentationMismatchError):
            evaluate_typed_ref_digest(ref, cited["payload"], entry)


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
            evaluate_typed_ref_digest(ref, cited["payload"], entry)


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
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(["a_id"]),
    )
    entry_b = ArtifactTypeRegistryEntry(
        name="artifact-b",
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(["b_id", "weight"]),
    )
    digest_a = canonical_digest(
        artifact_a["payload"],
        entry_a.whole_object_exclusion_set,
        algorithm=entry_a.algorithm,
    )
    digest_b = canonical_digest(
        artifact_b["payload"],
        entry_b.whole_object_exclusion_set,
        algorithm=entry_b.algorithm,
    )
    common = v["common_digest"]
    assert digest_a == common, "artifact-a must produce common_digest"
    assert digest_b == common, "artifact-b must produce common_digest"

    # Step 2: the typed reference claims artifact-A
    ref_a = TypedRef(type="artifact-a", digest_alg="SHA-256", digest=common)

    # Step 2a: correct verification — artifact-A bytes with artifact-A entry → PASS
    evaluate_typed_ref_digest(ref_a, artifact_a["payload"], entry_a)

    # Step 2b: naive verifier tries artifact-B's registry entry for artifact-A reference
    # → TypedRefError because entry_b.name ('artifact-b') != ref_a.type ('artifact-a')
    with pytest.raises(TypedRefError):
        evaluate_typed_ref_digest(ref_a, artifact_b["payload"], entry_b)

    # Step 3: a payload differing from artifact-A fails under artifact-A context
    different_payload = {"a_id": None, "color": "blue", "size": "99"}
    with pytest.raises(ContextMismatchError):
        evaluate_typed_ref_digest(ref_a, different_payload, entry_a)


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
    assert evaluate_typed_ref_digest(ref, cited["payload"], correct_entry) == cited["correct_derived_id"]

    # A verifier that applies the wrong exclusion set (per the vector's own
    # erroneous_verification.wrong_exclusion_set) must raise, not match.
    wrong_exclusion_set = frozenset(v["erroneous_verification"]["wrong_exclusion_set"])
    wrong_entry = ArtifactTypeRegistryEntry(
        name=cited["artifact_type_registry_entry"]["name"],
        algorithm=correct_entry.algorithm,
        whole_object_exclusion_set=wrong_exclusion_set,
    )
    with pytest.raises(ContextMismatchError):
        evaluate_typed_ref_digest(ref, cited["payload"], wrong_entry)


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
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    correct_digest = canonical_digest(
        payload, entry.whole_object_exclusion_set, algorithm=entry.algorithm
    )

    # Positive: digest_alg matching the registered algorithm's hash (SHA-256) verifies.
    ref_correct = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=correct_digest)
    assert evaluate_typed_ref_digest(ref_correct, payload, entry) == correct_digest

    # Negative: a SHA-512-labeled reference to the same digest value must NOT
    # verify under a jcs-n/SHA-256 context.
    ref_mislabeled = TypedRef(type="authorization-doc", digest_alg="SHA-512", digest=correct_digest)
    with pytest.raises(DigestAlgorithmMismatchError):
        evaluate_typed_ref_digest(ref_mislabeled, payload, entry)


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
    assert (
        canonical_digest(
            cited["payload"],
            entry.whole_object_exclusion_set,
            algorithm=entry.algorithm,
        )
        == v["correct_recomputed_digest"]
    )

    for example in v["typed_references_with_mislabeled_digest_alg"]:
        ref = TypedRef(type=cited["type"], digest_alg=example["digest_alg"], digest=example["digest"])
        with pytest.raises(DigestAlgorithmMismatchError):
            evaluate_typed_ref_digest(ref, cited["payload"], entry)


def test_typed_ref_purpose_matches_registered_label():
    """A carried `purpose` (§13.2) that matches the resolved type's one
    registered digest context label verifies normally, via the dict path
    verify_typed_ref accepts alongside TypedRef."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    digest = canonical_digest(
        payload, entry.whole_object_exclusion_set, algorithm=entry.algorithm
    )
    ref = {
        "type": "authorization-doc",
        "purpose": "identifier",
        "digest_alg": "SHA-256",
        "digest": digest,
    }
    assert evaluate_typed_ref_digest(ref, payload, entry) == digest


def test_typed_ref_purpose_mismatch_rejected():
    """A carried `purpose` that does not name this type's registered
    digest context label must be rejected, not silently ignored (round-2
    gap: the dict path used to extract only type/digest_alg/digest)."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    digest = canonical_digest(
        payload, entry.whole_object_exclusion_set, algorithm=entry.algorithm
    )
    ref = {
        "type": "authorization-doc",
        "purpose": "equivalence",
        "digest_alg": "SHA-256",
        "digest": digest,
    }
    with pytest.raises(PurposeMismatchError):
        evaluate_typed_ref_digest(ref, payload, entry)


def test_digest_evaluation_accepts_a_pre_resolved_purpose_less_reference():
    """The non-verifying helper receives an already-resolved context."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    digest = canonical_digest(
        payload,
        entry.whole_object_exclusion_set,
        algorithm="jcs",
    )
    ref = {"type": "authorization-doc", "digest_alg": "SHA-256", "digest": digest}
    assert evaluate_typed_ref_digest(ref, payload, entry) == digest


def test_verification_resolves_the_complete_context_set():
    raw = b'{"value":"x"}'
    identifier = ArtifactTypeRegistryEntry(
        name="example",
        algorithm="jcs",
        purpose="identifier",
        whole_object_exclusion_set=frozenset(),
    )
    equivalence = ArtifactTypeRegistryEntry(
        name="example",
        algorithm="jcs",
        purpose="equivalence",
        whole_object_exclusion_set=frozenset(),
    )
    digest = canonical_digest({"value": "x"}, algorithm="jcs")
    complete = _definition(identifier, equivalence)

    with pytest.raises(TypeError, match="ArtifactTypeDefinition"):
        verify_typed_ref(
            TypedRef("example", "SHA-256", digest, purpose="identifier"),
            raw,
            identifier,
        )

    # The old API trusted any Sequence as complete. Wrapping the caller-selected
    # row in a singleton list therefore bypassed the missing-purpose check. A
    # bare sequence is no longer a verification input, even when it is a list.
    with pytest.raises(TypeError, match="ArtifactTypeDefinition"):
        verify_typed_ref(TypedRef("example", "SHA-256", digest), raw, [identifier])

    with pytest.raises(PurposeRequiredError):
        verify_typed_ref(
            TypedRef("example", "SHA-256", digest),
            raw,
            complete,
        )

    # A genuinely single-context type is represented by a different, atomic
    # definition; it may omit purpose under the wire rule.
    assert verify_typed_ref(
        TypedRef("example", "SHA-256", digest),
        raw,
        _definition(identifier),
    ) == digest

    assert verify_typed_ref(
        TypedRef("example", "SHA-256", digest, purpose="identifier"),
        raw,
        complete,
    ) == digest

    # The dataclass cannot be instantiated directly to invent an anchor.
    with pytest.raises(TypeError):
        ArtifactTypeDefinition(
            name="example",
            contexts=(identifier,),
            context_set_sha256=complete.context_set_sha256,
        )

    # Reusing the complete definition's independently trusted pin with a
    # truncated tuple fails before a verifier can mistake it for a one-context
    # type. Omitting a pin is not an API option either.
    with pytest.raises(DigestContextResolutionError, match="integrity check"):
        ArtifactTypeDefinition.from_contexts(
            [identifier],
            expected_context_set_sha256=complete.context_set_sha256,
        )
    with pytest.raises(TypeError, match="expected_context_set_sha256"):
        ArtifactTypeDefinition.from_contexts([identifier])


def test_construction_only_definition_cannot_authorize_verification():
    raw = b'{"value":"x"}'
    context = ArtifactTypeRegistryEntry(
        name="example",
        algorithm="jcs",
        purpose="identifier",
        whole_object_exclusion_set=frozenset(),
    )
    local_declaration = ArtifactTypeDefinition.for_construction([context])

    ref = make_typed_ref_json(raw, local_declaration)
    with pytest.raises(DigestContextResolutionError, match="independently trusted"):
        verify_typed_ref(ref, raw, local_declaration)


def test_verification_rejects_duplicate_purpose_contexts():
    raw = b'{"value":"x"}'
    digest = canonical_digest({"value": "x"}, algorithm="jcs")
    contexts = (
        ArtifactTypeRegistryEntry(
            name="example",
            algorithm="jcs",
            purpose="identifier",
            whole_object_exclusion_set=frozenset(),
        ),
        ArtifactTypeRegistryEntry(
            name="example",
            algorithm="jcs",
            purpose="identifier",
            whole_object_exclusion_set=frozenset({"value"}),
        ),
    )
    definition = _definition(*contexts)
    ref = TypedRef("example", "SHA-256", digest, purpose="identifier")
    with pytest.raises(DigestContextResolutionError, match="duplicate"):
        verify_typed_ref(ref, raw, definition)
    with pytest.raises(DigestContextResolutionError, match="duplicate"):
        make_typed_ref_json(raw, definition, purpose="identifier")


def test_unsupported_contexts_participate_in_resolution_without_blocking_a_sibling():
    raw = b'{"value":"x"}'
    digest = canonical_digest({"value": "x"}, algorithm="jcs")
    contexts = (
        ArtifactTypeRegistryEntry(
            name="example",
            algorithm="as-transmitted",
            purpose="identifier",
        ),
        ArtifactTypeRegistryEntry(
            name="example",
            algorithm="jcs",
            purpose="equivalence",
            whole_object_exclusion_set=frozenset(),
        ),
    )
    definition = _definition(*contexts)
    assert verify_typed_ref(
        TypedRef("example", "SHA-256", digest, purpose="equivalence"),
        raw,
        definition,
    ) == digest
    with pytest.raises(UnsupportedDigestContextError):
        verify_typed_ref(
            TypedRef("example", "SHA-256", digest, purpose="identifier"),
            raw,
            definition,
        )


def test_metadata_only_field_selection_cannot_be_executed():
    raw = b'{"action_id":"a","outcome":"ok","extra":"not-in-context"}'
    context = ArtifactTypeRegistryEntry(
        name="example",
        algorithm="jcs",
        purpose="equivalence",
    )
    ref = TypedRef(
        "example",
        "SHA-256",
        canonical_digest({"action_id": "a", "outcome": "ok"}, algorithm="jcs"),
        purpose="equivalence",
    )
    with pytest.raises(UnsupportedDigestContextError, match="field-selection"):
        verify_typed_ref(ref, raw, _definition(context))


def test_typed_ref_raw_representation_boundary():
    """Round-2 Blocker 2: raw octets and hex are distinct, non-interchangeable
    representations (§5.1) -- not two spellings of one 'bare-hex' concept.
    A hex string is REJECTED where 'raw' (bytes) is declared, and a bytes
    object is REJECTED where 'bare-hex' (str) is declared, even when one is
    exactly the decoding of the other."""
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    hex_entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs",
        whole_object_exclusion_set=frozenset(["doc_id"]),
    )
    raw_entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs",
        whole_object_exclusion_set=frozenset(["doc_id"]),
        representation="raw",
    )
    digest_hex = canonical_digest(
        payload,
        hex_entry.whole_object_exclusion_set,
        algorithm="jcs",
    )
    digest_raw = hex_to_raw(digest_hex)

    # Positive: raw bytes verify under a 'raw' registry entry.
    ref_raw = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_raw)
    assert evaluate_typed_ref_digest(ref_raw, payload, raw_entry) == digest_hex

    # Positive: the hex str agrees under a 'bare-hex' registry entry.
    ref_hex = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_hex)
    assert evaluate_typed_ref_digest(ref_hex, payload, hex_entry) == digest_hex

    # Boundary negative: the hex str of the CORRECT digest is rejected where
    # 'raw' is declared -- content is right, representation is wrong.
    ref_hex_as_raw = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_hex)
    with pytest.raises(RepresentationMismatchError):
        evaluate_typed_ref_digest(ref_hex_as_raw, payload, raw_entry)

    # Boundary negative: the raw bytes of the CORRECT digest are rejected
    # where 'bare-hex' is declared.
    ref_raw_as_hex = TypedRef(type="authorization-doc", digest_alg="SHA-256", digest=digest_raw)
    with pytest.raises(RepresentationMismatchError):
        evaluate_typed_ref_digest(ref_raw_as_hex, payload, hex_entry)

    # Explicit conversions round-trip.
    assert hex_to_raw(raw_to_hex(digest_raw)) == digest_raw
    assert raw_to_hex(hex_to_raw(digest_hex)) == digest_hex

    # TypedRef itself is a JSON object whose digest member is a string. The
    # generic raw representation has no normative encoding in that wire form,
    # so conformance construction and verification reject it explicitly.
    raw_json = json.dumps(payload, separators=(",", ":"))
    with pytest.raises(UnsupportedRepresentationError, match="JSON TypedRef"):
        make_typed_ref_json(raw_json, _definition(raw_entry))
    with pytest.raises(UnsupportedRepresentationError, match="JSON TypedRef"):
        verify_typed_ref(ref_raw, raw_json, _definition(raw_entry))


@pytest.mark.parametrize(
    "invalid",
    [
        "0" * 63,
        "0" * 65,
        "A" + "0" * 63,
        " " + "0" * 63,
        b"0" * 64,
    ],
)
def test_hex_to_raw_rejects_noncanonical_text(invalid):
    """The explicit conversion accepts the declared representation only.

    ``bytes.fromhex`` itself accepts whitespace and uppercase, so delegating
    validation to it silently widens the normative 64-lowercase-ASCII form.
    """
    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        hex_to_raw(invalid)


@pytest.mark.parametrize("invalid", [b"\x00" * 31, b"\x00" * 33, "0" * 32])
def test_raw_to_hex_requires_exactly_32_octets(invalid):
    with pytest.raises(ValueError, match="32 raw octets"):
        raw_to_hex(invalid)


def test_prefixed_representation_validates_the_hex_payload_grammar():
    payload = {"value": "x"}
    entry = ArtifactTypeRegistryEntry(
        name="example",
        algorithm="jcs",
        representation="sha256-prefixed",
        whole_object_exclusion_set=frozenset(),
    )
    ref = TypedRef(
        type="example",
        digest_alg="SHA-256",
        digest="sha256:" + "z" * 64,
    )
    with pytest.raises(RepresentationMismatchError):
        evaluate_typed_ref_digest(ref, payload, entry)


def test_digest_alg_comparison_is_byte_exact():
    """Two-sided, and it is the pair that was missing.

    The comparison used to case-fold both sides, so a reference carrying
    `sha-256` was accepted against a registered `SHA-256`. The suite passed
    only because no vector differed by case -- the tolerance was invisible
    rather than tested. The IANA registries an implementer might reach for
    disagree on the spelling for the same function, so accepting either one
    silently admits a reference naming a different registry's token.
    """
    vectors = load_vectors("typed-refs/pass")
    assert vectors, "no PASS vectors to build the pair from"
    v = vectors[0]
    cited = v["cited_artifact"]
    entry = _entry_from_vector(v)
    fields = _typed_ref_fields(v["typed_reference"])

    exact = TypedRef(**fields)
    evaluate_typed_ref_digest(exact, cited["payload"], entry)

    case_shifted = dict(fields)
    registered = case_shifted["digest_alg"]
    case_shifted["digest_alg"] = (
        registered.lower() if registered != registered.lower() else registered.upper()
    )
    assert case_shifted["digest_alg"] != registered, "vector's digest_alg has no case to shift"

    with pytest.raises(DigestAlgorithmMismatchError):
        evaluate_typed_ref_digest(TypedRef(**case_shifted), cited["payload"], entry)


def _historical_reference_fixture():
    payload = {
        "doc_id": None,
        "subject": "WS-42",
        "scope": "temperature-write",
        "issued_at": "2026-07-24T00:00:00Z",
    }
    raw = json.dumps(payload, separators=(",", ":"))
    entry = ArtifactTypeRegistryEntry(
        name="authorization-doc",
        algorithm="jcs-n",
        whole_object_exclusion_set=frozenset(["doc_id"]),
        representation="bare-hex",
    )
    digest = canonical_digest(
        payload, entry.whole_object_exclusion_set, algorithm=entry.algorithm
    )
    ref = TypedRef(type=entry.name, digest_alg="SHA-256", digest=digest)
    return payload, raw, entry, digest, ref


def test_historical_verify_requires_authenticated_pre_cutoff_vintage():
    _, raw, entry, digest, ref = _historical_reference_fixture()
    evidence = {"proof": b"profile-specific-proof", "digest": digest}

    def verify_evidence(candidate, recomputed):
        assert candidate is evidence
        assert candidate["digest"] == recomputed
        return datetime(2026, 7, 24, tzinfo=timezone.utc)

    assert verify_typed_ref(
        ref,
        raw,
        _definition(entry),
        vintage_evidence=evidence,
        verify_vintage_evidence=verify_evidence,
    ) == digest


def test_historical_verify_fails_closed_without_evidence_or_verifier():
    _, raw, entry, digest, ref = _historical_reference_fixture()

    with pytest.raises(VintageEvidenceError):
        verify_typed_ref(ref, raw, _definition(entry))
    with pytest.raises(VintageEvidenceError):
        verify_typed_ref(
            ref,
            raw,
            _definition(entry),
            vintage_evidence={"digest": digest},
        )


@pytest.mark.parametrize(
    "authenticated_time",
    [
        datetime(2026, 8, 18, tzinfo=timezone.utc),
        datetime(2026, 9, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 24),
    ],
)
def test_historical_verify_rejects_post_cutoff_or_naive_time(authenticated_time):
    _, raw, entry, digest, ref = _historical_reference_fixture()

    with pytest.raises(VintageEvidenceError):
        verify_typed_ref(
            ref,
            raw,
            _definition(entry),
            vintage_evidence={"digest": digest},
            verify_vintage_evidence=lambda evidence, recomputed: authenticated_time,
        )


def test_historical_verify_rejects_unverified_payload_date():
    """A date in the payload cannot substitute for cryptographic evidence."""
    _, raw, entry, _, ref = _historical_reference_fixture()
    with pytest.raises(VintageEvidenceError):
        verify_typed_ref(ref, raw, _definition(entry))


def test_verified_path_requires_raw_json_not_a_collapsed_mapping():
    payload, _, entry, _, ref = _historical_reference_fixture()
    with pytest.raises(TypeError, match="raw JSON"):
        verify_typed_ref(
            ref,
            payload,
            _definition(entry),
            vintage_evidence=object(),
            verify_vintage_evidence=lambda evidence, recomputed: datetime(
                2026, 7, 24, tzinfo=timezone.utc
            ),
        )


def test_verified_path_rejects_duplicate_even_when_member_is_excluded():
    _, _, entry, digest, ref = _historical_reference_fixture()
    duplicate_raw = (
        '{"doc_id":"first","doc_id":"second","subject":"WS-42",'
        '"scope":"temperature-write","issued_at":"2026-07-24T00:00:00Z"}'
    )
    with pytest.raises(JsonWireFormatError) as exc_info:
        verify_typed_ref(
            ref,
            duplicate_raw,
            _definition(entry),
            vintage_evidence={"digest": digest},
            verify_vintage_evidence=lambda evidence, recomputed: datetime(
                2026, 7, 24, tzinfo=timezone.utc
            ),
        )
    assert any(v.code == "duplicate_key" for v in exc_info.value.violations)
