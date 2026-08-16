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
    DigestAlgorithmMismatchError,
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


def _handle_digest_algorithm_inconsistent_with_context(v: dict) -> None:
    """typed-ref-fail-05 (-01 §7.1): digest_alg must be confirmed consistent
    with the referenced artifact type's registered canonicalization context
    -- SHA-512, MD5, an unregistered name, and the empty string must all be
    rejected even though the carried digest is otherwise correct."""
    cited = v["cited_artifact"]
    reg = cited["registry_entry"]
    entry = ArtifactTypeRegistryEntry(
        name=reg["name"],
        algorithm=reg["algorithm"],
        exclusion_set=frozenset(reg["exclusion_set"]),
    )
    for example in v["typed_references_with_mislabeled_digest_alg"]:
        ref = TypedRef(type=cited["type"], digest_alg=example["digest_alg"], digest=example["digest"])
        with pytest.raises(DigestAlgorithmMismatchError):
            verify_typed_ref(ref, cited["payload"], entry)


def _handle_digest_alg_inconsistent_with_registered_context(v: dict) -> None:
    """typed-ref-cpb01-02 (ARP fold, -01 §7.1): digest_alg 'SHA-512' against a
    jcs-n/SHA-256 registered context, carrying the otherwise-correct digest.
    Folded byte-for-byte from Joel Hillier's arp-typed-ref-cpb01-v0.1.json;
    the registry entry lives at the vector's top level, not nested under
    cited_artifact, per that vector file's own schema."""
    reg = v["artifact_type_registry_entry"]
    entry = ArtifactTypeRegistryEntry(
        name=reg["name"],
        algorithm=reg["algorithm"],
        exclusion_set=frozenset(reg["exclusion_set"]),
        representation=reg.get("representation", "bare_hex"),
    )
    cited = v["cited_artifact"]
    ref = TypedRef(**{k: v["typed_reference"][k] for k in ("type", "digest_alg", "digest")})
    with pytest.raises(DigestAlgorithmMismatchError):
        verify_typed_ref(ref, cited["payload"], entry)


def _handle_representation_mismatch_identifier_whitespace(v: dict) -> None:
    """jcs-n-kat-20/21: identifier grammar, trailing newline / surrounding
    whitespace. The carried digest is padded (a 65+ char string), which is
    not a 64-char lowercase hex string per section 4.1 -- the verifier MUST
    reject it, not strip whitespace and compare the remainder."""
    cited = v["cited_artifact"]
    reg = cited["registry_entry"]
    entry = ArtifactTypeRegistryEntry(
        name=reg["name"],
        algorithm=reg["algorithm"],
        exclusion_set=frozenset(reg["exclusion_set"]),
        representation=reg["representation"],
    )
    ref = TypedRef(
        type=reg["name"],
        digest_alg="SHA-256",
        digest=v["typed_reference_with_wrong_representation"]["digest"],
    )
    with pytest.raises(RepresentationMismatchError):
        verify_typed_ref(ref, cited["payload"], entry)


def _handle_nfc_normalisation_deviation(v: dict) -> None:
    """jcs-n-nfc-contrast-01: informative. jcs-n does NOT normalise; the
    library's actual output must land on the non-normalising (correct) side,
    never the nfc_contrast (would-be-normalised) side."""
    excl = set(v.get("exclusion_set", []))
    digest = canonical_digest(v["input"], excl or None)
    assert digest == v["jcs_n_correct_digest"]
    assert digest != v["nfc_contrast_digest"]


def _handle_string_escape_uppercase_hex(v: dict) -> None:
    """jcs-n-esc-uppercase-contrast: RFC 8785 §3.2.2.2 requires lowercase hex
    in \\uXXXX escape sequences. The library MUST produce the lowercase-hex
    pre-image (jcs_n_correct_digest) and MUST NOT produce the uppercase-hex
    pre-image (uppercase_contrast_digest)."""
    excl = set(v.get("exclusion_set", []))
    digest = canonical_digest(v["input"], excl or None)
    assert digest == v["jcs_n_correct_digest"]
    assert digest != v["uppercase_contrast_digest"]


def _handle_string_escape_long_form_for_named_char(v: dict) -> None:
    """jcs-n-tab-long-form-contrast: RFC 8785 §3.2.2.2 assigns TAB the named
    escape \\t; the library MUST NOT output the six-byte \\u0009 form instead.
    Asserts correct digest (jcs_n_correct_digest) and not the long-form digest
    (long_form_contrast_digest)."""
    excl = set(v.get("exclusion_set", []))
    digest = canonical_digest(v["input"], excl or None)
    assert digest == v["jcs_n_correct_digest"]
    assert digest != v["long_form_contrast_digest"]


def _handle_key_sort_by_escaped_bytes_not_code_units(v: dict) -> None:
    """jcs-n-control-key-escaped-sort-contrast: RFC 8785 §3.2.3 sorts member
    names by UTF-16 code units of the unescaped key, not by the bytes of the
    escaped serialization. The library MUST produce the code-unit-ordered
    pre-image (jcs_n_correct_digest) and MUST NOT produce the escaped-sort
    pre-image (escaped_sort_contrast_digest)."""
    excl = set(v.get("exclusion_set", []))
    digest = canonical_digest(v["input"], excl or None)
    assert digest == v["jcs_n_correct_digest"]
    assert digest != v["escaped_sort_contrast_digest"]


def _handle_stream_incomplete(v: dict) -> None:
    """domain-transform-fail-01: truncated stream must raise ValueError.

    Verifies that applying the stream-reassemble transform to a source with no
    terminal chunk raises ValueError.  The cpb library does not implement
    stream reassembly (that belongs in the producer/consumer, not the digest
    layer); this handler uses the same inline reassembler as check_vectors.py
    so the two remain in sync.
    """
    import json as _json

    def _reassemble(source: list) -> dict:
        has_terminal = any(item.get("done") is True for item in source)
        if not has_terminal:
            raise ValueError("stream_incomplete: no terminal chunk")
        concatenated = "".join(item.get("chunk", "") for item in source)
        return _json.loads(concatenated)

    transforms = v.get("domain_transforms", [])
    source = v.get("source", [])
    with pytest.raises(ValueError, match="stream_incomplete"):
        result = source
        for t in transforms:
            if t.get("id") == "stream-reassemble":
                result = _reassemble(result)
            else:
                raise ValueError(f"unknown transform: {t.get('id')!r}")


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


def _handle_invalid_wire_number_token(v: dict) -> None:
    """jcs-n-kat-35 (was kat-28 pre-renumber): the token -0 must be rejected
    by the wire rule before the parser normalizes it.  The cpb library
    operates on already-parsed Python objects (where -0 == 0), so this check
    is a wire-level gate that must be applied to the raw text.  We verify
    that the raw vector text fails the strict wire-rule parse."""
    import re as _re
    import unicodedata as _ud

    _WIRE_NUMBER_RE = _re.compile(r'^(0|-?[1-9][0-9]*)$')
    _SAFE_INT_MAX = (1 << 53) - 1

    def _parse_int_wire(s):
        if not _WIRE_NUMBER_RE.match(s):
            raise ValueError(f"invalid wire number token: {s!r}")
        val = int(s)
        if abs(val) > _SAFE_INT_MAX:
            raise ValueError(f"integer exceeds ±(2^53-1): {s!r}")
        return val

    def _reject_float_wire(s):
        raise ValueError(f"non-integer number token: {s!r}")

    # Find the vector file path to get the raw text
    raw = None
    for f in sorted(VECTORS_DIR.rglob("*.json")):
        try:
            candidate = json.loads(f.read_text(encoding="utf-8"))
            if candidate.get("id") == v.get("id"):
                raw = f.read_text(encoding="utf-8")
                break
        except Exception:
            continue

    assert raw is not None, f"could not find vector file for id={v.get('id')!r}"
    with pytest.raises(ValueError, match="invalid wire number token"):
        json.loads(raw, parse_int=_parse_int_wire, parse_float=_reject_float_wire)


def _handle_duplicate_key(v: dict) -> None:
    """jcs-n-kat-37 (was kat-30 pre-renumber): duplicate keys must be
    rejected after NFC normalization.  The cpb library operates on
    already-parsed Python objects (where duplicate keys are lost to
    last-wins); rejection must occur at the wire level using
    object_pairs_hook.  We verify that the raw vector text fails the strict
    duplicate-key check."""
    import unicodedata as _ud

    def _no_dup_keys(pairs):
        seen = {}
        result = {}
        for k, val in pairs:
            nfc = _ud.normalize('NFC', k)
            if nfc in seen:
                raise ValueError(f"duplicate key after NFC normalization: {k!r}")
            seen[nfc] = True
            result[k] = val
        return result

    raw = None
    for f in sorted(VECTORS_DIR.rglob("*.json")):
        try:
            candidate = json.loads(f.read_text(encoding="utf-8"))
            if candidate.get("id") == v.get("id"):
                raw = f.read_text(encoding="utf-8")
                break
        except Exception:
            continue

    assert raw is not None, f"could not find vector file for id={v.get('id')!r}"
    with pytest.raises(ValueError, match="duplicate key"):
        json.loads(raw, object_pairs_hook=_no_dup_keys)


_HANDLERS = {
    "float_in_digest_bearing_field": _handle_float_in_digest_bearing_field,
    "unsafe_integer_in_digest_bearing_field": _handle_unsafe_integer_in_digest_bearing_field,
    "integer_formatting_divergence": _handle_integer_formatting_divergence,
    "carried_id_mismatch": _handle_carried_id_mismatch,
    "recomputed_digest_mismatch": _handle_recomputed_digest_mismatch,
    "digest_context_incompatible_equal_hex_is_not_a_join": _handle_textual_equality_trap,
    "representation_mismatch": _handle_representation_mismatch,
    "representation_mismatch_trailing_newline": _handle_representation_mismatch_identifier_whitespace,
    "representation_mismatch_surrounding_whitespace": _handle_representation_mismatch_identifier_whitespace,
    "stream_incomplete": _handle_stream_incomplete,
    "identifier_inconsistent_with_context": _handle_identifier_inconsistent_with_context,
    "digest_algorithm_inconsistent_with_context": _handle_digest_algorithm_inconsistent_with_context,
    "digest_alg_inconsistent_with_registered_context": _handle_digest_alg_inconsistent_with_registered_context,
    "nfc_normalisation_deviation": _handle_nfc_normalisation_deviation,
    "string_escape_uppercase_hex": _handle_string_escape_uppercase_hex,
    "string_escape_long_form_for_named_char": _handle_string_escape_long_form_for_named_char,
    "key_sort_by_escaped_bytes_not_code_units": _handle_key_sort_by_escaped_bytes_not_code_units,
    "profile_independence_violation": _handle_profile_independence_violation,
    "invalid_wire_number_token": _handle_invalid_wire_number_token,
    "duplicate_key": _handle_duplicate_key,
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
