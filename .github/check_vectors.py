#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone vector integrity checker — no dependencies beyond stdlib.

For every jcs-n PASS vector: independently recomputes the canonical form
using a minimal RFC 8785 / jcs-n implementation, then verifies:
  1. Recomputed pre_image == pinned pre_image
  2. pre_image encoded as UTF-8 hex == pre_image_bytes_hex
  3. SHA-256 of pre_image bytes == digest
  For domain-transform PASS vectors (those with 'domain_transforms' + 'source'):
  additionally verifies that applying the named transform to source produces 'input'.

For diverge vectors ('diverge': true) — category J:
  J. Subject-binding algorithm divergence: 'action' + 'jcs' + 'jcs_n'
     -> compute plain JCS (_jcs(action), no normalize) AND jcs-n
        (jcs_n_pre_image(action)); verify both against pinned pre_image /
        pre_image_bytes_hex / digest fields; assert jcs.digest != jcs_n.digest.
     Mutation probe: replaces null/empty members with 'n/a' so JCS==jcs-n;
     the inequality assertion must FLIP to failure on the mutant.
     These vectors document the gap between composition §6.3.2 (plain JCS) and
     CPB's Canonicalization Algorithm Registry (jcs-n only).

For must_fail vectors — each MUST match at least one category (enforced):
  A. Algorithm-rejection: 'input' present, no 'jcs_n_correct_digest'/'pre_image'
     -> assert jcs_n_pre_image(input) raises ValueError.
  B. NFC-contrast: 'jcs_n_correct_digest' present
     -> verify all pinned hex/digest fields; verify jcs_n impl output.
  C. Typed-ref erroneous_verification: 'wrong_pre_image' + 'wrong_recomputed_digest'
     -> verify wrong_pre_image -> SHA-256 = wrong_recomputed_digest.
  D. Derived-id mismatch: 'correct_derived_id' + 'carried_id'
     -> REQUIRES full_payload (missing full_payload is a hard failure -- a bare string
        comparison of correct_derived_id vs. carried_id certifies nothing); recompute
        from full_payload (exclusion_set applied); assert recomputed == correct_derived_id
        AND recomputed != carried_id.
  E. Profile-independence scenario: 'failure_reason' == 'profile_independence_violation'
     -> INFORMATIVE: behavioral prohibition cannot be tested programmatically.
        REQUIRES both the decision/auth-document join (scenario.authorization_doc +
        scenario.decision_record) AND the explicit non_conforming_verifier_behavior.violation
        + conforming_alternative.action.  A hollow record missing either side is a hard
        failure, not informative.  These vectors are NOT counted as MUST-FAIL exercised
        (separate 'informative' counter).
  F. Common-canonical-form trap: 'common_canonical_form' + 'common_digest'
     -> verify SHA-256(common_canonical_form) == common_digest; REQUIRES complete typed
        artifact_a + artifact_b (each with 'type' and 'payload'); assert artifact_a.type !=
        artifact_b.type (incompatibility is real); recompute both artifact canonical forms
        and verify each equals common_canonical_form.
  G. Cited-artifact derived-id: 'cited_artifact.correct_derived_id_bare_hex'
     -> recompute jcs_n from cited_artifact.payload (using registry exclusion_set
        if present); verify == correct_derived_id_bare_hex; REQUIRES a carried
        typed_reference_with_wrong_representation/typed_reference_with_wrong_digest.digest;
        assert it is REJECTED as a representation -- not just unequal in content, but
        actually failing the declared bare 64-char lowercase-hex grammar (a different but
        syntactically-valid bare-hex digest is a content mismatch, not a representation
        mismatch, and does NOT satisfy this category).
  H. Top-level erroneous pre-image: 'erroneous_pre_image_that_produced_wrong_digest'
     -> REQUIRES typed_reference_with_wrong_digest.digest AND verification.correct_pre_image
        + verification.recomputed_digest; verify erroneous pre-image -> SHA-256 =
        typed_reference_with_wrong_digest.digest; verify verification.correct_pre_image ->
        SHA-256 = verification.recomputed_digest; assert wrong_digest != recomputed_digest
        (inequality is real).
  I. digest_alg mismatch: 'failure_reason' in {'digest_algorithm_inconsistent_with_context',
     'digest_alg_inconsistent_with_registered_context'}
     -> REQUIRES cited_artifact.payload AND a resolvable registry entry (checked at
        cited_artifact.registry_entry, cited_artifact.artifact_type_registry_entry, or
        the vector's own top-level artifact_type_registry_entry) naming either an
        explicit hash_algorithm_registered_by_algorithm_entry or algorithm 'jcs-n'
        (registered hash SHA-256); recompute the digest independently from the payload
        and assert it equals every carried digest_alg example's digest (the mislabeling
        must be isolated to digest_alg, not hidden by an also-wrong digest value); assert
        every example's digest_alg does NOT case-insensitively equal the registered hash
        algorithm (the mismatch is real). Examples are read from either
        typed_references_with_mislabeled_digest_alg (a list) or typed_reference (a single
        object) -- vector files fold from different sources with different shapes.
  L. Domain-transform stream-incomplete: 'domain_transforms' present + 'source' present
     + no 'input' field + failure_reason == 'stream_incomplete'
     -> apply _stream_reassemble(source); assert it raises ValueError.
     Mutant: append a terminal chunk so reassembly succeeds -- checker must flip to failure.
     Letter reserved by Anton 2026-08-19: main owns A-J (through #31's diverge-vector
     category J); #16 takes K; this category takes L.

  I. Assembled pre-image, member mapping undeclared: 'implementation_a' + 'implementation_b'
     + 'declared_digest_context'
     -> REQUIRES declared_digest_context.member_mapping to be absent or null (that absence
        IS the condition under test; a vector carrying a mapping proves the opposite thing
        and is a hard failure).  REQUIRES source_object + selected_source_pointers, and each
        implementation to carry assembled/pre_image/pre_image_bytes_hex/digest.  Recompute
        jcs_n over each 'assembled' and verify it equals that side's pinned pre_image, hex
        and digest; assert the two pre_images AND the two digests differ (the fork is real);
        assert BOTH assembled objects carry exactly the multiset of values found at
        selected_source_pointers in source_object, each once and nothing else -- that is what
        makes both of them conforming readings of the SAME declared field set, and without
        it the vector would only show that two different objects hash differently.
     SCOPE, stated so it is not mistaken for more: the conforming-reading test is against
        the vector's own selected_source_pointers, NOT against a parse of the prose in
        declared_digest_context.field_set, which is free text this checker does not read.
        It also compares TOP-LEVEL member values, so it treats flat assembly as given and
        would reject a nesting-preserving reading of the same field set.

  J. Member-mapping derivation: 'declared_digest_context.member_mapping' non-null
     -> REQUIRES source_object + 'input'.  Applies the mapping to source_object and asserts
        the derived object equals 'input' exactly.  Runs for PASS vectors too, so the
        "sufficient declaration" half of a pair is executed rather than asserted in prose;
        a mapping naming an absent source path, writing a pre-image path twice, or yielding
        a different object is a hard failure.

A must_fail vector matching NONE of the above is a hard failure -- 'ran_any_check' is
enforced.  A bare {'must_fail': true} fails the suite.

Mutation-probe self-test: for every fired category (except exempt ones), the suite
auto-generates a condition-removed mutant and asserts the checker FLIPS to failure on
it.  A category that passes its mutant is reported ASSERTION-FREE and fails CI.
Every future category MUST register a mutant generator in _MUTANT_GENERATORS or be
added to _MUTANT_EXEMPT_CATEGORIES, or the suite will refuse to count it as exercised.
A registered generator that returns None is ALSO a hard ASSERTION-FREE failure -- it
never silently "covers" the category; a generator refusing to build a mutant proves
nothing, so every category's real check requires its complete invariant inputs to
guarantee a mutant can always be built.

A pinned vector that was never run is not a vector.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sys
import unicodedata
from pathlib import Path


# \A...\Z, not ^...$: Python's $ also matches immediately before a trailing
# newline, so a ^...$ pattern accepts "<64 hex chars>\n" as bare hex.
_BARE_HEX_64_RE = re.compile(r"\A[0-9a-f]{64}\Z")

_WIRE_NUMBER_RE = re.compile(r'^(0|-?[1-9][0-9]*)$')
_SAFE_INT_MAX = (1 << 53) - 1


def _parse_int_wire(s):
    if not _WIRE_NUMBER_RE.match(s):
        raise ValueError(f"invalid wire number token: {s!r}")
    val = int(s)
    if abs(val) > _SAFE_INT_MAX:
        raise ValueError(f"integer exceeds ±(2^53-1): {s!r}")
    return val


def _reject_float_wire(s):
    raise ValueError(f"non-integer number token in digest-bearing field: {s!r}")


def _no_dup_keys(pairs):
    seen = {}
    result = {}
    for k, v in pairs:
        nfc = unicodedata.normalize('NFC', k)
        if nfc in seen:
            raise ValueError(f"duplicate key after NFC normalization: {k!r}")
        seen[nfc] = True
        result[k] = v
    return result


# ---------------------------------------------------------------------------
# Minimal jcs-n implementation (spec-pure, no external deps)
# ---------------------------------------------------------------------------

def _jcs_sort_key(k: str) -> bytes:
    """RFC 8785 section 3.2.3: lexicographic on UTF-16-BE code units (no length-first rule)."""
    return k.encode("utf-16-be")


def _normalize(obj: object) -> object:
    """Remove null, empty-array, and empty-object members bottom-up (jcs-n section 3.1 E3).

    Array *elements* are not object members -- they stay in the array even when
    they normalize to {}.  But the elements themselves are recursed so that any
    null/empty members *inside* them are removed.
    """
    if isinstance(obj, list):
        return [_normalize(item) for item in obj]
    if not isinstance(obj, dict):
        return obj
    result: dict[str, object] = {}
    for k, v in obj.items():
        nv = _normalize(v)
        if nv is None or nv == [] or nv == {}:
            continue
        result[k] = nv
    return result


def _jcs(obj: object) -> str:
    """RFC 8785 canonical JSON with keys sorted per section 3.2.3.

    jcs-n rejects floats and integers outside the safe range, including when
    they appear inside arrays.  Validation recurses through array elements so
    no forbidden numeric can slip through via a list wrapper.
    """
    if isinstance(obj, dict):
        sorted_k = sorted(obj.keys(), key=_jcs_sort_key)
        pairs = [_jcs(k) + ":" + _jcs(obj[k]) for k in sorted_k]
        return "{" + ",".join(pairs) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(_jcs(item) for item in obj) + "]"
    if not isinstance(obj, bool) and isinstance(obj, int):
        n = abs(obj)
        if n >= 10 ** 21:
            raise ValueError(
                f"integer >= 1e21: Python json.dumps produces full decimal digits "
                f"but JCS requires scientific notation for this value: {obj!r}"
            )
        if n >= 1 << 53:
            raise ValueError(
                f"unsafe integer (|n| >= 2^53): cannot be exactly represented "
                f"in IEEE 754 double; jcs-n forbids these: {obj!r}"
            )
    if isinstance(obj, float):
        raise ValueError(f"float not allowed in jcs-n payloads: {obj!r}")
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _reject_json_constant(name: str) -> object:
    """Refuse Infinity / -Infinity / NaN, which Python's json accepts by default.

    RFC 8259 defines none of them, so a vector carrying one is not a JSON text
    that another implementation would read at all.
    """
    raise ValueError(
        f"JSON constant {name!r} is not valid JSON (RFC 8259 defines no such "
        f"literal); a vector must not carry it"
    )


def _jcs_rfc8785(obj: object) -> str:
    """Plain RFC 8785 JCS — identical to _jcs() except floats are allowed.

    Used only for Category J Direction-B (float) vectors where the subject
    binding (composition §6.3.2) accepts floating-point values that jcs-n
    MUST-FAIL on (draft §11.3's blanket float prohibition).  Do NOT use for
    jcs-n computation.

    Float serialization is verified correct only for float forms like the
    pinned vector value 0.95, NOT for RFC 8785 §3.2.2.3 in general: Python's
    json.dumps diverges from RFC 8785's shortest-decimal grammar for
    whole-number floats (1.0 -> "1.0", RFC 8785 wants "1"), small-magnitude
    exponential forms (1e-7 -> "1e-07", RFC 8785 wants "1e-7"), negative zero
    (-0.0 -> "-0.0", RFC 8785 wants "0"), and large-magnitude exponential
    forms (1e16 -> "1e+16", RFC 8785 wants "10000000000000000"). The guard
    below raises rather than silently emit a non-conformant digest for any
    float outside the verified form.
    """
    if isinstance(obj, dict):
        sorted_k = sorted(obj.keys(), key=_jcs_sort_key)
        pairs = [_jcs_rfc8785(k) + ":" + _jcs_rfc8785(obj[k]) for k in sorted_k]
        return "{" + ",".join(pairs) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(_jcs_rfc8785(item) for item in obj) + "]"
    if not isinstance(obj, bool) and isinstance(obj, int):
        n = abs(obj)
        if n >= 10 ** 21:
            raise ValueError(
                f"integer >= 1e21: Python json.dumps produces full decimal digits "
                f"but JCS requires scientific notation for this value: {obj!r}"
            )
        if n >= 1 << 53:
            raise ValueError(
                f"unsafe integer (|n| >= 2^53): cannot be exactly represented "
                f"in IEEE 754 double: {obj!r}"
            )
    if isinstance(obj, float):
        # Non-finite first: json.dumps emits Infinity / -Infinity / NaN by default
        # (allow_nan=True), none of which contain an 'e' or end in '.0', so the
        # form guard below waved them through as a canonical pre-image. RFC 8785
        # section 3.2.2.3 admits only finite values, and those three tokens are
        # not JSON at all.
        if not math.isfinite(obj):
            raise ValueError(
                f"non-finite number cannot appear in a canonical pre-image: {obj!r} "
                f"(RFC 8785 section 3.2.2.3 admits finite values only)"
            )
        s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        if "e" in s or "E" in s or s.endswith(".0"):
            raise ValueError(
                f"_jcs_rfc8785 float form not verified RFC 8785-conformant: "
                f"json.dumps({obj!r}) = {s!r}. This helper's float handling is "
                f"verified correct only for forms like the pinned vector value "
                f"0.95; whole-number and exponential float forms are known to "
                f"diverge from RFC 8785 §3.2.2.3 (see docstring)."
            )
        return s
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def jcs_n_pre_image(
    payload: dict[str, object],
    exclusion_set: list[str] | None = None,
) -> str:
    """Return the jcs-n canonical pre-image string."""
    if exclusion_set:
        payload = {k: v for k, v in payload.items() if k not in exclusion_set}
    return _jcs(_normalize(payload))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# digest_alg-mismatch helpers (Category I)
# ---------------------------------------------------------------------------

_DIGEST_ALG_MISMATCH_FAILURE_REASONS = frozenset({
    "digest_algorithm_inconsistent_with_context",
    "digest_alg_inconsistent_with_registered_context",
})


def _digest_alg_registry_entry(v: dict) -> dict:
    """Vectors fold from different sources with different registry-entry
    locations: nested under cited_artifact (this repo's own fail-05), or a
    sibling of cited_artifact at the vector's top level (ARP's fold)."""
    cited = v.get("cited_artifact", {})
    return (
        cited.get("registry_entry")
        or cited.get("artifact_type_registry_entry")
        or v.get("artifact_type_registry_entry")
        or {}
    )


def _expected_hash_alg(reg: dict) -> str | None:
    explicit = reg.get("hash_algorithm_registered_by_algorithm_entry")
    if explicit:
        return explicit
    if reg.get("algorithm") == "jcs-n":
        return "SHA-256"
    return None


def _digest_alg_examples(v: dict) -> list[dict]:
    examples = v.get("typed_references_with_mislabeled_digest_alg")
    if examples is not None:
        return examples
    single = v.get("typed_reference")
    return [single] if single else []


# ---------------------------------------------------------------------------
# Domain-transform helpers (Category L)
# ---------------------------------------------------------------------------

def _stream_reassemble(source: list) -> dict:
    """Apply the 'stream-reassemble' transform: concatenate 'chunk' fields in
    order and parse the result as JSON.  Raises ValueError if no chunk carries
    'done: true' (stream is incomplete) or if the concatenated bytes are not
    valid JSON.
    """
    if not isinstance(source, list) or not source:
        raise ValueError("stream_incomplete: source is empty or not a list")
    has_terminal = any(item.get("done") is True for item in source)
    if not has_terminal:
        raise ValueError(
            "stream_incomplete: no terminal chunk (none has 'done': true) -- "
            "the pre-image cannot be determined from a truncated stream"
        )
    concatenated = "".join(item.get("chunk", "") for item in source)
    try:
        return json.loads(concatenated)
    except json.JSONDecodeError as exc:
        raise ValueError(f"stream_incomplete: concatenated chunks are not valid JSON: {exc}") from exc


_TRANSFORM_HANDLERS = {
    "stream-reassemble": _stream_reassemble,
}


def _apply_domain_transforms(transforms: list, source: object) -> object:
    """Apply a declared transform chain to 'source', returning the result.
    Only 'stream-reassemble' is currently defined.  Unknown transform ids
    are a hard error (the declaration must use stable registered identifiers).
    """
    result = source
    for t in transforms:
        tid = t.get("id", "")
        handler = _TRANSFORM_HANDLERS.get(tid)
        if handler is None:
            raise ValueError(
                f"unknown transform id {tid!r} -- only {list(_TRANSFORM_HANDLERS)} are defined; "
                "the canonicalization declaration requires stable identifiers for all transforms"
            )
        result = handler(result)
    return result


# ---------------------------------------------------------------------------
# Informative-vector helpers (Category E)
# ---------------------------------------------------------------------------

_INFORMATIVE_FAILURE_REASONS = frozenset({"profile_independence_violation"})


def _check_informative_vector(v: dict, vid: str) -> list[str]:
    """Structural consistency check for informative behavioral vectors.

    Category E documents behavioral anti-patterns (cross-profile field access)
    that cannot be tested programmatically: a mock non-conforming verifier would
    be a separate implementation artifact outside the checker's scope.  We verify
    the vector's own data is internally consistent but do NOT count these as
    MUST-FAIL exercised.

    A record is REQUIRED to carry BOTH sides of the behavioral documentation --
    the decision/auth-document join AND the explicit non-conforming behavior
    (with its conforming alternative) -- or it does not demonstrate anything and
    must NOT be counted informative.  A hollow {'must_fail': true,
    'failure_reason': ...} record with no supporting data is a hard failure here,
    not a free pass.
    """
    errs: list[str] = []
    scenario = v.get("scenario", {})
    auth_doc = scenario.get("authorization_doc", {})
    if not auth_doc or "derived_id" not in auth_doc or "payload" not in auth_doc:
        errs.append(
            "informative vector missing scenario.authorization_doc.derived_id/payload "
            "-- the decision/auth-document join cannot be checked"
        )
    else:
        try:
            computed = jcs_n_pre_image(auth_doc["payload"])
            got = hashlib.sha256(computed.encode("utf-8")).hexdigest()
            if got != auth_doc["derived_id"]:
                errs.append(
                    f"authorization_doc.derived_id mismatch: "
                    f"expected {auth_doc['derived_id']}, got {got}"
                )
            carried_digest = (
                scenario.get("decision_record", {})
                .get("payload", {})
                .get("authorization", {})
                .get("digest")
            )
            if not carried_digest:
                errs.append(
                    "informative vector missing scenario.decision_record.payload."
                    "authorization.digest -- the decision/auth-document join cannot "
                    "be checked"
                )
            elif got != carried_digest:
                errs.append(
                    "authorization_doc.derived_id != decision_record authorization.digest"
                )
        except Exception as exc:
            errs.append(f"informative structural check raised: {exc!r}")

    behavior = v.get("non_conforming_verifier_behavior")
    if not behavior or not behavior.get("violation"):
        errs.append(
            "informative vector missing non_conforming_verifier_behavior.violation "
            "-- the explicit non-conforming behavior must be documented, not implied "
            "by failure_reason alone"
        )

    alternative = v.get("conforming_alternative")
    if not alternative or not alternative.get("action"):
        errs.append(
            "informative vector missing conforming_alternative.action -- the "
            "conforming alternative must be documented alongside the violation"
        )

    return errs


# ---------------------------------------------------------------------------
# Mutation-probe infrastructure
# ---------------------------------------------------------------------------

_MUTANT_EXEMPT_CATEGORIES = frozenset({
    "C",  # Data-integrity check; condition-removed mutant passes without semantic change.
})

# (correct_pre_image_bytes_hex_field, contrast_pre_image_bytes_hex_field, contrast_digest_field)
# for string-escape contrast vectors (Category B extension).
_ESCAPE_CONTRAST_TRIPLETS = [
    ("jcs_n_correct_pre_image_bytes_hex", "uppercase_contrast_pre_image_bytes_hex", "uppercase_contrast_digest"),
    ("jcs_n_correct_pre_image_bytes_hex", "long_form_contrast_pre_image_bytes_hex", "long_form_contrast_digest"),
    ("jcs_n_correct_pre_image_bytes_hex", "escaped_sort_contrast_pre_image_bytes_hex", "escaped_sort_contrast_digest"),
]


def _mutant_A(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    m["input"] = {}
    return m


def _mutant_B(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    # NFC-contrast shape (original Category B)
    if "jcs_n_correct_pre_image_bytes_hex" in m and "nfc_contrast_pre_image_bytes_hex" in m:
        m["jcs_n_correct_pre_image_bytes_hex"], m["nfc_contrast_pre_image_bytes_hex"] = (
            m["nfc_contrast_pre_image_bytes_hex"],
            m["jcs_n_correct_pre_image_bytes_hex"],
        )
        m["jcs_n_correct_digest"], m["nfc_contrast_digest"] = (
            m.get("nfc_contrast_digest"),
            m.get("jcs_n_correct_digest"),
        )
        return m
    # Escape-contrast shapes: swap correct hex/digest with the named contrast pair.
    # After the swap the library still produces the real correct bytes, but
    # jcs_n_correct_pre_image_bytes_hex now holds the contrast bytes, so
    # Category B's library-output check FAILS on the mutant.
    for _, contrast_hex_key, contrast_digest_key in _ESCAPE_CONTRAST_TRIPLETS:
        if contrast_hex_key in m and contrast_digest_key in m and "jcs_n_correct_pre_image_bytes_hex" in m:
            m["jcs_n_correct_pre_image_bytes_hex"], m[contrast_hex_key] = (
                m[contrast_hex_key],
                m["jcs_n_correct_pre_image_bytes_hex"],
            )
            m["jcs_n_correct_digest"], m[contrast_digest_key] = (
                m[contrast_digest_key],
                m["jcs_n_correct_digest"],
            )
            return m
    return None


def _mutant_D(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    m["carried_id"] = m.get("correct_derived_id", "0" * 64)
    return m


def _mutant_F(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    if "artifact_b" not in m or "type" not in m.get("artifact_a", {}):
        return None
    m.setdefault("artifact_a", {})["type"] = m["artifact_b"].get("type")
    return m


def _mutant_G(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    cited = m.get("cited_artifact", {})
    bare_hex = cited.get("correct_derived_id_bare_hex", "")
    ref = (
        m.get("typed_reference_with_wrong_representation")
        or m.get("typed_reference_with_wrong_digest")
    )
    if ref and bare_hex:
        ref["digest"] = bare_hex
        return m
    return None


def _mutant_H(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    recomputed = m.get("verification", {}).get("recomputed_digest", "")
    ref = m.get("typed_reference_with_wrong_digest", {})
    if recomputed and ref:
        ref["digest"] = recomputed
        return m
    return None


def _mutant_I(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    reg = _digest_alg_registry_entry(m)
    expected = _expected_hash_alg(reg)
    examples = _digest_alg_examples(m)
    if not expected or not examples:
        return None
    for ex in examples:
        ex["digest_alg"] = expected
    return m


def _mutant_L(v: dict) -> dict | None:
    """Append a terminal chunk so _stream_reassemble succeeds on the mutant.
    The real vector has no terminal chunk; adding one makes the reassembler
    return a valid (possibly empty or partial) object instead of raising,
    which should flip the Category L check to failure.
    """
    m = copy.deepcopy(v)
    source = m.get("source")
    if not isinstance(source, list):
        return None
    # Gather all existing chunk text and close it as valid JSON so parse succeeds
    existing_chunks = "".join(item.get("chunk", "") for item in source)
    # Build a terminal chunk that completes the JSON (use {} as a safe fallback
    # if existing content is empty or incomplete)
    try:
        json.loads(existing_chunks)
        terminal_content = ""
    except (json.JSONDecodeError, ValueError):
        existing_chunks = ""
        terminal_content = "{}"
    m["source"] = [{"chunk": existing_chunks + terminal_content, "done": True}]
    return m


def _mutant_K(v: dict) -> dict | None:
    """Collapse implementation B onto A: the declared field set now DOES fix
    the bytes, so the vector demonstrates nothing and Category K must flip to
    failure.
    """
    m = copy.deepcopy(v)
    impl_a = m.get("implementation_a")
    impl_b = m.get("implementation_b")
    if not impl_a or not impl_b:
        return None
    # Collapse B onto A: the declared field set now DOES fix the bytes, so the
    # vector demonstrates nothing and the checker must flip to failure.
    for key in ("assembled", "pre_image", "pre_image_bytes_hex", "digest"):
        if key not in impl_a:
            return None
        impl_b[key] = copy.deepcopy(impl_a[key])
    return m


_MUTANT_GENERATORS: dict[str, object] = {
    "A": _mutant_A,
    "B": _mutant_B,
    "D": _mutant_D,
    "F": _mutant_F,
    "G": _mutant_G,
    "H": _mutant_H,
    "I": _mutant_I,
    "K": _mutant_K,
    "L": _mutant_L,
}


def _unescape_pointer_token(token: str) -> str:
    """RFC 6901 section 3/4: the only escapes are ~0 and ~1, and ~1 unescapes first.

    A bare `~`, or `~` followed by anything other than 0 or 1, is not valid pointer
    syntax.  A plain str.replace() silently passes those through as literal text, so
    `/a~2b` would address a member named "a~2b" that RFC 6901 cannot name at all.
    Validate before unescaping, and the order of the two replacements stays normative.
    """
    i = 0
    while i < len(token):
        if token[i] == "~":
            if i + 1 >= len(token) or token[i + 1] not in "01":
                found = token[i:i + 2] if i + 1 < len(token) else "~ at end of token"
                raise ValueError(
                    f"invalid RFC 6901 escape {found!r} in reference token {token!r}: "
                    "the only valid escapes are ~0 and ~1"
                )
            i += 2
            continue
        i += 1
    return token.replace("~1", "/").replace("~0", "~")


def _parse_json_pointer(pointer: str) -> list[str]:
    """Parse an RFC 6901 JSON Pointer into reference tokens.

    Dotted paths were ambiguous: with a source object of {"a.b": 1, "a": {"b": 2}},
    "a.b" named both the literal top-level member and the nested one, and the literal
    member could not be addressed at all.  A JSON Pointer distinguishes them as
    "/a.b" and "/a/b".
    """
    if not isinstance(pointer, str):
        raise ValueError(f"JSON Pointer must be a string, got {type(pointer).__name__}")
    if pointer == "":
        raise ValueError("the empty JSON Pointer addresses the whole document; name a member")
    if not pointer.startswith("/"):
        raise ValueError(f"JSON Pointer must start with '/': {pointer!r}")
    return [_unescape_pointer_token(t) for t in pointer.split("/")[1:]]


def _resolve_source_pointer(obj: dict, pointer: str):
    """Resolve an RFC 6901 pointer against a source object.

    Raises KeyError if any token is missing, so a vector naming a member the
    source object does not have is a hard failure rather than a silent skip.
    Object members only: arrays are out of scope for this template element, and a
    numeric token against a list is rejected rather than guessed at.
    """
    cur = obj
    for token in _parse_json_pointer(pointer):
        if isinstance(cur, list):
            raise ValueError(
                f"{pointer!r} traverses an array; array members are out of scope for member_mapping"
            )
        if not isinstance(cur, dict) or token not in cur:
            raise KeyError(pointer)
        cur = cur[token]
    return cur


def _check_destination_collisions(destinations: list[str]) -> None:
    """Every destination shares one namespace, whatever produced it.

    Three collisions are rejected, and constants and fields are checked together
    because a constant colliding with a field is the same defect as two fields
    colliding.
    """
    parsed = [(d, _parse_json_pointer(d)) for d in destinations]
    for i, (ptr_a, toks_a) in enumerate(parsed):
        for ptr_b, toks_b in parsed[i + 1:]:
            if toks_a == toks_b:
                raise ValueError(f"member_mapping writes {ptr_a!r} twice")
            shorter, longer = sorted((toks_a, toks_b), key=len)
            if longer[: len(shorter)] == shorter:
                raise ValueError(
                    f"member_mapping destinations collide: {ptr_a!r} and {ptr_b!r} "
                    "(one is an ancestor of the other)"
                )


def _apply_member_mapping(source: dict, mapping: dict) -> dict:
    """Derive the assembled pre-image object from a source object and a mapping.

    The mapping is a function from source pointers to pre-image pointers, plus
    constants that are not source fields at all.  Applying it must yield exactly
    one object, which is the whole point of declaring it.
    """
    fields = mapping.get("fields") or []
    constants = mapping.get("constants") or []
    _check_destination_collisions(
        [f["preimage_pointer"] for f in fields] + [c["preimage_pointer"] for c in constants]
    )

    out: dict = {}
    for dest, value in (
        [(f["preimage_pointer"], _resolve_source_pointer(source, f["source_pointer"])) for f in fields]
        + [(c["preimage_pointer"], c["value"]) for c in constants]
    ):
        tokens = _parse_json_pointer(dest)
        cur = out
        for token in tokens[:-1]:
            nxt = cur.setdefault(token, {})
            if not isinstance(nxt, dict):
                raise ValueError(f"member_mapping writes through a non-object at {dest!r}")
            cur = nxt
        cur[tokens[-1]] = value
    return out


_ABSENT = object()


def _check_member_mapping_derivation(v: dict) -> list[str]:
    """Category K: a declared member mapping MUST derive the vector's `input`.

    Without this, a vector could declare a mapping naming a nonexistent source
    path, or one producing a different object, and still pass every other check
    -- the declaration would be prose the suite never reads.
    """
    ctx = v.get("declared_digest_context") or {}
    # A sentinel, not None: JSON `null` deserializes to None, so testing `is None`
    # made an explicitly declared null mapping indistinguishable from no mapping at
    # all -- the same bypass as `member_mapping: {}`, one notch narrower. Absence is
    # the key not being there; anything present, null included, is a declaration and
    # must derive `input`.
    mapping = ctx.get("member_mapping", _ABSENT)
    if mapping is _ABSENT:
        return []
    if mapping is None:
        return ["member_mapping is declared as null; a declared mapping MUST name at "
                "least one field or constant, or the key must be absent"]
    if not isinstance(mapping, dict):
        return [f"member_mapping must be an object, got {type(mapping).__name__}"]
    if not (mapping.get("fields") or mapping.get("constants")):
        return ["declared member_mapping is empty; a declared mapping MUST name at least "
                "one field or constant, or be absent"]
    source = v.get("source_object")
    if not isinstance(source, dict):
        return ["declared member_mapping but no source_object to apply it to"]
    if "input" not in v:
        return ["declared member_mapping but no `input` to derive"]
    try:
        derived = _apply_member_mapping(source, mapping)
    except KeyError as exc:
        return [f"member_mapping names a source path absent from source_object: {exc}"]
    except Exception as exc:
        return [f"member_mapping could not be applied: {exc!r}"]
    if _jcs(derived) != _jcs(v["input"]):
        return [
            "applying member_mapping to source_object does not yield `input`\n"
            f"  derived: {_jcs(derived)}\n"
            f"  input:   {_jcs(v['input'])}"
        ]
    return []


# ---------------------------------------------------------------------------
# must_fail vector exerciser (defined before _run_self_tests for forward reference)
# ---------------------------------------------------------------------------

_MEMBER_DECODER = json.JSONDecoder()


def _member_raw_text(text: str, key: str) -> str | None:
    """Raw JSON text of one top-level member's value, or None if absent.

    A literal substring of *text*: raw_decode is used only to find where the
    value ends, and the value it parses is discarded.  Wire-layer checks need
    the member's own bytes -- `-0` and duplicate keys do not survive a parse,
    which is the whole reason this exists.  Deliberately narrower than
    harness.py's _top_level_member_spans: one member, no duplicate handling,
    no exception on a non-object (callers treat None as "cannot check").
    """
    try:
        n = len(text)
        i = 0
        while i < n and text[i] in " \t\n\r":
            i += 1
        if i >= n or text[i] != "{":
            return None
        i += 1
        while True:
            while i < n and text[i] in " \t\n\r":
                i += 1
            if i >= n or text[i] == "}":
                return None
            k, i = _MEMBER_DECODER.raw_decode(text, i)
            while i < n and text[i] in " \t\n\r":
                i += 1
            if i >= n or text[i] != ":":
                return None
            i += 1
            while i < n and text[i] in " \t\n\r":
                i += 1
            start = i
            _, i = _MEMBER_DECODER.raw_decode(text, i)
            if k == key:
                return text[start:i]
            while i < n and text[i] in " \t\n\r":
                i += 1
            if i < n and text[i] == ",":
                i += 1
                continue
            return None
    except (ValueError, TypeError):
        return None


def _exercise_must_fail(
    v: dict,
    vid: str,
    exclusion_set: list[str],
    raw_text: str | None = None,
    *,
    _probe_mutants: bool = True,
) -> tuple[bool, list[str]]:
    """Exercise a must_fail vector.  Returns (all_ok, error_messages).

    Categories are non-exclusive.  A vector triggering NONE is a hard failure.

    _probe_mutants=False is used internally for recursive mutant checks to
    prevent infinite recursion.
    """
    vec_errors: list[str] = []
    ran_any_check = False
    categories_fired: list[str] = []

    # A. Algorithm-rejection vectors
    if "input" in v and "jcs_n_correct_digest" not in v and "pre_image" not in v:
        ran_any_check = True
        categories_fired.append("A")
        # The wire layer sees tokens the parsed object cannot: `-0` is already 0
        # and duplicate keys have already collapsed by the time jcs_n_pre_image
        # runs.  So a vector whose rejection happens at the wire layer is proven
        # by re-parsing its raw text with the wire hooks -- but ONLY the `input`
        # member's raw text.  Parsing the whole file certifies a vector whose
        # input is perfectly acceptable whenever any unrelated metadata field
        # carries an offending token, which is a self-certification hole in the
        # one check family that exists to prove rejection.
        token_rejected = False
        if raw_text is not None:
            input_raw = _member_raw_text(raw_text, "input")
            if input_raw is not None:
                try:
                    json.loads(input_raw, parse_int=_parse_int_wire,
                               parse_float=_reject_float_wire,
                               object_pairs_hook=_no_dup_keys)
                except ValueError:
                    token_rejected = True
        if not token_rejected:
            try:
                jcs_n_pre_image(v["input"], exclusion_set or None)
                vec_errors.append(
                    "runner accepted invalid input -- jcs_n_pre_image should have raised ValueError"
                )
            except (ValueError, TypeError):
                pass

    # B. NFC-contrast
    if "jcs_n_correct_digest" in v:
        ran_any_check = True
        categories_fired.append("B")
        if "jcs_n_correct_pre_image_bytes_hex" in v:
            correct_bytes = bytes.fromhex(v["jcs_n_correct_pre_image_bytes_hex"])
            got = hashlib.sha256(correct_bytes).hexdigest()
            if got != v["jcs_n_correct_digest"]:
                vec_errors.append(
                    f"jcs_n_correct_digest mismatch\n"
                    f"  expected: {v['jcs_n_correct_digest']}\n"
                    f"  got:      {got}"
                )
        if "nfc_contrast_pre_image_bytes_hex" in v and "nfc_contrast_digest" in v:
            nfc_bytes = bytes.fromhex(v["nfc_contrast_pre_image_bytes_hex"])
            got = hashlib.sha256(nfc_bytes).hexdigest()
            if got != v["nfc_contrast_digest"]:
                vec_errors.append(
                    f"nfc_contrast_digest mismatch\n"
                    f"  expected: {v['nfc_contrast_digest']}\n"
                    f"  got:      {got}"
                )
        # Escape-contrast pairs: verify contrast bytes hash to contrast digest.
        for _, contrast_hex_key, contrast_digest_key in _ESCAPE_CONTRAST_TRIPLETS:
            if contrast_hex_key in v and contrast_digest_key in v:
                contrast_bytes = bytes.fromhex(v[contrast_hex_key])
                got = hashlib.sha256(contrast_bytes).hexdigest()
                if got != v[contrast_digest_key]:
                    vec_errors.append(
                        f"{contrast_hex_key} -> SHA-256 != {contrast_digest_key}\n"
                        f"  expected: {v[contrast_digest_key]}\n"
                        f"  got:      {got}"
                    )
        if "input" in v and "jcs_n_correct_pre_image_bytes_hex" in v:
            try:
                computed = jcs_n_pre_image(v["input"], exclusion_set or None)
                got_hex = computed.encode("utf-8").hex()
                if got_hex != v["jcs_n_correct_pre_image_bytes_hex"]:
                    vec_errors.append(
                        f"jcs_n impl produced wrong pre_image for NFC-contrast vector\n"
                        f"  expected hex: {v['jcs_n_correct_pre_image_bytes_hex']}\n"
                        f"  got hex:      {got_hex}"
                    )
            except Exception as exc:
                vec_errors.append(f"jcs_n_pre_image raised unexpectedly on NFC-contrast input: {exc!r}")

    # C. Typed-ref erroneous_verification (wrong_pre_image + wrong_recomputed_digest)
    ev = v.get("erroneous_verification", {})
    if "wrong_pre_image" in ev and "wrong_recomputed_digest" in ev:
        ran_any_check = True
        categories_fired.append("C")
        got = _sha256_hex(ev["wrong_pre_image"])
        if got != ev["wrong_recomputed_digest"]:
            vec_errors.append(
                f"wrong_recomputed_digest mismatch\n"
                f"  expected: {ev['wrong_recomputed_digest']}\n"
                f"  got:      {got}"
            )

    # D. Derived-id mismatch: recompute from full_payload, assert == correct_derived_id AND != carried_id
    if "correct_derived_id" in v and "carried_id" in v:
        ran_any_check = True
        categories_fired.append("D")
        full_payload = v.get("full_payload")
        excl = v.get("exclusion_set") or []
        if full_payload is None:
            vec_errors.append(
                "Category D vector missing full_payload — correct_derived_id cannot be "
                "independently recomputed, so neither ID is grounded in an artifact and "
                "no mismatch can be demonstrated (a bare string comparison certifies "
                "nothing)"
            )
        else:
            try:
                computed = jcs_n_pre_image(full_payload, excl or None)
                got = _sha256_hex(computed)
                if got != v["correct_derived_id"]:
                    vec_errors.append(
                        f"correct_derived_id does not match recomputed from full_payload\n"
                        f"  expected: {v['correct_derived_id']}\n"
                        f"  got:      {got}"
                    )
                elif got == v["carried_id"]:
                    vec_errors.append(
                        f"recomputed derived_id == carried_id — no mismatch demonstrated: {got!r}"
                    )
            except Exception as exc:
                vec_errors.append(f"Category D: jcs_n_pre_image raised: {exc!r}")

    # F. Common-canonical-form trap: verify digest AND type incompatibility AND both canonical forms
    if "common_canonical_form" in v and "common_digest" in v:
        ran_any_check = True
        categories_fired.append("F")
        got = _sha256_hex(v["common_canonical_form"])
        if got != v["common_digest"]:
            vec_errors.append(
                f"common_digest mismatch\n"
                f"  expected: {v['common_digest']}\n"
                f"  got:      {got}"
            )
        art_a = v.get("artifact_a", {})
        art_b = v.get("artifact_b", {})
        if not art_a or not art_b or "type" not in art_a or "type" not in art_b or \
                "payload" not in art_a or "payload" not in art_b:
            vec_errors.append(
                "Category F vector missing required artifact_a/artifact_b (with "
                "type and payload) — the type-incompatibility invariant cannot be "
                "demonstrated without both complete typed artifacts"
            )
        else:
            if art_a.get("type") == art_b.get("type"):
                vec_errors.append(
                    f"artifact_a.type == artifact_b.type ({art_a.get('type')!r}) — "
                    f"no type incompatibility demonstrated"
                )
            for art_key in ("artifact_a", "artifact_b"):
                art = v.get(art_key, {})
                art_excl: list[str] = art.get("registry_entry", {}).get("exclusion_set") or []
                try:
                    art_computed = jcs_n_pre_image(art["payload"], art_excl or None)
                    if art_computed != v["common_canonical_form"]:
                        vec_errors.append(
                            f"{art_key} canonical form != common_canonical_form\n"
                            f"  expected: {v['common_canonical_form']!r}\n"
                            f"  got:      {art_computed!r}"
                        )
                except Exception as exc:
                    vec_errors.append(f"{art_key}: jcs_n_pre_image raised: {exc!r}")

    # K. Assembled pre-image with no declared member mapping
    if "implementation_a" in v and "implementation_b" in v and "declared_digest_context" in v:
        ran_any_check = True
        categories_fired.append("K")
        ctx = v.get("declared_digest_context") or {}
        source_object = v.get("source_object")
        selected = v.get("selected_source_pointers")

        if ctx.get("member_mapping") is not None:
            vec_errors.append(
                "Category I vector declares a member_mapping — the absence of the "
                "mapping IS the condition under test, so a vector carrying one "
                "demonstrates the opposite property"
            )
        if not isinstance(source_object, dict) or not selected:
            vec_errors.append(
                "Category I vector missing source_object/selected_source_pointers — "
                "without them there is no way to check that both implementations "
                "satisfy the SAME declared field set"
            )
        else:
            try:
                want = sorted(
                    _jcs(_resolve_source_pointer(source_object, p)) for p in selected
                )
            except KeyError as exc:
                want = None
                vec_errors.append(
                    f"selected_source_pointers names a pointer absent from source_object: {exc}"
                )

            sides = {}
            for side in ("implementation_a", "implementation_b"):
                impl = v.get(side) or {}
                missing = [
                    k for k in ("assembled", "pre_image", "pre_image_bytes_hex", "digest")
                    if k not in impl
                ]
                if missing:
                    vec_errors.append(f"{side} missing required field(s): {missing}")
                    continue
                try:
                    computed = _jcs(impl["assembled"])
                except Exception as exc:
                    vec_errors.append(f"{side}: jcs raised: {exc!r}")
                    continue
                if computed != impl["pre_image"]:
                    vec_errors.append(
                        f"{side} pre_image != recomputed canonical form\n"
                        f"  expected: {impl['pre_image']!r}\n"
                        f"  got:      {computed!r}"
                    )
                if computed.encode("utf-8").hex() != impl["pre_image_bytes_hex"]:
                    vec_errors.append(f"{side} pre_image_bytes_hex does not encode pre_image")
                got = _sha256_hex(computed)
                if got != impl["digest"]:
                    vec_errors.append(
                        f"{side} digest mismatch\n"
                        f"  expected: {impl['digest']}\n  got:      {got}"
                    )
                if want is not None:
                    have = sorted(_jcs(m) for m in impl["assembled"].values())
                    if have != want:
                        vec_errors.append(
                            f"{side} does not carry exactly the selected source values, "
                            f"each once and nothing else — it is not a conforming reading "
                            f"of the declared field set, so the fork it shows is not the "
                            f"one this category is about"
                        )
                sides[side] = impl

            if len(sides) == 2:
                a_impl, b_impl = sides["implementation_a"], sides["implementation_b"]
                if a_impl["pre_image"] == b_impl["pre_image"]:
                    vec_errors.append(
                        "implementation_a.pre_image == implementation_b.pre_image — "
                        "no divergence demonstrated; the declared field set does fix "
                        "the bytes for this pair"
                    )
                if a_impl["digest"] == b_impl["digest"]:
                    vec_errors.append(
                        "implementation_a.digest == implementation_b.digest — no digest "
                        "fork demonstrated"
                    )

    # G. Cited-artifact derived-id: recompute AND assert carried representation is REJECTED
    cited = v.get("cited_artifact", {})
    if "correct_derived_id_bare_hex" in cited and "payload" in cited:
        ran_any_check = True
        categories_fired.append("G")
        reg_excl: list[str] = cited.get("registry_entry", {}).get("exclusion_set") or []
        try:
            computed = jcs_n_pre_image(cited["payload"], reg_excl or None)
            got = _sha256_hex(computed)
            if got != cited["correct_derived_id_bare_hex"]:
                vec_errors.append(
                    f"cited_artifact.correct_derived_id_bare_hex mismatch\n"
                    f"  expected: {cited['correct_derived_id_bare_hex']}\n"
                    f"  got:      {got}"
                )
            ref = (
                v.get("typed_reference_with_wrong_representation")
                or v.get("typed_reference_with_wrong_digest")
            )
            if not ref or "digest" not in ref:
                vec_errors.append(
                    "Category G vector missing typed_reference_with_wrong_representation."
                    "digest / typed_reference_with_wrong_digest.digest — the "
                    "representation-mismatch invariant cannot be demonstrated without "
                    "a carried typed reference"
                )
            else:
                ref_digest = ref["digest"]
                # The declared representation for a resolved artifact type is bare
                # 64-char lowercase hex (registry_entry.digest_context).  Category G
                # tests that the carried representation itself is REJECTED, not merely
                # that its content differs — a syntactically-valid bare-hex digest that
                # simply carries different content is a content mismatch, not a
                # representation mismatch, and must NOT satisfy this category.
                if ref_digest == cited["correct_derived_id_bare_hex"]:
                    vec_errors.append(
                        f"typed reference digest == correct_derived_id_bare_hex — "
                        f"no mismatch demonstrated: {ref_digest!r}"
                    )
                elif _BARE_HEX_64_RE.match(ref_digest):
                    vec_errors.append(
                        f"typed reference digest {ref_digest!r} is a syntactically valid "
                        f"bare 64-char lowercase-hex representation — it differs only in "
                        f"content, not representation; Category G requires the carried "
                        f"representation itself to be invalid (e.g. prefixed/non-bare form)"
                    )
        except Exception as exc:
            vec_errors.append(f"cited_artifact derived-id: jcs_n_pre_image raised: {exc!r}")

    # H. Top-level erroneous pre-image: verify both SHA-256 AND assert wrong != recomputed
    erroneous_pre = v.get("erroneous_pre_image_that_produced_wrong_digest")
    if erroneous_pre is not None:
        ran_any_check = True
        categories_fired.append("H")
        wrong_digest = v.get("typed_reference_with_wrong_digest", {}).get("digest")
        verification = v.get("verification", {})
        correct_pre = verification.get("correct_pre_image")
        recomputed_digest = verification.get("recomputed_digest")
        if not wrong_digest or not correct_pre or not recomputed_digest:
            vec_errors.append(
                "Category H vector missing required typed_reference_with_wrong_digest."
                "digest and/or verification.correct_pre_image/recomputed_digest — the "
                "erroneous-vs-correct pre-image invariant cannot be demonstrated without "
                "the complete correct-side fields"
            )
        else:
            got = _sha256_hex(erroneous_pre)
            if got != wrong_digest:
                vec_errors.append(
                    f"erroneous pre-image SHA-256 != typed_reference_with_wrong_digest.digest\n"
                    f"  expected: {wrong_digest}\n"
                    f"  got:      {got}"
                )
            got = _sha256_hex(correct_pre)
            if got != recomputed_digest:
                vec_errors.append(
                    f"verification.correct_pre_image SHA-256 != verification.recomputed_digest\n"
                    f"  expected: {recomputed_digest}\n"
                    f"  got:      {got}"
                )
            if wrong_digest == recomputed_digest:
                vec_errors.append(
                    f"wrong_digest == recomputed_digest — no inequality demonstrated: {wrong_digest!r}"
                )

    # I. digest_alg mismatch: carried digest is correct, digest_alg is mislabeled
    if v.get("failure_reason") in _DIGEST_ALG_MISMATCH_FAILURE_REASONS:
        ran_any_check = True
        categories_fired.append("I")
        cited = v.get("cited_artifact", {})
        payload = cited.get("payload")
        reg = _digest_alg_registry_entry(v)
        expected_alg = _expected_hash_alg(reg)
        examples = _digest_alg_examples(v)
        if payload is None or not expected_alg or not examples:
            vec_errors.append(
                "Category I vector missing cited_artifact.payload, a resolvable "
                "registry entry (algorithm / hash_algorithm_registered_by_algorithm_entry), "
                "and/or a typed_references_with_mislabeled_digest_alg list or "
                "typed_reference object -- the digest_alg mismatch cannot be "
                "independently checked"
            )
        else:
            reg_excl = reg.get("exclusion_set") or []
            try:
                computed = jcs_n_pre_image(payload, reg_excl or None)
                recomputed_digest = _sha256_hex(computed)
            except Exception as exc:
                vec_errors.append(f"Category I: jcs_n_pre_image raised: {exc!r}")
                recomputed_digest = None
            for ex in examples:
                digest_alg = ex.get("digest_alg")
                digest = ex.get("digest")
                if recomputed_digest is not None and digest != recomputed_digest:
                    vec_errors.append(
                        f"Category I: carried digest {digest!r} != independently "
                        f"recomputed digest {recomputed_digest!r} -- the mislabeling "
                        f"must be isolated to digest_alg, not hidden behind an "
                        f"also-wrong digest value"
                    )
                if digest_alg is None:
                    vec_errors.append("Category I: example missing digest_alg")
                elif digest_alg.upper() == expected_alg.upper():
                    vec_errors.append(
                        f"Category I: declared digest_alg {digest_alg!r} matches the "
                        f"registered hash algorithm {expected_alg!r} -- no mismatch "
                        f"demonstrated"
                    )

    # L. Domain-transform stream-incomplete
    domain_transforms = v.get("domain_transforms")
    source = v.get("source")
    if (
        domain_transforms
        and source is not None
        and "input" not in v
        and v.get("failure_reason") == "stream_incomplete"
    ):
        ran_any_check = True
        categories_fired.append("L")
        try:
            _apply_domain_transforms(domain_transforms, source)
            vec_errors.append(
                "domain transform succeeded on supposedly incomplete source -- "
                "expected ValueError for stream_incomplete"
            )
        except ValueError:
            pass

    # Enforcement: a vector matching none of the above is a hard failure.
    if not ran_any_check:
        vec_errors.append(
            "no verification path matched (ran_any_check=False) -- vector carries "
            "no executable assertion; add a recognized failure-kind field or "
            "reclassify as informative"
        )

    # Mutation probes: for each fired category, assert checker FLIPS on condition-removed mutant.
    if _probe_mutants:
        for cat in categories_fired:
            if cat in _MUTANT_EXEMPT_CATEGORIES:
                continue
            gen = _MUTANT_GENERATORS.get(cat)
            if gen is None:
                vec_errors.append(
                    f"ASSERTION-FREE: no mutant generator for Category {cat} — "
                    f"register one in _MUTANT_GENERATORS or add to _MUTANT_EXEMPT_CATEGORIES"
                )
                continue
            mutant = gen(v)
            if mutant is None:
                vec_errors.append(
                    f"ASSERTION-FREE: mutant generator for Category {cat} returned None "
                    f"({vid}) — a generator that refuses to build a mutant proves nothing; "
                    f"the vector must carry the category's complete invariant inputs so a "
                    f"condition-removed mutant can be built and probed, or the generator "
                    f"must be fixed to build one from this shape"
                )
                continue
            mutant_ok, _ = _exercise_must_fail(
                mutant, f"{vid}[mutant-{cat}]", exclusion_set, _probe_mutants=False
            )
            if mutant_ok:
                vec_errors.append(
                    f"ASSERTION-FREE: Category {cat} passed its condition-removed mutant "
                    f"({vid}[mutant-{cat}]) — the check does not test rejection"
                )

    return (not vec_errors), vec_errors


# ---------------------------------------------------------------------------
# Subject-binding divergence exerciser (Category J)
# ---------------------------------------------------------------------------

def _exercise_diverge(
    v: dict,
    vid: str,
    *,
    _probe_mutant: bool = True,
) -> tuple[bool, list[str]]:
    """Exercise a diverge vector: run plain JCS and jcs-n, assert they differ.

    Bytes-on-disk: the pre_image for each algorithm is computed from v['action']
    by the respective implementation, then compared against the pinned fields read
    directly from the vector file -- the digest input is the computed UTF-8 bytes,
    not a round-tripped parse.

    Direction A (jcs_n_must_fail absent or false) — different digests:
    1. Compute plain JCS (_jcs(action), no normalization pass).
    2. Assert computed == pinned jcs.pre_image.
    3. Assert UTF-8 hex of computed == jcs.pre_image_bytes_hex.
    4. Assert SHA-256(computed bytes) == jcs.digest.
    5. Compute jcs-n (jcs_n_pre_image(action): normalize then JCS).
    6. Assert computed == pinned jcs_n.pre_image.
    7. Assert UTF-8 hex of computed == jcs_n.pre_image_bytes_hex.
    8. Assert SHA-256(computed bytes) == jcs_n.digest.
    9. Assert jcs.digest != jcs_n.digest (divergence is real, not asserted).
    Mutation probe: replace null/empty members with 'n/a' → jcs == jcs-n → step 9
    must flip to failure.

    Direction B (jcs_n_must_fail: true) — acceptance vs rejection:
    1. Compute plain RFC 8785 JCS (_jcs_rfc8785(action), floats allowed).
    2-4. Assert pinned jcs fields (pre_image, hex, digest).
    5. Assert jcs_n_pre_image(action) RAISES (float prohibition) — MUST-FAIL.
    Mutation probe: replace float members with string equivalents → jcs-n no longer
    raises; now jcs.digest == jcs_n.digest (no divergence) → exerciser must fail.
    """
    errs: list[str] = []
    action = v.get("action")
    jcs_pin = v.get("jcs", {})
    jcsn_pin = v.get("jcs_n", {})
    direction_b = bool(v.get("jcs_n_must_fail"))

    if action is None or not jcs_pin or not jcsn_pin:
        errs.append(
            "diverge vector missing required 'action', 'jcs', or 'jcs_n' fields"
        )
        return False, errs

    # Steps 1–4: plain JCS side.
    # Direction A uses _jcs() (no floats); Direction B uses _jcs_rfc8785() (floats ok).
    try:
        plain_pre = _jcs_rfc8785(action) if direction_b else _jcs(action)
    except Exception as exc:
        fn = "_jcs_rfc8785" if direction_b else "_jcs"
        errs.append(f"plain JCS ({fn}(action)) raised: {exc!r}")
        return False, errs

    pinned_plain = jcs_pin.get("pre_image", "")
    if plain_pre != pinned_plain:
        errs.append(
            f"jcs.pre_image mismatch (plain JCS result != pinned)\n"
            f"  computed: {plain_pre!r}\n"
            f"  pinned:   {pinned_plain!r}"
        )
    plain_hex = plain_pre.encode("utf-8").hex()
    pinned_plain_hex = jcs_pin.get("pre_image_bytes_hex", "")
    if pinned_plain_hex and plain_hex != pinned_plain_hex:
        errs.append(
            f"jcs.pre_image_bytes_hex mismatch\n"
            f"  computed: {plain_hex}\n"
            f"  pinned:   {pinned_plain_hex}"
        )
    plain_digest = hashlib.sha256(plain_pre.encode("utf-8")).hexdigest()
    pinned_plain_digest = jcs_pin.get("digest", "")
    if pinned_plain_digest and plain_digest != pinned_plain_digest:
        errs.append(
            f"jcs.digest mismatch\n"
            f"  computed: {plain_digest}\n"
            f"  pinned:   {pinned_plain_digest}"
        )

    if direction_b:
        # Direction B: jcs-n MUST-FAIL (blanket float prohibition, draft §11.3).
        # Assert jcs_n_pre_image raises; if it succeeds, that is a hard failure.
        try:
            jcsn_computed = jcs_n_pre_image(action)
            errs.append(
                f"Expected jcs_n_pre_image(action) to raise (float prohibition) "
                f"but it returned: {jcsn_computed!r}"
            )
        except (ValueError, TypeError):
            pass  # Expected — jcs-n correctly rejects the float

        if errs:
            return False, errs

        # Mutation probe for Direction B: replace float members with their string
        # equivalents (e.g. 0.95 → "0.95") so jcs-n no longer raises.  Now
        # jcs.digest == jcs_n.digest (no normalization needed), so step 9 must
        # flip to failure, confirming the MUST-FAIL assertion is live.
        if _probe_mutant:
            mutant_action: dict[str, object] = {}
            for k, val in v["action"].items():
                mutant_action[k] = repr(val) if isinstance(val, float) else val
            mutant_plain = _jcs(mutant_action)
            mutant_plain_hex = mutant_plain.encode("utf-8").hex()
            mutant_digest = hashlib.sha256(mutant_plain.encode("utf-8")).hexdigest()
            mutant_jcsn = _jcs(_normalize(mutant_action))
            mutant_jcsn_hex = mutant_jcsn.encode("utf-8").hex()
            mutant_jcsn_digest = hashlib.sha256(mutant_jcsn.encode("utf-8")).hexdigest()
            mutant = copy.deepcopy(v)
            mutant["action"] = mutant_action
            mutant["jcs_n_must_fail"] = False
            mutant["jcs"] = {
                **mutant.get("jcs", {}),
                "pre_image": mutant_plain,
                "pre_image_bytes_hex": mutant_plain_hex,
                "digest": mutant_digest,
            }
            mutant["jcs_n"] = {
                "pre_image": mutant_jcsn,
                "pre_image_bytes_hex": mutant_jcsn_hex,
                "digest": mutant_jcsn_digest,
            }
            mutant_ok, _ = _exercise_diverge(
                mutant, f"{vid}[mutant-J-float]", _probe_mutant=False
            )
            if mutant_ok:
                errs.append(
                    f"ASSERTION-FREE: float mutant ({vid}[mutant-J-float]) passed — "
                    f"replacing floats with strings did not flip the exerciser to "
                    f"failure; the jcs_n_must_fail check is not being tested"
                )

        return (not errs), errs

    # Direction A: Steps 5–8: jcs-n (normalize then JCS)
    try:
        jcsn_pre = jcs_n_pre_image(action)
    except Exception as exc:
        errs.append(f"jcs-n (jcs_n_pre_image(action)) raised: {exc!r}")
        return False, errs

    pinned_jcsn = jcsn_pin.get("pre_image", "")
    if jcsn_pre != pinned_jcsn:
        errs.append(
            f"jcs_n.pre_image mismatch (jcs-n result != pinned)\n"
            f"  computed: {jcsn_pre!r}\n"
            f"  pinned:   {pinned_jcsn!r}"
        )
    jcsn_hex = jcsn_pre.encode("utf-8").hex()
    pinned_jcsn_hex = jcsn_pin.get("pre_image_bytes_hex", "")
    if pinned_jcsn_hex and jcsn_hex != pinned_jcsn_hex:
        errs.append(
            f"jcs_n.pre_image_bytes_hex mismatch\n"
            f"  computed: {jcsn_hex}\n"
            f"  pinned:   {pinned_jcsn_hex}"
        )
    jcsn_digest = hashlib.sha256(jcsn_pre.encode("utf-8")).hexdigest()
    pinned_jcsn_digest = jcsn_pin.get("digest", "")
    if pinned_jcsn_digest and jcsn_digest != pinned_jcsn_digest:
        errs.append(
            f"jcs_n.digest mismatch\n"
            f"  computed: {jcsn_digest}\n"
            f"  pinned:   {pinned_jcsn_digest}"
        )

    # Step 9: assert divergence (the central claim of this vector class)
    effective_plain_digest = pinned_plain_digest or plain_digest
    effective_jcsn_digest = pinned_jcsn_digest or jcsn_digest
    if effective_plain_digest == effective_jcsn_digest:
        errs.append(
            f"jcs.digest == jcs_n.digest — no divergence demonstrated: "
            f"{effective_plain_digest!r}\n"
            f"  plain JCS pre_image: {plain_pre!r}\n"
            f"  jcs-n pre_image:     {jcsn_pre!r}"
        )

    if errs:
        return False, errs

    # Mutation probe for Direction A: replace null/empty-object/empty-array action
    # members with 'n/a' so that normalization is a no-op and JCS == jcs-n.
    # Recompute the correct pinned values for both sides; now jcs.digest ==
    # jcs_n.digest, so step 9 must flip to failure.
    if _probe_mutant:
        mutant_action = {}
        for k, val in v["action"].items():
            if val is None or val == {} or val == []:
                mutant_action[k] = "n/a"
            else:
                mutant_action[k] = val
        mutant_plain = _jcs(mutant_action)
        mutant_plain_hex = mutant_plain.encode("utf-8").hex()
        mutant_digest = hashlib.sha256(mutant_plain.encode("utf-8")).hexdigest()
        # jcs-n of mutant_action is identical to plain JCS (no null/empty members).
        mutant = copy.deepcopy(v)
        mutant["action"] = mutant_action
        mutant["jcs"] = {
            **mutant.get("jcs", {}),
            "pre_image": mutant_plain,
            "pre_image_bytes_hex": mutant_plain_hex,
            "digest": mutant_digest,
        }
        mutant["jcs_n"] = {
            **mutant.get("jcs_n", {}),
            "pre_image": mutant_plain,
            "pre_image_bytes_hex": mutant_plain_hex,
            "digest": mutant_digest,
        }
        mutant_ok, _ = _exercise_diverge(mutant, f"{vid}[mutant-J]", _probe_mutant=False)
        if mutant_ok:
            errs.append(
                f"ASSERTION-FREE: divergence mutant ({vid}[mutant-J]) passed — "
                f"null/empty→'n/a' mutation did not flip the inequality check to failure; "
                f"the divergence assertion is not being tested"
            )

    return (not errs), errs


# ---------------------------------------------------------------------------
# Self-tests (run at start of every check_vectors invocation)
# ---------------------------------------------------------------------------

def _run_self_tests() -> None:
    """Regression assertions for known-buggy edge cases.  Exits non-zero on failure."""
    errors: list[str] = []

    # Fix 2 regression: _normalize must recurse into list elements.
    result = _normalize({"outer": [{"x": None}]})
    expected = {"outer": [{}]}
    if result != expected:
        errors.append(
            f"SELF-TEST FAIL: _normalize array-element recursion\n"
            f"  got:      {result!r}\n"
            f"  expected: {expected!r}"
        )

    # Fix 3: _jcs must reject forbidden numerics, including when nested in arrays.
    def _expect_reject(value: object, label: str) -> None:
        try:
            _jcs({"k": value})
            errors.append(f"SELF-TEST FAIL: _jcs should have rejected {label}: {value!r}")
        except ValueError:
            pass

    _expect_reject(1.5,          "float")
    _expect_reject(float("inf"), "float inf")
    _expect_reject(1 << 53,      "unsafe integer 2^53")
    _expect_reject(-(1 << 53),   "unsafe integer -2^53")
    _expect_reject(10 ** 21,     "integer >= 1e21")
    _expect_reject(-(10 ** 21),  "integer <= -1e21")
    _expect_reject([1.5],        "float inside array")
    _expect_reject([1 << 53],    "unsafe integer inside array")
    _expect_reject([10 ** 21],   "integer >= 1e21 inside array")

    try:
        _jcs({"k": (1 << 53) - 1})
        _jcs({"k": 0})
        _jcs({"k": -((1 << 53) - 1)})
        _jcs({"k": [(1 << 53) - 1]})
    except ValueError as exc:
        errors.append(f"SELF-TEST FAIL: _jcs rejected safe integer: {exc}")

    # ran_any_check enforcement: bare must_fail must hard-fail.
    ok, _errs = _exercise_must_fail({"must_fail": True}, "bare-must_fail-self-test", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: bare {'must_fail': true} vector returned ok=True "
            "-- ran_any_check guard not enforced"
        )

    # --- Anton round-5 P1s: the mutation framework is itself verification code. ---

    # P1-1: synthetic vectors for F/G/H that fire the category but lack the fields
    # a mutant generator needs must HARD-ERROR, not silently pass via a None mutant.
    synth_f_no_artifacts = {
        "must_fail": True,
        "failure_reason": "common_canonical_form_trap",
        "common_canonical_form": '{"a":1}',
        "common_digest": _sha256_hex('{"a":1}'),
    }
    ok, _errs = _exercise_must_fail(synth_f_no_artifacts, "self-test-f-no-artifacts", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: Category F vector with common form/digest but no artifacts "
            "returned ok=True -- None-mutant / missing-invariant-inputs guard not enforced"
        )

    g_cited_payload = {"x": 1}
    g_bare_hex_no_ref = _sha256_hex(jcs_n_pre_image(g_cited_payload))
    synth_g_no_typed_ref = {
        "must_fail": True,
        "failure_reason": "representation_mismatch",
        "cited_artifact": {
            "payload": g_cited_payload,
            "correct_derived_id_bare_hex": g_bare_hex_no_ref,
        },
    }
    ok, _errs = _exercise_must_fail(synth_g_no_typed_ref, "self-test-g-no-typed-ref", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: Category G vector with cited payload/digest but no typed "
            "reference returned ok=True -- None-mutant / missing-invariant-inputs guard "
            "not enforced"
        )

    synth_h_no_correct_side = {
        "must_fail": True,
        "failure_reason": "erroneous_pre_image",
        "erroneous_pre_image_that_produced_wrong_digest": "some-wrong-preimage",
    }
    ok, _errs = _exercise_must_fail(synth_h_no_correct_side, "self-test-h-no-correct-side", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: Category H vector with erroneous preimage/digest but no "
            "correct-side fields returned ok=True -- None-mutant / missing-invariant-"
            "inputs guard not enforced"
        )

    # P1-1b: generator-refusal backstop -- a registered generator returning None must
    # hard-error the mutation probe even when the vector's own real check passes.
    # Isolated from category-specific field tightening via a temporary stub generator.
    d_vector = {
        "must_fail": True,
        "correct_derived_id": _sha256_hex(jcs_n_pre_image({"k": "v"})),
        "carried_id": "0" * 64,
        "full_payload": {"k": "v"},
    }
    _orig_d_gen = _MUTANT_GENERATORS.get("D")
    _MUTANT_GENERATORS["D"] = lambda v: None
    try:
        ok, _errs = _exercise_must_fail(copy.deepcopy(d_vector), "self-test-generator-refusal", [])
    finally:
        if _orig_d_gen is not None:
            _MUTANT_GENERATORS["D"] = _orig_d_gen
        else:
            del _MUTANT_GENERATORS["D"]
    if ok:
        errors.append(
            "SELF-TEST FAIL: a registered mutant generator returning None was silently "
            "skipped instead of hard-erroring the mutation probe"
        )

    # P1-2: Category G must reject the declared REPRESENTATION, not just any different
    # content.  A different-but-syntactically-valid bare-hex digest is a content
    # mismatch, not a representation mismatch, and must NOT satisfy Category G.
    g_payload = {"doc_id": None, "subject": "WS-1"}
    g_bare_hex = _sha256_hex(jcs_n_pre_image(g_payload))
    base_g_vector = {
        "must_fail": True,
        "failure_reason": "representation_mismatch",
        "cited_artifact": {"payload": g_payload, "correct_derived_id_bare_hex": g_bare_hex},
        "typed_reference_with_wrong_representation": {"digest": "sha256:" + g_bare_hex},
    }
    ok, errs = _exercise_must_fail(copy.deepcopy(base_g_vector), "self-test-g-base", [])
    if not ok:
        errors.append(
            f"SELF-TEST FAIL: a real representation-mismatch G vector was rejected: {errs!r}"
        )
    different_valid_hex = "a" * 64 if g_bare_hex != "a" * 64 else "b" * 64
    mutant_g = copy.deepcopy(base_g_vector)
    mutant_g["typed_reference_with_wrong_representation"]["digest"] = different_valid_hex
    ok, _errs = _exercise_must_fail(mutant_g, "self-test-g-valid-hex-content-mutant", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: Category G accepted a different-but-valid bare-hex digest "
            "as a representation mismatch -- it only checks content inequality, not "
            "representation validity"
        )

    # Round-6 (tyche-dev inline P1 on 6bc55ed): Category D must require full_payload --
    # a bare correct_derived_id/carried_id string comparison with no full_payload
    # certifies nothing, since neither ID is grounded in an independently recomputed
    # artifact.
    d_no_payload = {
        "must_fail": True,
        "correct_derived_id": "1" * 64,
        "carried_id": "0" * 64,
    }
    ok, _errs = _exercise_must_fail(d_no_payload, "self-test-d-no-payload", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: Category D vector with correct_derived_id/carried_id but "
            "no full_payload returned ok=True -- missing-recomputation-input guard not "
            "enforced"
        )

    # P1-3: a hollow E record, and a real E vector with non_conforming_verifier_behavior
    # stripped out, must NOT be counted informative.
    hollow_e = {"must_fail": True, "failure_reason": "profile_independence_violation"}
    errs = _check_informative_vector(hollow_e, "self-test-hollow-e")
    if not errs:
        errors.append(
            "SELF-TEST FAIL: hollow E record ({'must_fail': true, 'failure_reason': "
            "'profile_independence_violation'}) with no scenario/behavior data was "
            "counted informative"
        )

    e_auth_payload = {"doc_id": None, "subject": "WS-1"}
    e_auth_digest = _sha256_hex(jcs_n_pre_image(e_auth_payload))
    full_e_vector = {
        "must_fail": True,
        "failure_reason": "profile_independence_violation",
        "scenario": {
            "decision_record": {"payload": {"authorization": {"digest": e_auth_digest}}},
            "authorization_doc": {"payload": e_auth_payload, "derived_id": e_auth_digest},
        },
        "non_conforming_verifier_behavior": {"violation": "..."},
        "conforming_alternative": {"action": "..."},
    }
    errs = _check_informative_vector(copy.deepcopy(full_e_vector), "self-test-e-full")
    if errs:
        errors.append(
            f"SELF-TEST FAIL: a complete, conforming E vector was rejected: {errs!r}"
        )
    stripped_e_vector = copy.deepcopy(full_e_vector)
    del stripped_e_vector["non_conforming_verifier_behavior"]
    errs = _check_informative_vector(stripped_e_vector, "self-test-e-stripped-behavior")
    if not errs:
        errors.append(
            "SELF-TEST FAIL: E vector with non_conforming_verifier_behavior removed was "
            "still counted informative"
        )

    # cpb-vectors-runner-mustfail: Category C (fail-01-style erroneous_verification) is
    # the one category listed in _MUTANT_EXEMPT_CATEGORIES, so it gets no automatic
    # condition-removed mutant probe when real vectors are checked. Without a dedicated
    # guard, a future regression that weakens or drops the wrong_pre_image ->
    # wrong_recomputed_digest recompute would go undetected -- a pinned digest nobody
    # recomputes is not verified, it's just asserted. This mirrors the real
    # typed-ref-fail-01 vector shape and probes both sides directly.
    c_wrong_pre_image = (
        '{"doc_id":"secret-id-123","issued_at":"2026-07-24T00:00:00Z",'
        '"scope":"temperature-write","subject":"WS-42"}'
    )
    c_vector = {
        "must_fail": True,
        "failure_reason": "recomputed_digest_mismatch",
        "erroneous_verification": {
            "wrong_pre_image": c_wrong_pre_image,
            "wrong_recomputed_digest": _sha256_hex(c_wrong_pre_image),
        },
    }
    ok, errs = _exercise_must_fail(copy.deepcopy(c_vector), "self-test-c-base", [])
    if not ok:
        errors.append(
            f"SELF-TEST FAIL: a real Category C (fail-01 style) vector with a "
            f"correctly-recomputed wrong_recomputed_digest was rejected: {errs!r}"
        )
    mutant_c = copy.deepcopy(c_vector)
    mutant_c["erroneous_verification"]["wrong_recomputed_digest"] = "0" * 64
    ok, _errs = _exercise_must_fail(mutant_c, "self-test-c-corrupted-digest-mutant", [])
    if ok:
        errors.append(
            "SELF-TEST FAIL: Category C accepted a wrong_recomputed_digest that does "
            "not match SHA-256(wrong_pre_image) -- the pinned digest is not actually "
            "being recomputed and verified against the library"
        )

    # Category J self-tests: subject-binding divergence exerciser.
    # Real diverging vector: null member means JCS != jcs-n.
    j_action_real = {"task": "write-report", "notes": None, "device": "sensor-01"}
    j_plain_real = _jcs(j_action_real)
    j_jcsn_real = _jcs(_normalize(j_action_real))
    j_real_vector = {
        "diverge": True,
        "action": j_action_real,
        "jcs": {
            "pre_image": j_plain_real,
            "pre_image_bytes_hex": j_plain_real.encode("utf-8").hex(),
            "digest": _sha256_hex(j_plain_real),
        },
        "jcs_n": {
            "pre_image": j_jcsn_real,
            "pre_image_bytes_hex": j_jcsn_real.encode("utf-8").hex(),
            "digest": _sha256_hex(j_jcsn_real),
        },
    }
    ok, errs = _exercise_diverge(copy.deepcopy(j_real_vector), "self-test-j-real")
    if not ok:
        errors.append(
            f"SELF-TEST FAIL: a real diverge vector (null member) was rejected: {errs!r}"
        )

    # Non-diverging vector must fail: action has no null/empty members → JCS==jcs-n.
    j_action_nodiv = {"task": "write-report", "notes": "n/a", "device": "sensor-01"}
    j_plain_nodiv = _jcs(j_action_nodiv)
    j_nodiv_vector = {
        "diverge": True,
        "action": j_action_nodiv,
        "jcs": {
            "pre_image": j_plain_nodiv,
            "pre_image_bytes_hex": j_plain_nodiv.encode("utf-8").hex(),
            "digest": _sha256_hex(j_plain_nodiv),
        },
        "jcs_n": {
            "pre_image": j_plain_nodiv,
            "pre_image_bytes_hex": j_plain_nodiv.encode("utf-8").hex(),
            "digest": _sha256_hex(j_plain_nodiv),
        },
    }
    ok, _errs = _exercise_diverge(j_nodiv_vector, "self-test-j-nodiv", _probe_mutant=False)
    if ok:
        errors.append(
            "SELF-TEST FAIL: a non-diverging action (no null/empty members) passed "
            "the diverge exerciser — the inequality assertion is not tested"
        )

    # Direction B self-test: float member → plain RFC 8785 accepts; jcs-n MUST-FAIL.
    j_action_float = {"task": "classify", "confidence": 0.95, "device": "sensor-01"}
    j_plain_float = _jcs_rfc8785(j_action_float)
    j_float_vector = {
        "diverge": True,
        "jcs_n_must_fail": True,
        "action": j_action_float,
        "jcs": {
            "pre_image": j_plain_float,
            "pre_image_bytes_hex": j_plain_float.encode("utf-8").hex(),
            "digest": _sha256_hex(j_plain_float),
        },
        "jcs_n": {
            "must_fail": True,
            "failure_reason": "float_in_digest_bearing_field",
        },
    }
    ok, float_errs = _exercise_diverge(copy.deepcopy(j_float_vector), "self-test-j-float")
    if not ok:
        errors.append(
            f"SELF-TEST FAIL: Direction B (float must-fail) vector rejected: {float_errs!r}"
        )

    # Direction B probe: replace float with string → jcs-n accepts → exerciser must fail.
    j_action_float_str = {
        "task": "classify",
        "confidence": "0.95",
        "device": "sensor-01",
    }
    j_plain_fstr = _jcs(j_action_float_str)
    j_jcsn_fstr = _jcs(_normalize(j_action_float_str))
    j_float_nodiv = {
        "diverge": True,
        "jcs_n_must_fail": False,
        "action": j_action_float_str,
        "jcs": {
            "pre_image": j_plain_fstr,
            "pre_image_bytes_hex": j_plain_fstr.encode("utf-8").hex(),
            "digest": _sha256_hex(j_plain_fstr),
        },
        "jcs_n": {
            "pre_image": j_jcsn_fstr,
            "pre_image_bytes_hex": j_jcsn_fstr.encode("utf-8").hex(),
            "digest": _sha256_hex(j_jcsn_fstr),
        },
    }
    ok, _ = _exercise_diverge(j_float_nodiv, "self-test-j-float-nodiv", _probe_mutant=False)
    if ok:
        errors.append(
            "SELF-TEST FAIL: a non-diverging string-confidence action passed the "
            "exerciser with jcs_n_must_fail=False — step 9 is not checked for the "
            "float direction (jcs.digest == jcs_n.digest but exerciser accepted)"
        )

    # Category K: a mapping that does not derive `input` MUST be rejected.
    _k_good = {
        "declared_digest_context": {"member_mapping": {
            "fields": [{"source_pointer": "/a/b", "preimage_pointer": "/x"}],
            "constants": [{"preimage_pointer": "/k", "value": "v"}],
        }},
        "source_object": {"a": {"b": 1}},
        "input": {"x": 1, "k": "v"},
    }
    if _check_member_mapping_derivation(_k_good):
        errors.append("SELF-TEST FAIL: a correct member_mapping derivation was rejected")
    _k_bad = copy.deepcopy(_k_good)
    _k_bad["declared_digest_context"]["member_mapping"]["fields"][0]["preimage_pointer"] = "/WRONG"
    if not _check_member_mapping_derivation(_k_bad):
        errors.append(
            "SELF-TEST FAIL: a member_mapping that does not derive `input` was accepted "
            "-- Category K is assertion-free"
        )
    _k_absent = copy.deepcopy(_k_good)
    _k_absent["declared_digest_context"]["member_mapping"]["fields"][0]["source_pointer"] = "/a/nope"
    if not _check_member_mapping_derivation(_k_absent):
        errors.append(
            "SELF-TEST FAIL: a member_mapping naming an absent source pointer was accepted"
        )

    # An empty declared mapping is DECLARED, not absent.  With a falsy absence test this
    # returned no errors and skipped Category K entirely, so a vector could declare a
    # mapping and derive nothing.
    _k_empty = {
        "declared_digest_context": {"member_mapping": {}},
        "source_object": {"a": 1},
        "input": {"wrong": 2},
    }
    if not _check_member_mapping_derivation(_k_empty):
        errors.append(
            "SELF-TEST FAIL: `member_mapping: {}` was treated as absent -- an empty declared "
            "mapping bypasses Category K"
        )
    for _empty in ({"fields": []}, {"constants": []}, {"fields": [], "constants": []}):
        _k_e = copy.deepcopy(_k_empty)
        _k_e["declared_digest_context"]["member_mapping"] = _empty
        if not _check_member_mapping_derivation(_k_e):
            errors.append(f"SELF-TEST FAIL: declared but empty mapping {_empty} bypassed Category K")
    _k_null = copy.deepcopy(_k_good)
    _k_null["declared_digest_context"]["member_mapping"] = None
    if not _check_member_mapping_derivation(_k_null):
        errors.append(
            "SELF-TEST FAIL: `member_mapping: null` was treated as absent -- JSON null "
            "deserializes to None, so an explicitly declared null mapping derived nothing "
            "and skipped Category K entirely"
        )
    _k_gone = copy.deepcopy(_k_good)
    _k_gone["declared_digest_context"].pop("member_mapping", None)
    if _check_member_mapping_derivation(_k_gone):
        errors.append(
            "SELF-TEST FAIL: an absent member_mapping was rejected -- absence is the "
            "condition Category K vectors exist to document"
        )
    _k_type = copy.deepcopy(_k_empty)
    _k_type["declared_digest_context"]["member_mapping"] = []
    if not _check_member_mapping_derivation(_k_type):
        errors.append("SELF-TEST FAIL: a non-object member_mapping was accepted")
    _k_none = copy.deepcopy(_k_good)
    _k_none["declared_digest_context"].pop("member_mapping")
    if _check_member_mapping_derivation(_k_none):
        errors.append("SELF-TEST FAIL: an ABSENT member_mapping was treated as declared")

    # RFC 6901: the literal member "a.b" and the nested one are different addresses.
    _amb = {"a.b": 1, "a": {"b": 2}}
    if _resolve_source_pointer(_amb, "/a.b") != 1 or _resolve_source_pointer(_amb, "/a/b") != 2:
        errors.append("SELF-TEST FAIL: JSON Pointer does not separate a literal dot from nesting")
    for _bad_ptr in ("a/b", "", "a.b"):
        try:
            _parse_json_pointer(_bad_ptr)
        except ValueError:
            pass
        else:
            errors.append(f"SELF-TEST FAIL: {_bad_ptr!r} was accepted as a JSON Pointer")
    if _resolve_source_pointer({"a/b": 1}, "/a~1b") != 1 or _resolve_source_pointer({"a~b": 1}, "/a~0b") != 1:
        errors.append("SELF-TEST FAIL: RFC 6901 ~1/~0 escaping is not honoured")
    for _bad_esc in ("/a~2b", "/a~", "/~", "/a~b", "/a~~0b"):
        try:
            _parse_json_pointer(_bad_esc)
        except ValueError:
            pass
        else:
            errors.append(
                f"SELF-TEST FAIL: {_bad_esc!r} was accepted; only ~0 and ~1 are valid escapes"
            )
    _k_bad_esc = copy.deepcopy(_k_good)
    _k_bad_esc["declared_digest_context"]["member_mapping"]["fields"][0]["source_pointer"] = "/a~2b"
    if not _check_member_mapping_derivation(_k_bad_esc):
        errors.append("SELF-TEST FAIL: a mapping using an invalid tilde escape was accepted")

    # Destination collisions, all three kinds, constants and fields in one namespace.
    for _dests in (["/x", "/x"], ["/a", "/a/b"], ["/a/b", "/a"]):
        try:
            _check_destination_collisions(_dests)
        except ValueError:
            pass
        else:
            errors.append(f"SELF-TEST FAIL: colliding destinations {_dests} were accepted")
    _k_const_clash = copy.deepcopy(_k_good)
    _k_const_clash["declared_digest_context"]["member_mapping"]["constants"][0]["preimage_pointer"] = "/x"
    if not _check_member_mapping_derivation(_k_const_clash):
        errors.append("SELF-TEST FAIL: a constant colliding with a field destination was accepted")
    try:
        _resolve_source_pointer({"a": [1, 2]}, "/a/0")
    except ValueError:
        pass
    else:
        errors.append("SELF-TEST FAIL: an array traversal was accepted; arrays are out of scope")

    if errors:
        print("SELF-TEST FAILURES:")
        for e in errors:
            print(e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

def check_vectors(root: Path) -> int:
    _run_self_tests()

    passed = skipped = failed = informative = diverged = 0
    errors: list[str] = []

    for vec_path in sorted(root.rglob("*.json")):
        raw = vec_path.read_text(encoding="utf-8")
        try:
            # parse_constant rejects the Infinity / -Infinity / NaN literals that
            # Python accepts by default and RFC 8259 does not define. Without it a
            # vector could carry a token no other JSON reader would accept, and the
            # suite would happily compute a digest over it.
            v = json.loads(raw, parse_constant=_reject_json_constant)
        except json.JSONDecodeError as exc:
            errors.append(f"{vec_path}: invalid JSON: {exc}")
            failed += 1
            continue
        except ValueError as exc:
            errors.append(f"{vec_path}: {exc}")
            failed += 1
            continue

        vid = v.get("id", str(vec_path))
        exclusion_set: list[str] = v.get("exclusion_set", [])

        if v.get("diverge"):
            ok, vec_errors = _exercise_diverge(v, vid)
            if ok:
                diverged += 1
            else:
                errors.append(
                    f"FAIL {vid} (diverge):\n"
                    + "\n".join(f"  {e}" for e in vec_errors)
                )
                failed += 1

        # J. Member-mapping derivation.  Runs for ANY vector (pass or must_fail)
        # that declares a mapping, so the "here is the sufficient declaration"
        # half of a pair is executed rather than asserted in prose.
        map_errs = _check_member_mapping_derivation(v)
        if map_errs:
            for e in map_errs:
                errors.append(f"FAIL {vid} (member-mapping derivation): {e}")
            failed += 1
            continue

        if v.get("must_fail"):
            if v.get("failure_reason") in _INFORMATIVE_FAILURE_REASONS:
                errs = _check_informative_vector(v, vid)
                if errs:
                    for e in errs:
                        errors.append(f"FAIL {vid} (informative structural): {e}")
                    failed += 1
                else:
                    informative += 1
                continue

            ok, vec_errors = _exercise_must_fail(v, vid, exclusion_set, raw_text=raw)
            if ok:
                passed += 1
            else:
                errors.append(
                    f"FAIL {vid} (must_fail verification):\n"
                    + "\n".join(f"  {e}" for e in vec_errors)
                )
                failed += 1
            continue

        if "pre_image" not in v or "input" not in v:
            skipped += 1
            continue

        # For domain-transform PASS vectors: verify the transform chain produces 'input'.
        domain_transforms = v.get("domain_transforms")
        source = v.get("source")
        if domain_transforms and source is not None:
            try:
                transformed = _apply_domain_transforms(domain_transforms, source)
                if transformed != v["input"]:
                    errors.append(
                        f"FAIL {vid}: domain transform produced wrong 'input'\n"
                        f"  transform chain: {[t.get('id') for t in domain_transforms]}\n"
                        f"  expected: {v['input']!r}\n"
                        f"  got:      {transformed!r}"
                    )
                    failed += 1
                    continue
            except Exception as exc:
                errors.append(
                    f"FAIL {vid}: domain transform raised unexpectedly: {exc!r}"
                )
                failed += 1
                continue

        pinned_pre_image: str = v["pre_image"]
        pinned_hex: str = v.get("pre_image_bytes_hex", "")
        pinned_digest: str = v.get("digest", "")

        try:
            computed_pre_image = jcs_n_pre_image(v["input"], exclusion_set or None)
        except Exception as exc:
            errors.append(f"FAIL {vid}: jcs_n_pre_image raised {exc!r}")
            failed += 1
            continue

        if computed_pre_image != pinned_pre_image:
            errors.append(
                f"FAIL {vid}: pre_image MISMATCH (algorithm output != pinned value)\n"
                f"  computed: {computed_pre_image!r}\n"
                f"  pinned:   {pinned_pre_image!r}\n"
                f"  computed bytes: {computed_pre_image.encode('utf-8').hex()}\n"
                f"  pinned bytes:   {pinned_pre_image.encode('utf-8').hex()}"
            )
            failed += 1
            continue

        actual_bytes = pinned_pre_image.encode("utf-8")
        if pinned_hex and actual_bytes.hex() != pinned_hex:
            errors.append(
                f"FAIL {vid}: pre_image_bytes_hex mismatch\n"
                f"  expected: {pinned_hex}\n"
                f"  got:      {actual_bytes.hex()}"
            )
            failed += 1
            continue

        actual_digest = hashlib.sha256(actual_bytes).hexdigest()
        if pinned_digest and actual_digest != pinned_digest:
            errors.append(
                f"FAIL {vid}: digest mismatch\n"
                f"  expected: {pinned_digest}\n"
                f"  got:      {actual_digest}"
            )
            failed += 1
            continue

        passed += 1

    print(
        f"vectors: {passed} pass/exercised, {diverged} diverged, "
        f"{informative} informative, {skipped} no-check (skipped), {failed} FAILED"
    )
    for err in errors:
        print(err)
    return 1 if errors else 0


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("vectors")
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        sys.exit(2)
    sys.exit(check_vectors(root))
