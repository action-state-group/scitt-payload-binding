#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone vector integrity checker — no dependencies beyond stdlib.

For every jcs-n PASS vector: independently recomputes the canonical form
using a minimal RFC 8785 / jcs-n implementation, then verifies:
  1. Recomputed pre_image == pinned pre_image
  2. pre_image encoded as UTF-8 hex == pre_image_bytes_hex
  3. SHA-256 of pre_image bytes == digest

For must_fail vectors — each MUST match at least one category (enforced):
  A. Algorithm-rejection: 'input' present, no 'jcs_n_correct_digest'/'pre_image'
     -> assert jcs_n_pre_image(input) raises ValueError.
  B. NFC-contrast: 'jcs_n_correct_digest' present
     -> verify all pinned hex/digest fields; verify jcs_n impl output.
  C. Typed-ref erroneous_verification: 'wrong_pre_image' + 'wrong_recomputed_digest'
     -> verify wrong_pre_image -> SHA-256 = wrong_recomputed_digest.
  D. Derived-id mismatch: 'correct_derived_id' + 'carried_id'
     -> recompute from full_payload (exclusion_set applied); assert recomputed ==
        correct_derived_id AND recomputed != carried_id.
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
import re
import sys
from pathlib import Path


_BARE_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _mutant_A(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    m["input"] = {}
    return m


def _mutant_B(v: dict) -> dict | None:
    m = copy.deepcopy(v)
    if "jcs_n_correct_pre_image_bytes_hex" not in m or "nfc_contrast_pre_image_bytes_hex" not in m:
        return None
    m["jcs_n_correct_pre_image_bytes_hex"], m["nfc_contrast_pre_image_bytes_hex"] = (
        m["nfc_contrast_pre_image_bytes_hex"],
        m["jcs_n_correct_pre_image_bytes_hex"],
    )
    m["jcs_n_correct_digest"], m["nfc_contrast_digest"] = (
        m.get("nfc_contrast_digest"),
        m.get("jcs_n_correct_digest"),
    )
    return m


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


_MUTANT_GENERATORS: dict[str, object] = {
    "A": _mutant_A,
    "B": _mutant_B,
    "D": _mutant_D,
    "F": _mutant_F,
    "G": _mutant_G,
    "H": _mutant_H,
}


# ---------------------------------------------------------------------------
# must_fail vector exerciser (defined before _run_self_tests for forward reference)
# ---------------------------------------------------------------------------

def _exercise_must_fail(
    v: dict,
    vid: str,
    exclusion_set: list[str],
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
        if full_payload is not None:
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
        else:
            if v["correct_derived_id"] == v["carried_id"]:
                vec_errors.append(
                    "correct_derived_id == carried_id — values identical "
                    "(add full_payload to vector for real recomputation)"
                )

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

    passed = skipped = failed = informative = 0
    errors: list[str] = []

    for vec_path in sorted(root.rglob("*.json")):
        raw = vec_path.read_text(encoding="utf-8")
        try:
            v = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"{vec_path}: invalid JSON: {exc}")
            failed += 1
            continue

        vid = v.get("id", str(vec_path))
        exclusion_set: list[str] = v.get("exclusion_set", [])

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

            ok, vec_errors = _exercise_must_fail(v, vid, exclusion_set)
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
        f"vectors: {passed} pass/exercised, {informative} informative, "
        f"{skipped} no-check (skipped), {failed} FAILED"
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
