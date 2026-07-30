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
     -> assert they differ.
  E. Profile-independence scenario: 'scenario.authorization_doc' with 'derived_id'
     -> recompute derived_id from payload; verify equals the typed-ref digest in
       decision_record.payload.authorization.digest.
  F. Common-canonical-form trap: 'common_canonical_form' + 'common_digest'
     -> verify SHA-256(common_canonical_form.encode('utf-8')) == common_digest.
  G. Cited-artifact derived-id: 'cited_artifact.correct_derived_id_bare_hex'
     -> recompute jcs_n from cited_artifact.payload (using registry exclusion_set
       if present); verify == correct_derived_id_bare_hex.
  H. Top-level erroneous pre-image: 'erroneous_pre_image_that_produced_wrong_digest'
     -> verify erroneous pre-image -> SHA-256 = typed_reference_with_wrong_digest.digest;
       verify verification.correct_pre_image -> SHA-256 = verification.recomputed_digest.

A must_fail vector matching NONE of the above is a hard failure -- 'ran_any_check' is
enforced.  A bare {'must_fail': true} fails the suite.

A pinned vector that was never run is not a vector.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


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
# must_fail vector exerciser (defined before _run_self_tests for forward reference)
# ---------------------------------------------------------------------------

def _exercise_must_fail(
    v: dict,
    vid: str,
    exclusion_set: list[str],
) -> tuple[bool, list[str]]:
    """Exercise a must_fail vector.  Returns (all_ok, error_messages).

    Categories are non-exclusive.  A vector triggering NONE is a hard failure.
    """
    vec_errors: list[str] = []
    ran_any_check = False

    # A. Algorithm-rejection vectors
    if "input" in v and "jcs_n_correct_digest" not in v and "pre_image" not in v:
        ran_any_check = True
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
        got = _sha256_hex(ev["wrong_pre_image"])
        if got != ev["wrong_recomputed_digest"]:
            vec_errors.append(
                f"wrong_recomputed_digest mismatch\n"
                f"  expected: {ev['wrong_recomputed_digest']}\n"
                f"  got:      {got}"
            )

    # D. Derived-id mismatch: correct_derived_id must differ from carried_id
    if "correct_derived_id" in v and "carried_id" in v:
        ran_any_check = True
        if v["correct_derived_id"] == v["carried_id"]:
            vec_errors.append(
                f"correct_derived_id == carried_id -- vector claims mismatch but "
                f"values are identical: {v['correct_derived_id']!r}"
            )

    # E. Profile-independence scenario: recompute authorization_doc derived_id
    scenario = v.get("scenario", {})
    auth_doc = scenario.get("authorization_doc", {})
    if auth_doc and "derived_id" in auth_doc and "payload" in auth_doc:
        ran_any_check = True
        try:
            computed = jcs_n_pre_image(auth_doc["payload"])
            got = hashlib.sha256(computed.encode("utf-8")).hexdigest()
            if got != auth_doc["derived_id"]:
                vec_errors.append(
                    f"authorization_doc.derived_id mismatch\n"
                    f"  expected: {auth_doc['derived_id']}\n"
                    f"  got:      {got}"
                )
            carried_digest = (
                scenario.get("decision_record", {})
                .get("payload", {})
                .get("authorization", {})
                .get("digest")
            )
            if carried_digest and got != carried_digest:
                vec_errors.append(
                    f"authorization_doc.derived_id != decision_record authorization.digest\n"
                    f"  derived_id:           {got}\n"
                    f"  authorization.digest: {carried_digest}"
                )
        except Exception as exc:
            vec_errors.append(f"profile-independence scenario: jcs_n_pre_image raised: {exc!r}")

    # F. Common-canonical-form trap: verify SHA-256 of pinned canonical form
    if "common_canonical_form" in v and "common_digest" in v:
        ran_any_check = True
        got = _sha256_hex(v["common_canonical_form"])
        if got != v["common_digest"]:
            vec_errors.append(
                f"common_digest mismatch\n"
                f"  expected: {v['common_digest']}\n"
                f"  got:      {got}"
            )

    # G. Cited-artifact derived-id: recompute from payload
    cited = v.get("cited_artifact", {})
    if "correct_derived_id_bare_hex" in cited and "payload" in cited:
        ran_any_check = True
        reg_excl: list[str] = cited.get("registry_entry", {}).get("exclusion_set") or []
        try:
            computed = jcs_n_pre_image(cited["payload"], reg_excl or None)
            got = hashlib.sha256(computed.encode("utf-8")).hexdigest()
            if got != cited["correct_derived_id_bare_hex"]:
                vec_errors.append(
                    f"cited_artifact.correct_derived_id_bare_hex mismatch\n"
                    f"  expected: {cited['correct_derived_id_bare_hex']}\n"
                    f"  got:      {got}"
                )
        except Exception as exc:
            vec_errors.append(f"cited_artifact derived-id: jcs_n_pre_image raised: {exc!r}")

    # H. Top-level erroneous pre-image (identifier-inconsistent-with-context)
    erroneous_pre = v.get("erroneous_pre_image_that_produced_wrong_digest")
    if erroneous_pre is not None:
        ran_any_check = True
        wrong_digest = v.get("typed_reference_with_wrong_digest", {}).get("digest")
        if wrong_digest:
            got = _sha256_hex(erroneous_pre)
            if got != wrong_digest:
                vec_errors.append(
                    f"erroneous pre-image SHA-256 != typed_reference_with_wrong_digest.digest\n"
                    f"  expected: {wrong_digest}\n"
                    f"  got:      {got}"
                )
        verification = v.get("verification", {})
        correct_pre = verification.get("correct_pre_image")
        recomputed_digest = verification.get("recomputed_digest")
        if correct_pre and recomputed_digest:
            got = _sha256_hex(correct_pre)
            if got != recomputed_digest:
                vec_errors.append(
                    f"verification.correct_pre_image SHA-256 != verification.recomputed_digest\n"
                    f"  expected: {recomputed_digest}\n"
                    f"  got:      {got}"
                )

    # Enforcement: a vector matching none of the above is a hard failure.
    if not ran_any_check:
        vec_errors.append(
            "no verification path matched (ran_any_check=False) -- vector carries "
            "no executable assertion; add a recognized failure-kind field or "
            "reclassify as informative"
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

    passed = skipped = failed = 0
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

    print(f"vectors: {passed} pass/exercised, {skipped} no-check (skipped), {failed} FAILED")
    for err in errors:
        print(err)
    return 1 if errors else 0


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("vectors")
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        sys.exit(2)
    sys.exit(check_vectors(root))
