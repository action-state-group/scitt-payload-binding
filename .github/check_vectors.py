#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone vector integrity checker — no dependencies beyond stdlib.

For every jcs-n PASS vector: independently recomputes the canonical form
using a minimal RFC 8785 / jcs-n implementation, then verifies:
  1. Recomputed pre_image == pinned pre_image
  2. pre_image encoded as UTF-8 hex == pre_image_bytes_hex
  3. SHA-256 of pre_image bytes == digest

For must_fail vectors:
  A. Algorithm-rejection vectors (have 'input', no 'jcs_n_correct_digest'):
     assert jcs_n_pre_image(input) raises ValueError.
  B. NFC-contrast vectors (have 'jcs_n_correct_digest'):
     verify all pinned hex/digest fields; verify jcs_n impl produces the
     correct canonical form from the decomposed input.
  C. Typed-ref fail vectors (have 'erroneous_verification'):
     verify wrong_pre_image → wrong_recomputed_digest via SHA-256.

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
    """RFC 8785 §3.2.3: lexicographic on UTF-16-BE code units (no length-first rule)."""
    return k.encode("utf-16-be")


def _normalize(obj: object) -> object:
    """Remove null, empty-array, and empty-object members bottom-up (jcs-n §3.1 E3).

    Array *elements* are not object members — they stay in the array even when
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
    """RFC 8785 canonical JSON with keys sorted per §3.2.3.

    jcs-n rejects floats and integers outside the safe range, including when
    they appear inside arrays.  Validation recurses through array elements so
    no forbidden numeric can slip through via a list wrapper.

    Rejection rules:
      - floats: always rejected (jcs-n payload must use integer numeric values)
      - |n| >= 2^53: unsafe integer — cannot be exactly represented in IEEE 754
      - |n| >= 1e21: Python json.dumps diverges from JCS here (Python: full
        decimal digits; JCS: scientific notation, e.g. 1e+21)
    """
    if isinstance(obj, dict):
        sorted_k = sorted(obj.keys(), key=_jcs_sort_key)
        pairs = [
            _jcs(k) + ":" + _jcs(obj[k])
            for k in sorted_k
        ]
        return "{" + ",".join(pairs) + "}"
    if isinstance(obj, list):
        # Recurse so that forbidden numerics inside arrays are caught, not
        # silently accepted via json.dumps.
        return "[" + ",".join(_jcs(item) for item in obj) + "]"
    # bool must be checked before int (bool is a subclass of int in Python)
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
        raise ValueError(
            f"float not allowed in jcs-n payloads: {obj!r}"
        )
    # Delegate to json.dumps for strings, booleans, null, safe integers
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def jcs_n_pre_image(
    payload: dict[str, object],
    exclusion_set: list[str] | None = None,
) -> str:
    """Return the jcs-n canonical pre-image string."""
    if exclusion_set:
        payload = {k: v for k, v in payload.items() if k not in exclusion_set}
    normalized = _normalize(payload)
    return _jcs(normalized)


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
            pass  # expected

    # Scalar rejection (original Fix 3)
    _expect_reject(1.5,           "float")
    _expect_reject(float("inf"),  "float inf")
    _expect_reject(1 << 53,       "unsafe integer 2^53")
    _expect_reject(-(1 << 53),    "unsafe integer -2^53")
    _expect_reject(10 ** 21,      "integer >= 1e21")
    _expect_reject(-(10 ** 21),   "integer <= -1e21")

    # Array-nested rejection (Fix 1 — the array bypass)
    _expect_reject([1.5],         "float inside array")
    _expect_reject([1 << 53],     "unsafe integer inside array")
    _expect_reject([10 ** 21],    "integer >= 1e21 inside array")

    # Safe-integer boundary must be ACCEPTED (scalar and array)
    try:
        _jcs({"k": (1 << 53) - 1})
        _jcs({"k": 0})
        _jcs({"k": -((1 << 53) - 1)})
        _jcs({"k": [(1 << 53) - 1]})
    except ValueError as exc:
        errors.append(f"SELF-TEST FAIL: _jcs rejected safe integer: {exc}")

    if errors:
        print("SELF-TEST FAILURES:")
        for e in errors:
            print(e)
        sys.exit(1)


# ---------------------------------------------------------------------------
# must_fail vector exerciser
# ---------------------------------------------------------------------------

def _exercise_must_fail(
    v: dict,
    vid: str,
    exclusion_set: list[str],
) -> tuple[bool, list[str]]:
    """Exercise a must_fail vector.  Returns (all_ok, error_messages).

    Three categories (non-exclusive — a vector may have fields from several):
      A. Algorithm-rejection: has 'input' but no 'jcs_n_correct_digest' or 'pre_image'
         → assert jcs_n_pre_image raises ValueError.
      B. NFC-contrast: has 'jcs_n_correct_digest'
         → verify pinned hex/digest fields; verify jcs_n impl output.
      C. Typed-ref erroneous computation: has 'erroneous_verification' with
         'wrong_pre_image' and 'wrong_recomputed_digest'
         → verify wrong_pre_image → SHA-256 = wrong_recomputed_digest.
    """
    vec_errors: list[str] = []
    ran_any_check = False

    # A. Algorithm-rejection vectors
    if (
        "input" in v
        and "jcs_n_correct_digest" not in v
        and "pre_image" not in v
    ):
        ran_any_check = True
        try:
            jcs_n_pre_image(v["input"], exclusion_set or None)
            vec_errors.append(
                "runner accepted invalid input — jcs_n_pre_image should have raised ValueError"
            )
        except (ValueError, TypeError):
            pass  # correctly rejected

    # B. NFC-contrast: verify pinned hex→digest pairs and jcs_n impl output
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
        # Verify jcs_n impl produces the correct canonical form from the input
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
                vec_errors.append(
                    f"jcs_n_pre_image raised unexpectedly on NFC-contrast input: {exc!r}"
                )

    # C. Typed-ref erroneous-computation verification
    ev = v.get("erroneous_verification", {})
    if "wrong_pre_image" in ev and "wrong_recomputed_digest" in ev:
        ran_any_check = True
        got = hashlib.sha256(ev["wrong_pre_image"].encode("utf-8")).hexdigest()
        if got != ev["wrong_recomputed_digest"]:
            vec_errors.append(
                f"wrong_recomputed_digest mismatch\n"
                f"  expected: {ev['wrong_recomputed_digest']}\n"
                f"  got:      {got}"
            )

    return (not vec_errors), vec_errors


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
            continue  # not a fully-specified digest-bearing vector

        pinned_pre_image: str = v["pre_image"]
        pinned_hex: str = v.get("pre_image_bytes_hex", "")
        pinned_digest: str = v.get("digest", "")

        # 1. Recompute canonical form independently
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

        # 2. Verify byte-level consistency
        actual_bytes = pinned_pre_image.encode("utf-8")
        if pinned_hex and actual_bytes.hex() != pinned_hex:
            errors.append(
                f"FAIL {vid}: pre_image_bytes_hex mismatch\n"
                f"  expected: {pinned_hex}\n"
                f"  got:      {actual_bytes.hex()}"
            )
            failed += 1
            continue

        # 3. Verify digest
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
        f"vectors: {passed} pass/exercised, {skipped} no-check (skipped), {failed} FAILED"
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
