#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone vector integrity checker — no dependencies beyond stdlib.

For every jcs-n PASS vector: independently recomputes the canonical form
using a minimal RFC 8785 / jcs-n implementation, then verifies:
  1. Recomputed pre_image == pinned pre_image
  2. pre_image encoded as UTF-8 hex == pre_image_bytes_hex
  3. SHA-256 of pre_image bytes == digest

Vectors with must_fail=true are skipped.

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
        # Recurse into each element; the element stays in the list regardless
        # of its normalized value (array elements are not members).
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

    jcs-n rejects floats and integers outside the safe range so that the
    runner catches invalid payloads rather than silently producing a canonical
    form that diverges from a conforming implementation:
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
    # Delegate to json.dumps for strings, booleans, null, safe integers, arrays
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
    # {'outer': [{'x': None}]} → {'outer': [{}]}  (null member removed inside
    # the element; the element {} stays in the array).
    result = _normalize({"outer": [{"x": None}]})
    expected = {"outer": [{}]}
    if result != expected:
        errors.append(
            f"SELF-TEST FAIL: _normalize array-element recursion\n"
            f"  got:      {result!r}\n"
            f"  expected: {expected!r}"
        )

    # Fix 3: _jcs must reject floats, unsafe integers, and 1e21-boundary integers.
    def _expect_reject(value: object, label: str) -> None:
        try:
            _jcs({"k": value})
            errors.append(f"SELF-TEST FAIL: _jcs should have rejected {label}: {value!r}")
        except ValueError:
            pass  # expected

    _expect_reject(1.5,            "float")
    _expect_reject(float("inf"),   "float inf")
    _expect_reject(1 << 53,        "unsafe integer 2^53")
    _expect_reject(-(1 << 53),     "unsafe integer -2^53")
    _expect_reject(10 ** 21,       "integer >= 1e21")
    _expect_reject(-(10 ** 21),    "integer <= -1e21")

    # Fix 3: safe-integer boundary must be ACCEPTED.
    try:
        _jcs({"k": (1 << 53) - 1})
        _jcs({"k": 0})
        _jcs({"k": -((1 << 53) - 1)})
    except ValueError as exc:
        errors.append(f"SELF-TEST FAIL: _jcs rejected safe integer: {exc}")

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

        if v.get("must_fail"):
            skipped += 1
            continue

        if "pre_image" not in v or "input" not in v:
            continue  # not a fully-specified digest-bearing vector

        vid = v.get("id", str(vec_path))
        pinned_pre_image: str = v["pre_image"]
        pinned_hex: str = v.get("pre_image_bytes_hex", "")
        pinned_digest: str = v.get("digest", "")
        exclusion_set: list[str] = v.get("exclusion_set", [])

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
        f"vectors: {passed} pass, {skipped} must_fail (skipped), {failed} FAILED"
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
