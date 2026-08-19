#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-command vector regeneration and mutation-check for algorithm jcs-n.

Usage:
    python3 vectors/generate.py [<vectors-dir>]          # validate all pinned values
    python3 vectors/generate.py --update [<vectors-dir>] # recompute and write back
    python3 vectors/generate.py --mutate [<vectors-dir>] # mutation check (byte-flip)

All modes use only stdlib — no external dependencies.

--validate (default)
    For every PASS vector with 'input', 'pre_image', 'pre_image_bytes_hex', and 'digest':
    recompute all three from 'input' and report any mismatch.  Exit non-zero if any
    mismatch found.

--update
    Same as --validate, but also writes the recomputed values back to the vector file.
    Use when adding a new vector whose 'pre_image' / 'digest' fields are placeholders.
    Never updates must_fail vectors or vectors without 'input'.

--mutate
    For every PASS vector with a pinned 'digest': flip one byte of the canonical
    pre_image and assert the resulting digest does NOT equal the pinned digest.  A
    vector whose digest is invariant under a single-byte pre_image mutation fails this
    check (cryptographic property of SHA-256 means this cannot happen in practice, but
    the check documents the requirement).  Exit non-zero if any mismatch.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Minimal jcs-n implementation (same logic as check_vectors.py)
# ---------------------------------------------------------------------------

def _jcs_sort_key(k: str) -> bytes:
    return k.encode("utf-16-be")


def _normalize(obj: object) -> object:
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
    if isinstance(obj, dict):
        sorted_k = sorted(obj.keys(), key=_jcs_sort_key)
        pairs = [_jcs(k) + ":" + _jcs(obj[k]) for k in sorted_k]
        return "{" + ",".join(pairs) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(_jcs(item) for item in obj) + "]"
    if not isinstance(obj, bool) and isinstance(obj, int):
        n = abs(obj)
        if n >= 10 ** 21 or n >= 1 << 53:
            raise ValueError(f"unsafe or oversized integer: {obj!r}")
    if isinstance(obj, float):
        raise ValueError(f"float not allowed in jcs-n: {obj!r}")
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def jcs_n_pre_image(payload: dict, exclusion_set: list[str] | None = None) -> str:
    if exclusion_set:
        payload = {k: v for k, v in payload.items() if k not in exclusion_set}
    return _jcs(_normalize(payload))


def compute_vector(v: dict) -> tuple[str, str, str]:
    """Return (pre_image, pre_image_bytes_hex, digest) for a PASS vector."""
    excl = v.get("exclusion_set") or []
    pre_image = jcs_n_pre_image(v["input"], excl or None)
    pre_image_bytes = pre_image.encode("utf-8")
    digest = hashlib.sha256(pre_image_bytes).hexdigest()
    return pre_image, pre_image_bytes.hex(), digest


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    update = "--update" in argv
    mutate = "--mutate" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = Path(args[0]) if args else Path(__file__).parent

    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    failures: list[str] = []
    checked = 0

    for vec_path in sorted(root.rglob("*.json")):
        try:
            v = json.loads(vec_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"{vec_path}: invalid JSON: {exc}")
            continue

        if v.get("must_fail") or "input" not in v:
            continue

        vid = v.get("id", str(vec_path))

        try:
            computed_pre, computed_hex, computed_digest = compute_vector(v)
        except Exception as exc:
            failures.append(f"{vid}: compute_vector raised: {exc!r}")
            continue

        checked += 1

        if mutate:
            # Flip one byte in the pre_image and verify digest changes.
            pre_bytes = bytearray(computed_pre.encode("utf-8"))
            pre_bytes[0] ^= 0xFF
            mutated_digest = hashlib.sha256(bytes(pre_bytes)).hexdigest()
            if mutated_digest == computed_digest:
                failures.append(
                    f"{vid}: MUTATION INVARIANT — digest unchanged after single-byte "
                    f"pre_image flip; this should be cryptographically impossible"
                )
            continue

        # Validate pinned fields.
        pinned_pre = v.get("pre_image", "")
        pinned_hex = v.get("pre_image_bytes_hex", "")
        pinned_digest = v.get("digest", "")

        if pinned_pre and computed_pre != pinned_pre:
            failures.append(
                f"{vid}: pre_image MISMATCH\n"
                f"  computed: {computed_pre!r}\n"
                f"  pinned:   {pinned_pre!r}"
            )
        if pinned_hex and computed_hex != pinned_hex:
            failures.append(
                f"{vid}: pre_image_bytes_hex MISMATCH\n"
                f"  computed: {computed_hex}\n"
                f"  pinned:   {pinned_hex}"
            )
        if pinned_digest and computed_digest != pinned_digest:
            failures.append(
                f"{vid}: digest MISMATCH\n"
                f"  computed: {computed_digest}\n"
                f"  pinned:   {pinned_digest}"
            )

        if update:
            changed = (
                v.get("pre_image") != computed_pre
                or v.get("pre_image_bytes_hex") != computed_hex
                or v.get("digest") != computed_digest
            )
            if changed:
                v["pre_image"] = computed_pre
                v["pre_image_bytes_hex"] = computed_hex
                v["digest"] = computed_digest
                vec_path.write_text(
                    json.dumps(v, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                print(f"updated {vec_path}")

    mode = "mutate" if mutate else ("update" if update else "validate")
    print(f"generate ({mode}): {checked} vectors checked, {len(failures)} failures")
    for f in failures:
        print(f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
