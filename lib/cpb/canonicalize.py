# SPDX-License-Identifier: BSD-3-Clause
"""Algorithm jcs-n: absent-field normalization + JCS + SHA-256 + lowercase hex.

Reference: draft-mih-sokolov-scitt-payload-binding-00 §3.1

CANONICAL-DIGEST(jcs-n, P) =
    lowercase_hex(SHA-256(JCS(normalize(P minus exclusion_set))))
"""
from __future__ import annotations

import hashlib
from typing import Any

__all__ = [
    "FloatInDigestError",
    "UnsafeIntegerError",
    "MAX_SAFE_INTEGER",
    "normalize",
    "jcs",
    "canonical_digest",
]

# IEEE-754 double safe integer bound (ECMAScript Number.MAX_SAFE_INTEGER).
# Integers whose magnitude exceeds this cannot round-trip through an
# ECMAScript-Number-based reader, so two conforming verifiers could derive
# different digests from the same bytes. §3.1 forbids floats in digest-bearing
# fields; this bound additionally rejects any integer outside the safe range.
MAX_SAFE_INTEGER = 2**53 - 1  # 9007199254740991


class FloatInDigestError(ValueError):
    """A JSON float reached a digest-bearing field. §3.1 forbids this."""


class UnsafeIntegerError(ValueError):
    """An integer outside ±(2^53-1) reached a digest-bearing field.
    Represent large integers as exact decimal strings (§3.1)."""


def normalize(v: Any) -> Any:
    """Absent-field normalization (§3.1 step 1): remove, bottom-up and
    recursively, every object member whose value is JSON null, an empty
    array (zero elements), or an empty object (zero members). Returns a
    normalized copy; does not mutate the input.

    Applied bottom-up so that an object that becomes empty only after its
    own null/empty members are removed is itself removed by its parent.
    """
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for key, val in v.items():
            nv = normalize(val)
            if nv is None:
                continue
            if isinstance(nv, (dict, list)) and len(nv) == 0:
                continue
            out[key] = nv
        return out
    if isinstance(v, list):
        # Array elements are not "members" (§3.1); do not remove them,
        # but do normalize nested objects within them.
        return [normalize(x) for x in v]
    return v


def _jcs_string(s: str) -> str:
    # RFC 8785 §3.2.2.2: minimal escaping; two-char shortcuts for known
    # control characters; \u00XX for the rest; no escaping of '/'.
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x09:
            out.append("\\t")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0D:
            out.append("\\r")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_value(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, bool):  # pragma: no cover — handled above
        return "true" if v else "false"
    if isinstance(v, int):
        # Guard the JS-safe range: magnitude beyond 2^53-1 is not reproducible
        # across ECMAScript-Number readers.
        if v > MAX_SAFE_INTEGER or v < -MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(
                f"integer {v} is outside the safe range ±{MAX_SAFE_INTEGER}; "
                "represent large integers as exact decimal strings (§3.1)"
            )
        return str(v)
    if isinstance(v, float):
        raise FloatInDigestError(
            "JSON floating-point value in a digest-bearing field; §3.1 requires "
            "exact decimal strings for monetary/quantity values"
        )
    if isinstance(v, list):
        return "[" + ",".join(_jcs_value(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785 §3.2.3: sort by UTF-16 code units of the member name.
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                _jcs_string(k) + ":" + _jcs_value(val) for k, val in items
            )
            + "}"
        )
    raise TypeError(f"value of type {type(v).__name__!r} is not JSON-serializable")


def jcs(v: Any) -> bytes:
    """RFC 8785 JCS serialization of v as UTF-8 bytes (no normalization)."""
    return _jcs_value(v).encode("utf-8")


def canonical_digest(v: Any, exclusion_set: frozenset[str] | set[str] | None = None) -> str:
    """CANONICAL-DIGEST for algorithm jcs-n (§3.1).

    Args:
        v: The JSON-serializable value to digest (must be a dict for CPB payloads).
        exclusion_set: Optional set of top-level field names to remove before
            normalization (§4). Applied to the input dict before any normalization.

    Returns:
        64-character lowercase hex string.
    """
    if exclusion_set and isinstance(v, dict):
        v = {k: val for k, val in v.items() if k not in exclusion_set}
    return hashlib.sha256(jcs(normalize(v))).hexdigest()
