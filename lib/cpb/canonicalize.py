# SPDX-License-Identifier: BSD-3-Clause
"""CPB ``jcs`` construction and historical ``jcs-n`` evaluation.

The live algorithm applies RFC 8785 directly.  The withdrawn algorithm is
retained byte-for-byte for historical records:

``CANONICAL-DIGEST(jcs-n, P) =
lowercase_hex(SHA-256(JCS(normalize(P minus exclusion_set))))``
"""
from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from ._lex import RawViolation, lex

__all__ = [
    "FloatInDigestError",
    "UnsafeIntegerError",
    "JsonWireFormatError",
    "MAX_SAFE_INTEGER",
    "normalize",
    "jcs",
    "jcs_n",
    "raw_digest",
    "canonical_digest",
    "canonical_digest_json",
]

# IEEE-754 double safe integer bound (ECMAScript Number.MAX_SAFE_INTEGER).
# Integers whose magnitude exceeds this cannot round-trip through an
# ECMAScript-Number-based reader, so two conforming verifiers could derive
# different digests from the same bytes. Historical draft -00 §3.1 forbids
# floats in jcs-n digest-bearing
# fields; this bound additionally rejects any integer outside the safe range.
MAX_SAFE_INTEGER = 2**53 - 1  # 9007199254740991


class FloatInDigestError(ValueError):
    """A JSON float reached a historical jcs-n digest-bearing field."""


class UnsafeIntegerError(ValueError):
    """An integer outside ±(2^53-1) reached a digest-bearing field.
    Represent large integers as exact decimal strings (historical draft -00 §3.1)."""


class JsonWireFormatError(ValueError):
    """Raw JSON violates the selected canonicalization algorithm's wire rules.

    ``violations`` preserves the duplicate-member or number-token findings
    emitted before a normal JSON parser could erase them.
    """

    def __init__(self, violations: list[RawViolation]) -> None:
        self.violations = tuple(violations)
        details = "; ".join(
            f"{violation.code} at {violation.path}: {violation.detail}"
            for violation in violations
        )
        super().__init__(details)


def normalize(v: Any) -> Any:
    """Historical jcs-n absent-field normalization (draft -00 §3.1 step 1).

    Remove, bottom-up and
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
        # Array elements are not "members" (draft -00 §3.1); do not remove them,
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


def _jcs_n_value(v: Any) -> str:
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
                "represent large integers as exact decimal strings "
                "(historical draft -00 §3.1)"
            )
        return str(v)
    if isinstance(v, float):
        raise FloatInDigestError(
            "JSON floating-point value in a historical jcs-n digest-bearing field; "
            "draft -00 §3.1 requires "
            "exact decimal strings for monetary/quantity values"
        )
    if isinstance(v, list):
        return "[" + ",".join(_jcs_n_value(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785 §3.2.3: sort by UTF-16 code units of the member name.
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                _jcs_string(k) + ":" + _jcs_n_value(val) for k, val in items
            )
            + "}"
        )
    raise TypeError(f"value of type {type(v).__name__!r} is not JSON-serializable")


def jcs(v: Any) -> bytes:
    """RFC 8785 JCS serialization of ``v`` as UTF-8 bytes."""
    return rfc8785.dumps(v)


def jcs_n(v: Any) -> bytes:
    """Historical jcs-n serialization after its numeric restrictions.

    Normalization is deliberately separate: callers apply :func:`normalize`
    before this serializer when evaluating the withdrawn algorithm.
    """
    return _jcs_n_value(v).encode("utf-8")


def raw_digest(
    v: Any,
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str,
) -> bytes:
    """Evaluate a parsed canonical value or exact transmitted octets.

    The result is exactly the byte form whose lowercase hexadecimal rendering
    is returned by :func:`canonical_digest`; it is not the UTF-8 encoding of
    that rendering. The algorithm is mandatory and explicit.

    For ``jcs`` and historical ``jcs-n``, this parsed-value helper cannot prove
    that source JSON had no duplicate members and does not report a verification
    result. When raw JSON is available, use :func:`canonical_digest_json` for
    its duplicate-preserving gate and pass that result through
    :func:`cpb.hex_to_raw` at a declared raw-output boundary. Historical
    ``jcs-n`` evaluation also does not by itself establish pre-withdrawal
    vintage.

    For ``as-transmitted``, ``v`` must be the exact ``bytes`` selected by the
    container format's cited named production, and no non-empty exclusion set
    is permitted. This function hashes those bytes; it cannot establish that a
    caller selected the correct production or byte boundary.
    """
    if algorithm == "as-transmitted":
        if not isinstance(v, bytes):
            raise TypeError("as-transmitted input must be the exact bytes to hash")
        if exclusion_set:
            raise ValueError("as-transmitted does not permit an exclusion set")
        return hashlib.sha256(v).digest()
    if algorithm not in {"jcs", "jcs-n"}:
        raise ValueError(f"unsupported canonicalization algorithm {algorithm!r}")
    if exclusion_set and isinstance(v, dict):
        v = {k: val for k, val in v.items() if k not in exclusion_set}
    pre_image = jcs(v) if algorithm == "jcs" else jcs_n(normalize(v))
    return hashlib.sha256(pre_image).digest()


def canonical_digest(
    v: Any,
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str,
) -> str:
    """Evaluate a CPB digest over a parsed value or exact transmitted bytes.

    The algorithm is explicit so upgrading from the former ``jcs-n`` API can
    never silently change a content address. ``jcs-n`` is retained only for historical
    evaluation; selecting it does not establish pre-withdrawal vintage and
    MUST NOT be interpreted as a verification result. A parsed mapping cannot
    prove that its source JSON had no duplicate members; use
    :func:`canonical_digest_json` whenever raw JSON is available.

    Args:
        v: A JSON-serializable value for ``jcs``/``jcs-n``; exact ``bytes`` for
            ``as-transmitted``.
        exclusion_set: Optional set of top-level field names to remove before
            the algorithm runs (§5), including before jcs-n normalization.

    Returns:
        64-character lowercase hex string.
    """
    return raw_digest(v, exclusion_set, algorithm=algorithm).hex()


def canonical_digest_json(
    raw: str | bytes,
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str = "jcs",
) -> str:
    """Evaluate ``jcs`` or historical ``jcs-n`` without losing duplicates.

    The duplicate-preserving lexer runs before exclusion or normalization.
    Therefore a duplicate member is rejected even when that member would later
    be excluded. Historical jcs-n's integer-only wire form is enforced at the
    same gate; live jcs accepts the RFC 8259 number forms that RFC 8785
    canonicalizes. Like :func:`canonical_digest`, this function only evaluates
    digest bytes; it does not establish vintage or report a record as verified.
    """
    value = _parse_json_object(raw, algorithm=algorithm)
    return canonical_digest(value, exclusion_set, algorithm=algorithm)


def _parse_json_object(raw: str | bytes, *, algorithm: str) -> dict[str, Any]:
    """Parse raw input after enforcing the selected algorithm's wire rules."""
    if not isinstance(raw, (str, bytes)):
        raise TypeError("canonicalization input must be raw JSON text or bytes")
    if algorithm not in {"jcs", "jcs-n"}:
        raise ValueError(f"unsupported canonicalization algorithm {algorithm!r}")
    value, violations = lex(raw)
    applicable = [
        violation
        for violation in violations
        if violation.code == "duplicate_key" or algorithm == "jcs-n"
    ]
    if applicable:
        raise JsonWireFormatError(applicable)
    if not isinstance(value, dict):
        raise TypeError(f"{algorithm} construction input must be a JSON object")
    return value
