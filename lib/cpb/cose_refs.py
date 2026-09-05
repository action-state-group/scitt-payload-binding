# SPDX-License-Identifier: BSD-3-Clause
"""Safe decoding of CPB typed references carried by COSE_Sign1.

The decoder accepts ordinary RFC 8949 CBOR, including indefinite-length and
non-preferred encodings, because CPB does not narrow COSE's serialization.
Callers may request deterministic decoding for pinned test fixtures.  Maps
remain entry pairs until duplicate checks finish, so conversion to a Python
``dict`` can never erase malformed repeated keys.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .typed_ref import TypedRef

__all__ = [
    "CborMap",
    "CborSimple",
    "CborTag",
    "CoseSign1",
    "CpbRefsError",
    "CpbRefsLocationError",
    "DuplicateCborKeyError",
    "MalformedCborError",
    "cose_signature1_structure",
    "decode_cose_sign1",
    "encode_deterministic_cbor",
    "extract_cpb_refs",
]

MAX_COSE_BYTES = 1 << 20
MAX_CBOR_ITEMS = 4096
MAX_CBOR_DEPTH = 16
MAX_REFS = 64
MAX_TYPE_BYTES = 255
MAX_PURPOSE_BYTES = 64
MAX_DIGEST_ALG_BYTES = 32
MAX_DIGEST_BYTES = 128


class CpbRefsError(ValueError):
    """Base class for malformed or non-conforming CPB carrier data."""


class MalformedCborError(CpbRefsError):
    """The input is not a well-formed supported CBOR encoding."""


class DuplicateCborKeyError(MalformedCborError):
    """A CBOR map repeats a key."""


class CpbRefsLocationError(CpbRefsError):
    """``cpb-refs`` is absent when required or occurs outside protection."""


@dataclass(frozen=True)
class CborMap:
    """Decoded CBOR map that preserves key types and insertion order."""

    pairs: tuple[tuple[Any, Any], ...]

    def get(self, key: Any, default: Any = None) -> Any:
        for candidate, value in self.pairs:
            if type(candidate) is type(key) and candidate == key:
                return value
        return default

    def __contains__(self, key: Any) -> bool:
        return any(type(candidate) is type(key) and candidate == key for candidate, _ in self.pairs)

    def keys(self) -> tuple[Any, ...]:
        return tuple(key for key, _ in self.pairs)


@dataclass(frozen=True)
class CborTag:
    tag: int
    value: Any


@dataclass(frozen=True)
class CborSimple:
    """An unassigned or undefined CBOR simple value in an extension field."""

    value: int


@dataclass(frozen=True)
class CoseSign1:
    protected_bytes: bytes
    protected: CborMap
    unprotected: CborMap
    payload: bytes | None
    signature: bytes


_BREAK = object()


def _read_argument(
    data: bytes,
    pos: int,
    additional: int,
    *,
    require_deterministic: bool,
) -> tuple[int | None, int]:
    if additional < 24:
        return additional, pos
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional == 31:
        if require_deterministic:
            raise MalformedCborError("indefinite-length CBOR is not deterministic")
        return None, pos
    width = widths.get(additional)
    if width is None:
        raise MalformedCborError(f"reserved CBOR additional-information value {additional}")
    end = pos + width
    if end > len(data):
        raise MalformedCborError("truncated CBOR argument")
    value = int.from_bytes(data[pos:end], "big")
    minimum = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[width]
    if require_deterministic and value < minimum:
        raise MalformedCborError("non-shortest CBOR integer/length encoding")
    return value, end


def _same_key(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _decode_item(
    data: bytes,
    pos: int,
    *,
    depth: int,
    budget: list[int],
    require_deterministic: bool,
    allow_break: bool = False,
) -> tuple[Any, int]:
    if depth > MAX_CBOR_DEPTH:
        raise MalformedCborError("CBOR nesting exceeds the CPB processing limit")
    budget[0] -= 1
    if budget[0] < 0:
        raise MalformedCborError("CBOR item count exceeds the CPB processing limit")
    if pos >= len(data):
        raise MalformedCborError("truncated CBOR item")

    initial = data[pos]
    pos += 1
    major = initial >> 5
    additional = initial & 0x1F
    # Simple values and floats use additional information as an opcode rather
    # than an integer argument.
    if major == 7:
        if additional < 20:
            return CborSimple(additional), pos
        if additional == 20:
            return False, pos
        if additional == 21:
            return True, pos
        if additional == 22:
            return None, pos
        if additional == 23:
            return CborSimple(23), pos
        if additional == 24:
            if pos >= len(data):
                raise MalformedCborError("truncated CBOR simple value")
            value = data[pos]
            if require_deterministic and value < 32:
                raise MalformedCborError("non-shortest CBOR simple-value encoding")
            return CborSimple(value), pos + 1
        float_widths = {25: (2, ">e"), 26: (4, ">f"), 27: (8, ">d")}
        if additional in float_widths:
            if require_deterministic:
                raise MalformedCborError(
                    "floating-point extension values are not supported in deterministic fixtures"
                )
            width, format_code = float_widths[additional]
            end = pos + width
            if end > len(data):
                raise MalformedCborError("truncated CBOR floating-point value")
            return struct.unpack(format_code, data[pos:end])[0], end
        if additional == 31:
            if allow_break:
                return _BREAK, pos
            raise MalformedCborError("unexpected CBOR break code")
        raise MalformedCborError(f"reserved CBOR simple value {additional}")

    argument, pos = _read_argument(
        data,
        pos,
        additional,
        require_deterministic=require_deterministic,
    )

    if major == 0:
        if argument is None:
            raise MalformedCborError("an integer cannot use indefinite-length encoding")
        return argument, pos
    if major == 1:
        if argument is None:
            raise MalformedCborError("an integer cannot use indefinite-length encoding")
        return -1 - argument, pos
    if major in (2, 3):
        if argument is None:
            chunks: list[bytes | str] = []
            while True:
                if pos >= len(data):
                    raise MalformedCborError("unterminated indefinite-length CBOR string")
                if data[pos] == 0xFF:
                    pos += 1
                    break
                if data[pos] >> 5 != major or data[pos] & 0x1F == 31:
                    raise MalformedCborError(
                        "indefinite-length CBOR strings require definite chunks of the same type"
                    )
                chunk, pos = _decode_item(
                    data,
                    pos,
                    depth=depth + 1,
                    budget=budget,
                    require_deterministic=require_deterministic,
                )
                chunks.append(chunk)
            if major == 2:
                return b"".join(chunks), pos
            return "".join(chunks), pos
        end = pos + argument
        if end > len(data):
            raise MalformedCborError("truncated CBOR string")
        raw = data[pos:end]
        if major == 2:
            return raw, end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise MalformedCborError("CBOR text string is not valid UTF-8") from exc
    if major == 4:
        values: list[Any] = []
        remaining = argument
        while remaining is None or remaining > 0:
            value, pos = _decode_item(
                data,
                pos,
                depth=depth + 1,
                budget=budget,
                require_deterministic=require_deterministic,
                allow_break=remaining is None,
            )
            if value is _BREAK:
                break
            values.append(value)
            if remaining is not None:
                remaining -= 1
        return values, pos
    if major == 5:
        pairs: list[tuple[Any, Any]] = []
        prior_key_encoding: bytes | None = None
        remaining = argument
        while remaining is None or remaining > 0:
            key_start = pos
            key, pos = _decode_item(
                data,
                pos,
                depth=depth + 1,
                budget=budget,
                require_deterministic=require_deterministic,
                allow_break=remaining is None,
            )
            if key is _BREAK:
                break
            key_encoding = data[key_start:pos]
            if isinstance(key, (list, CborMap, CborTag)):
                raise MalformedCborError("container-valued CBOR map keys are not permitted")
            if any(_same_key(key, prior) for prior, _ in pairs):
                raise DuplicateCborKeyError(f"duplicate CBOR map key {key!r}")
            if require_deterministic and prior_key_encoding is not None and (
                len(key_encoding), key_encoding
            ) <= (len(prior_key_encoding), prior_key_encoding):
                raise MalformedCborError("CBOR map keys are not in deterministic order")
            prior_key_encoding = key_encoding
            value, pos = _decode_item(
                data,
                pos,
                depth=depth + 1,
                budget=budget,
                require_deterministic=require_deterministic,
            )
            pairs.append((key, value))
            if remaining is not None:
                remaining -= 1
        return CborMap(tuple(pairs)), pos
    if major == 6:
        if argument is None:
            raise MalformedCborError("a tag cannot use indefinite-length encoding")
        value, pos = _decode_item(
            data,
            pos,
            depth=depth + 1,
            budget=budget,
            require_deterministic=require_deterministic,
        )
        return CborTag(argument, value), pos
    raise MalformedCborError(f"unsupported CBOR major type {major}")


def _decode_exact(data: bytes, *, require_deterministic: bool = False) -> Any:
    value, pos = _decode_item(
        data,
        0,
        depth=0,
        budget=[MAX_CBOR_ITEMS],
        require_deterministic=require_deterministic,
    )
    if pos != len(data):
        raise MalformedCborError("trailing bytes after the CBOR item")
    return value


def _head(major: int, argument: int) -> bytes:
    if argument < 0:
        raise ValueError("CBOR argument must be non-negative")
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument <= 0xFF:
        return bytes([(major << 5) | 24, argument])
    if argument <= 0xFFFF:
        return bytes([(major << 5) | 25]) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + argument.to_bytes(4, "big")
    if argument <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + argument.to_bytes(8, "big")
    raise ValueError("CBOR integer exceeds uint64")


def encode_deterministic_cbor(value: Any) -> bytes:
    """Encode the definite-length CBOR types used by CPB and COSE fixtures."""

    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode_deterministic_cbor(item) for item in value)
    if isinstance(value, CborTag):
        return _head(6, value.tag) + encode_deterministic_cbor(value.value)
    if isinstance(value, CborMap):
        pairs = list(value.pairs)
    elif isinstance(value, dict):
        pairs = list(value.items())
    else:
        raise TypeError(f"cannot encode {type(value).__name__} as CPB CBOR")

    encoded_pairs: list[tuple[bytes, bytes]] = []
    seen: list[Any] = []
    for key, item in pairs:
        if any(_same_key(key, prior) for prior in seen):
            raise DuplicateCborKeyError(f"duplicate CBOR map key {key!r}")
        seen.append(key)
        encoded_pairs.append((encode_deterministic_cbor(key), encode_deterministic_cbor(item)))
    encoded_pairs.sort(key=lambda pair: (len(pair[0]), pair[0]))
    return _head(5, len(encoded_pairs)) + b"".join(k + v for k, v in encoded_pairs)


def decode_cose_sign1(
    encoded: bytes,
    *,
    require_deterministic: bool = False,
) -> CoseSign1:
    """Decode a tagged COSE_Sign1 and its protected header safely.

    CPB itself accepts RFC 8949 CBOR serialization.  Set
    ``require_deterministic`` only for byte-pinned reproducibility fixtures;
    it rejects indefinite lengths, non-preferred arguments, and map-key order
    that differs from deterministic encoding.
    """

    if len(encoded) > MAX_COSE_BYTES:
        raise MalformedCborError("COSE_Sign1 exceeds the CPB processing limit")
    outer = _decode_exact(encoded, require_deterministic=require_deterministic)
    if not isinstance(outer, CborTag) or outer.tag != 18:
        raise MalformedCborError("Signed Statement must use CBOR tag 18 (COSE_Sign1)")
    if not isinstance(outer.value, list) or len(outer.value) != 4:
        raise MalformedCborError("COSE_Sign1 must be a four-element array")
    protected_bytes, unprotected, payload, signature = outer.value
    if not isinstance(protected_bytes, bytes):
        raise MalformedCborError("COSE_Sign1 protected header must be a byte string")
    if not isinstance(unprotected, CborMap):
        raise MalformedCborError("COSE_Sign1 unprotected header must be a map")
    if payload is not None and not isinstance(payload, bytes):
        raise MalformedCborError("COSE_Sign1 payload must be a byte string or nil")
    if not isinstance(signature, bytes):
        raise MalformedCborError("COSE_Sign1 signature must be a byte string")
    # RFC 9052 permits a zero-length protected bstr as the compact encoding
    # of an empty protected map.
    protected = (
        CborMap(())
        if protected_bytes == b""
        else _decode_exact(
            protected_bytes,
            require_deterministic=require_deterministic,
        )
    )
    if not isinstance(protected, CborMap):
        raise MalformedCborError("decoded protected header must be a map")
    return CoseSign1(protected_bytes, protected, unprotected, payload, signature)


def _nonempty_text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value:
        raise CpbRefsError(f"typed reference {name} must be a non-empty text string")
    if len(value.encode("utf-8")) > maximum:
        raise CpbRefsError(f"typed reference {name} exceeds {maximum} UTF-8 bytes")
    return value


def _validate_reference_map(item: Any) -> TypedRef:
    if not isinstance(item, CborMap):
        raise CpbRefsError("each cpb-refs array element must be a CBOR map")
    keys = item.keys()
    if any(type(key) is not int for key in keys):
        raise CpbRefsError("cpb-refs member keys must be integers")
    unknown = set(keys) - {1, 2, 3, 4}
    if unknown:
        raise CpbRefsError(f"unknown cpb-refs member key(s): {sorted(unknown)!r}")
    missing = {1, 3, 4} - set(keys)
    if missing:
        raise CpbRefsError(f"cpb-refs entry missing required member key(s): {sorted(missing)!r}")

    artifact_type = _nonempty_text(item.get(1), "type", MAX_TYPE_BYTES)
    purpose = (
        _nonempty_text(item.get(2), "purpose", MAX_PURPOSE_BYTES)
        if 2 in item
        else None
    )
    digest_alg = _nonempty_text(item.get(3), "digest_alg", MAX_DIGEST_ALG_BYTES)
    digest = item.get(4)
    if not isinstance(digest, (str, bytes)) or isinstance(digest, bool) or len(digest) == 0:
        raise CpbRefsError("typed reference digest must be a non-empty text or byte string")
    digest_length = len(digest.encode("utf-8")) if isinstance(digest, str) else len(digest)
    if digest_length > MAX_DIGEST_BYTES:
        raise CpbRefsError(f"typed reference digest exceeds {MAX_DIGEST_BYTES} bytes")
    return TypedRef(type=artifact_type, purpose=purpose, digest_alg=digest_alg, digest=digest)


def extract_cpb_refs(
    encoded: bytes,
    label: int | str,
    *,
    required: bool = False,
    require_critical: bool = False,
    require_deterministic: bool = False,
) -> list[TypedRef]:
    """Extract and validate the protected ``cpb-refs`` value.

    This validates carrier syntax and location.  It does not validate the COSE
    signature or verify the cited artifacts; callers perform those independent
    operations before reporting signature-valid or verified states.
    """

    cose = decode_cose_sign1(
        encoded,
        require_deterministic=require_deterministic,
    )
    if label in cose.unprotected:
        raise CpbRefsLocationError("cpb-refs MUST NOT occur in the unprotected header")
    if label not in cose.protected:
        if required:
            raise CpbRefsLocationError("required cpb-refs protected header is absent")
        return []
    value = cose.protected.get(label)

    critical = cose.protected.get(2)
    if critical is not None:
        if not isinstance(critical, list) or not critical:
            raise CpbRefsError("crit must be a non-empty array when present")
        if any(not isinstance(item, (int, str)) for item in critical):
            raise CpbRefsError("crit entries must be COSE header labels")
    if require_critical and (not isinstance(critical, list) or label not in critical):
        raise CpbRefsError("cpb-refs must be listed in crit for this profile")

    if not isinstance(value, list) or not value:
        raise CpbRefsError("cpb-refs must be a non-empty array")
    if len(value) > MAX_REFS:
        raise CpbRefsError(f"cpb-refs exceeds the {MAX_REFS}-reference processing limit")

    refs = [_validate_reference_map(item) for item in value]
    seen: set[tuple[str, str | None, str, str, str | bytes]] = set()
    for ref in refs:
        digest_kind = "text" if isinstance(ref.digest, str) else "bytes"
        identity = (ref.type, ref.purpose, ref.digest_alg, digest_kind, ref.digest)
        if identity in seen:
            raise CpbRefsError("cpb-refs repeats the same typed digest reference")
        seen.add(identity)
    return refs


def cose_signature1_structure(
    cose: CoseSign1,
    *,
    external_aad: bytes = b"",
    detached_payload: bytes | None = None,
) -> bytes:
    """Return RFC 9052's deterministic ``Sig_structure`` bytes for Sign1."""

    payload = cose.payload if cose.payload is not None else detached_payload
    if payload is None:
        raise CpbRefsError("a detached COSE_Sign1 requires detached_payload")
    return encode_deterministic_cbor(["Signature1", cose.protected_bytes, external_aad, payload])
