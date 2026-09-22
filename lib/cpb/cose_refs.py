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
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv6Address
from typing import Any, Literal
from urllib.parse import urlsplit

from .typed_ref import TypedRef

__all__ = [
    "FULL_CONTENT_MODE",
    "HASH_ENVELOPE_MODE",
    "CborMap",
    "CborSimple",
    "CborTag",
    "CoseHeaderError",
    "CoseSign1",
    "CpbRefsError",
    "CpbRefsLocationError",
    "CriticalHeaderError",
    "DuplicateCborKeyError",
    "MalformedCborError",
    "SignedStatementError",
    "StatementMode",
    "cose_signature1_structure",
    "decode_cose_sign1",
    "encode_deterministic_cbor",
    "extract_cpb_refs",
    "validate_cose_headers",
    "validate_cpb_signed_statement",
    "validate_cpb_statement_mode",
    "validate_critical_headers",
    "validate_rfc9943_baseline",
]

MAX_COSE_BYTES = 1 << 20
MAX_CBOR_ITEMS = 4096
MAX_CBOR_DEPTH = 16
MAX_REFS = 64
MAX_TYPE_BYTES = 255
MAX_PURPOSE_BYTES = 64
MAX_DIGEST_ALG_BYTES = 32
MAX_DIGEST_BYTES = 128

FULL_CONTENT_MODE = "rfc9943-full-content"
HASH_ENVELOPE_MODE = "rfc9995-hash-envelope"
StatementMode = Literal["rfc9943-full-content", "rfc9995-hash-envelope"]

COSE_CRIT = 2
COSE_ALG = 1
COSE_CONTENT_TYPE = 3
COSE_KID = 4
COSE_CWT_CLAIMS = 15
COSE_X5CHAIN = 33
COSE_X5T = 34
COSE_PAYLOAD_HASH_ALG = 258
COSE_PREIMAGE_CONTENT_TYPE = 259
COSE_PAYLOAD_LOCATION = 260


class CpbRefsError(ValueError):
    """Base class for malformed or non-conforming CPB carrier data."""


class MalformedCborError(CpbRefsError):
    """The input is not a well-formed supported CBOR encoding."""


class DuplicateCborKeyError(MalformedCborError):
    """A CBOR map repeats a key."""


class CpbRefsLocationError(CpbRefsError):
    """``cpb-refs`` is absent when required or occurs outside protection."""


class CoseHeaderError(CpbRefsError):
    """A COSE header bucket violates the requirements applied by CPB."""


class CriticalHeaderError(CoseHeaderError):
    """The RFC 9052 ``crit`` header cannot be processed safely."""


class SignedStatementError(CpbRefsError):
    """A CPB Signed Statement violates its RFC 9943 or RFC 9995 mode."""


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


def _is_label(value: Any) -> bool:
    """Return whether *value* is a COSE label (and not a CBOR boolean)."""

    return type(value) is int or isinstance(value, str)


def _validate_label_map(value: CborMap, name: str) -> None:
    """Validate label types and uniqueness even for hand-built ``CborMap``s."""

    seen: list[Any] = []
    for label, _ in value.pairs:
        if not _is_label(label):
            raise CoseHeaderError(
                f"{name} contains non-COSE header label {label!r}; labels must be integers or text strings"
            )
        if any(_same_key(label, prior) for prior in seen):
            raise DuplicateCborKeyError(f"duplicate CBOR map key {label!r} in {name}")
        seen.append(label)


def validate_cose_headers(cose: CoseSign1) -> tuple[int | str, ...]:
    """Validate COSE header buckets and return the protected ``crit`` labels.

    RFC 9052 requires labels to be unique within each bucket, places ``crit``
    only in the protected bucket, requires a non-empty array of labels, and
    makes a critical label absent from the protected bucket a fatal error.
    CPB additionally rejects a label repeated across the two buckets rather
    than applying RFC 9052's protected-bucket precedence rule.

    This function validates ``crit`` structure and referential integrity.  Use
    :func:`validate_critical_headers` when the caller is also ready to assert
    which critical labels it actually understands and processed.
    """

    _validate_label_map(cose.protected, "protected header")
    _validate_label_map(cose.unprotected, "unprotected header")

    for label, _ in cose.protected.pairs:
        if label in cose.unprotected:
            raise CoseHeaderError(
                f"COSE header label {label!r} occurs in both protected and unprotected buckets"
            )

    if COSE_CRIT in cose.unprotected:
        raise CriticalHeaderError("crit (label 2) MUST occur only in the protected header")
    if COSE_CRIT not in cose.protected:
        return ()

    critical = cose.protected.get(COSE_CRIT)
    if not isinstance(critical, list) or not critical:
        raise CriticalHeaderError("crit must be a non-empty array")

    seen: list[Any] = []
    for label in critical:
        if not _is_label(label):
            raise CriticalHeaderError(
                f"crit entry {label!r} is not a COSE header label"
            )
        if any(_same_key(label, prior) for prior in seen):
            raise CriticalHeaderError(f"crit repeats header label {label!r}")
        seen.append(label)
        if label not in cose.protected:
            raise CriticalHeaderError(
                f"crit names header label {label!r}, but that label is absent from the protected header"
            )
    return tuple(critical)


def validate_critical_headers(
    cose: CoseSign1,
    *,
    understood_labels: Iterable[int | str] = (),
) -> tuple[int | str, ...]:
    """Enforce RFC 9052 critical-header processing for this application.

    ``understood_labels`` is the set of labels the caller has actually
    processed.  A present critical label outside that set is fatal; merely
    preserving an unknown value is not sufficient under RFC 9052.
    """

    understood = tuple(understood_labels)
    for label in understood:
        if not _is_label(label):
            raise TypeError("understood critical labels must be integers or text strings")

    critical = validate_cose_headers(cose)
    for label in critical:
        if not any(_same_key(label, known) for known in understood):
            raise CriticalHeaderError(
                f"critical header label {label!r} was not declared understood and processed"
            )
    return critical


_MEDIA_TYPE_NAME_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&-^_.+"
)


def _is_media_type_name(value: str) -> bool:
    """Apply RFC 6838 Section 4.2's ``restricted-name`` production."""

    return (
        1 <= len(value) <= 127
        and value[0].isascii()
        and value[0].isalnum()
        and all(character in _MEDIA_TYPE_NAME_CHARS for character in value)
    )


def _require_content_type(value: Any, name: str) -> None:
    """Validate RFC 9052 content-format integers or media-type strings."""

    if isinstance(value, str):
        type_name, separator, subtype_name = value.partition("/")
        if (
            not separator
            or "/" in subtype_name
            or not _is_media_type_name(type_name)
            or not _is_media_type_name(subtype_name)
        ):
            raise SignedStatementError(
                f"{name} text value must use RFC 6838 type-name/subtype-name syntax "
                "without leading or trailing whitespace"
            )
        return
    if type(value) is int and value >= 0:
        return
    raise SignedStatementError(f"{name} must be an unsigned integer or text string")


_URI_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_URI_SUB_DELIMS = frozenset("!$&'()*+,;=")
_URI_HEXDIG = frozenset("0123456789ABCDEFabcdef")
_URI_PCHAR = _URI_UNRESERVED | _URI_SUB_DELIMS | frozenset(":@")


def _valid_uri_component(value: str, allowed: frozenset[str]) -> bool:
    """Validate an RFC 3986 component, including percent-encoding syntax."""

    offset = 0
    while offset < len(value):
        character = value[offset]
        if character == "%":
            if (
                offset + 2 >= len(value)
                or value[offset + 1] not in _URI_HEXDIG
                or value[offset + 2] not in _URI_HEXDIG
            ):
                return False
            offset += 3
            continue
        if character not in allowed:
            return False
        offset += 1
    return True


def _valid_uri_authority(authority: str) -> bool:
    """Validate the authority production of an RFC 3986 URI."""

    if "@" in authority:
        if authority.count("@") != 1:
            return False
        userinfo, host_and_port = authority.rsplit("@", 1)
        if not _valid_uri_component(
            userinfo,
            _URI_UNRESERVED | _URI_SUB_DELIMS | frozenset(":"),
        ):
            return False
    else:
        host_and_port = authority

    if host_and_port.startswith("["):
        closing_bracket = host_and_port.find("]")
        if closing_bracket < 0:
            return False
        literal = host_and_port[1:closing_bracket]
        remainder = host_and_port[closing_bracket + 1 :]
        if remainder and (
            not remainder.startswith(":")
            or (
                remainder[1:]
                and any(character not in "0123456789" for character in remainder[1:])
            )
        ):
            return False
        if literal[:1].lower() == "v":
            version, separator, address = literal[1:].partition(".")
            if (
                not separator
                or not version
                or any(character not in _URI_HEXDIG for character in version)
                or not address
                or not _valid_uri_component(
                    address,
                    _URI_UNRESERVED | _URI_SUB_DELIMS | frozenset(":"),
                )
            ):
                return False
        else:
            try:
                IPv6Address(literal)
            except ValueError:
                return False
        return True

    if ":" in host_and_port:
        host, port = host_and_port.rsplit(":", 1)
        if ":" in host or (
            port and any(character not in "0123456789" for character in port)
        ):
            return False
    else:
        host = host_and_port
    return _valid_uri_component(host, _URI_UNRESERVED | _URI_SUB_DELIMS)


def _is_rfc3986_uri(value: str) -> bool:
    """Return whether *value* has the generic URI syntax from RFC 3986."""

    if any(
        not character.isascii() or ord(character) <= 0x20 or ord(character) == 0x7F
        for character in value
    ):
        return False
    scheme, separator, _ = value.partition(":")
    if (
        not separator
        or not scheme
        or not scheme[0].isalpha()
        or not scheme[0].isascii()
        or any(
            not (
                character.isascii()
                and (character.isalnum() or character in "+-.")
            )
            for character in scheme[1:]
        )
    ):
        return False

    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if not parsed.scheme:
        return False
    if not _valid_uri_component(parsed.path, _URI_PCHAR | frozenset("/")):
        return False
    if not _valid_uri_component(
        parsed.query,
        _URI_PCHAR | frozenset("/?"),
    ):
        return False
    if not _valid_uri_component(
        parsed.fragment,
        _URI_PCHAR | frozenset("/?"),
    ):
        return False
    return _valid_uri_authority(parsed.netloc)


def _is_rfc8392_string_or_uri(value: str) -> bool:
    """Apply RFC 8392's RFC 7519 StringOrURI rule."""

    return ":" not in value or _is_rfc3986_uri(value)


def _validate_x5t(value: Any, location: str) -> None:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or not _is_label(value[0])
        or not isinstance(value[1], bytes)
    ):
        raise SignedStatementError(
            f"{location} x5t (label 34) must be "
            "[integer-or-text hash algorithm, byte-string hash]"
        )


def _validate_x5chain(value: Any, location: str) -> None:
    if isinstance(value, bytes):
        return
    if (
        not isinstance(value, list)
        or len(value) < 2
        or any(not isinstance(certificate, bytes) for certificate in value)
    ):
        raise SignedStatementError(
            f"{location} x5chain (label 33) must be one certificate byte string "
            "or an array of at least two byte strings"
        )


def _validate_x509_parameters(cose: CoseSign1) -> bool:
    """Validate RFC 9360 value types and report protected X.509 identity."""

    for location, bucket in (
        ("protected", cose.protected),
        ("unprotected", cose.unprotected),
    ):
        if COSE_X5T in bucket:
            _validate_x5t(bucket.get(COSE_X5T), location)
        if COSE_X5CHAIN in bucket:
            _validate_x5chain(bucket.get(COSE_X5CHAIN), location)
    return COSE_X5T in cose.protected or COSE_X5CHAIN in cose.protected


def validate_rfc9943_baseline(cose: CoseSign1) -> None:
    """Validate RFC 9943's mandatory Signed Statement protected metadata.

    The CWT Claims protected header (15) must contain RFC 8392 StringOrURI
    ``iss`` (1) and ``sub`` (2) claims.  An issuer used with a protected
    ``x5t`` or ``x5chain`` is additionally constrained to 1..8192 characters.
    When neither X.509 parameter is protected, RFC 9943 requires a protected
    byte-string ``kid``.

    This function checks message syntax and credential carriage only.  It does
    not parse certificates, match an unprotected chain's leaf to ``x5t`` or
    ``kid``, build a certification path, or make a cryptographic trust decision.
    """

    if COSE_ALG in cose.protected and type(cose.protected.get(COSE_ALG)) is not int:
        raise SignedStatementError(
            "RFC 9943 protected alg (label 1) must be an integer"
        )
    if COSE_CWT_CLAIMS not in cose.protected:
        raise SignedStatementError(
            "RFC 9943 Signed Statement requires CWT Claims (label 15) in the protected header"
        )
    claims = cose.protected.get(COSE_CWT_CLAIMS)
    if not isinstance(claims, CborMap):
        raise SignedStatementError("CWT Claims (label 15) must be a CBOR map")
    _validate_label_map(claims, "CWT Claims")
    for claim_label, claim_name in ((1, "iss"), (2, "sub")):
        claim_value = claims.get(claim_label)
        if claim_label not in claims or not isinstance(claim_value, str):
            raise SignedStatementError(
                f"CWT Claims must contain text {claim_name} (claim label {claim_label})"
            )
        if not _is_rfc8392_string_or_uri(claim_value):
            raise SignedStatementError(
                f"CWT {claim_name} (claim label {claim_label}) must satisfy "
                "RFC 8392 StringOrURI syntax"
            )

    if COSE_KID in cose.protected and not isinstance(cose.protected.get(COSE_KID), bytes):
        raise SignedStatementError("protected kid (label 4) must be a byte string")
    has_protected_certificate = _validate_x509_parameters(cose)
    if has_protected_certificate:
        issuer = claims.get(1)
        if not 1 <= len(issuer) <= 8192:
            raise SignedStatementError(
                "CWT iss must contain 1..8192 characters when protected x5t or x5chain is present"
            )
    if (
        COSE_X5CHAIN in cose.unprotected
        and COSE_X5T not in cose.protected
        and COSE_KID not in cose.protected
    ):
        raise SignedStatementError(
            "unprotected x5chain requires protected x5t or protected kid to identify its leaf certificate"
        )
    if not has_protected_certificate and COSE_KID not in cose.protected:
        raise SignedStatementError(
            "RFC 9943 requires protected kid when neither x5t nor x5chain is protected"
        )


def _effective_payload(
    cose: CoseSign1,
    detached_payload: bytes | None,
) -> bytes | None:
    if detached_payload is not None and not isinstance(detached_payload, bytes):
        raise TypeError("detached_payload must be bytes when supplied")
    if cose.payload is not None:
        if detached_payload is not None:
            raise SignedStatementError(
                "detached_payload must not be supplied when COSE_Sign1 carries an attached payload"
            )
        return cose.payload
    return detached_payload


def validate_cpb_statement_mode(
    cose: CoseSign1,
    mode: StatementMode,
    *,
    detached_payload: bytes | None = None,
    expected_payload_hash_alg: int | None = None,
    expected_hash_size: int | None = None,
) -> None:
    """Validate the mutually exclusive CPB full-content and hash modes.

    ``expected_payload_hash_alg`` and ``expected_hash_size`` bind Hash Envelope
    syntax to the selected CPB canonicalization-algorithm entry.  Structural
    validation remains possible without the preimage, including for a detached
    payload that has not yet been obtained.  The caller must separately obtain
    and canonicalize the preimage and compare its hash with the effective
    payload before reporting a verified content binding.
    """

    payload = _effective_payload(cose, detached_payload)
    if expected_payload_hash_alg is not None and type(expected_payload_hash_alg) is not int:
        raise TypeError("expected_payload_hash_alg must be an integer")
    if expected_hash_size is not None and (
        type(expected_hash_size) is not int or expected_hash_size <= 0
    ):
        raise ValueError("expected_hash_size must be a positive integer")

    if mode == FULL_CONTENT_MODE:
        for label in (
            COSE_PAYLOAD_HASH_ALG,
            COSE_PREIMAGE_CONTENT_TYPE,
            COSE_PAYLOAD_LOCATION,
        ):
            if label in cose.protected or label in cose.unprotected:
                raise SignedStatementError(
                    f"RFC 9995 header label {label} MUST NOT appear in Full-Content Mode"
                )
        if COSE_CONTENT_TYPE not in cose.protected:
            raise SignedStatementError(
                "Full-Content Mode requires content_type (label 3) in the protected header"
            )
        if COSE_CONTENT_TYPE in cose.unprotected:
            raise SignedStatementError(
                "Full-Content Mode content_type (label 3) MUST NOT be unprotected"
            )
        _require_content_type(
            cose.protected.get(COSE_CONTENT_TYPE),
            "content_type (label 3)",
        )
        return

    if mode != HASH_ENVELOPE_MODE:
        raise ValueError(
            f"unknown CPB Signed Statement mode {mode!r}; expected "
            f"{FULL_CONTENT_MODE!r} or {HASH_ENVELOPE_MODE!r}"
        )

    if COSE_CONTENT_TYPE in cose.protected or COSE_CONTENT_TYPE in cose.unprotected:
        raise SignedStatementError(
            "RFC 9995 Hash Envelope Mode forbids content_type (label 3) in both header buckets"
        )
    for label in (
        COSE_PAYLOAD_HASH_ALG,
        COSE_PREIMAGE_CONTENT_TYPE,
        COSE_PAYLOAD_LOCATION,
    ):
        if label in cose.unprotected:
            raise SignedStatementError(
                f"RFC 9995 header label {label} MUST NOT appear in the unprotected header"
            )

    if COSE_PAYLOAD_HASH_ALG not in cose.protected:
        raise SignedStatementError(
            "Hash Envelope Mode requires payload-hash-alg (label 258) in the protected header"
        )
    payload_hash_alg = cose.protected.get(COSE_PAYLOAD_HASH_ALG)
    if type(payload_hash_alg) is not int:
        raise SignedStatementError("payload-hash-alg (label 258) must be an integer")
    if (
        expected_payload_hash_alg is not None
        and payload_hash_alg != expected_payload_hash_alg
    ):
        raise SignedStatementError(
            f"payload-hash-alg {payload_hash_alg!r} does not match the selected CPB context's "
            f"COSE hash algorithm {expected_payload_hash_alg!r}"
        )

    # RFC 9995 makes 259 optional; CPB Hash Envelope Mode strengthens it to
    # mandatory so the exact canonical preimage media type is identified.
    if COSE_PREIMAGE_CONTENT_TYPE not in cose.protected:
        raise SignedStatementError(
            "CPB Hash Envelope Mode requires preimage-content-type (label 259) in the protected header"
        )
    _require_content_type(
        cose.protected.get(COSE_PREIMAGE_CONTENT_TYPE),
        "preimage-content-type (label 259)",
    )
    if (
        COSE_PAYLOAD_LOCATION in cose.protected
        and not isinstance(cose.protected.get(COSE_PAYLOAD_LOCATION), str)
    ):
        raise SignedStatementError("payload-location (label 260) must be a text string")

    if payload is not None:
        if not payload:
            raise SignedStatementError("Hash Envelope payload digest must not be empty")
        if expected_hash_size is not None and len(payload) != expected_hash_size:
            raise SignedStatementError(
                f"Hash Envelope payload is {len(payload)} bytes; selected context requires "
                f"{expected_hash_size} bytes"
            )


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


def _extract_cpb_refs_from_cose(
    cose: CoseSign1,
    label: int | str,
    *,
    required: bool = False,
    require_critical: bool = False,
    critical: tuple[int | str, ...] = (),
) -> list[TypedRef]:
    if label in cose.unprotected:
        raise CpbRefsLocationError("cpb-refs MUST NOT occur in the unprotected header")
    if label not in cose.protected:
        if required:
            raise CpbRefsLocationError("required cpb-refs protected header is absent")
        return []
    value = cose.protected.get(label)
    if require_critical and not any(_same_key(label, item) for item in critical):
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


def extract_cpb_refs(
    encoded: bytes,
    label: int | str,
    *,
    required: bool = False,
    require_critical: bool = False,
    require_deterministic: bool = False,
    understood_critical_labels: Iterable[int | str] = (),
) -> list[TypedRef]:
    """Extract and validate the protected ``cpb-refs`` value.

    RFC 9052 header and ``crit`` processing is performed before carrier
    extraction.  The CPB label is understood by this function; callers must
    name any additional critical labels they have processed through
    ``understood_critical_labels``.

    This function does not apply the RFC 9943 baseline, select a statement
    mode, validate the COSE signature, or verify cited artifacts.  Use
    :func:`validate_cpb_signed_statement` for the complete structural CPB
    envelope checks, and perform cryptographic and reference verification as
    independent operations.
    """

    if not _is_label(label):
        raise TypeError("cpb-refs label must be an integer or text string")
    cose = decode_cose_sign1(
        encoded,
        require_deterministic=require_deterministic,
    )
    # Preserve the specific CPB location error even when the same label also
    # appears in the protected bucket (which is independently a bucket clash).
    if label in cose.unprotected:
        raise CpbRefsLocationError("cpb-refs MUST NOT occur in the unprotected header")
    understood = (label, *tuple(understood_critical_labels))
    critical = validate_critical_headers(cose, understood_labels=understood)
    return _extract_cpb_refs_from_cose(
        cose,
        label,
        required=required,
        require_critical=require_critical,
        critical=critical,
    )


def validate_cpb_signed_statement(
    cose: CoseSign1,
    cpb_refs_label: int | str,
    *,
    mode: StatementMode,
    cpb_refs_required: bool = False,
    cpb_refs_critical: bool = False,
    understood_critical_labels: Iterable[int | str] = (),
    detached_payload: bytes | None = None,
    expected_payload_hash_alg: int | None = None,
    expected_hash_size: int | None = None,
) -> list[TypedRef]:
    """Validate a decoded CPB Signed Statement and return its typed references.

    The function composes RFC 9052 header/critical processing, RFC 9943's
    mandatory protected metadata, the selected CPB Full-Content or RFC 9995
    Hash Envelope mode, and the closed protected ``cpb-refs`` carrier.  It does
    not verify the COSE signature, a Hash Envelope preimage, or cited artifact
    digests.
    """

    if not _is_label(cpb_refs_label):
        raise TypeError("cpb-refs label must be an integer or text string")
    if cpb_refs_label in cose.unprotected:
        raise CpbRefsLocationError("cpb-refs MUST NOT occur in the unprotected header")

    # These labels are interpreted by the validations below.  A signature
    # implementation must explicitly add any other critical labels it handled,
    # such as ``alg``, via understood_critical_labels.
    understood = (
        cpb_refs_label,
        COSE_CRIT,
        COSE_CONTENT_TYPE,
        COSE_CWT_CLAIMS,
        COSE_PAYLOAD_HASH_ALG,
        COSE_PREIMAGE_CONTENT_TYPE,
        COSE_PAYLOAD_LOCATION,
        *tuple(understood_critical_labels),
    )
    critical = validate_critical_headers(cose, understood_labels=understood)
    validate_rfc9943_baseline(cose)
    validate_cpb_statement_mode(
        cose,
        mode,
        detached_payload=detached_payload,
        expected_payload_hash_alg=expected_payload_hash_alg,
        expected_hash_size=expected_hash_size,
    )
    return _extract_cpb_refs_from_cose(
        cose,
        cpb_refs_label,
        required=cpb_refs_required,
        require_critical=cpb_refs_critical,
        critical=critical,
    )


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
