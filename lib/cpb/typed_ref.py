# SPDX-License-Identifier: BSD-3-Clause
"""Typed digest reference: construction and verification.

Reference: draft-mih-sokolov-scitt-payload-binding-00 §6
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonicalize import canonical_digest

__all__ = [
    "TypedRef",
    "ArtifactTypeRegistryEntry",
    "TypedRefError",
    "ContextMismatchError",
    "RepresentationMismatchError",
    "DigestAlgorithmMismatchError",
    "make_typed_ref",
    "verify_typed_ref",
    "hex_to_raw",
    "raw_to_hex",
]

_BARE_HEX_CHARS = frozenset("0123456789abcdef")

# The hash algorithm implied by each canonicalization algorithm's registry
# entry (REGISTRY.md §Payload Canonicalization Algorithm Registry). jcs-n is
# defined as "JCS + absent-field normalization; SHA-256; lowercase hex
# output" -- SHA-256 is fixed by the algorithm, not chosen per-reference.
_ALGORITHM_DIGEST_ALG: dict[str, str] = {
    "jcs-n": "SHA-256",
}


def hex_to_raw(digest_hex: str) -> bytes:
    """Convert a 64-char lowercase hex digest to its 32 raw octets (§4.1).

    This is the ONLY sanctioned way to obtain the raw-octet representation
    from the hex representation. §6.1 (Leaf Construction): the raw bytes
    are ``bytes.fromhex(D)``, never ``D.encode("utf-8")`` -- the two are
    different byte sequences of different lengths (32 vs 64 bytes) and MUST
    NOT be substituted for one another.
    """
    return bytes.fromhex(digest_hex)


def raw_to_hex(digest_raw: bytes) -> str:
    """Convert 32 raw digest octets to their 64-char lowercase hex string (§4.1).

    This is the ONLY sanctioned way to obtain the hex representation from the
    raw-octet representation.
    """
    return digest_raw.hex()


class TypedRefError(ValueError):
    """Base class for typed reference verification failures."""


class ContextMismatchError(TypedRefError):
    """Recomputed digest does not match the carried digest (§6.1)."""

    def __init__(self, carried: str | bytes, recomputed: str, artifact_type: str) -> None:
        self.carried = carried
        self.recomputed = recomputed
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: recomputed digest "
            f"{recomputed!r} does not match carried digest {carried!r}"
        )


class RepresentationMismatchError(TypedRefError):
    """The carried identifier is inconsistent with the declared representation (§6.1).

    The spec (§4.1): "Representations are distinct and not interchangeable."
    This error is raised when the carried digest does not conform to the
    representation declared in the artifact type registry entry -- including
    when a raw-octet (``bytes``) representation is declared but a hex
    ``str`` is carried instead (or vice versa): the raw-octet and hex
    representations are never implicitly interchangeable, even when one is
    the byte-for-byte decoding of the other.
    """

    def __init__(self, carried: object, expected_repr: str, artifact_type: str) -> None:
        self.carried = carried
        self.expected_repr = expected_repr
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: carried identifier {carried!r} "
            f"is not in the declared representation {expected_repr!r}"
        )


class DigestAlgorithmMismatchError(TypedRefError):
    """The reference's digest_alg does not name the hash algorithm actually
    used by the referenced artifact type's canonicalization algorithm (§6).

    §6 defines ``digest_alg`` as "the hash algorithm of the digest value";
    the canonicalization CONTEXT is always resolved from the artifact-type
    registry entry, never from ``digest_alg`` -- but the field still makes a
    factual claim about which hash algorithm produced the carried digest.
    A reference that mislabels this (e.g. a jcs-n/SHA-256 artifact cited
    with ``digest_alg: "SHA-512"``) is internally inconsistent and MUST NOT
    be silently recomputed and compared as though the label were correct.
    """

    def __init__(self, declared: str, expected: str, artifact_type: str) -> None:
        self.declared = declared
        self.expected = expected
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: declared digest_alg "
            f"{declared!r} does not match {expected!r}, the hash algorithm "
            f"used by this artifact type's registered canonicalization algorithm"
        )


@dataclass(frozen=True)
class ArtifactTypeRegistryEntry:
    """An entry in the Artifact Type Registry (§11.2 / REGISTRY.md).

    name:
        The artifact type name (the 'type' field value).
    algorithm:
        The canonicalization algorithm from the Algorithm Registry (§11.1).
        Currently the only registered value is 'jcs-n'.
    exclusion_set:
        The fields excluded from the canonical form before the derived
        identifier is computed (§4).
    representation:
        The representation of the output digest. Must be one of:
        'bare_hex' — 64-character lowercase hexadecimal (default for jcs-n);
        'prefixed' — 'sha256:' followed by 64-char lowercase hex;
        'raw' — 32 raw bytes.
        These are distinct and not interchangeable (§4.1).
    """

    name: str
    algorithm: str = "jcs-n"
    exclusion_set: frozenset[str] = field(default_factory=frozenset)
    representation: str = "bare_hex"

    def __post_init__(self) -> None:
        if self.algorithm != "jcs-n":
            raise ValueError(
                f"unsupported algorithm {self.algorithm!r}; only 'jcs-n' is "
                "defined in this revision of the spec"
            )
        if self.representation not in ("bare_hex", "prefixed", "raw"):
            raise ValueError(
                f"unknown representation {self.representation!r}; "
                "must be 'bare_hex', 'prefixed', or 'raw'"
            )


@dataclass(frozen=True)
class TypedRef:
    """A typed digest reference (§6).

    Fields match the spec-defined JSON object:
        type       — artifact type, from Artifact Type Registry
        digest_alg — hash algorithm of the digest value (e.g., 'SHA-256')
        digest     — digest of the cited artifact, in its declared representation.
                     A ``str`` for the 'bare_hex'/'prefixed' representations;
                     a ``bytes`` object of 32 octets for 'raw' (§4.1 — raw
                     octets and hex are distinct representations, never
                     implicitly interchangeable).
    """

    type: str
    digest_alg: str
    digest: str | bytes

    def as_dict(self) -> dict[str, str]:
        """Render as a JSON-serializable dict. Only valid for str-typed
        (hex/prefixed) digests -- JSON has no native byte-string type, so a
        'raw' (bytes) TypedRef has no JSON rendering; convert with
        ``raw_to_hex`` first if one is needed."""
        if not isinstance(self.digest, str):
            raise TypeError(
                f"as_dict() requires a str-typed digest (raw bytes has no JSON "
                f"encoding); got {type(self.digest).__name__}; convert with "
                f"raw_to_hex() first"
            )
        return {"type": self.type, "digest_alg": self.digest_alg, "digest": self.digest}


def _check_representation(digest: str | bytes, representation: str, artifact_type: str) -> None:
    """Raise RepresentationMismatchError if digest does not match the declared representation.

    §4.1 declares raw octets, lowercase hex, and prefixed hex as distinct,
    non-interchangeable representations. This is enforced at the Python type
    level, not just the string grammar: 'bare_hex' and 'prefixed' require a
    ``str``; 'raw' requires an actual ``bytes`` object of 32 octets. A hex
    ``str`` -- even one that is the exact hex encoding of the correct raw
    bytes -- is REJECTED where 'raw' is declared, and a ``bytes`` object is
    REJECTED where 'bare_hex'/'prefixed' (str-typed) representations are
    declared. Converting between the two requires the explicit
    ``hex_to_raw``/``raw_to_hex`` functions; there is no implicit path.
    """
    if representation == "bare_hex":
        if not isinstance(digest, str) or len(digest) != 64 or not all(c in _BARE_HEX_CHARS for c in digest):
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="bare_hex (64-char lowercase hex str)",
                artifact_type=artifact_type,
            )
    elif representation == "prefixed":
        if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 7 + 64:
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="prefixed ('sha256:' + 64-char lowercase hex str)",
                artifact_type=artifact_type,
            )
    elif representation == "raw":
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="raw (32 raw octets, as a bytes object -- not a hex str)",
                artifact_type=artifact_type,
            )


def make_typed_ref(
    artifact_payload: dict[str, Any],
    registry_entry: ArtifactTypeRegistryEntry,
) -> TypedRef:
    """Construct a typed digest reference to an artifact (§6).

    Args:
        artifact_payload: The artifact payload as a JSON-serializable dict.
        registry_entry: The Artifact Type Registry entry for this artifact type.

    Returns:
        A TypedRef with the recomputed digest.
    """
    digest_hex = canonical_digest(artifact_payload, registry_entry.exclusion_set)
    digest: str | bytes
    if registry_entry.representation == "prefixed":
        digest = "sha256:" + digest_hex
    elif registry_entry.representation == "raw":
        digest = hex_to_raw(digest_hex)  # explicit conversion -- never implicit
    else:
        digest = digest_hex
    return TypedRef(
        type=registry_entry.name,
        digest_alg=_ALGORITHM_DIGEST_ALG[registry_entry.algorithm],
        digest=digest,
    )


def verify_typed_ref(
    ref: TypedRef | dict[str, str],
    artifact_payload: dict[str, Any],
    registry_entry: ArtifactTypeRegistryEntry,
) -> str:
    """Verify a typed digest reference (§6.1).

    Steps:
    1. Resolve the artifact type from the registry entry.
    2. Confirm digest_alg names the hash algorithm this artifact type's
       canonicalization algorithm actually uses.
    3. Check the carried identifier is consistent with the declared representation.
    4. Recompute the artifact digest under the declared digest context.
    5. Compare the recomputed digest to the carried digest.

    The spec states: "The verifier MUST confirm that the identifier carried by
    the reference is consistent with the established context. It MUST then
    recompute the referenced artifact's digest under that context and compare
    the recomputed digest with the digest carried by the reference."

    Args:
        ref: The typed digest reference to verify (TypedRef or dict).
        artifact_payload: The bytes of the cited artifact as a dict.
        registry_entry: The Artifact Type Registry entry resolved from ref.type.
            Callers MUST resolve this from the registry using ref.type; they
            MUST NOT derive it from ref.digest_alg alone.

    Returns:
        The recomputed digest (64-char lowercase hex).

    Raises:
        DigestAlgorithmMismatchError: digest_alg does not name the hash
            algorithm this artifact type's canonicalization algorithm uses.
        RepresentationMismatchError: Carried digest is not in the declared representation.
        ContextMismatchError: Recomputed digest does not match the carried digest.
    """
    if isinstance(ref, dict):
        ref = TypedRef(**{k: ref[k] for k in ("type", "digest_alg", "digest")})

    # Step 1: confirm registry_entry is for the correct type
    if registry_entry.name != ref.type:
        raise TypedRefError(
            f"registry entry {registry_entry.name!r} does not match "
            f"typed reference type {ref.type!r}"
        )

    # Step 2: confirm digest_alg names the hash algorithm this artifact
    # type's canonicalization algorithm actually uses. This is independent
    # of the canonicalization CONTEXT check below, which always comes from
    # registry_entry -- never from digest_alg.
    expected_alg = _ALGORITHM_DIGEST_ALG[registry_entry.algorithm]
    if ref.digest_alg.upper() != expected_alg.upper():
        raise DigestAlgorithmMismatchError(
            declared=ref.digest_alg,
            expected=expected_alg,
            artifact_type=ref.type,
        )

    # Step 3: check representation
    _check_representation(ref.digest, registry_entry.representation, ref.type)

    # Step 4: recompute under the declared digest context
    recomputed = canonical_digest(artifact_payload, registry_entry.exclusion_set)

    # Normalize carried digest to bare hex for comparison. 'raw' goes
    # through the explicit raw_to_hex conversion -- never an implicit
    # bytes/str reinterpretation.
    if registry_entry.representation == "prefixed":
        carried_bare = ref.digest[len("sha256:"):]
    elif registry_entry.representation == "raw":
        carried_bare = raw_to_hex(ref.digest)
    else:
        carried_bare = ref.digest

    # Step 5: compare
    if recomputed != carried_bare:
        raise ContextMismatchError(
            carried=ref.digest,
            recomputed=recomputed,
            artifact_type=ref.type,
        )

    return recomputed
