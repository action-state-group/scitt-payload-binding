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
    "make_typed_ref",
    "verify_typed_ref",
]

_BARE_HEX_CHARS = frozenset("0123456789abcdef")


class TypedRefError(ValueError):
    """Base class for typed reference verification failures."""


class ContextMismatchError(TypedRefError):
    """Recomputed digest does not match the carried digest (§6.1)."""

    def __init__(self, carried: str, recomputed: str, artifact_type: str) -> None:
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
    This error is raised when the carried digest string does not conform to the
    representation declared in the artifact type registry entry (e.g., a
    sha256:-prefixed string where bare 64-char lowercase hex is required).
    """

    def __init__(self, carried: str, expected_repr: str, artifact_type: str) -> None:
        self.carried = carried
        self.expected_repr = expected_repr
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: carried identifier {carried!r} "
            f"is not in the declared representation {expected_repr!r}"
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
        digest     — digest of the cited artifact, in its declared representation
    """

    type: str
    digest_alg: str
    digest: str

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "digest_alg": self.digest_alg, "digest": self.digest}


def _check_representation(digest: str, representation: str, artifact_type: str) -> None:
    """Raise RepresentationMismatchError if digest does not match the declared representation."""
    if representation == "bare_hex":
        if len(digest) != 64 or not all(c in _BARE_HEX_CHARS for c in digest):
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="bare_hex (64-char lowercase hex)",
                artifact_type=artifact_type,
            )
    elif representation == "prefixed":
        if not digest.startswith("sha256:") or len(digest) != 7 + 64:
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="prefixed ('sha256:' + 64-char lowercase hex)",
                artifact_type=artifact_type,
            )
    elif representation == "raw":
        # raw bytes: caller passes a hex string; we expect exactly 32 bytes
        if len(digest) != 64 or not all(c in _BARE_HEX_CHARS for c in digest):
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="raw (32 bytes, passed as 64-char lowercase hex here)",
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
    digest = canonical_digest(artifact_payload, registry_entry.exclusion_set)
    if registry_entry.representation == "prefixed":
        digest = "sha256:" + digest
    return TypedRef(
        type=registry_entry.name,
        digest_alg="SHA-256",
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
    2. Check the carried identifier is consistent with the declared representation.
    3. Recompute the artifact digest under the declared digest context.
    4. Compare the recomputed digest to the carried digest.

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

    # Step 2: check representation
    _check_representation(ref.digest, registry_entry.representation, ref.type)

    # Step 3: recompute under the declared digest context
    recomputed = canonical_digest(artifact_payload, registry_entry.exclusion_set)

    # Normalize carried digest to bare hex for comparison
    carried_bare = ref.digest
    if registry_entry.representation == "prefixed":
        carried_bare = ref.digest[len("sha256:"):]

    # Step 4: compare
    if recomputed != carried_bare:
        raise ContextMismatchError(
            carried=ref.digest,
            recomputed=recomputed,
            artifact_type=ref.type,
        )

    return recomputed
