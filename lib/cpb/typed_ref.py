# SPDX-License-Identifier: BSD-3-Clause
"""Typed digest reference: construction and verification.

Reference: draft-mih-sokolov-scitt-payload-binding-02 §8 (Typed Digest
References) / §8.1 (Cross-Profile Comparability). §8.1 requires the
verifier to confirm that ``digest_alg`` identifies a hash algorithm
consistent with the referenced artifact type's registered canonicalization
context, in addition to recomputing and comparing the digest itself.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .canonicalize import canonical_digest, canonical_digest_json
from .vintage import (
    VintageEvidenceVerifier,
    WithdrawnAlgorithmError,
    require_pre_cutoff_jcs_n_vintage,
)

__all__ = [
    "ArtifactDigestContext",
    "ArtifactTypeDefinition",
    "TypedRef",
    "ArtifactTypeRegistryEntry",
    "TypedRefError",
    "ContextMismatchError",
    "DigestContextResolutionError",
    "RepresentationMismatchError",
    "DigestAlgorithmMismatchError",
    "PurposeMismatchError",
    "PurposeRequiredError",
    "UnsupportedDigestContextError",
    "UnsupportedRepresentationError",
    "make_typed_ref",
    "make_typed_ref_json",
    "evaluate_typed_ref_digest",
    "verify_typed_ref",
    "verify_typed_ref_json",
    "hex_to_raw",
    "raw_to_hex",
]

_BARE_HEX_CHARS = frozenset("0123456789abcdef")


def _is_bare_hex_256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _BARE_HEX_CHARS for char in value)
    )

# The hash algorithm implied by each canonicalization algorithm's registry
# entry (REGISTRY.md §Payload Canonicalization Algorithm Registry). jcs-n is
# defined as "JCS + absent-field normalization; SHA-256; lowercase hex
# output" -- SHA-256 is fixed by the algorithm, not chosen per-reference.
_ALGORITHM_DIGEST_ALG: dict[str, str] = {
    "as-transmitted": "SHA-256",
    "jcs": "SHA-256",
    "jcs-n": "SHA-256",
}


def hex_to_raw(digest_hex: str) -> bytes:
    """Convert a 64-char lowercase hex digest to its 32 raw octets (§5.1).

    This is the ONLY sanctioned way to obtain the raw-octet representation
    from the hex representation. At the representation boundary, the raw bytes
    are ``bytes.fromhex(D)``, never ``D.encode("utf-8")`` -- the two are
    different byte sequences of different lengths (32 vs 64 bytes) and MUST
    NOT be substituted for one another.
    """
    if not _is_bare_hex_256(digest_hex):
        raise ValueError(
            "digest_hex must be exactly 64 lowercase hexadecimal characters"
        )
    return bytes.fromhex(digest_hex)


def raw_to_hex(digest_raw: bytes) -> str:
    """Convert 32 raw digest octets to their 64-char lowercase hex string (§5.1).

    This is the ONLY sanctioned way to obtain the hex representation from the
    raw-octet representation.
    """
    if not isinstance(digest_raw, bytes) or len(digest_raw) != 32:
        raise ValueError("digest_raw must be exactly 32 raw octets")
    return digest_raw.hex()


class TypedRefError(ValueError):
    """Base class for typed reference verification failures."""


class ContextMismatchError(TypedRefError):
    """Recomputed digest does not match the carried digest (§8.1)."""

    def __init__(self, carried: str | bytes, recomputed: str, artifact_type: str) -> None:
        self.carried = carried
        self.recomputed = recomputed
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: recomputed digest "
            f"{recomputed!r} does not match carried digest {carried!r}"
        )


class DigestContextResolutionError(TypedRefError):
    """The complete context set does not resolve the reference uniquely."""


class UnsupportedDigestContextError(TypedRefError):
    """The selected context is well-formed but not executable by this library."""


class UnsupportedRepresentationError(TypedRefError):
    """The selected representation has no encoding in the JSON TypedRef wire form."""


class RepresentationMismatchError(TypedRefError):
    """The carried identifier is inconsistent with the declared representation (§8.1).

    The spec (§5.1): "Representations are distinct and not interchangeable."
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
    used by the referenced artifact type's canonicalization algorithm (§8.1).

    §8 defines ``digest_alg`` as "the hash algorithm of the digest value".
    §8.1 requires the verifier to confirm that ``digest_alg`` is consistent
    with the referenced artifact type's registered canonicalization context
    -- the canonicalization CONTEXT itself is always resolved from the
    artifact-type registry entry, never from ``digest_alg``, but the field
    still makes a factual claim about which hash algorithm produced the
    carried digest. A reference that mislabels this (e.g. a jcs-n/SHA-256
    artifact cited with ``digest_alg: "SHA-512"``) is internally
    inconsistent and MUST NOT be silently recomputed and compared as though
    the label were correct.
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


class PurposeMismatchError(TypedRefError):
    """The reference purpose does not select a declared digest context (§8.1)."""

    def __init__(self, declared: str, expected: str, artifact_type: str) -> None:
        self.declared = declared
        self.expected = expected
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: declared purpose "
            f"{declared!r} does not match {expected!r}, the label this "
            f"artifact type's digest context is registered under"
        )


class PurposeRequiredError(TypedRefError):
    """Purpose was omitted without an explicit single-context guarantee."""

    def __init__(self, artifact_type: str) -> None:
        self.artifact_type = artifact_type
        super().__init__(
            f"typed reference to {artifact_type!r}: purpose is required unless "
            "the resolver explicitly establishes that the type has exactly one "
            "digest context"
        )


@dataclass(frozen=True)
class ArtifactDigestContext:
    """One digest context in a complete artifact-type definition.

    name:
        The artifact type name (the 'type' field value).
    algorithm:
        A non-empty canonicalization-algorithm token. Unknown algorithms are
        retained as resolution metadata so unsupported siblings can still
        participate in uniqueness checks.
    whole_object_exclusion_set:
        ``None`` means resolution metadata only: this library cannot execute
        the context's field selection. A ``frozenset`` explicitly declares the
        supported whole-JSON-object-minus-exclusions execution mode; the empty
        set means the whole object with no exclusions.
    representation:
        The representation of the output digest. Must be one of:
        'bare-hex' — 64-character lowercase hexadecimal (default);
        'sha256-prefixed' — 'sha256:' followed by 64-char lowercase hex;
        'raw' — 32 raw bytes.
        These are distinct and not interchangeable (§5.1).
    purpose:
        The purpose label under which this digest context is registered.
        Defaults to ``identifier``.
    """

    name: str
    algorithm: str
    representation: str = "bare-hex"
    purpose: str = "identifier"
    whole_object_exclusion_set: frozenset[str] | None = None

    def __post_init__(self) -> None:
        for field_name in ("name", "algorithm", "representation", "purpose"):
            if not isinstance(getattr(self, field_name), str) or not getattr(
                self, field_name
            ):
                raise ValueError(f"{field_name} must be a non-empty string")
        if self.representation not in {"bare-hex", "sha256-prefixed", "raw"}:
            raise ValueError(
                f"unknown representation {self.representation!r}; must be "
                "'bare-hex', 'sha256-prefixed', or 'raw'"
            )
        if self.whole_object_exclusion_set is not None and not isinstance(
            self.whole_object_exclusion_set, frozenset
        ):
            raise TypeError("whole_object_exclusion_set must be a frozenset or None")
        if self.whole_object_exclusion_set is not None and any(
            not isinstance(member, str) or not member
            for member in self.whole_object_exclusion_set
        ):
            raise ValueError(
                "whole_object_exclusion_set members must be non-empty strings"
            )


def _context_set_sha256(
    name: str,
    contexts: tuple[ArtifactDigestContext, ...],
) -> str:
    """Content-address the complete executable/metadata context assertion."""
    rows = [
        {
            "name": context.name,
            "algorithm": context.algorithm,
            "representation": context.representation,
            "purpose": context.purpose,
            "whole_object_exclusion_set": (
                None
                if context.whole_object_exclusion_set is None
                else sorted(context.whole_object_exclusion_set)
            ),
        }
        for context in contexts
    ]
    # Contexts form a set for resolution purposes, so their source-table order
    # is deliberately not part of the integrity binding. Duplicate rows remain
    # present after sorting and therefore still change the digest.
    rows.sort(
        key=lambda row: json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    )
    body = json.dumps(
        {"name": name, "contexts": rows},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(b"cpb-artifact-type-definition-v1\x00" + body).hexdigest()


@dataclass(frozen=True, init=False)
class ArtifactTypeDefinition:
    """Atomic assertion of an artifact type's complete digest-context set.

    High-level construction and verification accept this object instead of a
    bare sequence so a caller cannot resolve a complete set and then
    accidentally pass only the selected row. ``context_set_sha256`` binds the
    name, every context (including unsupported siblings), and executable field
    selection. It detects truncation or mutation of an existing definition; it
    is a content address, not proof of registry origin. A caller importing a
    registry definition should compare it with an independently trusted pin.

    Producers defining a profile use :meth:`for_construction`, publish its
    ``context_set_sha256``, and cannot use that unpinned object for a verification
    verdict. Verifiers use :meth:`from_contexts` with the independently trusted
    published pin, or receive a snapshot-bound definition from
    :meth:`cpb.registry.RegistrySnapshot.artifact_type_definition`.
    """

    name: str
    contexts: tuple[ArtifactDigestContext, ...]
    context_set_sha256: str
    verification_anchor: str | None

    @classmethod
    def for_construction(
        cls,
        contexts: Sequence[ArtifactDigestContext],
    ) -> ArtifactTypeDefinition:
        """Declare a complete local set for production, without verification trust."""
        name, entries, actual = cls._prepare_contexts(contexts)
        return cls._build(
            name=name,
            contexts=entries,
            context_set_sha256=actual,
            verification_anchor=None,
        )

    @classmethod
    def from_contexts(
        cls,
        contexts: Sequence[ArtifactDigestContext],
        *,
        expected_context_set_sha256: str,
    ) -> ArtifactTypeDefinition:
        """Bind supplied contexts to an independently trusted per-type pin."""
        name, entries, _ = cls._prepare_contexts(contexts)
        return cls._build(
            name=name,
            contexts=entries,
            context_set_sha256=expected_context_set_sha256,
            verification_anchor=(
                f"context-set-sha256:{expected_context_set_sha256}"
            ),
        )

    @classmethod
    def _from_trusted_snapshot(
        cls,
        contexts: Sequence[ArtifactDigestContext],
        *,
        snapshot_sha256: str,
    ) -> ArtifactTypeDefinition:
        """Build from the complete entry in an externally pinned snapshot."""
        name, entries, actual = cls._prepare_contexts(contexts)
        return cls._build(
            name=name,
            contexts=entries,
            context_set_sha256=actual,
            verification_anchor=f"registry-snapshot-sha256:{snapshot_sha256}",
        )

    @classmethod
    def _prepare_contexts(
        cls,
        contexts: Sequence[ArtifactDigestContext],
    ) -> tuple[str, tuple[ArtifactDigestContext, ...], str]:
        entries = tuple(contexts)
        if not entries:
            raise DigestContextResolutionError("no digest contexts supplied")
        if any(not isinstance(entry, ArtifactDigestContext) for entry in entries):
            raise TypeError("every digest context must be an ArtifactDigestContext")
        type_names = {entry.name for entry in entries}
        if len(type_names) != 1:
            raise DigestContextResolutionError(
                "an artifact-type definition must describe exactly one artifact type"
            )
        name = next(iter(type_names))
        return name, entries, _context_set_sha256(name, entries)

    @classmethod
    def _build(
        cls,
        *,
        name: str,
        contexts: tuple[ArtifactDigestContext, ...],
        context_set_sha256: str,
        verification_anchor: str | None,
    ) -> ArtifactTypeDefinition:
        definition = object.__new__(cls)
        object.__setattr__(definition, "name", name)
        object.__setattr__(definition, "contexts", contexts)
        object.__setattr__(definition, "context_set_sha256", context_set_sha256)
        object.__setattr__(definition, "verification_anchor", verification_anchor)
        definition._require_integrity(require_verification_anchor=False)
        return definition

    def _require_integrity(self, *, require_verification_anchor: bool) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("artifact type name must be a non-empty string")
        if not isinstance(self.contexts, tuple) or not self.contexts:
            raise TypeError("contexts must be a non-empty tuple")
        if any(not isinstance(entry, ArtifactDigestContext) for entry in self.contexts):
            raise TypeError("every digest context must be an ArtifactDigestContext")
        if any(entry.name != self.name for entry in self.contexts):
            raise DigestContextResolutionError(
                "every context must name the artifact type bound by the definition"
            )
        if (
            not isinstance(self.context_set_sha256, str)
            or len(self.context_set_sha256) != 64
            or any(char not in _BARE_HEX_CHARS for char in self.context_set_sha256)
        ):
            raise ValueError("context_set_sha256 must be 64 lowercase hex characters")
        actual = _context_set_sha256(self.name, self.contexts)
        if actual != self.context_set_sha256:
            raise DigestContextResolutionError(
                "artifact-type definition context-set integrity check failed: "
                f"expected {self.context_set_sha256!r}, got {actual!r}"
            )
        if self.verification_anchor is not None:
            prefix, separator, digest = self.verification_anchor.rpartition(":")
            if (
                not separator
                or prefix
                not in {"context-set-sha256", "registry-snapshot-sha256"}
                or len(digest) != 64
                or any(char not in _BARE_HEX_CHARS for char in digest)
            ):
                raise DigestContextResolutionError(
                    "artifact-type definition has an invalid verification anchor"
                )
            if prefix == "context-set-sha256" and digest != self.context_set_sha256:
                raise DigestContextResolutionError(
                    "artifact-type definition pin does not bind its context set"
                )
        if require_verification_anchor and self.verification_anchor is None:
            raise DigestContextResolutionError(
                "typed-reference verification requires a definition bound to an "
                "independently trusted context-set or registry-snapshot pin"
            )


# Migration alias for the pre-0.2 public name. The 0.2 constructor is
# intentionally not call-compatible: algorithm and executable field selection
# must now be explicit, and verification consumes an ArtifactTypeDefinition.
ArtifactTypeRegistryEntry = ArtifactDigestContext


@dataclass(frozen=True)
class TypedRef:
    """A typed digest reference (§8).

    Fields match the spec-defined JSON object:
        type       — artifact type, from Artifact Type Registry
        digest_alg — hash algorithm of the digest value (e.g., 'SHA-256')
        digest     — digest of the cited artifact, in its declared representation.
                     The JSON wire form permits the textual ``bare-hex`` and
                     ``sha256-prefixed`` representations. ``bytes`` is retained
                     only for explicit raw-boundary diagnostic evaluation; raw
                     has no JSON TypedRef wire encoding.
    """

    type: str
    digest_alg: str
    digest: str | bytes
    purpose: str | None = None

    def as_dict(self) -> dict[str, str]:
        """Render as a JSON-serializable dict. Only valid for str-typed
        (hex/prefixed) digests. JSON has no native byte-string type, so a
        ``raw`` (bytes) value has no TypedRef JSON rendering; the selected
        digest context must expressly declare a textual comparison
        representation instead."""
        if not isinstance(self.digest, str):
            raise TypeError(
                f"as_dict() requires a str-typed digest (raw bytes has no JSON "
                f"TypedRef encoding); got {type(self.digest).__name__}; use a "
                f"context that expressly declares a textual representation"
            )
        result = {
            "type": self.type,
            "digest_alg": self.digest_alg,
            "digest": self.digest,
        }
        if self.purpose is not None:
            result["purpose"] = self.purpose
        return result


def _check_representation(digest: str | bytes, representation: str, artifact_type: str) -> None:
    """Raise RepresentationMismatchError if digest does not match the declared representation.

    §5.1 declares raw octets, lowercase hex, and prefixed hex as distinct,
    non-interchangeable representations. This is enforced at the Python type
    level, not just the string grammar: 'bare-hex' and 'sha256-prefixed'
    require a
    ``str``; 'raw' requires an actual ``bytes`` object of 32 octets. A hex
    ``str`` -- even one that is the exact hex encoding of the correct raw
    bytes -- is REJECTED where 'raw' is declared, and a ``bytes`` object is
    REJECTED where 'bare-hex'/'sha256-prefixed' (str-typed) representations are
    declared. Converting between the two requires the explicit
    ``hex_to_raw``/``raw_to_hex`` functions; there is no implicit path.
    """
    if representation == "bare-hex":
        if not _is_bare_hex_256(digest):
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="bare-hex (64-char lowercase hex str)",
                artifact_type=artifact_type,
            )
    elif representation == "sha256-prefixed":
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not _is_bare_hex_256(digest[len("sha256:"):])
        ):
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="sha256-prefixed ('sha256:' + 64-char lowercase hex str)",
                artifact_type=artifact_type,
            )
    elif representation == "raw":
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise RepresentationMismatchError(
                carried=digest,
                expected_repr="raw (32 raw octets, as a bytes object -- not a hex str)",
                artifact_type=artifact_type,
            )
    else:
        raise UnsupportedDigestContextError(
            f"typed reference to {artifact_type!r}: unsupported representation "
            f"{representation!r}"
        )


def make_typed_ref(
    artifact_payload: dict[str, Any],
    registry_entry: ArtifactDigestContext,
) -> TypedRef:
    """Refuse parsed construction input.

    A parsed mapping cannot demonstrate that its source had no duplicate JSON
    members. Use :func:`make_typed_ref_json`, which accepts raw JSON and permits
    the live ``jcs`` algorithm while rejecting historical ``jcs-n``.
    """
    raise TypeError(
        "typed-reference construction requires raw JSON text or bytes; "
        "use make_typed_ref_json()"
    )


def make_typed_ref_json(
    artifact_json: str | bytes,
    artifact_type: ArtifactTypeDefinition,
    *,
    purpose: str | None = None,
) -> TypedRef:
    """Construct from raw JSON after resolving an integrity-bound context set.

    ``jcs-n`` remains available for historical evaluation but is rejected for
    every new construction. Duplicate purpose labels and purpose-less
    multi-context definitions fail before any digest is emitted.
    """
    if not isinstance(artifact_type, ArtifactTypeDefinition):
        raise TypeError(
            "construction requires an ArtifactTypeDefinition, not a bare or "
            "caller-selected digest-context sequence"
        )
    artifact_type._require_integrity(require_verification_anchor=False)
    registry_entry = _select_context(
        artifact_type.name,
        purpose,
        artifact_type.contexts,
    )
    _require_json_typed_ref_representation(registry_entry)
    _require_executable_context(registry_entry)
    # Run the raw-input gate before the withdrawal check. This ensures that no
    # construction API ever treats a duplicate-collapsing parse as valid input.
    digest_hex = _digest_json_for_context(artifact_json, registry_entry)
    if registry_entry.algorithm == "jcs-n":
        raise WithdrawnAlgorithmError(
            "cannot construct a new typed reference with withdrawn algorithm 'jcs-n'"
        )
    return TypedRef(
        type=registry_entry.name,
        digest_alg=_ALGORITHM_DIGEST_ALG[registry_entry.algorithm],
        digest=_render_digest(digest_hex, registry_entry.representation),
        purpose=registry_entry.purpose,
    )


def _render_digest(digest_hex: str, representation: str) -> str | bytes:
    """Render a bare-hex result in the explicitly selected representation."""
    if representation == "sha256-prefixed":
        return "sha256:" + digest_hex
    if representation == "raw":
        return hex_to_raw(digest_hex)
    return digest_hex


def _prepare_reference(
    ref: TypedRef | dict[str, str],
    registry_entry: ArtifactDigestContext,
) -> TypedRef:
    """Validate reference metadata before digest comparison."""
    carried_purpose = ref.get("purpose") if isinstance(ref, dict) else ref.purpose
    if isinstance(ref, dict):
        ref = TypedRef(
            **{k: ref[k] for k in ("type", "digest_alg", "digest")},
            purpose=carried_purpose,
        )

    # Step 1: confirm registry_entry is for the correct type
    if registry_entry.name != ref.type:
        raise TypedRefError(
            f"registry entry {registry_entry.name!r} does not match "
            f"typed reference type {ref.type!r}"
        )

    # Step 1a: a carried purpose must name this type's registered digest
    # context -- see the `purpose` note in the docstring above.
    if carried_purpose is not None and carried_purpose != registry_entry.purpose:
        raise PurposeMismatchError(
            declared=carried_purpose,
            expected=registry_entry.purpose,
            artifact_type=ref.type,
        )

    # Step 2: confirm digest_alg names the hash algorithm this artifact
    # type's canonicalization algorithm actually uses. This is independent
    # of the canonicalization CONTEXT check below, which always comes from
    # registry_entry -- never from digest_alg.
    _require_executable_context(registry_entry)
    expected_alg = _ALGORITHM_DIGEST_ALG[registry_entry.algorithm]
    # Exact octets, not case-folded: the draft requires byte-for-byte comparison
    # because the IANA registries an implementer might reach for disagree on
    # spelling ("sha-256" vs "SHA-256"), and tolerating either silently accepts a
    # reference naming a different registry's token.
    if ref.digest_alg != expected_alg:
        raise DigestAlgorithmMismatchError(
            declared=ref.digest_alg,
            expected=expected_alg,
            artifact_type=ref.type,
        )

    # Step 3: check representation
    _check_representation(ref.digest, registry_entry.representation, ref.type)

    return ref


def _select_context(
    ref_type: str,
    purpose: str | None,
    registry_entries: Sequence[ArtifactDigestContext],
) -> ArtifactDigestContext:
    """Select one context by type and purpose from a complete context set."""
    candidates = tuple(entry for entry in registry_entries if entry.name == ref_type)
    if not candidates:
        raise DigestContextResolutionError(
            f"typed reference type {ref_type!r} has no supplied digest context"
        )

    purposes = [entry.purpose for entry in candidates]
    duplicate_purposes = sorted(
        purpose_name for purpose_name in set(purposes) if purposes.count(purpose_name) > 1
    )
    if duplicate_purposes:
        raise DigestContextResolutionError(
            f"typed reference type {ref_type!r} has duplicate digest-context "
            f"purpose labels: {duplicate_purposes!r}"
        )

    if purpose is None:
        if len(candidates) != 1:
            raise PurposeRequiredError(str(ref_type))
        selected = candidates[0]
        return selected

    matches = tuple(entry for entry in candidates if entry.purpose == purpose)
    if len(matches) != 1:
        expected = ", ".join(sorted(purposes))
        raise PurposeMismatchError(
            declared=str(purpose),
            expected=expected,
            artifact_type=str(ref_type),
        )
    return matches[0]


def _require_json_typed_ref_representation(
    registry_entry: ArtifactDigestContext,
) -> None:
    if registry_entry.representation == "raw":
        raise UnsupportedRepresentationError(
            f"typed reference to {registry_entry.name!r}: the JSON TypedRef "
            "digest field is a string and has no normative encoding for the "
            "'raw' representation"
        )


def _resolve_reference_context(
    ref: TypedRef | dict[str, str],
    artifact_type: ArtifactTypeDefinition,
) -> tuple[TypedRef, ArtifactDigestContext]:
    """Resolve exactly one context from an integrity-bound artifact definition."""
    if not isinstance(artifact_type, ArtifactTypeDefinition):
        raise TypeError(
            "verification requires an ArtifactTypeDefinition, not a bare or "
            "caller-selected digest-context sequence"
        )
    artifact_type._require_integrity(require_verification_anchor=True)
    ref_type = ref.get("type") if isinstance(ref, dict) else ref.type
    purpose = ref.get("purpose") if isinstance(ref, dict) else ref.purpose
    selected = _select_context(str(ref_type), purpose, artifact_type.contexts)
    _require_json_typed_ref_representation(selected)
    return _prepare_reference(ref, selected), selected


def _require_executable_context(registry_entry: ArtifactDigestContext) -> None:
    if registry_entry.algorithm not in {"jcs", "jcs-n"}:
        raise UnsupportedDigestContextError(
            f"typed reference to {registry_entry.name!r}: canonicalization "
            f"algorithm {registry_entry.algorithm!r} is not executable by this library"
        )
    if registry_entry.whole_object_exclusion_set is None:
        raise UnsupportedDigestContextError(
            f"typed reference to {registry_entry.name!r}: selected context has "
            "no executable whole-object field-selection declaration"
        )


def _digest_json_for_context(
    artifact_json: str | bytes,
    registry_entry: ArtifactDigestContext,
) -> str:
    _require_executable_context(registry_entry)
    return canonical_digest_json(
        artifact_json,
        registry_entry.whole_object_exclusion_set,
        algorithm=registry_entry.algorithm,
    )


def _compare_recomputed(
    ref: TypedRef,
    recomputed: str,
    registry_entry: ArtifactDigestContext,
) -> str:
    """Compare a recomputed bare-hex digest with its carried representation."""
    if registry_entry.representation == "sha256-prefixed":
        carried_bare = ref.digest[len("sha256:"):]
    elif registry_entry.representation == "raw":
        carried_bare = raw_to_hex(ref.digest)
    else:
        carried_bare = ref.digest

    if recomputed != carried_bare:
        raise ContextMismatchError(
            carried=ref.digest,
            recomputed=recomputed,
            artifact_type=ref.type,
        )
    return recomputed


def evaluate_typed_ref_digest(
    ref: TypedRef | dict[str, str],
    artifact_payload: dict[str, Any],
    registry_entry: ArtifactDigestContext,
) -> str:
    """Evaluate typed-reference digest agreement, not wire validity.

    This parsed-value helper exists for retained vectors and diagnostics.  It
    checks type, purpose, digest-algorithm, representation, and digest equality,
    but it deliberately does **not** report the reference as verified: a parsed
    mapping cannot prove that duplicate JSON members were absent. When the
    registry entry names historical ``jcs-n``, this call also establishes no
    authenticated pre-cutoff vintage.
    """
    if not isinstance(artifact_payload, dict):
        raise TypeError("artifact_payload must be an already-parsed JSON object")
    checked_ref = _prepare_reference(ref, registry_entry)
    _require_executable_context(registry_entry)
    recomputed = canonical_digest(
        artifact_payload,
        registry_entry.whole_object_exclusion_set,
        algorithm=registry_entry.algorithm,
    )
    return _compare_recomputed(checked_ref, recomputed, registry_entry)


def verify_typed_ref_json(
    ref: TypedRef | dict[str, str],
    artifact_json: str | bytes,
    artifact_type: ArtifactTypeDefinition,
    *,
    vintage_evidence: object | None = None,
    verify_vintage_evidence: VintageEvidenceVerifier | None = None,
) -> str:
    """Verify a typed reference from duplicate-preserving raw JSON.

    The raw JSON is checked for duplicate members before parsing. Historical
    ``jcs-n`` additionally enforces its integer-only wire rule and requires a
    consuming-profile callback that cryptographically authenticates evidence
    binding the recomputed artifact digest to a time before 2026-08-18 UTC.
    Missing, unauthenticated, naive, or post-cutoff evidence fails closed.
    Live ``jcs`` requires no vintage evidence.
    """
    checked_ref, registry_entry = _resolve_reference_context(ref, artifact_type)
    recomputed = _digest_json_for_context(artifact_json, registry_entry)
    _compare_recomputed(checked_ref, recomputed, registry_entry)
    if registry_entry.algorithm == "jcs-n":
        require_pre_cutoff_jcs_n_vintage(
            evidence=vintage_evidence,
            verify_evidence=verify_vintage_evidence,
            artifact_digest=recomputed,
        )
    return recomputed


def verify_typed_ref(
    ref: TypedRef | dict[str, str],
    artifact_json: str | bytes,
    artifact_type: ArtifactTypeDefinition,
    *,
    vintage_evidence: object | None = None,
    verify_vintage_evidence: VintageEvidenceVerifier | None = None,
) -> str:
    """Verify from raw JSON; parsed mappings are intentionally not accepted.

    This compatibility name delegates to :func:`verify_typed_ref_json`.  Use
    :func:`evaluate_typed_ref_digest` for non-verifying inspection of an
    already-parsed value.
    """
    if not isinstance(artifact_json, (str, bytes)):
        raise TypeError(
            "verified typed-reference input must be raw JSON text or bytes; "
            "use evaluate_typed_ref_digest() for non-verifying parsed-value analysis"
        )
    return verify_typed_ref_json(
        ref,
        artifact_json,
        artifact_type,
        vintage_evidence=vintage_evidence,
        verify_vintage_evidence=verify_vintage_evidence,
    )
