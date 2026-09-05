# SPDX-License-Identifier: BSD-3-Clause
"""Legacy repository-snapshot loader and algorithm-id lookup.

Draft -03 does not define a CPB artifact-type registry: consuming profiles
identify their accepted artifact-type declarations by stable reference.  This
module remains a compatibility trust source for deployments that have already
pinned this repository's machine-readable snapshot; it is not discovery and
does not make that snapshot a protocol registry.

Snapshot-pin mechanism: a verifier loads a specific registry.json snapshot,
checks its internal content-address (snapshot_sha256), compares that address
with an independently trusted pin, and reports it in verdicts so external
parties know which snapshot was used. The snapshot's own hash is not proof of
origin.

Verdict taxonomy — distinct by design; MUST NOT be conflated:
  VERDICT_VERIFIED              — id found in snapshot AND its status is a live
                                   registration (_LIVE_STATUSES); entry returned.
  VERDICT_RESERVED               — id found in snapshot but held rather than live:
                                   "Reserved" (a pre-registration hold on a name)
                                   or "provisional" (kept out of the live tables
                                   until vectors and pinning are complete). Neither
                                   has semantics to verify against, so a fail-closed
                                   verifier MUST NOT treat this the same as
                                   VERDICT_VERIFIED. Entry is returned (the caller
                                   may want the status/reference), but is never
                                   mistaken for a verified id because the verdict
                                   string itself differs.
  VERDICT_UNKNOWN_ID            — authoritative check (pinned=False); id is
                                  genuinely absent from the registry.
  VERDICT_ID_UNKNOWN_TO_SNAPSHOT — pinned-snapshot check (pinned=True); id is
                                   absent from THIS snapshot but MAY exist in a
                                   newer one. "Not registered" and "not in my
                                   stale snapshot" must not share a failure mode:
                                   a fail-closed verifier with an old snapshot
                                   would otherwise reject legitimately-registered
                                   new entries with the wrong reason.

Usage:
    snap = RegistrySnapshot.load("registry.json", expected_sha256=trusted_sha256)
    verdict, entry = snap.lookup_algorithm("jcs-n")          # pinned (default)
    verdict, entry = snap.lookup_algorithm("jcs-n", pinned=False)  # authoritative
    snap.snapshot_sha256  # report in verdict output for traceability
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from collections.abc import Sequence
from copy import deepcopy

from .typed_ref import ArtifactDigestContext, ArtifactTypeDefinition

__all__ = [
    "VERDICT_VERIFIED",
    "VERDICT_RESERVED",
    "VERDICT_UNKNOWN_ID",
    "VERDICT_ID_UNKNOWN_TO_SNAPSHOT",
    "SnapshotIntegrityError",
    "RegistrySnapshot",
    "compute_snapshot_sha256",
]

VERDICT_VERIFIED = "verified"
VERDICT_RESERVED = "reserved"
VERDICT_UNKNOWN_ID = "unknown-id"
VERDICT_ID_UNKNOWN_TO_SNAPSHOT = "id-unknown-to-snapshot"

#: Status values (registry.json "status" field) that constitute a live,
#: verifiable registration. Mirrors REGISTRY.md's Entry Status Vocabulary:
#: the legacy "Registered" spelling plus the vocabulary terms that denote an
#: entry in the live tables. "Reserved" is a pre-registration hold on a name,
#: and "provisional" is held out of the live tables until its vectors and
#: pinning are complete — neither has semantics to verify against.
#:
#: This mirrors the vocabulary rather than reading it: the library consumes
#: registry.json, which carries no vocabulary. test_registry.py cross-checks
#: this set against the statuses actually present in the committed snapshot,
#: so a new status cannot enter the registry without being classified here.
_LIVE_STATUSES = frozenset({
    "Registered",              # legacy spelling, pre-vocabulary rows
    "owner-confirmed",
    "third-party-documented",
    "standards-referenced",
})
_HELD_STATUSES = frozenset({
    "Reserved",
    "provisional",
    # A withdrawn token is never a live registration. Some withdrawn tokens
    # never had a definition; a retired defined token such as jcs-n may have a
    # separate authenticated historical-vintage path. Registry lookup alone
    # establishes neither, so it always returns the non-live verdict here.
    "withdrawn",
})


class SnapshotIntegrityError(ValueError):
    """snapshot_sha256 in a registry.json does not match the document content."""


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """Build a JSON object while rejecting duplicate decoded member names."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotIntegrityError(
                f"registry snapshot contains duplicate JSON member {key!r}"
            )
        result[key] = value
    return result


class RegistrySnapshot:
    """A content-addressed CPB registry snapshot.

    Every snapshot carries a ``snapshot_sha256`` — the SHA-256 of the canonical
    JSON of the document body (all fields except ``snapshot_sha256`` itself,
    keys sorted, compact encoding, ASCII). Loading checks internal consistency.
    Authenticity or hostile replacement is established only when the caller
    supplies an independently trusted ``expected_sha256`` (or otherwise trusts
    the file through its distribution channel).

    After loading, call ``lookup_algorithm(id)`` to resolve a canonicalization
    algorithm id and get one of the three verdicts above.  The snapshot's
    ``snapshot_sha256`` should be included in the verifier's verdict output so
    consumers can identify which snapshot version was in effect.
    """

    def __init__(self, data: dict) -> None:
        # Own a private tree: a caller cannot mutate its input after integrity
        # verification and thereby change future lookup results under the old
        # snapshot hash.
        self._data = deepcopy(data)
        self._snapshot_sha256 = self._data.get("snapshot_sha256")
        self._verified = False
        # Set only when the caller supplied and matched an independent pin.
        # Internal self-consistency alone is insufficient provenance for a
        # definition that can authorize a typed-reference verification verdict.
        self._trusted_snapshot_sha256: str | None = None

    @classmethod
    def load(
        cls,
        path: str | pathlib.Path,
        *,
        expected_sha256: str | None = None,
    ) -> "RegistrySnapshot":
        """Load a registry file, optionally checking an independently trusted pin."""
        raw = pathlib.Path(path).read_text(encoding="utf-8")
        data = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
        snap = cls(data)
        snap._verify_integrity(expected_sha256=expected_sha256)
        return snap

    @classmethod
    def from_dict(
        cls,
        data: dict,
        *,
        verify: bool = True,
        expected_sha256: str | None = None,
    ) -> "RegistrySnapshot":
        """Construct from a pre-parsed dict.

        verify=True (default): verify snapshot_sha256 before returning.
        verify=False: skip integrity check (use only when building a new snapshot).
        """
        snap = cls(data)
        if verify:
            snap._verify_integrity(expected_sha256=expected_sha256)
        return snap

    def _verify_integrity(self, *, expected_sha256: str | None = None) -> None:
        if self._data.get("schema_version") != "1":
            raise SnapshotIntegrityError(
                "unsupported registry schema_version; this library supports exactly '1'"
            )
        if not isinstance(self._data.get("canonicalization_algorithms"), dict):
            raise SnapshotIntegrityError("canonicalization_algorithms must be an object")
        if not isinstance(self._data.get("artifact_types"), dict):
            raise SnapshotIntegrityError("artifact_types must be an object")
        if (
            not isinstance(self._snapshot_sha256, str)
            or len(self._snapshot_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self._snapshot_sha256)
        ):
            raise SnapshotIntegrityError("snapshot_sha256 must be 64 lowercase hex characters")
        expected = self._snapshot_sha256
        actual = _compute_body_sha256(self._data)
        if actual != expected:
            raise SnapshotIntegrityError(
                f"registry snapshot integrity check failed: "
                f"expected snapshot_sha256={expected!r}, got {actual!r}"
            )
        if expected_sha256 is not None and actual != expected_sha256:
            raise SnapshotIntegrityError(
                "registry snapshot does not match the independently trusted pin: "
                f"expected {expected_sha256!r}, got {actual!r}"
            )
        for type_name, entry in self._data.get("artifact_types", {}).items():
            if not isinstance(entry, dict):
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} must be an object"
                )
            contexts = entry.get("digest_contexts")
            if not isinstance(contexts, list):
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} digest_contexts must be an array"
                )
            if not contexts:
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} must declare at least one "
                    "digest context"
                )
            if entry.get("status") not in _LIVE_STATUSES:
                continue
            purposes: set[str] = set()
            for context in contexts:
                if not isinstance(context, dict):
                    raise SnapshotIntegrityError(
                        f"artifact type {type_name!r} digest context must be an object"
                    )
                purpose = context.get("purpose")
                if not isinstance(purpose, str) or not purpose:
                    raise SnapshotIntegrityError(
                        f"live artifact type {type_name!r} has a context without a purpose"
                    )
                if purpose in purposes:
                    raise SnapshotIntegrityError(
                        f"live artifact type {type_name!r} repeats digest-context "
                        f"purpose {purpose!r}; type+purpose cannot resolve uniquely"
                    )
                purposes.add(purpose)
        if expected_sha256 is not None:
            self._trusted_snapshot_sha256 = actual
        self._verified = True

    def _require_verified(self) -> None:
        if not self._verified:
            raise SnapshotIntegrityError(
                "registry snapshot has not passed integrity and schema verification"
            )

    @property
    def snapshot_sha256(self) -> str:
        """Content-address, not proof of origin; compare it with a trusted pin."""
        return self._snapshot_sha256

    @property
    def schema_version(self) -> str:
        return str(self._data.get("schema_version", "1"))

    def lookup_algorithm(
        self, algorithm_id: str, *, pinned: bool = True
    ) -> tuple[str, dict | None]:
        """Look up a canonicalization algorithm by id.

        Args:
            algorithm_id: The algorithm identifier, e.g. ``'jcs-n'``.
            pinned: Controls the not-found verdict.
                True  (default) — pinned-snapshot semantics:
                    absent id → VERDICT_ID_UNKNOWN_TO_SNAPSHOT.
                    "My snapshot does not contain this id; it may exist in a
                    newer snapshot."
                False — authoritative-registry semantics:
                    absent id → VERDICT_UNKNOWN_ID.
                    "This id is not in the registry."

        Returns:
            ``(verdict, entry)`` where entry is a dict on VERDICT_VERIFIED or
            VERDICT_RESERVED, or None on any other verdict. An entry present
            in the snapshot but held rather than live (``Reserved`` or
            ``provisional``) is VERDICT_RESERVED, never VERDICT_VERIFIED —
            presence alone does not verify an id.
        """
        self._require_verified()
        algorithms: dict = self._data.get("canonicalization_algorithms", {})
        entry = algorithms.get(algorithm_id)
        if entry is not None:
            if entry.get("status") in _LIVE_STATUSES:
                return (VERDICT_VERIFIED, deepcopy(entry))
            return (VERDICT_RESERVED, deepcopy(entry))
        if pinned:
            return (VERDICT_ID_UNKNOWN_TO_SNAPSHOT, None)
        return (VERDICT_UNKNOWN_ID, None)

    def lookup_artifact_type(
        self, type_name: str, *, pinned: bool = True
    ) -> tuple[str, dict | None]:
        """Look up an artifact type by name.

        Same pinned/authoritative/VERDICT_RESERVED semantics as
        ``lookup_algorithm``.
        """
        self._require_verified()
        types: dict = self._data.get("artifact_types", {})
        entry = types.get(type_name)
        if entry is not None:
            if entry.get("status") in _LIVE_STATUSES:
                return (VERDICT_VERIFIED, deepcopy(entry))
            return (VERDICT_RESERVED, deepcopy(entry))
        if pinned:
            return (VERDICT_ID_UNKNOWN_TO_SNAPSHOT, None)
        return (VERDICT_UNKNOWN_ID, None)

    def artifact_type_definition(
        self,
        type_name: str,
        *,
        implementations: Sequence[ArtifactDigestContext] = (),
    ) -> ArtifactTypeDefinition:
        """Resolve a complete type definition from an independently pinned snapshot.

        Every registry context is retained, in registry order, even when this
        library cannot execute it. ``implementations`` may supply executable
        field-selection declarations for selected purposes; their type,
        purpose, algorithm, and representation must exactly match the pinned
        registry metadata. Missing implementations remain metadata-only and
        therefore fail closed if selected.

        The registry records field-selection prose rather than a normative
        machine mapping to ``whole_object_exclusion_set``. Consequently, a
        consuming profile remains responsible for checking each supplied
        implementation against that profile. This method establishes snapshot
        provenance, complete-set cardinality, and exact digest-context metadata;
        it does not infer executable field selection from prose.
        """
        self._require_verified()
        if self._trusted_snapshot_sha256 is None:
            raise SnapshotIntegrityError(
                "artifact-type verification requires a registry snapshot matched "
                "against an independently trusted expected_sha256"
            )

        verdict, entry = self.lookup_artifact_type(type_name)
        if verdict != VERDICT_VERIFIED or entry is None:
            raise SnapshotIntegrityError(
                f"artifact type {type_name!r} is not a live registration in the "
                f"trusted snapshot (verdict: {verdict})"
            )

        by_purpose: dict[str, ArtifactDigestContext] = {}
        for implementation in implementations:
            if not isinstance(implementation, ArtifactDigestContext):
                raise TypeError(
                    "every artifact-type implementation must be an "
                    "ArtifactDigestContext"
                )
            if implementation.name != type_name:
                raise SnapshotIntegrityError(
                    f"implementation for purpose {implementation.purpose!r} names "
                    f"artifact type {implementation.name!r}, expected {type_name!r}"
                )
            if implementation.purpose in by_purpose:
                raise SnapshotIntegrityError(
                    f"multiple implementations supplied for purpose "
                    f"{implementation.purpose!r}"
                )
            by_purpose[implementation.purpose] = implementation

        contexts: list[ArtifactDigestContext] = []
        registry_purposes: set[str] = set()
        for raw_context in entry["digest_contexts"]:
            # Live-entry validation already guarantees object rows and unique,
            # non-empty purposes. Keep these checks local so this security
            # boundary remains explicit if loader validation is later refactored.
            if not isinstance(raw_context, dict):
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} has a non-object digest context"
                )
            purpose = raw_context.get("purpose")
            algorithm = raw_context.get("algorithm")
            representation = raw_context.get("representation")
            if not isinstance(purpose, str) or not purpose:
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} has a context without a purpose"
                )
            if not isinstance(algorithm, str) or not algorithm:
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} purpose {purpose!r} has no "
                    "canonicalization algorithm"
                )
            if not isinstance(representation, str) or not representation:
                raise SnapshotIntegrityError(
                    f"artifact type {type_name!r} purpose {purpose!r} has no "
                    "explicit digest representation"
                )
            registry_purposes.add(purpose)

            implementation = by_purpose.get(purpose)
            if implementation is None:
                try:
                    context = ArtifactDigestContext(
                        name=type_name,
                        algorithm=algorithm,
                        representation=representation,
                        purpose=purpose,
                        whole_object_exclusion_set=None,
                    )
                except (TypeError, ValueError) as exc:
                    raise SnapshotIntegrityError(
                        f"artifact type {type_name!r} purpose {purpose!r} has "
                        f"invalid digest-context metadata: {exc}"
                    ) from exc
            else:
                if implementation.algorithm != algorithm:
                    raise SnapshotIntegrityError(
                        f"implementation for {type_name!r} purpose {purpose!r} "
                        f"uses algorithm {implementation.algorithm!r}, but the "
                        f"trusted registry declares {algorithm!r}"
                    )
                if implementation.representation != representation:
                    raise SnapshotIntegrityError(
                        f"implementation for {type_name!r} purpose {purpose!r} "
                        f"uses representation {implementation.representation!r}, "
                        f"but the trusted registry declares {representation!r}"
                    )
                context = implementation
            contexts.append(context)

        extra_purposes = set(by_purpose) - registry_purposes
        if extra_purposes:
            raise SnapshotIntegrityError(
                f"implementations supplied for unregistered purposes of "
                f"{type_name!r}: {sorted(extra_purposes)!r}"
            )

        return ArtifactTypeDefinition._from_trusted_snapshot(
            contexts,
            snapshot_sha256=self._trusted_snapshot_sha256,
        )


def _compute_body_sha256(data: dict) -> str:
    """SHA-256 of the canonical body — all fields except snapshot_sha256, keys sorted."""
    body = {k: v for k, v in data.items() if k != "snapshot_sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def compute_snapshot_sha256(data: dict) -> str:
    """Compute the content-address for a registry snapshot dict.

    Call this before inserting ``snapshot_sha256`` into the document.  The input
    dict must NOT contain a ``snapshot_sha256`` key (or must have it set to a
    placeholder — it is excluded from the computation regardless).
    """
    return _compute_body_sha256(data)
