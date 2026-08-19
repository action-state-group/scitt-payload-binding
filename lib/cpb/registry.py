# SPDX-License-Identifier: BSD-3-Clause
"""Registry snapshot loader and algorithm-id lookup.

Snapshot-pin mechanism: a verifier loads a specific registry.json snapshot,
verifies its content-address (snapshot_sha256), and reports the snapshot
version in verdicts so external parties know which snapshot was used.

Verdict taxonomy — distinct by design; MUST NOT be conflated:
  VERDICT_VERIFIED              — id found in snapshot; entry returned.
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
    snap = RegistrySnapshot.load("registry.json")
    verdict, entry = snap.lookup_algorithm("jcs-n")          # pinned (default)
    verdict, entry = snap.lookup_algorithm("jcs-n", pinned=False)  # authoritative
    snap.snapshot_sha256  # report in verdict output for traceability
"""
from __future__ import annotations

import hashlib
import json
import pathlib

__all__ = [
    "VERDICT_VERIFIED",
    "VERDICT_UNKNOWN_ID",
    "VERDICT_ID_UNKNOWN_TO_SNAPSHOT",
    "SnapshotIntegrityError",
    "RegistrySnapshot",
    "compute_snapshot_sha256",
]

VERDICT_VERIFIED = "verified"
VERDICT_UNKNOWN_ID = "unknown-id"
VERDICT_ID_UNKNOWN_TO_SNAPSHOT = "id-unknown-to-snapshot"


class SnapshotIntegrityError(ValueError):
    """snapshot_sha256 in a registry.json does not match the document content."""


class RegistrySnapshot:
    """A content-addressed CPB registry snapshot.

    Every snapshot carries a ``snapshot_sha256`` — the SHA-256 of the canonical
    JSON of the document body (all fields except ``snapshot_sha256`` itself,
    keys sorted, compact encoding, ASCII).  Loading verifies this automatically;
    tampering is detected before any lookup.

    After loading, call ``lookup_algorithm(id)`` to resolve a canonicalization
    algorithm id and get one of the three verdicts above.  The snapshot's
    ``snapshot_sha256`` should be included in the verifier's verdict output so
    consumers can identify which snapshot version was in effect.
    """

    def __init__(self, data: dict) -> None:
        self._data = data
        self._snapshot_sha256: str = data["snapshot_sha256"]

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "RegistrySnapshot":
        """Load and verify a registry.json file from disk."""
        raw = pathlib.Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        snap = cls(data)
        snap._verify_integrity()
        return snap

    @classmethod
    def from_dict(cls, data: dict, *, verify: bool = True) -> "RegistrySnapshot":
        """Construct from a pre-parsed dict.

        verify=True (default): verify snapshot_sha256 before returning.
        verify=False: skip integrity check (use only when building a new snapshot).
        """
        snap = cls(data)
        if verify:
            snap._verify_integrity()
        return snap

    def _verify_integrity(self) -> None:
        expected = self._snapshot_sha256
        actual = _compute_body_sha256(self._data)
        if actual != expected:
            raise SnapshotIntegrityError(
                f"registry snapshot integrity check failed: "
                f"expected snapshot_sha256={expected!r}, got {actual!r}"
            )

    @property
    def snapshot_sha256(self) -> str:
        """Content-address of this snapshot — include in verifier verdict output."""
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
            None on any failure verdict.
        """
        algorithms: dict = self._data.get("canonicalization_algorithms", {})
        entry = algorithms.get(algorithm_id)
        if entry is not None:
            return (VERDICT_VERIFIED, dict(entry))
        if pinned:
            return (VERDICT_ID_UNKNOWN_TO_SNAPSHOT, None)
        return (VERDICT_UNKNOWN_ID, None)

    def lookup_artifact_type(
        self, type_name: str, *, pinned: bool = True
    ) -> tuple[str, dict | None]:
        """Look up an artifact type by name.

        Same pinned/authoritative semantics as ``lookup_algorithm``.
        """
        types: dict = self._data.get("artifact_types", {})
        entry = types.get(type_name)
        if entry is not None:
            return (VERDICT_VERIFIED, dict(entry))
        if pinned:
            return (VERDICT_ID_UNKNOWN_TO_SNAPSHOT, None)
        return (VERDICT_UNKNOWN_ID, None)


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
