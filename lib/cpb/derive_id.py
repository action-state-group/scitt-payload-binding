# SPDX-License-Identifier: BSD-3-Clause
"""Derived-identifier construction, evaluation, and verification.

Live construction uses ``jcs``. Withdrawn ``jcs-n`` remains available only for
historical evaluation and verification backed by authenticated vintage proof.
"""
from __future__ import annotations

from typing import Any

from .canonicalize import (
    _parse_json_object,
    canonical_digest,
    canonical_digest_json,
)
from .vintage import (
    VintageEvidenceVerifier,
    WithdrawnAlgorithmError,
    require_pre_cutoff_jcs_n_vintage,
)

__all__ = [
    "derive_id",
    "derive_id_json",
    "evaluate_derived_id",
    "evaluate_derived_id_json",
    "verify_carried_id",
    "CarriedIdMismatch",
]


class CarriedIdMismatch(ValueError):
    """Recomputed derived identifier does not match the carried value (§5 defect)."""

    def __init__(self, carried: str, recomputed: str) -> None:
        self.carried = carried
        self.recomputed = recomputed
        super().__init__(
            f"carried derived identifier {carried!r} does not match "
            f"recomputed value {recomputed!r}; this is a defect in the record (§5)"
        )


def derive_id(
    payload_json: str | bytes,
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str = "jcs",
) -> str:
    """Construct a derived identifier from duplicate-preserving raw JSON.

    Live ``jcs`` is the default. Selecting withdrawn ``jcs-n`` for a new
    construction fails closed. Parsed mappings are not accepted because they
    cannot prove that duplicate members were absent on the wire.
    """
    if not isinstance(payload_json, (str, bytes)):
        raise TypeError(
            "derived-identifier construction requires raw JSON text or bytes"
        )
    digest = canonical_digest_json(
        payload_json,
        exclusion_set,
        algorithm=algorithm,
    )
    if algorithm == "jcs-n":
        raise WithdrawnAlgorithmError(
            "cannot construct a new derived identifier with withdrawn algorithm 'jcs-n'"
        )
    return digest


derive_id_json = derive_id


def evaluate_derived_id(
    payload: dict[str, Any],
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str = "jcs-n",
) -> str:
    """Evaluate an identifier from a parsed value without claiming conformance.

    The historical ``jcs-n`` algorithm remains the default for compatibility
    with the retained vector corpus. Callers may explicitly select ``jcs``.

    This diagnostic helper neither establishes wire conformance nor verifies
    pre-cutoff vintage.  Use :func:`evaluate_derived_id_json` when raw JSON is
    available, and :func:`verify_carried_id` for a verification result.

    Args:
        payload: The payload as a JSON-serializable dict.
        exclusion_set: The fields declared by the payload class as
            self-referential or chain-linkage fields. Must be the SAME
            exclusion set the producer used; verifiers MUST apply the
            same set.

    Returns:
        64-character lowercase hex string.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a JSON object (dict)")
    return canonical_digest(payload, exclusion_set, algorithm=algorithm)


def evaluate_derived_id_json(
    payload_json: str | bytes,
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str = "jcs-n",
) -> str:
    """Evaluate a digest from duplicate-preserving raw JSON."""
    return canonical_digest_json(
        payload_json,
        exclusion_set,
        algorithm=algorithm,
    )


def verify_carried_id(
    payload_json: str | bytes,
    carried_field: str,
    exclusion_set: frozenset[str] | set[str] | None = None,
    *,
    algorithm: str = "jcs",
    vintage_evidence: object | None = None,
    verify_vintage_evidence: VintageEvidenceVerifier | None = None,
) -> str:
    """Verify a carried identifier from duplicate-preserving raw JSON (§5).

    The spec states: "Verifiers MUST recompute the derived identifier from the
    payload bytes; a carried derived-identifier value is advisory only and a
    mismatch is a defect."

    Duplicate members are rejected before parsing. Live ``jcs`` needs no
    vintage argument. A successful digest comparison is
    still not enough for withdrawn ``jcs-n``: the caller must supply
    profile-defined cryptographic evidence and a callback that verifies the
    evidence binds the recomputed digest to a pre-cutoff time.

    Args:
        payload_json: Raw JSON for the full payload (including the carried
            identifier field).
        carried_field: Name of the field that carries the derived identifier.
        exclusion_set: The payload class exclusion set. Must include
            ``carried_field`` when the field is self-referential.

    Returns:
        The recomputed derived identifier (64-char lowercase hex).

    Raises:
        CarriedIdMismatch: If the recomputed value differs from the carried value.
    """
    if not isinstance(payload_json, (str, bytes)):
        raise TypeError(
            "verified derived-identifier input must be raw JSON text or bytes; "
            "use evaluate_derived_id() for non-verifying parsed-value analysis"
        )
    payload = _parse_json_object(payload_json, algorithm=algorithm)
    recomputed = canonical_digest(
        payload,
        exclusion_set,
        algorithm=algorithm,
    )
    carried = payload.get(carried_field)
    if carried_field in payload and carried != recomputed:
        raise CarriedIdMismatch(carried=str(carried), recomputed=recomputed)
    if algorithm == "jcs-n":
        require_pre_cutoff_jcs_n_vintage(
            evidence=vintage_evidence,
            verify_evidence=verify_vintage_evidence,
            artifact_digest=recomputed,
        )
    return recomputed
