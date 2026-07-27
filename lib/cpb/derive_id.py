# SPDX-License-Identifier: BSD-3-Clause
"""Derived identifier: CANONICAL-DIGEST(A, payload minus exclusion_set).

Reference: draft-mih-sokolov-scitt-payload-binding-00 §4
"""
from __future__ import annotations

from typing import Any

from .canonicalize import canonical_digest

__all__ = ["derive_id", "verify_carried_id", "CarriedIdMismatch"]


class CarriedIdMismatch(ValueError):
    """Recomputed derived identifier does not match the carried value (§4 defect)."""

    def __init__(self, carried: str, recomputed: str) -> None:
        self.carried = carried
        self.recomputed = recomputed
        super().__init__(
            f"carried derived identifier {carried!r} does not match "
            f"recomputed value {recomputed!r}; this is a defect in the record (§4)"
        )


def derive_id(
    payload: dict[str, Any],
    exclusion_set: frozenset[str] | set[str] | None = None,
) -> str:
    """Compute the derived identifier of a payload (§4).

    id = CANONICAL-DIGEST(jcs-n, payload minus exclusion_set)

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
    return canonical_digest(payload, exclusion_set)


def verify_carried_id(
    payload: dict[str, Any],
    carried_field: str,
    exclusion_set: frozenset[str] | set[str] | None = None,
) -> str:
    """Recompute the derived identifier and compare to the carried value (§4).

    The spec states: "Verifiers MUST recompute the derived identifier from the
    payload bytes; a carried derived-identifier value is advisory only and a
    mismatch is a defect."

    Args:
        payload: The full payload (including the carried identifier field).
        carried_field: Name of the field that carries the derived identifier.
        exclusion_set: The payload class exclusion set. Must include
            ``carried_field`` when the field is self-referential.

    Returns:
        The recomputed derived identifier (64-char lowercase hex).

    Raises:
        CarriedIdMismatch: If the recomputed value differs from the carried value.
    """
    recomputed = derive_id(payload, exclusion_set)
    carried = payload.get(carried_field)
    if carried is not None and carried != recomputed:
        raise CarriedIdMismatch(carried=str(carried), recomputed=recomputed)
    return recomputed
