# SPDX-License-Identifier: BSD-3-Clause
"""Fail-closed handling for withdrawn canonicalization algorithms."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, TypeAlias

__all__ = [
    "JCS_N_WITHDRAWAL_CUTOFF",
    "VintageEvidenceVerifier",
    "WithdrawnAlgorithmError",
    "VintageEvidenceError",
    "require_pre_cutoff_jcs_n_vintage",
]


JCS_N_WITHDRAWAL_CUTOFF = datetime(2026, 8, 18, tzinfo=timezone.utc)

# The callback is the profile boundary: it verifies the profile-defined
# cryptographic evidence and returns the authenticated time.  The digest passed
# to it is the digest recomputed by this library, so the proof can be checked as
# binding the exact artifact under the selected digest context.
VintageEvidenceVerifier: TypeAlias = Callable[[object, str], datetime]


class WithdrawnAlgorithmError(ValueError):
    """A withdrawn algorithm was requested for a new construction."""


class VintageEvidenceError(ValueError):
    """Historical verification lacks valid, authenticated pre-cutoff evidence."""


def require_pre_cutoff_jcs_n_vintage(
    *,
    evidence: object | None,
    verify_evidence: VintageEvidenceVerifier | None,
    artifact_digest: str,
) -> datetime:
    """Authenticate and enforce the historical ``jcs-n`` vintage cutoff.

    ``verify_evidence`` is supplied by the consuming profile because CPB does
    not define a timestamp format.  It MUST cryptographically verify that
    ``evidence`` binds ``artifact_digest`` and return the authenticated time.
    Payload fields, file times, source-control dates, and transport times are
    not accepted directly by this API.
    """
    if evidence is None or verify_evidence is None:
        raise VintageEvidenceError(
            "jcs-n verification requires profile-defined cryptographic evidence "
            "and an evidence-verification callback binding the recomputed digest"
        )

    try:
        committed_at = verify_evidence(evidence, artifact_digest)
    except Exception as exc:
        raise VintageEvidenceError("jcs-n vintage evidence verification failed") from exc

    if not isinstance(committed_at, datetime):
        raise VintageEvidenceError(
            "vintage evidence verifier must return an authenticated datetime"
        )
    if committed_at.tzinfo is None or committed_at.utcoffset() is None:
        raise VintageEvidenceError(
            "authenticated vintage time must be timezone-aware"
        )

    committed_at_utc = committed_at.astimezone(timezone.utc)
    if committed_at_utc >= JCS_N_WITHDRAWAL_CUTOFF:
        raise VintageEvidenceError(
            "jcs-n evidence does not establish a pre-2026-08-18 UTC vintage"
        )
    return committed_at_utc
