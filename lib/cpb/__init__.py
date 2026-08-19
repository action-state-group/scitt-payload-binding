# SPDX-License-Identifier: BSD-3-Clause
"""CPB reference library — spec-pure construction and verification.

Implements only the mechanisms defined in draft-mih-sokolov-scitt-payload-binding:
  §3.1  Algorithm jcs-n: normalize → JCS → SHA-256 → lowercase hex
  §4    Derived identifier: CANONICAL-DIGEST(A, payload minus exclusion_set)
  §6    Typed digest reference: construction and verification
  §13   Registry snapshot lookup (machine-readable registry.json)

No payload semantics from any specific profile are included here.
"""
from .canonicalize import (
    FloatInDigestError,
    UnsafeIntegerError,
    MAX_SAFE_INTEGER,
    normalize,
    jcs,
    canonical_digest,
)
from .derive_id import derive_id, verify_carried_id, CarriedIdMismatch
from .typed_ref import (
    TypedRef,
    ArtifactTypeRegistryEntry,
    TypedRefError,
    ContextMismatchError,
    RepresentationMismatchError,
    DigestAlgorithmMismatchError,
    PurposeMismatchError,
    make_typed_ref,
    verify_typed_ref,
    hex_to_raw,
    raw_to_hex,
)
from .registry import (
    VERDICT_VERIFIED,
    VERDICT_RESERVED,
    VERDICT_UNKNOWN_ID,
    VERDICT_ID_UNKNOWN_TO_SNAPSHOT,
    SnapshotIntegrityError,
    RegistrySnapshot,
    compute_snapshot_sha256,
)

__all__ = [
    "FloatInDigestError",
    "UnsafeIntegerError",
    "MAX_SAFE_INTEGER",
    "normalize",
    "jcs",
    "canonical_digest",
    "derive_id",
    "verify_carried_id",
    "CarriedIdMismatch",
    "TypedRef",
    "ArtifactTypeRegistryEntry",
    "TypedRefError",
    "ContextMismatchError",
    "RepresentationMismatchError",
    "DigestAlgorithmMismatchError",
    "PurposeMismatchError",
    "make_typed_ref",
    "verify_typed_ref",
    "hex_to_raw",
    "raw_to_hex",
    "VERDICT_VERIFIED",
    "VERDICT_RESERVED",
    "VERDICT_UNKNOWN_ID",
    "VERDICT_ID_UNKNOWN_TO_SNAPSHOT",
    "SnapshotIntegrityError",
    "RegistrySnapshot",
    "compute_snapshot_sha256",
]
