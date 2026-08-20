# SPDX-License-Identifier: BSD-3-Clause
"""Registry snapshot tests — verdict taxonomy and mutant discipline.

Verdict taxonomy under test:
  VERDICT_VERIFIED              — id found in snapshot
  VERDICT_UNKNOWN_ID            — authoritative check, id genuinely absent
  VERDICT_ID_UNKNOWN_TO_SNAPSHOT — pinned snapshot, id in newer registry

Mutant discipline: for every negative check (unknown-id, id-unknown-to-snapshot),
there is an explicit mutant that removes or reverses the condition and asserts the
verdict FLIPS away from the negative verdict.  A negative check whose mutant
still returns the same negative verdict is not exercised.

Snapshot-pin: every lookup returns snapshot_sha256 via the snapshot object so
verifiers can include it in their verdict output for traceability.
"""
import pathlib
import pytest

from cpb.registry import (
    VERDICT_VERIFIED,
    VERDICT_RESERVED,
    VERDICT_UNKNOWN_ID,
    VERDICT_ID_UNKNOWN_TO_SNAPSHOT,
    RegistrySnapshot,
    SnapshotIntegrityError,
    compute_snapshot_sha256,
)

# ---------------------------------------------------------------------------
# Snapshot fixtures
# ---------------------------------------------------------------------------

_JCS_N_ENTRY = {
    "description": (
        "RFC 8785 JCS over a normalized JSON object "
        "(null, empty-array, and empty-object members removed bottom-up); "
        "SHA-256; lowercase hex"
    ),
    "reference": "draft-mih-sokolov-scitt-payload-binding",
    "status": "Registered",
}

_AS_TRANSMITTED_ENTRY = {
    "description": (
        "No canonicalization: the pre-image is the exact octet sequence "
        "identified by a cited named production in the container format; "
        "SHA-256; 64-character lowercase hex"
    ),
    "reference": "draft-mih-sokolov-scitt-payload-binding",
    "status": "Registered",
}

_CDE_N_RESERVED_ENTRY = {
    "description": "Deterministic CBOR canonicalization profile; SHA-256",
    "reference": "draft-mih-sokolov-scitt-payload-binding",
    "status": "Reserved",
}


def _build_snapshot(algorithms: dict, artifact_types: dict | None = None) -> dict:
    """Build a valid snapshot dict with correct snapshot_sha256."""
    data: dict = {
        "schema_version": "1",
        "canonicalization_algorithms": algorithms,
        "artifact_types": artifact_types or {},
    }
    data["snapshot_sha256"] = compute_snapshot_sha256(data)
    return data


@pytest.fixture
def snapshot_old():
    """Old pinned snapshot: only jcs-n, missing as-transmitted."""
    return RegistrySnapshot.from_dict(
        _build_snapshot({"jcs-n": _JCS_N_ENTRY}), verify=True
    )


@pytest.fixture
def snapshot_current():
    """Current snapshot: jcs-n + as-transmitted."""
    return RegistrySnapshot.from_dict(
        _build_snapshot({"jcs-n": _JCS_N_ENTRY, "as-transmitted": _AS_TRANSMITTED_ENTRY}),
        verify=True,
    )


@pytest.fixture
def snapshot_with_reserved():
    """Snapshot holding one Registered entry and one Reserved entry."""
    return RegistrySnapshot.from_dict(
        _build_snapshot({"jcs-n": _JCS_N_ENTRY, "cde-n": _CDE_N_RESERVED_ENTRY}),
        verify=True,
    )


# ---------------------------------------------------------------------------
# VERDICT_VERIFIED
# ---------------------------------------------------------------------------

class TestVerdictVerified:
    def test_registered_id_found(self, snapshot_current):
        verdict, entry = snapshot_current.lookup_algorithm("jcs-n")
        assert verdict == VERDICT_VERIFIED
        assert entry is not None
        assert entry["status"] == "Registered"

    def test_entry_contents_returned(self, snapshot_current):
        _, entry = snapshot_current.lookup_algorithm("as-transmitted")
        assert entry is not None
        assert "description" in entry
        assert "reference" in entry

    def test_verified_does_not_appear_for_absent_id(self, snapshot_old):
        # Mutant for unknown-id: confirm VERIFIED is NOT returned for an absent id
        verdict, _ = snapshot_old.lookup_algorithm("not-a-real-alg", pinned=False)
        assert verdict != VERDICT_VERIFIED

    def test_verified_does_not_appear_for_snapshot_miss(self, snapshot_old):
        # Mutant for id-unknown-to-snapshot: confirm VERIFIED is NOT returned
        # when as-transmitted is absent from the old snapshot
        verdict, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=True)
        assert verdict != VERDICT_VERIFIED


# ---------------------------------------------------------------------------
# VERDICT_RESERVED — presence alone MUST NOT verify (issue #37)
#
# lookup_algorithm previously returned VERDICT_VERIFIED for ANY entry present
# in the snapshot, regardless of its `status`. A Reserved entry (a
# pre-registration hold with no defined semantics — e.g. `cde-n`) was
# indistinguishable from a live Registered entry to a fail-closed verifier
# keying on the verdict string. Two-sided: Registered -> verified,
# Reserved -> not-verified, on the SAME snapshot so status is the only
# variable.
# ---------------------------------------------------------------------------

class TestVerdictReserved:
    def test_registered_entry_is_verified(self, snapshot_with_reserved):
        verdict, entry = snapshot_with_reserved.lookup_algorithm("jcs-n")
        assert verdict == VERDICT_VERIFIED
        assert entry["status"] == "Registered"

    def test_reserved_entry_is_not_verified(self, snapshot_with_reserved):
        verdict, entry = snapshot_with_reserved.lookup_algorithm("cde-n")
        assert verdict != VERDICT_VERIFIED
        assert verdict == VERDICT_RESERVED
        assert entry["status"] == "Reserved"

    def test_reserved_verdict_distinct_from_all_others(self):
        assert VERDICT_RESERVED != VERDICT_VERIFIED
        assert VERDICT_RESERVED != VERDICT_UNKNOWN_ID
        assert VERDICT_RESERVED != VERDICT_ID_UNKNOWN_TO_SNAPSHOT

    def test_artifact_type_reserved_entry_is_not_verified(self):
        # Same gate applies to lookup_artifact_type.
        data = _build_snapshot(
            {},
            {"reserved-type": {"description": "d", "reference": "r", "status": "Reserved"}},
        )
        snap = RegistrySnapshot.from_dict(data, verify=True)
        verdict, entry = snap.lookup_artifact_type("reserved-type")
        assert verdict != VERDICT_VERIFIED
        assert verdict == VERDICT_RESERVED
        assert entry["status"] == "Reserved"


# ---------------------------------------------------------------------------
# VERDICT_UNKNOWN_ID  (authoritative / pinned=False check)
# ---------------------------------------------------------------------------

class TestVerdictUnknownId:
    def test_genuinely_unregistered_id(self, snapshot_current):
        """Genuinely unregistered id against authoritative registry → unknown-id."""
        verdict, entry = snapshot_current.lookup_algorithm(
            "not-a-real-alg", pinned=False
        )
        assert verdict == VERDICT_UNKNOWN_ID
        assert entry is None

    def test_unknown_id_entry_is_none(self, snapshot_current):
        verdict, entry = snapshot_current.lookup_algorithm("invented-alg", pinned=False)
        assert entry is None

    # Mutant: change the id to a registered one — verdict MUST flip to verified
    def test_mutant_registered_id_flips_to_verified(self, snapshot_current):
        verdict, _ = snapshot_current.lookup_algorithm("jcs-n", pinned=False)
        assert verdict == VERDICT_VERIFIED
        assert verdict != VERDICT_UNKNOWN_ID

    # Mutant: change pinned=False to pinned=True — verdict MUST flip to id-unknown-to-snapshot
    def test_mutant_pinned_true_flips_verdict_for_absent_id(self, snapshot_old):
        # With old snapshot: as-transmitted is absent
        # pinned=False (authoritative) → unknown-id
        # pinned=True (snapshot)      → id-unknown-to-snapshot
        live_verdict, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=False)
        pinned_verdict, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=True)
        assert live_verdict == VERDICT_UNKNOWN_ID
        assert pinned_verdict == VERDICT_ID_UNKNOWN_TO_SNAPSHOT
        # Removing the pinned=False condition flips the verdict — mutant is detected
        assert live_verdict != pinned_verdict


# ---------------------------------------------------------------------------
# VERDICT_ID_UNKNOWN_TO_SNAPSHOT  (pinned-snapshot check)
# ---------------------------------------------------------------------------

class TestVerdictIdUnknownToSnapshot:
    def test_new_id_absent_from_old_snapshot(self, snapshot_old):
        """as-transmitted is absent from the old snapshot → id-unknown-to-snapshot."""
        verdict, entry = snapshot_old.lookup_algorithm("as-transmitted", pinned=True)
        assert verdict == VERDICT_ID_UNKNOWN_TO_SNAPSHOT
        assert entry is None

    def test_entry_is_none_on_snapshot_miss(self, snapshot_old):
        verdict, entry = snapshot_old.lookup_algorithm("as-transmitted")
        assert entry is None

    # Mutant: use current snapshot (has the id) — verdict MUST flip to verified
    def test_mutant_current_snapshot_flips_to_verified(self, snapshot_current):
        verdict, _ = snapshot_current.lookup_algorithm("as-transmitted", pinned=True)
        assert verdict == VERDICT_VERIFIED
        assert verdict != VERDICT_ID_UNKNOWN_TO_SNAPSHOT

    # Mutant: flip pinned from True to False — MUST NOT produce id-unknown-to-snapshot
    def test_mutant_pinned_false_flips_verdict(self, snapshot_old):
        pinned_verdict, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=True)
        live_verdict, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=False)
        assert pinned_verdict == VERDICT_ID_UNKNOWN_TO_SNAPSHOT
        assert live_verdict != VERDICT_ID_UNKNOWN_TO_SNAPSHOT


# ---------------------------------------------------------------------------
# Distinctness: unknown-id and id-unknown-to-snapshot MUST be different strings
# ---------------------------------------------------------------------------

class TestVerdictDistinctness:
    def test_verdict_strings_are_distinct(self):
        assert VERDICT_UNKNOWN_ID != VERDICT_ID_UNKNOWN_TO_SNAPSHOT

    def test_both_verdicts_distinct_from_verified(self):
        assert VERDICT_UNKNOWN_ID != VERDICT_VERIFIED
        assert VERDICT_ID_UNKNOWN_TO_SNAPSHOT != VERDICT_VERIFIED

    def test_same_id_same_snapshot_different_pinned_gives_different_verdict(
        self, snapshot_old
    ):
        """The pinned flag is the only axis that changes; the verdicts diverge."""
        v_pinned, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=True)
        v_live, _ = snapshot_old.lookup_algorithm("as-transmitted", pinned=False)
        assert v_pinned == VERDICT_ID_UNKNOWN_TO_SNAPSHOT
        assert v_live == VERDICT_UNKNOWN_ID
        assert v_pinned != v_live


# ---------------------------------------------------------------------------
# Snapshot integrity (content-address verification)
# ---------------------------------------------------------------------------

class TestSnapshotIntegrity:
    def test_valid_snapshot_loads(self):
        data = _build_snapshot({"jcs-n": _JCS_N_ENTRY})
        snap = RegistrySnapshot.from_dict(data, verify=True)
        assert len(snap.snapshot_sha256) == 64
        assert all(c in "0123456789abcdef" for c in snap.snapshot_sha256)

    def test_tampered_content_raises(self):
        data = _build_snapshot({"jcs-n": _JCS_N_ENTRY})
        # Inject an extra entry after the sha was computed
        data["canonicalization_algorithms"]["injected"] = {"status": "Registered"}
        with pytest.raises(SnapshotIntegrityError):
            RegistrySnapshot.from_dict(data, verify=True)

    def test_tampered_sha_raises(self):
        data = _build_snapshot({"jcs-n": _JCS_N_ENTRY})
        data["snapshot_sha256"] = "a" * 64
        with pytest.raises(SnapshotIntegrityError):
            RegistrySnapshot.from_dict(data, verify=True)

    def test_snapshot_sha256_is_deterministic(self):
        data_a = _build_snapshot({"jcs-n": _JCS_N_ENTRY})
        data_b = _build_snapshot({"jcs-n": _JCS_N_ENTRY})
        assert data_a["snapshot_sha256"] == data_b["snapshot_sha256"]

    def test_different_content_different_sha(self):
        sha_a = _build_snapshot({"jcs-n": _JCS_N_ENTRY})["snapshot_sha256"]
        sha_b = _build_snapshot(
            {"jcs-n": _JCS_N_ENTRY, "as-transmitted": _AS_TRANSMITTED_ENTRY}
        )["snapshot_sha256"]
        assert sha_a != sha_b


# ---------------------------------------------------------------------------
# Snapshot version reporting
# ---------------------------------------------------------------------------

class TestSnapshotVersionReporting:
    def test_snapshot_sha256_accessible(self, snapshot_old, snapshot_current):
        assert snapshot_old.snapshot_sha256 != snapshot_current.snapshot_sha256

    def test_snapshot_sha256_64_hex(self, snapshot_current):
        sha = snapshot_current.snapshot_sha256
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_schema_version_reported(self, snapshot_current):
        assert snapshot_current.schema_version == "1"


# ---------------------------------------------------------------------------
# Load from disk (round-trip via vectors/registry/)
# ---------------------------------------------------------------------------

class TestLoadFromDisk:
    def test_load_snapshot_v0(self):
        p = (
            pathlib.Path(__file__).parent.parent.parent
            / "vectors" / "registry" / "snapshot-v0.json"
        )
        if not p.exists():
            pytest.skip("vectors/registry/snapshot-v0.json not yet generated")
        snap = RegistrySnapshot.load(p)
        assert snap.snapshot_sha256  # non-empty
        assert "jcs-n" in snap._data["canonicalization_algorithms"]
        # as-transmitted is absent from v0
        verdict, _ = snap.lookup_algorithm("as-transmitted", pinned=True)
        assert verdict == VERDICT_ID_UNKNOWN_TO_SNAPSHOT

    def test_load_snapshot_v1(self):
        p = (
            pathlib.Path(__file__).parent.parent.parent
            / "vectors" / "registry" / "snapshot-v1.json"
        )
        if not p.exists():
            pytest.skip("vectors/registry/snapshot-v1.json not yet generated")
        snap = RegistrySnapshot.load(p)
        verdict, _ = snap.lookup_algorithm("as-transmitted", pinned=True)
        assert verdict == VERDICT_VERIFIED

    def test_load_registry_json(self):
        p = (
            pathlib.Path(__file__).parent.parent.parent
            / "registry.json"
        )
        if not p.exists():
            pytest.skip("registry.json not yet generated")
        snap = RegistrySnapshot.load(p)
        # All Registered algorithms must be findable
        for alg_id, entry in snap._data["canonicalization_algorithms"].items():
            if entry.get("status") == "Registered":
                verdict, _ = snap.lookup_algorithm(alg_id)
                assert verdict == VERDICT_VERIFIED, f"registered id {alg_id!r} not found"


# ---------------------------------------------------------------------------
# The live/held classification must cover every status the registry actually
# uses. registry.json carries no vocabulary, so the set in registry.py mirrors
# REGISTRY.md rather than reading it -- this is the guard on that mirror.
# ---------------------------------------------------------------------------

def test_every_status_in_the_snapshot_is_classified():
    """A status that is neither live nor held would silently read as held.

    That is the failure this catches: `jcs` merged with status
    `standards-referenced`, which was not in the live set, and a fully
    specified RFC 8785 entry reported as a pre-registration hold.
    """
    import json as _json
    import pathlib as _pathlib
    from cpb.registry import _HELD_STATUSES, _LIVE_STATUSES

    snapshot = _json.loads(
        (_pathlib.Path(__file__).resolve().parents[2] / "registry.json").read_text(encoding="utf-8")
    )
    present = {e.get("status") for e in snapshot["canonicalization_algorithms"].values()}
    present |= {e.get("status") for e in snapshot["artifact_types"].values()}

    unclassified = present - _LIVE_STATUSES - _HELD_STATUSES
    assert not unclassified, (
        f"registry.json carries status(es) {sorted(unclassified)} that registry.py "
        f"classifies as neither live nor held; a lookup would report them held. "
        f"Classify them against REGISTRY.md's Entry Status Vocabulary."
    )
    assert not (_LIVE_STATUSES & _HELD_STATUSES), "a status cannot be both live and held"


def test_live_entries_verify_and_held_entries_do_not():
    """Two-sided, against the committed snapshot rather than a fixture."""
    import pathlib as _pathlib
    from cpb.registry import VERDICT_RESERVED, VERDICT_VERIFIED, RegistrySnapshot

    snap = RegistrySnapshot.load(_pathlib.Path(__file__).resolve().parents[2] / "registry.json")
    assert snap.lookup_algorithm("jcs")[0] == VERDICT_VERIFIED, (
        "a standards-referenced entry is a live registration"
    )
    assert snap.lookup_algorithm("jcs-n")[0] == VERDICT_RESERVED, (
        "jcs-n is withdrawn (2026-08-18) — a held name has no live registration "
        "to verify against, same as a Reserved name"
    )
    assert snap.lookup_algorithm("cde-n")[0] == VERDICT_RESERVED, (
        "a Reserved name has no defined semantics to verify against"
    )
