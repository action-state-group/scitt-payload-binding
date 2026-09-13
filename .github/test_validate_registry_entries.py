#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for validate_registry_entries.py — the CI gate for registry/entries/*.yaml.

Every hard-failure path here is proven to actually fail (not just asserted in
prose): a missing vectors_dir, a vectors_dir whose vectors don't run clean, a
one-sided set at a rung that requires two-sidedness, and a schema-invalid
entry. That is the mutation-test discipline QUEUE_PROTOCOL.md §7 requires for
any check that can reject something: a check that cannot be observed to fail
is not evidence.
"""
import importlib.util
import json
import pathlib

import pytest
import yaml

_HERE = pathlib.Path(__file__).parent

_spec = importlib.util.spec_from_file_location(
    "validate_registry_entries", _HERE / "validate_registry_entries.py"
)
vre = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vre)

# A real, self-consistent jcs-n pre_image/digest pair (mirrors
# test_check_vectors.py's fixture) -- reused so the arithmetic under test is
# genuinely correct, and only the coverage/execution bookkeeping is exercised.
_INPUT = {"b": "x", "a": "y"}
_PRE_IMAGE = '{"a":"y","b":"x"}'
_DIGEST = "7951deff61d4304af5863a13c2ef570ffc96f1d8df5fb3214743dc9953b8aeea"


def _positive_vector(vec_id="pos-01"):
    return {
        "id": vec_id,
        "algorithm": "jcs-n",
        "input": _INPUT,
        "exclusion_set": [],
        "pre_image": _PRE_IMAGE,
        "pre_image_bytes_hex": _PRE_IMAGE.encode("utf-8").hex(),
        "digest": _DIGEST,
    }


def _broken_positive_vector(vec_id="pos-broken-01"):
    """Same shape as _positive_vector but with a digest that does not match —
    the mutant proving run_check_vectors can actually observe a FAILED case."""
    v = _positive_vector(vec_id)
    v["digest"] = "0" * 64
    return v


def _must_fail_vector(vec_id="neg-01"):
    return {
        "id": vec_id,
        "algorithm": "jcs-n",
        "must_fail": True,
        "failure_reason": "float_rejected",
        "input": {"a": 1.5},
    }


def _base_entry(**overrides):
    entry = {
        "name": "widget-record",
        "target_registry": "artifact_types",
        "rung": "provisional",
        "status": "provisional",
        "reference": "example-org/widget @ 0123456789abcdef0123456789abcdef01234567",
        "owner": {"name": "Example Org", "affiliation": "Example Org"},
        "de_reviewer": "TBD",
        "open_questions": ["TBD"],
        "seven_questions": {
            "digest_input_bytes": "all widget fields",
            "exclusion_set": "none",
            "canonicalization_profile": "jcs-n",
            "hash_algorithm": "SHA-256",
            "representation": "64-char lowercase hex",
            "composite_or_not": {"is_composite": False, "statement": "no composite members"},
            "cross_language_parity": {"statement": "not yet demonstrated — N/A, single implementation to date"},
        },
    }
    entry.update(overrides)
    return entry


def _write_entry(entries_dir: pathlib.Path, name: str, entry: dict) -> pathlib.Path:
    entries_dir.mkdir(parents=True, exist_ok=True)
    path = entries_dir / f"{name}.yaml"
    path.write_text(yaml.safe_dump(entry, sort_keys=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def test_reserved_entry_needs_no_seven_questions():
    schema = vre.load_schema()
    entry = {
        "name": "vto",
        "target_registry": "artifact_types",
        "rung": "reserved",
        "status": "reserved",
        "reference": "sibling filing [cpb-vto-provisional-entries]",
        "owner": {"name": "libp2p / VTO team"},
        "de_reviewer": "TBD",
        "open_questions": ["TBD — filed as a separate sibling entry"],
    }
    vre.validate_schema(entry, pathlib.Path("vto.yaml"), schema)  # must not raise


def test_reserved_entry_rejects_seven_questions_present():
    schema = vre.load_schema()
    entry = _base_entry(rung="reserved", status="reserved")
    with pytest.raises(Exception):
        vre.validate_schema(entry, pathlib.Path("bad.yaml"), schema)


def test_provisional_entry_missing_seven_questions_is_rejected():
    schema = vre.load_schema()
    entry = _base_entry()
    del entry["seven_questions"]
    with pytest.raises(Exception):
        vre.validate_schema(entry, pathlib.Path("bad.yaml"), schema)


def test_owner_authored_requires_status_owner_confirmed():
    schema = vre.load_schema()
    entry = _base_entry(rung="owner_authored", status="provisional", fixtures={"vectors_dir": "vectors/x"})
    with pytest.raises(Exception):
        vre.validate_schema(entry, pathlib.Path("bad.yaml"), schema)


# ---------------------------------------------------------------------------
# Fixture / vector execution — the "vectors don't run" gate
# ---------------------------------------------------------------------------

def test_provisional_entry_with_no_fixtures_is_allowed(tmp_path):
    entry = _base_entry()
    warnings = vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))
    assert warnings == []


def test_missing_vectors_dir_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    entry = _base_entry(
        rung="owner_authored",
        status="owner-confirmed",
        fixtures={"vectors_dir": "vectors/does-not-exist"},
    )
    with pytest.raises(vre.EntryError, match="does not exist"):
        vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))


def test_vectors_that_fail_to_execute_are_rejected(monkeypatch, tmp_path):
    """The mutant: a vector whose digest is wrong must make CI reject the entry."""
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    vdir = tmp_path / "vectors" / "widget-record"
    vdir.mkdir(parents=True)
    (vdir / "pos-broken.json").write_text(json.dumps(_broken_positive_vector()), encoding="utf-8")
    (vdir / "neg.json").write_text(json.dumps(_must_fail_vector()), encoding="utf-8")

    entry = _base_entry(
        rung="owner_authored",
        status="owner-confirmed",
        fixtures={"vectors_dir": "vectors/widget-record"},
    )
    with pytest.raises(vre.EntryError, match="did not execute cleanly"):
        vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))


def test_clean_two_sided_vectors_pass(monkeypatch, tmp_path):
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    vdir = tmp_path / "vectors" / "widget-record"
    vdir.mkdir(parents=True)
    (vdir / "pos.json").write_text(json.dumps(_positive_vector()), encoding="utf-8")
    (vdir / "neg.json").write_text(json.dumps(_must_fail_vector()), encoding="utf-8")

    entry = _base_entry(
        rung="owner_authored",
        status="owner-confirmed",
        fixtures={"vectors_dir": "vectors/widget-record"},
    )
    warnings = vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))
    assert warnings == []


def test_one_sided_vectors_hard_fail_at_owner_authored_rung(monkeypatch, tmp_path):
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    vdir = tmp_path / "vectors" / "widget-record"
    vdir.mkdir(parents=True)
    (vdir / "pos.json").write_text(json.dumps(_positive_vector()), encoding="utf-8")
    # no must_fail vector committed

    entry = _base_entry(
        rung="owner_authored",
        status="owner-confirmed",
        fixtures={"vectors_dir": "vectors/widget-record"},
    )
    with pytest.raises(vre.EntryError, match="not two-sided"):
        vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))


def test_one_sided_vectors_only_warns_at_provisional_rung(monkeypatch, tmp_path):
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    vdir = tmp_path / "vectors" / "widget-record"
    vdir.mkdir(parents=True)
    (vdir / "pos.json").write_text(json.dumps(_positive_vector()), encoding="utf-8")

    entry = _base_entry(fixtures={"vectors_dir": "vectors/widget-record"})  # rung=provisional
    warnings = vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))
    assert any("not two-sided" in w for w in warnings)


def test_external_vector_set_requires_real_commit_pin():
    entry = _base_entry(
        rung="third_party_documented",
        status="third-party-documented",
        registrant={"name": "Jane Doe", "self_attestation": "Registered by Jane Doe from widget-spec-01 / commit abc1234."},
        fixtures={"external_vector_set": {"repository": "owner/widget", "commit": "not-a-commit", "path": "vectors/"}},
    )
    with pytest.raises(vre.EntryError, match="not a commit-hash pin"):
        vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))


def test_external_vector_set_with_real_pin_is_not_executed_locally():
    entry = _base_entry(
        rung="third_party_documented",
        status="third-party-documented",
        registrant={"name": "Jane Doe", "self_attestation": "Registered by Jane Doe from widget-spec-01 / commit abc1234."},
        fixtures={"external_vector_set": {"repository": "owner/widget", "commit": "abc1234", "path": "vectors/"}},
    )
    warnings = vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))
    assert warnings == []


def test_owner_authored_without_any_fixtures_is_rejected():
    entry = _base_entry(rung="owner_authored", status="owner-confirmed")
    with pytest.raises(vre.EntryError, match="requires fixtures"):
        vre.validate_fixtures(entry, pathlib.Path("widget-record.yaml"))


# ---------------------------------------------------------------------------
# End-to-end over a directory, and TEMPLATE.yaml exclusion
# ---------------------------------------------------------------------------

def test_template_file_is_excluded_from_iteration(tmp_path):
    entries_dir = tmp_path / "entries"
    entries_dir.mkdir()
    (entries_dir / "TEMPLATE.yaml").write_text("name: not-real\n", encoding="utf-8")
    _write_entry(entries_dir, "widget-record", _base_entry())
    files = vre.iter_entry_files(entries_dir)
    assert [f.name for f in files] == ["widget-record.yaml"]


def test_main_returns_nonzero_on_a_bad_entry(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    entries_dir = tmp_path / "registry_entries"
    bad = _base_entry()
    del bad["reference"]  # required field missing
    _write_entry(entries_dir, "widget-record", bad)
    rc = vre.main([str(entries_dir)])
    assert rc == 1


def test_main_returns_zero_on_a_clean_directory(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vre, "REPO_ROOT", tmp_path)
    entries_dir = tmp_path / "registry_entries"
    _write_entry(entries_dir, "widget-record", _base_entry())
    rc = vre.main([str(entries_dir)])
    assert rc == 0


def test_the_committed_registry_entries_directory_validates_clean():
    """End-to-end smoke test against the real, committed entries — the same
    invocation CI runs. If this fails, a committed entry is broken."""
    rc = vre.main([str(vre.DEFAULT_ENTRIES_DIR)])
    assert rc == 0
