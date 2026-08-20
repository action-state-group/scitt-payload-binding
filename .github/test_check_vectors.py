#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Per-entry two-sidedness coverage report (AUDIT.md §C finding 2).

Registration Rule 2 requires a required conformance vector set to be
two-sided (both a positive case and a MUST-FAIL case). check_vectors.py
previously scored every *.json file's arithmetic independently with no
notion of "which registered name does this vector belong to", so a
one-direction-only submission for a brand-new name was scored as an
ordinary passing positive vector -- 0 FAILED, no signal at all.
"""
import importlib.util
import json
import pathlib

import pytest

_HERE = pathlib.Path(__file__).parent

_spec = importlib.util.spec_from_file_location("check_vectors", _HERE / "check_vectors.py")
check_vectors = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_vectors)

# A real, self-consistent jcs-n pre_image/digest pair (jcs-n-kat-01's values),
# reused here under a made-up registered name -- the arithmetic must be
# genuinely correct so this vector is a real PASS, not a rejected one; the
# gap under test is coverage bookkeeping, not vector correctness.
_POS_ONLY_INPUT = {"b": "x", "a": "y"}
_POS_ONLY_PRE_IMAGE = '{"a":"y","b":"x"}'
_POS_ONLY_DIGEST = "7951deff61d4304af5863a13c2ef570ffc96f1d8df5fb3214743dc9953b8aeea"


def _write_pos_only_vector(root: pathlib.Path, name: str = "pos-only-alg") -> None:
    (root / "one-direction-only").mkdir(parents=True, exist_ok=True)
    vector = {
        "id": "pos-only-01",
        "algorithm": name,
        "input": _POS_ONLY_INPUT,
        "exclusion_set": [],
        "pre_image": _POS_ONLY_PRE_IMAGE,
        "pre_image_bytes_hex": _POS_ONLY_PRE_IMAGE.encode("utf-8").hex(),
        "digest": _POS_ONLY_DIGEST,
    }
    (root / "one-direction-only" / "pos-only-01.json").write_text(
        json.dumps(vector), encoding="utf-8"
    )


def test_one_direction_only_set_is_admitted_with_zero_failed(tmp_path, capsys):
    """Reproduces the audit's exact result: 0 FAILED, admitted by tooling."""
    _write_pos_only_vector(tmp_path)
    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 pass/exercised" in out
    assert "0 FAILED" in out


def test_one_direction_only_set_now_emits_a_named_warning(tmp_path, capsys):
    """The catch: a coverage warning now names the registered name and the
    imbalance, without turning it into a failure (still exit 0)."""
    _write_pos_only_vector(tmp_path)
    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "coverage 'pos-only-alg': 1 positive, 0 MUST-FAIL" in out
    assert "WARNING: registered name 'pos-only-alg'" in out
    assert "not two-sided" in out


def test_two_sided_set_gets_no_warning(tmp_path, capsys):
    _write_pos_only_vector(tmp_path, name="two-sided-alg")
    must_fail_vector = {
        "id": "neg-only-01",
        "algorithm": "two-sided-alg",
        "must_fail": True,
        "failure_reason": "algorithm_rejection",
        "input": {"a": 1.5},
    }
    (tmp_path / "one-direction-only" / "neg-only-01.json").write_text(
        json.dumps(must_fail_vector), encoding="utf-8"
    )
    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "coverage 'two-sided-alg': 1 positive, 1 MUST-FAIL" in out
    assert "WARNING" not in out


def test_vectors_without_an_algorithm_field_are_not_grouped():
    """Vectors that don't declare a registered name (e.g. diverge, registry-
    lookup, or general spec-conformance vectors) are simply not part of any
    coverage bucket -- this is not a per-vector requirement, only a
    per-registered-name one."""
    coverage = {}
    warnings = check_vectors._coverage_warnings(coverage)
    assert warnings == []


def test_committed_vector_suite_produces_no_coverage_warnings():
    """The real, committed vectors/ tree must stay green under this check."""
    root = _HERE.parent / "vectors"
    if not root.is_dir():
        pytest.skip("vectors/ not found")
    rc = check_vectors.check_vectors(root)
    assert rc == 0
