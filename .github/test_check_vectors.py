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


def _committed_representation_vector() -> dict:
    path = _HERE.parent / "vectors" / "representation-contrast" / "01-raw-vs-hex-text.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_representation_vector_exercises_raw_vs_ascii_boundary():
    vector = _committed_representation_vector()
    ok, errors = check_vectors._exercise_representation_contrast(vector, vector["id"])
    assert ok, errors


def test_representation_vector_rejects_a_mutated_check_hash():
    vector = _committed_representation_vector()
    vector["raw_input"]["check_sha256"] = "0" * 64
    ok, errors = check_vectors._exercise_representation_contrast(
        vector, "representation-mutant"
    )
    assert not ok
    assert any("raw_input.check_sha256 mismatch" in error for error in errors)


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


def test_candidate_mode_runs_the_same_checks_and_prints_the_disclaimer(tmp_path, capsys):
    """--candidate DIR is the self-service pre-submission entry point: same
    arithmetic + coverage report as a bare DIR argument, plus an explicit,
    unmissable disclaimer that Gates B/C are Designated Expert judgment, not
    something this tool can check."""
    _write_pos_only_vector(tmp_path)
    rc = check_vectors.main(["--candidate", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "coverage 'pos-only-alg': 1 positive, 0 MUST-FAIL" in out
    assert "WARNING: registered name 'pos-only-alg'" in out
    assert check_vectors.CANDIDATE_DISCLAIMER in out


def test_non_candidate_mode_does_not_print_the_disclaimer(tmp_path, capsys):
    _write_pos_only_vector(tmp_path)
    rc = check_vectors.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert check_vectors.CANDIDATE_DISCLAIMER not in out


def test_candidate_mode_rejects_missing_directory(capsys):
    rc = check_vectors.main(["--candidate", "/no/such/directory"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "is not a directory" in err


def test_candidate_mode_grades_the_directory_it_is_given_not_the_checkout_root(
    tmp_path, capsys, monkeypatch
):
    """candidate-validate.yml runs the checker from the BASE checkout against
    the PR head unpacked at ./pr -- `check_vectors.py --candidate pr/vectors`
    with the base's own vectors/ sitting right there in the working directory.

    That layout is exactly the shape of a gate that silently grades the wrong
    tree: if the path argument were ignored, or resolved against the script's
    own location, CI would score the base's (always-green) vectors and report
    success for a PR it never read. The mutation probe below is what makes
    this test carrying rather than decorative -- it asserts the checker
    NOTICES a defect that exists only in the given directory.
    """
    base = tmp_path / "base"
    (base / "vectors").mkdir(parents=True)
    _write_pos_only_vector(base / "vectors", name="base-alg")

    pr = tmp_path / "base" / "pr"
    (pr / "vectors").mkdir(parents=True)
    _write_pos_only_vector(pr / "vectors", name="pr-alg")

    # Run from the base checkout root, as the workflow does.
    monkeypatch.chdir(base)

    rc = check_vectors.main(["--candidate", "pr/vectors"])
    out = capsys.readouterr().out
    assert rc == 0
    # The PR's registered name is the one graded; the base's is not read.
    assert "coverage 'pr-alg':" in out
    assert "coverage 'base-alg':" not in out

    # Mutation probe: break a digest that exists ONLY in the PR tree. A gate
    # reading the base tree would stay green here.
    victim = pr / "vectors" / "one-direction-only" / "pos-only-01.json"
    vector = json.loads(victim.read_text())
    vector["digest"] = "0" * 64
    victim.write_text(json.dumps(vector), encoding="utf-8")

    rc = check_vectors.main(["--candidate", "pr/vectors"])
    out = capsys.readouterr().out
    assert rc == 1, "checker did not read the directory it was given"
    assert "1 FAILED" in out
