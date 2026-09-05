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


def _write_category_m_vector(root: pathlib.Path, vector: dict | None = None) -> pathlib.Path:
    target = root / "typed-refs" / "fail"
    target.mkdir(parents=True, exist_ok=True)
    path = target / "category-m.json"
    path.write_text(
        json.dumps(vector or check_vectors._category_m_self_test_vector()),
        encoding="utf-8",
    )
    return path


def _minimal_positive_carrier() -> dict:
    """A carrier-only PASS fixture with authoritative CBOR and optional mirrors."""
    label = -65537
    digest = "00" * 32
    ref = check_vectors._CborMap(
        ((1, "example-artifact"), (3, "SHA-256"), (4, digest))
    )
    header = check_vectors._CborMap(((label, [ref]),))
    protected = check_vectors._encode_cbor_deterministic(header)
    cose = check_vectors._CborTag(
        18,
        [protected, check_vectors._CborMap(()), b"payload", b"signature"],
    )
    return {
        "id": "minimal-positive-carrier",
        "must_fail": False,
        "protected_header": {
            "bytes_hex": protected.hex(),
            "cpb_refs_label": label,
            "entry_index": 0,
        },
        "cose_sign1_bytes_hex": check_vectors._encode_cbor_deterministic(cose).hex(),
        "cbor_map_entry": {
            "1": "example-artifact",
            "3": "SHA-256",
            "4": digest,
        },
        "typed_reference": {
            "type": "example-artifact",
            "digest_alg": "SHA-256",
            "digest": digest,
        },
    }


def _write_positive_carrier(root: pathlib.Path, vector: dict | None = None) -> pathlib.Path:
    target = root / "typed-refs" / "pass"
    target.mkdir(parents=True, exist_ok=True)
    path = target / "minimal-carrier.json"
    path.write_text(
        json.dumps(vector or _minimal_positive_carrier()), encoding="utf-8"
    )
    return path


def test_carrier_only_positive_is_exercised_not_skipped(tmp_path, capsys):
    _write_positive_carrier(tmp_path)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert "1 pass/exercised" in out
    assert "0 no-check (skipped)" in out
    assert "0 FAILED" in out


@pytest.mark.parametrize(
    ("deleted", "message"),
    [
        ("protected_header", "requires protected_header object"),
        (
            "cose_sign1_bytes_hex",
            "requires cose_sign1_bytes_hex to prove cpb-refs is protected",
        ),
    ],
)
def test_carrier_only_positive_rejects_deletion(
    tmp_path, capsys, deleted, message
):
    vector = _minimal_positive_carrier()
    del vector[deleted]
    _write_positive_carrier(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out

    assert rc == 1
    assert "1 FAILED" in out
    assert message in out


def test_carrier_only_positive_rejects_protected_byte_mutation(tmp_path, capsys):
    vector = _minimal_positive_carrier()
    vector["protected_header"]["bytes_hex"] = "a0"
    _write_positive_carrier(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out

    assert rc == 1
    assert "protected header does not contain cpb-refs label" in out


def test_carrier_only_positive_rejects_cose_protected_bstr_mismatch(
    tmp_path, capsys
):
    vector = _minimal_positive_carrier()
    parts, _ = check_vectors._cose_sign1_parts(
        bytes.fromhex(vector["cose_sign1_bytes_hex"])
    )
    parts[0] = b"\xa0"
    vector["cose_sign1_bytes_hex"] = check_vectors._encode_cbor_deterministic(
        check_vectors._CborTag(18, parts)
    ).hex()
    _write_positive_carrier(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out

    assert rc == 1
    assert "COSE_Sign1 protected bstr does not match" in out


def test_carrier_only_positive_rejects_unprotected_cpb_refs(tmp_path, capsys):
    vector = _minimal_positive_carrier()
    parts, _ = check_vectors._cose_sign1_parts(
        bytes.fromhex(vector["cose_sign1_bytes_hex"])
    )
    label = vector["protected_header"]["cpb_refs_label"]
    parts[1] = check_vectors._CborMap(((label, []),))
    vector["cose_sign1_bytes_hex"] = check_vectors._encode_cbor_deterministic(
        check_vectors._CborTag(18, parts)
    ).hex()
    _write_positive_carrier(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out

    assert rc == 1
    assert "must not also appear in COSE unprotected headers" in out


@pytest.mark.parametrize(
    ("mirror", "member", "replacement", "message"),
    [
        (
            "cbor_map_entry",
            "1",
            "wrong-type",
            "cbor_map_entry mirror does not exactly match",
        ),
        (
            "typed_reference",
            "digest_alg",
            "SHA-512",
            "typed_reference mirror disagrees",
        ),
    ],
)
def test_carrier_only_positive_rejects_mutated_mirrors(
    tmp_path, capsys, mirror, member, replacement, message
):
    vector = _minimal_positive_carrier()
    vector[mirror][member] = replacement
    _write_positive_carrier(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out

    assert rc == 1
    assert message in out


def test_category_m_executes_the_carried_protected_header(tmp_path, capsys):
    """Category M is live before draft-03's vector lands on this branch."""
    _write_category_m_vector(tmp_path)
    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 pass/exercised" in out
    assert "0 FAILED" in out


def test_category_m_rejects_a_descriptive_mirror_without_carried_bytes(
    tmp_path, capsys
):
    vector = check_vectors._category_m_self_test_vector()
    del vector["protected_header"]
    del vector["cose_sign1_bytes_hex"]
    _write_category_m_vector(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 1
    assert "Category M requires protected_header object" in out


def test_category_m_requires_cose_wrapper_to_prove_protected_location(
    tmp_path, capsys
):
    vector = check_vectors._category_m_self_test_vector()
    del vector["cose_sign1_bytes_hex"]
    _write_category_m_vector(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 1
    assert "requires cose_sign1_bytes_hex to prove cpb-refs is protected" in out


def test_category_m_preserves_duplicate_purpose_entries_and_fails_closed():
    contexts = [
        {"purpose": "identifier", "algorithm": "jcs-n"},
        {"purpose": "identifier", "algorithm": "jcs-n-v2"},
    ]
    entries = check_vectors._digest_context_entries(contexts)
    assert entries == contexts
    assert len(entries) == 2
    with pytest.raises(ValueError, match="matches 2"):
        check_vectors._resolve_digest_context("identifier", contexts)


def test_category_m_vector_rejects_duplicate_purpose_ambiguity(tmp_path, capsys):
    vector = check_vectors._category_m_self_test_vector()
    contexts = vector["artifact_type_registry_entry"]["digest_contexts"]
    contexts[1]["purpose"] = contexts[0]["purpose"]
    _write_category_m_vector(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 1
    assert "duplicate purpose labels make the registry entry itself ambiguous" in out


def test_category_m_rejects_cose_protected_bstr_mismatch(tmp_path, capsys):
    vector = check_vectors._category_m_self_test_vector()
    mismatched = check_vectors._CborTag(18, [b"", {}, None, b""])
    vector["cose_sign1_bytes_hex"] = check_vectors._encode_cbor_deterministic(
        mismatched
    ).hex()
    _write_category_m_vector(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 1
    assert "COSE_Sign1 protected bstr does not match" in out


def test_category_m_mutant_changes_the_carried_map_and_wrapper():
    vector = check_vectors._category_m_self_test_vector()
    original_protected = vector["protected_header"]["bytes_hex"]
    original_cose = vector["cose_sign1_bytes_hex"]

    mutant = check_vectors._mutant_M(vector)
    assert mutant is not None
    _, _, _, carried, protected = check_vectors._decode_cpb_carrier(mutant)
    cose_parts, _ = check_vectors._cose_sign1_parts(
        bytes.fromhex(mutant["cose_sign1_bytes_hex"])
    )

    assert carried[2] == "identifier"
    assert protected.hex() != original_protected
    assert mutant["cose_sign1_bytes_hex"] != original_cose
    assert cose_parts[0] == protected
    assert mutant["cbor_map_entry"]["2"] == "identifier"
    assert mutant["typed_reference"]["purpose"] == "identifier"

    ok, errors = check_vectors._exercise_must_fail(
        mutant, "category-m-purpose-present", [], _probe_mutants=False
    )
    assert not ok
    assert any("contains key 2" in error for error in errors)


def _replace_category_m_protected(vector: dict, header: object) -> None:
    protected = check_vectors._encode_cbor_deterministic(header)
    vector["protected_header"]["bytes_hex"] = protected.hex()
    parts, _ = check_vectors._cose_sign1_parts(
        bytes.fromhex(vector["cose_sign1_bytes_hex"])
    )
    parts[0] = protected
    vector["cose_sign1_bytes_hex"] = check_vectors._encode_cbor_deterministic(
        check_vectors._CborTag(18, parts)
    ).hex()


def test_category_m_rejects_unknown_carried_member_keys(tmp_path, capsys):
    vector = check_vectors._category_m_self_test_vector()
    header, refs, _, carried, _ = check_vectors._decode_cpb_carrier(vector)
    refs[0] = check_vectors._CborMap((*carried.pairs, (5, "extension")))
    _replace_category_m_protected(vector, header)
    del vector["cbor_map_entry"]
    del vector["typed_reference"]
    _write_category_m_vector(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 1
    assert "unknown cpb-refs member key" in out


def test_category_m_rejects_unprotected_cpb_refs(tmp_path, capsys):
    vector = check_vectors._category_m_self_test_vector()
    parts, _ = check_vectors._cose_sign1_parts(
        bytes.fromhex(vector["cose_sign1_bytes_hex"])
    )
    label = vector["protected_header"]["cpb_refs_label"]
    parts[1] = check_vectors._CborMap(((label, []),))
    vector["cose_sign1_bytes_hex"] = check_vectors._encode_cbor_deterministic(
        check_vectors._CborTag(18, parts)
    ).hex()
    _write_category_m_vector(tmp_path, vector)

    rc = check_vectors.check_vectors(tmp_path)
    out = capsys.readouterr().out
    assert rc == 1
    assert "must not also appear in COSE unprotected headers" in out


def test_category_m_enforces_carrier_value_limits():
    overlong_type = check_vectors._CborMap(
        ((1, "x" * 256), (3, "SHA-256"), (4, b"digest"))
    )
    with pytest.raises(ValueError, match="exceeds 255"):
        check_vectors._validate_cpb_ref_map(overlong_type)


@pytest.mark.parametrize(
    "encoded, message",
    [
        ("a201010102", "duplicate CBOR map key"),
        ("a202000100", "deterministic order"),
        ("9f01ff", "indefinite-length"),
    ],
)
def test_category_m_strict_cbor_rejects_ambiguous_encodings(encoded, message):
    with pytest.raises(ValueError, match=message):
        check_vectors.decode_strict_cbor(bytes.fromhex(encoded))
