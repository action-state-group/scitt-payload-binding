#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate registry/entries/*.yaml against registry/entry.schema.json, and
mechanically enforce that a declared vector set actually EXECUTES.

This is the CI-side half of the join-without-asking registration path
documented in registry/README.md. Two independent things are checked per
entry file:

  1. Schema shape — every required field for the entry's rung is present and
     well-formed (registry/entry.schema.json, itself the machine-checkable
     form of REGISTRY.md's Entry Template and the seven registration
     questions).

  2. Vector execution — if the entry declares `fixtures.vectors_dir` (a path
     to vectors committed IN THIS REPO), those vectors are run through
     .github/check_vectors.py and the entry is REJECTED if any vector fails
     to execute cleanly, or if the vectors_dir does not exist at all. An
     entry whose vectors_dir is declared but never actually runs is exactly
     the gap this script exists to close — "vector-backed" must mean
     "mechanically exercised", not "a path was typed into a document".

     Two-sidedness (Registration Rule 2: positive AND MUST-FAIL vectors) is
     enforced as a HARD FAILURE for rungs that claim to be complete enough to
     leave `provisional` (owner_authored, third_party_documented). For a
     `provisional` entry it is only a warning, mirroring
     check_vectors.py's own --candidate behavior — incompleteness is what
     `provisional` is for.

     An entry may instead cite `fixtures.external_vector_set` (a third
     party's own published, commit-pinned vectors, per Third-Party
     Registration Rule 4) — this repository cannot execute another
     repository's test suite, so that path is checked for a well-formed
     commit pin only, not executed.

This script does not, and cannot, evaluate the Designated Expert Admission
Checklist's Gates A/B/C (discriminating vector judgment, consuming-profile
adequacy, independence) -- those remain human judgment, exactly as
REGISTRY.md and check_vectors.py's own CANDIDATE_DISCLAIMER already state.

Usage:
    python3 .github/validate_registry_entries.py [ENTRIES_DIR]
Exit 0 = every entry file validates and every declared local vector set runs
clean; 1 = at least one entry failed; 2 = misconfiguration (missing schema,
no PyYAML, etc).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only in a misconfigured env
    print("error: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

try:
    import jsonschema
except ImportError:  # pragma: no cover
    print("error: jsonschema is required (pip install jsonschema)", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "registry" / "entry.schema.json"
DEFAULT_ENTRIES_DIR = REPO_ROOT / "registry" / "entries"
CHECK_VECTORS = REPO_ROOT / ".github" / "check_vectors.py"
TEMPLATE_NAME = "TEMPLATE.yaml"

_COMPLETE_RUNGS = frozenset({"owner_authored", "third_party_documented"})

_VECTORS_SUMMARY_RE = re.compile(
    r"vectors:\s*(?P<passed>\d+) pass/exercised,\s*(?P<diverged>\d+) diverged,\s*"
    r"(?P<informative>\d+) informative,\s*(?P<skipped>\d+) no-check \(skipped\),\s*"
    r"(?P<failed>\d+) FAILED"
)
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")


class EntryError(Exception):
    """A single entry file failed validation; message is human-readable."""


def load_schema() -> dict:
    if not SCHEMA_PATH.is_file():
        print(f"error: schema not found at {SCHEMA_PATH}", file=sys.stderr)
        sys.exit(2)
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def iter_entry_files(entries_dir: Path) -> list[Path]:
    return sorted(p for p in entries_dir.glob("*.yaml") if p.name != TEMPLATE_NAME)


def validate_schema(entry: object, path: Path, schema: dict) -> None:
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(entry), key=lambda e: list(e.path))
    if errors:
        msgs = []
        for e in errors:
            where = "/".join(str(p) for p in e.path) or "<root>"
            msgs.append(f"{path.name}: {where}: {e.message}")
        raise EntryError("\n".join(msgs))


def _looks_like_vector(v: object) -> bool:
    if not isinstance(v, dict):
        return False
    return "input" in v or "pre_image" in v or v.get("diverge") or v.get("must_fail")


def count_two_sidedness(vectors_dir: Path) -> tuple[int, int]:
    """(positive_count, must_fail_count) across every *.json under vectors_dir.

    Deliberately independent of check_vectors.py's own coverage dict, which
    keys coverage off each vector's ``algorithm`` field -- a convention built
    for the Payload Canonicalization Algorithm Registry that artifact-type
    vectors are not guaranteed to carry. Counting must_fail vs positive
    directly makes this check apply uniformly to both registries.
    """
    positive = must_fail = 0
    for f in sorted(vectors_dir.rglob("*.json")):
        try:
            v = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue  # check_vectors.py already rejects this; don't double-report
        if not _looks_like_vector(v):
            continue
        if v.get("must_fail"):
            must_fail += 1
        else:
            positive += 1
    return positive, must_fail


def run_check_vectors(vectors_dir: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(CHECK_VECTORS), str(vectors_dir)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    return result.returncode, (result.stdout + result.stderr)


def validate_fixtures(entry: dict, path: Path) -> list[str]:
    """Returns non-fatal warnings; raises EntryError on a hard failure."""
    warnings: list[str] = []
    rung = entry["rung"]
    fixtures = entry.get("fixtures") or {}
    vectors_dir_field = fixtures.get("vectors_dir")
    external = fixtures.get("external_vector_set")

    if not vectors_dir_field and not external:
        if rung in _COMPLETE_RUNGS:
            raise EntryError(
                f"{path.name}: rung {rung!r} requires fixtures.vectors_dir "
                f"(in-repo vectors) or fixtures.external_vector_set (a cited "
                f"owner-published set) — Registration Rule 2."
            )
        return warnings  # provisional / reserved may file with no vectors yet

    if vectors_dir_field:
        vectors_dir = REPO_ROOT / vectors_dir_field
        if not vectors_dir.is_dir():
            raise EntryError(
                f"{path.name}: fixtures.vectors_dir {vectors_dir_field!r} "
                f"does not exist — a declared vector set that isn't committed "
                f"cannot run, and an entry whose vectors don't run is rejected."
            )

        rc, output = run_check_vectors(vectors_dir)
        match = _VECTORS_SUMMARY_RE.search(output)
        if not match:
            raise EntryError(
                f"{path.name}: could not parse check_vectors.py output for "
                f"{vectors_dir_field}; treating as failed to run:\n{output}"
            )
        failed = int(match.group("failed"))
        if rc != 0 or failed > 0:
            raise EntryError(
                f"{path.name}: declared vectors under {vectors_dir_field} did "
                f"not execute cleanly ({failed} FAILED, exit {rc}):\n{output}"
            )

        positive, must_fail = count_two_sidedness(vectors_dir)
        if positive == 0 or must_fail == 0:
            msg = (
                f"{path.name}: fixtures.vectors_dir {vectors_dir_field} is not "
                f"two-sided ({positive} positive, {must_fail} MUST-FAIL) — "
                f"Registration Rule 2 requires both directions."
            )
            if rung in _COMPLETE_RUNGS:
                raise EntryError(msg)
            warnings.append("WARNING: " + msg + " (allowed at rung=provisional)")

    elif external:
        commit = external.get("commit", "")
        if not _COMMIT_RE.match(commit):
            raise EntryError(
                f"{path.name}: fixtures.external_vector_set.commit {commit!r} "
                f"is not a commit-hash pin (Third-Party Registration Rule 1: "
                f"a branch or tag alone is not a pin)."
            )

    return warnings


def validate_entry_file(path: Path, schema: dict) -> list[str]:
    """Returns warnings for one entry file. Raises EntryError on hard failure."""
    try:
        entry = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise EntryError(f"{path.name}: invalid YAML: {exc}") from exc

    if not isinstance(entry, dict):
        raise EntryError(f"{path.name}: top-level document must be a mapping")

    validate_schema(entry, path, schema)
    return validate_fixtures(entry, path)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    entries_dir = Path(argv[0]) if argv else DEFAULT_ENTRIES_DIR

    if not entries_dir.is_dir():
        print(f"error: {entries_dir} is not a directory", file=sys.stderr)
        return 2

    schema = load_schema()
    entry_files = iter_entry_files(entries_dir)
    if not entry_files:
        print(f"no *.yaml entry files under {entries_dir} (TEMPLATE.yaml excluded)")
        return 0

    problems: list[str] = []
    for path in entry_files:
        try:
            warnings = validate_entry_file(path, schema)
        except EntryError as exc:
            problems.append(str(exc))
            continue
        for w in warnings:
            print(w)
        entry = yaml.safe_load(path.read_text(encoding="utf-8"))
        print(f"OK   {path.name}  ({entry['rung']} / {entry['status']})")

    if problems:
        print("\nFAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(f"\n{len(entry_files)} registry entry file(s) validated clean.")
    print(
        "Mechanical checks only — Designated Expert Admission Checklist Gates "
        "A/B/C (discriminating vector, consuming profile, independence) are "
        "human judgment and are NOT checked here."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
