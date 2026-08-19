#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cell-fidelity test for gen_registry.py.

For every non-empty cell in REGISTRY.md's tables, assert the value actually
present in the generated registry.json under the correctly-normalized header
key. The raw table parse and the header normalization here are deliberately
NOT the ones gen_registry.py uses internally (_parse_md_table normalizes
headers as part of the same step being tested) -- reusing them would let a
normalization bug agree with itself. There is also no second hand-maintained
list of expected column values: headers and cells are read straight from
REGISTRY.md, so a renamed/added column is caught automatically instead of
needing a matching update to a fixture list.

This is the regression test for the bug where "Pre-image encoding" survived
normalization with its hyphen intact ("pre-image_encoding") while the lookup
used the underscore form ("pre_image_encoding"), silently dropping that field
from every digest context in the committed registry.json.
"""
import importlib.util
import pathlib
import re

import pytest

_HERE = pathlib.Path(__file__).parent
_REPO_ROOT = _HERE.parent
_REGISTRY_MD = _REPO_ROOT / "REGISTRY.md"

_spec = importlib.util.spec_from_file_location("gen_registry", _HERE / "gen_registry.py")
gen_registry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_registry)


def _normalize_header(raw: str) -> str:
    """Independent header normalization: lowercase, spaces AND hyphens -> '_'.

    Deliberately reimplemented rather than imported from gen_registry, so a
    bug in gen_registry's own normalization can't hide from this test.
    """
    return raw.strip().lower().replace(" ", "_").replace("-", "_")


def _raw_pipe_table(lines: list[str]) -> tuple[list[str] | None, list[list[str]]]:
    """Parse a markdown pipe-table into (raw headers, [raw row cells...]).

    Does not call gen_registry._parse_md_table: that function's header
    normalization is exactly what this test exists to check independently.
    """
    raw_headers: list[str] | None = None
    rows: list[list[str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if raw_headers is not None:
                break
            continue
        cells = [gen_registry._strip_md(c) for c in stripped.strip("|").split("|")]
        if raw_headers is None:
            raw_headers = cells
        elif all(re.match(r"^[-: ]+$", c) for c in cells):
            continue  # separator row
        else:
            rows.append(cells)
    return raw_headers, rows


@pytest.fixture(scope="module")
def registry_md_lines() -> list[str]:
    if not _REGISTRY_MD.exists():
        pytest.skip("REGISTRY.md not found")
    return _REGISTRY_MD.read_text(encoding="utf-8").splitlines(keepends=True)


@pytest.fixture(scope="module")
def generated(registry_md_lines) -> dict:
    return gen_registry.generate(_REGISTRY_MD)


class TestArtifactTypeCellFidelity:
    """Every cell in each artifact type's digest-context table must round-trip."""

    def test_every_nonempty_cell_round_trips(self, registry_md_lines, generated):
        section = gen_registry._section_lines(registry_md_lines, "Artifact Type Registry")
        subs = gen_registry._subsections(section)

        checked_rows = 0
        for sub_name, sub_lines in subs:
            if not sub_name:
                continue
            raw_headers, raw_rows = _raw_pipe_table(sub_lines)
            if raw_headers is None:
                continue  # this subsection has no digest-context table

            artifact = generated["artifact_types"].get(sub_name)
            assert artifact is not None, (
                f"artifact type {sub_name!r} found in REGISTRY.md but missing "
                f"from generated artifact_types"
            )

            norm_headers = [_normalize_header(h) for h in raw_headers]

            # Mirror gen_registry's own row filter (purpose or algorithm present)
            # so raw rows line up 1:1 with generated digest_contexts by position.
            kept_rows = []
            for raw_cells in raw_rows:
                norm_row = dict(zip(norm_headers, raw_cells))
                if norm_row.get("purpose") or norm_row.get("algorithm"):
                    kept_rows.append(raw_cells)

            contexts = artifact["digest_contexts"]
            assert len(kept_rows) == len(contexts), (
                f"{sub_name!r}: REGISTRY.md has {len(kept_rows)} digest-context "
                f"row(s) but registry.json has {len(contexts)}"
            )

            for raw_cells, ctx in zip(kept_rows, contexts):
                for header, cell in zip(norm_headers, raw_cells):
                    cell = cell.strip()
                    if not cell:
                        continue
                    checked_rows += 1
                    assert ctx.get(header) == cell, (
                        f"{sub_name!r}: column {header!r} (raw header from "
                        f"REGISTRY.md) has value {cell!r} but registry.json "
                        f"digest context has {ctx.get(header)!r} -- the cell "
                        f"was silently dropped or misnormalized"
                    )

        assert checked_rows > 0, "no digest-context cells found to check -- test is vacuous"

    def test_pre_image_encoding_specifically_round_trips(self, generated):
        """Direct regression check for the hyphen/underscore normalization bug."""
        found = False
        for artifact in generated["artifact_types"].values():
            for ctx in artifact["digest_contexts"]:
                if "pre_image_encoding" in ctx:
                    found = True
                    assert ctx["pre_image_encoding"]
        assert found, (
            "no digest context carries 'pre_image_encoding' -- the "
            "'Pre-image encoding' column is not round-tripping from REGISTRY.md"
        )


class TestAlgorithmRegistryCellFidelity:
    """Every cell in the algorithm registry table must round-trip (name-keyed)."""

    def test_every_nonempty_cell_round_trips(self, registry_md_lines, generated):
        section = gen_registry._section_lines(
            registry_md_lines, "Payload Canonicalization Algorithm Registry"
        )
        raw_headers, raw_rows = _raw_pipe_table(section)
        assert raw_headers is not None, "no algorithm registry table found"
        norm_headers = [_normalize_header(h) for h in raw_headers]

        checked = 0
        for raw_cells in raw_rows:
            row = dict(zip(norm_headers, raw_cells))
            name = row.get("name", "").strip()
            if not name:
                continue
            entry = generated["canonicalization_algorithms"].get(name)
            assert entry is not None, f"algorithm {name!r} missing from generated output"

            for field in ("description", "reference"):
                cell = row.get(field, "").strip()
                if not cell:
                    continue
                checked += 1
                assert entry.get(field) == cell, (
                    f"algorithm {name!r}: column {field!r} has value {cell!r} "
                    f"but registry.json has {entry.get(field)!r}"
                )

        assert checked > 0, "no algorithm cells found to check -- test is vacuous"
