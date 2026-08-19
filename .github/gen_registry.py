#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate registry.json from REGISTRY.md.

Parses the two markdown tables in REGISTRY.md:
  - Payload Canonicalization Algorithm Registry
  - Artifact Type Registry

Produces a content-addressed registry.json whose snapshot_sha256 field is the
SHA-256 of the document body (all fields except snapshot_sha256 itself, keys
sorted, compact ASCII JSON).  This makes every released snapshot self-certifying:
a verifier can recompute the sha and detect tampering or truncation.

Usage:
  python .github/gen_registry.py                 # write registry.json in-place
  python .github/gen_registry.py --check         # exit 1 if committed file differs
  python .github/gen_registry.py --out path.json # write to a specific path
  python .github/gen_registry.py --print         # dump to stdout, do not write

Run from the repository root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Markdown stripping helpers
# ---------------------------------------------------------------------------

def _strip_md(s: str) -> str:
    """Strip common inline markdown from a table cell value."""
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)       # **bold**
    s = re.sub(r"\*(.+?)\*", r"\1", s)            # *italic*
    s = re.sub(r"`(.+?)`", r"\1", s)              # `code`
    s = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", s)  # [text](url)
    return s.strip()


_LEGACY_STATUSES = frozenset({"Registered", "Reserved"})


def _normalize_status(raw: str) -> str:
    """Normalize a legacy status cell; leave every other status untouched.

    Legacy rows spell their status with a trailing qualifier ('Reserved (defined
    in a subsequent revision)'), so those two names are matched at the start of
    the cell and returned bare.  Vocabulary statuses are NOT prefix-matched: the
    policy requires them verbatim, and prefix-matching would silently accept
    'provisional — pending X' as 'provisional', which is the drift the
    validation exists to catch.
    """
    m = re.match(r"\s*(Registered|Reserved)\b", raw, re.IGNORECASE)
    if m:
        return m.group(1).capitalize()
    return raw.strip()


def _parse_md_table(lines: list[str]) -> list[dict[str, str]]:
    """Parse a markdown pipe-table from a list of lines.

    Returns a list of dicts keyed by the lowercased, underscore-separated
    header names.  Stops at the first line that doesn't start with '|'.

    A row whose cell count doesn't match the header count (e.g. an unescaped
    '|' inside a backticked span, which GFM also splits on) is a malformed
    source row: zip()-ing it against headers would silently mis-assign every
    subsequent column, so this raises instead of shifting.
    """
    rows: list[dict[str, str]] = []
    headers: list[str] | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if headers is not None:
                break
            continue
        cells = [_strip_md(c) for c in stripped.strip("|").split("|")]
        if headers is None:
            headers = [c.lower().replace(" ", "_").replace("-", "_") for c in cells]
        elif all(re.match(r"^[-: ]+$", c) for c in cells):
            continue  # separator row
        else:
            if len(cells) != len(headers):
                raise ValueError(
                    f"malformed table row: expected {len(headers)} cells for "
                    f"headers {headers!r}, got {len(cells)}: {stripped!r} -- "
                    f"check for an unescaped '|' inside a backticked span"
                )
            rows.append(dict(zip(headers, cells)))
    return rows


# ---------------------------------------------------------------------------
# Section extraction helpers
# ---------------------------------------------------------------------------

def _section_lines(md_lines: list[str], heading: str) -> list[str]:
    """Return all lines under a ## heading until the next same-or-higher heading."""
    result: list[str] = []
    inside = False
    for line in md_lines:
        if line.startswith("## "):
            if inside:
                break
            if heading in line:
                inside = True
            continue
        if inside:
            result.append(line)
    return result


def _subsections(section_lines: list[str]) -> list[tuple[str, list[str]]]:
    """Split a section into (subsection_name, lines) pairs at ### headings."""
    subs: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []
    for line in section_lines:
        if line.startswith("### "):
            if current_name is not None:
                subs.append((current_name, current_lines))
            current_name = _strip_md(line[4:].strip())
            current_lines = []
        else:
            current_lines.append(line)
    if current_name is not None:
        subs.append((current_name, current_lines))
    return subs


# ---------------------------------------------------------------------------
# Registry parsers
# ---------------------------------------------------------------------------

def _parse_status_vocabulary(md_lines: list[str]) -> set[str]:
    """Read the legal status strings out of REGISTRY.md itself.

    The vocabulary table under 'Entry Status Vocabulary' is the single source of
    truth: policy and validator cannot drift because there is only one list.
    The legacy spellings are added because the same section defines them as the
    reading for pre-existing rows.
    """
    section = _section_lines(md_lines, "Entry Status Vocabulary")
    statuses = {row["status"].strip() for row in _parse_md_table(section)
                if row.get("status", "").strip()}
    if not statuses:
        raise ValueError(
            "no status vocabulary parsed from REGISTRY.md — refusing to validate "
            "against an empty set (fail closed rather than accept anything)"
        )
    return statuses | _LEGACY_STATUSES


def _parse_algorithm_registry(md_lines: list[str]) -> dict[str, dict]:
    """Parse the Payload Canonicalization Algorithm Registry table.

    Every non-name column found in the table is carried through verbatim
    (status excepted, which is normalized) -- a renamed or newly added column
    is picked up automatically instead of silently dropped by a hardcoded
    field list.
    """
    section = _section_lines(md_lines, "Payload Canonicalization Algorithm Registry")
    rows = _parse_md_table(section)
    algorithms: dict[str, dict] = {}
    for row in rows:
        name = row.get("name", "").strip()
        if not name:
            continue
        entry: dict[str, str] = {}
        for header, value in row.items():
            if header == "name":
                continue
            value = value.strip()
            entry[header] = _normalize_status(value) if header == "status" else value
        algorithms[name] = entry
    return algorithms


def _parse_artifact_type_registry(md_lines: list[str]) -> dict[str, dict]:
    section = _section_lines(md_lines, "Artifact Type Registry")
    subs = _subsections(section)
    artifact_types: dict[str, dict] = {}
    for sub_name, sub_lines in subs:
        if not sub_name:
            continue
        # Extract **Reference:** and **Status:** from prose lines
        reference = ""
        status = ""
        for line in sub_lines:
            m_ref = re.search(r"\*\*Reference:\*\*\s*(.+?)(?:\s*\n|$)", line)
            if m_ref:
                reference = _strip_md(m_ref.group(1).strip())
            m_sta = re.search(r"\*\*Status:\*\*\s*(.+?)(?:\s*\n|$)", line)
            if m_sta:
                status = _normalize_status(_strip_md(m_sta.group(1).strip()))
        # Parse the digest-context table
        rows = _parse_md_table(sub_lines)
        digest_contexts = []
        for row in rows:
            ctx: dict[str, str] = {}
            for col in (
                "purpose",
                "profile_version",
                "algorithm",
                "field_set",
                "exclusion_set",
                "domain_separation",
                "pre_image_encoding",
                "representation",
            ):
                val = row.get(col, "").strip()
                if val:
                    ctx[col] = val
            if ctx.get("purpose") or ctx.get("algorithm"):
                digest_contexts.append(ctx)
        artifact_types[sub_name] = {
            "reference": reference,
            "status": status,
            "digest_contexts": digest_contexts,
        }
    return artifact_types


# ---------------------------------------------------------------------------
# Snapshot content-address
# ---------------------------------------------------------------------------

def _compute_body_sha256(data: dict) -> str:
    """SHA-256 of the canonical body (all fields except snapshot_sha256, sorted keys)."""
    body = {k: v for k, v in data.items() if k != "snapshot_sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------
# Structural validation (stdlib-only; full JSON Schema via CI jsonschema)
# ---------------------------------------------------------------------------

def _validate_structure(data: dict, legal_statuses: set[str]) -> list[str]:
    errors: list[str] = []
    expected = ", ".join(sorted(legal_statuses))
    for field in ("schema_version", "snapshot_sha256", "canonicalization_algorithms", "artifact_types"):
        if field not in data:
            errors.append(f"missing required field: {field!r}")
    algs = data.get("canonicalization_algorithms", {})
    if not isinstance(algs, dict):
        errors.append("canonicalization_algorithms must be an object")
    else:
        for name, entry in algs.items():
            for sub in ("description", "reference", "status"):
                if sub not in entry:
                    errors.append(f"algorithm {name!r}: missing {sub!r}")
            if entry.get("status") not in legal_statuses:
                errors.append(
                    f"algorithm {name!r}: status must be one of [{expected}] "
                    f"used verbatim, got {entry.get('status')!r}"
                )
    arts = data.get("artifact_types", {})
    if isinstance(arts, dict):
        for name, entry in arts.items():
            if entry.get("status") not in legal_statuses:
                errors.append(
                    f"artifact type {name!r}: status must be one of [{expected}] "
                    f"used verbatim, got {entry.get('status')!r}"
                )
    sha = data.get("snapshot_sha256", "")
    if not re.match(r"^[0-9a-f]{64}$", sha):
        errors.append(f"snapshot_sha256 must be 64 lowercase hex chars, got {sha!r}")
    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate(registry_md: Path) -> dict:
    md_lines = registry_md.read_text(encoding="utf-8").splitlines(keepends=True)
    algorithms = _parse_algorithm_registry(md_lines)
    artifact_types = _parse_artifact_type_registry(md_lines)
    if not algorithms:
        print("WARNING: no algorithm entries parsed from REGISTRY.md", file=sys.stderr)
    data: dict = {
        "schema_version": "1",
        "canonicalization_algorithms": algorithms,
        "artifact_types": artifact_types,
    }
    data["snapshot_sha256"] = _compute_body_sha256(data)
    return data


def _render(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="Exit 1 if committed registry.json differs from generated")
    parser.add_argument("--out", default="registry.json",
                        help="Output path (default: registry.json)")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="Print to stdout, do not write")
    parser.add_argument("--registry-md", default="REGISTRY.md",
                        help="Path to REGISTRY.md (default: REGISTRY.md)")
    args = parser.parse_args(argv)

    registry_md = Path(args.registry_md)
    if not registry_md.exists():
        print(f"error: {registry_md} not found (run from repo root)", file=sys.stderr)
        return 2

    data = generate(registry_md)
    md_lines = registry_md.read_text(encoding="utf-8").splitlines(keepends=True)
    errs = _validate_structure(data, _parse_status_vocabulary(md_lines))
    if errs:
        for e in errs:
            print(f"validation error: {e}", file=sys.stderr)
        return 1

    rendered = _render(data)

    if args.print_only:
        sys.stdout.write(rendered)
        return 0

    out = Path(args.out)

    if args.check:
        if not out.exists():
            print(f"error: {out} does not exist; run: python .github/gen_registry.py", file=sys.stderr)
            return 1
        committed = out.read_text(encoding="utf-8")
        if committed != rendered:
            print(
                f"ERROR: {out} is stale.\n"
                f"Run: python .github/gen_registry.py\n"
                f"Then commit the updated {out}.",
                file=sys.stderr,
            )
            return 1
        print(f"{out}: up-to-date (snapshot_sha256={data['snapshot_sha256'][:16]}...)")
        return 0

    out.write_text(rendered, encoding="utf-8")
    print(f"wrote {out} (snapshot_sha256={data['snapshot_sha256'][:16]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
