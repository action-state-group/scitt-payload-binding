#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Neutrality gate — fail the build if reserved vocabulary appears in this repo.

This repository is a neutral public surface (the agentactioncapsule.org standard
site for the Agent Action Capsule specification). A small set of concepts is reserved
and must not appear here. The reserved list is deliberately NOT stored in this
repository — a public gate that enumerated the terms would itself disclose them.
Instead the list is supplied at run time via the ``NEUTRALITY_TERMS`` repository
secret, and this script is pure matching logic parameterized by that secret.

Fail-closed: if the secret is absent/empty the gate errors (exit 2) rather than
passing silently — a missing list must never read as "clean".

Secret schema (JSON):
    {"substring": [...], "word": [...], "allow_phrases": [...]}
  - substring   : matched case-insensitively anywhere
  - word        : matched case-insensitively at word boundaries (low-collision
                  short names that must not false-positive inside other words)
  - allow_phrases: already-public sentences that legitimately carry a token; a
                  match is exempt only when it is part of such a phrase carried
                  on the same line (narrow — keyed on the phrase, not the file).

Usage: python .github/neutrality_scan.py [ROOT=.]
Exit 0 = clean; 1 = reserved vocabulary found (prints file:line); 2 = misconfig.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCAN_SUFFIXES = (
    ".html", ".py", ".go", ".md", ".rst", ".txt", ".xml", ".toml", ".cfg",
    ".yml", ".yaml", ".json",
)


def _load_config() -> tuple[re.Pattern[str], tuple[str, ...]]:
    raw = os.environ.get("NEUTRALITY_TERMS", "").strip()
    if not raw:
        print(
            "error: NEUTRALITY_TERMS secret is empty or unset. The neutrality "
            "gate is fail-closed — configure the repository secret. (On fork PRs "
            "secrets are withheld by design; run this gate on same-repo PRs.)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: NEUTRALITY_TERMS is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    substring = tuple(cfg.get("substring", ()))
    word = tuple(cfg.get("word", ()))
    allow = tuple(p.lower() for p in cfg.get("allow_phrases", ()))
    if not substring and not word:
        print("error: NEUTRALITY_TERMS carries no terms.", file=sys.stderr)
        raise SystemExit(2)
    parts = [re.escape(t) for t in substring]
    parts += [r"\b" + re.escape(t) + r"\b" for t in word]
    return re.compile("|".join(parts), re.IGNORECASE), allow


def _line_offenders(line: str, pattern: re.Pattern[str], allow: tuple[str, ...]) -> list[str]:
    carried = [p for p in allow if p in line.lower()]
    hits: list[str] = []
    for m in pattern.finditer(line):
        token = m.group(0)
        if any(token.lower() in p for p in carried):
            continue
        hits.append(token)
    return hits


def _git_tracked_files(root: Path) -> list[Path] | None:
    r = subprocess.run(
        ["git", "ls-files"],
        cwd=root, capture_output=True, text=True
    )
    if r.returncode != 0:
        return None
    return [root / f for f in r.stdout.splitlines() if f]


def scan(root: Path, pattern: re.Pattern[str], allow: tuple[str, ...]) -> list[str]:
    tracked = _git_tracked_files(root)
    candidates: list[Path] = tracked if tracked is not None else sorted(root.rglob("*"))
    offenders: list[str] = []
    for path in candidates:
        path = Path(path)
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if ".git/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for token in _line_offenders(line, pattern, allow):
                offenders.append(f"{path.relative_to(root)}:{i}: {token!r}")
    return offenders


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0]) if argv else Path(".")
    pattern, allow = _load_config()
    offenders = scan(root, pattern, allow)
    if offenders:
        print(f"NEUTRALITY VIOLATION: reserved vocabulary present ({len(offenders)} hit(s)):")
        for o in offenders:
            print(f"  {o}")
        print("\nThis public repo must carry none of the reserved vocabulary. "
              "Remove the flagged content.")
        return 1
    print("OK: no reserved vocabulary found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
