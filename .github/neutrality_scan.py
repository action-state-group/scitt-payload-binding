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
                  match is exempt ONLY when it falls inside the span of such a
                  phrase on the same line — not every occurrence of the token on
                  the line (two-occurrence fix: track spans, not just presence).

Output redaction: matched terms are NOT printed unless ``NEUTRALITY_REVEAL`` is
set to a truthy value. Redacted output keeps file:line and a per-line hit count.
Set it only on trusted runs (same-repo events); leaving it unset on runs
reachable from a fork is what stops the reserved list leaking one term at a time
through the build log.

Usage: python .github/neutrality_scan.py [ROOT=.]
       python .github/neutrality_scan.py --self-test
Exit 0 = clean; 1 = reserved vocabulary found (prints file:line); 2 = misconfig.
"""
from __future__ import annotations

import json
import os
import contextlib
import io
import re
import subprocess
import sys
import tempfile
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
    """Return reserved-vocabulary hits in *line* that are NOT inside an allow-phrase span.

    Each allow-phrase match creates a character span [start, end) over the
    lowercased line.  A vocabulary hit is exempt only when its entire span falls
    inside one of those allow-phrase spans.  Two occurrences of the same term on
    one line are therefore handled correctly: one inside a phrase → exempt, one
    outside → flagged.
    """
    line_lower = line.lower()

    # Collect all allow-phrase spans (case-insensitive, over lowercased line).
    allow_spans: list[tuple[int, int]] = []
    for phrase in allow:
        start = 0
        while True:
            pos = line_lower.find(phrase, start)
            if pos < 0:
                break
            allow_spans.append((pos, pos + len(phrase)))
            start = pos + 1  # allow overlapping phrase matches

    hits: list[str] = []
    for m in pattern.finditer(line):
        ms, me = m.start(), m.end()
        # Exempt only if this hit's span is fully contained within an allow span.
        if any(s <= ms and me <= e for s, e in allow_spans):
            continue
        hits.append(m.group(0))
    return hits


_MARKDOWN_SOURCE_COMMENT_RE = re.compile(
    r"<!--\s*##markdown-source:.*?-->", re.DOTALL
)


def _strip_generated_comments(text: str) -> str:
    """Strip kramdown-rfc's compressed+base64 markdown-source echo.

    xml2rfc/kramdown-rfc embeds the original .md source, gzip+base64
    encoded, in a ``<!-- ##markdown-source: ... -->`` comment for
    round-trip tooling. That blob is opaque binary data reflected through
    base64's limited alphabet, so it can coincidentally spell a reserved
    substring nowhere present in the actual .md source, which is scanned
    directly and is already the authoritative text. Strip the blob before
    matching so the gate can't fire on its own compression noise.
    """
    return _MARKDOWN_SOURCE_COMMENT_RE.sub("", text)


def _git_tracked_files(root: Path) -> list[Path] | None:
    r = subprocess.run(
        ["git", "ls-files"],
        cwd=root, capture_output=True, text=True
    )
    if r.returncode != 0:
        return None
    return [root / f for f in r.stdout.splitlines() if f]


def _reveal_matches() -> bool:
    """Whether matched terms may be printed verbatim.

    Redaction is the DEFAULT, and the caller must opt in. The reserved list is
    withheld from this repository precisely so that it is not public; echoing a
    matched term back into a build log republishes the very thing the gate
    exists to protect. Under ``pull_request_target`` the scan is reachable from
    a fork, so on an untrusted run an outsider could recover the list one term
    at a time by submitting a wordlist and reading the output. Actions' log
    masking does not help here: it masks the whole ``NEUTRALITY_TERMS`` JSON
    payload, not the individual terms this script parses out and re-emits.

    Redaction of the term alone is not sufficient. ``path:line`` on a fork run
    describes content the SUBMITTER wrote, so a stranger can submit one candidate
    per line and read the reserved list out of the line numbers in the public log
    — a faster oracle than the per-term one it replaced. So an untrusted run emits
    the verdict and NOTHING that varies with the input: no path, no line, no count.
    That leaves one bit per pull request, which is irreducible for any gate that
    reports a verdict to an untrusted contributor, and is visible to a human each
    time.

    THIS ENVIRONMENT VARIABLE IS THE WHOLE SECURITY BOUNDARY. The workflow is the
    only intended caller: it grants the opt-in only when the run is not
    ``pull_request_target`` or the head repository equals the base. It reads as a
    convenience toggle and is not one.
    """
    return os.environ.get("NEUTRALITY_REVEAL", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def scan(
    root: Path,
    pattern: re.Pattern[str],
    allow: tuple[str, ...],
    reveal: bool | None = None,
) -> list[str]:
    if reveal is None:
        reveal = _reveal_matches()
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
        text = _strip_generated_comments(text)
        for i, line in enumerate(text.splitlines(), 1):
            hits = _line_offenders(line, pattern, allow)
            if not hits:
                continue
            rel = path.relative_to(root)
            if reveal:
                offenders.extend(f"{rel}:{i}: {tok!r}" for tok in hits)
            else:
                n = len(hits)
                offenders.append(
                    f"{rel}:{i}: {n} reserved term{'' if n == 1 else 's'} (redacted)"
                )
    return offenders


def _run_self_tests() -> None:
    """Anton two-occurrence test: span-based allow-phrase exemption.

    One occurrence of the term inside the allow-phrase span → exempt.
    One occurrence outside → flagged.  Both on the same line.
    """
    errors: list[str] = []
    pattern = re.compile(r"reserved", re.IGNORECASE)
    allow: tuple[str, ...] = ("use of reserved keyword",)

    # Occurrence entirely outside any allow-phrase → must be flagged.
    line1 = "reserved word found here"
    hits1 = _line_offenders(line1, pattern, allow)
    if hits1 != ["reserved"]:
        errors.append(
            f"two-occurrence test 1 failed: expected ['reserved'], got {hits1!r}"
        )

    # Occurrence inside the allow-phrase → must be exempt.
    line2 = "see use of reserved keyword in docs"
    hits2 = _line_offenders(line2, pattern, allow)
    if hits2 != []:
        errors.append(
            f"two-occurrence test 2 failed: expected [], got {hits2!r}"
        )

    # Two occurrences on the same line: one inside the phrase (exempt), one outside (flagged).
    line3 = "reserved is bad but use of reserved keyword is documented"
    hits3 = _line_offenders(line3, pattern, allow)
    if len(hits3) != 1 or hits3[0].lower() != "reserved":
        errors.append(
            f"two-occurrence test 3 failed: expected exactly one 'reserved', got {hits3!r}"
        )

    # kramdown-rfc markdown-source comment: a reserved term that appears only
    # inside the compressed/base64 echo must NOT be flagged; the same term in
    # real content, outside the comment, still must be.
    pattern2 = re.compile(r"reserved", re.IGNORECASE)
    doc = (
        "real content before\n"
        "<!-- ##markdown-source:\n"
        "b64noisereservedmorenoise\n"
        "-->\n"
        "reserved appears here in real content\n"
    )
    stripped = _strip_generated_comments(doc)
    if "reservedmorenoise" in stripped:
        errors.append(
            "markdown-source comment test failed: blob text survived stripping"
        )
    hits4 = [
        tok
        for line in stripped.splitlines()
        for tok in _line_offenders(line, pattern2, ())
    ]
    if hits4 != ["reserved"]:
        errors.append(
            f"markdown-source comment test failed: expected exactly one "
            f"real-content 'reserved' hit after stripping, got {hits4!r}"
        )

    # Redaction: the matched term must never appear in redacted output, and
    # must appear when the caller explicitly opts in. Run against a real tree
    # rather than _line_offenders, since scan() is what formats the output.
    # The stand-in term must not collide with the wording of the redaction
    # label itself, or "term absent from the output" cannot be asserted.
    secret_term = "zzsecretterm"
    pattern3 = re.compile(re.escape(secret_term), re.IGNORECASE)

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td)
        (troot / "doc.md").write_text(
            f"{secret_term} here\nclean line\n{secret_term} and {secret_term}\n",
            encoding="utf-8",
        )

        redacted = scan(troot, pattern3, (), reveal=False)
        if any(secret_term in o.lower() for o in redacted):
            errors.append(
                f"redaction test failed: matched term echoed in redacted "
                f"output: {redacted!r}"
            )
        if redacted != [
            "doc.md:1: 1 reserved term (redacted)",
            "doc.md:3: 2 reserved terms (redacted)",
        ]:
            errors.append(
                f"redaction test failed: expected path:line + per-line count, "
                f"got {redacted!r}"
            )

        # The default path, with no reveal argument and no env set, is the one
        # a fork run actually takes — assert it directly. Passing reveal=False
        # above only proves the formatting branch, not that it is the default.
        prior = os.environ.pop("NEUTRALITY_REVEAL", None)
        try:
            defaulted = scan(troot, pattern3, ())
        finally:
            if prior is not None:
                os.environ["NEUTRALITY_REVEAL"] = prior
        if defaulted != redacted:
            errors.append(
                f"redaction-default test failed: with NEUTRALITY_REVEAL unset "
                f"scan() must redact, got {defaulted!r}"
            )

        revealed = scan(troot, pattern3, (), reveal=True)
        if revealed != [f"doc.md:1: '{secret_term}'",
                        f"doc.md:3: '{secret_term}'",
                        f"doc.md:3: '{secret_term}'"]:
            errors.append(
                f"reveal test failed: expected one entry per hit with the term, "
                f"got {revealed!r}"
            )

    # Default must be redacted: an unset NEUTRALITY_REVEAL is the untrusted
    # case, and this is the assertion that keeps redaction opt-in rather than
    # opt-out if the env plumbing is ever changed.
    for value, expected in (("", False), ("0", False), ("no", False),
                            ("1", True), ("true", True), ("YES", True)):
        prior = os.environ.get("NEUTRALITY_REVEAL")
        try:
            if value:
                os.environ["NEUTRALITY_REVEAL"] = value
            else:
                os.environ.pop("NEUTRALITY_REVEAL", None)
            if _reveal_matches() is not expected:
                errors.append(
                    f"reveal-env test failed: NEUTRALITY_REVEAL={value!r} "
                    f"should be {expected}"
                )
        finally:
            if prior is None:
                os.environ.pop("NEUTRALITY_REVEAL", None)
            else:
                os.environ["NEUTRALITY_REVEAL"] = prior

    # Untrusted output carries NOTHING that varies with the input. Redacting the
    # term is not enough: path:line on a fork run describes the submitter's own
    # content, so one candidate per line turns the log into a per-line oracle.
    # This asserts the whole-run output, not scan()'s return value, because main()
    # is what the log actually sees.
    with tempfile.TemporaryDirectory() as td:
        troot = Path(td)
        (troot / "secretfile.md").write_text(
            f"clean line\n{secret_term} here\nclean\n", encoding="utf-8"
        )
        prior = os.environ.get("NEUTRALITY_REVEAL")
        prior_terms = os.environ.get("NEUTRALITY_TERMS")
        try:
            os.environ.pop("NEUTRALITY_REVEAL", None)
            os.environ["NEUTRALITY_TERMS"] = json.dumps({"substring": [secret_term]})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main([str(troot)])
            out_a = buf.getvalue()
            if rc != 1:
                errors.append(f"untrusted-output test: expected exit 1, got {rc}")

            # The invariant, asserted directly: untrusted output is CONSTANT.
            # A second tree differing in filename, line number, hit count and
            # which term fired must produce byte-identical output. This catches
            # leaks nobody thought to enumerate, which a list of forbidden
            # substrings cannot.
            (troot / "z.md").unlink(missing_ok=True)
            other = Path(td) / "second"
            other.mkdir()
            (other / "wholly-different-name.md").write_text(
                f"{secret_term}\n{secret_term} and {secret_term}\n",
                encoding="utf-8",
            )
            buf_b = io.StringIO()
            with contextlib.redirect_stdout(buf_b):
                rc_b = main([str(other)])
            out_b = buf_b.getvalue()
            if rc_b != 1:
                errors.append(f"untrusted-output test: expected exit 1, got {rc_b}")
            if out_a != out_b:
                errors.append(
                    "untrusted-output test failed: output varies with input — "
                    f"{out_a!r} vs {out_b!r}"
                )
            if "withheld" not in out_a:
                errors.append(
                    f"untrusted-output test failed: expected the withheld-details "
                    f"verdict, got {out_a!r}"
                )
        finally:
            if prior is None:
                os.environ.pop("NEUTRALITY_REVEAL", None)
            else:
                os.environ["NEUTRALITY_REVEAL"] = prior
            if prior_terms is None:
                os.environ.pop("NEUTRALITY_TERMS", None)
            else:
                os.environ["NEUTRALITY_TERMS"] = prior_terms

    if errors:
        print("NEUTRALITY SELF-TEST FAILURES:")
        for e in errors:
            print(f"  {e}")
        raise SystemExit(1)

    print("neutrality self-test: OK (span-based allow-phrase exemption)")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if argv and argv[0] == "--self-test":
        _run_self_tests()
        return 0

    root = Path(argv[0]) if argv else Path(".")
    pattern, allow = _load_config()
    offenders = scan(root, pattern, allow)
    if offenders:
        if not _reveal_matches():
            # Untrusted run: verdict only. The location count is the same oracle
            # at lower resolution, so it is withheld too.
            print(
                "neutrality: content check failed. Details are withheld on fork "
                "runs; a maintainer can re-run this gate on a trusted event."
            )
            return 1
        # "location(s)", not "hit(s)": a redacted entry collapses every hit on a
        # line into one entry carrying its own count, so entry count == hit
        # count only on a revealing run.
        print(
            f"NEUTRALITY VIOLATION: reserved vocabulary present "
            f"({len(offenders)} location(s)):"
        )
        for o in offenders:
            print(f"  {o}")
        print("\nThis public repo must carry none of the reserved vocabulary. "
              "Remove the flagged content.")
        return 1
    print("OK: no reserved vocabulary found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
