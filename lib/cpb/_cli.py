# SPDX-License-Identifier: BSD-3-Clause
"""cpb-check — CPB record grammar conformance checker (Phase 1).

Five-line quickstart
--------------------
    pip install ./lib            # from the scitt-payload-binding repo root
    cpb-check record.json        # human-readable verdict
    cpb-check record.json --json # machine-readable JSON
    cpb-check --self-test        # run the built-in vector suite
    echo $?                      # 0 = verified, 1 = non-conforming, 2 = error

Exit codes
----------
0  verified      — no P/R grammar violations found
1  non-conforming — grammar violations found; see output for path and rule
2  error          — parse failure or usage error
"""
from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from importlib import resources
from pathlib import Path

from .check import CheckResult, check

_EXIT_VERIFIED = 0
_EXIT_NON_CONFORMING = 1
_EXIT_ERROR = 2

_USAGE = """\
cpb-check <record.json> [--json]
cpb-check --self-test

Phase 1 grammar conformance checker for CPB records.
Checks P (normal-form) and R (wire-layer) rules.
Phase 2 (digest recomputation, canonicalization_id resolution) not yet implemented.

Options:
  --json       Emit machine-readable JSON on stdout.
  --self-test  Run the built-in vector suite and exit.
  -h, --help   Show this help.

Exit codes: 0=verified  1=non-conforming  2=error
"""


# ---------------------------------------------------------------------------
# Self-test: run the built-in cpb-check vector suite
# ---------------------------------------------------------------------------

def _vector_files(root) -> Iterable:
    """Yield packaged vector resources without assuming a filesystem Path.

    ``importlib.resources`` may return a Traversable backed by an installed
    wheel rather than a checkout, so use only the Traversable interface.
    """
    for child in sorted(root.iterdir(), key=lambda item: item.name):
        if child.is_dir():
            yield from _vector_files(child)
        elif child.name.endswith('.json'):
            yield child


def _self_test() -> int:
    vectors_root = resources.files('cpb').joinpath('_vectors', 'cpb-check')
    if not vectors_root.is_dir():
        print('self-test: packaged vector directory not found', file=sys.stderr)
        return _EXIT_ERROR

    passed = failed = skipped = 0

    for vec_file in _vector_files(vectors_root):
        try:
            vec = json.loads(vec_file.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            print(f'  LOAD-ERROR  {vec_file.name}: {exc}', file=sys.stderr)
            failed += 1
            continue

        expected = vec.get('expected_verdict')
        if expected is None:
            print(f'  SKIP        {vec_file.name}: no expected_verdict field')
            skipped += 1
            continue

        # Support both 'record' (Python value, re-encoded) and 'record_raw'
        # (raw JSON string, preserves duplicate keys etc.)
        if 'record_raw' in vec:
            raw: str | bytes = vec['record_raw']
        elif 'record' in vec:
            raw = json.dumps(vec['record'])
        else:
            print(f'  SKIP        {vec_file.name}: no record or record_raw field')
            skipped += 1
            continue

        try:
            result = check(raw)
        except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
            print(f'  PARSE-ERROR {vec_file.name}: {exc}', file=sys.stderr)
            failed += 1
            continue

        if result.verdict == expected:
            print(f'  OK   {vec_file.name}  [{result.verdict}]')
            passed += 1
        else:
            paths = [v.path for v in result.violations]
            print(
                f'  FAIL {vec_file.name}: '
                f'expected {expected!r}, got {result.verdict!r}'
                + (f' (violations: {paths})' if paths else ''),
                file=sys.stderr,
            )
            failed += 1

    total = passed + failed + skipped
    print(f'\nself-test: {passed}/{total} passed, {failed} failed, {skipped} skipped')
    return _EXIT_VERIFIED if failed == 0 else _EXIT_NON_CONFORMING


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def _print_human(result: CheckResult, source: str) -> None:
    print(f'{source}: verdict: {result.verdict}')
    for v in result.violations:
        print(f'  [{v.rule}] {v.path}: {v.detail}')
    if result.note and not result.violations:
        print(f'  note: {result.note}')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    emit_json = '--json' in args
    args = [a for a in args if a != '--json']

    if '--self-test' in args:
        sys.exit(_self_test())

    if args[:1] in ([], ['-h'], ['--help']) or not args:
        # Asking for help is not an error; being handed nothing to check is.
        # These were inverted: a bare `cpb-check` exited 0, and 0 is this tool's
        # word for "verified" -- so a CI gate whose path variable came out empty
        # concluded the record conformed without a record ever being read.
        if args:
            print(_USAGE)
            sys.exit(_EXIT_VERIFIED)
        print(_USAGE, file=sys.stderr)
        print('cpb-check: no record given -- nothing was checked', file=sys.stderr)
        sys.exit(_EXIT_ERROR)

    path_arg = args[0]
    try:
        raw: bytes = (
            sys.stdin.buffer.read() if path_arg == '-'
            else Path(path_arg).read_bytes()
        )
    except OSError as exc:
        print(f'cpb-check: {exc}', file=sys.stderr)
        sys.exit(_EXIT_ERROR)

    try:
        result = check(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        print(f'cpb-check: parse error: {exc}', file=sys.stderr)
        sys.exit(_EXIT_ERROR)

    if emit_json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        _print_human(result, path_arg)

    sys.exit(_EXIT_VERIFIED if result.verdict == 'verified' else _EXIT_NON_CONFORMING)


if __name__ == '__main__':
    main()
