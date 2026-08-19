# SPDX-License-Identifier: BSD-3-Clause
"""Drives vectors/harness.py verify-impl end-to-end.

D1-survives-inside-D4 gap (Anton, 2026-08-19): the algorithm-rejection leg of
verify_impl() built the object it sends to the external command by filtering
the *parsed* vector dict (already collapsed by a plain json.loads with no
wire hooks) and re-serializing it with json.dumps. That silently turns -0
into 0 and collapses duplicate keys before the implementation under test
ever sees them -- inverting exactly the two vectors (kat-35 negative-zero,
kat-37 duplicate-key) that exist to pin this rejection. CI stayed green
because nothing drove verify-impl's subprocess path end-to-end; check_vectors.py
and pytest only exercised the harness's internal reference implementation.

This module closes that gap: it runs the harness's own reference-impl as
its own external command against every real vector (the missing self-run),
and separately proves that the algorithm-rejection leg forwards byte-exact
field spans, not a re-serialization.
"""
from __future__ import annotations

import subprocess
import sys

from .conftest import VECTORS_DIR

HARNESS_PATH = VECTORS_DIR / "harness.py"


def test_verify_impl_end_to_end_against_reference_impl() -> None:
    """Self-run: drive verify-impl with the harness's own reference-impl as
    the external command, against every real pinned vector -- the check
    Anton asked for so this leg cannot regress silently again."""
    result = subprocess.run(
        [
            sys.executable,
            str(HARNESS_PATH),
            "verify-impl",
            f"{sys.executable} {HARNESS_PATH} reference-impl",
            str(VECTORS_DIR),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"harness verify-impl reported failures against its own reference-impl:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    assert "0 FAILED" in result.stdout, result.stdout


def test_algo_rejection_leg_forwards_raw_field_spans(tmp_path) -> None:
    """Mutation-provable regression test for the D1-survives-inside-D4 bug.

    A must_fail algorithm-rejection vector whose 'input' carries a negative
    zero and a duplicate key is written to disk with those exact bytes. The
    external "command" is a stub that captures whatever it receives on
    stdin, verbatim, then exits non-zero (satisfying the must_fail
    contract). If verify_impl() ever again rebuilds the stripped object from
    the parsed-and-collapsed vector dict via json.dumps, -0 becomes 0 and
    the duplicate key collapses, and this assertion flips to failure.
    """
    sys.path.insert(0, str(HARNESS_PATH.parent))
    try:
        import harness  # noqa: PLC0415 -- vectors/ is not a package
    finally:
        sys.path.remove(str(HARNESS_PATH.parent))

    probe = tmp_path / "probe-algo-rejection.json"
    raw = (
        '{"id": "probe-algo-rejection", "algorithm": "jcs-n", "must_fail": true, '
        '"failure_reason": "invalid_wire_number_token", '
        '"input": {"count": -0, "a": 1, "a": 2}}'
    )
    probe.write_text(raw, encoding="utf-8")

    capture = tmp_path / "captured_stdin.txt"
    stub_command = f"{sys.executable} -c \"import sys; open(r'{capture}', 'w').write(sys.stdin.read())\"; exit 1"

    rc = harness.verify_impl(stub_command, tmp_path)
    assert rc == 0  # the stub exits 1, which satisfies the must_fail vector

    got = capture.read_text(encoding="utf-8")
    # The stripped object drops harness metadata (id, must_fail, failure_reason)
    # but must preserve "input" byte-exact -- including the -0 token and both
    # occurrences of the duplicate key "a".
    assert '"count": -0' in got or '"count":-0' in got, (
        f"negative zero was normalized away: {got!r}"
    )
    assert got.count('"a"') == 2, f"duplicate key 'a' was collapsed: {got!r}"
    assert '"id"' not in got, f"harness metadata field 'id' was not stripped: {got!r}"
    assert '"must_fail"' not in got, f"must_fail flag was not stripped: {got!r}"
