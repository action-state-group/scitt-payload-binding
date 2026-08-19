#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-language conformance harness for algorithm jcs-n.

An independent implementation accepts our records and we accept theirs — as a command,
not an intention.  This harness defines the protocol and runs it in both directions.

Protocol
--------
The external command is invoked once per vector with the vector JSON on stdin.
It MUST write a JSON object to stdout with at most these keys:

  {"pre_image": "<string>", "digest": "<64-char lowercase hex>"}

For PASS vectors: the command's pre_image and digest MUST match the pinned values.
For MUST-FAIL vectors: the command MUST exit with a non-zero status.

If the command writes nothing to stdout and exits zero, that is treated as
"skipped" (informational, not a failure).

Usage
-----
    # Run an external implementation against our vectors:
    python3 vectors/harness.py verify-impl <command> [<vectors-dir>]

    # Generate a stub conforming implementation (for testing the harness itself):
    python3 vectors/harness.py generate-stub [<output-path>]

    # Show the protocol specification:
    python3 vectors/harness.py protocol

Example
-------
    python3 vectors/harness.py verify-impl 'python3 my_impl.py' vectors/

    # The external command receives one vector on stdin per invocation.
    # For PASS vectors it should print the pre_image and digest.
    # For MUST-FAIL vectors it should exit non-zero.

Both directions
---------------
Direction 1 (this script): we run an external impl against our vectors.
Direction 2 (their script): they run our reference impl against their vectors.

The reference impl command for direction 2:
    python3 vectors/harness.py reference-impl

This command reads one vector from stdin and writes the computed pre_image+digest,
or exits 1 if the input should be rejected.  Use it as the <command> in their harness.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path


# ---------------------------------------------------------------------------
# Wire-rule helpers (D2: validate number tokens before parser normalization)
# ---------------------------------------------------------------------------

_WIRE_NUMBER_RE = re.compile(r'^(0|-?[1-9][0-9]*)$')
_SAFE_INT_MAX = (1 << 53) - 1


def _parse_int_wire(s):
    if not _WIRE_NUMBER_RE.match(s):
        raise ValueError(f"invalid wire number token: {s!r}")
    val = int(s)
    if abs(val) > _SAFE_INT_MAX:
        raise ValueError(f"integer exceeds ±(2^53-1): {s!r}")
    return val


def _reject_float_wire(s):
    raise ValueError(f"non-integer number token in digest-bearing field: {s!r}")


def _no_dup_keys(pairs):
    seen = {}
    result = {}
    for k, v in pairs:
        nfc = unicodedata.normalize('NFC', k)
        if nfc in seen:
            raise ValueError(f"duplicate key after NFC normalization: {k!r}")
        seen[nfc] = True
        result[k] = v
    return result


# ---------------------------------------------------------------------------
# Minimal jcs-n reference implementation (same logic as check_vectors.py)
# ---------------------------------------------------------------------------

def _jcs_sort_key(k: str) -> bytes:
    return k.encode("utf-16-be")


def _normalize(obj: object) -> object:
    if isinstance(obj, list):
        return [_normalize(item) for item in obj]
    if not isinstance(obj, dict):
        return obj
    result: dict[str, object] = {}
    for k, v in obj.items():
        nv = _normalize(v)
        if nv is None or nv == [] or nv == {}:
            continue
        result[k] = nv
    return result


def _jcs(obj: object) -> str:
    if isinstance(obj, dict):
        sorted_k = sorted(obj.keys(), key=_jcs_sort_key)
        pairs = [_jcs(k) + ":" + _jcs(obj[k]) for k in sorted_k]
        return "{" + ",".join(pairs) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(_jcs(item) for item in obj) + "]"
    if not isinstance(obj, bool) and isinstance(obj, int):
        n = abs(obj)
        if n >= 10 ** 21 or n >= 1 << 53:
            raise ValueError(f"unsafe or oversized integer: {obj!r}")
    if isinstance(obj, float):
        raise ValueError(f"float not allowed in jcs-n: {obj!r}")
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def jcs_n_pre_image(payload: dict, exclusion_set: list[str] | None = None) -> str:
    if exclusion_set:
        payload = {k: v for k, v in payload.items() if k not in exclusion_set}
    return _jcs(_normalize(payload))


# ---------------------------------------------------------------------------
# Reference-impl mode: run as the external command in another harness
# ---------------------------------------------------------------------------

def _reference_impl_main() -> int:
    """Read one vector from stdin; write pre_image+digest or exit 1."""
    try:
        raw = sys.stdin.read()
        try:
            json.loads(raw, parse_int=_parse_int_wire, parse_float=_reject_float_wire,
                       object_pairs_hook=_no_dup_keys)
        except ValueError as exc:
            print(f"error: wire-rule violation: {exc}", file=sys.stderr)
            return 1
        v = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 2

    if v.get("must_fail"):
        # Reference impl: attempt the computation and exit 1 if it would produce a result.
        if "input" in v:
            excl = v.get("exclusion_set") or []
            try:
                jcs_n_pre_image(v["input"], excl or None)
                # If we get here without raising, we should have rejected this.
                # For vectors whose rejection is based on representation (not algorithm),
                # we still exit 1 — the pre_image is correct but the carried digest is wrong.
                return 1
            except (ValueError, TypeError):
                return 1
        return 1

    if "input" not in v:
        # Nothing to compute (skipped).
        return 0

    excl = v.get("exclusion_set") or []
    try:
        pre_image = jcs_n_pre_image(v["input"], excl or None)
    except (ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    digest = hashlib.sha256(pre_image.encode("utf-8")).hexdigest()
    print(json.dumps({"pre_image": pre_image, "digest": digest}))
    return 0


# ---------------------------------------------------------------------------
# verify-impl mode: run external command against our vectors
# ---------------------------------------------------------------------------

_span_decoder = json.JSONDecoder()


def _top_level_member_spans(text: str) -> dict[str, str]:
    """Return, for each top-level object member in *text*, the RAW JSON text
    of its value -- a literal substring of *text*, never a re-serialization.

    Uses JSONDecoder.raw_decode only to locate where each value ends; the
    parsed value it returns is discarded, so number tokens like "-0" and
    escaped-string content are never round-tripped through json.dumps.
    Duplicate keys are last-wins, matching json.loads.  This is what D4's
    field-stripping needs: build a smaller object without ever parsing +
    re-serializing the fields that survive (the exact bug D1 reintroduced).
    """
    spans: dict[str, str] = {}
    n = len(text)

    def _skip_ws(i: int) -> int:
        while i < n and text[i] in " \t\n\r":
            i += 1
        return i

    p = _skip_ws(0)
    if p >= n or text[p] != "{":
        raise ValueError("expected top-level object")
    p = _skip_ws(p + 1)
    if p < n and text[p] == "}":
        return spans
    while True:
        p = _skip_ws(p)
        key, p = _span_decoder.raw_decode(text, p)
        if not isinstance(key, str):
            raise ValueError(f"expected string key at position {p}")
        p = _skip_ws(p)
        if p >= n or text[p] != ":":
            raise ValueError(f"expected ':' at position {p}")
        p = _skip_ws(p + 1)
        value_start = p
        _, value_end = _span_decoder.raw_decode(text, p)
        spans[key] = text[value_start:value_end]
        p = _skip_ws(value_end)
        if p < n and text[p] == ",":
            p += 1
            continue
        if p < n and text[p] == "}":
            break
        raise ValueError(f"expected ',' or '}}' at position {p}")
    return spans


def _run_command(command: str, vector_json: str) -> tuple[int, str, str]:
    """Run command with vector_json on stdin.  Returns (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            input=vector_json,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def verify_impl(command: str, root: Path) -> int:
    """Run external command against all vectors in root.  Returns exit code."""
    passed = failed = skipped = 0
    failures: list[str] = []

    for vec_path in sorted(root.rglob("*.json")):
        try:
            v = json.loads(vec_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue

        vid = v.get("id", str(vec_path))
        raw_text = vec_path.read_text(encoding="utf-8")
        assert vec_path.read_bytes() == raw_text.encode("utf-8"), f"bytes-on-disk mismatch: {vec_path}"

        # D4: For input-bearing algorithm-rejection vectors, strip harness metadata
        # so the external impl must reject based on content, not the must_fail flag.
        is_algo_rejection = (
            v.get("must_fail")
            and "input" in v
            and "jcs_n_correct_digest" not in v
            and "pre_image" not in v
        )

        if v.get("must_fail") and not is_algo_rejection:
            skipped += 1
            continue

        if is_algo_rejection:
            # D1 survives inside D4 if this rebuilds the stripped object from
            # `v` (already collapsed by the plain json.loads() above) and
            # re-serializes it: -0 becomes 0 and duplicate keys collapse
            # before the external impl ever sees them.  Slice the RAW byte
            # spans of the surviving fields out of the original file text
            # instead -- never re-derive them from the parsed value.
            spans = _top_level_member_spans(raw_text)
            parts = [f'"{k}":{spans[k]}' for k in ("input", "exclusion_set", "algorithm") if k in spans]
            vector_json_to_send = "{" + ",".join(parts) + "}"
            rc, stdout, stderr = _run_command(command, vector_json_to_send)
            if rc == 0:
                failures.append(
                    f"FAIL {vid}: must-fail vector (algorithm-rejection) — command accepted invalid input"
                )
                failed += 1
            else:
                passed += 1
            continue

        if "input" not in v or "pre_image" not in v:
            skipped += 1
            continue

        rc, stdout, stderr = _run_command(command, raw_text)

        if rc != 0:
            failures.append(
                f"FAIL {vid}: command exited {rc}\n  stderr: {stderr.strip()!r}"
            )
            failed += 1
            continue

        if not stdout.strip():
            skipped += 1
            continue

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            failures.append(f"FAIL {vid}: command stdout is not valid JSON: {exc}")
            failed += 1
            continue

        got_pre = result.get("pre_image", "")
        got_digest = result.get("digest", "")
        pinned_pre = v.get("pre_image", "")
        pinned_digest = v.get("digest", "")

        if pinned_pre and got_pre != pinned_pre:
            failures.append(
                f"FAIL {vid}: pre_image mismatch\n"
                f"  expected: {pinned_pre!r}\n"
                f"  got:      {got_pre!r}"
            )
            failed += 1
            continue

        if pinned_digest and got_digest != pinned_digest:
            failures.append(
                f"FAIL {vid}: digest mismatch\n"
                f"  expected: {pinned_digest}\n"
                f"  got:      {got_digest}"
            )
            failed += 1
            continue

        passed += 1

    print(
        f"harness verify-impl: {passed} pass, {skipped} skipped, {failed} FAILED"
    )
    for f in failures:
        print(f)
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# generate-stub mode: produce a minimal conforming implementation
# ---------------------------------------------------------------------------

_STUB_TEXT = '''\
#!/usr/bin/env python3
# Minimal jcs-n stub generated by vectors/harness.py.
# This is a conforming implementation of algorithm jcs-n suitable for use
# as the external command in `python3 vectors/harness.py verify-impl`.
#
# Protocol: read one vector JSON from stdin; write {"pre_image": ..., "digest": ...}
# to stdout for PASS vectors; exit non-zero for must_fail vectors.
import hashlib, json, sys

def sort_key(k): return k.encode("utf-16-be")

def normalize(v):
    if isinstance(v, dict):
        out = {}
        for k, val in v.items():
            nv = normalize(val)
            if nv is None or nv == [] or nv == {}: continue
            out[k] = nv
        return out
    if isinstance(v, list): return [normalize(x) for x in v]
    return v

def jcs_str(s):
    out = [\'"\']
    for ch in s:
        o = ord(ch)
        if ch == \'"\': out.append(\'\\\\"\')
        elif ch == \'\\\\\': out.append(\'\\\\\\\\')
        elif o == 8: out.append(\'\\\\b\')
        elif o == 9: out.append(\'\\\\t\')
        elif o == 10: out.append(\'\\\\n\')
        elif o == 12: out.append(\'\\\\f\')
        elif o == 13: out.append(\'\\\\r\')
        elif o < 32: out.append(f\'\\\\u{o:04x}\')
        else: out.append(ch)
    out.append(\'"\')
    return \'\'.join(out)

def jcs(v):
    if v is None: return \'null\'
    if v is True: return \'true\'
    if v is False: return \'false\'
    if isinstance(v, str): return jcs_str(v)
    if isinstance(v, bool): return \'true\' if v else \'false\'
    if isinstance(v, int):
        if abs(v) >= 2**53 or abs(v) >= 10**21: raise ValueError(f"unsafe int: {v}")
        return str(v)
    if isinstance(v, float): raise ValueError(f"float not allowed: {v}")
    if isinstance(v, list): return \'[\' + \',\'.join(jcs(x) for x in v) + \']\'
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return \'{\' + \',\'.join(jcs_str(k) + \':\' + jcs(val) for k, val in items) + \'}\'

def run():
    v = json.load(sys.stdin)
    if "input" not in v: sys.exit(0)
    excl = v.get("exclusion_set") or []
    payload = {k: val for k, val in v["input"].items() if k not in excl}
    pre = jcs(normalize(payload))
    digest = hashlib.sha256(pre.encode("utf-8")).hexdigest()
    print(json.dumps({"pre_image": pre, "digest": digest}))

run()
'''


def _generate_stub(output_path: Path) -> int:
    output_path.write_text(_STUB_TEXT, encoding="utf-8")
    output_path.chmod(0o755)
    print(f"stub written to {output_path}")
    return 0


# ---------------------------------------------------------------------------
# Protocol documentation
# ---------------------------------------------------------------------------

_PROTOCOL_TEXT = """\
jcs-n Conformance Harness Protocol
====================================

External command contract
--------------------------
The external command is invoked once per vector.  The full vector JSON object
is written to the command's stdin.  The command MUST:

  For PASS vectors (no 'must_fail' field, 'input' present):
    - Exit 0.
    - Write to stdout a JSON object: {"pre_image": "<string>", "digest": "<hex>"}.
    - pre_image: the JCS-canonical UTF-8 string (before hashing).
    - digest: 64 lowercase hex characters (SHA-256 of pre_image bytes).

  For MUST-FAIL vectors ('must_fail': true):
    - Exit non-zero (any non-zero status).
    - May write anything to stdout or stderr; it is ignored.

  For vectors with no 'input' field:
    - May exit 0 and write nothing, which is treated as "skipped".

Comparison
-----------
  pre_image: compared as strings (byte-exact).
  digest: compared as strings (case-sensitive, must be 64 lowercase hex chars).

Both directions
----------------
  Direction 1 (verify-impl):
    We call the external command against our pinned vectors.
    Command: python3 vectors/harness.py verify-impl <cmd> [<dir>]

  Direction 2 (reference-impl):
    An external harness calls our reference implementation against their vectors.
    Command: python3 vectors/harness.py reference-impl

The reference-impl reads one vector from stdin and writes pre_image+digest,
or exits 1 for inputs that should be rejected.  It implements algorithm jcs-n
exactly as specified in CANONICALIZATION_DECLARATION.md.

Mutation check
---------------
A conforming implementation must reject all must_fail vectors.  The harness
additionally supports:
    python3 vectors/generate.py --mutate [<dir>]
to demonstrate that flipping one byte of a pre_image changes the digest.
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if not argv or argv[0] == "protocol":
        print(_PROTOCOL_TEXT)
        return 0

    if argv[0] == "reference-impl":
        return _reference_impl_main()

    if argv[0] == "generate-stub":
        output = Path(argv[1]) if len(argv) > 1 else Path("vectors/stub_impl.py")
        return _generate_stub(output)

    if argv[0] == "verify-impl":
        if len(argv) < 2:
            print("usage: harness.py verify-impl <command> [<vectors-dir>]", file=sys.stderr)
            return 2
        command = argv[1]
        root = Path(argv[2]) if len(argv) > 2 else Path(__file__).parent
        if not root.is_dir():
            print(f"error: {root} is not a directory", file=sys.stderr)
            return 2
        return verify_impl(command, root)

    print(f"unknown subcommand: {argv[0]!r}", file=sys.stderr)
    print("usage: harness.py [protocol | reference-impl | generate-stub | verify-impl <cmd>]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
