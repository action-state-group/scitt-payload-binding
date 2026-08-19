# SPDX-License-Identifier: BSD-3-Clause
"""Duplicate-preserving raw-bytes JSON lexer.

Security note
-------------
``json.loads`` collapses duplicate object keys before any rule can examine
them.  A record containing ``{"a":1,"a":2}`` becomes ``{"a":2}`` after
``json.loads``, so a checker built on ``json.loads`` would silently accept
a duplicate-key R violation.  This scanner reads JSON byte-by-byte, reports
every duplicate key with its full JSON path, and returns both the parsed
value (last-wins, matching stdlib) and the complete violation list.

This is the most security-relevant component of cpb-check.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

__all__ = ['RawViolation', 'lex']

# Anchored integer-only form.
# Accepts:  0  1  -1  100  -999
# Rejects:  -0  01  1.5  1e2  1E2  0.0  1.0  -0.5
_STRICT_INT_RE = re.compile(r'^(?:0|-?[1-9][0-9]*)$')

# Full JSON number grammar (RFC 8259 §6) — used to consume a token.
_JSON_NUM_RE = re.compile(r'-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?')

# Nesting bound for objects/arrays. The scanner is recursive-descent, so an
# unbounded depth turns adversarial input into an uncaught RecursionError
# instead of a verdict — for the most security-relevant component in this
# checker, a crash is a worse failure mode than a rejection. Each nesting
# level costs two Python stack frames (parse() -> _object()/_array()), so
# against CPython's default recursion limit (1000) a bound of 500 is already
# too tight once caller frames (CLI, test runner, pytest) are on the stack —
# measured empirically failing at 500, passing at 400. 300 is well above any
# legitimate CPB record depth and leaves real headroom below the crash line.
_MAX_DEPTH = 300


@dataclass(frozen=True)
class RawViolation:
    """An R-layer violation found by the raw-bytes scanner."""
    path: str    # JSON path, e.g. '$["payload"]["amount"]'
    code: str    # 'duplicate_key' | 'number_token_form'
    detail: str  # human-readable description


class _Scanner:
    """Minimal recursive-descent JSON scanner.

    Unlike ``json.loads``, this scanner:
    - reports every duplicate object key before the dict is constructed,
    - captures number tokens as raw strings so their lexical form can be
      checked against ``_STRICT_INT_RE``,
    - tracks JSON paths throughout the tree.
    """
    __slots__ = ('_t', '_p', '_depth', 'violations')

    def __init__(self, text: str) -> None:
        self._t: str = text
        self._p: int = 0
        self._depth: int = 0
        self.violations: list[RawViolation] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ws(self) -> None:
        t = self._t
        while self._p < len(t) and t[self._p] in ' \t\n\r':
            self._p += 1

    def _expect(self, ch: str) -> None:
        if self._p >= len(self._t) or self._t[self._p] != ch:
            got = self._t[self._p:self._p + 8] if self._p < len(self._t) else '<EOF>'
            raise ValueError(f'expected {ch!r} at position {self._p} (got {got!r})')
        self._p += 1

    # ------------------------------------------------------------------
    # Value parsers
    # ------------------------------------------------------------------

    def parse(self, path: str = '$') -> Any:
        self._ws()
        t = self._t
        p = self._p
        if p >= len(t):
            raise ValueError('unexpected end of input')
        c = t[p]
        if c == '{':
            return self._object(path)
        if c == '[':
            return self._array(path)
        if c == '"':
            return self._string()
        if c in '-0123456789':
            return self._number(path)
        if t[p:p + 4] == 'null':
            self._p += 4
            return None
        if t[p:p + 4] == 'true':
            self._p += 4
            return True
        if t[p:p + 5] == 'false':
            self._p += 5
            return False
        raise ValueError(f'unexpected character {c!r} at position {p}')

    def _push_depth(self, path: str) -> None:
        self._depth += 1
        if self._depth > _MAX_DEPTH:
            raise ValueError(
                f'nesting too deep at {path}: exceeds max depth {_MAX_DEPTH}'
            )

    def _object(self, path: str) -> dict[str, Any]:
        self._push_depth(path)
        try:
            self._p += 1                            # consume '{'
            result: dict[str, Any] = {}
            seen: dict[str, int] = {}               # NFC(key) -> char-position of first occurrence
            first = True
            while True:
                self._ws()
                if self._p >= len(self._t):
                    raise ValueError(f'unterminated object at {path}')
                c = self._t[self._p]
                if c == '}':
                    self._p += 1
                    return result
                if not first:
                    self._expect(',')
                first = False
                self._ws()
                key = self._string()
                self._ws()
                self._expect(':')
                # json.dumps, not raw interpolation: a key literally named
                # 'a"]["b' otherwise renders as $["a"]["b"], forging the path of a
                # genuine two-level nesting, and a key containing a newline injects
                # whole fake violation lines into an operator's log. ensure_ascii
                # also keeps a lone surrogate from crashing the printer.
                member_path = f'{path}[{json.dumps(key)}]'
                # Duplicate detection compares NFC-normalized keys: two members whose
                # keys are distinct Unicode encodings of the same identifier (e.g. one
                # NFC, one NFD) are the same wire-layer key and must not both survive —
                # jcs-n itself does not normalize (CANONICALIZATION_DECLARATION.md §3),
                # so an un-normalized duplicate check would let an attacker smuggle two
                # "different" keys that collapse to one identifier downstream.
                norm_key = unicodedata.normalize('NFC', key)
                if norm_key in seen:
                    self.violations.append(RawViolation(
                        path=member_path,
                        code='duplicate_key',
                        detail=(
                            f'key "{key}" appears more than once in the object at '
                            f'{path} (first occurrence at character {seen[norm_key]})'
                        ),
                    ))
                else:
                    seen[norm_key] = self._p
                val = self.parse(member_path)
                result[key] = val                   # last-wins, same as json.loads
        finally:
            self._depth -= 1

    def _array(self, path: str) -> list[Any]:
        self._push_depth(path)
        try:
            self._p += 1                            # consume '['
            result: list[Any] = []
            first = True
            while True:
                self._ws()
                if self._p >= len(self._t):
                    raise ValueError(f'unterminated array at {path}')
                c = self._t[self._p]
                if c == ']':
                    self._p += 1
                    return result
                if not first:
                    self._expect(',')
                first = False
                idx = len(result)
                val = self.parse(f'{path}[{idx}]')
                result.append(val)
        finally:
            self._depth -= 1

    def _string(self) -> str:
        self._ws()
        t = self._t
        p = self._p
        if p >= len(t) or t[p] != '"':
            got = t[p:p + 4] if p < len(t) else '<EOF>'
            raise ValueError(f'expected string at position {p} (got {got!r})')
        p += 1                                  # skip opening quote
        buf: list[str] = []
        while p < len(t):
            c = t[p]
            if c == '"':
                self._p = p + 1
                return ''.join(buf)
            if c == '\\':
                p += 1
                if p >= len(t):
                    raise ValueError('incomplete escape sequence')
                esc = t[p]
                if esc == '"':
                    buf.append('"')
                elif esc == '\\':
                    buf.append('\\')
                elif esc == '/':
                    buf.append('/')
                elif esc == 'b':
                    buf.append('\b')
                elif esc == 'f':
                    buf.append('\f')
                elif esc == 'n':
                    buf.append('\n')
                elif esc == 'r':
                    buf.append('\r')
                elif esc == 't':
                    buf.append('\t')
                elif esc == 'u':
                    hex4 = t[p + 1:p + 5]
                    if len(hex4) < 4:
                        raise ValueError('incomplete \\u escape')
                    code = int(hex4, 16)
                    if 0xD800 <= code <= 0xDBFF and t[p + 5:p + 7] == '\\u':
                        low = int(t[p + 7:p + 11], 16)
                        if 0xDC00 <= low <= 0xDFFF:
                            buf.append(chr(0x10000 + (code - 0xD800) * 0x400 + (low - 0xDC00)))
                            # 11 characters consumed from p: 'u' + 4 hex + '\\' + 'u'
                            # + 4 hex. At 10 the final hex digit of the low escape
                            # was left behind and appended as a literal, so
                            # "\\ud83d\\ude00" lexed as the emoji followed by '0' --
                            # a different document than every other parser sees.
                            p += 11
                            continue
                    buf.append(chr(code))
                    p += 4
                else:
                    raise ValueError(f'invalid escape \\{esc!r} at position {p}')
                p += 1
            else:
                if ord(c) < 0x20:
                    # RFC 8259 section 7: characters below U+0020 MUST be escaped.
                    # stdlib json rejects them; accepting them here would mean this
                    # scanner and every other parser read different documents, which
                    # is the differential this module exists to close.
                    raise ValueError(
                        f'raw control character U+{ord(c):04X} in string at position {p} '
                        f'(RFC 8259 section 7 requires it escaped)'
                    )
                buf.append(c)
                p += 1
        raise ValueError('unterminated string')

    def _number(self, path: str) -> int | float:
        m = _JSON_NUM_RE.match(self._t, self._p)
        if not m:
            raise ValueError(f'expected number at position {self._p}')
        tok = m.group()
        self._p = m.end()
        if not _STRICT_INT_RE.match(tok):
            self.violations.append(RawViolation(
                path=path,
                code='number_token_form',
                detail=(
                    f'number token {tok!r} is not in integer-token form; '
                    r'must match ^(?:0|-?[1-9][0-9]*)$ '
                    '(no floats, no -0, no leading zeros, no exponent notation)'
                ),
            ))
        # Return the numeric value for use in P checks
        if '.' in tok or 'e' in tok.lower():
            return float(tok)
        return int(tok)


def lex(raw: str | bytes) -> tuple[Any, list[RawViolation]]:
    """Parse *raw* JSON, preserving duplicate-key information.

    Parameters
    ----------
    raw:
        JSON text as ``str`` or UTF-8 ``bytes``.

    Returns
    -------
    value:
        Parsed Python value.  Duplicate object keys use last-wins (matching
        ``json.loads`` behaviour).
    violations:
        List of :class:`RawViolation` describing every R-layer violation:
        duplicate object keys and number tokens outside the integer-only form
        ``^(?:0|-?[1-9][0-9]*)$``.

    Security note
    -------------
    This is the security-critical path.  ``json.loads`` collapses duplicate
    keys silently; this function reports them *before* they are lost.  A
    collapsing-parser mutant would accept ``{"a":1,"a":2}`` without violation;
    this function returns one ``duplicate_key`` violation for ``$["a"]``.
    """
    if isinstance(raw, bytes):
        text = raw.decode('utf-8')
    else:
        text = str(raw)
    scanner = _Scanner(text)
    value = scanner.parse('$')
    scanner._ws()
    if scanner._p != len(text):
        raise ValueError(
            f'trailing bytes after top-level value at position {scanner._p} '
            f'(got {text[scanner._p:scanner._p + 8]!r})'
        )
    return value, scanner.violations
