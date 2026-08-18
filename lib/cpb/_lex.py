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

import re
from dataclasses import dataclass
from typing import Any

__all__ = ['RawViolation', 'lex']

# Anchored integer-only form.
# Accepts:  0  1  -1  100  -999
# Rejects:  -0  01  1.5  1e2  1E2  0.0  1.0  -0.5
_STRICT_INT_RE = re.compile(r'^(?:0|-?[1-9][0-9]*)$')

# Full JSON number grammar (RFC 8259 §6) — used to consume a token.
_JSON_NUM_RE = re.compile(r'-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?')


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
    __slots__ = ('_t', '_p', 'violations')

    def __init__(self, text: str) -> None:
        self._t: str = text
        self._p: int = 0
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

    def _object(self, path: str) -> dict[str, Any]:
        self._p += 1                            # consume '{'
        result: dict[str, Any] = {}
        seen: dict[str, int] = {}               # key -> char-position of first colon
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
            member_path = f'{path}["{key}"]'
            if key in seen:
                self.violations.append(RawViolation(
                    path=member_path,
                    code='duplicate_key',
                    detail=(
                        f'key "{key}" appears more than once in the object at '
                        f'{path} (first occurrence at character {seen[key]})'
                    ),
                ))
            else:
                seen[key] = self._p
            val = self.parse(member_path)
            result[key] = val                   # last-wins, same as json.loads

    def _array(self, path: str) -> list[Any]:
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
                            p += 10
                            continue
                    buf.append(chr(code))
                    p += 4
                else:
                    raise ValueError(f'invalid escape \\{esc!r} at position {p}')
                p += 1
            else:
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
    return value, scanner.violations
