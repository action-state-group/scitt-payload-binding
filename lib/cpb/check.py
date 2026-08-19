# SPDX-License-Identifier: BSD-3-Clause
"""CPB P/R grammar conformance checker — Phase 1.

Checks a JSON record against the CPB wire grammar (P and R rules).

Phase 1 scope
-------------
- P  Normal-form walk: no dict member (at any depth, including dicts inside
  arrays) may have value null, [] or {}.  Array elements are exempt.
  Scope matches normalize() exactly (§3.1 step 1).
- R  Wire-layer: every number token must be in integer-token form
  ^(?:0|-?[1-9][0-9]*)$; no duplicate object keys; declared array order
  where the profile states one (profile-specific, not yet wired — awaits the
  profile registry in Phase 2).

Phase 2 (not implemented here)
-------------------------------
- ``digest-mismatch``: recompute the digest under the declared
  ``canonicalization_id`` and compare — waits on G1 (capsule-emit writing
  the id field).
- ``unknown-id``: cross-check the declared id against the registry — same
  prerequisite.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from ._lex import lex

__all__ = [
    'Verdict',
    'Violation',
    'CheckResult',
    'check',
    'check_p',
    'check_r',
]

Verdict = Literal['verified', 'non-conforming', 'digest-mismatch', 'unknown-id']


@dataclass(frozen=True)
class Violation:
    """A single grammar violation."""
    path: str    # JSON path, e.g. '$["payload"]["amount"]'
    rule: str    # 'P' or 'R'
    detail: str  # human-readable description


@dataclass
class CheckResult:
    """Result of a grammar conformance check."""
    verdict: Verdict
    violations: list[Violation] = field(default_factory=list)
    note: str = ''

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'verdict': self.verdict}
        if self.violations:
            d['violations'] = [
                {'path': v.path, 'rule': v.rule, 'detail': v.detail}
                for v in self.violations
            ]
        if self.note:
            d['note'] = self.note
        return d


# ---------------------------------------------------------------------------
# P rule — normal-form walk
# ---------------------------------------------------------------------------

def check_p(value: Any, path: str = '$') -> list[Violation]:
    """Return P-rule violations found in *value*.

    P rule: no member of any dict (at any depth, including dicts inside
    arrays) may have value ``None``, ``[]``, or ``{}``.  Array *elements* are
    exempt — the restriction applies to *members of dicts*, not to elements of
    arrays regardless of their position.

    The scope matches ``normalize()`` exactly (§3.1 step 1).
    """
    violations: list[Violation] = []
    _p_walk(value, path, violations)
    return violations


def _p_walk(v: Any, path: str, out: list[Violation]) -> None:
    if isinstance(v, dict):
        for k, val in v.items():
            member_path = f'{path}["{k}"]'
            if val is None:
                out.append(Violation(member_path, 'P', 'null member'))
            elif isinstance(val, list) and not val:
                out.append(Violation(member_path, 'P', 'empty array member'))
            elif isinstance(val, dict) and not val:
                out.append(Violation(member_path, 'P', 'empty object member'))
            else:
                _p_walk(val, member_path, out)
    elif isinstance(v, list):
        # Array elements are exempt from the null/empty check.  But dicts
        # nested inside arrays are still subject to the member rule.
        for i, item in enumerate(v):
            _p_walk(item, f'{path}[{i}]', out)


# ---------------------------------------------------------------------------
# R rule — wire-layer (via the duplicate-preserving lexer)
# ---------------------------------------------------------------------------

def check_r(raw: str | bytes) -> list[Violation]:
    """Return R-rule violations found in *raw* JSON.

    Uses the duplicate-preserving lexer so that duplicate object keys are
    detected *before* the dict is built, rather than being silently collapsed
    by ``json.loads``.
    """
    _, raw_violations = lex(raw)
    return [
        Violation(path=rv.path, rule='R', detail=rv.detail)
        for rv in raw_violations
    ]


# ---------------------------------------------------------------------------
# Combined check
# ---------------------------------------------------------------------------

def check(raw: str | bytes) -> CheckResult:
    """Check *raw* JSON against CPB P and R grammar rules.

    Returns ``'verified'`` if no violations are found, or ``'non-conforming'``
    with the full violation list otherwise.

    Phase 1 only.  ``'digest-mismatch'`` and ``'unknown-id'`` verdicts are
    Phase 2 and are not produced here.
    """
    value, raw_violations = lex(raw)

    r_violations = [
        Violation(path=rv.path, rule='R', detail=rv.detail)
        for rv in raw_violations
    ]
    p_violations = check_p(value)

    all_violations = r_violations + p_violations
    if all_violations:
        return CheckResult(verdict='non-conforming', violations=all_violations)

    return CheckResult(
        verdict='verified',
        note=(
            'grammar check passed (Phase 1); '
            'digest verification awaits Phase 2 (canonicalization_id / G1)'
        ),
    )
