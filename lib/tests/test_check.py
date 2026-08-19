# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the CPB P/R grammar conformance checker (Phase 1).

Mutant discipline (§7 QUEUE_PROTOCOL)
--------------------------------------
Every negative check must fail its mutant — a condition-removed variant that
the test then shows is CAUGHT by the real check.  Each section below:

1. Shows the mutant ACCEPTING what it should reject (mutant verdict == 'verified').
2. Shows the real checker REJECTING the same input (real verdict == 'non-conforming').

A check that does not have a failing mutant is not a check.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from cpb.check import CheckResult, Violation, check, check_p
from cpb._lex import RawViolation, lex

VECTORS_DIR = pathlib.Path(__file__).parent.parent.parent / 'vectors' / 'cpb-check'


# =============================================================================
# Helpers — mutant implementations
# =============================================================================

def _mutant_check_no_p(raw: str | bytes) -> CheckResult:
    """Mutant: P check disabled.  Only R is checked.  Accepts null/empty members."""
    value, raw_violations = lex(raw)
    r_violations = [Violation(rv.path, 'R', rv.detail) for rv in raw_violations]
    if r_violations:
        return CheckResult(verdict='non-conforming', violations=r_violations)
    return CheckResult(verdict='verified', note='MUTANT: P check disabled')


def _mutant_check_collapsing_parser(raw: str | bytes) -> CheckResult:
    """Mutant: uses json.loads (collapsing parser) instead of the duplicate-preserving lexer.

    json.loads silently drops duplicate keys, so this mutant returns 'verified'
    for any record that is otherwise grammar-clean but has duplicate keys.
    """
    if isinstance(raw, bytes):
        text = raw.decode('utf-8')
    else:
        text = str(raw)
    value = json.loads(text)                    # MUTANT: collapses duplicates silently
    p_violations = check_p(value)
    if p_violations:
        return CheckResult(verdict='non-conforming', violations=p_violations)
    return CheckResult(verdict='verified', note='MUTANT: collapsing parser')


def _mutant_check_value_based_number(raw: str | bytes) -> CheckResult:
    """Mutant: checks number values rather than number tokens.

    A value-based check (isinstance(v, float)) misses exponent notation like
    1e2 because json.loads converts it to the integer 100 before any rule sees
    the token.
    """
    if isinstance(raw, bytes):
        text = raw.decode('utf-8')
    else:
        text = str(raw)
    value = json.loads(text)

    violations: list[Violation] = []
    _value_based_number_walk(value, '$', violations)
    p_violations = check_p(value)
    all_violations = violations + p_violations
    if all_violations:
        return CheckResult(verdict='non-conforming', violations=all_violations)
    return CheckResult(verdict='verified', note='MUTANT: value-based number check')


def _value_based_number_walk(v: Any, path: str, out: list[Violation]) -> None:
    """Walk a parsed value and flag float instances — misses 1e2, -0, etc."""
    if isinstance(v, float):
        out.append(Violation(path, 'R', 'MUTANT: float value (misses exponent notation)'))
    elif isinstance(v, dict):
        for k, val in v.items():
            _value_based_number_walk(val, f'{path}["{k}"]', out)
    elif isinstance(v, list):
        for i, item in enumerate(v):
            _value_based_number_walk(item, f'{path}[{i}]', out)


def _mutant_check_no_r_number(raw: str | bytes) -> CheckResult:
    """Mutant: number-token form check disabled.  Accepts -0, 01, 1e2, 1.5."""
    value, raw_violations = lex(raw)
    # Only keep duplicate-key violations; drop number_token_form
    r_violations = [
        Violation(rv.path, 'R', rv.detail)
        for rv in raw_violations
        if rv.code != 'number_token_form'
    ]
    p_violations = check_p(value)
    all_violations = r_violations + p_violations
    if all_violations:
        return CheckResult(verdict='non-conforming', violations=all_violations)
    return CheckResult(verdict='verified', note='MUTANT: number-token check disabled')


def _mutant_check_no_r_duplicate(raw: str | bytes) -> CheckResult:
    """Mutant: duplicate-key check disabled.  Accepts records with duplicate keys."""
    value, raw_violations = lex(raw)
    # Only keep number_token_form violations; drop duplicate_key
    r_violations = [
        Violation(rv.path, 'R', rv.detail)
        for rv in raw_violations
        if rv.code != 'duplicate_key'
    ]
    p_violations = check_p(value)
    all_violations = r_violations + p_violations
    if all_violations:
        return CheckResult(verdict='non-conforming', violations=all_violations)
    return CheckResult(verdict='verified', note='MUTANT: duplicate-key check disabled')


# =============================================================================
# P-rule tests with mutants
# =============================================================================

class TestPRule:

    # --- null member ---

    def test_null_member_rejected(self) -> None:
        """Real checker rejects a null member."""
        raw = b'{"type":"action","payload":{"x":null}}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["payload"]["x"]' in paths
        rules = [v.rule for v in result.violations if v.path == '$["payload"]["x"]']
        assert rules == ['P']

    def test_null_member_mutant_accepts(self) -> None:
        """MUTANT (P check disabled) accepts the same null-bearing record."""
        raw = b'{"type":"action","payload":{"x":null}}'
        result = _mutant_check_no_p(raw)
        assert result.verdict == 'verified', (
            f'mutant should accept null member but got {result.verdict}'
        )

    # --- empty object member ---

    def test_empty_object_member_rejected(self) -> None:
        raw = b'{"type":"action","meta":{}}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["meta"]' in paths

    def test_empty_object_member_mutant_accepts(self) -> None:
        raw = b'{"type":"action","meta":{}}'
        result = _mutant_check_no_p(raw)
        assert result.verdict == 'verified', (
            f'mutant should accept empty-object member but got {result.verdict}'
        )

    # --- empty array member ---

    def test_empty_array_member_rejected(self) -> None:
        raw = b'{"type":"action","tags":[]}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["tags"]' in paths

    def test_empty_array_member_mutant_accepts(self) -> None:
        raw = b'{"type":"action","tags":[]}'
        result = _mutant_check_no_p(raw)
        assert result.verdict == 'verified'

    # --- deep null ---

    def test_deep_null_rejected(self) -> None:
        raw = b'{"a":{"b":{"c":null}}}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["a"]["b"]["c"]' in paths

    # --- null in object inside array ---

    def test_null_in_object_inside_array_rejected(self) -> None:
        """P rule applies to dicts inside arrays (members are still members)."""
        raw = b'{"items":[{"kind":"a","opt":null}]}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["items"][0]["opt"]' in paths

    def test_null_in_object_inside_array_mutant_accepts(self) -> None:
        raw = b'{"items":[{"kind":"a","opt":null}]}'
        result = _mutant_check_no_p(raw)
        assert result.verdict == 'verified'

    # --- array elements exempt ---

    def test_null_array_element_is_exempt(self) -> None:
        """A null that is an array *element* (not a dict member) is exempt."""
        raw = b'{"items":[null,"a",1]}'
        result = check(raw)
        assert result.verdict == 'verified'

    def test_empty_array_element_is_exempt(self) -> None:
        """An empty array that is itself an array element is exempt."""
        raw = b'{"items":[[],[1,2]]}'
        result = check(raw)
        assert result.verdict == 'verified'

    # --- conforming record ---

    def test_conforming_record_passes(self) -> None:
        raw = b'{"type":"action","id":"x","payload":{"action":"approve","actor":"agent-1","count":7}}'
        result = check(raw)
        assert result.verdict == 'verified'


# =============================================================================
# R-rule tests with mutants — duplicate key
# =============================================================================

class TestRDuplicateKey:

    # THE security-critical case.
    _DUP_RAW = b'{"type":"action","id":"1234","type":"injected"}'

    def test_duplicate_key_rejected(self) -> None:
        """Real checker (duplicate-preserving lexer) rejects duplicate key."""
        result = check(self._DUP_RAW)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["type"]' in paths
        rules = [v.rule for v in result.violations if v.path == '$["type"]']
        assert 'R' in rules

    def test_duplicate_key_collapsing_mutant_accepts(self) -> None:
        """MUTANT (collapsing parser) silently accepts the same duplicate-key record.

        json.loads({'type': 'action', 'id': '1234', 'type': 'injected'})
        returns {'type': 'injected', 'id': '1234'} — the first value is lost
        and no violation is reported.
        """
        result = _mutant_check_collapsing_parser(self._DUP_RAW)
        assert result.verdict == 'verified', (
            f'collapsing-parser mutant should accept duplicate-key record '
            f'but got {result.verdict!r} (violations: {result.violations})'
        )

    def test_duplicate_key_no_dup_check_mutant_accepts(self) -> None:
        """MUTANT (dup check disabled) also accepts."""
        result = _mutant_check_no_r_duplicate(self._DUP_RAW)
        assert result.verdict == 'verified'

    def test_duplicate_key_nested_rejected(self) -> None:
        """Duplicate key inside a nested object is also rejected."""
        raw = b'{"type":"a","payload":{"action":"approve","actor":"x","action":"override"}}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["payload"]["action"]' in paths

    def test_unique_keys_pass(self) -> None:
        raw = b'{"a":1,"b":2,"c":3}'
        result = check(raw)
        assert result.verdict == 'verified'


# =============================================================================
# R-rule tests with mutants — number token form
# =============================================================================

class TestRNumberTokenForm:

    # --- float token ---

    def test_float_rejected(self) -> None:
        raw = b'{"amount":12.50}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        paths = [v.path for v in result.violations]
        assert '$["amount"]' in paths

    def test_float_mutant_no_number_check_accepts(self) -> None:
        raw = b'{"amount":12.50}'
        result = _mutant_check_no_r_number(raw)
        assert result.verdict == 'verified'

    # --- negative zero ---

    def test_negative_zero_rejected(self) -> None:
        raw = b'{"value":-0}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        codes = {rv.code for rv in lex(raw)[1]}
        assert 'number_token_form' in codes

    def test_negative_zero_mutant_accepts(self) -> None:
        raw = b'{"value":-0}'
        result = _mutant_check_no_r_number(raw)
        assert result.verdict == 'verified'

    # --- exponent notation: the token-vs-value discriminator ---

    def test_exponent_notation_rejected(self) -> None:
        """1e2 is rejected by the TOKEN check but accepted by a VALUE check.

        json.loads('{"count":1e2}') == {'count': 100} — the exponent token is
        converted to integer 100 by the parser, so a value-based isinstance(v, float)
        check would see an integer and accept it.  The token-based check sees '1e2'
        and rejects.
        """
        raw = b'{"count":1e2}'
        result = check(raw)
        assert result.verdict == 'non-conforming', (
            'token-based checker should reject exponent notation 1e2'
        )

    def test_negative_zero_value_mutant_accepts(self) -> None:
        """-0 is the token-vs-value discriminator in CPython.

        Python's json.loads converts -0 to the integer 0 (Python integers have
        no negative zero).  A value-based isinstance(v, float) check sees 0
        (an int) and accepts it.  The token-based check sees the raw token '-0'
        and rejects it because '-0' does not match ^(?:0|-?[1-9][0-9]*)$.
        """
        raw = b'{"value":-0}'
        # Confirm: Python json.loads returns int 0, not float -0.0
        import json as _json
        assert isinstance(_json.loads('{"value":-0}')['value'], int), (
            'pre-condition: json.loads must return int for -0 in CPython'
        )
        result = _mutant_check_value_based_number(raw)
        assert result.verdict == 'verified', (
            f'value-based mutant should accept -0 (it becomes int 0 via json.loads) '
            f'but got {result.verdict!r}'
        )

    def test_exponent_notation_no_number_check_mutant_accepts(self) -> None:
        raw = b'{"count":1e2}'
        result = _mutant_check_no_r_number(raw)
        assert result.verdict == 'verified'

    # --- uppercase E ---

    def test_uppercase_exponent_rejected(self) -> None:
        raw = b'{"count":1E2}'
        result = check(raw)
        assert result.verdict == 'non-conforming'

    # --- float zero: valid JSON, invalid token form ---

    def test_float_zero_rejected(self) -> None:
        """0.0 is valid JSON but not integer-token form."""
        raw = b'{"value":0.0}'
        result = check(raw)
        assert result.verdict == 'non-conforming'
        assert any(v.code == 'number_token_form' for v in
                   [RawViolation(rv.path, rv.code, rv.detail) for rv in lex(raw)[1]])

    def test_malformed_json_leading_zero_raises(self) -> None:
        """007 is not valid JSON (leading zero outside string) — parser raises."""
        import pytest as _pytest
        with _pytest.raises(ValueError):
            check(b'{"code":007}')

    # --- valid integer tokens ---

    def test_zero_accepted(self) -> None:
        result = check(b'{"n":0}')
        assert result.verdict == 'verified'

    def test_positive_integer_accepted(self) -> None:
        result = check(b'{"n":42}')
        assert result.verdict == 'verified'

    def test_negative_integer_accepted(self) -> None:
        result = check(b'{"n":-1}')
        assert result.verdict == 'verified'

    def test_large_integer_accepted(self) -> None:
        result = check(b'{"n":9007199254740991}')
        assert result.verdict == 'verified'


# =============================================================================
# Vector-suite runner — run the built-in cpb-check vectors
# =============================================================================

def _load_check_vectors() -> list[tuple[str, dict]]:
    vectors = []
    if not VECTORS_DIR.is_dir():
        return vectors
    for f in sorted(VECTORS_DIR.rglob('*.json')):
        try:
            vec = json.loads(f.read_text(encoding='utf-8'))
            vectors.append((f.name, vec))
        except Exception:
            pass
    return vectors


@pytest.mark.parametrize('name,vec', _load_check_vectors())
def test_check_vector_suite(name: str, vec: dict) -> None:
    """Every cpb-check vector produces the expected verdict."""
    expected = vec.get('expected_verdict')
    if expected is None:
        pytest.skip(f'{name}: no expected_verdict field')

    if 'record_raw' in vec:
        raw: str | bytes = vec['record_raw']
    elif 'record' in vec:
        raw = json.dumps(vec['record'])
    else:
        pytest.skip(f'{name}: no record or record_raw field')

    result = check(raw)
    assert result.verdict == expected, (
        f'{name}: expected verdict {expected!r}, got {result.verdict!r}; '
        f'violations: {[{"path": v.path, "rule": v.rule} for v in result.violations]}'
    )


# =============================================================================
# Lex unit tests — direct scanner tests
# =============================================================================

class TestLex:

    def test_simple_object(self) -> None:
        value, violations = lex(b'{"a":1,"b":"hello"}')
        assert value == {'a': 1, 'b': 'hello'}
        assert violations == []

    def test_duplicate_key_reported(self) -> None:
        value, violations = lex(b'{"x":1,"y":2,"x":99}')
        assert len(violations) == 1
        assert violations[0].code == 'duplicate_key'
        assert violations[0].path == '$["x"]'
        assert value['x'] == 99           # last-wins

    def test_three_duplicates_reported(self) -> None:
        value, violations = lex(b'{"a":1,"a":2,"a":3}')
        assert len(violations) == 2       # second AND third are duplicates

    def test_float_token_reported(self) -> None:
        _, violations = lex(b'{"v":1.5}')
        assert len(violations) == 1
        assert violations[0].code == 'number_token_form'
        assert '1.5' in violations[0].detail

    def test_negative_zero_reported(self) -> None:
        _, violations = lex(b'{"v":-0}')
        assert len(violations) == 1
        assert violations[0].code == 'number_token_form'
        assert '-0' in violations[0].detail

    def test_exponent_reported(self) -> None:
        _, violations = lex(b'{"v":1e2}')
        assert len(violations) == 1
        assert violations[0].code == 'number_token_form'
        assert '1e2' in violations[0].detail

    def test_valid_integers_no_violation(self) -> None:
        _, violations = lex(b'{"a":0,"b":-1,"c":100,"d":-999}')
        assert violations == []

    def test_nested_duplicate(self) -> None:
        _, violations = lex(b'{"outer":{"inner":1,"inner":2}}')
        assert len(violations) == 1
        assert violations[0].path == '$["outer"]["inner"]'

    def test_number_in_string_not_flagged(self) -> None:
        """Numbers inside string VALUES must not trigger R violations."""
        _, violations = lex(b'{"v":"1e2 is fine as a string","n":42}')
        assert violations == []

    def test_bytes_input(self) -> None:
        value, violations = lex(b'{"a":1}')
        assert value == {'a': 1}
        assert violations == []

    def test_str_input(self) -> None:
        value, violations = lex('{"a":1}')
        assert value == {'a': 1}

    # --- trailing bytes after the top-level value ---

    def test_trailing_bytes_rejected(self) -> None:
        """A top-level value followed by extra bytes must be rejected, not
        silently ignored (verified: {"a":1}+trailing content was previously
        accepted with the trailing bytes discarded)."""
        with pytest.raises(ValueError, match='trailing bytes'):
            lex(b'{"a":1}{"a":2}')

    def test_trailing_garbage_rejected(self) -> None:
        with pytest.raises(ValueError, match='trailing bytes'):
            lex(b'{"a":1}not json')

    def test_trailing_whitespace_accepted(self) -> None:
        """Trailing whitespace after the top-level value is not 'trailing bytes'."""
        value, violations = lex(b'{"a":1}  \n\t')
        assert value == {'a': 1}
        assert violations == []

    def test_trailing_bytes_mutant_accepts(self) -> None:
        """MUTANT: parse only the top-level value, never check what follows —
        the pre-fix behavior.  Demonstrates the check catches a real regression."""
        def _mutant_no_trailing_check(raw: bytes) -> Any:
            from cpb._lex import _Scanner
            scanner = _Scanner(raw.decode('utf-8'))
            return scanner.parse('$')  # no trailing-bytes check afterward

        value = _mutant_no_trailing_check(b'{"a":1}{"a":2}')
        assert value == {'a': 1}  # silently ignores the second object

    # --- duplicate-key detection is NFC-normalized ---

    def test_nfc_nfd_keys_are_duplicates(self) -> None:
        """A key encoded as precomposed NFC and a second member using the
        NFD-decomposed form of the same identifier are the same wire-layer
        key and must be flagged as a duplicate — otherwise a record could
        smuggle two 'different' keys that a downstream NFC-normalizing
        consumer collapses into one, silently overwriting a value."""
        nfc_key = "\u00c5"   # LATIN CAPITAL LETTER A WITH RING ABOVE (precomposed)
        nfd_key = "A\u030a"  # 'A' + COMBINING RING ABOVE (decomposed)
        assert nfc_key != nfd_key  # distinct code point sequences
        raw = ('{"' + nfc_key + '":1,"' + nfd_key + '":2}').encode('utf-8')
        _, violations = lex(raw)
        assert len(violations) == 1
        assert violations[0].code == 'duplicate_key'

    def test_nfc_duplicate_mutant_accepts(self) -> None:
        """MUTANT: duplicate detection compares raw (non-NFC-normalized) keys --
        the pre-fix behavior.  Walks the same parsed key list the real checker
        sees but compares with plain string equality, showing an NFC/NFD pair
        is missed."""
        nfc_key = "\u00c5"   # LATIN CAPITAL LETTER A WITH RING ABOVE (precomposed)
        nfd_key = "A\u030a"  # 'A' + COMBINING RING ABOVE (decomposed)
        keys = [nfc_key, nfd_key]
        seen: set[str] = set()
        dup_found = False
        for key in keys:
            if key in seen:              # MUTANT: no NFC normalization
                dup_found = True
            else:
                seen.add(key)
        assert not dup_found  # mutant treats the NFC/NFD pair as distinct keys

    # --- nesting depth is bounded ---

    def test_deep_nesting_rejected_not_crashed(self) -> None:
        """20k-deep nesting must produce a typed ValueError, not an uncaught
        RecursionError.  For the most security-relevant component in this
        checker, a crash on adversarial input is a worse failure mode than a
        rejection — a crash gives an attacker a denial-of-service on the
        checker itself instead of a verdict."""
        deeply_nested = ('[' * 20_000) + (']' * 20_000)
        with pytest.raises(ValueError, match='nesting too deep'):
            lex(deeply_nested)

    def test_shallow_nesting_unaffected(self) -> None:
        """The depth bound must not reject ordinary CPB records."""
        value, violations = lex(b'{"a":{"b":{"c":[1,2,3]}}}')
        assert value == {'a': {'b': {'c': [1, 2, 3]}}}
        assert violations == []

    def test_deep_nesting_mutant_crashes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """MUTANT: raise the depth bound far above CPython's recursion limit --
        the pre-fix behavior.  Demonstrates the guard is load-bearing: without
        it, the same input that test_deep_nesting_rejected_not_crashed handles
        cleanly instead crashes with RecursionError."""
        import cpb._lex as lex_module
        monkeypatch.setattr(lex_module, '_MAX_DEPTH', 1_000_000)
        deeply_nested = ('[' * 20_000) + (']' * 20_000)
        with pytest.raises(RecursionError):
            lex_module.lex(deeply_nested)
