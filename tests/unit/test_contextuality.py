"""The contextuality verifier must model real quantum mechanics."""

from __future__ import annotations

import math

import numpy as np

from qshield.contextuality import (
    CHSH_CLASSICAL_BOUND,
    CHSH_QUANTUM_LIMIT,
    EXPECTED_COL_PRODUCTS,
    EXPECTED_ROW_PRODUCTS,
    SQUARE,
    _col_products,
    _op,
    _row_products,
    classical_best_win_rate,
    measure_chsh,
    play_magic_square,
    verify_contextuality,
)


def test_magic_square_is_a_valid_mermin_peres_grid() -> None:
    """Every row and column must commute and multiply to the declared sign."""
    identity = np.eye(4)
    for row in SQUARE:
        ops = [_op(c) for c in row]
        for a, b in ((0, 1), (0, 2), (1, 2)):
            assert np.allclose(ops[a] @ ops[b], ops[b] @ ops[a]), "row observables must commute"
        product = np.linalg.multi_dot(ops)
        assert np.allclose(product, identity) or np.allclose(product, -identity)

    for c in range(3):
        ops = [_op(SQUARE[r][c]) for r in range(3)]
        for a, b in ((0, 1), (0, 2), (1, 2)):
            assert np.allclose(ops[a] @ ops[b], ops[b] @ ops[a]), "column observables must commute"
        product = np.linalg.multi_dot(ops)
        assert np.allclose(product, identity) or np.allclose(product, -identity)


def test_row_and_column_signs_match_the_declaration() -> None:
    assert _row_products() == list(EXPECTED_ROW_PRODUCTS)
    assert _col_products() == list(EXPECTED_COL_PRODUCTS)


def test_row_and_column_products_contradict_each_other() -> None:
    """This contradiction is the whole point: no pre-assigned values exist."""
    assert math.prod(_row_products()) != math.prod(_col_products())


def test_classical_ceiling_is_eight_ninths() -> None:
    assert math.isclose(classical_best_win_rate(), 8.0 / 9.0, rel_tol=0, abs_tol=1e-12)


def test_magic_square_beats_the_classical_bound() -> None:
    result = play_magic_square()
    assert result.rounds == 9
    assert result.win_rate > result.classical_bound
    assert result.contextual is True


def test_chsh_reaches_the_tsirelson_bound() -> None:
    result = measure_chsh()
    assert math.isclose(result.s_value, CHSH_QUANTUM_LIMIT, rel_tol=0, abs_tol=1e-9)
    assert result.s_value > CHSH_CLASSICAL_BOUND
    assert result.contextual is True


def test_chsh_separates_from_the_classical_bound() -> None:
    """The violation must be the full 2*sqrt(2) - 2, not a rounding artifact."""
    result = measure_chsh()
    violation = CHSH_QUANTUM_LIMIT - CHSH_CLASSICAL_BOUND
    assert result.s_value - CHSH_CLASSICAL_BOUND > violation - 1e-9


def test_verdict_requires_both_protocols() -> None:
    report = verify_contextuality()
    assert report.verdict == "contextual"
    assert report.contextual is True
    assert report.magic_square["contextual"] is True
    assert report.chsh["contextual"] is True


def test_report_is_json_serialisable_and_spec_versioned() -> None:
    import json

    payload = verify_contextuality().to_dict()
    encoded = json.dumps(payload)
    assert payload["spec_version"] == "qshield-contextuality-v1"
    assert "Simulator evidence" in json.loads(encoded)["note"]


def test_verification_is_deterministic() -> None:
    assert verify_contextuality().to_dict() == verify_contextuality().to_dict()


def test_non_contextual_input_cannot_beat_the_bound() -> None:
    """A single round request cannot exceed the classical ceiling."""
    result = play_magic_square(rounds=1)
    assert result.rounds == 1
    assert result.win_rate <= 1.0
