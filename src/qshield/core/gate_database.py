"""Database of known quantum gates with unitary matrix generators.

Each entry describes the canonical name, arity, parameter signature and a
function producing the unitary matrix given numeric parameters.  Aliases map
framework-specific names onto the canonical ones.

Matrix convention: a k-qubit gate's matrix acts on its own subsystem with the
gate's qubit list taken in order, qubit 0 of the gate being the most
significant.  Angles are in radians.  ``rz`` uses the Qiskit/OpenQASM
convention ``diag(e^{-iθ/2}, e^{iθ/2})``.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from math import e, pi, sqrt

import numpy as np

SQRT1_2 = 1.0 / sqrt(2.0)
EXP_I_PI_4 = e ** (1j * pi / 4)

I2 = np.eye(2, dtype=complex)
X = np.array([[0, 1], [1, 0]], dtype=complex)
Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
Z = np.array([[1, 0], [0, -1]], dtype=complex)
H = SQRT1_2 * np.array([[1, 1], [1, -1]], dtype=complex)
S = np.array([[1, 0], [0, 1j]], dtype=complex)
SDG = np.array([[1, 0], [0, -1j]], dtype=complex)
T = np.array([[1, 0], [0, EXP_I_PI_4]], dtype=complex)
TDG = np.array([[1, 0], [0, np.conj(EXP_I_PI_4)]], dtype=complex)
SX = 0.5 * np.array([[1 + 1j, 1 - 1j], [1 - 1j, 1 + 1j]], dtype=complex)
CNOT = np.array(
    [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]], dtype=complex
)
CX = CNOT
CY = np.array(
    [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, -1j], [0, 0, 1j, 0]], dtype=complex
)
CZ = np.diag([1, 1, 1, -1]).astype(complex)
SWAP = np.array(
    [[1, 0, 0, 0], [0, 0, 1, 0], [0, 1, 0, 0], [0, 0, 0, 1]], dtype=complex
)


def _rx(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.array([[c, -1j * s], [-1j * s, c]], dtype=complex)


def _ry(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.array([[c, -s], [s, c]], dtype=complex)


def _rz(theta: float) -> np.ndarray:
    return np.diag([np.exp(-1j * theta / 2), np.exp(1j * theta / 2)])


def _u1(lam: float) -> np.ndarray:
    return np.diag([1.0, np.exp(1j * lam)])


def _u2(phi: float, lam: float) -> np.ndarray:
    return SQRT1_2 * np.array(
        [[1, -np.exp(1j * lam)], [np.exp(1j * phi), np.exp(1j * (phi + lam))]],
        dtype=complex,
    )


def _u3(theta: float, phi: float, lam: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.array(
        [
            [c, -np.exp(1j * lam) * s],
            [np.exp(1j * phi) * s, np.exp(1j * (phi + lam)) * c],
        ],
        dtype=complex,
    )


def _p(lam: float) -> np.ndarray:
    return _u1(lam)


def _crz(lam: float) -> np.ndarray:
    return np.diag(
        [1.0, 1.0, np.exp(-1j * lam / 2), np.exp(1j * lam / 2)]
    ).astype(complex)


def _cp(lam: float) -> np.ndarray:
    return np.diag([1.0, 1.0, 1.0, np.exp(1j * lam)]).astype(complex)


def _crx(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.array(
        [
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, c, -1j * s],
            [0, 0, -1j * s, c],
        ],
        dtype=complex,
    )


def _cry(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.array(
        [
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, c, -s],
            [0, 0, s, c],
        ],
        dtype=complex,
    )


def _ch(_: float | None = None) -> np.ndarray:
    zero = np.array([[1, 0], [0, 0]], dtype=complex)
    return np.block([[zero, np.zeros((2, 2))], [np.zeros((2, 2)), H]])


def _cu3(theta: float, phi: float, lam: float) -> np.ndarray:
    u3 = _u3(theta, phi, lam)
    z = np.zeros((2, 2), dtype=complex)
    return np.block([[np.eye(2, dtype=complex), z], [z, u3]])


def _rxx(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.eye(4, dtype=complex) * c + (-1j * s) * np.kron(X, X)


def _ryy(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.eye(4, dtype=complex) * c + (-1j * s) * np.kron(Y, Y)


def _rzz(theta: float) -> np.ndarray:
    c, s = np.cos(theta / 2), np.sin(theta / 2)
    return np.eye(4, dtype=complex) * c + (-1j * s) * np.kron(Z, Z)


def _toffoli(_: float | None = None) -> np.ndarray:
    m = np.eye(8, dtype=complex)
    m[6, 6] = 0
    m[7, 7] = 0
    m[6, 7] = 1
    m[7, 6] = 1
    return m


@dataclass(frozen=True)
class GateSpec:
    name: str
    arity: int
    num_params: int  # required parameter count (-1 for variadic-special)
    matrix: Callable[..., np.ndarray]
    is_parameterized: bool


def _spec(name, arity, num_params, matrix):
    return GateSpec(
        name=name,
        arity=arity,
        num_params=num_params,
        matrix=matrix,
        is_parameterized=num_params != 0,
    )


_GATE_SPECS: list[GateSpec] = [
    _spec("id", 1, 0, lambda: I2.copy()),
    _spec("iden", 1, 0, lambda: I2.copy()),
    _spec("x", 1, 0, lambda: X.copy()),
    _spec("y", 1, 0, lambda: Y.copy()),
    _spec("z", 1, 0, lambda: Z.copy()),
    _spec("h", 1, 0, lambda: H.copy()),
    _spec("s", 1, 0, lambda: S.copy()),
    _spec("sdg", 1, 0, lambda: SDG.copy()),
    _spec("t", 1, 0, lambda: T.copy()),
    _spec("tdg", 1, 0, lambda: TDG.copy()),
    _spec("sx", 1, 0, lambda: SX.copy()),
    _spec("sxdg", 1, 0, lambda: SX.conj().T.copy()),
    _spec("rx", 1, 1, _rx),
    _spec("ry", 1, 1, _ry),
    _spec("rz", 1, 1, _rz),
    _spec("p", 1, 1, _p),
    _spec("u1", 1, 1, _u1),
    _spec("u2", 1, 2, _u2),
    _spec("u3", 1, 3, _u3),
    _spec("u", 1, 3, _u3),
    # 2-qubit
    _spec("cx", 2, 0, lambda: CNOT.copy()),
    _spec("cy", 2, 0, lambda: CY.copy()),
    _spec("cz", 2, 0, lambda: CZ.copy()),
    _spec("swap", 2, 0, lambda: SWAP.copy()),
    _spec("ch", 2, 0, _ch),
    _spec("crz", 2, 1, _crz),
    _spec("cp", 2, 1, _cp),
    _spec("cu1", 2, 1, _cp),
    _spec("crx", 2, 1, _crx),
    _spec("cry", 2, 1, _cry),
    _spec("cu3", 2, 3, _cu3),
    _spec("cu", 2, 3, _cu3),
    _spec("rxx", 2, 1, _rxx),
    _spec("ryy", 2, 1, _ryy),
    _spec("rzz", 2, 1, _rzz),
    # 3-qubit
    _spec("ccx", 3, 0, _toffoli),
    _spec("ccz", 3, 0, lambda: np.diag([1] * 7 + [-1]).astype(complex)),
]

ALIASES: dict[str, str] = {
    "cnot": "cx",
    "toffoli": "ccx",
    "ccnot": "ccx",
    "identity": "id",
    "idg": "id",
    "cphase": "cp",
    "cphi": "cp",
    "cu1_": "cu1",
    "rcx": "crx",
    "p_": "p",
    "ph": "p",
    "phase": "p",
    "u_1": "u1",
    "u_2": "u2",
    "u_3": "u3",
}


class GateDatabase:
    """Lookup of gate specifications and unitary matrices."""

    def __init__(self) -> None:
        self._specs: dict[str, GateSpec] = {}
        for spec in _GATE_SPECS:
            self._specs[spec.name] = spec
        for alias, target in ALIASES.items():
            base = self._specs.get(target)
            if base is not None:
                self._specs[alias] = GateSpec(
                    name=alias,
                    arity=base.arity,
                    num_params=base.num_params,
                    matrix=base.matrix,
                    is_parameterized=base.is_parameterized,
                )

    # ------------------------------------------------------------------
    def known_names(self) -> list[str]:
        return sorted(self._specs)

    def has(self, name: str) -> bool:
        return self.canon(name) in self._specs

    @staticmethod
    def canon(name: str) -> str:
        n = name.strip().lower()
        # strip trailing markers used by some exporters
        if n.endswith(("†", "_dag")):
            pass  # leave as-is; adjoint handled by caller if needed
        return n

    def get_spec(self, name: str) -> GateSpec | None:
        return self._specs.get(self.canon(name))

    def arity(self, name: str) -> int | None:
        spec = self.get_spec(name)
        return spec.arity if spec else None

    def is_parameterized(self, name: str) -> bool:
        spec = self.get_spec(name)
        return bool(spec and spec.is_parameterized)

    def matrix(self, name: str, params: list[float] | None = None) -> np.ndarray | None:
        """Return the unitary for ``name(params)`` or ``None`` if unknown."""
        spec = self.get_spec(name)
        if spec is None:
            return None
        params = list(params or [])
        # tolerate symbolic / unknown parameters: treat NaN as 0.0
        params = [p if (isinstance(p, (int, float)) and not math.isnan(p)) else 0.0 for p in params]
        if spec.is_parameterized:
            if len(params) < spec.num_params:
                return None
            try:
                mat = spec.matrix(*params[: spec.num_params])
            except Exception:
                return None
        else:
            # some param-free specs accept an optional argument (e.g. ch)
            try:
                mat = spec.matrix()
            except TypeError:
                mat = spec.matrix(None)
        return np.asarray(mat, dtype=complex)

    def is_unitary(self, name: str, params: list[float] | None = None, tol: float = 1e-9) -> bool:
        mat = self.matrix(name, params)
        if mat is None:
            return False
        ident = np.eye(mat.shape[0], dtype=complex)
        return np.allclose(mat.conj().T @ mat, ident, atol=tol)


#: Shared singleton instance.
GATE_DB = GateDatabase()
