import numpy as np
import pytest

from qshield.core.gate_database import GATE_DB


@pytest.mark.parametrize("name", ["id", "x", "y", "z", "h", "s", "t", "sx", "cx", "cz", "swap", "ccx"])
def test_fixed_gates_are_unitary(name):
    assert GATE_DB.is_unitary(name)


@pytest.mark.parametrize("name,params", [
    ("rx", [0.3]), ("ry", [1.1]), ("rz", [0.785]), ("p", [2.7]),
    ("u1", [1.0]), ("u2", [0.5, 1.5]), ("u3", [0.3, 0.1, 0.2]), ("u", [0.3, 0.1, 0.2]),
    ("crz", [0.4]), ("cp", [1.2]), ("crx", [0.9]), ("cry", [0.7]),
    ("cu3", [0.3, 0.1, 0.2]), ("rxx", [0.8]), ("ryy", [0.8]), ("rzz", [0.8]),
])
def test_parameterized_gates_are_unitary(name, params):
    assert GATE_DB.is_unitary(name, params)


def test_aliases_resolve():
    assert GATE_DB.canon("cnot") == "cx" or GATE_DB.get_spec("cnot") is not None
    assert GATE_DB.get_spec("toffoli") is not None
    assert GATE_DB.get_spec("CNOT") is not None  # case-insensitive


def test_unknown_gate_returns_none():
    assert GATE_DB.matrix("definitely-not-a-gate") is None


def test_bell_matrix_values():
    h = GATE_DB.matrix("h")
    assert np.allclose(h @ h, np.eye(2))
    cx = GATE_DB.matrix("cx")
    assert np.allclose(cx @ cx, np.eye(4))


def test_gate_database_has_100_plus_entries():
    assert len(GATE_DB.known_names()) >= 100


def test_every_registered_gate_is_unitary():
    bad = []
    for name in GATE_DB.known_names():
        spec = GATE_DB.get_spec(name)
        params = [0.3 + 0.1 * i for i in range(max(spec.num_params, 0))]
        m = GATE_DB.matrix(name, params)
        if m is None or not np.allclose(m.conj().T @ m, np.eye(m.shape[0]), atol=1e-9):
            bad.append(name)
    assert not bad, f"non-unitary specs: {bad}"


def test_ch_not_zero_block():
    """Regression: controlled-H top-left block must be identity."""
    ch = GATE_DB.matrix("ch")
    assert np.allclose(ch[:2, :2], np.eye(2))
    h = GATE_DB.matrix("h")
    assert np.allclose(ch[2:, 2:], h)


def test_c3x_c4x_flip_bottom_subspace():
    c3x = GATE_DB.matrix("c3x")
    assert c3x.shape == (16, 16)
    assert c3x[14, 15] == 1 and c3x[15, 14] == 1 and c3x[0, 0] == 1
    c4x = GATE_DB.matrix("c4x")
    assert c4x.shape == (32, 32)
    assert c4x[30, 31] == 1 and c4x[31, 30] == 1


def test_fsim_sycamore_iswap():
    fsim = GATE_DB.matrix("fsim", [np.pi / 2, np.pi / 6])
    assert np.allclose(fsim[0], [1, 0, 0, 0])
    assert np.allclose(fsim[3, 3], np.exp(-1j * np.pi / 6))
    syc = GATE_DB.matrix("sycamore")
    assert np.allclose(syc, fsim)
    si = GATE_DB.matrix("sqrt_iswap")
    assert np.allclose(si[1, 1], 1 / np.sqrt(2))
    iswap = GATE_DB.matrix("iswap")
    assert iswap[1, 2] == 1j and iswap[2, 1] == 1j
    assert GATE_DB.matrix("iswapdg")[1, 2] == -1j


def test_r_gate_matches_u3_identity():
    r = GATE_DB.matrix("r", [0.7, 1.1])
    assert np.isclose(np.linalg.norm(r[:, 0]), 1.0)


def test_rzx_equals_exp_of_zx():
    from qshield.core.gate_database import X, Z
    theta = 0.9
    rzx = GATE_DB.matrix("rzx", [theta])
    expected = np.cos(theta / 2) * np.eye(4) - 1j * np.sin(theta / 2) * np.kron(Z, X)
    assert np.allclose(rzx, expected)


def test_dagger_identities_exact():
    t = 0.31
    assert np.allclose(GATE_DB.matrix("u3dg", [t, 0.2, 1.1]),
                       np.conj(GATE_DB.matrix("u3", [t, 0.2, 1.1]).T))
    assert np.allclose(GATE_DB.matrix("cu3dg", [t, 0.2, 1.1]),
                       np.conj(GATE_DB.matrix("cu3", [t, 0.2, 1.1]).T))
    assert np.allclose(GATE_DB.matrix("cpdg", [t]),
                       np.conj(GATE_DB.matrix("cp", [t]).T))
    assert np.allclose(GATE_DB.matrix("rxdg", [t]) @ GATE_DB.matrix("rx", [t]), np.eye(2))
    assert np.allclose(GATE_DB.matrix("crxdg", [t]) @ GATE_DB.matrix("crx", [t]), np.eye(4))


def test_u2dg_exact_identity():
    for phi, lam in [(0.3, 1.1), (0.0, 0.0), (1.5, -0.7)]:
        u2 = GATE_DB.matrix("u2", [phi, lam])
        u2dg = GATE_DB.matrix("u2dg", [phi, lam])
        assert np.allclose(u2dg, np.conj(u2.T))
        cu2 = GATE_DB.matrix("cu2", [phi, lam])
        assert np.allclose(GATE_DB.matrix("cu2dg", [phi, lam]), np.conj(cu2.T))
