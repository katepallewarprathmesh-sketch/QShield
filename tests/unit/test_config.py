import pytest

from qshield.core.config import load_config


def test_default_config():
    cfg = load_config("default")
    assert cfg.static_check("check_dead_qubits")
    assert cfg.threshold("min_confidence") == 0.5
    assert not cfg.dynamic_enabled


def test_strict_profile():
    cfg = load_config("strict")
    assert cfg.threshold("min_confidence") == 0.3
    assert cfg.threshold("gate_count_multiplier") == 1.5


def test_permissive_profile():
    cfg = load_config("permissive")
    assert cfg.threshold("min_confidence") == 0.8
    assert cfg.threshold("gate_count_multiplier") == 3.0


def test_file_config(tmp_path):
    cfg_file = tmp_path / ".qshield.yaml"
    cfg_file.write_text(
        "thresholds:\n  min_confidence: 0.9\nanalysis:\n  static:\n    check_dead_qubits: false\n"
    )
    cfg = load_config(str(cfg_file))
    assert cfg.threshold("min_confidence") == 0.9
    assert not cfg.static_check("check_dead_qubits")


def test_unknown_profile():
    with pytest.raises(FileNotFoundError):
        load_config("does-not-exist")
