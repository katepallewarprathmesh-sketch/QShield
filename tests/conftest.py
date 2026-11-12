from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
CLEAN = FIXTURES / "clean_circuits"
MALICIOUS = FIXTURES / "malicious_circuits"


def fixture_text(directory: Path, name: str) -> str:
    return (directory / name).read_text(encoding="utf-8")


@pytest.fixture()
def clean_dir() -> Path:
    return CLEAN


@pytest.fixture()
def malicious_dir() -> Path:
    return MALICIOUS


@pytest.fixture()
def clean_circuits() -> dict[str, Path]:
    return {p.stem: p for p in sorted(CLEAN.glob("*.qasm"))}


@pytest.fixture()
def malicious_circuits() -> dict[str, Path]:
    return {p.stem: p for p in sorted(MALICIOUS.glob("*.qasm"))}


@pytest.fixture()
def bell_source() -> str:
    return (CLEAN / "bell_state.qasm").read_text(encoding="utf-8")
