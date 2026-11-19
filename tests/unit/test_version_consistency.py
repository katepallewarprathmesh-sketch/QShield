"""The package version must match the version declared in pyproject.toml."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import qshield

_ROOT = Path(__file__).resolve().parents[2]


def _declared_version() -> str:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # Python 3.10
        tomllib = pytest.importorskip("tomli", reason="tomli backfills tomllib on 3.10")
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def _fallback_version() -> str:
    source = (_ROOT / "src" / "qshield" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', source, re.M)
    assert match is not None, "no __version__ literal in src/qshield/__init__.py"
    return match.group(1)


def test_package_version_matches_pyproject() -> None:
    assert qshield.__version__ == _declared_version()


def test_fallback_literal_matches_pyproject() -> None:
    assert _fallback_version() == _declared_version()
