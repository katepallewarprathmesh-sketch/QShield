from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "build_static_site.py"
_SPEC = importlib.util.spec_from_file_location("qshield_build_static_site", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
site_builder = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(site_builder)


def test_builder_renders_security_architecture_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "source.html"
    source.write_text("<title>QSHIELD Security Architecture</title> v__QSHIELD_VERSION__", encoding="utf-8")
    monkeypatch.setattr(site_builder, "SECURITY_ARCHITECTURE_PAGE", source)
    target = site_builder._write_security_architecture_page(tmp_path / "out", "1.3.0")
    assert target.name == "security-architecture.html"
    assert "v1.3.0" in target.read_text(encoding="utf-8")
    assert "__QSHIELD_VERSION__" not in target.read_text(encoding="utf-8")


def test_builder_fails_if_security_architecture_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(site_builder, "SECURITY_ARCHITECTURE_PAGE", tmp_path / "missing.html")
    with pytest.raises(RuntimeError, match="not found"):
        site_builder._write_security_architecture_page(tmp_path / "out", "1.3.0")


def test_builder_renders_public_benchmark_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "benchmark.html"
    source.write_text("<title>QSHIELD Open Benchmark</title> v__QSHIELD_VERSION__", encoding="utf-8")
    monkeypatch.setattr(site_builder, "BENCHMARK_PAGE", source)
    target = site_builder._write_benchmark_page(tmp_path / "out", "1.3.0")
    assert target.name == "benchmark.html"
    text = target.read_text(encoding="utf-8")
    assert "v1.3.0" in text and "__QSHIELD_VERSION__" not in text


def test_builder_fails_if_public_benchmark_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(site_builder, "BENCHMARK_PAGE", tmp_path / "missing.html")
    with pytest.raises(RuntimeError, match="not found"):
        site_builder._write_benchmark_page(tmp_path / "out", "1.3.0")
