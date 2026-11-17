from __future__ import annotations

from pathlib import Path

import pytest

import scripts.build_static_site as site_builder


def test_builder_renders_public_threat_model_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "source.html"
    source.write_text("<title>QSHIELD Threat Model</title> v__QSHIELD_VERSION__", encoding="utf-8")
    monkeypatch.setattr(site_builder, "THREAT_MODEL_PAGE", source)
    target = site_builder._write_public_threat_model(tmp_path / "out", "1.3.0")
    assert target.name == "threat-model.html"
    assert "v1.3.0" in target.read_text(encoding="utf-8")
    assert "__QSHIELD_VERSION__" not in target.read_text(encoding="utf-8")


def test_builder_fails_if_public_threat_model_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(site_builder, "THREAT_MODEL_PAGE", tmp_path / "missing.html")
    with pytest.raises(RuntimeError, match="not found"):
        site_builder._write_public_threat_model(tmp_path / "out", "1.3.0")
