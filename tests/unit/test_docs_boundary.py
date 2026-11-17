from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.check_public_docs_boundary import (
    BoundaryError,
    _is_docs_path,
    check_distributions,
    check_public_site,
    check_source_tree,
)


def test_docs_path_detection_is_segment_based():
    assert _is_docs_path("docs/threat-model.md")
    assert _is_docs_path("qshield-1.0/docs/internal.md")
    assert not _is_docs_path("scripts/site/threat-model.html")
    assert not _is_docs_path("src/qshield/documentation.py")


def test_source_tree_rejects_docs_directory(tmp_path: Path):
    (tmp_path / "docs").mkdir()
    with pytest.raises(BoundaryError, match="must not exist"):
        check_source_tree(tmp_path)


def test_distribution_check_rejects_docs_and_accepts_public_docs_location(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    with tarfile.open(dist / "qshield-1.3.0.tar.gz", "w:gz") as archive:
        info = tarfile.TarInfo("qshield-1.3.0/README.md")
        info.size = 0
        archive.addfile(info)
        info = tarfile.TarInfo("qshield-1.3.0/docs/internal.md")
        info.size = 0
        archive.addfile(info)
    with zipfile.ZipFile(dist / "qshield-1.3.0-py3-none-any.whl", "w") as archive:
        archive.writestr("qshield/__init__.py", "")
    with pytest.raises(BoundaryError, match="internal docs found"):
        check_distributions(dist)


def test_public_site_requires_generated_threat_model(tmp_path: Path):
    with pytest.raises(BoundaryError, match="page missing"):
        check_public_site(tmp_path)
    page = tmp_path / "threat-model.html"
    page.write_text("<!doctype html><title>QSHIELD Threat Model</title> v1.3.0", encoding="utf-8")
    check_public_site(tmp_path)


def test_public_site_rejects_internal_docs_path(tmp_path: Path):
    (tmp_path / "threat-model.html").write_text(
        "<title>QSHIELD Threat Model</title> v1.3.0", encoding="utf-8"
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "secret.md").write_text("internal", encoding="utf-8")
    with pytest.raises(BoundaryError, match="internal docs path"):
        check_public_site(tmp_path)
