"""Deterministic source archive normalization used by the release workflow."""

from __future__ import annotations

import gzip
import hashlib
import io
import runpy
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
normalize_sdist = runpy.run_path(str(ROOT / "scripts" / "normalize_sdist.py"))["normalize_sdist"]


def _make_sdist(path: Path, *, mtime: int, gzip_mtime: int, uid: int) -> None:
    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="arbitrary-name", mode="wb", fileobj=raw, mtime=gzip_mtime) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        root = tarfile.TarInfo("qshield-1.5.0")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.mtime = mtime
        root.uid = uid
        root.gid = uid
        root.uname = "builder"
        root.gname = "builders"
        archive.addfile(root)

        data = b"release contents\n"
        member = tarfile.TarInfo("qshield-1.5.0/README.md")
        member.size = len(data)
        member.mode = 0o644
        member.mtime = mtime
        member.uid = uid
        member.gid = uid
        member.uname = "builder"
        member.gname = "builders"
        archive.addfile(member, io.BytesIO(data))


def test_sdist_normalization_is_byte_reproducible(tmp_path):
    first, second = tmp_path / "first.tar.gz", tmp_path / "second.tar.gz"
    _make_sdist(first, mtime=1_700_000_000, gzip_mtime=1_700_000_001, uid=1000)
    _make_sdist(second, mtime=1_800_000_000, gzip_mtime=1_800_000_001, uid=2000)

    normalize_sdist(first, 1_650_000_000)
    normalize_sdist(second, 1_650_000_000)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()

    with tarfile.open(first, "r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == sorted(member.name for member in members)
        assert all(member.mtime == 1_650_000_000 for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        assert archive.extractfile("qshield-1.5.0/README.md").read() == b"release contents\n"


def test_sdist_normalization_rejects_traversal_paths(tmp_path):
    path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("../outside.txt")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))

    with pytest.raises(ValueError, match="unsafe path"):
        normalize_sdist(path, 1_650_000_000)
