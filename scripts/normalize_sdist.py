"""Normalize a built sdist archive for deterministic release comparisons."""

from __future__ import annotations

import argparse
import copy
import gzip
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def normalize_sdist(path: str | Path, source_date_epoch: int) -> None:
    """Rewrite one .tar.gz sdist with stable order, ownership, timestamps, and gzip header."""
    archive = Path(path)
    if source_date_epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    if not archive.is_file() or not archive.name.endswith(".tar.gz"):
        raise ValueError("expected an existing .tar.gz source distribution")

    fd, temp_name = tempfile.mkstemp(prefix=f".{archive.name}.", suffix=".tmp", dir=archive.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with tarfile.open(archive, mode="r:gz") as source:
            members = sorted(source.getmembers(), key=lambda member: member.name)
            for member in members:
                posix_name = PurePosixPath(member.name)
                if posix_name.is_absolute() or ".." in posix_name.parts:
                    raise ValueError(f"unsafe path in sdist: {member.name!r}")

            with (
                temp_path.open("wb") as raw_output,
                gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0, compresslevel=9) as gz,
                tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as normalized,
            ):
                for member in members:
                    info = copy.copy(member)
                    info.mtime = source_date_epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.pax_headers = {}
                    content = source.extractfile(member) if member.isfile() else None
                    try:
                        normalized.addfile(info, content)
                    finally:
                        if content is not None:
                            content.close()
                raw_output.flush()
                os.fsync(raw_output.fileno())
        os.replace(temp_path, archive)
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="built source distribution (.tar.gz)")
    parser.add_argument(
        "--source-date-epoch", type=int, required=True,
        help="stable UNIX timestamp used for tar member mtimes",
    )
    args = parser.parse_args()
    normalize_sdist(args.archive, args.source_date_epoch)


if __name__ == "__main__":
    main()
