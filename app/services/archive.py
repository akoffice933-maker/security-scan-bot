"""Safe archive extraction (zip-slip resistant)."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

ALLOWED_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024


def is_allowed_archive(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(s) for s in ALLOWED_SUFFIXES)


def _safe_join(root: Path, member: str) -> Path:
    dest = (root / member).resolve()
    root_resolved = root.resolve()
    if dest != root_resolved and not str(dest).startswith(str(root_resolved) + "/"):
        raise ValueError(f"отказ: путь выходит за каталог распаковки ({member})")
    return dest


def extract_archive(archive_path: str | Path, dest_dir: str | Path) -> Path:
    archive = Path(archive_path)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()

    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    _safe_join(dest, info.filename)
                    continue
                target = _safe_join(dest, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, open(target, "wb") as out:
                    out.write(src.read())
        return dest

    if name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(archive, "r:*") as tf:
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    continue
                _safe_join(dest, member.name)
            tf.extractall(dest, filter="data")
        return dest

    raise ValueError("поддерживаются zip и tar.* архивы")
