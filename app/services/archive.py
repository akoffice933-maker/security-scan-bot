"""Safe archive extraction (zip-slip and zip-bomb resistant)."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

ALLOWED_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
_CHUNK = 64 * 1024


def is_allowed_archive(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(s) for s in ALLOWED_SUFFIXES)


def _safe_join(root: Path, member: str) -> Path:
    dest = (root / member).resolve()
    root_resolved = root.resolve()
    if dest != root_resolved and not str(dest).startswith(str(root_resolved) + "/"):
        raise ValueError(f"отказ: путь выходит за каталог распаковки ({member})")
    return dest


def _copy_limited(src, dest_path: Path, written: list[int]) -> None:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "wb") as out:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            written[0] += len(chunk)
            if written[0] > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("архив слишком большой после распаковки (zip-бомба)")
            out.write(chunk)


def extract_archive(archive_path: str | Path, dest_dir: str | Path) -> Path:
    archive = Path(archive_path)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    written = [0]
    files = 0

    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    _safe_join(dest, info.filename)
                    continue
                files += 1
                if files > MAX_ARCHIVE_FILES:
                    raise ValueError("в архиве слишком много файлов")
                if info.file_size and written[0] + int(info.file_size) > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("архив слишком большой после распаковки (zip-бомба)")
                target = _safe_join(dest, info.filename)
                with zf.open(info, "r") as src:
                    _copy_limited(src, target, written)
        return dest

    if name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(archive, "r:*") as tf:
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    continue
                if member.isdir():
                    _safe_join(dest, member.name)
                    continue
                if not member.isfile():
                    continue
                files += 1
                if files > MAX_ARCHIVE_FILES:
                    raise ValueError("в архиве слишком много файлов")
                if member.size and written[0] + int(member.size) > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("архив слишком большой после распаковки (zip-бомба)")
                target = _safe_join(dest, member.name)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                with extracted:
                    _copy_limited(extracted, target, written)
        return dest

    raise ValueError("поддерживаются zip и tar.* архивы")
