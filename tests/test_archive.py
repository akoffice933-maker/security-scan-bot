import io
import zipfile
from pathlib import Path

import pytest

from app.services.archive import extract_archive, is_allowed_archive


def test_allowed_names():
    assert is_allowed_archive("src.zip")
    assert is_allowed_archive("src.tar.gz")
    assert not is_allowed_archive("src.exe")


def test_extract_zip(tmp_path: Path):
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("hello/world.txt", "hi")
    dest = tmp_path / "out"
    extract_archive(archive, dest)
    assert (dest / "hello" / "world.txt").read_text() == "hi"


def test_zip_slip_rejected(tmp_path: Path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("../pwned.txt")
        zf.writestr(info, "nope")
    with pytest.raises(ValueError, match="отказ"):
        extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "pwned.txt").exists()


def test_absolute_path_in_zip_rejected(tmp_path: Path):
    archive = tmp_path / "abs.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("/tmp/evil.txt", "nope")
    archive.write_bytes(buf.getvalue())
    with pytest.raises(ValueError):
        extract_archive(archive, tmp_path / "out")
