import zipfile

import pytest

from app.services.parser import ParseError, safe_extract_zip, validate_zip_members


def test_zip_traversal_is_rejected(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../escape.tf", "resource {}")
    with pytest.raises(ParseError, match="Unsafe ZIP"):
        safe_extract_zip(archive, tmp_path / "extract")


def test_zip_ratio_is_bounded(tmp_path):
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr("large.tf", "a" * 200_000)
    with pytest.raises(ParseError, match="compression ratio"):
        safe_extract_zip(archive, tmp_path / "extract")


def test_zip_symlinks_and_encrypted_members_are_rejected():
    symlink = zipfile.ZipInfo("link.tf")
    symlink.create_system = 3
    symlink.external_attr = 0o120777 << 16
    with pytest.raises(ParseError, match="symbolic links"):
        validate_zip_members([symlink])

    encrypted = zipfile.ZipInfo("secret.tf")
    encrypted.flag_bits = 0x1
    with pytest.raises(ParseError, match="Encrypted ZIP"):
        validate_zip_members([encrypted])
