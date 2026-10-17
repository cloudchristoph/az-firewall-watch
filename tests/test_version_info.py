"""scripts/version_info.py: the Windows version resource SignPath pins (ProductName, ProductVersion)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "version_info.py"
_spec = importlib.util.spec_from_file_location("version_info", _SCRIPT)
assert _spec and _spec.loader
version_info = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(version_info)


def test_renders_product_name_and_version():
    text = version_info.render("0.7.0\n")
    assert "filevers=(0, 7, 0, 0)" in text and "prodvers=(0, 7, 0, 0)" in text
    assert "StringStruct('ProductName', 'Azure Firewall Watch')" in text
    assert "StringStruct('ProductVersion', '0.7.0')" in text
    assert "StringStruct('OriginalFilename', 'az-firewall-watch.exe')" in text
    assert "StringStruct('CompanyName', 'CloudChristoph')" in text


@pytest.mark.parametrize("bad", ["0.7", "v0.7.0", "0.7.0-rc1", "unknown", ""])
def test_rejects_anything_but_major_minor_patch(bad):
    with pytest.raises(SystemExit):
        version_info.render(bad)


def test_repo_version_renders():
    version = (_SCRIPT.parent.parent / "version.txt").read_text(encoding="utf-8")
    assert f"StringStruct('ProductVersion', '{version.strip()}')" in version_info.render(version)
