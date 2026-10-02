"""Write the Windows version resource that PyInstaller embeds into the .exe.

SignPath pins ProductName and ProductVersion in its artifact configuration,
so both come from one place: ``version.txt``.

Usage: python scripts/version_info.py [OUTPUT]   (default: version_info.txt)
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRODUCT = "Azure Firewall Watch"

TEMPLATE = """\
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', ''),
          StringStruct('FileDescription', '{product}'),
          StringStruct('FileVersion', '{version}'),
          StringStruct('InternalName', 'az-firewall-watch'),
          StringStruct('LegalCopyright', 'MIT License'),
          StringStruct('OriginalFilename', 'az-firewall-watch.exe'),
          StringStruct('ProductName', '{product}'),
          StringStruct('ProductVersion', '{version}')
        ]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def render(version: str) -> str:
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version.strip())
    if not m:
        raise SystemExit(f"version.txt must read MAJOR.MINOR.PATCH, got {version!r}")
    major, minor, patch = m.groups()
    return TEMPLATE.format(major=major, minor=minor, patch=patch, product=PRODUCT, version=version.strip())


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "version_info.txt")
    out.write_text(render((ROOT / "version.txt").read_text()), encoding="utf-8")
