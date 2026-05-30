"""Constants and configuration helpers for the viewer TUI."""
from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv


# ── base directory (works both from source and as a PyInstaller binary) ───────
if getattr(sys, "frozen", False):
    # Running as a compiled binary — place .env next to the executable
    BASE_DIR = Path(sys.executable).parent
    SRC_DIR = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    BASE_DIR = Path(__file__).parent.parent
    SRC_DIR = BASE_DIR


# ── version ───────────────────────────────────────────────────────────────────
try:
    VERSION = (SRC_DIR / "version.txt").read_text(encoding="utf-8").strip()
except Exception:
    VERSION = "unknown"


# ── runtime limits ────────────────────────────────────────────────────────────
MAX_ROWS = 5000  # maximum rows kept in memory


# ── category dropdown options ─────────────────────────────────────────────────
CATEGORY_OPTIONS: list[tuple[str, str]] = [
    ("NetworkRule", "networkrule"),
    ("AppRule", "apprule"),
    ("NATRule", "natrule"),
    ("DnsQuery", "dnsquery"),
    ("IDPS", "idps"),
    ("ThreatIntel", "threatintel"),
]


def load_env(path: Path, override: bool = False) -> None:
    """Load a .env file, falling back to latin-1 if the file is not valid UTF-8."""
    try:
        load_dotenv(path, encoding="utf-8", override=override)
    except UnicodeDecodeError:
        load_dotenv(path, encoding="latin-1", override=override)
