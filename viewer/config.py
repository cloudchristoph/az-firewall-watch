"""Constants and configuration helpers for the viewer TUI."""
from __future__ import annotations

import sys
from pathlib import Path

from helpers import load_env  # re-exported for main.py


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
# The table may exceed MAX_ROWS by this many rows before a full rebuild trims it
# (removing rows one by one is O(n) each in Textual's DataTable).
TABLE_TRIM_SLACK = 250


# ── category dropdown options ─────────────────────────────────────────────────
CATEGORY_OPTIONS: list[tuple[str, str]] = [
    ("NetworkRule", "networkrule"),
    ("AppRule", "apprule"),
    ("NATRule", "natrule"),
    ("DnsQuery", "dnsquery"),
    ("IDPS", "idps"),
    ("ThreatIntel", "threatintel"),
]

__all__ = ["BASE_DIR", "SRC_DIR", "VERSION", "MAX_ROWS", "TABLE_TRIM_SLACK", "CATEGORY_OPTIONS", "load_env"]
