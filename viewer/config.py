"""Constants and configuration helpers for the viewer TUI."""
from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path

from helpers import load_env  # re-exported for main.py


def is_homebrew_install(executable: str | Path) -> bool:
    """True when *executable* lives in a Homebrew Caskroom. ``brew`` links the
    binary into ``bin``, so the symlink is resolved first."""
    try:
        return "Caskroom" in Path(executable).resolve().parts
    except OSError:
        return False


def frozen_base_dir(executable: str | Path) -> Path:
    """Where a compiled binary keeps its ``.env``: next to the executable, or
    the user's config directory for a Homebrew install, whose Caskroom folder
    is versioned and replaced by every ``brew upgrade``."""
    if is_homebrew_install(executable):
        from platformdirs import user_config_dir

        return Path(user_config_dir("az-firewall-watch", appauthor=False))
    return Path(executable).parent


# ── base directory (works both from source and as a PyInstaller binary) ───────
HOMEBREW = False
if getattr(sys, "frozen", False):
    HOMEBREW = is_homebrew_install(sys.executable)
    BASE_DIR = frozen_base_dir(sys.executable)
    BASE_DIR.mkdir(parents=True, exist_ok=True)
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
# Presets come first: one pick hides whole classes of rows (FlowTrace and DNS
# can flood the table) without another switch in the filter bar. Values with the
# ``group:`` prefix are looked up in CATEGORY_GROUPS; plain values match the
# category name.
CATEGORY_GROUPS: dict[str, frozenset[str]] = {
    "decisions": frozenset({"networkrule", "apprule", "natrule", "threatintel", "idps"}),
    "traffic": frozenset({"flowtrace", "fatflow"}),
    "dns": frozenset({"dnsquery", "dnsfailure"}),
}
CATEGORY_OPTIONS: list[tuple[str, str]] = [
    ("Decisions", "group:decisions"),  # rules, ThreatIntel, IDPS
    ("Traffic", "group:traffic"),      # FlowTrace, FatFlow
    ("DNS", "group:dns"),              # DnsQuery, DnsFailure
    ("NetworkRule", "networkrule"),
    ("AppRule", "apprule"),
    ("NATRule", "natrule"),
    ("DnsQuery", "dnsquery"),
    ("DnsFailure", "dnsfailure"),
    ("IDPS", "idps"),
    ("ThreatIntel", "threatintel"),
    ("FlowTrace", "flowtrace"),
    ("FatFlow", "fatflow"),
]

# ── policy context flag ──────────────────────────────────────────────────────
POLICY_CONTEXT_KEY = "POLICY_CONTEXT"
_ON_VALUES = ("on", "true", "1", "yes")


def policy_context_setting(argv: list[str], environ: Mapping[str, str]) -> tuple[bool, bool]:
    """Resolve the policy-context flag.

    Returns ``(enabled, explicit)``. ``--no-policy-context`` / ``--policy-context`` on
    the command line win, then ``POLICY_CONTEXT=on|off`` from the environment (or
    ``.env``). A missing value means *enabled* but *not explicit* — the viewer
    then shows a one-time notice so the user knows what is switched on.
    """
    if "--no-policy-context" in argv:
        return False, True
    if "--policy-context" in argv:
        return True, True
    raw = (environ.get(POLICY_CONTEXT_KEY) or "").strip().lower()
    if not raw:
        return True, False
    return raw in _ON_VALUES, True


__all__ = ["BASE_DIR", "SRC_DIR", "HOMEBREW", "is_homebrew_install", "frozen_base_dir", "VERSION", "MAX_ROWS", "TABLE_TRIM_SLACK", "CATEGORY_OPTIONS", "CATEGORY_GROUPS",
           "POLICY_CONTEXT_KEY", "policy_context_setting", "load_env"]
