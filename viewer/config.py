"""Constants and configuration helpers for the viewer TUI."""
from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from helpers import load_env  # re-exported for main.py

WINGET_ID = "cloudchristoph.az-firewall-watch"

# How to update a binary that a package manager installed (see install_source).
UPGRADE_COMMANDS: dict[str, str] = {
    "homebrew": "brew upgrade --cask az-firewall-watch",
    "winget": f"winget upgrade {WINGET_ID}",
}


def install_source_of(parts: tuple[str, ...]) -> str | None:
    """Which package manager owns a binary at a path with these *parts*:
    ``homebrew`` for a Caskroom, ``winget`` for a portable package (its
    ``Packages`` folder or the ``Links`` folder on PATH), else ``None``."""
    lower = [part.lower() for part in parts]
    if "caskroom" in lower:
        return "homebrew"
    if any(a == "winget" and b in ("packages", "links") for a, b in zip(lower, lower[1:], strict=False)):
        return "winget"
    return None


def install_source(executable: str | Path) -> str | None:
    """:func:`install_source_of` for *executable*, with symlinks resolved:
    ``brew`` links the binary into ``bin``, winget into its ``Links`` folder."""
    try:
        path = Path(executable).resolve()
    except OSError:
        path = Path(executable)
    return install_source_of(path.parts)


def frozen_base_dir(executable: str | Path) -> Path:
    """Where a compiled binary keeps its ``.env``: next to the executable, or
    the user's config directory when a package manager installed it. Its folder
    belongs to the package manager: ``brew upgrade`` replaces the versioned
    Caskroom folder, and winget's ``Links`` folder is shared by every package."""
    if install_source(executable):
        from platformdirs import user_config_dir

        return Path(user_config_dir("az-firewall-watch", appauthor=False))
    return Path(executable).parent


def prepare_base_dir(path: Path, private: bool) -> None:
    """Create *path*. A package install's config directory is the app's own
    and holds a ``.env`` that may carry a SAS key, so it is made private to the
    user (0700); next to a downloaded binary the folder belongs to the user."""
    path.mkdir(parents=True, exist_ok=True)
    if private:
        try:
            os.chmod(path, 0o700)  # no-op beyond the read-only flag on Windows, where %LOCALAPPDATA% is per-user
        except OSError:
            pass


# ── base directory (works both from source and as a PyInstaller binary) ───────
INSTALL_SOURCE: str | None = None
if getattr(sys, "frozen", False):
    INSTALL_SOURCE = install_source(sys.executable)
    BASE_DIR = frozen_base_dir(sys.executable)
    prepare_base_dir(BASE_DIR, private=INSTALL_SOURCE is not None)
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


# ── update check flag ────────────────────────────────────────────────────────
UPDATE_CHECK_KEY = "UPDATE_CHECK"


def update_check_enabled(argv: list[str], environ: Mapping[str, str]) -> bool:
    """Whether the viewer asks api.github.com for a newer release at start-up.
    ``--no-update-check`` wins, then ``UPDATE_CHECK=on|off`` from the environment
    (or ``.env``); a missing value means on."""
    if "--no-update-check" in argv:
        return False
    raw = (environ.get(UPDATE_CHECK_KEY) or "").strip().lower()
    return not raw or raw in _ON_VALUES


__all__ = ["BASE_DIR", "SRC_DIR", "INSTALL_SOURCE", "UPGRADE_COMMANDS", "WINGET_ID",
           "install_source", "install_source_of", "frozen_base_dir", "prepare_base_dir", "VERSION", "MAX_ROWS", "TABLE_TRIM_SLACK", "CATEGORY_OPTIONS", "CATEGORY_GROUPS",
           "POLICY_CONTEXT_KEY", "policy_context_setting", "UPDATE_CHECK_KEY", "update_check_enabled", "load_env"]
