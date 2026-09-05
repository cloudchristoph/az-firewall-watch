from __future__ import annotations

import re
from datetime import datetime

from rich.text import Text


# Azure emits 7-digit fractional seconds; Python < 3.11 only parses exactly 3 or 6.
_FRACTION_RE = re.compile(r"\.(\d+)")


def _normalise_fraction(match: "re.Match[str]") -> str:
    return "." + match.group(1)[:6].ljust(6, "0")


def _to_local(ts: str) -> str:
    """Convert a UTC ISO-8601 timestamp to the local system timezone."""
    try:
        normalised = _FRACTION_RE.sub(_normalise_fraction, ts.replace("Z", "+00:00"), count=1)
        dt = datetime.fromisoformat(normalised)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts[:19]


def _highlight(text: str, term: str) -> Text:
    """Return a Rich Text with *term* highlighted (case-insensitive)."""
    t = Text(text)
    if term:
        t.highlight_regex(f"(?i){re.escape(term)}", style="bold reverse")
    return t


_CATEGORY_STYLES: dict[str, str] = {
    "networkrule": "cyan",
    "apprule":     "bright_blue",
    "natrule":     "yellow",
    "dnsquery":    "dark_orange3",
    "idps":        "bold red",
    "threatintel": "bold magenta",
}


def _category_text(category: str, term: str = "") -> Text:
    """Return a colour-coded Rich Text for a category, with optional search highlight."""
    style = _CATEGORY_STYLES.get(category.lower(), "")
    t = Text(category, style=style)
    if term:
        t.highlight_regex(f"(?i){re.escape(term)}", style="bold reverse")
    return t


def _parse_eventhub_endpoint(conn_str: str) -> tuple[str, str]:
    """Extract (namespace, hub_name) from a connection string — key is never returned."""
    namespace = hub = ""
    for part in conn_str.split(";"):
        low = part.lower()
        if low.startswith("endpoint=sb://"):
            namespace = part[len("Endpoint=sb://"):].rstrip("/")
        elif low.startswith("entitypath="):
            hub = part[part.index("=") + 1:]
    return namespace or "unknown", hub or "unknown"
