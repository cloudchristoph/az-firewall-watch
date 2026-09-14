from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from rich.text import Text


def load_env(path: Path, override: bool = False) -> None:
    """Load a .env file, falling back to latin-1 if the file is not valid UTF-8."""
    try:
        load_dotenv(path, encoding="utf-8", override=override)
    except UnicodeDecodeError:
        load_dotenv(path, encoding="latin-1", override=override)


# Azure emits 7-digit fractional seconds; Python < 3.11 only parses exactly 3 or 6.
_FRACTION_RE = re.compile(r"\.(\d+)")


def _normalise_fraction(match: re.Match[str]) -> str:
    return "." + match.group(1)[:6].ljust(6, "0")


def _to_local(ts: str) -> str:
    """Convert a UTC ISO-8601 timestamp to the local system timezone."""
    try:
        normalised = _FRACTION_RE.sub(_normalise_fraction, ts.replace("Z", "+00:00"), count=1)
        dt = datetime.fromisoformat(normalised)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts[:19]


def _utc_short(ts: str) -> str:
    """UTC ISO-8601 timestamp trimmed to seconds (``2026-09-07T16:14:09Z``).

    Azure writes up to seven fractional digits; nobody reads them in a dialog.
    """
    try:
        normalised = _FRACTION_RE.sub(_normalise_fraction, ts.replace("Z", "+00:00"), count=1)
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return ts


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
    "dnsfailure":  "bold dark_orange3",
    "flowtrace":   "bright_black",
    "fatflow":     "bold cyan",
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


def _is_ipv6(address: str) -> bool:
    """True if *address* parses as an IPv6 literal.

    Used to decide bracketing; shared so the decision is made the same way
    everywhere instead of each call site re-implementing an IP-address probe.
    """
    try:
        return ipaddress.ip_address(address).version == 6
    except ValueError:
        return False


def split_endpoint(text: str) -> tuple[str, str]:
    """Split a legacy log's ``address:port`` token into ``(address, port)``.

    Azure's legacy (properties.msg) format writes socket endpoints as plain
    ``host:port`` text, and it is not known whether Azure ever brackets an
    IPv6 host there itself (``[fd00::1]:1234``) — this handles both, plus the
    unbracketed form the field is normally seen in.

    The unbracketed IPv6 case is genuinely ambiguous: ``fd00::1:1234`` is, on
    its own, already a complete and valid IPv6 address (1234 is a legal
    16-bit group), so a naive "does the whole string parse as an address"
    check would swallow the port into the address. Since every legacy
    endpoint field in this log format carries a port, the rule chosen here is
    to always try splitting at the *last* colon first and accept that split
    when the part before it is itself a valid IP address (v4 or v6) — only
    when that fails is the full string tried as a bare, port-less address.
    This mirrors the bracket decision ``format_endpoint`` makes on the way
    back out.

    A missing port renders as ``"-"``, matching the placeholder the rest of
    the codebase already uses for "no port".
    """
    if not text:
        return text, "-"
    if text.startswith("[") and "]" in text:
        address, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else "-"
        return address, port or "-"
    if ":" not in text:
        return text, "-"
    address, _, port = text.rpartition(":")
    # A trailing colon leaves an empty port. Report it as the "-" placeholder the
    # rest of the codebase tests for, so no caller has to know both spellings.
    port = port or "-"
    try:
        ipaddress.ip_address(address)
        return address, port
    except ValueError:
        pass
    try:
        ipaddress.ip_address(text)
        return text, "-"  # a bare, complete IPv6 address; no port to split off
    except ValueError:
        pass
    return address, port  # FQDN:port, or something malformed we pass through as-is


def format_endpoint(address: str, port: str) -> str:
    """Join ``(address, port)`` back into display text, the inverse of ``split_endpoint``.

    Brackets IPv6 addresses (``[fd00::1]:1234``); IPv4 and FQDNs stay bare. A
    missing/placeholder port returns just the address, matching how the rest
    of the codebase already treats "no port" (e.g. the old ``_ports_join``).
    """
    if not port or port == "-":
        return address
    return f"[{address}]:{port}" if _is_ipv6(address) else f"{address}:{port}"


def parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """``ipaddress.ip_address`` that answers ``None`` instead of raising."""
    if not value or value == "-":
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """``ipaddress.ip_network(strict=False)`` that answers ``None`` instead of raising.

    Host bits are tolerated (``10.0.0.7/8`` is ``10.0.0.0/8``) because that is
    what people type into a filter box.
    """
    if not value:
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def normalise_address(value: str) -> str:
    """One spelling per address: brackets off, IPv6 compressed, everything else untouched.

    A dual-stack firewall writes the same address three ways: structured
    ``AZFWNetworkRule`` rows carry ``[fd10:0003:0005:0001:0000:0000:0000:0004]``
    (bracketed and expanded), legacy network-rule messages the same without
    brackets once ``split_endpoint`` is through, and ``AZFWDnsQuery`` rows the
    compressed ``fd10:3:5:1::4``. Parsing all of them to ``fd10:3:5:1::4`` keeps
    the table, the filters, the ``AzFw.<n>`` labels and the trace on one form.
    FQDNs, ``-`` and anything that is not an address come back unchanged.
    """
    text = (value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    addr = parse_address(text)
    return addr.compressed if addr is not None else value


def address_matches(needle: str, value: str) -> bool:
    """Filter semantics for the Source and Dest / FQDN inputs.

    ``needle`` is what the user typed, already lower-cased by the caller:

    * a CIDR (``10.3.0.0/16``, ``fd10:2::/32``) matches every address inside it
      and nothing else — never an FQDN, never the other address family;
    * a full address matches the same address in any spelling
      (``fd10::10`` finds ``fd10:0:0:0:0:0:0:10``);
    * anything else is a substring match against the value as logged and,
      for IPv6, against its compressed form (``::10`` finds
      ``fd10:0:0:2:0:0:0:10``).

    Substring matching stays, so ``10.0.1.4`` still finds ``10.0.1.44`` as it
    always did; a CIDR is the precise tool.
    """
    if not needle:
        return True
    haystack = (value or "").lower()
    if "/" in needle:
        net = parse_network(needle)
        if net is None:
            return needle in haystack   # not a CIDR after all: plain text
        addr = parse_address(haystack)
        return addr is not None and addr.version == net.version and addr in net
    if needle in haystack:
        return True
    addr = parse_address(haystack)
    if addr is None:
        return False
    return parse_address(needle) == addr or needle in addr.compressed


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
