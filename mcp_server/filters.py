"""Row filters for the log tools, with the TUI's semantics.

Source and destination use :func:`helpers.address_matches` (CIDR, any IPv6
spelling, substring), categories accept the TUI's presets, and action,
protocol and ports are case-insensitive substrings exactly like the filter bar.
On top come the fields an agent needs and the TUI does not have: source port,
rule path, free text, a time window and id cursors.

Caller mistakes raise ``ValueError`` with a sentence that says what was wrong;
the tools turn it into an error result the model can read.
"""
from __future__ import annotations

import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, fields
from typing import Any

from helpers import address_matches, parse_network
from viewer.config import CATEGORY_GROUPS

from .buffer import BufferedRow, parse_log_time

# Every display category the parser produces, lower-case.
KNOWN_CATEGORIES = ("networkrule", "apprule", "natrule", "dnsquery", "dnsfailure",
                    "idps", "threatintel", "flowtrace", "fatflow")

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd])\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_RULE_SEP_RE = re.compile(r"\s*»\s*")


def parse_duration(text: str) -> float | None:
    """``30s`` / ``15m`` / ``2h`` / ``1d`` in seconds, ``None`` when ``text`` is not a duration."""
    match = _DURATION_RE.match(text or "")
    if match is None:
        return None
    return float(match.group(1)) * _UNIT_SECONDS[match.group(2).lower()]


def parse_time(value: str, *, now: float, name: str) -> float:
    """A relative duration (back from ``now``) or an ISO 8601 timestamp, as epoch seconds."""
    text = (value or "").strip()
    seconds = parse_duration(text)
    if seconds is not None:
        return now - seconds
    if text.lower() == "now":
        return now
    epoch = parse_log_time(text)
    if epoch is None:
        raise ValueError(f"{name} {value!r} is neither a relative duration (30s, 15m, 2h, 1d) nor an "
                         f"ISO 8601 timestamp (2026-10-15T08:00:00Z).")
    return epoch


def parse_window(since: str | None, until: str | None, *, now: float | None = None
                 ) -> tuple[float | None, float | None]:
    """``(since, until)`` as epoch seconds; either side ``None`` when not given."""
    ref = time.time() if now is None else now
    start = parse_time(since, now=ref, name="since") if since not in (None, "") else None
    end = parse_time(until, now=ref, name="until") if until not in (None, "") else None
    if start is not None and end is not None and start > end:
        raise ValueError("since lies after until; the window would be empty.")
    return start, end


def _category_entries(category: str | Iterable[str] | None) -> tuple[str, ...]:
    if category is None:
        return ()
    items = [category] if isinstance(category, str) else list(category)
    out: list[str] = []
    for item in items:
        text = str(item).strip().lower()
        if not text:
            continue
        if text.startswith("group:"):
            text = text[6:]
        if text not in CATEGORY_GROUPS and not any(text in known for known in KNOWN_CATEGORIES):
            raise ValueError(
                f"Unknown category {item!r}. Use a preset ({', '.join(sorted(CATEGORY_GROUPS))}) or one of "
                "NetworkRule, AppRule, NATRule, DnsQuery, DnsFailure, IDPS, ThreatIntel, FlowTrace, FatFlow.")
        out.append(text)
    return tuple(dict.fromkeys(out))


def _address_needle(value: str | None, name: str) -> str:
    text = (value or "").strip().lower()
    if "/" in text and parse_network(text) is None:
        raise ValueError(f"{name} {value!r} looks like a CIDR but is not a valid network (e.g. 10.0.0.0/16, fd10::/16).")
    return text


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


@dataclass(frozen=True)
class LogFilter:
    """A parsed, validated filter. Empty fields match everything.

    String fields hold the lower-cased needle; ``categories`` holds category
    names or preset names; ``since``/``until`` are epoch seconds.
    """

    categories: tuple[str, ...] = ()
    action: str = ""
    source: str = ""
    destination: str = ""
    protocol: str = ""
    dst_port: str = ""
    src_port: str = ""
    rule: str = ""
    text: str = ""
    since: float | None = None
    until: float | None = None
    after_id: int | None = None
    before_id: int | None = None

    @classmethod
    def build(cls, *, category: str | Iterable[str] | None = None, action: str | None = None,
              source: str | None = None, destination: str | None = None, protocol: str | None = None,
              dst_port: str | int | None = None, src_port: str | int | None = None, rule: str | None = None,
              text: str | None = None, since: str | None = None, until: str | None = None,
              after_id: int | None = None, before_id: int | None = None, now: float | None = None) -> LogFilter:
        start, end = parse_window(since, until, now=now)
        return cls(
            categories=_category_entries(category),
            action=_text(action),
            source=_address_needle(source, "source"),
            destination=_address_needle(destination, "destination"),
            protocol=_text(protocol),
            dst_port=_text(dst_port),
            src_port=_text(src_port),
            rule=_RULE_SEP_RE.sub("»", _text(rule)),
            text=_text(text),
            since=start,
            until=end,
            after_id=after_id,
            before_id=before_id,
        )

    def _category_ok(self, category: str) -> bool:
        cat = category.lower()
        for entry in self.categories:
            group = CATEGORY_GROUPS.get(entry)
            if group is not None:
                if cat in group:
                    return True
            elif entry in cat:
                return True
        return False

    def matches(self, item: BufferedRow) -> bool:
        row = item.row
        if self.after_id is not None and item.id <= self.after_id: return False
        if self.before_id is not None and item.id >= self.before_id: return False
        if self.categories and not self._category_ok(row.category): return False
        if self.source and not address_matches(self.source, row.sourceip): return False
        if self.destination and not address_matches(self.destination, row.targetip): return False
        if self.action and self.action not in row.action.lower(): return False
        if self.protocol and self.protocol not in row.protocol.lower(): return False
        if self.dst_port and self.dst_port not in row.targetport.lower(): return False
        if self.src_port and self.src_port not in row.srcport.lower(): return False
        if self.rule and self.rule not in row.policy.lower(): return False
        if self.since is not None and item.effective_time < self.since: return False
        if self.until is not None and item.effective_time > self.until: return False
        if self.text and not any(self.text in str(getattr(row, f.name) or "").lower()
                                 for f in fields(row) if f.name != "rowid"):
            return False
        return True

    def __call__(self, item: BufferedRow) -> bool:
        return self.matches(item)

    def echo(self) -> dict[str, Any]:
        """The active criteria, for the answer: only fields that are set."""
        from .serialize import iso_utc

        out: dict[str, Any] = {}
        if self.categories:
            out["category"] = list(self.categories)
        for name in ("action", "source", "destination", "protocol", "dst_port", "src_port", "rule", "text"):
            value = getattr(self, name)
            if value:
                out[name] = value
        if self.since is not None:
            out["since"] = iso_utc(self.since)
        if self.until is not None:
            out["until"] = iso_utc(self.until)
        if self.after_id is not None:
            out["after_id"] = self.after_id
        if self.before_id is not None:
            out["before_id"] = self.before_id
        return out


__all__ = ["LogFilter", "parse_window", "parse_duration", "parse_time", "KNOWN_CATEGORIES"]
