"""The in-memory log buffer the tools query.

A bounded deque of parsed rows, each with a buffer id that only ever grows.
Ids are assigned here, not taken from ``FirewallDataRow.rowid``: the parser's
counter also advances for skipped records, and a cursor that an agent holds
must stay meaningful after the buffer has been trimmed or cleared. Because
ids are consecutive inside the deque, a lookup by id is an index computation.
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fw_parser import FirewallDataRow
from helpers import _FRACTION_RE, _normalise_fraction

MALFORMED_REASON = "MalformedEvent"


def parse_log_time(ts: str) -> float | None:
    """Epoch seconds of an ISO 8601 timestamp, ``None`` when it is not one.

    Azure writes seven fractional digits, which ``datetime.fromisoformat``
    rejects before Python 3.11; the fraction is cut to six like the TUI does.
    A timestamp without a zone is taken as UTC, which is what Azure means.
    """
    if not ts or not isinstance(ts, str):
        return None
    text = ts.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(_normalise_fraction, text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass
class BufferedRow:
    """One parsed log row as kept by the buffer.

    ``raw`` is the diagnostic record exactly as received; ``time_epoch`` is the
    log's own time (``None`` when unparseable), ``received_at`` the arrival time.
    """

    id: int
    row: FirewallDataRow
    raw: dict[str, Any]
    received_at: float
    time_epoch: float | None

    @property
    def effective_time(self) -> float:
        """The log time when known, else the arrival time: what time windows compare."""
        return self.time_epoch if self.time_epoch is not None else self.received_at


class LogBuffer:
    """Bounded, id-addressed row store with counters and a long-poll wait."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.capacity = capacity
        self._rows: deque[BufferedRow] = deque()
        self._last_id = 0
        self.received = 0                          # rows accepted since start (cleared rows included)
        self.skipped: Counter[str] = Counter()     # reason → records not shown (SKIP: categories, bad events)
        self.per_category: Counter[str] = Counter()
        self.last_event_at: float | None = None    # wall clock of the last record of any kind
        self.last_log_time: float | None = None    # newest log timestamp seen
        # Waiters hold the current event; every append sets it and swaps in a
        # fresh one, so a waiter wakes once per batch and re-checks its filter.
        self._changed = asyncio.Event()

    # ── writing ──────────────────────────────────────────────────────────────
    def append(self, row: FirewallDataRow, raw: dict[str, Any], *, received_at: float | None = None) -> BufferedRow:
        now = time.time() if received_at is None else received_at
        self._last_id += 1
        item = BufferedRow(id=self._last_id, row=row, raw=raw, received_at=now, time_epoch=parse_log_time(row.time))
        self._rows.append(item)
        while len(self._rows) > self.capacity:
            self._rows.popleft()
        self.received += 1
        self.per_category[row.category] += 1
        self.last_event_at = now
        if item.time_epoch is not None and (self.last_log_time is None or item.time_epoch > self.last_log_time):
            self.last_log_time = item.time_epoch
        self._wake()
        return item

    def count_skip(self, reason: str, *, received_at: float | None = None) -> None:
        """A record that arrived but is not kept; it still proves the stream is alive."""
        self.skipped[reason or "Unknown"] += 1
        self.last_event_at = time.time() if received_at is None else received_at

    def clear(self) -> int:
        """Drop every row; ids keep counting so cursors stay valid. Returns the number dropped."""
        dropped = len(self._rows)
        self._rows.clear()
        return dropped

    def _wake(self) -> None:
        self._changed.set()
        self._changed = asyncio.Event()

    # ── reading ──────────────────────────────────────────────────────────────
    @property
    def size(self) -> int:
        return len(self._rows)

    @property
    def first_id(self) -> int | None:
        return self._rows[0].id if self._rows else None

    @property
    def last_id(self) -> int:
        """The newest id ever assigned (0 before the first row), also after a clear."""
        return self._last_id

    def get(self, row_id: int) -> BufferedRow | None:
        if not self._rows:
            return None
        index = row_id - self._rows[0].id
        if 0 <= index < len(self._rows):
            return self._rows[index]
        return None

    def __len__(self) -> int:
        return len(self._rows)

    def __iter__(self) -> Iterator[BufferedRow]:
        return iter(list(self._rows))

    def snapshot(self) -> list[BufferedRow]:
        """A copy of the rows, oldest first, safe to iterate while the stream appends."""
        return list(self._rows)

    def after(self, after_id: int) -> list[BufferedRow]:
        """Rows with an id greater than ``after_id``, oldest first."""
        if not self._rows:
            return []
        start = max(0, after_id + 1 - self._rows[0].id)
        if start >= len(self._rows):
            return []
        if start == 0:
            return list(self._rows)
        return [self._rows[i] for i in range(start, len(self._rows))]

    async def wait_for(self, after_id: int, timeout: float,
                       predicate: Callable[[BufferedRow], bool] | None = None,
                       limit: int | None = None) -> list[BufferedRow]:
        """Rows after ``after_id`` that satisfy ``predicate``, waiting up to ``timeout`` seconds for one.

        Returns as soon as at least one matching row exists (immediately when
        one is already buffered), else an empty list once the timeout is over.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, timeout)
        cursor = after_id
        while True:
            fresh = self.after(cursor)
            if fresh:
                cursor = fresh[-1].id
            matched = [r for r in fresh if predicate is None or predicate(r)]
            if matched:
                # Rows already passed over by this call are not matches; start
                # from the caller's cursor once more so the answer is complete.
                result = [r for r in self.after(after_id) if predicate is None or predicate(r)]
                return result[:limit] if limit is not None else result
            remaining = deadline - loop.time()
            if remaining <= 0:
                return []
            changed = self._changed
            try:
                await asyncio.wait_for(changed.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return []

    def counters(self) -> dict[str, Any]:
        return {
            "received": self.received,
            "skipped": dict(self.skipped),
            "skipped_total": sum(self.skipped.values()),
            "per_category": dict(self.per_category),
        }


__all__ = ["BufferedRow", "LogBuffer", "parse_log_time", "MALFORMED_REASON"]
