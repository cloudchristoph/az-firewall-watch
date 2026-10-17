"""LogBuffer (mcp_server/buffer.py): ids, capacity, counters, long-poll wait, time parsing."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from fw_parser import parse_record
from mcp_server.buffer import LogBuffer, parse_log_time


@pytest.fixture
def make_row(structured_record):
    def _make(source: str = "10.0.0.1", action: str = "Allow", category: str = "AZFWNetworkRule",
              time: str = "2026-09-05T08:00:00Z"):
        rec = structured_record(category, time=time, Protocol="TCP", SourceIp=source, SourcePort=1234,
                                DestinationIp="10.1.0.1", DestinationPort=443, Action=action)
        row = parse_record(rec)
        assert row is not None
        return row, rec
    return _make


def fill(buf: LogBuffer, make_row, n: int, **kw):
    return [buf.append(*make_row(source=f"10.0.0.{i}", **kw)) for i in range(n)]


def test_append_assigns_consecutive_ids_and_keeps_raw(make_row):
    buf = LogBuffer(10)
    row, rec = make_row()
    item = buf.append(row, rec, received_at=1000.0)
    assert (item.id, item.raw, item.received_at) == (1, rec, 1000.0)
    assert item.time_epoch == datetime(2026, 9, 5, 8, tzinfo=timezone.utc).timestamp()
    assert buf.get(1) is item
    assert (buf.size, buf.first_id, buf.last_id) == (1, 1, 1)


def test_capacity_trims_oldest_and_ids_stay_monotonic(make_row):
    buf = LogBuffer(3)
    items = fill(buf, make_row, 5)
    assert [i.id for i in items] == [1, 2, 3, 4, 5]
    assert [i.id for i in buf.snapshot()] == [3, 4, 5]
    assert (buf.first_id, buf.last_id, buf.size, len(buf)) == (3, 5, 3, 3)
    assert buf.get(2) is None and buf.get(6) is None and buf.get(4) is items[3]
    assert [i.id for i in buf.after(3)] == [4, 5]
    assert [i.id for i in buf.after(0)] == [3, 4, 5]   # a cursor older than the buffer starts at its head
    assert buf.after(5) == []


def test_clear_keeps_counting(make_row):
    buf = LogBuffer(10)
    fill(buf, make_row, 4)
    assert buf.clear() == 4
    assert (buf.size, buf.first_id, buf.last_id) == (0, None, 4)
    assert buf.get(1) is None and buf.after(0) == []
    assert buf.append(*make_row()).id == 5
    assert buf.received == 5   # received counts every row since start


def test_counters(make_row):
    buf = LogBuffer(10)
    fill(buf, make_row, 2)
    buf.append(*make_row(category="AZFWDnsQuery"))
    buf.count_skip("ResourceType")
    buf.count_skip("ResourceType")
    buf.count_skip("")
    c = buf.counters()
    assert c["received"] == 3
    assert c["per_category"] == {"NetworkRule": 2, "DnsQuery": 1}
    assert c["skipped"] == {"ResourceType": 2, "Unknown": 1}
    assert c["skipped_total"] == 3
    assert buf.last_event_at is not None
    assert buf.last_log_time == parse_log_time("2026-09-05T08:00:00Z")


def test_skip_alone_marks_the_stream_alive():
    buf = LogBuffer(10)
    assert buf.last_event_at is None
    buf.count_skip("ResourceType", received_at=42.0)
    assert buf.last_event_at == 42.0


def test_capacity_must_be_positive():
    with pytest.raises(ValueError):
        LogBuffer(0)


async def test_wait_for_returns_buffered_match_immediately(make_row):
    buf = LogBuffer(10)
    fill(buf, make_row, 3)
    rows = await buf.wait_for(1, timeout=5)
    assert [r.id for r in rows] == [2, 3]


async def test_wait_for_wakes_on_matching_row_only(make_row):
    buf = LogBuffer(10)
    is_deny = lambda item: item.row.action == "Deny"   # noqa: E731
    waiter = asyncio.create_task(buf.wait_for(0, timeout=5, predicate=is_deny))
    await asyncio.sleep(0.01)
    buf.append(*make_row(action="Allow"))
    await asyncio.sleep(0.01)
    assert not waiter.done()                 # a non-matching row does not end the wait
    buf.append(*make_row(action="Deny"))
    rows = await asyncio.wait_for(waiter, 1)
    assert [r.id for r in rows] == [2]


async def test_wait_for_times_out_empty(make_row):
    buf = LogBuffer(10)
    loop = asyncio.get_running_loop()
    start = loop.time()
    assert await buf.wait_for(0, timeout=0.05) == []
    assert loop.time() - start < 1


async def test_wait_for_respects_limit(make_row):
    buf = LogBuffer(10)
    fill(buf, make_row, 5)
    assert [r.id for r in await buf.wait_for(0, timeout=1, limit=2)] == [1, 2]


@pytest.mark.parametrize("text, expected", [
    ("2026-09-05T08:00:00.1234567Z", datetime(2026, 9, 5, 8, 0, 0, 123456, tzinfo=timezone.utc)),   # Azure's 7 digits
    ("2026-09-05T08:00:00.5Z", datetime(2026, 9, 5, 8, 0, 0, 500000, tzinfo=timezone.utc)),
    ("2026-09-05T08:00:00Z", datetime(2026, 9, 5, 8, tzinfo=timezone.utc)),
    ("2026-09-05T10:00:00+02:00", datetime(2026, 9, 5, 8, tzinfo=timezone.utc)),
    ("2026-09-05T08:00:00", datetime(2026, 9, 5, 8, tzinfo=timezone.utc)),   # no zone: UTC, like Azure means it
    ("2026-09-05T08:00:00.918521+00:00", datetime(2026, 9, 5, 8, 0, 0, 918521, tzinfo=timezone.utc)),
])
def test_parse_log_time(text, expected):
    assert parse_log_time(text) == expected.timestamp()


@pytest.mark.parametrize("text", ["", "yesterday", "2026-13-01T00:00:00Z", None])
def test_parse_log_time_rejects_garbage(text):
    assert parse_log_time(text) is None
