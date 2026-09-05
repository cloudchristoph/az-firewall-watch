"""Headless integration tests: filter bar ↔ table ↔ status bar.

Runs the real Textual app via ``App.run_test`` with no Event Hub configured,
so the streaming worker exits immediately and rows are injected directly
into the pending queue (the same path the Event Hub callback uses).
"""
from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input, Select, Switch

import viewer.app as app_module
from dialogs import StatusBar
from fw_parser import parse_record
from viewer.app import FirewallLogApp

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")


@pytest.fixture
def no_update_check(monkeypatch):
    async def _noop(*_a, **_kw):
        return None

    monkeypatch.setattr(app_module, "check_for_update", _noop)


def _rows(structured_record):
    rows = []
    for i in range(4):
        rows.append(parse_record(structured_record(
            "AZFWNetworkRule", time=f"2026-09-05T08:00:0{i}Z",
            Protocol="TCP", SourceIp=f"10.0.1.{i}", SourcePort=1,
            DestinationIp="10.0.2.5", DestinationPort=443,
            Action="Allow" if i % 2 else "Deny",
            Policy="pol", RuleCollectionGroup="rcg", RuleCollection="rc", Rule="r",
        )))
    rows.append(parse_record(structured_record(
        "AZFWDnsQuery", time="2026-09-05T08:00:09Z",
        SourceIp="10.0.1.9", SourcePort=5353, QueryName="example.com",
        QueryType="A", ResponseCode="NOERROR",
    )))
    return rows


async def _inject(app: FirewallLogApp, pilot, rows, skipped: int = 0):
    app._pending.extend(rows)
    app._skip_pending += skipped
    await app._flush_rows()
    await pilot.pause()


async def test_flush_populates_table_and_status(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, _rows(structured_record), skipped=2)

        table = app.query_one("#log-table", DataTable)
        status = app.query_one("#status", StatusBar)
        assert status.total == 5
        assert status.skipped == 2
        # Hide DNS is on by default → the DnsQuery row is hidden and the counter is active
        assert table.row_count == 4
        assert status.visible_count == 4
        assert "filtered" in status.render()


async def test_hide_dns_toggle_reveals_dns_rows(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, _rows(structured_record))

        app.query_one("#f-hide-dns", Switch).value = False
        await pilot.pause()
        table = app.query_one("#log-table", DataTable)
        status = app.query_one("#status", StatusBar)
        assert table.row_count == 5
        assert status.visible_count == -1  # no filter active → plain counter
        assert "filtered" not in status.render()


async def test_action_filter_narrows_rows(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, _rows(structured_record))

        app.query_one("#f-action", Input).value = "deny"
        await pilot.pause()
        table = app.query_one("#log-table", DataTable)
        assert table.row_count == 2
        assert app.query_one("#status", StatusBar).visible_count == 2


async def test_selecting_dnsquery_category_disables_hide_dns(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, _rows(structured_record))

        app.query_one("#f-cat", Select).value = "dnsquery"
        await pilot.pause()
        assert app.query_one("#f-hide-dns", Switch).value is False
        assert app.query_one("#log-table", DataTable).row_count == 1


async def test_escape_clears_all_filters(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, _rows(structured_record))

        app.query_one("#f-action", Input).value = "deny"
        app.query_one("#f-proto", Input).value = "tcp"
        app.query_one("#f-hide-dns", Switch).value = False
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

        assert app.query_one("#f-action", Input).value == ""
        assert app.query_one("#f-proto", Input).value == ""
        assert app.query_one("#f-hide-dns", Switch).value is True
        assert app.query_one("#log-table", DataTable).row_count == 4


async def test_clear_logs_resets_everything(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, _rows(structured_record), skipped=1)

        await pilot.press("c")
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        assert app.query_one("#log-table", DataTable).row_count == 0
        assert app._all_rows == []
        assert (status.total, status.skipped, status.visible_count) == (0, 0, -1)


async def test_rows_are_sorted_newest_first_and_capped(structured_record, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_ROWS", 3)
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        rows = [
            parse_record(structured_record("AZFWNetworkRule", time=f"2026-09-05T08:00:{s:02d}Z", Action="Allow"))
            for s in (5, 1, 9, 3)
        ]
        await _inject(app, pilot, rows)
        times = [r.time for r in app._all_rows]
        assert times == ["2026-09-05T08:00:09Z", "2026-09-05T08:00:05Z", "2026-09-05T08:00:03Z"]


async def test_pause_toggle_updates_status_bar(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        assert status.paused is False
        await pilot.press("ctrl+p")
        await pilot.pause()
        assert status.paused is True
        assert "PAUSED" in status.render()
        assert status.has_class("paused")
