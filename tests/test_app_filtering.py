"""Headless integration tests: filter bar ↔ table ↔ status bar.

Runs the real Textual app via ``App.run_test`` with no Event Hub configured,
so the streaming worker exits immediately and rows are injected directly
into the pending queue (the same path the Event Hub callback uses).
"""
from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input, Select, Static, Switch

import viewer.app as app_module
from dialogs import DetailDialog, StatusBar
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


# ── incremental table updates ────────────────────────────────────────────────

def _table_keys(app: FirewallLogApp) -> list[str]:
    tbl = app.query_one("#log-table", DataTable)
    return [tbl.coordinate_to_cell_key((i, 0)).row_key.value for i in range(tbl.row_count)]


def _net(structured_record, ts: str, **props):
    base = dict(Protocol="TCP", SourceIp="10.0.0.1", SourcePort=1, DestinationIp="10.1.0.1",
                DestinationPort=443, Action="Allow", Policy="pol", RuleCollectionGroup="rcg",
                RuleCollection="rc", Rule="r")
    base.update(props)
    return parse_record(structured_record("AZFWNetworkRule", time=ts, **base))


async def test_incremental_append_keeps_newest_first_order(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        first = [_net(structured_record, f"2026-09-05T08:00:{s:02d}.5000000Z") for s in (10, 20, 30)]
        await _inject(app, pilot, first)
        # second batch interleaves with the first and includes a same-second, later fraction
        second = [
            _net(structured_record, "2026-09-05T08:00:25.0000000Z"),
            _net(structured_record, "2026-09-05T08:00:30.9000000Z"),
            _net(structured_record, "2026-09-05T08:00:05.0000000Z"),
        ]
        await _inject(app, pilot, second)
        assert _table_keys(app) == [r.rowid for r in app._all_rows]
        times = [r.time for r in app._all_rows]
        assert times == sorted(times, reverse=True)
        assert times[0] == "2026-09-05T08:00:30.9000000Z"


async def test_incremental_append_respects_active_filter(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _inject(app, pilot, [_net(structured_record, "2026-09-05T08:00:01Z", Action="Deny")])
        app.query_one("#f-action", Input).value = "deny"
        await pilot.pause()
        await _inject(app, pilot, [
            _net(structured_record, "2026-09-05T08:00:02Z", Action="Allow"),
            _net(structured_record, "2026-09-05T08:00:03Z", Action="Deny"),
        ])
        tbl = app.query_one("#log-table", DataTable)
        assert tbl.row_count == 2
        assert app.query_one("#status", StatusBar).visible_count == 2
        assert len(app._all_rows) == 3


async def test_table_is_trimmed_once_slack_is_exceeded(structured_record, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_ROWS", 10)
    monkeypatch.setattr(app_module, "TABLE_TRIM_SLACK", 4)
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        tbl = app.query_one("#log-table", DataTable)
        counts = []
        for i in range(8):
            await _inject(app, pilot, [_net(structured_record, f"2026-09-05T08:00:{i*3+j:02d}Z") for j in range(3)])
            counts.append(tbl.row_count)
        assert len(app._all_rows) == 10
        assert max(counts) <= 10 + 4 + 3  # never far beyond MAX_ROWS + slack
        assert any(c > 10 for c in counts)  # slack was actually used
        assert counts[-1] <= 10 + 4
        # newest rows always at the top
        assert _table_keys(app)[:10] == [r.rowid for r in app._all_rows]


async def test_detail_dialog_works_for_row_lingering_beyond_buffer(structured_record, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_ROWS", 3)
    monkeypatch.setattr(app_module, "TABLE_TRIM_SLACK", 10)
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        oldest = _net(structured_record, "2026-09-05T08:00:00Z", SourceIp="10.9.9.9")
        await _inject(app, pilot, [oldest])
        await _inject(app, pilot, [_net(structured_record, f"2026-09-05T08:00:0{i}Z") for i in (1, 2, 3)])
        assert oldest not in app._all_rows  # fell off the buffer …
        tbl = app.query_one("#log-table", DataTable)
        assert tbl.row_count == 4          # … but is still shown (within slack)
        tbl.focus()
        tbl.move_cursor(row=3, animate=False)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, DetailDialog)
        assert "10.9.9.9" in " ".join(str(s.content) for s in app.screen.query(Static))


async def test_second_policy_triggers_full_rerender_of_rule_info(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        first = _net(structured_record, "2026-09-05T08:00:01Z", Policy="pol-a")
        await _inject(app, pilot, [first])
        tbl = app.query_one("#log-table", DataTable)
        info_col = tbl.ordered_columns[-1].key
        assert tbl.get_cell(first.rowid, info_col).plain == "rcg » rc » r"  # single policy → prefix stripped
        await _inject(app, pilot, [_net(structured_record, "2026-09-05T08:00:02Z", Policy="pol-b")])
        assert tbl.get_cell(first.rowid, info_col).plain == "pol-a » rcg » rc » r"


async def test_selected_row_stays_selected_when_rows_arrive(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        rows = [_net(structured_record, f"2026-09-05T08:00:0{i}Z") for i in (1, 2, 3)]
        await _inject(app, pilot, rows)
        tbl = app.query_one("#log-table", DataTable)
        tbl.focus()
        tbl.move_cursor(row=1, animate=False)  # the middle row (08:00:02)
        await pilot.pause()
        assert app._selected_rowid == rows[1].rowid
        await _inject(app, pilot, [_net(structured_record, f"2026-09-05T08:00:1{i}Z") for i in range(5)])
        assert tbl.cursor_row == 6  # five newer rows were inserted above it
        assert tbl.coordinate_to_cell_key((tbl.cursor_row, 0)).row_key.value == rows[1].rowid


async def test_row_index_stays_bounded_under_restrictive_filter(structured_record, monkeypatch):
    """Regression (Copilot review): rows filtered out on arrival must not accumulate in _row_index."""
    monkeypatch.setattr(app_module, "MAX_ROWS", 20)
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.query_one("#f-action", Input).value = "deny"
        await pilot.pause()
        for i in range(10):
            await _inject(app, pilot, [_net(structured_record, f"2026-09-05T08:{i:02d}:{j:02d}Z") for j in range(5)])
        tbl = app.query_one("#log-table", DataTable)
        assert tbl.row_count == 0                      # nothing matches "deny"
        assert len(app._row_index) == 0                # … so nothing is indexed
        assert len(app._all_rows) == 20
        app.query_one("#f-action", Input).value = ""
        await pilot.pause()
        assert tbl.row_count == 20
        assert set(app._row_index) == {r.rowid for r in app._all_rows}
        # A full rebuild under a filter indexes only the visible rows
        app.query_one("#f-hide-dns", Switch).value = False  # triggers _refresh_table
        app.query_one("#f-action", Input).value = "allow"
        await pilot.pause()
        assert tbl.row_count == 20
        app.query_one("#f-action", Input).value = "deny"
        await pilot.pause()
        assert tbl.row_count == 0
        assert app._row_index == {}
