"""Dialog behaviour inside the running app (DetailDialog, StatusBar).

Includes the regression for Escape being swallowed by the app-level
"Clear Filters" binding before modal screens could see it.
"""
from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input, Static

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


def _network_row(structured_record, **extra):
    props = dict(
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=51000,
        DestinationIp="10.0.2.5", DestinationPort=443, Action="Deny",
        Policy="pol-hub", RuleCollectionGroup="rcg", RuleCollection="rc", Rule="r-web",
    )
    props.update(extra)
    return parse_record(structured_record("AZFWNetworkRule", **props))


async def _open_detail(app: FirewallLogApp, pilot, row) -> DetailDialog:
    app._pending.append(row)
    await app._flush_rows()
    await pilot.pause()
    app.query_one("#log-table", DataTable).focus()
    await pilot.press("enter")
    await pilot.pause(0.2)
    assert isinstance(app.screen, DetailDialog)
    return app.screen


def _dialog_text(screen) -> str:
    return "\n".join(str(s.content) for s in screen.query(Static))


async def test_enter_opens_detail_dialog_with_all_fields(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        text = _dialog_text(dialog)
        assert "Log Entry — NetworkRule" in text
        assert "2026-09-05T08:00:00Z" in text
        assert "10.0.1.4:51000" in text
        assert "10.0.2.5:443" in text
        assert "Deny" in text
        assert "pol-hub" in text and "rcg" in text and "rc" in text and "r-web" in text


async def test_detail_dialog_shows_action_reason_when_no_rule_matched(structured_record):
    row = parse_record(structured_record(
        "AZFWNetworkRule", Action="Deny", SourceIp="1.1.1.1", DestinationIp="2.2.2.2",
        ActionReason="No rule matched. Proceeding with default action.",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, row)
        text = _dialog_text(dialog)
        assert "Policy / Info" in text
        assert "No rule matched" in text


async def test_detail_dialog_escapes_rich_markup_in_values(structured_record):
    row = parse_record(structured_record("AZFWApplicationRule", Fqdn="[bold]evil[/bold].example", Action="Allow"))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, row)
        # The literal brackets must survive as text, not be interpreted as markup.
        assert "[bold]evil" in _dialog_text(dialog)


@pytest.mark.parametrize("key", ["escape", "q"])
async def test_detail_dialog_closes_on_key(structured_record, key):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _open_detail(app, pilot, _network_row(structured_record))
        await pilot.press(key)
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailDialog)


async def test_q_in_detail_dialog_does_not_quit_the_app(structured_record):
    """Regression: 'q' must be consumed by the dialog, not bubble to the app's quit binding."""
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _open_detail(app, pilot, _network_row(structured_record))
        await pilot.press("q")
        await pilot.pause(0.3)
        assert not isinstance(app.screen, DetailDialog)
        assert app.is_running
        assert app.return_value is None
        assert not app._exit


async def test_detail_dialog_closes_on_button(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await _open_detail(app, pilot, _network_row(structured_record))
        await pilot.click("#btn-close")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailDialog)


async def test_escape_in_dialog_does_not_clear_main_screen_filters(structured_record):
    """Regression: the app-level Escape binding must not fire while a modal is open."""
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.query_one("#f-action", Input).value = "deny"
        await pilot.pause()
        await _open_detail(app, pilot, _network_row(structured_record))
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailDialog)
        assert app.query_one("#f-action", Input).value == "deny"


async def test_escape_clears_filters_while_input_is_focused(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        await pilot.press("f")  # focus Source-IP filter
        await pilot.press("1", "0", ".")
        await pilot.pause()
        assert app.query_one("#f-src", Input).value == "10."
        await pilot.press("escape")
        await pilot.pause()
        assert app.query_one("#f-src", Input).value == ""


async def test_status_bar_click_toggles_pause():
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        await pilot.click("#status")
        await pilot.pause()
        assert status.paused is True
        assert app._paused is True
        await pilot.click("#status")
        await pilot.pause()
        assert status.paused is False


def test_status_bar_render_variants():
    bar = StatusBar()
    bar.status = "Connected"
    bar.total = 12
    assert "▶ LIVE" in bar.render()
    assert "Events: 12" in bar.render()
    assert "Skipped" not in bar.render()

    bar.skipped = 3
    assert "Skipped: 3" in bar.render()

    bar.visible_count = 4
    assert "Events (filtered): 4/12" in bar.render()

    bar.paused = True
    assert "⏸ PAUSED" in bar.render()
