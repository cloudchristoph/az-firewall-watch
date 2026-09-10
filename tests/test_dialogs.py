"""Dialog behaviour inside the running app (DetailDialog, StatusBar).

Includes the regression for Escape being swallowed by the app-level
"Clear Filters" binding before modal screens could see it.
"""
from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input, Static, Switch

import viewer.app as app_module
from dialogs import StatusBar
from fw_parser import parse_record
from helpers import _to_local
from viewer.app import FirewallLogApp
from viewer.views.detail_screen import DetailDialog

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
        assert "NetworkRule" in text  # category now sits in the header, not a "Log Entry —" title
        # Local time depends on the machine's zone (CI runs in UTC), so ask the
        # same helper; the UTC clock beside it is fixed.
        assert _to_local("2026-09-05T08:00:00Z") in text and "08:00:00Z UTC" in text
        assert "10.0.1.4" in text and "51000 → 443" in text  # ports on their own line
        assert "10.0.2.5" in text
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


async def test_threat_intel_entry_labels_and_long_values(structured_record):
    fqdn = "testmaliciousdomain.eastus.cloudapp.azure.com"
    row = parse_record(structured_record(
        "AZFWThreatIntel", time="2026-09-07T16:14:09.903912+00:00", Protocol="HTTP", SourceIp="10.3.8.4",
        SourcePort=47074, DestinationIp="", DestinationPort=80, Fqdn=fqdn, Action="alert",
        ThreatDescription="This is a test indicator for a Microsoft owned domain.",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, row)
        contents = [str(s.content) for s in dialog.query(Static)]
        text = "\n".join(contents)
        assert "16:14:09Z" in text and ".903912" not in text      # UTC trimmed to seconds, date only when it differs
        assert "Threat" in text and "More Info" not in text                   # category-specific label
        # The destination and protocol are the header's job now (ThreatIntel's
        # Source/Destination equal it exactly); no separate field repeats them.
        assert fqdn in text and "HTTP" in text
        assert not any(c.startswith("[dim]Destination  [/]") for c in contents)
        assert not any(c.startswith("[dim]Protocol     [/]") for c in contents)
        assert not dialog.query("#btn-close")


async def test_flowtrace_dialog_shows_connection_and_packet_direction(structured_record):
    """A SYN-ACK is logged with the server as source; the dialog must not leave that ambiguous."""
    row = parse_record(structured_record(
        "AZFWFlowTrace", Protocol="TCP", SourceIp="51.116.242.155", SourcePort=443,
        DestinationIp="10.3.14.4", DestinationPort=50674, Flag="SYN-ACK", Action="Log", ActionReason="Additional TCP Log",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, row)
        text = _dialog_text(dialog)
        assert "Flow" in text and "10.3.14.4:50674 → 51.116.242.155:443" in text   # client → server
        assert "Packet" in text and "51.116.242.155 → 10.3.14.4  (server → client)" in text
        assert "Flag" in text and "SYN-ACK" in text
        assert "Log Additional TCP Log" not in text                                # boilerplate gone
        assert "Action" not in text and "More Info" not in text and "Policy SKU" not in text


async def test_dns_query_dialog_uses_dns_wording(structured_record):
    row = parse_record(structured_record(
        "AZFWDnsQuery", SourceIp="10.3.8.4", SourcePort=39294, QueryName="www.lonelyplanet.com",
        QueryType="A", ResponseCode="NOERROR",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.query_one("#f-hide-dns", Switch).value = False  # DNS rows are hidden by default
        await pilot.pause()
        text = _dialog_text(await _open_detail(app, pilot, row))
    assert "Query type" in text and "Client" in text and "Query" in text and "Response" in text
    assert "Protocol" not in text and "Action" not in text and "Destination" not in text


async def test_idps_dialog_splits_the_signature(structured_record):
    row = parse_record(structured_record(
        "AZFWIdpsSignature", Protocol="TCP", SourceIp="10.3.8.4", SourcePort=55460, DestinationIp="10.3.6.4",
        DestinationPort=80, Action="alert", Severity=2, SignatureId=2032081,
        Category="Potentially Bad Traffic", Description="USER_AGENTS Suspicious User-Agent (HaxerMen)",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        contents = [str(s.content) for s in (await _open_detail(app, pilot, row)).query(Static)]
    joined = "\n".join(contents)
    assert "[dim]Severity     [/]  2" in joined
    assert "[dim]Signature    [/]  2032081" in joined
    assert "[dim]Class        [/]  Potentially Bad Traffic" in joined
    assert "Suspicious User-Agent (HaxerMen)" in joined
    assert "SEV:2 ·" not in joined and "More Info" not in joined


async def test_fatflow_dialog_shows_flow_and_rate(structured_record):
    row = parse_record(structured_record(
        "AZFWFatFlow", Protocol="TCP", SourceIp="142.251.14.97", SourcePort=443, DestinationIp="10.2.0.6",
        DestinationPort=24994, FlowRate="0.048",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        text = _dialog_text(await _open_detail(app, pilot, row))
    assert "10.2.0.6:24994 → 142.251.14.97:443" in text      # client → server
    assert "(server → client)" in text
    assert "Rate" in text and "Mbps" in text
    assert "Top flow by bandwidth" not in text and "Action" not in text


async def test_dnat_dialog_shows_public_destination_and_translation(structured_record):
    row = parse_record(structured_record(
        "AZFWNatRule", Protocol="TCP", SourceIp="95.91.87.6", SourcePort=60223,
        DestinationIp="72.144.131.50", DestinationPort=18080, TranslatedIp="10.3.6.4", TranslatedPort=80,
        Policy="p", RuleCollectionGroup="g", RuleCollection="c", Rule="r",
    ))
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        text = _dialog_text(await _open_detail(app, pilot, row))
    assert "72.144.131.50" in text and "60223 → 18080" in text
    assert "Translated" in text and "10.3.6.4:80" in text


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
