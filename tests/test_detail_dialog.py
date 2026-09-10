"""The redesigned detail dialog: header, footer and grouped fields.

Works with and without policy context; every check below runs the relevant
case in both modes where the case applies to both.
"""
from __future__ import annotations

import time

import pytest
from textual.widgets import Static, Switch

from fw_parser import parse_record
from tests.test_dialogs import _dialog_text, _open_detail
from tests.test_views import _load, make_snapshot, mgmt  # noqa: F401  (fixture; pytest needs it bound as "mgmt")
from viewer.app import FirewallLogApp
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, IpGroupInfo
from viewer.cache import CachedSnapshot
from viewer.views.detail_screen import DetailDialog
from viewer.views.trace_screen import TracePanel

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")


@pytest.fixture
def no_update_check(monkeypatch):
    import viewer.app as app_module

    async def _noop(*_a, **_kw):
        return None

    monkeypatch.setattr(app_module, "check_for_update", _noop)


def _header_text(screen) -> str:
    return str(screen.query_one("#dialog-header", Static).content)


def _footer_text(screen) -> str:
    return str(screen.query_one("#dialog-footer", Static).content)


# ── row builders ──────────────────────────────────────────────────────────────

def _app_row(structured_record, **extra):
    props = dict(Protocol="HTTPS", SourceIp="10.3.11.4", SourcePort=41644,
                 Fqdn="www.petmd.com", DestinationPort=443, Action="Allow")
    props.update(extra)
    return parse_record(structured_record("AZFWApplicationRule", **props))


def _network_row(structured_record, **extra):
    props = dict(Protocol="TCP", SourceIp="10.0.1.4", SourcePort=51000,
                 DestinationIp="10.0.2.5", DestinationPort=443, Action="Deny")
    props.update(extra)
    return parse_record(structured_record("AZFWNetworkRule", **props))


def _nat_row(structured_record, **extra):
    props = dict(Protocol="TCP", SourceIp="95.91.87.6", SourcePort=60223,
                 DestinationIp="72.144.131.50", DestinationPort=18080,
                 TranslatedIp="10.3.6.4", TranslatedPort=80)
    props.update(extra)
    return parse_record(structured_record("AZFWNatRule", **props))


def _flowtrace_row(structured_record, **extra):
    props = dict(Protocol="TCP", SourceIp="51.116.242.155", SourcePort=443,
                 DestinationIp="10.3.14.4", DestinationPort=50674, Flag="SYN-ACK", Action="Log")
    props.update(extra)
    return parse_record(structured_record("AZFWFlowTrace", **props))


def _dns_row(structured_record, **extra):
    props = dict(SourceIp="10.3.8.4", SourcePort=39294, QueryName="www.lonelyplanet.com",
                 QueryType="A", ResponseCode="NOERROR")
    props.update(extra)
    return parse_record(structured_record("AZFWDnsQuery", **props))


def _threatintel_row(structured_record, **extra):
    props = dict(Protocol="HTTP", SourceIp="10.3.8.4", SourcePort=47074, DestinationIp="",
                 DestinationPort=80, Fqdn="bad.example.com", Action="Alert",
                 ThreatDescription="test indicator")
    props.update(extra)
    return parse_record(structured_record("AZFWThreatIntel", **props))


def _matched_network_row(structured_record, **extra):
    """Matches rc-web » allow-web in ``make_snapshot``'s policy — the log must
    name the rule itself; the trace only confirms a rule the firewall named."""
    props = dict(Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1,
                 DestinationIp="1.1.1.1", DestinationPort=443, Action="Allow",
                 Policy="fwp-hub-premium-gwc", RuleCollectionGroup="rcg-net",
                 RuleCollection="rc-web", Rule="allow-web")
    props.update(extra)
    return parse_record(structured_record("AZFWNetworkRule", **props))


def _no_match_network_row(structured_record, **extra):
    props = dict(Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1,
                 DestinationIp="1.1.1.1", DestinationPort=8443, Action="Deny",
                 ActionReason="No rule matched. Proceeding with default action.")
    props.update(extra)
    return parse_record(structured_record("AZFWNetworkRule", **props))


def _stale_cache_row(structured_record, **extra):
    """The logged rule name is not in the loaded policy — a stale cache."""
    props = dict(Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1,
                 DestinationIp="1.1.1.1", DestinationPort=443, Action="Allow",
                 Policy="fwp-hub-premium-gwc", RuleCollectionGroup="ghost-group",
                 RuleCollection="ghost-coll", Rule="ghost-rule")
    props.update(extra)
    return parse_record(structured_record("AZFWNetworkRule", **props))


# ── header line 1: built from the row alone, identical with and without a trace ──

@pytest.mark.parametrize("build,expected", [
    (_app_row, "10.3.11.4:41644 → www.petmd.com:443"),
    (_network_row, "10.0.1.4:51000 → 10.0.2.5:443"),
    (_nat_row, "95.91.87.6:60223 → 72.144.131.50:18080"),   # the public destination, not the translated one
    (_flowtrace_row, "10.3.14.4:50674 → 51.116.242.155:443"),  # client → server, not the packet's src/dst
    (_dns_row, "10.3.8.4:39294 → www.lonelyplanet.com:53"),
])
async def test_header_line1_without_trace(structured_record, build, expected):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.query_one("#f-hide-dns", Switch).value = False  # DNS rows are hidden by default
        await pilot.pause()
        dialog = await _open_detail(app, pilot, build(structured_record))
        assert not dialog.has_trace
        assert expected in _header_text(dialog)


@pytest.mark.parametrize("build,expected", [
    (_app_row, "10.3.11.4:41644 → www.petmd.com:443"),
    (_nat_row, "95.91.87.6:60223 → 72.144.131.50:18080"),
    (_flowtrace_row, "10.3.14.4:50674 → 51.116.242.155:443"),
])
async def test_header_line1_same_with_trace(structured_record, mgmt, firewall_id, build, expected):  # noqa: F811
    """The header's first line does not depend on whether a trace exists."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, build(structured_record))
        # Whether or not this particular row ends up with a trace (FlowTrace
        # never does; AppRule/NatRule do once metadata is loaded), the header's
        # first line is built from the row alone and reads the same either way.
        assert expected in _header_text(dialog)


async def test_header_action_and_category_present_without_repeating_protocol_label(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        header = _header_text(dialog)
        assert "TCP" in header and "Deny" in header and "NetworkRule" in header


# ── header line 2: only with a trace ──────────────────────────────────────────

async def test_header_line2_absent_without_trace(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        assert not dialog.has_trace
        header = _header_text(dialog)
        assert "\n" not in header  # one line only


async def test_header_line2_matched_rule_is_green_check(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _matched_network_row(structured_record))
        assert dialog.has_trace
        header = _header_text(dialog)
        assert "✓" in header and "Allow by rcg-net » rc-web » allow-web" in header
        assert "cached policy · fresh" in header


async def test_header_line2_default_deny_is_red_cross(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _no_match_network_row(structured_record))
        header = _header_text(dialog)
        assert "✗" in header and "default action: Deny" in header


async def test_header_line2_stale_cache_is_yellow_question_mark(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _stale_cache_row(structured_record))
        header = _header_text(dialog)
        assert "?" in header and "rule not in loaded policy" in header


async def test_header_line2_threat_intel_is_magenta_bang(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _threatintel_row(structured_record))
        header = _header_text(dialog)
        assert "!" in header and "Alert by Threat Intelligence" in header


async def test_header_line2_cache_age_older_snapshot(structured_record, mgmt, firewall_id):  # noqa: F811
    mgmt["snapshot"] = make_snapshot(fetched_at=time.time() - 12 * 60)
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _matched_network_row(structured_record))
        assert "cached policy · 12 min old" in _header_text(dialog)


# ── footer ────────────────────────────────────────────────────────────────────

async def test_footer_without_trace(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        assert _footer_text(dialog) == "[dim]Esc close[/]"


async def test_footer_with_trace(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _matched_network_row(structured_record))
        assert _footer_text(dialog) == (
            "[dim]Enter expand/collapse · p open in Policy tab · a all / focused · Shift+↑↓ detail · Esc close[/]"
        )


# ── no close button, either mode ──────────────────────────────────────────────

async def test_no_close_button_without_trace(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        assert not dialog.query("#btn-close")
        assert not dialog.query("Button")


async def test_no_close_button_with_trace(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _matched_network_row(structured_record))
        assert not dialog.query("#btn-close")
        assert not dialog.query("Button")


# ── keys ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("key", ["escape", "q"])
async def test_close_keys_do_not_quit_app_with_trace(structured_record, mgmt, firewall_id, key):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        await _open_detail(app, pilot, _matched_network_row(structured_record))
        await pilot.press(key)
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailDialog)
        assert app.is_running


async def test_a_toggles_expand_all_with_trace(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _matched_network_row(structured_record))
        panel = dialog.query_one(TracePanel)
        assert panel._expand_all is False
        await pilot.press("a")
        await pilot.pause()
        assert panel._expand_all is True
        await pilot.press("a")
        await pilot.pause()
        assert panel._expand_all is False


async def test_p_without_trace_does_nothing(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        await pilot.press("p")
        await pilot.pause()
        assert app.screen is dialog
        assert isinstance(app.screen, DetailDialog)


# ── group captions ────────────────────────────────────────────────────────────

async def test_connection_caption_always_present(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        text = _dialog_text(dialog)
        assert "[dim]Connection[/]" in text


async def test_inspection_caption_present_for_apprule_with_flags(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        with_flags = await _open_detail(
            app, pilot, _app_row(structured_record, IsExplicitProxyRequest=True, IsTlsInspected=False))
        text = _dialog_text(with_flags)
        assert "[dim]Inspection[/]" in text
        assert "Expl. proxy" in text and "TLS inspected" in text


async def test_inspection_caption_absent_otherwise(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        without_flags = await _open_detail(app, pilot, _network_row(structured_record))
        assert "[dim]Inspection[/]" not in _dialog_text(without_flags)


async def test_groups_caption_absent_without_metadata(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        no_mgmt = await _open_detail(app, pilot, _network_row(structured_record))
        assert "[dim]Groups[/]" not in _dialog_text(no_mgmt)


async def test_groups_caption_present_when_enriched(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        enriched = await _open_detail(app, pilot, _matched_network_row(structured_record))
        text = _dialog_text(enriched)
        assert "[dim]Groups[/]" in text
        assert "Src IP groups" in text and "ipgroup-all-spokes" in text


async def test_rule_caption_present_without_trace(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        row = _network_row(structured_record, Policy="pol-hub", RuleCollectionGroup="rcg",
                           RuleCollection="rc", Rule="r-web")
        no_trace = await _open_detail(app, pilot, row)
        assert "[dim]Rule[/]" in _dialog_text(no_trace)


async def test_rule_caption_absent_with_trace(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        with_trace = await _open_detail(app, pilot, _matched_network_row(structured_record))
        assert "[dim]Rule[/]" not in _dialog_text(with_trace)


async def test_ip_groups_render_one_per_line(structured_record, monkeypatch):
    """Two overlapping IP groups on one address must be two lines, not a comma list."""
    import viewer.app as app_module

    g1 = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipgroup-a"
    g2 = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipgroup-b"
    fw = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg",
                      location="germanywestcentral", sku_tier="Premium", private_ips=["10.2.0.4"],
                      subnet_ids=["/sn"], policy_id="/p")
    policy = FirewallPolicyInfo(id="/p", name="p", sku_tier="Standard", threat_intel_mode="Off",
                                rule_collection_groups=[])
    groups = {
        g1: IpGroupInfo(id=g1, name="ipgroup-a", location="germanywestcentral", ip_addresses=["10.3.0.0/16"]),
        g2: IpGroupInfo(id=g2, name="ipgroup-b", location="germanywestcentral", ip_addresses=["10.3.5.0/24"]),
    }
    snap = CachedSnapshot(firewall=fw, policy=policy, ip_groups=groups, subnet_cidrs=[], fetched_at=time.time())

    async def _load_fake(firewall_id, *, force=False):
        return snap

    monkeypatch.setattr(app_module, "load_management_data", _load_fake)

    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, "fw-id")
        dialog = await _open_detail(app, pilot, _network_row(structured_record, SourceIp="10.3.5.4"))
        contents = [str(s.content) for s in dialog.query(Static)]
        src_field = next(c for c in contents if c.startswith("[dim]Src IP groups[/]"))
        lines = src_field.split("\n")
        assert len(lines) == 2
        assert "ipgroup-a" in lines[0] and lines[1].strip() == "ipgroup-b"
        assert "ipgroup-a, ipgroup-b" not in "\n".join(contents)  # not a comma list


# ── header-only fields: Category / Protocol / Action absent from the body ────

async def test_category_protocol_action_are_header_only(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _network_row(structured_record))
        left = "\n".join(str(s.content) for s in dialog.query("#detail-pane Static"))
        assert "Category" not in left
        assert "[dim]Protocol" not in left
        assert "[dim]Action" not in left


async def test_category_protocol_action_are_header_only_with_trace(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        dialog = await _open_detail(app, pilot, _matched_network_row(structured_record))
        left = "\n".join(str(s.content) for s in dialog.query("#detail-pane Static"))
        assert "Category" not in left
        assert "[dim]Protocol" not in left
        assert "[dim]Action" not in left


async def test_dns_query_type_is_not_hidden_as_protocol(structured_record):
    """DNS's 'Query type' is not a protocol and must stay in the fields."""
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.query_one("#f-hide-dns", Switch).value = False  # DNS rows are hidden by default
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _dns_row(structured_record))
        text = _dialog_text(dialog)
        assert "Query type" in text and "A" in text


# ── the 0.6.0 note is still rendered without a trace ──────────────────────────

async def test_trace_note_still_rendered_without_trace(structured_record):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _flowtrace_row(structured_record))
        note = str(dialog.query_one("#trace-note", Static).content)
        assert "No rule decision in this log" in note
