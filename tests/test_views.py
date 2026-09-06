"""Enrichment in the running app: metadata load, status segment, tabs, detail dialog."""
from __future__ import annotations

import asyncio
import time
from typing import Callable

import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent, Tree

import viewer.app as app_module
from dialogs import DetailDialog, StatusBar
from fw_parser import parse_record
from viewer.app import FirewallLogApp
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup
from viewer.cache import CachedSnapshot
from viewer.views import FirewallView, IpGroupsView, PolicyView
from viewer.views.ip_groups import IpGroupDetailDialog
from viewer.views.trace_screen import TraceScreen

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")

G_SPOKES = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipgroup-all-spokes"
G_ONPREM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipgroup-onpremises"


def make_snapshot(fetched_at: float | None = None) -> CachedSnapshot:
    fw = FirewallInfo(id="/fw", name="fw-hub-gwc", subscription_id="s", resource_group="rg-hub-network-gwc",
                      location="germanywestcentral", sku_tier="Premium", private_ips=["10.2.0.4"],
                      subnet_ids=["/sn"], policy_id="/p")
    policy = FirewallPolicyInfo(id="/p", name="fwp-hub-premium-gwc", sku_tier="Premium", threat_intel_mode="Alert",
                                rule_collection_groups=[
        RuleCollectionGroup(id="/p/net", name="rcg-net", priority=2000, rule_collections=[
            RuleCollection(name="rc-deny", priority=50, action="Deny", rule_collection_type="Filter", rules=[
                Rule(name="deny-bad", rule_type="NetworkRule", source_addresses=["*"],
                     destination_addresses=["203.0.113.0/24"], destination_ports=["*"]),
            ]),
            RuleCollection(name="rc-web", priority=100, action="Allow", rule_collection_type="Filter", rules=[
                Rule(name="allow-web", rule_type="NetworkRule", source_ip_groups=[G_SPOKES],
                     destination_addresses=["*"], destination_ports=["443"], protocols=["TCP"]),
                Rule(name="allow-onprem", rule_type="NetworkRule", source_ip_groups=[G_ONPREM],
                     destination_ip_groups=[G_SPOKES], destination_ports=["*"]),
            ]),
        ]),
    ])
    groups = {
        G_SPOKES: IpGroupInfo(id=G_SPOKES, name="ipgroup-all-spokes", location="germanywestcentral", ip_addresses=["10.3.0.0/16"]),
        G_ONPREM: IpGroupInfo(id=G_ONPREM, name="ipgroup-onpremises", location="germanywestcentral", ip_addresses=["192.168.0.0/16"]),
    }
    return CachedSnapshot(firewall=fw, policy=policy, ip_groups=groups, subnet_cidrs=["10.2.0.0/26"],
                          fetched_at=time.time() if fetched_at is None else fetched_at)


@pytest.fixture
def no_update_check(monkeypatch):
    async def _noop(*_a, **_kw):
        return None

    monkeypatch.setattr(app_module, "check_for_update", _noop)


@pytest.fixture
def mgmt(monkeypatch):
    """Replace load_management_data with a controllable fake; returns its state."""
    state = {"snapshot": make_snapshot(), "calls": []}

    async def _load(firewall_id, *, force=False):
        state["calls"].append((firewall_id, force))
        return state["snapshot"]

    monkeypatch.setattr(app_module, "load_management_data", _load)
    return state


async def wait_until(pilot, cond: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await pilot.pause(0.05)


async def _load(app: FirewallLogApp, pilot, firewall_id: str) -> None:
    app.request_mgmt_load(firewall_id)
    await wait_until(pilot, lambda: app._mgmt_loaded)
    await pilot.pause()


def _net(structured_record, src: str, dst: str, port: int = 443):
    return parse_record(structured_record(
        "AZFWNetworkRule", Protocol="TCP", SourceIp=src, SourcePort=1, DestinationIp=dst,
        DestinationPort=port, Action="Allow", Policy="fwp-hub-premium-gwc",
        RuleCollectionGroup="rcg-net", RuleCollection="rc-web", Rule="allow-web",
    ))


def _text(widget) -> str:
    return "\n".join(str(s.content) for s in widget.query(Static))


# ── loading / status ─────────────────────────────────────────────────────────

async def test_metadata_load_fills_status_segment_and_title(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        before = status.status
        await _load(app, pilot, firewall_id)
        assert mgmt["calls"] == [(firewall_id, False)]
        assert status.status == before  # connection status untouched
        assert status.meta == "policy Premium · 2 IP groups · fresh"
        assert "policy Premium" in status.render()
        assert app.sub_title == "fw-hub-gwc"  # real name from ARM


async def test_metadata_cache_age_is_shown(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = make_snapshot(fetched_at=time.time() - 7 * 60)
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        assert app.query_one("#status", StatusBar).meta.endswith("cache 7m")


async def test_metadata_unavailable_is_reported_without_touching_status(firewall_id, monkeypatch):
    async def _none(*_a, **_kw):
        return None

    monkeypatch.setattr(app_module, "load_management_data", _none)
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        before = status.status
        app.request_mgmt_load(firewall_id)
        await wait_until(pilot, lambda: bool(status.meta))
        assert status.meta == "metadata unavailable (no ARM access)"
        assert status.status == before
        assert not app._mgmt_loaded


async def test_failed_refresh_keeps_previous_metadata(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        mgmt["snapshot"] = None  # ARM now unreachable
        await pilot.press("ctrl+r")
        status = app.query_one("#status", StatusBar)
        await wait_until(pilot, lambda: status.meta.startswith("refresh failed"))
        assert status.meta == "refresh failed · showing previous metadata"
        assert app._mgmt_loaded and app._policy_info is not None
        assert app._format_ip("10.2.0.6") == "AzFw.6"  # enrichment still works


async def test_request_is_only_honoured_once(mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app.request_mgmt_load(firewall_id)
        app.request_mgmt_load("/another")
        await pilot.pause(0.2)
        assert mgmt["calls"] == [(firewall_id, False)]


async def test_ctrl_r_forces_refresh(mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await pilot.press("ctrl+r")
        await pilot.pause()
        assert app.query_one("#status", StatusBar).meta == "refresh skipped: no firewall seen yet"
        await _load(app, pilot, firewall_id)
        await pilot.press("ctrl+r")
        await wait_until(pilot, lambda: len(mgmt["calls"]) == 2)
        assert mgmt["calls"][1] == (firewall_id, True)


# ── table enrichment ─────────────────────────────────────────────────────────

async def test_firewall_subnet_ips_render_as_instances(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        row = _net(structured_record, "10.2.0.6", "10.3.5.4")
        app._pending.append(row)
        await app._flush_rows()
        await pilot.pause()
        tbl = app.query_one("#log-table", DataTable)
        src_col = tbl.ordered_columns[3].key
        assert tbl.get_cell(row.rowid, src_col).plain == "10.2.0.6:1"
        await _load(app, pilot, firewall_id)  # triggers a table refresh
        assert tbl.get_cell(row.rowid, src_col).plain == "AzFw.6:1"
        assert app._format_ip("10.3.5.4") == "10.3.5.4"
        assert app._format_ip("-") == "-"


async def test_detail_dialog_shows_enrichment(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = _net(structured_record, "10.3.5.4", "1.1.1.1")
        app._pending.append(row)
        await app._flush_rows()
        await pilot.pause()
        app.query_one("#log-table", DataTable).focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: isinstance(app.screen, DetailDialog))
        await pilot.pause(0.2)
        text = _text(app.screen)
        assert "Src IP Groups" in text and "ipgroup-all-spokes" in text
        assert "Rule Priority" in text and "RCG:2000 » RC:100" in text
        assert "Rule Action" in text and "Allow" in text
        assert "Policy SKU" in text and "Premium" in text
        assert "Dst IP Groups" not in text  # 1.1.1.1 is in no group


async def test_detail_dialog_shows_logged_rule_definition(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = _net(structured_record, "10.3.5.4", "1.1.1.1")
        enr = app._compute_enrichment(row)
        assert enr["rule_priority"] == "RCG:2000 » RC:100"
        assert enr["rule_action"] == "Allow"
        assert enr["rule_definition"] == "TCP  443  from ipgroup-all-spokes  to *"
        assert enr["trace_hint"].startswith("press t")
        renamed = parse_record(structured_record(
            "AZFWNetworkRule", SourceIp="10.3.5.4", DestinationIp="1.1.1.1", Action="Allow",
            Policy="fwp-hub-premium-gwc", RuleCollectionGroup="rcg-net", RuleCollection="rc-web", Rule="gone",
        ))
        assert "not in loaded policy" in app._compute_enrichment(renamed)["rule_definition"]


# ── evaluation trace ─────────────────────────────────────────────────────────

async def _open_trace(app: FirewallLogApp, pilot, row) -> TraceScreen:
    app._pending.append(row)
    await app._flush_rows()
    await pilot.pause()
    tbl = app.query_one("#log-table", DataTable)
    tbl.focus()
    tbl.move_cursor(row=0, animate=False)
    await pilot.pause()
    await pilot.press("t")
    await wait_until(pilot, lambda: isinstance(app.screen, TraceScreen))
    await pilot.pause(0.2)
    return app.screen


def _tree_nodes(tree: Tree) -> list:
    out: list = []

    def walk(node):
        out.append(node)
        for child in node.children:
            walk(child)

    walk(tree.root)
    return out


def _tree_labels(tree: Tree) -> list[str]:
    return [n.label.plain for n in _tree_nodes(tree)]


async def test_trace_requires_selection_and_metadata(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        await pilot.press("t")
        await pilot.pause()
        assert status.meta == "trace: select a log row first"
        row = _net(structured_record, "10.3.5.4", "1.1.1.1")
        app._pending.append(row)
        await app._flush_rows()
        await pilot.pause()
        tbl = app.query_one("#log-table", DataTable)
        tbl.focus()
        tbl.move_cursor(row=0, animate=False)
        await pilot.pause()
        await pilot.press("t")
        await pilot.pause()
        assert status.meta == "trace needs policy metadata (not loaded)"
        assert not isinstance(app.screen, TraceScreen)


async def test_trace_screen_shows_logged_match_and_closes(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        tree = screen.query_one("#trace-tree", Tree)
        labels = _tree_labels(tree)
        joined = "\n".join(labels)
        assert "Threat Intelligence   mode Alert" in joined
        assert "Pass 1 · DNAT   no collections" in joined
        assert "Pass 2 · Network   ✓ matched" in joined
        assert "[2000] rcg-net" in joined and "✓ [100] rc-web (Allow)" in joined  # group once, collection below it
        assert "allow-web" in joined and "← logged" in joined
        assert "Pass 3 · Application   not evaluated" in joined
        assert "evaluation stopped at the logged rule" in joined
        header = _text(screen)
        assert "10.3.5.4 → 1.1.1.1:443 TCP" in header and "Allow by rcg-net » rc-web » allow-web" in header
        assert "Enter open rule · a toggle full tree" in header
        # path view: the missed collection before the match is one collapsed line with the reason
        deny = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("✗ [50] rc-deny"))
        assert "1 rule · nearest miss: destination" in deny.label.plain
        assert not deny.is_expanded and len(deny.children) == 1
        assert deny.children[0].label.plain == "✗ deny-bad   destination: 1.1.1.1"
        await pilot.press("a")  # expand all
        await pilot.pause()
        deny = next(n for n in _tree_nodes(screen.query_one("#trace-tree", Tree)) if n.label.plain.startswith("✗ [50] rc-deny"))
        assert deny.is_expanded and deny.children[0].is_expanded
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, TraceScreen)


async def test_trace_screen_enter_jumps_to_policy_rule(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None and "allow-web" in tree.cursor_node.label.plain  # pre-selected
        await pilot.press("enter")
        await wait_until(pilot, lambda: not isinstance(app.screen, TraceScreen))
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-policy"
        policy_tree = app.query_one("#policy-tree", Tree)
        assert policy_tree.cursor_node is not None and policy_tree.cursor_node.label.plain == "allow-web"


async def test_trace_for_no_rule_matched_row_shows_near_miss(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWNetworkRule", Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1, DestinationIp="1.1.1.1",
            DestinationPort=8443, Action="Deny", ActionReason="No rule matched. Proceeding with default action.",
        ))
        screen = await _open_trace(app, pilot, row)
        tree = screen.query_one("#trace-tree", Tree)
        joined = "\n".join(_tree_labels(tree))
        assert "Pass 2 · Network   ✗ no match" in joined
        assert "✗ [100] rc-web (Allow)   2 rules · nearest miss: port" in joined
        assert "✗ allow-web   port: 8443 not in 443 ★ nearest" in joined   # first problem inline, ranked
        assert "skipped — protocol TCP is not HTTP, HTTPS or MSSQL" in joined
        assert "default action: Deny" in joined
        # the collection holding the nearest misses is expanded in path view
        rc_node = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("✗ [100] rc-web"))
        assert rc_node.is_expanded


async def test_trace_header_omits_missing_port(structured_record, mgmt, firewall_id):
    """Copilot review: ICMP rows have no port; the header must not read '1.1.1.1:-'."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWNetworkRule", Protocol="ICMP", SourceIp="10.3.5.4", DestinationIp="1.1.1.1", Action="Deny",
            ActionReason="No rule matched. Proceeding with default action.",
        ))
        screen = await _open_trace(app, pilot, row)
        header = _text(screen)
        assert "10.3.5.4 → 1.1.1.1 ICMP" in header and ":-" not in header


async def test_detail_dialog_t_opens_trace(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app._pending.append(_net(structured_record, "10.3.5.4", "1.1.1.1"))
        await app._flush_rows()
        await pilot.pause()
        app.query_one("#log-table", DataTable).focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: isinstance(app.screen, DetailDialog))
        await pilot.pause(0.2)
        await pilot.press("t")
        await wait_until(pilot, lambda: isinstance(app.screen, TraceScreen))


def test_rule_definition_formats_dnat_targets_without_trailing_colon():
    app = FirewallLogApp()
    with_port = Rule(name="rdp", rule_type="NatRule", source_addresses=["*"], destination_addresses=["20.1.1.1"],
                     destination_ports=["3389"], protocols=["TCP"], translated_address="10.3.5.4", translated_port="3389")
    without_port = Rule(name="web", rule_type="NatRule", source_addresses=["*"], destination_addresses=["20.1.1.1"],
                        destination_ports=["443"], protocols=["TCP"], translated_fqdn="web.internal")
    assert app._rule_definition(with_port).endswith("to 20.1.1.1, → 10.3.5.4:3389")
    assert app._rule_definition(without_port).endswith("to 20.1.1.1, → web.internal")


def test_compute_enrichment_without_metadata(structured_record):
    app = FirewallLogApp()
    assert app._compute_enrichment(_net(structured_record, "10.3.5.4", "1.1.1.1")) == {}


# ── tabs ─────────────────────────────────────────────────────────────────────

async def test_switching_tabs_hides_filter_bar_and_restores_it(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#main-tabs", TabbedContent)
        bar = app.query_one("#filter-bar")
        assert bar.display
        tabs.active = "tab-policy"
        await pilot.pause()
        assert not bar.display
        app.query_one("#f-action", Input).value = "deny"  # must not explode while hidden
        await pilot.pause()
        tabs.active = "tab-logs"
        await pilot.pause()
        assert bar.display


async def test_views_show_placeholders_before_metadata(firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        assert "Waiting for first firewall event" in _text(app.query_one("#firewall-view", FirewallView))
        assert app.query_one("#policy-tree", Tree).root.label.plain == "Policy data unavailable"
        ipg = app.query_one("#ipg-table", DataTable)
        assert ipg.row_count == 1 and ipg.get_cell_at((0, 0)) == "No IP groups loaded"


async def test_policy_view_clears_root_data_when_policy_disappears(structured_record, mgmt, firewall_id):
    """Copilot review: after a refresh without policy, the root node must not keep the old details."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        tree = app.query_one("#policy-tree", Tree)
        assert isinstance(tree.root.data, dict) and tree.root.data["kind"] == "policy"
        app.query_one("#policy-view", PolicyView).render_data(None, {})
        await pilot.pause()
        assert tree.root.data is None
        assert tree.root.label.plain == "Policy data unavailable" and not tree.root.children


async def test_views_render_metadata(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        fw_text = _text(app.query_one("#firewall-view", FirewallView))
        assert "fw-hub-gwc" in fw_text and "rg-hub-network-gwc" in fw_text and "10.2.0.0/26" in fw_text
        tree = app.query_one("#policy-tree", Tree)
        assert "fwp-hub-premium-gwc" in tree.root.label.plain and "Premium" in tree.root.label.plain
        rcg_node = tree.root.children[0]
        assert "[2000] rcg-net" in rcg_node.label.plain
        assert [n.label.plain for n in rcg_node.children] == ["[50] rc-deny (Deny)", "[100] rc-web (Allow)"]
        assert [n.label.plain for n in rcg_node.children[1].children] == ["allow-web", "allow-onprem"]
        ipg = app.query_one("#ipg-table", DataTable)
        assert ipg.row_count == 2
        names = [ipg.get_cell_at((i, 0)) for i in range(2)]
        assert names == ["ipgroup-all-spokes", "ipgroup-onpremises"]  # sorted by name
        used_by = [ipg.get_cell_at((i, 3)) for i in range(2)]
        assert used_by == ["2", "1"]  # spokes: source of allow-web + destination of allow-onprem


async def test_ip_group_selection_lists_related_rules_and_jumps_to_policy(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app.query_one("#main-tabs", TabbedContent).active = "tab-ipgroups"
        await pilot.pause()
        view = app.query_one("#ipgroups-view", IpGroupsView)
        ipg = app.query_one("#ipg-table", DataTable)
        ipg.focus()
        ipg.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()
        assert "ipgroup-all-spokes" in _text(view)
        rules = app.query_one("#ipg-rules", DataTable)
        assert rules.row_count == 2
        assert [rules.get_cell_at((i, 2)) for i in range(2)] == ["allow-web", "allow-onprem"]
        assert [rules.get_cell_at((i, 3)) for i in range(2)] == ["source", "target"]
        rules.focus()
        rules.move_cursor(row=1)
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-policy"
        tree = app.query_one("#policy-tree", Tree)
        assert tree.cursor_node is not None and tree.cursor_node.label.plain == "allow-onprem"


async def test_policy_node_selection_updates_details(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app.query_one("#main-tabs", TabbedContent).active = "tab-policy"
        await pilot.pause()
        view = app.query_one("#policy-view", PolicyView)
        assert view.focus_rule("fwp-hub-premium-gwc|rcg-net|rc-web|allow-web")
        await pilot.pause()
        details = str(app.query_one("#policy-details", Static).content)
        assert "Rule: allow-web" in details
        assert "ipgroup-all-spokes" in details and "10.3.0.0/16" in details
        assert "443" in details
        assert not view.focus_rule("nope|nope|nope")


@pytest.mark.parametrize("key", ["escape", "q"])
async def test_ip_group_detail_dialog_closes_without_reaching_the_app(structured_record, mgmt, firewall_id, key):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        app.query_one("#f-action", Input).value = "deny"
        await app.push_screen(IpGroupDetailDialog(mgmt["snapshot"].ip_groups[G_SPOKES]))
        await pilot.pause(0.2)
        assert "ipgroup-all-spokes" in _text(app.screen) and "10.3.0.0/16" in _text(app.screen)
        await pilot.press(key)
        await pilot.pause(0.3)
        assert not isinstance(app.screen, IpGroupDetailDialog)
        assert app.is_running and not app._exit                       # q did not quit the app
        assert app.query_one("#f-action", Input).value == "deny"      # escape did not clear filters


def make_inherited_snapshot() -> CachedSnapshot:
    """Child policy with a parent that references ipgroup-onpremises."""
    snap = make_snapshot()
    parent = FirewallPolicyInfo(id="/base", name="fwp-base", sku_tier="Premium", rule_collection_groups=[
        RuleCollectionGroup(id="/base/net", name="base-net", priority=9000, rule_collections=[
            RuleCollection(name="base-rc", priority=100, action="Allow", rule_collection_type="Filter", rules=[
                Rule(name="base-rule", rule_type="NetworkRule", source_ip_groups=[G_ONPREM],
                     destination_addresses=["*"], destination_ports=["*"]),
            ]),
        ]),
    ])
    snap.policy.parent = parent
    return snap


async def test_inherited_policy_is_counted_listed_and_navigable(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = make_inherited_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        # usage counts include the parent rule (onprem: allow-onprem + base-rule)
        ipg = app.query_one("#ipg-table", DataTable)
        rows = {ipg.get_cell_at((i, 0)): ipg.get_cell_at((i, 3)) for i in range(ipg.row_count)}
        assert rows == {"ipgroup-all-spokes": "2", "ipgroup-onpremises": "2"}
        # policy tree shows the parent group first, marked with its origin
        tree = app.query_one("#policy-tree", Tree)
        assert [n.label.plain for n in tree.root.children] == ["[9000] base-net  · fwp-base", "[2000] rcg-net"]
        assert app.query_one("#policy-view", PolicyView).focus_rule("fwp-base|base-net|base-rc|base-rule")
        assert not app.query_one("#policy-view", PolicyView).focus_rule("base-net|base-rc|base-rule")  # policy is part of the key
        # related rules of the onprem group include the inherited one
        app.query_one("#main-tabs", TabbedContent).active = "tab-ipgroups"
        await pilot.pause()
        ipg.focus()
        ipg.move_cursor(row=1, animate=False)
        await pilot.press("enter")
        await pilot.pause()
        rules = app.query_one("#ipg-rules", DataTable)
        assert [rules.get_cell_at((i, 2)) for i in range(rules.row_count)] == ["base-rule", "allow-onprem"]


async def test_policy_details_escape_markup(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        view = app.query_one("#policy-view", PolicyView)
        assert view.focus_rule("fwp-hub-premium-gwc|rcg-net|rc-web|allow-web")
        await pilot.pause()
        details = str(app.query_one("#policy-details", Static).content)
        assert "ipgroup-all-spokes: (10.3.0.0/16)" in details   # parentheses, no bracket markup
