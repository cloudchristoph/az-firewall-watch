"""Enrichment in the running app: metadata load, status segment, tabs, detail dialog."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent, Tree

import viewer.app as app_module
from dialogs import StatusBar
from fw_parser import parse_record
from viewer.app import FirewallLogApp
from viewer.azure_resources import (
    FirewallInfo,
    FirewallPolicyInfo,
    IpGroupInfo,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
)
from viewer.cache import CachedSnapshot
from viewer.views import FirewallView, IpGroupsView, PolicyView
from viewer.views.detail_screen import DetailDialog, _ports_join
from viewer.views.firewall import _row
from viewer.views.ip_groups import IpGroupDetailDialog

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
        assert status.meta == "Policy: Premium · 2 IP groups · fresh"
        assert "Policy: Premium" in status.render()
        assert app.sub_title == "fw-hub-gwc"  # real name from ARM


async def test_unknown_logged_rule_triggers_one_auto_refresh(structured_record, mgmt, firewall_id):
    """A row naming a rule the cached policy lacks re-fetches once, then waits out the interval."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        assert mgmt["calls"] == [(firewall_id, False)]
        known = _net(structured_record, "10.3.5.4", "1.1.1.1")           # allow-web is in the fixture
        app._pending.append(known)
        await app._flush_rows()
        assert mgmt["calls"] == [(firewall_id, False)]                    # nothing to refresh
        renamed = parse_record(structured_record(
            "AZFWNetworkRule", SourceIp="10.3.5.4", DestinationIp="1.1.1.1", Action="Allow",
            Policy="fwp-hub-premium-gwc", RuleCollectionGroup="rcg-net", RuleCollection="rc-web", Rule="brand-new",
        ))
        app._pending.append(renamed)
        await app._flush_rows()
        await wait_until(pilot, lambda: (firewall_id, True) in mgmt["calls"])
        assert mgmt["calls"] == [(firewall_id, False), (firewall_id, True)]
        again = parse_record(structured_record(
            "AZFWNetworkRule", time="2026-09-05T08:00:01Z", SourceIp="10.3.5.4", DestinationIp="1.1.1.1",
            Action="Allow", Policy="fwp-hub-premium-gwc", RuleCollectionGroup="rcg-net", RuleCollection="rc-web",
            Rule="brand-new",
        ))
        app._pending.append(again)                                        # still unknown (fixture unchanged)
        await app._flush_rows()
        await pilot.pause(0.2)
        assert mgmt["calls"].count((firewall_id, True)) == 1              # rate-limited


async def test_expired_cache_is_refetched_by_the_minute_check(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = make_snapshot(fetched_at=time.time() - 61 * 60)  # older than the 1 h TTL
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        assert app.query_one("#status", StatusBar).meta.endswith("cache 61m")
        app._check_cache_age()
        await wait_until(pilot, lambda: (firewall_id, True) in mgmt["calls"])
        app._check_cache_age()                                            # within the interval: no second fetch
        await pilot.pause(0.2)
        assert mgmt["calls"].count((firewall_id, True)) == 1


async def test_minute_check_updates_the_cache_age(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = make_snapshot(fetched_at=time.time() - 7 * 60)
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app._snapshot.fetched_at -= 5 * 60                                # five minutes pass
        app._check_cache_age()
        assert app.query_one("#status", StatusBar).meta.endswith("cache 12m")


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
        assert "Src IP groups" in text and "ipgroup-all-spokes" in text
        assert "Rule Def." not in text and "TCP  443  from ipgroup-all-spokes  to *" not in text   # the trace shows the criteria
        assert "Dst IP groups" not in text  # 1.1.1.1 is in no group
        # priorities, action and policy path are shown once — in the trace, not the fields
        assert "Rule Priority" not in text
        labels = "\n".join(_tree_labels(app.screen.query_one("#trace-tree", Tree)))
        assert "[2000] rcg-net" in labels and "[100] rc-web  allow" in labels


async def test_detail_dialog_enrichment_names_priority_and_action_but_no_definition(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = _net(structured_record, "10.3.5.4", "1.1.1.1")
        enr = app._compute_enrichment(row)
        assert enr["rule_priority"] == "RCG:2000 » RC:100"
        assert enr["rule_action"] == "Allow"
        assert "rule_definition" not in enr  # the trace shows the criteria, the Policy tab the definition
        assert "trace_hint" not in enr  # the trace sits in the dialog itself now
        renamed = parse_record(structured_record(
            "AZFWNetworkRule", SourceIp="10.3.5.4", DestinationIp="1.1.1.1", Action="Allow",
            Policy="fwp-hub-premium-gwc", RuleCollectionGroup="rcg-net", RuleCollection="rc-web", Rule="gone",
        ))
        assert "rule_definition" not in app._compute_enrichment(renamed)  # the trace warns about a missing rule


# ── evaluation trace ─────────────────────────────────────────────────────────

async def _open_trace(app: FirewallLogApp, pilot, row) -> DetailDialog:
    app._pending.append(row)
    await app._flush_rows()
    await pilot.pause()
    tbl = app.query_one("#log-table", DataTable)
    tbl.focus()
    tbl.move_cursor(row=0, animate=False)
    await pilot.pause()
    await pilot.press("enter")
    await wait_until(pilot, lambda: isinstance(app.screen, DetailDialog) and app.screen.has_trace)
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


async def test_flow_trace_rows_get_no_evaluation_tree(structured_record, mgmt, firewall_id):
    """FlowTrace / FatFlow / DNS / IDPS rows are observations, not rule decisions."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWFlowTrace", Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1, DestinationIp="1.1.1.1",
            DestinationPort=443, Flag="SYN",
        ))
        assert row is not None and row.category == "FlowTrace"
        app._pending.append(row)
        await app._flush_rows()
        await pilot.pause()
        tbl = app.query_one("#log-table", DataTable)
        tbl.focus()
        tbl.move_cursor(row=0, animate=False)
        await pilot.pause()
        status_before = app.query_one("#status", StatusBar).meta
        await pilot.press("enter")
        await wait_until(pilot, lambda: isinstance(app.screen, DetailDialog))
        assert not app.screen.has_trace
        # The reason sits in the dialog, as a property of this row; the status
        # bar keeps the policy and cache state it had before.
        note = str(app.screen.query_one("#trace-note", Static).content)
        assert "No rule decision in this log" in note
        assert "FlowTrace records the handshake and flags of a connection, not a rule decision." in note
        assert app.query_one("#status", StatusBar).meta == status_before
        assert status_before.startswith("Policy: ")


async def test_detail_without_policy_metadata_has_no_trace(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        status = app.query_one("#status", StatusBar)
        row = _net(structured_record, "10.3.5.4", "1.1.1.1")
        app._pending.append(row)
        await app._flush_rows()
        await pilot.pause()
        tbl = app.query_one("#log-table", DataTable)
        tbl.focus()
        tbl.move_cursor(row=0, animate=False)
        await pilot.pause()
        status_before = status.meta
        await pilot.press("enter")
        await pilot.pause()
        # the plain detail dialog still opens — just without the trace column
        await wait_until(pilot, lambda: isinstance(app.screen, DetailDialog))
        assert not app.screen.has_trace
        assert not app.screen.query("#trace-tree")
        note = str(app.screen.query_one("#trace-note", Static).content)
        assert "Policy trace not available" in note and "not loaded yet" in note
        assert status.meta == status_before


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
        assert "DNAT rules   no collections" in joined
        assert "Network rules   ✓ matched" in joined
        assert "[2000] rcg-net" in joined and "✓ [100] rc-web  allow" in joined  # group once, collection below it
        assert "allow-web" in joined and "← logged" in joined
        assert "Application rules   not evaluated" in joined
        assert "evaluation stopped at the logged rule" in joined
        header = _text(screen)
        assert "10.3.5.4 → 1.1.1.1:443 TCP" in header and "Allow by rcg-net » rc-web » allow-web" in header
        assert "Enter: expand · Enter on an open rule: show in Policy tab" in header
        # top-level leaves are padded so their text lines up with expandable siblings
        assert any(line.startswith("  Threat Intelligence") for line in labels)
        assert any(line.startswith("  DNAT rules") for line in labels)
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
        await pilot.press("escape")
        await wait_until(pilot, lambda: not isinstance(app.screen, DetailDialog))


async def test_trace_screen_enter_jumps_to_policy_rule(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None and "allow-web" in tree.cursor_node.label.plain  # pre-selected
        await pilot.press("enter")
        await wait_until(pilot, lambda: not isinstance(app.screen, DetailDialog))
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-policy"
        policy_tree = app.query_one("#policy-tree", Tree)
        assert policy_tree.cursor_node is not None and policy_tree.cursor_node.label.plain == "allow-web"


async def test_threat_intel_trace_is_two_lines(structured_record, mgmt, firewall_id):
    """A ThreatIntel row was decided before the rules: no per-pass lines, no repeated verdict."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWThreatIntel", Protocol="HTTP", SourceIp="10.3.5.4", SourcePort=1, DestinationIp="",
            DestinationPort=80, Fqdn="testmaliciousdomain.eastus.cloudapp.azure.com", Action="Alert",
            ThreatDescription="test indicator",
        ))
        screen = await _open_trace(app, pilot, row)
        labels = _tree_labels(screen.query_one("#trace-tree", Tree))[1:]  # skip the hidden root
        assert len(labels) == 2, labels
        assert labels[0].startswith("  Threat Intelligence   hit — Alert by Threat Intelligence (mode Alert)")
        assert labels[1].startswith("  DNAT, Network and Application rules   not evaluated")
        title = str(screen.query_one("#trace-title", Static).content)
        assert "Alert by Threat Intelligence" in title  # the verdict lives in the header only


async def test_enter_on_collapsed_rule_expands_before_it_opens(structured_record, mgmt, firewall_id):
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
        rule = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("✗ allow-web"))
        assert not rule.is_expanded
        tree.move_cursor(rule)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert rule.is_expanded and app.screen is screen  # first Enter only unfolds the checks
        await pilot.press("space")
        await pilot.pause()
        assert not rule.is_expanded  # Space folds again
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await wait_until(pilot, lambda: not isinstance(app.screen, DetailDialog))
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-policy"


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
        assert "Network rules   ✗ no match" in joined
        assert "✗ [100] rc-web  allow   2 rules · nearest miss: port" in joined
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


async def test_enter_opens_entry_and_trace_side_by_side(structured_record, mgmt, firewall_id):
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
        screen = app.screen
        assert screen.has_trace and screen.has_class("-with-trace")
        left = "\n".join(str(s.content) for s in screen.query("#detail-pane Static"))
        assert "Rule Def." not in left
        # the category now lives in the dialog header, not repeated inside the pane
        assert "NetworkRule" not in left
        header = str(screen.query_one("#dialog-header", Static).content)
        assert "NetworkRule" in header
        # nothing twice: the policy path, priorities, action and SKU live in the trace
        for dup in ("Policy       ", "RCG          ", "Rule Coll.", "Rule         ", "Rule Priority", "Rule Action", "Policy SKU"):
            assert dup not in left, dup
        title = screen.query_one("#trace-title", Static).content
        assert str(title).startswith("▸ 10.3.5.4 → 1.1.1.1:443 TCP\n✓ Allow by rcg-net » rc-web » allow-web")
        # rendered as Rich Text, like the tree labels, so ✓ / ? / ✗ take the same theme colours everywhere
        from rich.text import Text as RichText
        assert isinstance(title, RichText) and "green" in str(title.spans)
        assert not screen.query("#trace-meta")  # the status bar already shows the metadata line
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.has_focus  # Enter on the tree opens the rule right away
        assert tree.cursor_node is not None and "allow-web" in tree.cursor_node.label.plain
        # the pane sits left of the trace, both inside the same dialog
        assert screen.query_one("#detail-pane").region.x < tree.region.x
        await pilot.press("t")  # no longer bound: must neither close the dialog nor move focus
        await pilot.pause()
        assert app.screen is screen and tree.has_focus


async def test_long_rule_details_are_shortened_on_collapsed_lines():
    """The collapsed rule line keeps a short reason; the full text lives on the child leaf."""
    from textual.app import App

    from viewer.trace import Flow, build_trace
    from viewer.views.trace_screen import TracePanel, _short

    assert _short("short") == "short"
    assert _short("x" * 60).endswith("…") and len(_short("x" * 60)) == 40

    many = [str(8000 + i) for i in range(14)]  # long port list → long miss detail
    policy = FirewallPolicyInfo(id="/p", name="p", sku_tier="Standard", threat_intel_mode="Alert",
                                rule_collection_groups=[
        RuleCollectionGroup(id="/p/g", name="g", priority=100, rule_collections=[
            RuleCollection(name="rc", priority=100, action="Allow", rule_collection_type="Filter", rules=[
                Rule(name="allow-many", rule_type="NetworkRule", source_addresses=["*"],
                     destination_addresses=["*"], destination_ports=many, protocols=["Any"]),
            ]),
        ]),
    ])
    trace = build_trace(Flow(category="NetworkRule", protocol="TCP", src_ip="10.3.5.4", dst_ip="1.1.1.1",
                             dst_port="443", action="Deny"), policy, {}, None)

    class _Host(App):
        def compose(self):
            yield TracePanel(trace)

    app = _Host()
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        labels = _tree_labels(app.query_one("#trace-tree", Tree))
    rule_line = next(line for line in labels if line.startswith("✗ allow-many"))
    assert "…" in rule_line and len(rule_line) < 80, rule_line
    assert any(line.startswith("✗ port:") and many[-1] in line for line in labels)  # full detail on the leaf


def test_flow_from_dnat_row_uses_the_public_destination(structured_record):
    """AZFWNatRule logs the translated target; the DNAT rule matched the public IP and port."""
    row = parse_record(structured_record(
        "AZFWNatRule", Protocol="TCP", SourceIp="95.91.87.6", SourcePort=60223,
        DestinationIp="72.144.131.50", DestinationPort=18080, TranslatedIp="10.3.6.4", TranslatedPort=80,
        Policy="p", RuleCollectionGroup="g", RuleCollection="c", Rule="r",
    ))
    flow = FirewallLogApp._flow_from_row(row)
    assert (flow.dst_ip, flow.dst_port) == ("72.144.131.50", "18080")
    assert flow.src_ip == "95.91.87.6" and flow.category == "NATRule"


def test_flow_from_legacy_ipv6_network_rule_keeps_full_address(legacy_record):
    """Regression: a legacy record with an unbracketed IPv6 destination used to be
    split at the first colon ('fd00' instead of 'fd00::1'), so ipaddress.ip_address()
    failed in _flow_from_row and the row ran into the FQDN branch — a confident wrong
    verdict instead of a correct address match."""
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
        "TCP request from fd00::1:1234 to fd00::2:443. Action: Allow. "
        "Rule Collection Group: rcg. Rule Collection: rc. Rule: r.",
    ))
    flow = FirewallLogApp._flow_from_row(row)
    assert flow.dst_ip == "fd00::2"
    assert flow.dst_fqdn == ""


def test_detail_values_stay_inline_in_the_wide_dialog_and_wrap_beside_the_trace(structured_record):
    """The own-line threshold follows the pane width: 84 columns alone, 52 beside the trace."""
    from viewer.trace import Flow, Trace
    row = parse_record(structured_record("AZFWFatFlow", Protocol="TCP", SourceIp="10.2.0.5", SourcePort=9684,
                                         DestinationIp="142.251.14.102", DestinationPort=443, Flag="", Rate="2.8 Mbps"))
    flow = "10.2.0.5:9684 → 142.251.14.102:443"      # 34 characters: the old threshold wrapped it nowhere
    assert len(flow) == 34
    alone = DetailDialog(row)
    assert str(alone._field("Flow         ", flow).content).startswith("[dim]Flow")
    assert "\n" not in str(alone._field("Flow         ", flow).content)
    beside = DetailDialog(row, trace=Trace(flow=Flow(), logged=None, threat_intel="", passes=[],
                                            infrastructure=None, outcome="x"))
    v6_flow = "[fd10:2:0:1::4]:9684 → [2603:1020:c01:16::275]:443"   # 50 characters: fits alone, not beside the trace
    assert "\n" not in str(alone._field("Flow         ", v6_flow).content)
    assert "\n" in str(beside._field("Flow         ", v6_flow).content)
    long_value = "x" * 70
    assert "\n" in str(alone._field("Rule Def.    ", long_value).content)   # still wraps when it would not fit


def test_ports_join_brackets_ipv6_addresses():
    assert _ports_join("fd00::1", "443") == "[fd00::1]:443"
    assert _ports_join("10.1.1.1", "443") == "10.1.1.1:443"
    assert _ports_join("10.1.1.1", "-") == "10.1.1.1"


def test_compute_enrichment_without_metadata(structured_record):
    app = FirewallLogApp()
    assert app._compute_enrichment(_net(structured_record, "10.3.5.4", "1.1.1.1")) == {}


# ── tabs ─────────────────────────────────────────────────────────────────────

async def test_filter_bar_lives_in_logs_tab_and_tab_strip_stays_put(structured_record, mgmt, firewall_id):
    from textual.widgets import Tabs
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#main-tabs", TabbedContent)
        strip_y = tabs.query_one(Tabs).region.y
        bar = app.query_one("#tab-logs #filter-bar")  # part of the Logs pane, not above the strip
        assert bar.region.y > strip_y
        tabs.active = "tab-policy"
        await pilot.pause()
        assert tabs.query_one(Tabs).region.y == strip_y  # the strip does not jump
        assert not app.query_one("#f-action", Input).region  # hidden with its pane
        app.query_one("#f-action", Input).value = "deny"  # must not explode while hidden
        await pilot.pause()
        tabs.active = "tab-logs"
        await pilot.pause()
        assert tabs.query_one(Tabs).region.y == strip_y
        assert app.query_one("#f-action", Input).region


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


async def test_firewall_tab_shows_instance_networking_policy_and_logging(structured_record, mgmt, firewall_id):
    from textual.containers import Grid

    from viewer.azure_resources import DiagnosticSetting, IpConfig
    snap = make_snapshot()
    snap.firewall.sku_name, snap.firewall.zones, snap.firewall.provisioning_state = "AZFW_VNet", ["1", "2", "3"], "Succeeded"
    snap.firewall.tags = {"project": "cclab"}
    snap.firewall.additional_properties = {"Network.AdditionalLogs.EnableFatFlowLogging": "true"}
    snap.firewall.ip_configs = [
        IpConfig(name="AzureFirewallIpConfiguration0", private_ip="10.2.0.4", public_ip_id="/p0",
                 public_ip_name="pip-fw-hub-gwc-001", public_ip_address="72.144.131.50", subnet_id="/vnet/subnets/AzureFirewallSubnet"),
        IpConfig(name="AzureFirewallIpConfiguration1", private_ip="fd10:2:0:1::4", public_ip_id="/p1",
                 public_ip_name="pip-fw-hub-gwc-ipv6-001", subnet_id="/vnet/subnets/AzureFirewallSubnet"),
    ]
    snap.firewall.subnet_ids = ["/vnet/subnets/AzureFirewallSubnet", "/vnet/subnets/AzureFirewallManagementSubnet"]
    snap.firewall.management_ip = IpConfig(name="AzureFirewallMgmtIpConfiguration", public_ip_id="/pm",
                                           public_ip_name="pip-fw-mgmt", public_ip_address="72.144.91.185",
                                           subnet_id="/vnet/subnets/AzureFirewallManagementSubnet")
    snap.policy.dns_proxy = True
    snap.policy.idps_mode, snap.policy.idps_override_count = "Alert", 2
    snap.policy.tls_ca_name = "fw-tls-intermediate-ca"
    snap.diagnostics = [DiagnosticSetting(name="diag-fw", event_hub="ehns-fw-gwc/firewall-logs",
                                          categories=["AZFWNetworkRule", "AZFWApplicationRule", "AZFWDnsQuery"])]
    mgmt["snapshot"] = snap
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        view = app.query_one("#firewall-view", FirewallView)
        assert not view.query_one("#fw-grid", Grid).display                 # nothing loaded yet
        await _load(app, pilot, firewall_id)
        await pilot.pause()
        assert view.query_one("#fw-grid", Grid).display
        title = str(view.query_one("#fw-title", Static).content)
        assert "fw-hub-gwc" in title and "Premium · AZFW_VNet · germanywestcentral" in title
        instance = str(view.query_one("#fw-instance", Static).content)
        assert "1, 2, 3" in instance and "Succeeded" in instance and "project=cclab" in instance
        assert _row("Fat flow logging", "on") in instance and "EnableFatFlowLogging" not in instance
        net = view.query_one("#fw-network", DataTable)
        rows = [[str(c) for c in net.get_row_at(i)] for i in range(net.row_count)]
        assert rows[0] == ["IpConfiguration0", "10.2.0.4", "pip-fw-hub-gwc-001\n72.144.131.50"]
        assert rows[1][1:] == ["fd10:2:0:1::4", "pip-fw-hub-gwc-ipv6-001\naddress not readable"]
        assert rows[2][0] == "management" and rows[2][2].endswith("72.144.91.185")
        net_note = str(view.query_one("#fw-network-note", Static).content)
        assert "10.2.0.0/26" in net_note and "AzureFirewallSubnet, AzureFirewallManagementSubnet" in net_note
        assert "own subnet and public IP" in net_note and "forced tunneling" not in net_note
        pol = str(view.query_one("#fw-policy", Static).content)
        assert "fwp-hub-premium-gwc" in pol and "1 rule collection groups" in pol
        assert "DNS proxy" in pol and "Azure DNS" in pol and "2 signature overrides" in pol and "CA: fw-tls-intermediate-ca" in pol
        log = view.query_one("#fw-logging", DataTable)
        lrows = [[str(c) for c in log.get_row_at(i)] for i in range(log.row_count)]
        assert lrows == [["diag-fw\n  Event Hub ehns-fw-gwc/firewall-logs · 3 categories · 3 of 9 viewer"]]
        note = str(view.query_one("#fw-logging-note", Static).content)
        assert "Not to Event Hub" in note and "AZFWFlowTrace" in note and "AZFWNatRule" in note


async def test_firewall_tab_shows_the_0_6_0_facts_from_the_snapshot(structured_record, mgmt, firewall_id):
    """Everything 0.6.0 reads must survive the app's plumbing from snapshot to tab:
    subnets, NAT gateway, maintenance, autoscale, auto-learn SNAT, explicit proxy."""
    from viewer.azure_resources import MaintenanceWindow, NatGatewayInfo, SubnetInfo
    snap = make_snapshot()
    snap.firewall.sku_name = "AZFW_VNet"
    snap.firewall.autoscale_min, snap.firewall.autoscale_max = 4, 4
    snap.firewall.route_server_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualHubs/rs-hub"
    snap.firewall.additional_properties = {"Network.RouteServerInfo.RouteServerID": snap.firewall.route_server_id}
    snap.subnets = [SubnetInfo(id="/sn", name="AzureFirewallSubnet", cidrs=["10.2.0.0/26"], nat_gateway_id="/ng")]
    snap.nat_gateways = [NatGatewayInfo(id="/ng", name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                                        public_ip_ids=["/p"], public_ip_names=["pip-natgw"], public_ip_addresses=["20.1.2.3"])]
    snap.maintenance = [MaintenanceWindow(assignment_name="a", configuration_id="/mc", configuration_name="mc-fw-nightly",
                                          readable=True, start="2026-01-01 22:00", duration="05:00",
                                          time_zone="W. Europe Standard Time", recur_every="Day",
                                          expiration="9999-12-31 23:59", scope="Resource", sub_scope="NetworkSecurity")]
    snap.policy.snat_auto_learn = "Enabled"
    snap.policy.explicit_proxy = True
    snap.policy.explicit_proxy_http_port = 8080
    snap.policy.explicit_proxy_pac = True
    snap.policy.explicit_proxy_pac_port = 8090
    snap.policy.explicit_proxy_pac_file = "https://acct.blob.core.windows.net/c/proxy.pac"
    mgmt["snapshot"] = snap
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        await pilot.pause()
        view = app.query_one("#firewall-view", FirewallView)
        instance = str(view.query_one("#fw-instance", Static).content)
        assert "fixed at 4 capacity units, autoscaling off" in instance
        assert "daily 22:00 for 5 h, W. Europe Standard Time" in instance and "mc-fw-nightly" in instance
        assert "RouteServerID" not in instance   # has its own row in the Policy block
        net_note = str(view.query_one("#fw-network-note", Static).content)
        assert "natgw-hub on AzureFirewallSubnet" in net_note and "leaves with 20.1.2.3" in net_note
        pol = str(view.query_one("#fw-policy", Static).content)
        assert "via Route Server rs-hub" in pol and "not readable from here" in pol
        assert "port 8080 for HTTP and HTTPS" in pol and "served on port 8090" in pol and "proxy.pac" in pol


async def test_firewall_tab_panels_scroll_on_a_small_terminal(structured_record, mgmt, firewall_id):
    """Regression for the Codex finding: a 120×30 terminal cannot show the whole
    Policy block, so the panel must scroll rather than cut the rest off."""
    from textual.containers import Vertical
    snap = make_snapshot()
    snap.policy.dns_proxy, snap.policy.dns_servers = True, ["10.0.0.53"]
    snap.policy.idps_mode, snap.policy.tls_ca_name = "Alert", "fw-tls-intermediate-ca"
    snap.policy.snat_auto_learn = "Enabled"
    snap.policy.explicit_proxy, snap.policy.explicit_proxy_http_port = True, 8080
    snap.policy.explicit_proxy_pac, snap.policy.explicit_proxy_pac_port = True, 8090
    snap.policy.explicit_proxy_pac_file = "https://acct.blob.core.windows.net/c/proxy.pac"
    mgmt["snapshot"] = snap
    app = FirewallLogApp()
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app.query_one("#main-tabs", TabbedContent).active = "tab-firewall"
        await pilot.pause()
        panel = app.query_one("#panel-policy", Vertical)
        text_lines = str(app.query_one("#fw-policy", Static).content).count("\n") + 1
        assert text_lines > panel.size.height, "the fixture must overflow the panel for this test to mean anything"
        assert panel.max_scroll_y > 0            # the overflow is reachable
        panel.scroll_end(animate=False)
        await pilot.pause()
        assert panel.scroll_y == panel.max_scroll_y


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
        # the cursor move and selection happen after the next refresh (slow on Windows CI)
        await wait_until(pilot, lambda: "Rule: allow-web" in str(app.query_one("#policy-details", Static).content))
        details = str(app.query_one("#policy-details", Static).content)
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
        # the cursor move and selection happen after the next refresh (slow on Windows CI)
        await wait_until(pilot, lambda: "Rule: allow-web" in str(app.query_one("#policy-details", Static).content))
        details = str(app.query_one("#policy-details", Static).content)
        assert "ipgroup-all-spokes: (10.3.0.0/16)" in details   # parentheses, no bracket markup
