"""The focused evaluation tree and its selection detail (viewer/views/trace_screen.py).

Covers work packages 3 and 4 of docs/detail-dialog-plan.md: the tree carries
only status, priority and name (no rule counts, no "nearest miss" suffix, no
inline check detail); collections before the logged one in its group fold
into one "preceding collections" node, collections after it into "not
evaluated"; the selection detail below the tree follows the cursor and is
where all of that detail — checks, header names, notes — actually lives.

Uses the app fixtures already established in test_views.py (make_snapshot,
mgmt, _load, _open_trace, wait_until, _tree_nodes, _tree_labels) rather than
duplicating them.
"""
from __future__ import annotations

import time

import pytest
from textual.widgets import Static, TabbedContent, Tree

from fw_parser import parse_record
from viewer.app import FirewallLogApp
from viewer.azure_resources import (
    FirewallInfo,
    FirewallPolicyInfo,
    HttpHeader,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
)
from viewer.cache import CachedSnapshot
from viewer.views.detail_screen import DetailDialog
from viewer.views.trace_screen import TracePanel

from .test_views import (  # noqa: F401  (no_update_check is a pytest fixture)
    _load,
    _net,
    _open_trace,
    _tree_labels,
    _tree_nodes,
    make_snapshot,
    no_update_check,
    wait_until,
)
from .test_views import mgmt as _mgmt  # noqa: F401  (pytest fixture, wrapped below)

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")


@pytest.fixture
def mgmt(_mgmt):  # noqa: F811  (re-bound so it can be used as a test parameter name)
    return _mgmt

MISSING_GROUP = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipgroup-missing"
HEADER_VALUE = "super-secret-tenant-token"


def _focused_group_snapshot() -> CachedSnapshot:
    """One group with three collections before the logged one (one of them
    UNKNOWN) and one collection after it that is never evaluated."""
    fw = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_tier="Premium")
    group = RuleCollectionGroup(id="/p/g", name="rcg-net", priority=100, rule_collections=[
        RuleCollection(name="rc-deny-1", priority=10, action="Deny", rule_collection_type="Filter", rules=[
            Rule(name="deny-1", rule_type="NetworkRule", source_addresses=["*"],
                 destination_addresses=["203.0.113.0/24"], destination_ports=["*"], protocols=["TCP"]),
        ]),
        RuleCollection(name="rc-unreadable", priority=20, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="check-unreadable", rule_type="NetworkRule", source_ip_groups=[MISSING_GROUP],
                 destination_addresses=["*"], destination_ports=["*"], protocols=["TCP"]),
        ]),
        RuleCollection(name="rc-deny-3", priority=30, action="Deny", rule_collection_type="Filter", rules=[
            Rule(name="deny-3", rule_type="NetworkRule", source_addresses=["*"],
                 destination_addresses=["198.51.100.0/24"], destination_ports=["*"], protocols=["TCP"]),
        ]),
        RuleCollection(name="rc-logged", priority=40, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="allow-it", rule_type="NetworkRule", source_addresses=["*"],
                 destination_addresses=["*"], destination_ports=["*"], protocols=["TCP"]),
        ]),
        RuleCollection(name="rc-after", priority=50, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="after-rule", rule_type="NetworkRule", source_addresses=["*"],
                 destination_addresses=["*"], destination_ports=["*"], protocols=["TCP"]),
        ]),
    ])
    policy = FirewallPolicyInfo(id="/p", name="fwp-a", sku_tier="Premium", threat_intel_mode="Off",
                                rule_collection_groups=[group])
    return CachedSnapshot(firewall=fw, policy=policy, ip_groups={}, fetched_at=time.time())


def _open_focused_group_row(structured_record):
    return parse_record(structured_record(
        "AZFWNetworkRule", Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1, DestinationIp="8.8.8.8",
        DestinationPort=443, Action="Allow", Policy="fwp-a", RuleCollectionGroup="rcg-net",
        RuleCollection="rc-logged", Rule="allow-it",
    ))


def _cross_pass_unknown_snapshot() -> CachedSnapshot:
    """A DNAT-kind collection with an unreadable IP group (no logged rule in
    that pass) alongside a Network group holding the logged rule."""
    fw = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_tier="Premium")
    dnat_group = RuleCollectionGroup(id="/p/dnat", name="rcg-dnat", priority=10, rule_collections=[
        RuleCollection(name="rc-dnat", priority=10, action="Dnat", rule_collection_type="Nat", rules=[
            Rule(name="dnat-unreadable", rule_type="NatRule", source_ip_groups=[MISSING_GROUP],
                 destination_addresses=["*"], destination_ports=["*"], protocols=["TCP"]),
        ]),
    ])
    net_group = RuleCollectionGroup(id="/p/net", name="rcg-net", priority=20, rule_collections=[
        RuleCollection(name="rc-logged", priority=10, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="allow-it", rule_type="NetworkRule", source_addresses=["*"],
                 destination_addresses=["*"], destination_ports=["*"], protocols=["TCP"]),
        ]),
    ])
    policy = FirewallPolicyInfo(id="/p", name="fwp-b", sku_tier="Premium", threat_intel_mode="Off",
                                rule_collection_groups=[dnat_group, net_group])
    return CachedSnapshot(firewall=fw, policy=policy, ip_groups={}, fetched_at=time.time())


def _header_snapshot() -> CachedSnapshot:
    fw = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_tier="Premium")
    rule = Rule(name="insert-headers", rule_type="ApplicationRule", source_addresses=["*"],
                destination_fqdns=["*.example.com"], destination_ports=["443"], protocols=["Https"],
                http_headers=[HttpHeader(name="X-Tenant-Id", value=HEADER_VALUE)])
    group = RuleCollectionGroup(id="/p/app", name="rcg-app", priority=100, rule_collections=[
        RuleCollection(name="rc-app", priority=100, action="Allow", rule_collection_type="Filter", rules=[rule]),
    ])
    policy = FirewallPolicyInfo(id="/p", name="fwp-c", sku_tier="Premium", threat_intel_mode="Off",
                                rule_collection_groups=[group])
    return CachedSnapshot(firewall=fw, policy=policy, ip_groups={}, fetched_at=time.time())


# ── the logged rule, and what the tree no longer says ─────────────────────────

async def test_logged_rule_is_cursor_node_and_carries_logged(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None
        assert "allow-web" in tree.cursor_node.label.plain and "LOGGED" in tree.cursor_node.label.plain
        assert tree.cursor_node.data["kind"] == "rule" and tree.cursor_node.data["rule"].logged


async def test_no_tree_label_carries_nearest_miss_or_rule_counts(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        joined = "\n".join(_tree_labels(screen.query_one("#trace-tree", Tree)))
        assert "nearest miss" not in joined
        assert "rules ·" not in joined and "rule ·" not in joined


# ── focused view: preceding / not-evaluated folding ───────────────────────────

async def test_preceding_collections_fold_and_flag_the_unknown_one(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _focused_group_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _open_focused_group_row(structured_record))
        tree = screen.query_one("#trace-tree", Tree)
        fold = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("▸ 3 preceding collections"))
        assert "1 with ?" in fold.label.plain
        assert not fold.is_expanded  # collapsed by default, but still expandable
        assert fold.allow_expand and len(fold.children) == 3
        unknown_child = next(c for c in fold.children if c.label.plain.startswith("?"))
        assert unknown_child.label.plain.startswith("? [20] rc-unreadable")


async def test_not_evaluated_collections_fold_after_the_logged_one(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _focused_group_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _open_focused_group_row(structured_record))
        tree = screen.query_one("#trace-tree", Tree)
        fold = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("▸ 1 not evaluated"))
        assert len(fold.children) == 1
        skipped = fold.children[0]
        assert skipped.label.plain.startswith("– [50] rc-after")
        assert "miss" not in skipped.label.plain.lower()  # never shown as a miss
        # its selection detail says so too — expand the fold first, or the
        # child has no visible line yet for move_cursor to land on
        fold.expand()
        await pilot.pause()
        tree.move_cursor(skipped)
        await pilot.pause()
        detail = str(screen.query_one("#trace-detail", Static).content)
        assert "not evaluated" in detail


async def test_unknown_collection_outside_the_logged_pass_stays_visible(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _cross_pass_unknown_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWNetworkRule", Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1, DestinationIp="8.8.8.8",
            DestinationPort=443, Action="Allow", Policy="fwp-b", RuleCollectionGroup="rcg-net",
            RuleCollection="rc-logged", Rule="allow-it",
        ))
        screen = await _open_trace(app, pilot, row)
        joined = "\n".join(_tree_labels(screen.query_one("#trace-tree", Tree)))
        assert "? [10] rc-dnat" in joined  # visible directly, not folded away
        assert "preceding collections" not in joined  # folding only applies to the logged rule's own group


# ── expand all / focused toggle ───────────────────────────────────────────────

async def test_a_expands_everything_then_returns_to_focused(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _focused_group_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _open_focused_group_row(structured_record))
        tree = screen.query_one("#trace-tree", Tree)
        fold = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("▸ 3 preceding collections"))
        assert not fold.is_expanded
        await pilot.press("a")
        await pilot.pause()
        tree = screen.query_one("#trace-tree", Tree)
        fold = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("▸ 3 preceding collections"))
        assert fold.is_expanded and all(c.is_expanded for c in fold.children if c.allow_expand)
        await pilot.press("a")
        await pilot.pause()
        tree = screen.query_one("#trace-tree", Tree)
        fold = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("▸ 3 preceding collections"))
        assert not fold.is_expanded  # back to focused


# ── keys: Enter only toggles, never dismisses or navigates ───────────────────

async def test_enter_toggles_a_node_and_never_dismisses_the_dialog(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        tree = screen.query_one("#trace-tree", Tree)
        pass_node = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("Network rules"))
        assert pass_node.is_expanded  # the pass holding the logged rule opens by default
        tree.move_cursor(pass_node)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert not pass_node.is_expanded  # Enter collapsed it
        assert app.screen is screen  # ...and nothing else

        # Enter on the logged rule leaf (the default cursor position) is a no-op too.
        logged = next(n for n in _tree_nodes(tree) if "LOGGED" in n.label.plain)
        tree.move_cursor(logged)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is screen


async def test_open_selected_rule_posts_rule_chosen_and_dismisses_to_policy_tab(structured_record, mgmt, firewall_id):
    """``p`` (wired in detail_screen.py, the parallel work package) calls this
    method; tested here directly since that key binding lives outside
    trace_screen.py."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        tree = screen.query_one("#trace-tree", Tree)
        assert "allow-web" in tree.cursor_node.label.plain
        screen.query_one(TracePanel).open_selected_rule()
        await wait_until(pilot, lambda: not isinstance(app.screen, DetailDialog))
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-policy"
        policy_tree = app.query_one("#policy-tree", Tree)
        assert policy_tree.cursor_node is not None and policy_tree.cursor_node.label.plain == "allow-web"


# ── selection detail ──────────────────────────────────────────────────────────

async def test_detail_shows_every_check_verbatim_and_header_names_never_values(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _header_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.3.5.4", SourcePort=1, DestinationPort=443,
            Fqdn="www.example.com", Action="Allow", Policy="fwp-c", RuleCollectionGroup="rcg-app",
            RuleCollection="rc-app", Rule="insert-headers",
        ))
        screen = await _open_trace(app, pilot, row)
        detail = str(screen.query_one("#trace-detail", Static).content)
        # every Check.detail, verbatim
        assert "*" in detail
        assert "www.example.com" in detail
        assert "443" in detail
        assert "HTTPS" in detail
        # header name, never the value
        assert "X-Tenant-Id" in detail and "inserts 1 HTTP header" in detail
        assert HEADER_VALUE not in detail
        assert "logged by the firewall" in detail


async def test_no_trace_title_and_legend_has_no_key_hints(structured_record, mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))
        assert not screen.query("#trace-title")
        legend = str(screen.query_one("#trace-legend", Static).content)
        assert "match" in legend and "miss" in legend and "cannot evaluate" in legend and "not in log" in legend
        assert "Enter" not in legend and "Policy tab" not in legend and "Space" not in legend


# ── no logged rule: ★ candidates and Threat Intelligence ──────────────────────

async def test_no_logged_rule_still_marks_and_expands_star_candidates(structured_record, mgmt, firewall_id):
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
        assert "★ nearest" in joined
        star_collection = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("✗ [100] rc-web"))
        assert star_collection.is_expanded


async def test_threat_intel_row_still_renders_its_two_lines(structured_record, mgmt, firewall_id):
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
