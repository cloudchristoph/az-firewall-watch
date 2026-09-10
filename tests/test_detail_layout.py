"""Small terminals: side by side, tabs, or the tree given more room back.

Package 6 of docs/detail-dialog-plan.md. Runs the real app at the three sizes
the plan measured — 160x45 (fine today), 120x30 (the tree used to be squeezed
to a few rows) and 80x24 (used to be unusable) — with and without a trace,
reusing the app fixtures already established in test_views.py and the dialog
helper from test_dialogs.py rather than duplicating them.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Static, TabbedContent, TabPane, Tree

from fw_parser import parse_record
from tests.test_dialogs import _open_detail
from tests.test_views import (
    _load,
    _net,
    _open_trace,
    _tree_nodes,
    make_snapshot,
    mgmt,  # noqa: F401  (fixture; pytest needs it bound as "mgmt")
    no_update_check,  # noqa: F401  (fixture; pytest needs it bound as "no_update_check")
    wait_until,
)
from viewer.app import FirewallLogApp
from viewer.azure_resources import IpGroupInfo
from viewer.views.detail_screen import DetailDialog
from viewer.views.trace_screen import TracePanel

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")

SIZES = [(160, 45), (120, 30), (80, 24)]


def _no_trace_row(structured_record, **extra):
    """A row with no rule fields at all — no trace, in any mode or size."""
    props = dict(Protocol="TCP", SourceIp="10.0.1.4", SourcePort=51000,
                 DestinationIp="10.0.2.5", DestinationPort=443, Action="Deny")
    props.update(extra)
    return parse_record(structured_record("AZFWNetworkRule", **props))


def _many_ip_groups_snapshot():
    """``make_snapshot()`` plus 20 IP groups that all contain 10.3.5.4 — enough
    lines under "Src IP groups" to overflow the fields pane on any terminal."""
    snap = make_snapshot()
    extra = {}
    for i in range(20):
        gid = f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipgroup-extra-{i}"
        extra[gid] = IpGroupInfo(id=gid, name=f"ipgroup-extra-{i}", location="germanywestcentral",
                                 ip_addresses=["10.3.5.0/24"])
    snap.ip_groups.update(extra)
    return snap


async def _open_matched_trace(app: FirewallLogApp, pilot, structured_record) -> DetailDialog:
    """Opens the dialog on a row that matches allow-web in ``make_snapshot``'s
    policy, so there is always a logged rule for the tree to select."""
    return await _open_trace(app, pilot, _net(structured_record, "10.3.5.4", "1.1.1.1"))


def _tree_visible_range(tree: Tree) -> tuple[float, float]:
    top = tree.scroll_y
    return top, top + tree.scrollable_content_region.height


def _logged_node_visible(tree: Tree) -> bool:
    node = tree.cursor_node
    if node is None:
        return False
    top, bottom = _tree_visible_range(tree)
    return top <= node.line < bottom


# ── layout mode per size ───────────────────────────────────────────────────────

@pytest.mark.parametrize("size,expect_tabbed", [((160, 45), False), ((120, 30), False), ((80, 24), True)])
async def test_layout_mode_matches_terminal_size_with_trace(structured_record, mgmt, firewall_id, size, expect_tabbed):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        assert screen.has_class("-tabbed") is expect_tabbed
        assert bool(screen.query(TabbedContent)) is expect_tabbed


@pytest.mark.parametrize("size", SIZES)
async def test_without_trace_never_shows_tabs_at_any_size(structured_record, size):
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        dialog = await _open_detail(app, pilot, _no_trace_row(structured_record))
        assert not dialog.has_trace
        assert not dialog.has_class("-tabbed")
        assert not dialog.query(TabbedContent)
        pane = dialog.query_one("#detail-pane")
        assert pane.region.width > 0 and pane.region.height > 0


@pytest.mark.parametrize("size", [(160, 45), (120, 30)])
async def test_fields_and_trace_sit_side_by_side_at_160_and_120(structured_record, mgmt, firewall_id, size):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        assert not screen.has_class("-tabbed")
        pane = screen.query_one("#detail-pane")
        tree = screen.query_one("#trace-tree", Tree)
        assert pane.region.width > 0 and tree.region.width > 0  # both visible at once
        assert pane.region.x < tree.region.x                    # fields left of the trace


async def test_narrow_with_trace_uses_two_tabs_trace_active_first(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        assert screen.has_class("-tabbed")
        tabs = screen.query_one(TabbedContent)
        assert len(screen.query(TabPane)) == 2
        assert tabs.active == "tab-trace"          # the logged rule is what you see first
        tree = screen.query_one("#trace-tree", Tree)
        fields = screen.query_one("#detail-pane")
        assert tree.region.width > 0
        assert fields.region.width == 0            # the Fields tab is not the one showing

        await pilot.press("tab")
        await pilot.pause(0.2)
        assert tabs.active == "tab-fields"
        assert fields.region.width > 0
        assert tree.region.width == 0

        await pilot.press("shift+tab")
        await pilot.pause(0.2)
        assert tabs.active == "tab-trace"


# ── the logged rule stays reachable ────────────────────────────────────────────

@pytest.mark.parametrize("size", SIZES)
async def test_logged_rule_is_cursor_and_visible_at_every_size(structured_record, mgmt, firewall_id, size):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None
        assert "allow-web" in tree.cursor_node.label.plain and "LOGGED" in tree.cursor_node.label.plain
        # DetailDialog._reveal_logged_rule corrects the scroll position one
        # refresh after mount (see its docstring) — poll rather than assume
        # a fixed pause always lands after that refresh has happened.
        await wait_until(pilot, lambda: _logged_node_visible(tree))


async def test_medium_terminal_gives_the_tree_at_least_eight_rows(structured_record, mgmt, firewall_id):  # noqa: F811
    """120x30: the fix is -short shrinking the selection detail, not tabs —
    the tree gets the room back rather than the 5 rows the old CSS left it."""
    app = FirewallLogApp()
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        assert screen.has_class("-short")
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.scrollable_content_region.height >= 8


# ── every pane scrolls on its own ──────────────────────────────────────────────

async def test_fields_pane_scrolls_at_80x24_with_many_ip_groups(structured_record, mgmt, firewall_id):  # noqa: F811
    mgmt["snapshot"] = _many_ip_groups_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        await pilot.press("tab")                  # switch to the Fields tab
        await pilot.pause(0.2)
        pane = screen.query_one("#detail-pane")
        assert pane.max_scroll_y > 0
        pane.scroll_end(animate=False)
        await pilot.pause(0.2)
        assert pane.scroll_y == pane.max_scroll_y
        text = "\n".join(str(s.content) for s in pane.query(Static))
        assert "ipgroup-extra-19" in text          # the last field, reached by scrolling


# ── keys still work in the trace tab at 80x24 ──────────────────────────────────

async def test_enter_and_a_still_work_in_the_trace_tab_at_80x24(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        tree = screen.query_one("#trace-tree", Tree)
        pass_node = next(n for n in _tree_nodes(tree) if n.label.plain.startswith("Network rules"))
        assert pass_node.is_expanded
        tree.move_cursor(pass_node)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert not pass_node.is_expanded           # Enter toggled it, nothing else
        assert app.screen is screen

        panel = screen.query_one(TracePanel)
        assert panel._expand_all is False
        await pilot.press("a")
        await pilot.pause()
        assert panel._expand_all is True


async def test_p_opens_policy_tab_from_the_trace_tab_at_80x24(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        assert "allow-web" in screen.query_one("#trace-tree", Tree).cursor_node.label.plain
        await pilot.press("p")
        await wait_until(pilot, lambda: not isinstance(app.screen, DetailDialog))
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-policy"
        policy_tree = app.query_one("#policy-tree", Tree)
        assert policy_tree.cursor_node is not None and policy_tree.cursor_node.label.plain == "allow-web"


@pytest.mark.parametrize("key", ["escape", "q"])
async def test_esc_and_q_close_from_the_trace_tab_at_80x24(structured_record, mgmt, firewall_id, key):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        await _open_matched_trace(app, pilot, structured_record)
        await pilot.press(key)
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailDialog)
        assert app.is_running


# ── footer and header text ─────────────────────────────────────────────────────

@pytest.mark.parametrize("size,expect_hint", [((160, 45), False), ((120, 30), False), ((80, 24), True)])
async def test_footer_tab_hint_only_in_tabbed_mode(structured_record, mgmt, firewall_id, size, expect_hint):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        footer = str(screen.query_one("#dialog-footer", Static).content)
        assert ("Tab fields/trace" in footer) is expect_hint


_LONG_GROUP = "cclab-network-rule-collection-group-germanywestcentral"
_LONG_COLLECTION = "outbound-access-demo-network-rules"


def _long_names_snapshot():
    """``make_snapshot()`` with the logged rule's group and collection renamed
    to something a real policy would carry, long enough that the outcome line
    cannot fit a narrow dialog in full."""
    snap = make_snapshot()
    group = snap.policy.rule_collection_groups[0]
    group.name = _LONG_GROUP
    group.rule_collections[1].name = _LONG_COLLECTION     # rc-web, the one allow-web sits in
    return snap


def _net_in_long_names(structured_record):
    return parse_record(structured_record(
        "AZFWNetworkRule", Protocol="TCP", SourceIp="10.3.5.4", SourcePort=1, DestinationIp="1.1.1.1",
        DestinationPort=443, Action="Allow", Policy="fwp-hub-premium-gwc",
        RuleCollectionGroup=_LONG_GROUP, RuleCollection=_LONG_COLLECTION, Rule="allow-web",
    ))


def test_header_line2_shortens_until_it_fits(structured_record):
    """Full outcome first; then the group and collection go; then the cache
    age. Never the rule name, never the icon."""
    from viewer.trace import build_trace
    from viewer.views.detail_screen import _header_line2

    snap = _long_names_snapshot()
    row = _net_in_long_names(structured_record)
    trace = build_trace(FirewallLogApp._flow_from_row(row), snap.policy, snap.ip_groups,
                        FirewallLogApp._logged_from_row(row))
    full = _header_line2(trace, "fresh")
    assert _LONG_GROUP in full and "cached policy · fresh" in full
    assert _header_line2(trace, "fresh", width=200) == full
    medium = _header_line2(trace, "fresh", width=60)
    assert "»" not in medium and "Allow · allow-web" in medium and "cached policy · fresh" in medium
    tight = _header_line2(trace, "fresh", width=30)
    assert tight == "[green]✓[/] Allow · allow-web"
    assert _header_line2(trace, "fresh", width=5) == tight   # never shorter than that


async def test_header_stays_two_lines_on_a_narrow_terminal(structured_record, mgmt, firewall_id):  # noqa: F811
    """80x24 with long policy names: the outcome line is shortened rather
    than wrapped, so the header costs the tree no third row."""
    mgmt["snapshot"] = _long_names_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _net_in_long_names(structured_record))
        header = screen.query_one("#dialog-header", Static)
        lines = str(header.content).split("\n")
        assert len(lines) == 2 and header.region.height == 2
        assert "allow-web" in lines[1] and "»" not in lines[1]


async def test_header_line2_stays_full_at_160x45(structured_record, mgmt, firewall_id):  # noqa: F811
    """The compact form only kicks in on a narrow, short terminal — the wide
    dialog keeps the group and collection the way 0.6.0 rendered them."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        header = str(screen.query_one("#dialog-header", Static).content)
        assert "rcg-net » rc-web » allow-web" in header


# ── screenshots: a cheap guard that rendering does not raise ──────────────────

@pytest.mark.parametrize("size", SIZES)
async def test_screenshot_renders_with_trace(structured_record, mgmt, firewall_id, size, tmp_path):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        await _open_matched_trace(app, pilot, structured_record)
        path = app.save_screenshot(filename=f"trace-{size[0]}x{size[1]}.svg", path=str(tmp_path))
        assert Path(path).exists()


@pytest.mark.parametrize("size", SIZES)
async def test_screenshot_renders_without_trace(structured_record, size, tmp_path):
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _open_detail(app, pilot, _no_trace_row(structured_record))
        path = app.save_screenshot(filename=f"fields-{size[0]}x{size[1]}.svg", path=str(tmp_path))
        assert Path(path).exists()


# ── what the screenshots showed and the fixtures above did not ─────────────────

def _wide_policy_snapshot():
    """``make_snapshot()`` plus an application group with eight collections,
    the logged rule in the last: more tree lines than a 120x30 or 80x24 tree
    has rows, so the logged rule is only reachable by scrolling."""
    from viewer.azure_resources import Rule, RuleCollection, RuleCollectionGroup

    snap = make_snapshot()
    apps = [RuleCollection(name=f"demo-{i}", priority=100 + i * 10, action="Allow", rule_collection_type="Filter",
                           rules=[Rule(name=f"allow-{i}", rule_type="ApplicationRule", source_addresses=["*"],
                                       destination_fqdns=[f"*.site{i}.example"], protocols=["Https"],
                                       destination_ports=["443"])])
            for i in range(6)]
    apps.append(RuleCollection(name="tags", priority=195, action="Allow", rule_collection_type="Filter", rules=[
        Rule(name="allow-wu", rule_type="ApplicationRule", source_addresses=["*"], fqdn_tags=["WindowsUpdate"],
             protocols=["Https"], destination_ports=["443"])]))
    apps.append(RuleCollection(name="outbound-access-demo-app-rules", priority=200, action="Allow",
                               rule_collection_type="Filter", rules=[
        Rule(name="allow-outbound-web-traffic", rule_type="ApplicationRule", source_addresses=["*"],
             destination_fqdns=["*"], protocols=["Http", "Https"], destination_ports=["80", "443"])]))
    snap.policy.rule_collection_groups.append(RuleCollectionGroup(
        id="/p/app", name="cclab-application-rule-collection-group", priority=100, rule_collections=apps))
    return snap


def _app_row(structured_record):
    return parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.3.11.4", SourcePort=41644, DestinationPort=443,
        Fqdn="www.petmd.com", Action="Allow", Policy="fwp-hub-premium-gwc",
        RuleCollectionGroup="cclab-application-rule-collection-group",
        RuleCollection="outbound-access-demo-app-rules", Rule="allow-outbound-web-traffic",
    ))


@pytest.mark.parametrize("size", [(120, 30), (80, 24)])
async def test_logged_rule_beyond_the_first_screen_is_scrolled_into_view(structured_record, mgmt, firewall_id, size):  # noqa: F811
    """The tree's one scroll after building runs against a height that is
    still settling; the tree re-scrolls on its own resizes, so the last
    layout pass is the one that counts."""
    mgmt["snapshot"] = _wide_policy_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_trace(app, pilot, _app_row(structured_record))
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None and "LOGGED" in tree.cursor_node.label.plain
        assert tree.cursor_node.line >= tree.scrollable_content_region.height   # not on the first screen
        await wait_until(pilot, lambda: _logged_node_visible(tree))
        assert not tree.show_horizontal_scrollbar                              # no row lost to a bar


async def test_footer_fits_one_row_at_80_columns(structured_record, mgmt, firewall_id):  # noqa: F811
    app = FirewallLogApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        footer = screen.query_one("#dialog-footer", Static)
        assert footer.region.height == 1
        assert "Tab fields/trace" in str(footer.content) and "Esc close" in str(footer.content)


async def test_resize_switches_between_columns_and_tabs(structured_record, mgmt, firewall_id):  # noqa: F811
    """Shrinking a wide terminal below 120 columns rebuilds the dialog with
    tabs, growing it back returns the columns; the logged rule is selected
    and visible after each."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_matched_trace(app, pilot, structured_record)
        assert not screen.query(TabbedContent) and "Tab fields/trace" not in str(screen.query_one("#dialog-footer", Static).content)

        await pilot.resize_terminal(80, 24)
        await wait_until(pilot, lambda: bool(screen.query(TabbedContent)))
        await pilot.pause(0.3)
        assert screen.has_class("-tabbed") and screen.has_class("-tiny")
        assert screen.query_one(TabbedContent).active == "tab-trace"
        assert "Tab fields/trace" in str(screen.query_one("#dialog-footer", Static).content)
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None and "LOGGED" in tree.cursor_node.label.plain
        await wait_until(pilot, lambda: _logged_node_visible(screen.query_one("#trace-tree", Tree)))

        await pilot.resize_terminal(160, 45)
        await wait_until(pilot, lambda: not screen.query(TabbedContent))
        await pilot.pause(0.3)
        assert not screen.has_class("-tabbed") and not screen.has_class("-tiny")
        assert screen.query_one("#detail-pane").region.width > 0 and screen.query_one(TracePanel).region.width > 0
        tree = screen.query_one("#trace-tree", Tree)
        assert tree.cursor_node is not None and "LOGGED" in tree.cursor_node.label.plain
        await wait_until(pilot, lambda: _logged_node_visible(tree))
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailDialog)
