"""HTTP header insertion on application rules (0.6.0 point: viewer/views/policy.py,
the header leaf in the trace tree in viewer/views/trace_screen.py).

Covers: ARM parsing (present / absent / non-dict entries skipped), the on-disk
cache round trip, the header leaf under a rule node in the trace tree,
and the Policy tab's reveal-on-request UI (hidden by default, "v" toggles,
a re-render hides again, the tree label never carries names or values, and
the three SKU/TLS scope lines).
"""
from __future__ import annotations

import time

import pytest
from textual.widgets import Static, TabbedContent, Tree

import viewer.app as app_module
import viewer.cache as cache
from viewer.app import FirewallLogApp
from viewer.azure_resources import (
    FirewallInfo,
    FirewallPolicyInfo,
    HttpHeader,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
    _parse_rule,
)
from viewer.views import PolicyView

from .test_views import _load, make_snapshot, no_update_check, wait_until  # noqa: F401

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")

TENANT_ID_VALUE = "11111111-2222-3333-4444-555555555555"
MARKUP_VALUE = "[b]x[/]"
RULE_REF = "fwp-hub-premium-gwc|rcg-app|rc-app|insert-headers"


# ── ARM parsing ─────────────────────────────────────────────────────────────

def test_parse_rule_headers_present_and_terminate_tls_true():
    raw = {
        "name": "insert-headers",
        "ruleType": "ApplicationRule",
        "protocols": [{"protocolType": "Https", "port": 443}],
        "targetFqdns": ["*.example.com"],
        "httpHeadersToInsert": [
            {"headerName": "X-Tenant-Id", "headerValue": TENANT_ID_VALUE},
            {"headerName": "X-Forwarded-Tenant", "headerValue": "acme"},
        ],
        "terminateTLS": True,
    }
    rule = _parse_rule(raw)
    assert rule.http_headers == [
        HttpHeader(name="X-Tenant-Id", value=TENANT_ID_VALUE),
        HttpHeader(name="X-Forwarded-Tenant", value="acme"),
    ]
    assert rule.terminate_tls is True


def test_parse_rule_headers_and_terminate_tls_absent():
    raw = {"name": "plain", "ruleType": "ApplicationRule", "protocols": [{"protocolType": "Http", "port": 80}]}
    rule = _parse_rule(raw)
    assert rule.http_headers == []
    assert rule.terminate_tls is False


def test_parse_rule_skips_non_dict_header_entries():
    raw = {
        "name": "mixed",
        "ruleType": "ApplicationRule",
        "httpHeadersToInsert": [
            {"headerName": "X-Ok", "headerValue": "v"},
            "not-a-dict",
            42,
            None,
        ],
    }
    rule = _parse_rule(raw)
    assert rule.http_headers == [HttpHeader(name="X-Ok", value="v")]


# ── cache round trip ─────────────────────────────────────────────────────────

CACHE_FW_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"


@pytest.fixture
def cache_file(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    monkeypatch.setattr(cache, "cache_path", lambda: path)
    return path


def test_cache_round_trip_keeps_http_headers_as_httpheader_objects(cache_file):
    fw = FirewallInfo(id=CACHE_FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_tier="Premium")
    rule = Rule(name="insert-headers", rule_type="ApplicationRule", protocols=["Https"],
                http_headers=[HttpHeader(name="X-Tenant-Id", value=TENANT_ID_VALUE)], terminate_tls=True)
    policy = FirewallPolicyInfo(id="/p", name="pol", sku_tier="Premium", rule_collection_groups=[
        RuleCollectionGroup(id="/g", name="rcg", priority=100, rule_collections=[
            RuleCollection(name="rc", priority=200, action="Allow", rule_collection_type="Filter", rules=[rule]),
        ]),
    ])
    snap = cache.CachedSnapshot(firewall=fw, policy=policy, fetched_at=time.time())
    cache.save(CACHE_FW_ID, snap)

    loaded = cache.load(CACHE_FW_ID)
    assert loaded is not None
    loaded_rule = loaded.policy.rule_collection_groups[0].rule_collections[0].rules[0]
    assert loaded_rule.http_headers == [HttpHeader(name="X-Tenant-Id", value=TENANT_ID_VALUE)]
    assert all(isinstance(h, HttpHeader) for h in loaded_rule.http_headers)
    assert loaded_rule.terminate_tls is True


# ── Policy tab UI ─────────────────────────────────────────────────────────────

def _apprule_snapshot(*, sku_tier: str = "Premium", terminate_tls: bool = False,
                      protocols: tuple[str, ...] = ("Https",)) -> cache.CachedSnapshot:
    """The shared 0.6.0 test snapshot plus one application rule that inserts
    two HTTP headers — one with a plausible tenant-id value, one whose value
    contains Rich markup characters to prove reveal escapes it."""
    snap = make_snapshot()
    headers = [
        HttpHeader(name="X-Tenant-Id", value=TENANT_ID_VALUE),
        HttpHeader(name="X-Forwarded-Tenant", value=MARKUP_VALUE),
    ]
    rule = Rule(name="insert-headers", rule_type="ApplicationRule", source_addresses=["*"],
                destination_fqdns=["*.example.com"], destination_ports=["443"],
                protocols=list(protocols), http_headers=headers, terminate_tls=terminate_tls)
    rc = RuleCollection(name="rc-app", priority=100, action="Allow", rule_collection_type="Filter", rules=[rule])
    rcg = RuleCollectionGroup(id="/p/app", name="rcg-app", priority=1000, rule_collections=[rc])
    snap.policy.sku_tier = sku_tier
    snap.policy.rule_collection_groups.append(rcg)
    return snap


def _install_snapshot(monkeypatch, snapshot: cache.CachedSnapshot) -> dict:
    state = {"snapshot": snapshot, "calls": []}

    async def _load_fn(firewall_id, *, force=False):
        state["calls"].append((firewall_id, force))
        return state["snapshot"]

    monkeypatch.setattr(app_module, "load_management_data", _load_fn)
    return state


@pytest.fixture
def apprule_mgmt(monkeypatch):
    return _install_snapshot(monkeypatch, _apprule_snapshot())


async def _open_policy_tab_on_rule(app: FirewallLogApp, pilot, firewall_id: str) -> PolicyView:
    await _load(app, pilot, firewall_id)
    app.query_one("#main-tabs", TabbedContent).active = "tab-policy"
    await pilot.pause()
    view = app.query_one("#policy-view", PolicyView)
    assert view.focus_rule(RULE_REF)
    await wait_until(pilot, lambda: "Rule: insert-headers" in str(app.query_one("#policy-details", Static).content))
    return view


async def test_header_names_shown_values_hidden_by_default(structured_record, apprule_mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _open_policy_tab_on_rule(app, pilot, firewall_id)
        details = str(app.query_one("#policy-details", Static).content)
        assert "X-Tenant-Id" in details and "X-Forwarded-Tenant" in details
        assert "2 inserted" in details
        assert "press v to show values" in details
        assert "••••••" in details
        assert TENANT_ID_VALUE not in details
        assert MARKUP_VALUE not in details


async def test_pressing_v_reveals_then_hides_values(structured_record, apprule_mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _open_policy_tab_on_rule(app, pilot, firewall_id)
        app.query_one("#policy-tree", Tree).focus()
        await pilot.pause()

        await pilot.press("v")
        await pilot.pause()
        details = str(app.query_one("#policy-details", Static).content)
        assert TENANT_ID_VALUE in details
        assert "••••••" not in details
        assert "values shown, press v to hide" in details

        await pilot.press("v")
        await pilot.pause()
        details = str(app.query_one("#policy-details", Static).content)
        assert TENANT_ID_VALUE not in details
        assert "••••••" in details
        assert "press v to show values" in details


async def test_v_on_a_node_without_headers_arms_nothing(structured_record, apprule_mgmt, firewall_id):
    """A stray v on a group must not reveal values on the next rule selected."""
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        view = await _open_policy_tab_on_rule(app, pilot, firewall_id)
        tree = app.query_one("#policy-tree", Tree)
        tree.focus()
        await pilot.pause()
        group_node = tree.root.children[0]
        tree.move_cursor(group_node)
        tree.select_node(group_node)
        await pilot.pause()
        await pilot.press("v")
        await pilot.pause()
        assert view._reveal_header_values is False

        assert view.focus_rule(RULE_REF)
        await wait_until(pilot, lambda: "Rule: insert-headers" in str(app.query_one("#policy-details", Static).content))
        details = str(app.query_one("#policy-details", Static).content)
        assert TENANT_ID_VALUE not in details and "••••••" in details


async def test_selecting_another_node_hides_revealed_values(structured_record, apprule_mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        view = await _open_policy_tab_on_rule(app, pilot, firewall_id)
        tree = app.query_one("#policy-tree", Tree)
        tree.focus()
        await pilot.pause()
        await pilot.press("v")
        await pilot.pause()
        assert view._reveal_header_values is True

        group_node = tree.root.children[0]
        tree.move_cursor(group_node)
        tree.select_node(group_node)
        await pilot.pause()
        assert view._reveal_header_values is False

        assert view.focus_rule(RULE_REF)
        await wait_until(pilot, lambda: "Rule: insert-headers" in str(app.query_one("#policy-details", Static).content))
        assert TENANT_ID_VALUE not in str(app.query_one("#policy-details", Static).content)


async def test_rerender_hides_previously_revealed_values(structured_record, apprule_mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        view = await _open_policy_tab_on_rule(app, pilot, firewall_id)
        app.query_one("#policy-tree", Tree).focus()
        await pilot.pause()
        await pilot.press("v")
        await pilot.pause()
        assert TENANT_ID_VALUE in str(app.query_one("#policy-details", Static).content)

        snap = apprule_mgmt["snapshot"]
        view.render_data(snap.policy, snap.ip_groups)
        await pilot.pause()
        assert view.focus_rule(RULE_REF)
        await wait_until(pilot, lambda: "Rule: insert-headers" in str(app.query_one("#policy-details", Static).content))
        details = str(app.query_one("#policy-details", Static).content)
        assert TENANT_ID_VALUE not in details
        assert "••••••" in details


async def test_rule_tree_label_never_carries_header_names_or_values(structured_record, apprule_mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        view = await _open_policy_tab_on_rule(app, pilot, firewall_id)
        label = view._rule_ref_to_node[RULE_REF].label.plain
        assert label == "insert-headers"
        assert "X-Tenant-Id" not in label and "X-Forwarded-Tenant" not in label
        assert TENANT_ID_VALUE not in label and MARKUP_VALUE not in label


async def test_trace_tree_names_inserted_headers_under_the_logged_rule_never_values(structured_record, apprule_mgmt,
                                                                                    firewall_id):
    """The header leaf moved out of the tree in the trace_screen redesign
    (docs/detail-dialog-plan.md, package 4): names now live in the selection
    detail under the tree, never in the tree label — and values never
    anywhere in the panel."""
    from textual.widgets import Static as StaticWidget
    from textual.widgets import Tree as TreeWidget

    from fw_parser import parse_record

    from .test_views import _open_trace

    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        row = parse_record(structured_record(
            "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.3.5.4", SourcePort=1, DestinationPort=443,
            Fqdn="www.example.com", Action="Allow", Policy="fwp-hub-premium-gwc",
            RuleCollectionGroup="rcg-app", RuleCollection="rc-app", Rule="insert-headers",
        ))
        screen = await _open_trace(app, pilot, row)
        tree = screen.query_one("#trace-tree", TreeWidget)
        labels = []

        def walk(node):
            labels.append(node.label.plain)
            for child in node.children:
                walk(child)

        walk(tree.root)
        assert not any("HTTP header" in lbl for lbl in labels)  # names/values live in the detail now
        assert not any(TENANT_ID_VALUE in lbl or "x[/]" in lbl for lbl in labels)
        # the logged rule is the cursor node after open; its detail carries the header names
        detail = str(screen.query_one("#trace-detail-text", StaticWidget).content)
        assert "inserts 2 HTTP headers: X-Tenant-Id, X-Forwarded-Tenant" in detail
        assert TENANT_ID_VALUE not in detail and "x[/]" not in detail


async def test_revealed_value_with_markup_characters_is_escaped(structured_record, apprule_mgmt, firewall_id):
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _open_policy_tab_on_rule(app, pilot, firewall_id)
        app.query_one("#policy-tree", Tree).focus()
        await pilot.pause()
        await pilot.press("v")
        await pilot.pause()
        details = str(app.query_one("#policy-details", Static).content)
        # rich.markup.escape() prefixes every "[" with a backslash; the literal,
        # un-escaped "[b]x[/]" must not appear (it would be interpreted as bold).
        assert "\\[b]x\\[/]" in details
        assert "[b]x[/]" not in details


@pytest.mark.parametrize("sku_tier, terminate_tls, protocols, expected", [
    # a rule that matches HTTP and HTTPS: the headers land in HTTP at least
    ("Standard", False, ("Http", "Https"), "HTTPS on Standard/Basic: headers are inserted into HTTP only"),
    ("Premium", False, ("Http", "Https"), "HTTPS without TLS inspection on this rule: headers are inserted into HTTP only"),
    ("Premium", True, ("Http", "Https"), "inserted into HTTP and TLS-inspected HTTPS"),
    # an HTTPS-only rule matches no HTTP, so "HTTP only" would name traffic it never sees
    ("Standard", False, ("Https",), "HTTPS on Standard/Basic: no traffic this rule matches gets the headers"),
    ("Premium", False, ("Https",), "HTTPS without TLS inspection on this rule: no traffic this rule matches gets the headers"),
    ("Premium", True, ("Https",), "inserted into TLS-inspected HTTPS"),
    ("", False, ("Https",), "policy SKU unknown: whether HTTPS gets the headers cannot be told from here"),
])
async def test_sku_and_tls_scope_line(structured_record, monkeypatch, firewall_id, sku_tier, terminate_tls, protocols,
                                      expected):
    _install_snapshot(monkeypatch, _apprule_snapshot(sku_tier=sku_tier, terminate_tls=terminate_tls, protocols=protocols))
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _open_policy_tab_on_rule(app, pilot, firewall_id)
        details = str(app.query_one("#policy-details", Static).content)
        assert expected in details
        if "HTTP only" not in expected and "into HTTP and" not in expected:
            assert "into HTTP" not in details


async def test_terminate_tls_true_shows_tls_inspection_on_line(structured_record, monkeypatch, firewall_id):
    _install_snapshot(monkeypatch, _apprule_snapshot(sku_tier="Premium", terminate_tls=True))
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _open_policy_tab_on_rule(app, pilot, firewall_id)
        details = str(app.query_one("#policy-details", Static).content)
        assert "TLS inspection" in details and " on" in details


async def test_http_only_rule_inserts_into_http_only_line(structured_record, monkeypatch, firewall_id):
    """No Https protocol: headers always land in HTTP, regardless of SKU/TLS inspection."""
    _install_snapshot(monkeypatch, _apprule_snapshot(sku_tier="Premium", terminate_tls=False, protocols=("Http",)))
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _open_policy_tab_on_rule(app, pilot, firewall_id)
        details = str(app.query_one("#policy-details", Static).content)
        assert "inserted into HTTP" in details
        assert "TLS-inspected" not in details and "Standard/Basic" not in details
