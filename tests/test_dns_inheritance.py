"""The DNS proxy of a policy that sets nothing itself (issue #58).

By design a child inherits its parent's DNS settings, while Azure's known
issues page says child policies do not. Either way "off" is not supported by
the documentation, so the Firewall tab says where the value comes from, and the
coverage line names AZFWDnsQuery as optional instead of dropping it.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict

import pytest

from viewer.azure_resources import DiagnosticSetting, FirewallInfo, FirewallPolicyInfo, fetch_policy
from viewer.cache import _hydrate_policy
from viewer.views.firewall import (
    VIEWER_CATEGORIES,
    FirewallView,
    _coverage_row,
    connected_event_hub_targets,
    expected_categories,
    logging_targets,
)

from .test_azure_resources import POLICY_ID, FakeArm

pytestmark = pytest.mark.usefixtures("no_eventhub_env")

FW = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc", sku_tier="Premium")


def _chain(child_dns=None, parent_dns=None, child_servers=(), parent_servers=("10.0.0.53",), unread=""):
    parent = FirewallPolicyInfo(id="/parent", name="parent-policy", sku_tier="Premium",
                                dns_proxy=parent_dns, dns_servers=list(parent_servers), threat_intel_mode="Alert")
    child = FirewallPolicyInfo(id="/child", name="child-policy", sku_tier="Premium", base_policy_id="/parent",
                               dns_proxy=child_dns, dns_servers=list(child_servers), threat_intel_mode="Alert",
                               parent=None if unread else parent, parent_unreadable=unread)
    return child


def _dns_text(policy) -> str:
    return "\n".join(r for r in FirewallView._policy(policy, FW) if "DNS proxy" in r)


# ── effective state ────────────────────────────────────────────────────────────

def test_a_child_that_sets_nothing_takes_the_parent_value_and_servers():
    assert _chain(None, True).effective_dns() == (True, ["10.0.0.53"], "parent-policy")
    assert _chain(None, False).effective_dns() == (False, ["10.0.0.53"], "parent-policy")


def test_the_childs_own_value_wins_even_when_it_is_false():
    assert _chain(False, True).effective_dns()[0] is False
    assert _chain(True, False, child_servers=("1.1.1.1",)).effective_dns() == (True, ["1.1.1.1"], "child-policy")


def test_nothing_set_anywhere_in_a_read_chain_is_off():
    assert _chain(None, None).effective_dns() == (False, [], "")
    assert FirewallPolicyInfo(id="/p", name="p").effective_dns() == (False, [], "")


def test_nothing_set_with_an_unreadable_parent_is_unknown_not_off():
    assert _chain(None, None, unread="/parent").effective_dns() == (None, [], "")
    assert _chain(True, None, unread="/parent").effective_dns()[0] is True   # own value still decides


# ── the Firewall tab row ───────────────────────────────────────────────────────

def test_inherited_on_is_shown_with_its_source_and_the_known_issue():
    text = _dns_text(_chain(None, True))
    assert "on (inherited from parent-policy)" in text and "10.0.0.53" in text
    assert "known issue" in text and "set it on this policy" in text


def test_inherited_off_is_labelled_inherited():
    text = _dns_text(_chain(None, False))
    assert "off (inherited from parent-policy)" in text


def test_own_values_read_as_before():
    assert "on" in _dns_text(_chain(True, None, child_servers=("10.1.1.1",))) and "10.1.1.1" in _dns_text(
        _chain(True, None, child_servers=("10.1.1.1",)))
    off = _dns_text(_chain(False, True))
    assert "off" in off and "inherited" not in off
    plain = _dns_text(_chain(None, None))
    assert "off" in plain and "inherited" not in plain and "unknown" not in plain


def test_unreadable_parent_is_unknown_on_the_tab():
    text = _dns_text(_chain(None, None, unread="/parent"))
    assert "unknown" in text and "not readable" in text and " off" not in text


# ── Event Hub coverage ─────────────────────────────────────────────────────────

def test_inherited_dns_proxy_is_optional_in_the_coverage_not_expected():
    child = _chain(None, True)
    assert "AZFWDnsQuery" not in expected_categories(child, FW)
    without = [c for c in VIEWER_CATEGORIES if c != "AZFWDnsQuery"]
    targets = logging_targets([DiagnosticSetting(name="eh", event_hub="ns/hub", categories=without)])
    line = _coverage_row(connected_event_hub_targets(targets), child, FW)
    assert "incomplete" not in line and "AZFWDnsQuery absent, not counted" in line


def test_the_same_holds_for_an_unknown_state_and_not_for_an_own_value():
    assert "AZFWDnsQuery" not in expected_categories(_chain(None, None, unread="/parent"), FW)
    assert "AZFWDnsQuery" in expected_categories(_chain(True, None), FW)
    assert "AZFWDnsQuery" not in expected_categories(_chain(False, True), FW)
    assert "AZFWDnsQuery" not in expected_categories(_chain(None, False), FW)


# ── parsing and the cache ──────────────────────────────────────────────────────

def _fetch(dns_props):
    props = {"dnsSettings": dns_props} if dns_props is not None else {}
    arm = FakeArm({POLICY_ID: {"id": POLICY_ID, "name": "p", "properties": props},
                   f"{POLICY_ID}/ruleCollectionGroups": {"value": []}})
    return asyncio.run(fetch_policy(arm, POLICY_ID))


def test_absent_enable_proxy_is_none_and_an_explicit_false_stays_false():
    assert _fetch(None).dns_proxy is None
    assert _fetch({}).dns_proxy is None
    assert _fetch({"servers": ["10.0.0.53"]}).dns_proxy is None
    assert _fetch({"enableProxy": False}).dns_proxy is False
    assert _fetch({"enableProxy": True, "servers": ["10.0.0.53"]}).dns_proxy is True


def test_the_unset_state_survives_the_cache():
    for value in (None, True, False):
        pol = _hydrate_policy(asdict(FirewallPolicyInfo(id="/p", name="p", dns_proxy=value)))
        assert pol is not None and pol.dns_proxy is value
