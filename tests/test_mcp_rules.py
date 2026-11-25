"""Rule helpers of the MCP server (mcp_server/rules.py): order, lookup, address coverage, IP group use."""
from __future__ import annotations

import pytest

from mcp_server.rules import (
    find_rule,
    iter_rules,
    rule_covers_address,
    rules_using_ip_group,
    split_ref,
)
from tests.test_trace import G_SPOKES, GROUPS, LAB, RANGE_GROUPS, nat, net, policy, rc, rcg


def test_iter_rules_follows_the_trace_order():
    refs = [(r.kind, r.ref, r.position) for r in iter_rules(LAB)]
    assert refs == [
        ("network", "pol » rcg-net » net-deny » deny-bad", 1),
        ("network", "pol » rcg-net » net-allow » allow-monitor", 2),
        ("network", "pol » rcg-net » net-allow » allow-web", 3),
        ("application", "pol » rcg-app » app-web » allow-web", 4),
    ]


def test_iter_rules_puts_parent_groups_first_within_each_pass():
    parent = policy(rcg("p-net", 500, rc("p-rc", 100, "Deny", net("p-rule"))), name="parent")
    child = policy(rcg("c-net", 100, rc("c-rc", 100, "Allow", net("c-rule"))),
                   rcg("c-nat", 100, rc("c-dnat", 100, "Dnat", nat("c-nat"), rc_type="FirewallPolicyNatRuleCollection")),
                   name="child", parent=parent)
    out = iter_rules(child)
    assert [(r.rule.name, r.inherited) for r in out] == [("c-nat", False), ("p-rule", True), ("c-rule", False)]


@pytest.mark.parametrize("ref, expected", [
    ("a » b » c » d", ["a", "b", "c", "d"]),
    ("b»c»d", ["b", "c", "d"]),
    ("a|b|c|d", ["a", "b", "c", "d"]),
])
def test_split_ref(ref, expected):
    assert split_ref(ref) == expected


@pytest.mark.parametrize("ref", ["", "a » b", "a » » c", "a » b » c » d » e"])
def test_split_ref_rejects_other_shapes(ref):
    with pytest.raises(ValueError, match="ref must look like"):
        split_ref(ref)


def test_find_rule_is_case_insensitive_and_names_ambiguity():
    assert find_rule(LAB, "RCG-NET » NET-ALLOW » ALLOW-WEB").rule.name == "allow-web"
    parent = policy(rcg("same", 100, rc("rc", 100, "Deny", net("r"))), name="parent")
    child = policy(rcg("same", 100, rc("rc", 100, "Allow", net("r"))), name="child", parent=parent)
    with pytest.raises(ValueError, match="2 rules match; add the policy to the ref: parent » same » rc » r; "
                                         "child » same » rc » r"):
        find_rule(child, "same » rc » r")
    assert find_rule(child, "child » same » rc » r").inherited is False


@pytest.mark.parametrize("address, expected", [
    ("10.3.5.4", {"source"}),              # inside the spokes IP group
    ("10.3.0.0/24", {"source"}),           # a CIDR the group's /16 contains
    ("10.0.0.0/8", {"source"}),            # a CIDR that only overlaps the /16
    ("10.9.0.1", set()),
    ("fd00::1", set()),                    # other family than every entry
])
def test_rule_covers_address_through_ip_groups(address, expected):
    rule = net("r", source_addresses=[], source_ip_groups=[G_SPOKES], destination_addresses=["AzureMonitor"])
    assert rule_covers_address(rule, address, GROUPS) == expected


def test_rule_covers_address_ranges_wildcards_and_unreadable_groups():
    rule = net("r", source_addresses=["*"], destination_addresses=[], destination_ip_groups=["/g/dmz", "/g/missing"])
    assert rule_covers_address(rule, "10.2.0.31", RANGE_GROUPS) == {"source", "destination"}
    assert rule_covers_address(rule, "10.2.0.32", RANGE_GROUPS) == {"source"}
    assert rule_covers_address(rule, "fd00::1a", RANGE_GROUPS) == {"source", "destination"}
    with pytest.raises(ValueError, match="address must be an IP address or a CIDR"):
        rule_covers_address(rule, "AzureMonitor", RANGE_GROUPS)


def test_rules_using_ip_group_matches_ids_case_insensitively():
    found = rules_using_ip_group(LAB, G_SPOKES.upper())
    assert [r.rule.name for r in found] == ["allow-monitor", "allow-web"]
    assert rules_using_ip_group(LAB, "/g/none") == []
