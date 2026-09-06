"""Pure enrichment helpers (viewer/enrichment.py): no I/O."""
from __future__ import annotations

import pytest

from viewer.azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup
from viewer.enrichment import (
    _fqdn_matches,
    _port_matches,
    find_matching_ip_groups,
    find_rule,
    resolve_fw_instance,
)

SUBNETS = ["10.2.0.0/26", "10.2.0.64/26"]
GROUPS = {
    "/g/spokes": IpGroupInfo(id="/g/spokes", name="ipgroup-all-spokes", location="gwc", ip_addresses=["10.3.0.0/16"]),
    "/g/onprem": IpGroupInfo(id="/g/onprem", name="ipgroup-onpremises", location="gwc", ip_addresses=["192.168.0.0/16", "10.3.5.4"]),
    "/g/bad": IpGroupInfo(id="/g/bad", name="broken", location="gwc", ip_addresses=["not-an-ip"]),
}


# ── firewall instance ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "ip, expected",
    [
        ("10.2.0.6", "AzFw.6"),       # AzureFirewallSubnet
        ("10.2.0.70", "AzFw.70"),     # AzureFirewallManagementSubnet
        ("10.3.5.4", None),           # a spoke client
        ("-", None),
        ("", None),
        ("garbage", None),
    ],
)
def test_resolve_fw_instance(ip, expected):
    assert resolve_fw_instance(ip, SUBNETS) == expected


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("fd00::1:2:3:abcd", "AzFw.abcd"),
        ("fd00::", "AzFw.0"),                 # compressed trailing zeros (Copilot review)
        ("fd00::00ab", "AzFw.ab"),            # leading zeros are not part of the label
        ("fd00:0:0:0:0:0:0:1", "AzFw.1"),     # uncompressed input, same label
    ],
)
def test_resolve_fw_instance_ipv6_uses_last_hextet(ip, expected):
    assert resolve_fw_instance(ip, ["fd00::/64"]) == expected


def test_resolve_fw_instance_ignores_invalid_cidrs():
    assert resolve_fw_instance("10.2.0.6", ["nope", "10.2.0.0/26"]) == "AzFw.6"


# ── IP groups ────────────────────────────────────────────────────────────────

def test_find_matching_ip_groups_returns_all_containing_groups():
    assert find_matching_ip_groups("10.3.5.4", GROUPS) == ["ipgroup-all-spokes", "ipgroup-onpremises"]


def test_find_matching_ip_groups_single_and_none():
    assert find_matching_ip_groups("192.168.1.1", GROUPS) == ["ipgroup-onpremises"]
    assert find_matching_ip_groups("8.8.8.8", GROUPS) == []
    assert find_matching_ip_groups("-", GROUPS) == []
    assert find_matching_ip_groups("x", GROUPS) == []


# ── rule matching ────────────────────────────────────────────────────────────

def _policy() -> FirewallPolicyInfo:
    net_rules = RuleCollection(
        name="rc-net", priority=100, action="Allow", rule_collection_type="FirewallPolicyFilterRuleCollection",
        rules=[
            Rule(name="allow-web", rule_type="NetworkRule", source_ip_groups=["/g/spokes"],
                 destination_addresses=["*"], destination_ports=["443", "8000-8100"], protocols=["TCP"]),
            Rule(name="allow-dns", rule_type="NetworkRule", source_addresses=["10.3.0.0/16"],
                 destination_addresses=["10.2.0.4"], destination_ports=["53"], protocols=["UDP"]),
        ],
    )
    deny_rules = RuleCollection(
        name="rc-deny", priority=50, action="Deny", rule_collection_type="FirewallPolicyFilterRuleCollection",
        rules=[Rule(name="deny-bad", rule_type="NetworkRule", source_addresses=["any"],
                    destination_addresses=["203.0.113.0/24"], destination_ports=["*"])],
    )
    app_rules = RuleCollection(
        name="rc-app", priority=200, action="Allow", rule_collection_type="FirewallPolicyFilterRuleCollection",
        rules=[Rule(name="allow-ms", rule_type="ApplicationRule", source_addresses=["*"],
                    destination_fqdns=["*.microsoft.com", "example.com"])],
    )
    return FirewallPolicyInfo(
        id="/p", name="pol", sku_tier="Premium",
        rule_collection_groups=[
            RuleCollectionGroup(id="/p/net", name="rcg-net", priority=2000, rule_collections=[net_rules, deny_rules]),
            RuleCollectionGroup(id="/p/app", name="rcg-app", priority=100, rule_collections=[app_rules]),
        ],
    )


def test_find_rule_network_by_ip_group_and_port_range():
    match = find_rule("NetworkRule", "10.3.5.4", "1.1.1.1", "", "8080", _policy(), GROUPS)
    assert match is not None
    rule, rcg, rc = match
    assert (rule.name, rcg.name, rc.name) == ("allow-web", "rcg-net", "rc-net")


def test_find_rule_respects_priority_order():
    # rc-deny (priority 50) comes before rc-net (100) inside rcg-net
    rule, _, rc = find_rule("NetworkRule", "10.3.5.4", "203.0.113.7", "", "443", _policy(), GROUPS)
    assert (rule.name, rc.action) == ("deny-bad", "Deny")


def test_find_rule_port_mismatch_returns_none():
    assert find_rule("NetworkRule", "10.3.5.4", "1.1.1.1", "", "22", _policy(), GROUPS) is None


def test_find_rule_source_mismatch_returns_none():
    assert find_rule("NetworkRule", "172.16.0.1", "1.1.1.1", "", "443", _policy(), GROUPS) is None


def test_find_rule_application_by_fqdn():
    rule, rcg, _ = find_rule("AppRule", "10.3.5.4", "", "login.microsoft.com", "443", _policy(), GROUPS)
    assert (rule.name, rcg.name) == ("allow-ms", "rcg-app")
    assert find_rule("AppRule", "10.3.5.4", "", "example.org", "443", _policy(), GROUPS) is None


def test_find_rule_without_policy():
    assert find_rule("NetworkRule", "10.3.5.4", "1.1.1.1", "", "443", None, GROUPS) is None


@pytest.mark.parametrize(
    "fqdn, patterns, expected",
    [
        ("www.microsoft.com", ["*.microsoft.com"], True),
        ("microsoft.com", ["*.microsoft.com"], True),
        ("evilmicrosoft.com", ["*.microsoft.com"], False),
        ("Example.COM", ["example.com"], True),
        ("anything", ["*"], True),
        ("", ["*"], False),
        ("a.b", ["", None], False),
    ],
)
def test_fqdn_matches(fqdn, patterns, expected):
    assert _fqdn_matches(fqdn, [p for p in patterns if p is not None] + ([""] if None in patterns else [])) is expected


@pytest.mark.parametrize(
    "port, spec, expected",
    [
        ("443", "443", True),
        ("443", "*", True),
        ("443", "any", True),
        ("8080", "8000-8100", True),
        ("7999", "8000-8100", False),
        ("x", "443", False),
        ("443", "abc", False),
        ("443", "a-b", False),
    ],
)
def test_port_matches(port, spec, expected):
    assert _port_matches(port, spec) is expected
