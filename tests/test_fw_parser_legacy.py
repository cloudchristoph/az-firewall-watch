"""Legacy (properties.msg) log format parsing."""
from __future__ import annotations

import pytest

from fw_parser import parse_record


def test_legacy_network_rule(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
        "TCP request from 10.1.1.1:1234 to 10.2.2.2:80. Action: Allow. "
        "Rule Collection Group: rcg-x. Rule Collection: rc-y. Rule: r-z.",
    ))
    assert row.category == "NetworkRule"
    assert row.protocol == "TCP"
    assert (row.sourceip, row.srcport) == ("10.1.1.1", "1234")
    assert (row.targetip, row.targetport) == ("10.2.2.2", "80")
    assert row.action == "Allow"
    assert row.policy == "rcg-x»rc-y»r-z"
    assert row.rule_collection_group == "rcg-x"
    assert row.rule_collection == "rc-y"
    assert row.rule_name == "r-z"


def test_legacy_network_rule_deny_without_rule_info(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
        "UDP request from 10.1.1.1:5000 to 10.2.2.2:123. Action: Deny.",
    ))
    assert row.protocol == "UDP"
    assert row.action == "Deny"
    assert row.policy == ""
    assert row.targetport == "123"


def test_legacy_application_rule_with_policy(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallApplicationRule", "AzureFirewallApplicationRuleLog",
        "HTTPS request from 10.1.1.1:55583 to www.example.com:443. Action: Allow. "
        "Policy: pol-hub. Rule Collection Group: rcg. Rule Collection: rc. Rule: r.",
    ))
    assert row.category == "AppRule"
    assert row.protocol == "HTTPS"
    assert (row.sourceip, row.srcport) == ("10.1.1.1", "55583")
    # FQDNs contain dots — the port split must happen at the last colon only
    assert (row.targetip, row.targetport) == ("www.example.com", "443")
    assert row.action == "Allow"
    assert row.policy == "pol-hub»rcg»rc»r"
    assert row.fw_policy == "pol-hub"


def test_legacy_application_rule_no_rule_matched(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallApplicationRule", "AzureFirewallApplicationRuleLog",
        "HTTPS request from 10.1.1.1:55583 to example.com:443. Action: Deny. "
        "No rule matched. Proceeding with default action",
    ))
    assert row.action == "Deny"
    assert row.policy == "N/A"


def test_legacy_application_rule_extracts_url(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallApplicationRule", "AzureFirewallApplicationRuleLog",
        "HTTP request from 10.1.1.1:55583 to example.com:80. Url: example.com/path. "
        "Action: Allow. Rule Collection Group: rcg. Rule Collection: rc. Rule: r.",
    ))
    assert row.moreinfo == "example.com/path"


def test_legacy_nat_rule(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNatRule", "AzureFirewallNatRuleLog",
        "TCP request from 1.2.3.4:1234 to 5.6.7.8:3389 was DNAT'ed to 10.1.1.1:3389",
    ))
    assert row.category == "NATRule"
    assert row.action == "DNAT"
    assert (row.sourceip, row.srcport) == ("1.2.3.4", "1234")
    assert (row.targetip, row.targetport) == ("10.1.1.1", "3389")


def test_legacy_dns_proxy_is_normalised_to_dnsquery(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallDnsProxy", "AzureFirewallDnsProxyLog",
        "DNS Request: 10.2.0.6:5350 - 10407 A IN ifconfig.me. udp 40 false 1232 "
        "NOERROR qr,aa,rd,ra 56 0.000324423s",
    ))
    assert row.category == "DnsQuery"
    assert (row.sourceip, row.srcport) == ("10.2.0.6", "5350")
    assert row.protocol == "A"
    assert row.targetip == "ifconfig.me"
    assert row.targetport == "53"
    assert row.action == "NOERROR"


def test_legacy_dns_proxy_nxdomain(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallDnsProxy", "AzureFirewallDnsProxyLog",
        "DNS Request: 10.2.0.6:5350 - 1 AAAA IN nope.invalid. udp 40 false 1232 "
        "NXDOMAIN qr,rd,ra 56 0.0001s",
    ))
    assert row.protocol == "AAAA"
    assert row.action == "NXDOMAIN"


def test_legacy_dns_proxy_short_message_does_not_crash(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallDnsProxy", "AzureFirewallDnsProxyLog", "DNS Request: 10.2.0.6:5350",
    ))
    assert row.category == "DnsQuery"
    assert row.sourceip == "10.2.0.6"
    assert row.protocol == "-"
    assert row.action == "-"


LAB_RESOLVE_FAIL = (
    "Failed to resolve FQDN ifconfig.me. Error lookup ifconfig.me on 127.0.0.53:53: "
    "read udp 10.2.0.6:48652->10.2.0.6:65053: read: connection refused; "
    "DNS resolution returned no IPv4 IPs. "
    "Rule Collection: fwp-hub-premium-gwc:cclab-network-rule-collection-group:priority-demo-net-rules. "
    "Rule: allow-ifconfig-me"
)


def test_legacy_dns_resolution_failure_is_resolvefail(legacy_record):
    """Real record from a lab firewall; previously counted as SKIP:ParseErr."""
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallDNSResolutionFailureLog", LAB_RESOLVE_FAIL,
    ))
    assert row.category == "DnsFailure"  # same rendering as structured AZFWFqdnResolveFailure
    assert row.action == "ResolveFail"
    assert row.targetip == "ifconfig.me"
    assert row.moreinfo.startswith("lookup ifconfig.me on 127.0.0.53:53")
    assert row.moreinfo.endswith("DNS resolution returned no IPv4 IPs")
    assert row.fw_policy == "fwp-hub-premium-gwc"
    assert row.rule_collection_group == "cclab-network-rule-collection-group"
    assert row.rule_collection == "priority-demo-net-rules"
    assert row.rule_name == "allow-ifconfig-me"
    assert row.policy == "fwp-hub-premium-gwc»cclab-network-rule-collection-group»priority-demo-net-rules»allow-ifconfig-me"


def test_legacy_dns_resolution_failure_without_rule_info(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallDNSResolutionFailureLog",
        "Failed to resolve FQDN nope.invalid. Error NXDOMAIN.",
    ))
    assert row.action == "ResolveFail"
    assert row.targetip == "nope.invalid"
    assert row.moreinfo == "NXDOMAIN"
    assert row.policy == ""


def test_legacy_dns_resolution_failure_without_error_text(legacy_record):
    """Regression (Copilot review): the optional 'Error …' group must not crash the parser."""
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallDNSResolutionFailureLog",
        "Failed to resolve FQDN nope.invalid. Rule Collection: pol:rcg:rc. Rule: r",
    ))
    assert row.category == "DnsFailure"
    assert row.targetip == "nope.invalid"
    assert row.moreinfo == ""
    assert row.policy == "pol»rcg»rc»r"


def test_legacy_malformed_message_is_counted_as_parse_error(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog", "garbage without structure",
    ))
    assert row.category == "SKIP:ParseErr:AzureFirewallNetworkRuleLog"


def test_legacy_unknown_operation_is_skipped(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "SomethingElse", "TCP request from a:1 to b:2. Action: Allow.",
    ))
    assert row.category.startswith("SKIP:ParseErr:")


# ── IPv6 (dual-stack firewall) ───────────────────────────────────────────────
# The exact spelling Azure uses for IPv6 endpoints in legacy messages is not
# documented; both the bracketed ``[addr]:port`` and the bare ``addr:port`` form
# are covered until lab records settle it (see docs/ipv6-plan.md).

V6_SRC = "fd10:2:0:2::10"
V6_DST = "2606:4700::6810:84e5"


@pytest.mark.parametrize("src, dst", [
    (f"[{V6_SRC}]:51000", f"[{V6_DST}]:443"),   # bracketed
    (f"{V6_SRC}:51000", f"{V6_DST}:443"),       # bare
])
def test_legacy_network_rule_ipv6(legacy_record, src, dst):
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
        f"TCP request from {src} to {dst}. Action: Allow. "
        "Rule Collection Group: rcg-x. Rule Collection: rc-y. Rule: r-z.",
    ))
    assert row.category == "NetworkRule"
    assert (row.sourceip, row.srcport) == (V6_SRC, "51000")
    assert (row.targetip, row.targetport) == (V6_DST, "443")
    assert row.action == "Allow"
    assert row.rule_name == "r-z"


def test_legacy_network_rule_ipv6_mixed_with_ipv4_stays_intact(legacy_record):
    """Regression: the old first-colon split turned fd10:2:0:2::10 into source 'fd10', port '2'."""
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
        f"UDP request from {V6_SRC}:5350 to 10.2.0.4:53. Action: Deny.",
    ))
    assert (row.sourceip, row.srcport) == (V6_SRC, "5350")
    assert (row.targetip, row.targetport) == ("10.2.0.4", "53")


def test_legacy_network_rule_icmpv6_without_ports(legacy_record):
    """ICMP messages carry no ports; an address ending in a decimal group must not lose it."""
    row = parse_record(legacy_record(
        "AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
        "ICMP request from fd10:2:0:2::10 to fd10:2:0:1::4. Action: Allow.",
    ))
    assert row.protocol == "ICMP"
    assert (row.sourceip, row.srcport) == ("fd10:2:0:2::10", "-")
    assert (row.targetip, row.targetport) == ("fd10:2:0:1::4", "-")


def test_legacy_nat_rule_ipv6(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallNatRule", "AzureFirewallNatRuleLog",
        "TCP request from [2001:db8::5]:1234 to [2603:1020:c01:16::275]:3389 was DNAT'ed to [fd10:2:0:2::10]:3389",
    ))
    assert (row.sourceip, row.srcport) == ("2001:db8::5", "1234")
    assert (row.targetip, row.targetport) == ("fd10:2:0:2::10", "3389")


def test_legacy_application_rule_ipv6_source(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallApplicationRule", "AzureFirewallApplicationRuleLog",
        f"HTTPS request from {V6_SRC}:55583 to www.example.com:443. Action: Allow. "
        "Policy: pol-hub. Rule Collection Group: rcg. Rule Collection: rc. Rule: r.",
    ))
    assert (row.sourceip, row.srcport) == (V6_SRC, "55583")
    assert (row.targetip, row.targetport) == ("www.example.com", "443")


def test_legacy_dns_proxy_ipv6_client(legacy_record):
    row = parse_record(legacy_record(
        "AzureFirewallDnsProxy", "AzureFirewallDnsProxyLog",
        f"DNS Request: {V6_SRC}:5350 - 10407 AAAA IN ifconfig.me. udp 40 false 1232 "
        "NOERROR qr,aa,rd,ra 56 0.000324423s",
    ))
    assert (row.sourceip, row.srcport) == (V6_SRC, "5350")
    assert row.protocol == "AAAA"
    assert row.targetip == "ifconfig.me"
