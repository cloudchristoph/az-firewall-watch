"""Legacy (properties.msg) log format parsing."""
from __future__ import annotations

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
