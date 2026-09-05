"""Structured (AZFW*) log format parsing."""
from __future__ import annotations

import pytest

from fw_parser import FirewallDataRow, parse_record

RULE_PROPS = {
    "Policy": "pol-hub",
    "RuleCollectionGroup": "rcg-default",
    "RuleCollection": "rc-allow",
    "Rule": "r-web",
}


def test_network_rule_with_rule_match(structured_record):
    row = parse_record(structured_record(
        "AZFWNetworkRule",
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=51000,
        DestinationIp="10.0.2.5", DestinationPort=443, Action="Allow",
        **RULE_PROPS,
    ))
    assert isinstance(row, FirewallDataRow)
    assert row.category == "NetworkRule"
    assert row.protocol == "TCP"
    assert (row.sourceip, row.srcport) == ("10.0.1.4", "51000")
    assert (row.targetip, row.targetport) == ("10.0.2.5", "443")
    assert row.action == "Allow"
    assert row.policy == "pol-hub»rcg-default»rc-allow»r-web"
    assert row.fw_policy == "pol-hub"
    assert row.rule_collection_group == "rcg-default"
    assert row.rule_collection == "rc-allow"
    assert row.rule_name == "r-web"
    assert row.resource_id.endswith("/AZUREFIREWALLS/FW-HUB")
    assert row.time == "2026-09-05T08:00:00Z"


def test_network_rule_without_match_uses_action_reason(structured_record):
    row = parse_record(structured_record(
        "AZFWNetworkRule",
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=1,
        DestinationIp="10.0.2.5", DestinationPort=22, Action="Deny",
        ActionReason="No rule matched. Proceeding with default action.",
    ))
    assert row.action == "Deny"
    assert row.policy == "No rule matched. Proceeding with default action."
    assert row.rule_collection_group == ""


def test_application_rule(structured_record):
    row = parse_record(structured_record(
        "AZFWApplicationRule",
        Protocol="HTTPS", SourceIp="10.0.1.4", SourcePort=51001,
        Fqdn="example.com", DestinationPort=443, Action="Allow",
        TargetUrl="example.com/index.html",
        **RULE_PROPS,
    ))
    assert row.category == "AppRule"
    assert row.protocol == "HTTPS"
    assert row.targetip == "example.com"
    assert row.targetport == "443"
    assert row.action == "Allow"
    assert row.policy == "pol-hub»rcg-default»rc-allow»r-web"
    assert row.moreinfo == "example.com/index.html"


def test_nat_rule_shows_translated_target_and_dnat_action(structured_record):
    row = parse_record(structured_record(
        "AZFWNatRule",
        Protocol="TCP", SourceIp="1.2.3.4", SourcePort=5000,
        DestinationIp="20.1.1.1", DestinationPort=3389,
        TranslatedIp="10.0.3.4", TranslatedPort=3389,
        **RULE_PROPS,
    ))
    assert row.category == "NATRule"
    assert row.action == "DNAT"
    assert (row.targetip, row.targetport) == ("10.0.3.4", "3389")
    assert row.policy == "pol-hub»rcg-default»rc-allow»r-web"


def test_nat_rule_without_match_uses_action_reason(structured_record):
    row = parse_record(structured_record(
        "AZFWNatRule",
        Protocol="TCP", SourceIp="1.2.3.4", DestinationIp="20.1.1.1",
        ActionReason="No rule matched.",
    ))
    assert row.policy == "No rule matched."


def test_dns_query_maps_query_type_and_response_code(structured_record):
    row = parse_record(structured_record(
        "AZFWDnsQuery",
        SourceIp="10.0.1.4", SourcePort=5353,
        QueryName="example.com", QueryType="AAAA", ResponseCode="NXDOMAIN",
        ErrorMessage="",
    ))
    assert row.category == "DnsQuery"
    assert row.protocol == "AAAA"
    assert row.targetip == "example.com"
    assert row.targetport == "53"
    assert row.action == "NXDOMAIN"


def test_dns_query_without_response_code_is_a_request(structured_record):
    row = parse_record(structured_record(
        "AZFWDnsQuery", SourceIp="10.0.1.4", QueryName="example.com", QueryType="A",
    ))
    assert row.action == "Request"


def test_idps_signature_moreinfo_combines_severity_and_signature(structured_record):
    row = parse_record(structured_record(
        "AZFWIdpsSignature",
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=1,
        DestinationIp="8.8.8.8", DestinationPort=80, Action="Alert",
        Severity=1, SignatureId=2024897,
        Category="Attempted User Privilege Gain", Description="ET TEST",
    ))
    assert row.category == "IDPS"
    assert row.action == "Alert"
    assert row.moreinfo == "SEV:1 2024897 Attempted User Privilege Gain ET TEST"


def test_threat_intel(structured_record):
    row = parse_record(structured_record(
        "AZFWThreatIntel",
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=1,
        DestinationIp="1.1.1.1", DestinationPort=80, Action="Deny",
        ThreatDescription="Known malicious IP",
    ))
    assert row.category == "ThreatIntel"
    assert row.action == "Deny"
    assert row.moreinfo == "Known malicious IP"


def test_fqdn_resolve_failure_is_dnsfailure_with_resolvefail(structured_record):
    row = parse_record(structured_record(
        "AZFWFqdnResolveFailure",
        Fqdn="nope.invalid", Error="NXDOMAIN", **RULE_PROPS,
    ))
    assert row.category == "DnsFailure"
    assert row.action == "ResolveFail"
    assert row.targetip == "nope.invalid"
    assert row.moreinfo == "NXDOMAIN"
    assert row.policy == "pol-hub»rcg-default»rc-allow»r-web"
    assert row.rule_name == "r-web"


def test_flow_trace_shows_flag_as_action(structured_record):
    row = parse_record(structured_record(
        "AZFWFlowTrace",
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=51000,
        DestinationIp="10.0.2.5", DestinationPort=443,
        Flag="INVALID", Action="Log", ActionReason="Additional TCP Log",
    ))
    assert row.category == "FlowTrace"
    assert row.action == "INVALID"
    assert (row.sourceip, row.srcport, row.targetip, row.targetport) == ("10.0.1.4", "51000", "10.0.2.5", "443")
    assert row.moreinfo == "Log Additional TCP Log"
    assert row.policy == ""


def test_flow_trace_without_flag(structured_record):
    row = parse_record(structured_record("AZFWFlowTrace", Protocol="TCP"))
    assert row.action == "-"


def test_fat_flow_shows_rate_in_mbps(structured_record):
    row = parse_record(structured_record(
        "AZFWFatFlow",
        Protocol="TCP", SourceIp="10.0.1.4", SourcePort=51000,
        DestinationIp="10.0.2.5", DestinationPort=443, FlowRate=12.3456,
    ))
    assert row.category == "FatFlow"
    assert row.action == "12.3 Mbps"
    assert row.moreinfo == "Top flow by bandwidth"


def test_fat_flow_with_unparseable_rate(structured_record):
    assert parse_record(structured_record("AZFWFatFlow", FlowRate="lots")).action == "lots Mbps"
    assert parse_record(structured_record("AZFWFatFlow")).action == "-"


def test_missing_properties_are_empty_strings_not_none(structured_record):
    row = parse_record(structured_record("AZFWNetworkRule"))
    assert row.category == "NetworkRule"
    for value in (row.protocol, row.sourceip, row.targetip, row.action, row.policy):
        assert value == ""
    assert (row.srcport, row.targetport) == ("-", "-")


def test_icmp_without_ports_renders_dashes(structured_record):
    row = parse_record(structured_record(
        "AZFWNetworkRule", Protocol="ICMP", SourceIp="10.0.1.4", DestinationIp="10.0.2.5", Action="Allow",
    ))
    assert row.protocol == "ICMP"
    assert (row.srcport, row.targetport) == ("-", "-")


def test_dns_query_name_loses_trailing_dot_like_legacy(structured_record):
    row = parse_record(structured_record("AZFWDnsQuery", QueryName="ifconfig.me.", QueryType="A"))
    assert row.targetip == "ifconfig.me"


def test_numeric_properties_are_stringified(structured_record):
    row = parse_record(structured_record(
        "AZFWNetworkRule", SourcePort=51000, DestinationPort=443,
    ))
    assert row.srcport == "51000"
    assert row.targetport == "443"


def test_rowids_are_unique_and_increasing(structured_record):
    a = parse_record(structured_record("AZFWNetworkRule"))
    b = parse_record(structured_record("AZFWNetworkRule"))
    assert a.rowid != b.rowid
    assert int(b.rowid) > int(a.rowid)


@pytest.mark.parametrize(
    "category, expected",
    [
        ("AZFWNetworkRule", "NetworkRule"),
        ("AZFWApplicationRule", "AppRule"),
        ("AZFWNatRule", "NATRule"),
        ("AZFWDnsQuery", "DnsQuery"),
        ("AZFWIdpsSignature", "IDPS"),
        ("AZFWThreatIntel", "ThreatIntel"),
        ("AZFWFqdnResolveFailure", "DnsFailure"),
        ("AZFWFlowTrace", "FlowTrace"),
        ("AZFWFatFlow", "FatFlow"),
    ],
)
def test_every_structured_category_maps_to_display_name(structured_record, category, expected):
    row = parse_record(structured_record(category))
    assert row.category == expected
