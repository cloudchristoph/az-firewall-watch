"""The TUI-free copies the MCP server uses must answer exactly like the TUI's originals.

``viewer.eventhub``, ``viewer.trace.flow_from_row`` / ``logged_from_row`` /
``no_decision_reason`` and ``viewer.enrichment.enrich_row`` duplicate code in
``viewer.streaming`` and ``viewer.app`` until PR #35 has landed. These tests
keep the two sides from drifting apart in the meantime.
"""
from __future__ import annotations

import pytest

import viewer.eventhub as eventhub
import viewer.streaming as streaming
from fw_parser import parse_record
from viewer.app import FirewallLogApp
from viewer.azure_resources import (
    FirewallPolicyInfo,
    IpGroupInfo,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
)
from viewer.enrichment import enrich_row
from viewer.trace import NO_DECISION_REASONS, TRACEABLE_CATEGORIES, flow_from_row, logged_from_row


def test_eventhub_tables_match_streaming():
    assert eventhub.AUTH_KEYWORDS == streaming._AUTH_KEYWORDS
    assert eventhub.BACKOFF == streaming._BACKOFF
    assert eventhub.RECONNECT_BACKOFF == streaming._RECONNECT_BACKOFF
    assert eventhub.MAX_ATTEMPTS == streaming._MAX_ATTEMPTS
    for value in ("latest", "", None, "EARLIEST", "@earliest", "-1", "12345"):
        assert eventhub.resolve_start_position(value) == streaming.resolve_start_position(value)


@pytest.mark.parametrize("exc, expected", [
    (PermissionError("x"), True), (RuntimeError("401"), True), (RuntimeError("Invalid signature"), True),
    (ConnectionError("name resolution failed"), False), (TimeoutError("did not respond"), False),
])
def test_is_configuration_error(exc, expected):
    assert eventhub.is_configuration_error(exc) is expected


def test_trace_tables_match_the_app():
    assert TRACEABLE_CATEGORIES == FirewallLogApp._TRACEABLE
    assert NO_DECISION_REASONS == FirewallLogApp._NO_DECISION


def _rows(structured_record):
    recs = [
        structured_record("AZFWNetworkRule", Protocol="TCP", SourceIp="10.3.0.4", SourcePort=1, DestinationIp="10.1.0.4",
                          DestinationPort=443, Action="Allow", Policy="child", RuleCollectionGroup="rcg",
                          RuleCollection="rc", Rule="r1"),
        structured_record("AZFWNatRule", Protocol="TCP", SourceIp="1.2.3.4", SourcePort=1, DestinationIp="20.1.1.1",
                          DestinationPort=3389, TranslatedIp="10.3.5.4", TranslatedPort=3389, Action="DNAT",
                          Policy="parent", RuleCollectionGroup="prcg", RuleCollection="prc", Rule="rdp"),
        structured_record("AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.3.0.4", SourcePort=1,
                          Fqdn="www.example.com", DestinationPort=443, Action="Deny", IsExplicitProxyRequest=True,
                          IsTlsInspected="false"),
        structured_record("AZFWFlowTrace", Protocol="TCP", SourceIp="10.3.0.4", SourcePort=1,
                          DestinationIp="10.1.0.4", DestinationPort=443, Flag="SYN"),
    ]
    rows = [parse_record(r) for r in recs]
    assert all(r is not None for r in rows)
    return rows


def test_flow_and_logged_from_row_match_the_app(structured_record):
    for row in _rows(structured_record):
        assert flow_from_row(row) == FirewallLogApp._flow_from_row(row)
        assert logged_from_row(row) == FirewallLogApp._logged_from_row(row)


def test_enrich_row_matches_the_app(structured_record):
    rule = Rule(name="r1", rule_type="NetworkRule", source_addresses=["*"], destination_addresses=["*"],
                destination_ports=["443"], protocols=["TCP"])
    nat = Rule(name="rdp", rule_type="NatRule", source_addresses=["*"], destination_addresses=["20.1.1.1"],
               destination_ports=["3389"], protocols=["TCP"])
    parent = FirewallPolicyInfo(id="/parent", name="parent", rule_collection_groups=[RuleCollectionGroup(
        id="/prcg", name="prcg", priority=50, rule_collections=[RuleCollection(
            name="prc", priority=100, action="Dnat", rule_collection_type="FirewallPolicyNatRuleCollection",
            rules=[nat])])])
    policy = FirewallPolicyInfo(id="/child", name="child", parent=parent, rule_collection_groups=[RuleCollectionGroup(
        id="/rcg", name="rcg", priority=200, rule_collections=[RuleCollection(
            name="rc", priority=300, action="Allow", rule_collection_type="FirewallPolicyFilterRuleCollection",
            rules=[rule])])])
    groups = {"/g": IpGroupInfo(id="/g", name="spokes", location="gwc", ip_addresses=["10.3.0.0/16"])}
    cidrs = ["10.1.0.0/26"]

    app = FirewallLogApp(policy_context=True)
    app._mgmt_loaded = True
    app._subnet_cidrs, app._ip_groups, app._policy_info = cidrs, groups, policy
    for row in _rows(structured_record):
        assert enrich_row(row, subnet_cidrs=cidrs, ip_groups=groups, policy=policy) == app._compute_enrichment(row)
    assert enrich_row(_rows(structured_record)[1], subnet_cidrs=cidrs, ip_groups=groups,
                      policy=policy)["rule_policy"] == "parent (inherited)"
