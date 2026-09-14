"""Real IPv6 records from the dual-stack lab firewall (``tests/fixtures/ipv6``).

Captured 2026-09-07 against ``fw-hub-gwc`` from both Event Hubs, strings verbatim
(see CC-AzureLab ``firewall-mon-app/samples/ipv6/README.md``). They pin down what
the preview really writes: structured ``AZFWNetworkRule`` rows carry the address
bracketed and fully expanded (``[fd10:0003:0005:0001:0000:0000:0000:0004]``),
``AZFWDnsQuery`` rows compressed and bare, legacy messages bracketed with the
same expanded/compressed split per category, ICMPv6 with port ``0``.
"""
from __future__ import annotations

import ipaddress
import json
from collections import Counter
from pathlib import Path

import pytest

from fw_parser import FirewallDataRow, parse_record
from helpers import address_matches, normalise_address
from viewer.app import FirewallLogApp
from viewer.enrichment import resolve_fw_instance

FIXTURES = Path(__file__).parent / "fixtures" / "ipv6"
SPOKE = "fd10:3:5:1::4"                      # the dual-stack demo VM that produced most records
SPOKE_EXPANDED = "fd10:0003:0005:0001:0000:0000:0000:0004"
SPOKES_PREFIX = "fd10:3:"                    # every spoke VNet in the lab sits under fd10:3::/32


def load(name: str) -> list[dict]:
    with (FIXTURES / name).open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def rows(name: str) -> list[FirewallDataRow]:
    parsed = [parse_record(rec) for rec in load(name)]
    assert parsed and all(r is not None for r in parsed)
    return parsed  # type: ignore[return-value]


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ── every record parses into clean, one-spelling addresses ───────────────────

@pytest.mark.parametrize("name, category", [
    ("AZFWNetworkRule.jsonl", "NetworkRule"),
    ("AzureFirewallNetworkRule.jsonl", "NetworkRule"),
])
def test_network_rule_records_have_bare_compressed_addresses(name, category):
    for row in rows(name):
        assert row.category == category
        assert _is_address(row.sourceip) and _is_address(row.targetip), (row.sourceip, row.targetip)
        assert "[" not in row.sourceip and "[" not in row.targetip
        assert row.sourceip == ipaddress.ip_address(row.sourceip).compressed
        assert row.targetip == ipaddress.ip_address(row.targetip).compressed
        assert row.action in ("Allow", "Deny")


@pytest.mark.parametrize("name", ["AZFWDnsQuery.jsonl", "AzureFirewallDnsProxy.jsonl"])
def test_dns_records_keep_the_compressed_client_address(name):
    for row in rows(name):
        assert row.category == "DnsQuery"
        assert row.sourceip.startswith(SPOKES_PREFIX) and "[" not in row.sourceip
        assert row.sourceip == ipaddress.ip_address(row.sourceip).compressed
        assert row.protocol in ("A", "AAAA")
        assert "." in row.targetip and not row.targetip.endswith(".")   # the queried name, trailing dot dropped
        assert row.action == "NOERROR"


def _flow_key(r: FirewallDataRow) -> tuple:
    # the fractional seconds differ between the two hubs' records of one event; the second does not
    return (r.time[:19], r.protocol, r.sourceip, r.srcport, r.targetip, r.targetport, r.action, r.policy, r.rule_name)


@pytest.mark.parametrize("structured_name, legacy_name", [
    ("AZFWNetworkRule.jsonl", "AzureFirewallNetworkRule.jsonl"),
    ("AZFWDnsQuery.jsonl", "AzureFirewallDnsProxy.jsonl"),
])
def test_structured_and_legacy_captures_are_the_same_events(structured_name, legacy_name):
    """Both Event Hubs received every one of these events; after parsing, the two formats
    must produce the same rows, record for record, addresses, ports, action and rule path
    included. A multiset comparison, so a dropped or altered row on either side fails."""
    structured = Counter(_flow_key(r) for r in rows(structured_name))
    legacy = Counter(_flow_key(r) for r in rows(legacy_name))
    assert sum(structured.values()) == sum(legacy.values())
    assert structured == legacy, (structured - legacy, legacy - structured)
    assert all(k[2].startswith(SPOKES_PREFIX) or k[4].startswith(SPOKES_PREFIX) for k in structured)


def test_rule_paths_match_between_formats():
    """The dual-stack firewall writes ``Policy:`` into legacy messages too; the path must be identical."""
    structured = {r.policy for r in rows("AZFWNetworkRule.jsonl") if r.rule_name}
    legacy = {r.policy for r in rows("AzureFirewallNetworkRule.jsonl") if r.rule_name}
    assert structured == legacy
    assert "fwp-hub-premium-gwc»cclab-network-rule-collection-group»ipv6-demo-net-rules»allow-ipv6-web" in legacy
    assert all(r.fw_policy == "fwp-hub-premium-gwc" for r in rows("AzureFirewallNetworkRule.jsonl") if r.rule_name)


@pytest.mark.parametrize("name", ["AZFWNetworkRule.jsonl", "AzureFirewallNetworkRule.jsonl"])
def test_default_deny_records_have_no_rule_but_say_default_action(name):
    defaults = [r for r in rows(name) if not r.rule_name]
    assert len(defaults) == 12
    for r in defaults:
        assert r.action == "Deny" and r.policy == "Default Action"   # structured: ActionReason; legacy: inferred


def test_icmpv6_records_parse_with_type_and_port_zero():
    for name in ("AZFWNetworkRule.jsonl", "AzureFirewallNetworkRule.jsonl"):
        icmp = [r for r in rows(name) if r.protocol.startswith("ICMP")]
        assert icmp, name
        for r in icmp:
            assert r.protocol == "ICMPv6 Type=128"
            assert (r.srcport, r.targetport) == ("0", "0")   # what the firewall writes, not "-"
            assert r.sourceip.startswith(SPOKES_PREFIX)


# ── downstream: flow, filters, labels ────────────────────────────────────────

def test_flow_from_structured_ipv6_row_is_an_address_flow():
    """Before normalisation the bracketed destination failed the address parse and the trace
    ran the FQDN branch: a confident wrong verdict on every IPv6 NetworkRule row."""
    for row in rows("AZFWNetworkRule.jsonl"):
        flow = FirewallLogApp._flow_from_row(row)
        assert flow.dst_fqdn == "" and _is_address(flow.dst_ip), row.targetip
        assert _is_address(flow.src_ip)


def test_cidr_filter_selects_the_spoke_prefix():
    for name in ("AZFWNetworkRule.jsonl", "AzureFirewallNetworkRule.jsonl", "AZFWDnsQuery.jsonl"):
        for row in rows(name):
            assert address_matches("fd10:3::/32", row.sourceip), row.sourceip   # every source is a spoke
            assert not address_matches("fd10:2::/32", row.sourceip)            # the hub's own range
            if row.sourceip == SPOKE:
                assert address_matches(SPOKE_EXPANDED, row.sourceip)           # typed the long way


def test_firewall_subnet_label_works_on_the_normalised_address():
    row = next(r for r in rows("AZFWNetworkRule.jsonl") if r.sourceip == SPOKE)
    assert resolve_fw_instance(row.sourceip, ["fd10:3:5:1::/64"]) == "AzFw.4"


@pytest.mark.parametrize("raw, expected", [
    ("[fd10:0003:0005:0001:0000:0000:0000:0004]", SPOKE),
    ("fd10:0003:0005:0001:0000:0000:0000:0004", SPOKE),
    ("fd10:3:5:1::4", SPOKE),
    ("[2606:4700:4700:0000:0000:0000:0000:1111]", "2606:4700:4700::1111"),
    ("10.3.5.4", "10.3.5.4"),
    ("[10.3.5.4]", "10.3.5.4"),
    ("ifconfig.me", "ifconfig.me"),
    ("-", "-"),
    ("", ""),
    ("[not-an-address]", "[not-an-address]"),
])
def test_normalise_address(raw, expected):
    assert normalise_address(raw) == expected
