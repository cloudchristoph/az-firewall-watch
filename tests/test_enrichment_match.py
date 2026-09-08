"""Pure enrichment helpers (viewer/enrichment.py): no I/O."""
from __future__ import annotations

import ipaddress

import pytest

from viewer.azure_resources import IpGroupInfo
from viewer.enrichment import (
    _fqdn_matches,
    _port_matches,
    find_containing_entry,
    find_matching_ip_groups,
    parse_address_entries,
    resolve_fw_instance,
)

SUBNETS = ["10.2.0.0/26", "10.2.0.64/26"]
GROUPS = {
    "/g/spokes": IpGroupInfo(id="/g/spokes", name="ipgroup-all-spokes", location="gwc", ip_addresses=["10.3.0.0/16"]),
    "/g/onprem": IpGroupInfo(id="/g/onprem", name="ipgroup-onpremises", location="gwc", ip_addresses=["192.168.0.0/16", "10.3.5.4"]),
    "/g/bad": IpGroupInfo(id="/g/bad", name="broken", location="gwc", ip_addresses=["not-an-ip"]),
}
RANGE_GROUPS = {
    "/g/dmz": IpGroupInfo(id="/g/dmz", name="ipgroup-dmz", location="gwc",
                          ip_addresses=["10.2.0.0-10.2.0.31", "fd00::10-fd00::1f"]),
    "/g/junk": IpGroupInfo(id="/g/junk", name="ipgroup-junk", location="gwc",
                           ip_addresses=["10.9.0.5-10.9.0.1", "10.0.0.1-fd00::1", "nonsense"]),
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


def test_parsed_networks_are_cached_per_cidr_list():
    """resolve_fw_instance runs per table row; the CIDR parsing must not (Copilot review)."""
    from viewer.enrichment import _parse_networks, _parsed_networks

    _parsed_networks.cache_clear()
    first = _parse_networks(["10.2.0.0/26", "bad", "10.2.0.64/26"])
    second = _parse_networks(["10.2.0.0/26", "bad", "10.2.0.64/26"])
    assert first is second and len(first) == 2
    assert _parsed_networks.cache_info().hits == 1
    assert _parse_networks(["10.2.0.0/26"]) is not first


# ── IP groups ────────────────────────────────────────────────────────────────

def test_find_matching_ip_groups_returns_all_containing_groups():
    assert find_matching_ip_groups("10.3.5.4", GROUPS) == ["ipgroup-all-spokes", "ipgroup-onpremises"]


def test_find_matching_ip_groups_single_and_none():
    assert find_matching_ip_groups("192.168.1.1", GROUPS) == ["ipgroup-onpremises"]
    assert find_matching_ip_groups("8.8.8.8", GROUPS) == []
    assert find_matching_ip_groups("-", GROUPS) == []
    assert find_matching_ip_groups("x", GROUPS) == []


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("10.2.0.0", ["ipgroup-dmz"]),        # first address of the range
        ("10.2.0.17", ["ipgroup-dmz"]),
        ("10.2.0.31", ["ipgroup-dmz"]),       # last address of the range
        ("10.2.0.32", []),                    # one past the end
        ("10.1.255.255", []),                 # one before the start
        ("fd00::10", ["ipgroup-dmz"]),
        ("fd00::1f", ["ipgroup-dmz"]),
        ("fd00::20", []),
        ("10.9.0.3", []),                     # inside a reversed range: not a match
    ],
)
def test_find_matching_ip_groups_handles_range_entries(ip, expected):
    """A range entry used to be dropped, so the group looked as if it did not contain the address."""
    assert find_matching_ip_groups(ip, RANGE_GROUPS) == expected


def test_parse_address_entries_separates_the_unreadable_ones():
    parsed, unreadable = parse_address_entries(
        ["10.0.0.0", "10.1.0.0/32", "10.2.0.0-10.2.0.31", "AzureMonitor",
         "10.9.0.5-10.9.0.1", "10.0.0.1-fd00::1", ""]
    )
    assert [entry for entry, _ in parsed] == ["10.0.0.0", "10.1.0.0/32", "10.2.0.0-10.2.0.31"]
    # reversed and mixed-family ranges describe nothing, so they are unreadable, not empty
    assert unreadable == ("AzureMonitor", "10.9.0.5-10.9.0.1", "10.0.0.1-fd00::1", "")


def test_find_containing_entry_names_the_entry_and_keeps_the_families_apart():
    parsed, _ = parse_address_entries(["10.2.0.0-10.2.0.31", "fd00::/64"])
    assert find_containing_entry(ipaddress.ip_address("10.2.0.7"), parsed) == "10.2.0.0-10.2.0.31"
    assert find_containing_entry(ipaddress.ip_address("fd00::7"), parsed) == "fd00::/64"
    assert find_containing_entry(ipaddress.ip_address("10.3.0.7"), parsed) is None


def test_parsed_address_entries_are_cached_per_entry_list():
    """The trace parses the same address lists once per rule and row."""
    from viewer.enrichment import _parsed_address_entries

    _parsed_address_entries.cache_clear()
    first = parse_address_entries(["10.2.0.0-10.2.0.31", "bad"])
    second = parse_address_entries(["10.2.0.0-10.2.0.31", "bad"])
    assert first is second
    assert _parsed_address_entries.cache_info().hits == 1


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
