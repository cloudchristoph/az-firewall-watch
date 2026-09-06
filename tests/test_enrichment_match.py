"""Pure enrichment helpers (viewer/enrichment.py): no I/O."""
from __future__ import annotations

import pytest

from viewer.azure_resources import IpGroupInfo
from viewer.enrichment import (
    _fqdn_matches,
    _port_matches,
    find_matching_ip_groups,
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
