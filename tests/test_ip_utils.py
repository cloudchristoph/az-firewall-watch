"""Address helpers (ip_utils.py): splitting, joining and matching v4 / v6 endpoints."""
from __future__ import annotations

import pytest

from ip_utils import (
    address_matches,
    format_endpoint,
    is_ipv6,
    normalise_address,
    parse_address,
    parse_network,
    split_endpoint,
)

V6 = "fd00:c1d0:3f1f:2::10"
V6_EXPANDED = "fd00:c1d0:3f1f:2:0:0:0:10"


# ── parsing ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value, ok", [
    ("10.0.1.4", True), (V6, True), (" fd00::1 ", True),
    ("", False), ("-", False), ("example.com", False), ("10.0.1", False), ("fd00", False),
])
def test_parse_address(value, ok):
    assert (parse_address(value) is not None) is ok


@pytest.mark.parametrize("value, ok", [
    ("10.0.0.0/8", True), ("10.0.0.7/8", True), ("fd00:c1d0::/32", True), ("fd00::1", True),
    ("", False), ("AzureMonitor", False), ("10.0.0.0/33", False), ("fd00::/129", False),
])
def test_parse_network_is_lenient_about_host_bits(value, ok):
    assert (parse_network(value) is not None) is ok


def test_is_ipv6():
    assert is_ipv6(V6) and is_ipv6(V6_EXPANDED)
    assert not is_ipv6("10.0.1.4") and not is_ipv6("example.com") and not is_ipv6("")


@pytest.mark.parametrize("value, expected", [
    (V6_EXPANDED, V6),
    ("FD00::1", "fd00::1"),
    ("fd00:0000:0000:0000:0000:0000:0000:0001", "fd00::1"),
    ("10.0.1.4", "10.0.1.4"),
    ("example.com", "example.com"),   # not an address: unchanged
    ("", ""),
])
def test_normalise_address(value, expected):
    assert normalise_address(value) == expected


# ── split_endpoint ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("token, expected", [
    ("10.1.1.1:1234", ("10.1.1.1", "1234")),
    ("10.2.2.2:80.", ("10.2.2.2", "80")),                 # sentence end from a legacy message
    ("www.example.com:443", ("www.example.com", "443")),   # dots in the name survive
    ("10.1.1.1", ("10.1.1.1", "-")),                       # ICMP: no port
    ("example.com", ("example.com", "-")),
    ("[fd00::1]:1234", ("fd00::1", "1234")),               # bracketed IPv6
    (f"[{V6}]:51000", (V6, "51000")),
    ("[fd00::1]", ("fd00::1", "-")),
    ("[fd00::1]:", ("fd00::1", "-")),
    (f"{V6}:51000", (V6, "51000")),                        # unbracketed IPv6 with a port
    ("2606:4700::6810:84e5:443", ("2606:4700::6810:84e5", "443")),
    (f"{V6_EXPANDED}:443", (V6_EXPANDED, "443")),
    ("", ("-", "-")),
])
def test_split_endpoint(token, expected):
    assert split_endpoint(token) == expected


def test_split_endpoint_unbracketed_ipv6_prefers_the_port_reading():
    """``fd00::1:1234`` is a valid address on its own, but TCP/UDP legacy messages
    always carry a port, so the last group is the port unless the rest is not an address."""
    assert split_endpoint("fd00::1:1234") == ("fd00::1", "1234")
    assert split_endpoint("fd00::abcd") == ("fd00::abcd", "-")   # "abcd" is not a port


def test_split_endpoint_without_expected_port_keeps_the_whole_address():
    """ICMP messages have no port: an address whose last group is decimal must stay intact."""
    assert split_endpoint("fd00::1:1234", expect_port=False) == ("fd00::1:1234", "-")
    assert split_endpoint(V6, expect_port=False) == (V6, "-")
    assert split_endpoint("[fd00::1]:5", expect_port=False) == ("fd00::1", "5")
    assert split_endpoint("10.1.1.1", expect_port=False) == ("10.1.1.1", "-")
    assert split_endpoint("fd00::zz:12", expect_port=False) == ("fd00::zz:12", "-")  # garbage stays garbage


# ── format_endpoint ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("address, port, expected", [
    ("10.1.1.1", "443", "10.1.1.1:443"),
    ("example.com", "443", "example.com:443"),
    (V6, "443", f"[{V6}]:443"),
    (V6, "-", V6),
    (V6, "", V6),
    ("10.1.1.1", "-", "10.1.1.1"),
    ("AzFw.6", "53", "AzFw.6:53"),          # display labels are not addresses and get no brackets
])
def test_format_endpoint(address, port, expected):
    assert format_endpoint(address, port) == expected


# ── address_matches (filter semantics) ───────────────────────────────────────

@pytest.mark.parametrize("needle, value, expected", [
    ("", "10.0.1.4", True),
    ("10.0.1", "10.0.1.4", True),                    # substring, as before
    ("10.0.2", "10.0.1.4", False),
    ("10.0.1.4", "10.0.1.44", True),                 # substring, as before; a CIDR is the precise tool
    ("10.0.1.4", "10.0.1.4", True),
    ("example", "www.Example.com", True),            # FQDNs: substring only
    ("10.0.0.0/8", "10.0.1.4", True),                # CIDR
    ("10.0.0.0/8", "192.168.0.1", False),
    ("10.0.0.0/8", "www.example.com", False),        # CIDR never matches a name
    ("10.0.0.0/8", "", False),
    ("fd00:c1d0::/32", V6, True),                    # IPv6 CIDR
    ("fd00:c1d0::/32", V6_EXPANDED, True),
    ("fd00:c1d0::/32", "fd01::1", False),
    ("fd00:c1d0::/32", "10.0.1.4", False),           # version mismatch is a miss, not an error
    ("10.0.0.0/8", V6, False),
    ("10.0.0.0/99", "10.0.1.4", False),              # not a CIDR: plain substring
    ("10.0/8", "10.0/8", True),
    (V6, V6_EXPANDED, True),                         # same address, other spelling
    (V6_EXPANDED, V6, True),
    ("fd00::1", "fd00:0:0:0:0:0:0:1", True),
    ("fd00::1", "fd00::10", True),                   # substring, as with IPv4
    ("fd00::1", "fd00:0:0:0:0:0:0:10", True),         # substring of the compressed spelling fd00::10
    ("::10", V6_EXPANDED, True),                     # fragment against the compressed form
    ("3f1f:2::", V6_EXPANDED, True),
    ("3f1f:2::", "fd00:c1d0:3f1f:3::10", False),
    ("fd00:c1d0", "FD00:C1D0:3F1F:2::10", True),     # upper-case hex in the log
])
def test_address_matches(needle, value, expected):
    assert address_matches(needle, value) is expected
