"""Pure filter / rendering logic of the viewer (no Textual runtime needed)."""
from __future__ import annotations

import pytest

from fw_parser import FirewallDataRow
from viewer.app import FirewallLogApp

matches = FirewallLogApp._matches


def make_row(**overrides) -> FirewallDataRow:
    base = dict(
        rowid="1", time="2026-09-05T08:00:00Z", category="NetworkRule",
        protocol="TCP", sourceip="10.0.1.4", srcport="51000",
        targetip="10.0.2.5", targetport="443", action="Allow",
    )
    base.update(overrides)
    return FirewallDataRow(**base)


def make_filters(**overrides) -> dict:
    f = {"src": "", "dst": "", "action": "", "cat": "", "proto": "", "port": "", "hide_dns": False}
    f.update(overrides)
    return f


def test_empty_filters_match_everything():
    assert matches(make_row(), make_filters())
    assert matches(make_row(category="DnsQuery"), make_filters())


@pytest.mark.parametrize(
    "key, row_field, value, needle, expected",
    [
        ("src", "sourceip", "10.0.1.4", "10.0.1", True),
        ("src", "sourceip", "10.0.1.4", "10.0.2", False),
        ("dst", "targetip", "www.Example.com", "example", True),
        ("dst", "targetip", "10.0.2.5", "8.8", False),
        ("action", "action", "Deny", "den", True),
        ("action", "action", "Allow", "deny", False),
        ("cat", "category", "AppRule", "apprule", True),
        ("cat", "category", "NetworkRule", "apprule", False),
        ("proto", "protocol", "HTTPS", "http", True),
        ("proto", "protocol", "UDP", "tcp", False),
        ("port", "targetport", "443", "44", True),
        ("port", "targetport", "443", "80", False),
    ],
)
def test_single_field_substring_match(key, row_field, value, needle, expected):
    row = make_row(**{row_field: value})
    assert matches(row, make_filters(**{key: needle})) is expected


def test_filters_are_case_insensitive_on_row_side():
    # The app lower-cases the needle before calling _matches; the row is lower-cased inside.
    assert matches(make_row(action="DENY"), make_filters(action="deny"))
    assert matches(make_row(protocol="Https"), make_filters(proto="https"))


def test_all_filters_must_match_together():
    row = make_row(action="Deny", protocol="UDP", targetport="53")
    assert matches(row, make_filters(action="deny", proto="udp", port="53"))
    assert not matches(row, make_filters(action="deny", proto="tcp", port="53"))


@pytest.mark.parametrize("preset, visible, hidden", [
    ("group:decisions", ["NetworkRule", "AppRule", "NATRule", "ThreatIntel", "IDPS"], ["FlowTrace", "FatFlow", "DnsQuery", "DnsFailure"]),
    ("group:traffic", ["FlowTrace", "FatFlow"], ["NetworkRule", "DnsQuery"]),
    ("group:dns", ["DnsQuery", "DnsFailure"], ["NetworkRule", "FlowTrace"]),
])
def test_category_presets_select_whole_groups(preset, visible, hidden):
    for cat in visible:
        assert matches(make_row(category=cat), make_filters(cat=preset)), cat
    for cat in hidden:
        assert not matches(make_row(category=cat), make_filters(cat=preset)), cat


def test_unknown_preset_matches_nothing():
    assert not matches(make_row(category="NetworkRule"), make_filters(cat="group:nope"))


def test_hide_dns_removes_only_dnsquery_rows():
    dns = make_row(category="DnsQuery")
    net = make_row(category="NetworkRule")
    assert not matches(dns, make_filters(hide_dns=True))
    assert matches(net, make_filters(hide_dns=True))
    assert matches(dns, make_filters(hide_dns=False))


def test_hide_dns_keeps_dns_failures_visible():
    assert matches(make_row(category="DnsFailure"), make_filters(hide_dns=True))


def test_hide_dns_wins_over_explicit_category_filter():
    dns = make_row(category="DnsQuery")
    assert not matches(dns, make_filters(hide_dns=True, cat="dnsquery"))


def test_empty_target_is_tolerated():
    row = make_row(targetip="")
    assert matches(row, make_filters())
    assert not matches(row, make_filters(dst="x"))


# ── rendering helpers ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "action, style",
    [
        ("Allow", "bold green"),
        ("Deny", "bold red"),
        ("DenyWithThreat", "bold red"),
        ("DNAT", "bold yellow"),
        ("Alert", "bold magenta"),
        ("NOERROR", "dim"),
        ("NXDOMAIN", "bold yellow"),
        ("SERVFAIL", "bold red"),
        ("REFUSED", "bold red"),
        ("ResolveFail", "bold dark_orange3"),
        ("INVALID", "bold red"),
        ("RST", "bold yellow"),
        ("FIN-ACK", "dim"),
        ("12.3 Mbps", "bold cyan"),
    ],
)
def test_action_text_styles(action, style):
    text = FirewallLogApp._action_text(action)
    assert text.plain == action
    assert text.style == style


def test_action_text_unknown_action_is_unstyled():
    text = FirewallLogApp._action_text("Whatever")
    assert text.plain == "Whatever"
    assert text.style == ""


def test_source_text_combines_ip_and_port():
    text = FirewallLogApp._source_text("10.0.1.4", "51000", "")
    assert text.plain == "10.0.1.4:51000"


def test_source_text_highlights_search_term():
    text = FirewallLogApp._source_text("10.0.1.4", "51000", "0.1.4")
    highlighted = [s for s in text.spans if "reverse" in str(s.style)]
    assert highlighted, "search term should be highlighted"


def test_info_text_renders_segments_with_separators():
    text = FirewallLogApp._info_text("rcg»rc»rule")
    assert text.plain == "rcg » rc » rule"


def test_info_text_truncates_long_segments():
    long = "x" * 60
    text = FirewallLogApp._info_text(long)
    assert text.plain == "x" * 40 + "…"


def test_info_text_empty():
    assert FirewallLogApp._info_text("").plain == ""


# ── IPv6 and CIDR (dual-stack firewall) ──────────────────────────────────────

V6 = "fd10:2:0:2::10"
V6_EXPANDED = "fd10:2:0:2:0:0:0:10"


@pytest.mark.parametrize("key, row_field, value, needle, expected", [
    ("src", "sourceip", V6, "fd10:2:0:2", True),               # fragment
    ("src", "sourceip", V6_EXPANDED, V6, True),                # other spelling of the same address
    ("src", "sourceip", V6, V6_EXPANDED, True),
    ("src", "sourceip", V6, "fd10:2::/32", True),              # IPv6 CIDR
    ("src", "sourceip", V6, "fd10:3::/32", False),
    ("src", "sourceip", "10.3.5.4", "10.3.0.0/16", True),      # IPv4 CIDR, new for v4 too
    ("src", "sourceip", "10.3.5.4", "10.4.0.0/16", False),
    ("src", "sourceip", "10.3.5.4", "fd10::/16", False),       # version mismatch is a plain miss
    ("dst", "targetip", V6, "fd10::/16", True),
    ("dst", "targetip", "www.example.com", "10.0.0.0/8", False),  # a CIDR never matches an FQDN
    ("dst", "targetip", "www.example.com", "example", True),
    ("dst", "targetip", "", "fd10::/16", False),
])
def test_address_filters_accept_cidr_and_any_ipv6_spelling(key, row_field, value, needle, expected):
    row = make_row(**{row_field: value})
    assert matches(row, make_filters(**{key: needle})) is expected


def test_source_text_brackets_ipv6_when_told_so():
    text = FirewallLogApp._source_text(V6, "51000", "", ipv6=True)
    assert text.plain == f"[{V6}]:51000"
    # the AzFw label replaces the address, but the brackets follow the row's address, not the label
    assert FirewallLogApp._source_text("AzFw.10", "53", "", ipv6=True).plain == "[AzFw.10]:53"
    assert FirewallLogApp._source_text("10.0.1.4", "51000", "").plain == "10.0.1.4:51000"


def test_source_text_highlights_inside_brackets():
    text = FirewallLogApp._source_text(V6, "51000", "0:2::10", ipv6=True)
    assert [s for s in text.spans if "reverse" in str(s.style)]
