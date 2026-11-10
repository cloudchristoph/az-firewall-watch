"""LogFilter and time windows (mcp_server/filters.py): TUI parity plus the agent-only fields."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from fw_parser import parse_record
from mcp_server.buffer import LogBuffer, parse_log_time
from mcp_server.filters import LogFilter, parse_duration, parse_window
from viewer.app import FirewallLogApp

FIXTURES = Path(__file__).parent / "fixtures" / "ipv6"
NOW = parse_log_time("2026-09-05T09:00:00Z")
assert NOW is not None


@pytest.fixture
def buf(structured_record, legacy_record) -> LogBuffer:
    """A small mixed buffer: network, app, NAT, DNS, flow trace; IPv4 and IPv6."""
    b = LogBuffer(100)
    recs = [
        structured_record("AZFWNetworkRule", time="2026-09-05T08:00:00.1234567Z", Protocol="TCP",
                          SourceIp="10.0.1.4", SourcePort=50000, DestinationIp="10.1.0.10", DestinationPort=443,
                          Action="Allow", Policy="fw-pol", RuleCollectionGroup="rcg-net", RuleCollection="rc-allow",
                          Rule="allow-web"),
        structured_record("AZFWNetworkRule", time="2026-09-05T08:30:00Z", Protocol="UDP",
                          SourceIp="[fd10:0003:0005:0001:0000:0000:0000:0004]", SourcePort=5353,
                          DestinationIp="[fd10:0002:0000:0000:0000:0000:0000:0010]", DestinationPort=53,
                          Action="Deny", ActionReason="Default Action"),
        structured_record("AZFWApplicationRule", time="2026-09-05T08:45:00Z", Protocol="HTTPS", SourceIp="10.0.1.44",
                          SourcePort=443, Fqdn="www.example.com", TargetUrl="", DestinationPort=4433, Action="Deny",
                          Policy="fw-pol", RuleCollectionGroup="rcg-app", RuleCollection="rc-deny", Rule="block-all",
                          IsExplicitProxyRequest=False, IsTlsInspected=False),
        structured_record("AZFWDnsQuery", time="2026-09-05T08:50:00Z", SourceIp="fd10:3:5:1::4", SourcePort=40000,
                          QueryType="AAAA", QueryName="example.com.", ResponseCode="NOERROR"),
        structured_record("AZFWFlowTrace", time="2026-09-05T08:55:00Z", Protocol="TCP", SourceIp="10.0.1.4",
                          SourcePort=50001, DestinationIp="10.1.0.10", DestinationPort=443, Flag="SYN"),
    ]
    for rec in recs:
        row = parse_record(rec)
        assert row is not None and not row.category.startswith("SKIP:"), rec
        b.append(row, rec, received_at=NOW)
    return b


def ids(buf: LogBuffer, flt: LogFilter) -> list[int]:
    return [i.id for i in buf.snapshot() if flt.matches(i)]


# ── parity with the TUI filter bar ───────────────────────────────────────────

def _tui(src="", dst="", action="", cat="", proto="", port="") -> dict:
    return {"src": src, "dst": dst, "action": action, "cat": cat, "proto": proto, "port": port, "hide_dns": False}


@pytest.mark.parametrize("tui, mcp", [
    (_tui(src="10.0.1.4"), {"source": "10.0.1.4"}),                       # substring: also 10.0.1.44
    (_tui(src="10.0.0.0/16"), {"source": "10.0.0.0/16"}),                 # CIDR
    (_tui(src="fd10::/16"), {"source": "fd10::/16"}),                     # IPv6 CIDR, never IPv4
    (_tui(src="fd10:3:5:1:0:0:0:4"), {"source": "fd10:3:5:1:0:0:0:4"}),   # any IPv6 spelling
    (_tui(dst="fd10:0002::10"), {"destination": "fd10:0002::10"}),
    (_tui(dst="example"), {"destination": "example"}),                    # FQDN substring
    (_tui(action="deny"), {"action": "Deny"}),
    (_tui(proto="tcp"), {"protocol": "TCP"}),
    (_tui(port="443"), {"dst_port": "443"}),                              # substring: 4433 too
    (_tui(cat="group:decisions"), {"category": "decisions"}),
    (_tui(cat="group:traffic"), {"category": "traffic"}),
    (_tui(cat="group:dns"), {"category": "dns"}),
    (_tui(cat="networkrule"), {"category": "NetworkRule"}),
    (_tui(cat="rule"), {"category": "rule"}),                             # substring across rule categories
])
def test_parity_with_tui(buf, tui, mcp):
    expected = [i.id for i in buf.snapshot() if FirewallLogApp._matches(i.row, tui)]
    assert ids(buf, LogFilter.build(**mcp)) == expected


def test_category_list_is_an_or(buf):
    assert ids(buf, LogFilter.build(category=["DnsQuery", "FlowTrace"])) == [4, 5]
    assert ids(buf, LogFilter.build(category=["group:dns", "apprule"])) == [3, 4]


def test_empty_filter_matches_everything(buf):
    assert ids(buf, LogFilter.build()) == [1, 2, 3, 4, 5]
    assert LogFilter.build().echo() == {}


# ── fields the TUI does not have ─────────────────────────────────────────────

def test_src_port(buf):
    assert ids(buf, LogFilter.build(src_port=5353)) == [2]
    assert ids(buf, LogFilter.build(src_port="5000")) == [1, 5]


def test_rule_path_substring_with_or_without_spaces(buf):
    assert ids(buf, LogFilter.build(rule="rc-allow")) == [1]
    assert ids(buf, LogFilter.build(rule="fw-pol » rcg-app")) == [3]
    assert ids(buf, LogFilter.build(rule="FW-POL»RCG-NET»rc-allow»allow-web")) == [1]
    assert ids(buf, LogFilter.build(rule="default action")) == [2]   # the action reason when no rule matched


def test_text_searches_every_column(buf):
    assert ids(buf, LogFilter.build(text="www.example.com")) == [3]
    assert ids(buf, LogFilter.build(text="block-all")) == [3]
    assert ids(buf, LogFilter.build(text="AAAA")) == [4]


def test_id_cursors(buf):
    assert ids(buf, LogFilter.build(after_id=3)) == [4, 5]
    assert ids(buf, LogFilter.build(before_id=3)) == [1, 2]
    assert ids(buf, LogFilter.build(after_id=1, before_id=4)) == [2, 3]


def test_filters_combine_with_and(buf):
    assert ids(buf, LogFilter.build(source="10.0.0.0/8", action="deny")) == [3]


# ── time windows ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text, seconds", [("30s", 30), ("15m", 900), ("2h", 7200), ("1d", 86400),
                                           ("1.5h", 5400), (" 10M ", 600)])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


def test_relative_window_counts_back_from_now(buf):
    flt = LogFilter.build(since="15m", now=NOW)   # 08:45 onwards
    assert ids(buf, flt) == [3, 4, 5]
    assert flt.echo()["since"] == "2026-09-05T08:45:00.000Z"


def test_absolute_window_with_azure_fractions(buf):
    flt = LogFilter.build(since="2026-09-05T08:00:00.1234567Z", until="2026-09-05T08:45:00Z", now=NOW)
    assert ids(buf, flt) == [1, 2, 3]


def test_until_relative(buf):
    assert ids(buf, LogFilter.build(until="10m", now=NOW)) == [1, 2, 3, 4]   # until 08:50


def test_parse_window_defaults():
    assert parse_window(None, None) == (None, None)
    assert parse_window("", "") == (None, None)
    assert parse_window("1h", "now", now=NOW) == (NOW - 3600, NOW)


# ── caller mistakes ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("kwargs, message", [
    ({"since": "last tuesday"}, "since 'last tuesday' is neither"),
    ({"until": "5 parsecs"}, "until '5 parsecs' is neither"),
    ({"since": "1m", "until": "1h"}, "since lies after until"),
    ({"source": "10.0.0.0/33"}, "not a valid network"),
    ({"destination": "fd10::/129"}, "not a valid network"),
    ({"category": "firewall"}, "Unknown category 'firewall'"),
    ({"category": ["dns", "nope"]}, "Unknown category 'nope'"),
])
def test_invalid_values_raise_with_a_sentence(kwargs, message):
    with pytest.raises(ValueError, match=message):
        LogFilter.build(now=NOW, **kwargs)


# ── real dual-stack records ──────────────────────────────────────────────────

def _fixture_buffer() -> LogBuffer:
    b = LogBuffer(1000)
    for path in sorted(FIXTURES.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                row = parse_record(rec)
                assert row is not None
                b.append(row, rec)
    return b


def test_ipv6_fixture_records_by_prefix():
    b = _fixture_buffer()
    assert b.size == 138
    net = ipaddress.ip_network("fd10::/16")

    def inside(value: str) -> bool:
        try:
            return ipaddress.ip_address(value) in net
        except ValueError:
            return False

    by_source = ids(b, LogFilter.build(source="fd10::/16"))
    assert len(by_source) == 138   # every captured record comes from a spoke VM
    expected_dst = [i.id for i in b.snapshot() if inside(i.row.targetip)]
    assert expected_dst and ids(b, LogFilter.build(destination="fd10::/16")) == expected_dst
    # An IPv4 CIDR never matches an IPv6 address, and a narrower prefix narrows.
    assert ids(b, LogFilter.build(source="10.0.0.0/8")) == []
    assert 0 < len(ids(b, LogFilter.build(source="fd10:3:5:1::/64"))) <= 138
    # The expanded spelling Azure writes in AZFWNetworkRule finds the same rows as the compressed one.
    assert ids(b, LogFilter.build(source="fd10:0003:0005:0001:0000:0000:0000:0004")) == \
        ids(b, LogFilter.build(source="fd10:3:5:1::4"))
