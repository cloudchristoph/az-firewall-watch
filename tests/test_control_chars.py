"""Control characters from Event Hub records never reach the terminal.

Rich and Textual drop only BEL, BS, VT, FF and CR; an ESC in an FQDN, a URL or
a rule name would otherwise be written to the terminal verbatim and run there
(OSC 52 clipboard write, CSI cursor moves, OSC 8 links, window title).
"""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import pytest

import fw_parser
from fw_parser import parse_record
from helpers import DISPLAY_PLACEHOLDER, display_safe, escape_markup, escape_rich_markup

FIXTURES = Path(__file__).parent / "fixtures" / "ipv6"

OSC52 = "\x1b]52;c;QUJD\x07"
CLEAR = "\x1b[2J"
C1_CSI = "\x9b31m"
HOSTILE = [OSC52, CLEAR, C1_CSI, "\x1b]8;;https://e\x1b\\x\x1b]8;;\x1b\\", "\x00", "\x7f", "\x9d0;title\x9c",
           "‮exe.txt", "a⁦b⁩"]


def _unsafe(value: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F or ch in "‪‫‬‭‮⁦⁧⁨⁩"
               for ch in value)


def _row_strings(row) -> list[str]:
    return [getattr(row, f.name) for f in fields(row) if isinstance(getattr(row, f.name), str)]


@pytest.mark.parametrize("payload", HOSTILE)
def test_display_safe_leaves_nothing_a_terminal_acts_on(payload):
    out = display_safe(f"host{payload}.example")
    assert not _unsafe(out)
    assert DISPLAY_PLACEHOLDER in out and out.startswith("host") and out.endswith(".example")


def test_display_safe_turns_a_tab_into_a_space_and_keeps_ordinary_text():
    assert display_safe("a\tb") == "a b"
    for value in ("", "www.example.com", "10.2.0.4", "fd10:3:5:1::4", "https://example.com/p?q=1&r=[2]",
                  "allow-web", "Ünïcödé · » ✓", "مرحبا", "Default Action"):
        assert display_safe(value) == value


def test_the_escape_helpers_sanitise_too():
    assert not _unsafe(escape_markup(OSC52 + "[/x"))
    assert not _unsafe(escape_rich_markup(OSC52 + "[/x"))


def test_structured_records_come_out_without_esc_or_c1(structured_record):
    records = [
        structured_record("AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.0.1", SourcePort=1,
                          Fqdn=f"evil{OSC52}.example", DestinationPort=443, TargetUrl=f"https://e/{CLEAR}",
                          Action="Allow", Policy="p", RuleCollectionGroup=f"g{C1_CSI}", RuleCollection="rc",
                          Rule=f"r{OSC52}", ActionReason=CLEAR),
        structured_record("AZFWNetworkRule", Protocol=f"TCP{C1_CSI}", SourceIp="10.0.0.1", SourcePort=1,
                          DestinationIp="10.0.0.2", DestinationPort=f"443{CLEAR}", Action=f"Allow{OSC52}",
                          ActionReason=f"Default{C1_CSI}"),
        structured_record("AZFWDnsQuery", SourceIp="10.0.0.1", SourcePort=1, QueryName=f"q{OSC52}.example.",
                          QueryType="A", ResponseCode=C1_CSI, ErrorMessage=CLEAR),
        structured_record("AZFWThreatIntel", SourceIp="10.0.0.1", Fqdn=f"ti{CLEAR}.example",
                          ThreatDescription=OSC52, Action="Deny"),
        structured_record("AZFWIdpsSignature", SourceIp="10.0.0.1", Description=f"d{OSC52}", Category=C1_CSI,
                          Severity=1, SignatureId=2, Action="alert"),
        structured_record("AZFWFqdnResolveFailure", Fqdn=f"f{OSC52}.example", Error=CLEAR, Rule=C1_CSI),
        structured_record("AZFWFlowTrace", SourceIp="10.0.0.1", SourcePort=1, DestinationIp="10.0.0.2",
                          DestinationPort=2, Flag=f"SYN{CLEAR}", ActionReason=OSC52),
        structured_record(f"AZFWUnknown{OSC52}"),
    ]
    for record in records:
        row = parse_record(record)
        assert row is not None
        for value in _row_strings(row):
            assert not _unsafe(value), (record["category"], value)
    app = parse_record(records[0])
    assert app is not None
    assert app.targetip == f"evil{DISPLAY_PLACEHOLDER}]52;c;QUJD{DISPLAY_PLACEHOLDER}.example"


def test_legacy_records_come_out_without_esc_or_c1(legacy_record):
    records = [
        legacy_record("AzureFirewallApplicationRule", "AzureFirewallApplicationRuleLog",
                      f"HTTPS request from 10.1.1.1:55583 to evil{OSC52}.example:443. Action: Allow. "
                      f"Policy: P. Rule Collection Group: G{C1_CSI}. Rule Collection: RC. Rule: R{CLEAR}. "
                      f"Url: https://e/{OSC52}"),
        legacy_record("AzureFirewallNetworkRule", "AzureFirewallNetworkRuleLog",
                      f"TCP{C1_CSI} request from 10.1.1.1:1234 to 10.2.2.2:80. Action: Deny{OSC52}."),
        legacy_record("AzureFirewallDnsProxy", "AzureFirewallDnsProxyLog",
                      f"DNS Request: 10.2.0.6:5350 - 10407 A IN q{OSC52}.example. udp 40 false 1232 {C1_CSI} "
                      "qr,aa,rd,ra 56 0.000324423s"),
        legacy_record("AzureFirewallNetworkRule", "AzureFirewallDNSResolutionFailureLog",
                      f"Failed to resolve FQDN f{CLEAR}.example. Error {OSC52} Rule Collection: p:g:rc. Rule: r"),
        legacy_record("AzureFirewallNetworkRule", f"Unparseable{OSC52}", "garbage"),
    ]
    for record in records:
        row = parse_record(record)
        assert row is not None
        for value in _row_strings(row):
            assert not _unsafe(value), (record["operationName"], value)


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.jsonl")))
def test_real_records_are_unchanged_by_the_sanitising(name):
    with (FIXTURES / name).open(encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    assert records
    for record in records:
        raw = fw_parser._parse_record(record)
        row = parse_record(record)
        assert raw is not None and row is not None
        assert _row_strings(row)[1:] == _row_strings(raw)[1:]   # rowid is a fresh counter value
