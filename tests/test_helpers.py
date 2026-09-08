"""Tests for helpers.py."""
from __future__ import annotations

import os
import time

import pytest

from helpers import (
    _category_text,
    _highlight,
    _parse_eventhub_endpoint,
    _to_local,
    _utc_short,
    format_endpoint,
    load_env,
    split_endpoint,
)


@pytest.fixture
def utc_tz(monkeypatch):
    """Pin the process timezone to UTC so local-time conversion is deterministic."""
    monkeypatch.setenv("TZ", "UTC")
    if hasattr(time, "tzset"):
        time.tzset()
    yield
    if hasattr(time, "tzset"):
        time.tzset()


@pytest.mark.parametrize("raw, expected", [
    ("2026-09-07T16:14:09.903912+00:00", "2026-09-07T16:14:09Z"),   # ARM-style, six digits
    ("2026-09-05T08:00:00.5000000Z", "2026-09-05T08:00:00Z"),       # seven digits, Z suffix
    ("2026-09-05T08:00:00Z", "2026-09-05T08:00:00Z"),
    ("2026-09-05T10:00:00+02:00", "2026-09-05T08:00:00Z"),          # converted to UTC
    ("not a time", "not a time"),
])
def test_utc_short_trims_to_seconds(raw, expected):
    assert _utc_short(raw) == expected


def test_to_local_converts_iso_utc(utc_tz):
    assert _to_local("2026-09-05T08:00:00Z") == "2026-09-05 08:00:00"


def test_to_local_handles_fractional_seconds_and_offset(utc_tz):
    assert _to_local("2026-09-05T08:00:00.1234567+02:00") == "2026-09-05 06:00:00"


@pytest.mark.parametrize(
    "ts",
    [
        "2026-09-05T08:00:00.1234567Z",   # Azure diagnostics: 7 digits
        "2026-09-05T08:00:00.123456Z",    # 6 digits
        "2026-09-05T08:00:00.123Z",       # 3 digits
        "2026-09-05T08:00:00.1Z",         # 1 digit
    ],
)
def test_to_local_accepts_any_fraction_length(utc_tz, ts):
    """Regression: Python 3.10 could not parse Azure's 7-digit fractions and fell back to raw UTC."""
    assert _to_local(ts) == "2026-09-05 08:00:00"


def test_to_local_falls_back_to_prefix_on_garbage():
    assert _to_local("garbage") == "garbage"
    assert _to_local("x" * 30) == "x" * 19
    assert _to_local("") == ""


def test_highlight_marks_term_case_insensitively():
    text = _highlight("Hello World", "world")
    assert text.plain == "Hello World"
    assert any("reverse" in str(span.style) for span in text.spans)


def test_highlight_without_term_has_no_spans():
    assert _highlight("Hello", "").spans == []


def test_highlight_escapes_regex_metacharacters():
    text = _highlight("10.0.1.4", "10.0.1.4")
    assert any("reverse" in str(span.style) for span in text.spans)
    # a term like "(" must not raise
    _highlight("a(b", "(")


@pytest.mark.parametrize(
    "category, style",
    [
        ("NetworkRule", "cyan"),
        ("AppRule", "bright_blue"),
        ("NATRule", "yellow"),
        ("DnsQuery", "dark_orange3"),
        ("DnsFailure", "bold dark_orange3"),
        ("FlowTrace", "bright_black"),
        ("FatFlow", "bold cyan"),
        ("IDPS", "bold red"),
        ("ThreatIntel", "bold magenta"),
        ("Unknown", ""),
    ],
)
def test_category_text_style(category, style):
    text = _category_text(category)
    assert text.plain == category
    assert text.style == style


def test_parse_eventhub_endpoint_extracts_namespace_and_hub():
    conn = (
        "Endpoint=sb://my-ns.servicebus.windows.net/;"
        "SharedAccessKeyName=listen;SharedAccessKey=SECRET;EntityPath=firewall-logs"
    )
    ns, hub = _parse_eventhub_endpoint(conn)
    assert ns == "my-ns.servicebus.windows.net"
    assert hub == "firewall-logs"


def test_parse_eventhub_endpoint_never_returns_key():
    conn = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKey=SECRET;EntityPath=h"
    assert "SECRET" not in "".join(_parse_eventhub_endpoint(conn))


def test_parse_eventhub_endpoint_missing_parts():
    assert _parse_eventhub_endpoint("") == ("unknown", "unknown")
    assert _parse_eventhub_endpoint("EntityPath=h") == ("unknown", "h")


def test_load_env_reads_utf8_and_falls_back_to_latin1(tmp_path, monkeypatch):
    monkeypatch.delenv("AZFW_TEST_VALUE", raising=False)
    env = tmp_path / ".env"
    env.write_bytes("# Überschrift\nAZFW_TEST_VALUE=eins\n".encode("cp1252"))
    load_env(env)
    assert os.environ["AZFW_TEST_VALUE"] == "eins"
    env.write_text("AZFW_TEST_VALUE=zwei\n", encoding="utf-8")
    load_env(env)  # no override → keeps the first value
    assert os.environ["AZFW_TEST_VALUE"] == "eins"
    load_env(env, override=True)
    assert os.environ["AZFW_TEST_VALUE"] == "zwei"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("10.1.1.1:1234", ("10.1.1.1", "1234")),
        ("10.1.1.1", ("10.1.1.1", "-")),
        ("fd00::1", ("fd00::1", "-")),                     # bare IPv6, no port
        ("[fd00::1]:1234", ("fd00::1", "1234")),            # bracketed IPv6 + port
        ("example.com:443", ("example.com", "443")),
        ("example.com", ("example.com", "-")),
        ("-", ("-", "-")),
        ("", ("", "-")),
    ],
)
def test_split_endpoint(text, expected):
    assert split_endpoint(text) == expected


def test_split_endpoint_unbracketed_ipv6_with_port_is_the_ambiguous_case():
    """'fd00::1:1234' is, on its own, already a complete IPv6 address (1234 is a
    valid hex group) — the chosen heuristic still splits off the trailing ':1234'
    as a port because the part before it also parses as a valid IPv6 address, and
    every endpoint the legacy log format writes carries a port.
    """
    assert split_endpoint("fd00::1:1234") == ("fd00::1", "1234")


def test_format_endpoint_brackets_ipv6_only():
    assert format_endpoint("fd00::1", "1234") == "[fd00::1]:1234"
    assert format_endpoint("10.1.1.1", "1234") == "10.1.1.1:1234"
    assert format_endpoint("example.com", "443") == "example.com:443"


@pytest.mark.parametrize("port", ["-", ""])
def test_format_endpoint_without_port_returns_bare_address(port):
    assert format_endpoint("fd00::1", port) == "fd00::1"
    assert format_endpoint("10.1.1.1", port) == "10.1.1.1"


@pytest.mark.parametrize(
    "text, expected_out",
    [
        ("10.1.1.1:1234", "10.1.1.1:1234"),
        ("example.com:443", "example.com:443"),
        # round-trips to the bracketed form, not the original text: format_endpoint
        # always brackets IPv6, since real records may or may not do so themselves.
        ("fd00::1:1234", "[fd00::1]:1234"),
        ("[fd00::1]:1234", "[fd00::1]:1234"),
    ],
)
def test_split_then_format_endpoint(text, expected_out):
    address, port = split_endpoint(text)
    assert format_endpoint(address, port) == expected_out
