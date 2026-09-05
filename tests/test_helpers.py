"""Tests for helpers.py."""
from __future__ import annotations

import os
import time

import pytest

from helpers import _category_text, _highlight, _parse_eventhub_endpoint, _to_local, load_env


@pytest.fixture
def utc_tz(monkeypatch):
    """Pin the process timezone to UTC so local-time conversion is deterministic."""
    monkeypatch.setenv("TZ", "UTC")
    if hasattr(time, "tzset"):
        time.tzset()
    yield
    if hasattr(time, "tzset"):
        time.tzset()


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
