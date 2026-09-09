"""The firewall's additionalProperties bag rendered as proper rows on the Instance panel."""
from __future__ import annotations

import pytest

from viewer.azure_resources import ROUTE_SERVER_KEY, FirewallInfo
from viewer.views.firewall import (
    ACTIVE_FTP_KEY,
    CLASSIC_DNS_PROXY_KEY,
    CLASSIC_DNS_SERVERS_KEY,
    CLASSIC_SNAT_KEY,
    DNS_FLOW_TRACE_KEY,
    FAT_FLOW_KEY,
    FirewallView,
    _additional_property_rows,
    _row,
)


def _fw(**props: str) -> FirewallInfo:
    return FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                        additional_properties=props)


def test_empty_bag_shows_only_fat_flow_logging_and_no_additional_line():
    assert _additional_property_rows(_fw()) == [_row("Fat flow logging", "off   [dim]not set[/]")]


@pytest.mark.parametrize("value,expected", [("true", "on"), ("True", "on"), ("false", "off"), ("maybe", "maybe")])
def test_fat_flow_logging_row(value, expected):
    rows = _additional_property_rows(_fw(**{FAT_FLOW_KEY: value}))
    assert rows[0] == _row("Fat flow logging", expected)


def test_dns_flow_trace_row_only_when_the_key_is_present():
    assert not any("DNS flow trace" in r for r in _additional_property_rows(_fw()))
    rows = _additional_property_rows(_fw(**{DNS_FLOW_TRACE_KEY: "true"}))
    assert _row("DNS flow trace", "on") in rows


def test_active_ftp_row_only_when_the_key_is_present():
    rows = _additional_property_rows(_fw(**{ACTIVE_FTP_KEY: "True"}))
    assert _row("Active FTP", "on") in rows
    assert not any("Active FTP" in r for r in _additional_property_rows(_fw()))


def test_classic_dns_proxy_and_snat_rows():
    rows = _additional_property_rows(_fw(**{CLASSIC_DNS_PROXY_KEY: "true", CLASSIC_DNS_SERVERS_KEY: "10.0.0.53",
                                             CLASSIC_SNAT_KEY: "10.0.0.0/8, 172.16.0.0/12"}))
    assert _row("DNS proxy (classic)", "on   [dim]servers: 10.0.0.53[/]") in rows
    assert _row("SNAT ranges (classic)", "10.0.0.0/8, 172.16.0.0/12") in rows


def test_unknown_keys_stay_visible_under_additional_and_known_ones_are_not_repeated():
    rows = _additional_property_rows(_fw(**{FAT_FLOW_KEY: "true", ROUTE_SERVER_KEY: "/rs",
                                             "Network.Future.Switch": "42", "Other": "[b]x[/]"}))
    additional = [r for r in rows if "Additional" in r]
    assert len(additional) == 1
    assert "Network.Future.Switch=42" in additional[0] and "Other=\\[b]x\\[/]" in additional[0]
    assert "EnableFatFlowLogging" not in additional[0] and "RouteServer" not in additional[0]


def test_instance_panel_places_the_switches_after_maintenance_and_before_the_resource_group():
    fw = _fw(**{FAT_FLOW_KEY: "true", ACTIVE_FTP_KEY: "true"})
    labels = [r.split("[/]", 1)[0].replace("[dim]", "").strip() for r in FirewallView._instance(fw, [])]
    assert labels.index("Fat flow logging") == labels.index("Maintenance") + 1
    assert labels.index("Active FTP") == labels.index("Resource group") - 1
    assert "Additional" not in labels
