"""The Logging block: a category × target matrix, the connected Event Hub,
and the one coverage line that says whether it carries what this firewall
can produce and this viewer shows."""
from __future__ import annotations

import pytest

from viewer.azure_resources import DiagnosticSetting, FirewallInfo, FirewallPolicyInfo
from viewer.views.firewall import (
    FAT_FLOW_KEY,
    VIEWER_CATEGORIES,
    _coverage_row,
    _row,
    connected_event_hub,
    connected_event_hub_targets,
    expected_categories,
    logging_targets,
)

pytestmark = pytest.mark.usefixtures("no_eventhub_env")


def _fw(**props: str) -> FirewallInfo:
    return FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                        sku_tier="Premium", additional_properties=dict(props))


def _policy(*, tier="Premium", dns_proxy=True, idps="Alert", ti="Alert") -> FirewallPolicyInfo:
    return FirewallPolicyInfo(id="/p", name="p", sku_tier=tier, dns_proxy=dns_proxy, idps_mode=idps,
                              threat_intel_mode=ti)


def _eh(name="d-eh", hub="ehns-fw-gwc/firewall-logs", categories=None, all_logs=False) -> DiagnosticSetting:
    return DiagnosticSetting(name=name, event_hub=hub, categories=list(categories or []), all_logs=all_logs)


# ── targets and headers ────────────────────────────────────────────────────────

def test_logging_targets_one_column_per_setting_and_target_numbered_when_a_kind_repeats():
    diags = [
        DiagnosticSetting(name="to-law", workspace="law-cclab", all_logs=True),
        DiagnosticSetting(name="to-storage", storage="stfwlogs", all_logs=True),
        _eh("legacy", hub="ehns-fw-gwc/firewall-logs-legacy", categories=["AzureFirewallNetworkRule"]),
        _eh("to-eh", categories=VIEWER_CATEGORIES),
        DiagnosticSetting(name="both", workspace="law-other", storage="stother", categories=["AZFWNatRule"]),
    ]
    targets = logging_targets(diags)
    assert [t.header for t in targets] == ["LAW ①", "Storage ①", "EH ①", "EH ②", "LAW ②", "Storage ②"]
    assert [t.long_kind for t in targets][:3] == ["Log Analytics", "Storage", "Event Hub"]
    assert targets[4].setting is diags[4] and targets[5].setting is diags[4]   # one setting, two columns


def test_logging_targets_single_kind_keeps_the_bare_header():
    targets = logging_targets([_eh(), DiagnosticSetting(name="law", workspace="law-cclab")])
    assert [t.header for t in targets] == ["EH", "LAW"]


# ── the connected hub ──────────────────────────────────────────────────────────

def test_connected_event_hub_from_entra_settings(monkeypatch):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "ehns-fw-gwc.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    assert connected_event_hub() == ("ehns-fw-gwc", "firewall-logs")


def test_connected_event_hub_from_connection_string_with_entity_path(monkeypatch):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING",
                       "Endpoint=sb://ehns-fw-gwc.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=x;EntityPath=firewall-logs")
    assert connected_event_hub() == ("ehns-fw-gwc", "firewall-logs")


def test_connected_event_hub_unknown_without_configuration():
    assert connected_event_hub() == ("", "")


def test_connected_targets_match_the_configured_hub_only(monkeypatch):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "ehns-fw-gwc.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    targets = logging_targets([_eh("legacy", hub="ehns-fw-gwc/firewall-logs-legacy"), _eh("ours"),
                               _eh("elsewhere", hub="ehns-other/firewall-logs")])
    assert [t.setting.name for t in connected_event_hub_targets(targets)] == ["ours"]


def test_connected_targets_fall_back_to_every_event_hub_when_not_identifiable():
    targets = logging_targets([_eh("a"), _eh("b", hub="ns/other"), DiagnosticSetting(name="law", workspace="w")])
    assert [t.setting.name for t in connected_event_hub_targets(targets)] == ["a", "b"]


# ── what the hub should carry ──────────────────────────────────────────────────

def test_expected_categories_follow_sku_and_switches():
    full = expected_categories(_policy(), _fw(**{FAT_FLOW_KEY: "true"}))
    assert full == [c for c in VIEWER_CATEGORIES if c != "AZFWFlowTrace"]
    standard = expected_categories(_policy(tier="Standard", dns_proxy=False, idps="", ti="Off"), _fw())
    assert standard == ["AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule", "AZFWFqdnResolveFailure"]


def test_expected_categories_without_a_policy_use_the_classic_switches():
    fw = _fw(**{"Network.DNS.EnableProxy": "true"})
    fw.threat_intel_mode = "Deny"
    assert "AZFWDnsQuery" in expected_categories(None, fw)
    assert "AZFWThreatIntel" in expected_categories(None, fw)
    assert "AZFWIdpsSignature" not in expected_categories(None, fw)


# ── the coverage line ──────────────────────────────────────────────────────────

def test_coverage_complete_names_the_optional_category_that_is_not_forwarded():
    targets = logging_targets([_eh(categories=[c for c in VIEWER_CATEGORIES if c != "AZFWFlowTrace"])])
    line = _coverage_row(connected_event_hub_targets(targets), _policy(), _fw(**{FAT_FLOW_KEY: "true"}))
    assert line.startswith(_row("Event Hub coverage", "[green]complete[/]"))
    assert "AZFWFlowTrace absent, not counted" in line and "incomplete" not in line


def test_coverage_complete_with_all_logs_has_nothing_to_add():
    line = _coverage_row(connected_event_hub_targets(logging_targets([_eh(all_logs=True)])), _policy(), _fw())
    assert line == _row("Event Hub coverage", "[green]complete[/]")


def test_coverage_incomplete_lists_only_what_this_firewall_can_produce():
    targets = logging_targets([_eh(categories=["AZFWNetworkRule", "AZFWApplicationRule"])])
    line = _coverage_row(connected_event_hub_targets(targets), _policy(tier="Standard", dns_proxy=False, idps="", ti="Off"), _fw())
    assert line == _row("Event Hub coverage", "[yellow]incomplete, missing AZFWNatRule, AZFWFqdnResolveFailure[/]")


def test_coverage_premium_features_count_when_the_policy_uses_them():
    targets = logging_targets([_eh(categories=["AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule",
                                                "AZFWFqdnResolveFailure"])])
    line = _coverage_row(connected_event_hub_targets(targets), _policy(), _fw(**{FAT_FLOW_KEY: "true"}))
    assert "missing AZFWThreatIntel, AZFWIdpsSignature, AZFWDnsQuery, AZFWFatFlow" in line


def test_coverage_without_any_event_hub_target_is_incomplete(monkeypatch):
    targets = logging_targets([DiagnosticSetting(name="law", workspace="w", all_logs=True)])
    assert "incomplete: no diagnostic setting targets an Event Hub" in _coverage_row(
        connected_event_hub_targets(targets), _policy(), _fw())
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "ehns-fw-gwc.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    line = _coverage_row(connected_event_hub_targets(logging_targets([_eh(hub="ehns-fw-gwc/other")])), _policy(), _fw())
    assert "no diagnostic setting targets the connected Event Hub ehns-fw-gwc/firewall-logs" in line
