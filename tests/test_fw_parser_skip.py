"""Records the parser must skip (and count) instead of displaying."""
from __future__ import annotations

import pytest

from fw_parser import parse_record


def test_non_firewall_resource_is_skipped(structured_record):
    rec = structured_record("AZFWNetworkRule", SourceIp="10.0.0.1")
    rec["resourceId"] = "/SUBSCRIPTIONS/x/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKS/vnet"
    row = parse_record(rec)
    assert row.category == "SKIP:ResourceType"


def test_resource_id_match_is_case_insensitive(structured_record):
    rec = structured_record("AZFWNetworkRule")
    rec["resourceId"] = rec["resourceId"].lower()
    assert parse_record(rec).category == "NetworkRule"


@pytest.mark.parametrize("category", ["AZFWDnsAdditional", "AZFWNetworkRuleAggregation", "AzureFirewallMetrics", ""])
def test_unknown_category_is_skipped_with_name(structured_record, category):
    row = parse_record(structured_record(category))
    assert row.category == f"SKIP:Category:{category}"


def test_skip_rows_keep_timestamp(structured_record):
    row = parse_record(structured_record("AZFWDnsAdditional", time="2026-01-02T03:04:05Z"))
    assert row.time == "2026-01-02T03:04:05Z"


def test_empty_record_does_not_raise():
    row = parse_record({})
    assert row is not None
    assert row.category == "SKIP:ResourceType"


def test_record_without_properties_is_tolerated(firewall_id):
    row = parse_record({"resourceId": firewall_id, "category": "AZFWNetworkRule", "time": "t"})
    assert row.category == "NetworkRule"
