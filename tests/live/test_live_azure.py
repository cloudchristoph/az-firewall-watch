"""Optional live integration tests against a real Azure environment.

Skipped unless the corresponding environment variables are set, so the
default ``pytest`` run and CI never touch Azure. Run them explicitly, e.g.::

    AZFW_LIVE_FIREWALL_ID=/subscriptions/.../azureFirewalls/fw-hub \\
    AZFW_LIVE_EVENTHUB_NAMESPACE=my-ns.servicebus.windows.net \\
    AZFW_LIVE_EVENTHUB_NAME=firewall-logs \\
    pytest tests/live -m live

Requirements: an identity that ``DefaultAzureCredential`` (or the Azure CLI)
can use, with Reader on the firewall, its policy and IP groups, and
*Azure Event Hubs Data Receiver* on the hub. Only read operations are made.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

pytestmark = pytest.mark.live

FIREWALL_ID = os.environ.get("AZFW_LIVE_FIREWALL_ID", "")
EH_NAMESPACE = os.environ.get("AZFW_LIVE_EVENTHUB_NAMESPACE", "")
EH_NAME = os.environ.get("AZFW_LIVE_EVENTHUB_NAME", "")

needs_firewall = pytest.mark.skipif(not FIREWALL_ID, reason="set AZFW_LIVE_FIREWALL_ID to run")
needs_eventhub = pytest.mark.skipif(
    not (EH_NAMESPACE and EH_NAME), reason="set AZFW_LIVE_EVENTHUB_NAMESPACE and AZFW_LIVE_EVENTHUB_NAME to run",
)


@pytest.fixture
def private_cache(tmp_path, monkeypatch):
    """Never touch the developer's real ~/.az-firewall-watch/cache.json."""
    import viewer.cache as cache

    monkeypatch.setattr(cache, "cache_path", lambda: tmp_path / "cache.json")
    return tmp_path / "cache.json"


@needs_firewall
async def test_arm_roundtrip_firewall_policy_ip_groups(private_cache):
    """Fetch the real firewall, policy and IP groups; verify the model and the cache."""
    from viewer.enrichment import resolve_fw_instance
    from viewer.management import load_management_data

    t0 = time.perf_counter()
    snap = await load_management_data(FIREWALL_ID, force=True)
    elapsed = time.perf_counter() - t0
    assert snap is not None, "no ARM access — check DefaultAzureCredential / az login and Reader role"

    fw = snap.firewall
    assert fw.name and fw.location and fw.subscription_id and fw.resource_group
    assert fw.sku_tier in ("Standard", "Premium", "Basic"), fw.sku_tier
    assert fw.subnet_ids, "firewall should have at least one subnet"
    assert snap.subnet_cidrs, "firewall subnets should resolve to CIDRs"
    for ip in fw.private_ips:
        assert resolve_fw_instance(ip, snap.subnet_cidrs) is not None, f"{ip} should lie inside a firewall subnet"

    if fw.policy_id:
        assert snap.policy is not None and snap.policy.name
        assert snap.policy.sku_tier in ("Standard", "Premium", "Basic")
        for gid in {g for grp in snap.policy.rule_collection_groups for rc in grp.rule_collections
                    for r in rc.rules for g in r.source_ip_groups + r.destination_ip_groups}:
            # every referenced group we could read has a name and parses as a network list
            if gid in snap.ip_groups:
                assert snap.ip_groups[gid].name

    # the snapshot was written to the (private) cache and is served from there next time
    assert private_cache.exists()
    assert json.loads(private_cache.read_text())["entries"][FIREWALL_ID]["firewall"]["name"] == fw.name
    t1 = time.perf_counter()
    cached = await load_management_data(FIREWALL_ID)
    assert cached is not None and cached.fetched_at == snap.fetched_at
    assert time.perf_counter() - t1 < elapsed / 2, "cache hit should be much faster than the ARM fetch"


@needs_eventhub
async def test_eventhub_delivers_parseable_firewall_records():
    """Receive from the hub's retention start and check the parser understands the records."""
    from azure.core.pipeline.transport import AsyncioRequestsTransport
    from azure.eventhub.aio import EventHubConsumerClient
    from azure.identity.aio import DefaultAzureCredential

    from fw_parser import parse_record
    from viewer.streaming import resolve_start_position

    credential = DefaultAzureCredential(transport=AsyncioRequestsTransport())
    client = EventHubConsumerClient(
        fully_qualified_namespace=EH_NAMESPACE, eventhub_name=EH_NAME,
        consumer_group=os.environ.get("AZFW_LIVE_CONSUMER_GROUP", "$Default"), credential=credential,
    )
    parsed: list = []
    skipped: list = []

    async def on_event(_ctx, event):
        if event is None:
            return
        for rec in json.loads(event.body_as_str()).get("records", []):
            row = parse_record(rec)
            (skipped if row.category.startswith("SKIP:") else parsed).append(row)

    try:
        async with client:
            task = asyncio.ensure_future(client.receive(on_event=on_event, starting_position=resolve_start_position("earliest")))
            deadline = time.time() + 45
            while time.time() < deadline and len(parsed) < 20:
                await asyncio.sleep(0.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    finally:
        await credential.close()

    assert parsed, "no firewall records received within 45 s — is the diagnostic setting active?"
    categories = {r.category for r in parsed}
    assert categories <= {"NetworkRule", "AppRule", "NATRule", "DnsQuery", "DnsFailure", "IDPS", "ThreatIntel", "FlowTrace", "FatFlow"}
    assert all(r.time and r.sourceip for r in parsed)
    # Unknown categories are allowed (e.g. aggregation logs) but parse errors are not.
    assert not [r for r in skipped if r.category.startswith("SKIP:ParseErr")], "parser rejected real records"
