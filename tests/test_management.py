"""Orchestration of cache + ARM fetches (viewer/management.py) with everything faked."""
from __future__ import annotations

import time
from typing import Any

import pytest

import viewer.management as mgmt
from viewer.arm import ArmError
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, IpGroupInfo
from viewer.cache import CachedSnapshot

FW_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"
FW = FirewallInfo(id=FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc",
                  subnet_ids=["/sn1", "/sn2"], policy_id="/p")
POLICY = FirewallPolicyInfo(id="/p", name="pol", sku_tier="Premium")
GROUPS = {"/g": IpGroupInfo(id="/g", name="grp", location="gwc", ip_addresses=["10.0.0.0/8"])}


class FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class FakeCredential:
    instances: list["FakeCredential"] = []

    def __init__(self, **_kw: Any) -> None:
        self.closed = False
        FakeCredential.instances.append(self)

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def world(monkeypatch):
    """Fake every collaborator; returns a dict to tweak behaviour and inspect calls."""
    state: dict[str, Any] = {
        "cached": None, "saved": [], "invalidated": [], "calls": [],
        "firewall": FW, "policy": POLICY, "groups": GROUPS, "cidrs": ["10.2.0.0/26"],
    }
    FakeCredential.instances = []

    def load(fw_id):
        state["calls"].append(("load", fw_id))
        return state["cached"]

    def save(fw_id, snap):
        state["saved"].append((fw_id, snap))
        if isinstance(state.get("save_error"), Exception):
            raise state["save_error"]

    def invalidate(fw_id):
        state["invalidated"].append(fw_id)

    async def fetch_firewall(arm, fw_id):
        state["calls"].append(("firewall", fw_id))
        if isinstance(state["firewall"], Exception):
            raise state["firewall"]
        return state["firewall"]

    async def fetch_policy(arm, pid):
        state["calls"].append(("policy", pid))
        if isinstance(state["policy"], Exception):
            raise state["policy"]
        return state["policy"]

    async def fetch_ip_groups(arm, ids):
        state["calls"].append(("groups", ids))
        if isinstance(state["groups"], Exception):
            raise state["groups"]
        return state["groups"]

    async def fetch_all_subnet_cidrs(arm, ids):
        state["calls"].append(("cidrs", ids))
        return state["cidrs"]

    for name, fn in (("load", load), ("save", save), ("invalidate", invalidate),
                     ("fetch_firewall", fetch_firewall), ("fetch_policy", fetch_policy),
                     ("fetch_ip_groups", fetch_ip_groups), ("fetch_all_subnet_cidrs", fetch_all_subnet_cidrs)):
        monkeypatch.setattr(mgmt, name, fn)
    monkeypatch.setattr(mgmt, "collect_ip_group_ids", lambda policy: ["/g"])
    monkeypatch.setattr(mgmt.aiohttp, "ClientSession", FakeSession)
    import azure.identity.aio as ident
    monkeypatch.setattr(ident, "DefaultAzureCredential", FakeCredential)
    return state


async def test_fresh_cache_hit_skips_arm(world):
    world["cached"] = CachedSnapshot(firewall=FW, policy=POLICY, fetched_at=time.time())
    snap = await mgmt.load_management_data(FW_ID)
    assert snap is world["cached"]
    assert world["calls"] == [("load", FW_ID)]
    assert FakeCredential.instances == []


async def test_stale_cache_triggers_full_fetch_and_save(world):
    world["cached"] = CachedSnapshot(firewall=FW, policy=POLICY, fetched_at=time.time() - 10 ** 6)
    snap = await mgmt.load_management_data(FW_ID)
    assert snap is not world["cached"]
    assert snap.firewall is FW and snap.policy is POLICY
    assert snap.ip_groups == GROUPS and snap.subnet_cidrs == ["10.2.0.0/26"]
    assert time.time() - snap.fetched_at < 5
    assert [c[0] for c in world["calls"]] == ["load", "firewall", "policy", "cidrs", "groups"] or \
        [c[0] for c in world["calls"]] == ["load", "firewall", "cidrs", "policy", "groups"]
    assert world["saved"][0][0] == FW_ID
    assert world["invalidated"] == []
    assert FakeCredential.instances[0].closed


async def test_force_invalidates_and_skips_cache_read(world):
    world["cached"] = CachedSnapshot(firewall=FW, policy=POLICY, fetched_at=time.time())
    snap = await mgmt.load_management_data(FW_ID, force=True)
    assert world["invalidated"] == [FW_ID]
    assert ("load", FW_ID) not in world["calls"]
    assert snap.policy is POLICY


async def test_firewall_fetch_failure_returns_none_and_closes_credential(world):
    world["firewall"] = ArmError(403, "AuthorizationFailed", "denied")
    assert await mgmt.load_management_data(FW_ID) is None
    assert world["saved"] == []
    assert FakeCredential.instances[0].closed


async def test_policy_failure_is_tolerated(world):
    world["policy"] = ArmError(404, "NotFound", "gone")
    snap = await mgmt.load_management_data(FW_ID)
    assert snap is not None and snap.policy is None
    assert snap.ip_groups == {}  # no policy → no IP groups looked up
    assert ("groups", ["/g"]) not in world["calls"]


async def test_ip_group_failure_is_tolerated(world):
    world["groups"] = ArmError(403, "AuthorizationFailed", "denied")
    snap = await mgmt.load_management_data(FW_ID)
    assert snap is not None and snap.policy is POLICY and snap.ip_groups == {}


async def test_firewall_without_policy(world):
    world["firewall"] = FirewallInfo(id=FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc")
    snap = await mgmt.load_management_data(FW_ID)
    assert snap.policy is None and snap.ip_groups == {}
    assert not any(c[0] == "policy" for c in world["calls"])


async def test_cache_write_failure_does_not_lose_snapshot(world):
    world["save_error"] = OSError("read-only")
    snap = await mgmt.load_management_data(FW_ID)
    assert snap is not None and snap.firewall is FW


async def test_credential_construction_failure_still_fetches(world, monkeypatch):
    import azure.identity.aio as ident

    class _Boom:
        def __init__(self, **_kw):
            raise RuntimeError("no identity libs")

    monkeypatch.setattr(ident, "DefaultAzureCredential", _Boom)
    snap = await mgmt.load_management_data(FW_ID)  # ArmClient handles the az-CLI fallback itself
    assert snap is not None and snap.firewall is FW
