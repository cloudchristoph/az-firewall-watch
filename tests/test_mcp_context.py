"""ContextHolder (mcp_server/context.py) with the ARM loader replaced by a fake."""
from __future__ import annotations

import time
from typing import Any

import pytest

from fw_parser import parse_record
from mcp_server.buffer import LogBuffer
from mcp_server.context import ContextHolder
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, Rule, RuleCollection, RuleCollectionGroup
from viewer.cache import DEFAULT_TTL_SECONDS, CachedSnapshot


def snapshot(*, age: float = 0.0, with_policy: bool = True) -> CachedSnapshot:
    policy = None
    if with_policy:
        rule = Rule(name="allow-web", rule_type="NetworkRule", source_addresses=["*"],
                    destination_addresses=["*"], destination_ports=["443"], protocols=["TCP"])
        rc = RuleCollection(name="rc-allow", priority=200, action="Allow",
                            rule_collection_type="FirewallPolicyFilterRuleCollection", rules=[rule])
        policy = FirewallPolicyInfo(id="/pol", name="fw-pol",
                                    rule_collection_groups=[RuleCollectionGroup(id="/rcg", name="rcg-net", priority=100,
                                                                                 rule_collections=[rc])])
    fw = FirewallInfo(id="/fw", name="fw-hub", subscription_id="sub", resource_group="rg", location="gwc")
    return CachedSnapshot(firewall=fw, policy=policy, fetched_at=time.time() - age)


class FakeLoader:
    def __init__(self, *results: Any) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, bool]] = []

    async def __call__(self, firewall_id: str, *, force: bool = False, errors: list[str] | None = None):
        self.calls.append((firewall_id, force))
        result = self.results.pop(0) if self.results else None
        if isinstance(result, Exception):
            raise result
        if isinstance(result, str):
            if errors is not None:
                errors.append(result)
            return None
        return result


def logged_row(structured_record, rule: str = "allow-web"):
    rec = structured_record("AZFWNetworkRule", Protocol="TCP", SourceIp="10.0.0.1", SourcePort=1,
                            DestinationIp="10.1.0.1", DestinationPort=443, Action="Allow", Policy="fw-pol",
                            RuleCollectionGroup="rcg-net", RuleCollection="rc-allow", Rule=rule)
    row = parse_record(rec)
    assert row is not None
    buf = LogBuffer(10)
    return [buf.append(row, rec)]


async def test_off_never_loads(firewall_id):
    loader = FakeLoader(snapshot())
    holder = ContextHolder(enabled=False, firewall_id=firewall_id, loader=loader)
    holder.start()
    holder.set_firewall_id(firewall_id)
    status = await holder.refresh(force=True)
    assert loader.calls == []
    assert status["state"] == "off" and "switched off" in status["reason"]
    answer = holder.unavailable_answer()
    assert answer["available"] is False and answer["state"] == "off" and "--no-policy-context" in answer["hint"]


async def test_waits_for_firewall_id_then_loads(firewall_id):
    loader = FakeLoader(snapshot())
    holder = ContextHolder(enabled=True, loader=loader)
    holder.start()
    assert holder.state == "waiting_for_firewall_id"
    assert "first log record" in holder.status()["reason"]
    assert holder.unavailable_answer()["state"] == "waiting_for_firewall_id"
    holder.set_firewall_id(firewall_id)
    assert holder.state == "loading"
    await holder.wait_idle()
    assert holder.state == "loaded" and holder.loaded
    assert loader.calls == [(firewall_id, False)]
    assert holder.known_rules == {("rcg-net", "rc-allow", "allow-web")}
    status = holder.status()
    assert status["reason"] is None and status["age_s"] is not None and status["fetched_at"].endswith("Z")
    holder.set_firewall_id(firewall_id.replace("FW-HUB", "FW-OTHER"))   # only the first id counts
    await holder.wait_idle()
    assert len(loader.calls) == 1 and holder.firewall_id == firewall_id


async def test_configured_firewall_id_loads_at_start(firewall_id):
    loader = FakeLoader(snapshot())
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader)
    assert holder.state == "loading"
    holder.start()
    await holder.wait_idle()
    assert holder.state == "loaded" and loader.calls == [(firewall_id, False)]


async def test_unavailable_with_reason(firewall_id):
    loader = FakeLoader("ARM 403: AuthorizationFailed on /fw")
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader)
    status = await holder.refresh(force=False)
    assert status["state"] == "unavailable"
    assert status["reason"] == "ARM 403: AuthorizationFailed on /fw"
    answer = holder.unavailable_answer()
    assert answer["reason"] == status["reason"] and "Reader" in answer["hint"]


async def test_loader_crash_is_unavailable_not_fatal(firewall_id):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=FakeLoader(RuntimeError("boom")))
    status = await holder.refresh()
    assert status["state"] == "unavailable" and status["reason"] == "boom"


async def test_forced_refresh_replaces_snapshot(firewall_id):
    first, second = snapshot(age=500), snapshot()
    loader = FakeLoader(first, second)
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader)
    await holder.refresh(force=False)
    assert holder.snapshot is first
    await holder.refresh(force=True)
    assert holder.snapshot is second
    assert loader.calls == [(firewall_id, False), (firewall_id, True)]


async def test_failed_refresh_keeps_previous_snapshot(firewall_id):
    snap = snapshot()
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=FakeLoader(snap, "network down"))
    await holder.refresh(force=False)
    status = await holder.refresh(force=True)
    assert holder.snapshot is snap
    assert status["state"] == "loaded"
    assert status["reason"].startswith("Refresh failed") and "network down" in status["reason"]


async def test_snapshot_without_policy_is_loaded(firewall_id):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=FakeLoader(snapshot(with_policy=False)))
    await holder.refresh(force=False)
    assert holder.state == "loaded" and holder.known_rules == frozenset()


# ── automatic refresh on an unknown rule ─────────────────────────────────────

async def test_unknown_rule_refreshes_once_per_minute(firewall_id, structured_record):
    loader = FakeLoader(snapshot(age=120), snapshot(age=120), snapshot())
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader)
    await holder.refresh(force=False)
    assert holder.note_rows(logged_row(structured_record, "allow-web")) is False   # known rule
    assert holder.note_rows(logged_row(structured_record, "brand-new")) is True
    await holder.wait_idle()
    assert loader.calls[-1] == (firewall_id, True)
    # Still unknown and still old, but the last automatic refresh was just now.
    assert holder.note_rows(logged_row(structured_record, "brand-new")) is False
    assert len(loader.calls) == 2


async def test_unknown_rule_in_a_young_snapshot_does_not_refresh(firewall_id, structured_record):
    loader = FakeLoader(snapshot(age=5))
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader)
    await holder.refresh(force=False)
    assert holder.note_unknown_rule("brand-new") is False
    assert holder.note_rows(logged_row(structured_record, "brand-new")) is False
    assert len(loader.calls) == 1


async def test_unknown_rule_refreshes_again_after_the_interval(firewall_id):
    loader = FakeLoader(snapshot(age=120), snapshot(age=120), snapshot(age=120))
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader, auto_refresh_interval=0.0)
    await holder.refresh(force=False)
    assert holder.note_unknown_rule("a") is True
    await holder.wait_idle()
    assert holder.note_unknown_rule("a") is True
    await holder.wait_idle()
    assert len(loader.calls) == 3


async def test_unknown_rule_before_load_does_nothing(firewall_id):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=FakeLoader())
    assert holder.note_unknown_rule("x") is False


async def test_expired_cache_refreshes(firewall_id):
    loader = FakeLoader(snapshot(age=DEFAULT_TTL_SECONDS + 10), snapshot())
    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=loader)
    await holder.refresh(force=False)
    assert holder.check_cache_age() is True
    await holder.wait_idle()
    assert loader.calls[-1] == (firewall_id, True)
    assert holder.check_cache_age() is False   # fresh now


async def test_default_loader_is_viewer_management(monkeypatch, firewall_id):
    import viewer.management as management

    calls: list[tuple[str, bool]] = []

    async def _load(fid, *, force=False, errors=None):
        calls.append((fid, force))
        return snapshot()

    monkeypatch.setattr(management, "load_management_data", _load)
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    await holder.refresh(force=False)
    assert calls == [(firewall_id, False)] and holder.loaded


async def test_aclose_cancels_a_running_load(firewall_id):
    import asyncio

    started = asyncio.Event()

    async def _slow(fid, *, force=False, errors=None):
        started.set()
        await asyncio.sleep(60)

    holder = ContextHolder(enabled=True, firewall_id=firewall_id, loader=_slow)
    holder.start()
    await asyncio.wait_for(started.wait(), 1)
    await holder.aclose()
    assert holder.state == "loading" and holder.reason is None   # cancelled, not failed


@pytest.mark.parametrize("enabled, fid, expected", [(False, None, "off"), (True, None, "waiting_for_firewall_id")])
def test_initial_states(enabled, fid, expected):
    assert ContextHolder(enabled=enabled, firewall_id=fid).state == expected
