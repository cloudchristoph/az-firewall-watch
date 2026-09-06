"""On-disk metadata cache (viewer/cache.py)."""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

import viewer.cache as cache
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup

FW_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"


@pytest.fixture
def cache_file(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "cache.json"
    monkeypatch.setattr(cache, "cache_path", lambda: path)
    return path


def _snapshot(fetched_at: float | None = None) -> cache.CachedSnapshot:
    fw = FirewallInfo(id=FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_tier="Premium", private_ips=["10.2.0.4"], subnet_ids=["/sn"], policy_id="/p")
    policy = FirewallPolicyInfo(id="/p", name="pol", sku_tier="Premium", threat_intel_mode="Alert", rule_collection_groups=[
        RuleCollectionGroup(id="/g", name="rcg", priority=100, rule_collections=[
            RuleCollection(name="rc", priority=200, action="Allow", rule_collection_type="Filter", rules=[
                Rule(name="r", rule_type="NetworkRule", source_ip_groups=["/ipg"], destination_ports=["443"], protocols=["TCP"]),
            ]),
        ]),
    ])
    groups = {"/ipg": IpGroupInfo(id="/ipg", name="grp", location="gwc", ip_addresses=["10.3.0.0/16"])}
    return cache.CachedSnapshot(firewall=fw, policy=policy, ip_groups=groups, subnet_cidrs=["10.2.0.0/26"],
                                fetched_at=time.time() if fetched_at is None else fetched_at)


def test_round_trip_preserves_everything(cache_file):
    snap = _snapshot()
    cache.save(FW_ID, snap)
    loaded = cache.load(FW_ID)
    assert loaded is not None
    assert loaded.firewall == snap.firewall
    assert loaded.policy == snap.policy
    assert loaded.ip_groups == snap.ip_groups
    assert loaded.subnet_cidrs == ["10.2.0.0/26"]
    assert loaded.fetched_at == snap.fetched_at
    assert loaded.is_fresh()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_cache_file_is_private(cache_file):
    cache.save(FW_ID, _snapshot())
    assert stat.S_IMODE(os.stat(cache_file).st_mode) == 0o600


def test_multiple_firewalls_share_one_file(cache_file):
    cache.save(FW_ID, _snapshot())
    cache.save("/other", _snapshot())
    data = json.loads(cache_file.read_text())
    assert set(data["entries"]) == {FW_ID, "/other"}
    assert data["_version"] == cache._CACHE_VERSION


def test_missing_and_unknown_entries(cache_file):
    assert cache.load(FW_ID) is None
    cache.save("/other", _snapshot())
    assert cache.load(FW_ID) is None


def test_corrupt_file_is_ignored(cache_file):
    cache_file.write_text("{not json")
    assert cache.load(FW_ID) is None
    cache.save(FW_ID, _snapshot())  # overwrites the corrupt file
    assert cache.load(FW_ID) is not None


def test_version_mismatch_is_ignored_and_reset(cache_file):
    cache_file.write_text(json.dumps({"_version": 999, "entries": {FW_ID: {"firewall": {}}}}))
    assert cache.load(FW_ID) is None
    cache.save(FW_ID, _snapshot())
    assert json.loads(cache_file.read_text())["_version"] == cache._CACHE_VERSION


def test_ttl(cache_file):
    old = _snapshot(fetched_at=time.time() - cache.DEFAULT_TTL_SECONDS - 5)
    assert not old.is_fresh()
    assert old.age_seconds() > cache.DEFAULT_TTL_SECONDS
    assert old.is_fresh(ttl=10 ** 9)


def test_policy_less_snapshot(cache_file):
    snap = _snapshot()
    snap.policy = None
    cache.save(FW_ID, snap)
    loaded = cache.load(FW_ID)
    assert loaded is not None and loaded.policy is None


def test_invalidate_removes_only_that_entry(cache_file):
    cache.save(FW_ID, _snapshot())
    cache.save("/other", _snapshot())
    cache.invalidate(FW_ID)
    assert cache.load(FW_ID) is None
    assert cache.load("/other") is not None
    cache.invalidate("/never-there")  # no error
    cache_file.unlink()
    cache.invalidate(FW_ID)  # no file → no error


def test_hydrate_tolerates_missing_optional_fields(cache_file):
    entry = {"firewall": {"id": FW_ID, "name": "fw", "subscription_id": "s", "resource_group": "rg", "location": "gwc"},
             "policy": {"id": "/p", "name": "p", "rule_collection_groups": [{"name": "g", "rule_collections": [{"name": "rc", "rules": [{"name": "r"}]}]}]},
             "fetched_at": 1.0}
    cache_file.write_text(json.dumps({"_version": cache._CACHE_VERSION, "entries": {FW_ID: entry}}))
    loaded = cache.load(FW_ID)
    assert loaded is not None
    assert loaded.policy.rule_collection_groups[0].rule_collections[0].rules[0].name == "r"
    assert loaded.subnet_cidrs == [] and loaded.ip_groups == {}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_cache_directory_is_private(monkeypatch, tmp_path):
    monkeypatch.setattr(cache.Path, "home", staticmethod(lambda: tmp_path))
    path = cache.cache_path()
    assert path == tmp_path / ".az-firewall-watch" / "cache.json"
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_cache_path_falls_back_when_home_unwritable(monkeypatch, tmp_path):
    class _Home:
        def __truediv__(self, _other):
            raise OSError("read-only home")

    monkeypatch.setattr(cache.Path, "home", staticmethod(lambda: _Home()))
    monkeypatch.setattr(cache, "BASE_DIR", tmp_path)
    assert cache.cache_path() == tmp_path / ".azfw-cache.json"
