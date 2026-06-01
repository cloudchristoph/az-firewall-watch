"""On-disk JSON cache for Azure management-plane data."""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from .azure_resources import (
    FirewallInfo,
    FirewallPolicyInfo,
    IpGroupInfo,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
)
from .config import BASE_DIR


DEFAULT_TTL_SECONDS = 24 * 60 * 60
_CACHE_VERSION = 1


@dataclass
class CachedSnapshot:
    firewall: FirewallInfo
    policy: FirewallPolicyInfo | None
    ip_groups: dict[str, IpGroupInfo] = field(default_factory=dict)
    subnet_cidrs: list[str] = field(default_factory=list)
    fetched_at: float = 0.0

    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.fetched_at)

    def is_fresh(self, ttl: float = DEFAULT_TTL_SECONDS) -> bool:
        return self.age_seconds() < ttl


def cache_path() -> Path:
    """Resolve the cache file path. Prefer ``~/.az-firewall-watch/`` and fall
    back to ``BASE_DIR`` if the home directory is not writable."""
    try:
        home = Path.home() / ".az-firewall-watch"
        home.mkdir(parents=True, exist_ok=True)
        return home / "cache.json"
    except OSError:
        return BASE_DIR / ".azfw-cache.json"


def load(firewall_id: str) -> CachedSnapshot | None:
    path = cache_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("_version") != _CACHE_VERSION:
        return None
    entries = data.get("entries") or {}
    entry = entries.get(firewall_id)
    if not entry:
        return None
    try:
        return _hydrate(entry)
    except (TypeError, KeyError):
        return None


def save(firewall_id: str, snapshot: CachedSnapshot) -> None:
    path = cache_path()
    existing: dict[str, Any] = {"_version": _CACHE_VERSION, "entries": {}}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if existing.get("_version") != _CACHE_VERSION:
                existing = {"_version": _CACHE_VERSION, "entries": {}}
        except (OSError, json.JSONDecodeError):
            existing = {"_version": _CACHE_VERSION, "entries": {}}
    existing.setdefault("entries", {})[firewall_id] = _serialize(snapshot)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2, default=_json_default), encoding="utf-8")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def invalidate(firewall_id: str) -> None:
    path = cache_path()
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    entries = data.get("entries") or {}
    if firewall_id in entries:
        del entries[firewall_id]
        path.write_text(json.dumps(data, indent=2, default=_json_default), encoding="utf-8")


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _serialize(snap: CachedSnapshot) -> dict[str, Any]:
    return {
        "firewall": asdict(snap.firewall),
        "policy": asdict(snap.policy) if snap.policy else None,
        "ip_groups": {k: asdict(v) for k, v in snap.ip_groups.items()},
        "subnet_cidrs": list(snap.subnet_cidrs),
        "fetched_at": snap.fetched_at,
    }


def _hydrate(entry: dict[str, Any]) -> CachedSnapshot:
    fw_raw = entry["firewall"]
    fw = FirewallInfo(**fw_raw)
    pol_raw = entry.get("policy")
    policy: FirewallPolicyInfo | None = None
    if pol_raw:
        rcg_list: list[RuleCollectionGroup] = []
        for g in pol_raw.get("rule_collection_groups") or []:
            rcs: list[RuleCollection] = []
            for rc in g.get("rule_collections") or []:
                rules = [Rule(**r) for r in (rc.get("rules") or [])]
                rcs.append(RuleCollection(
                    name=rc.get("name", ""),
                    priority=int(rc.get("priority") or 0),
                    action=rc.get("action", ""),
                    rule_collection_type=rc.get("rule_collection_type", ""),
                    rules=rules,
                ))
            rcg_list.append(RuleCollectionGroup(
                id=g.get("id", ""),
                name=g.get("name", ""),
                priority=int(g.get("priority") or 0),
                rule_collections=rcs,
            ))
        policy = FirewallPolicyInfo(
            id=pol_raw.get("id", ""),
            name=pol_raw.get("name", ""),
            sku_tier=pol_raw.get("sku_tier", ""),
            threat_intel_mode=pol_raw.get("threat_intel_mode", ""),
            base_policy_id=pol_raw.get("base_policy_id", ""),
            rule_collection_groups=rcg_list,
        )
    groups = {k: IpGroupInfo(**v) for k, v in (entry.get("ip_groups") or {}).items()}
    return CachedSnapshot(
        firewall=fw,
        policy=policy,
        ip_groups=groups,
        subnet_cidrs=list(entry.get("subnet_cidrs") or []),
        fetched_at=float(entry.get("fetched_at") or 0.0),
    )
