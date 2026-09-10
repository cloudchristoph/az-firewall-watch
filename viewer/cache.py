"""On-disk JSON cache for Azure management-plane data."""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

from .azure_resources import (
    DiagnosticSetting,
    FirewallInfo,
    FirewallPolicyInfo,
    HttpHeader,
    IpConfig,
    IpGroupInfo,
    MaintenanceWindow,
    NatGatewayInfo,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
    SubnetInfo,
)
from .config import BASE_DIR

# One hour: the evaluation trace explains the *cached* policy, so a long TTL
# would explain yesterday's rules. Ctrl+R refreshes on demand.
DEFAULT_TTL_SECONDS = 60 * 60
# v5: subnets with NAT gateways, maintenance windows, explicit proxy ports,
# auto-learn SNAT, autoscale, HTTP header insertion
_CACHE_VERSION = 5


@dataclass
class CachedSnapshot:
    firewall: FirewallInfo
    policy: FirewallPolicyInfo | None
    ip_groups: dict[str, IpGroupInfo] = field(default_factory=dict)
    subnet_cidrs: list[str] = field(default_factory=list)
    fetched_at: float = 0.0
    diagnostics: list[DiagnosticSetting] = field(default_factory=list)
    subnets: list[SubnetInfo] = field(default_factory=list)
    nat_gateways: list[NatGatewayInfo] = field(default_factory=list)
    maintenance: list[MaintenanceWindow] = field(default_factory=list)
    maintenance_readable: bool = True   # False: the assignment list could not be read (unknown, not none)

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
        try:
            os.chmod(home, 0o700)  # the file is 0600; keep the directory private too
        except OSError:
            pass
        return home / "cache.json"
    except OSError:
        return BASE_DIR / ".azfw-cache.json"


def _empty_store() -> dict[str, Any]:
    return {"_version": _CACHE_VERSION, "entries": {}}


def _read_store(path: Path) -> dict[str, Any] | None:
    """Read the cache file; ``None`` when unreadable, the wrong version, or not
    dict-shaped (valid JSON that is a list, or ``entries`` that is not a mapping)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("_version") != _CACHE_VERSION:
        return None
    if not isinstance(data.get("entries"), dict):
        return None
    return data


def load(firewall_id: str) -> CachedSnapshot | None:
    path = cache_path()
    if not path.exists():
        return None
    data = _read_store(path)
    if data is None:
        return None
    entry = data["entries"].get(firewall_id)
    if not isinstance(entry, dict):
        return None
    try:
        return _hydrate(entry)
    except (TypeError, KeyError, ValueError):
        # malformed or older entry (e.g. non-numeric priority) → treat as a miss
        return None


def save(firewall_id: str, snapshot: CachedSnapshot) -> None:
    path = cache_path()
    # A malformed or outdated file is reset rather than allowed to break a refresh.
    existing = (_read_store(path) if path.exists() else None) or _empty_store()
    existing["entries"][firewall_id] = _serialize(snapshot)
    # Create the temp file private from the start (0600) so the cache is never
    # world-readable, not even for the instant before os.replace().
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(existing, indent=2, default=_json_default))
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)  # in case the file pre-existed with wider permissions
    except OSError:
        pass


def invalidate(firewall_id: str) -> None:
    path = cache_path()
    if not path.exists():
        return
    data = _read_store(path)
    if data is None:
        return  # nothing usable to invalidate
    entries = data["entries"]
    if firewall_id in entries:
        del entries[firewall_id]
        try:
            path.write_text(json.dumps(data, indent=2, default=_json_default), encoding="utf-8")
        except OSError:
            pass  # a read-only cache must not block a forced refresh; save() will retry later


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _serialize(snap: CachedSnapshot) -> dict[str, Any]:
    # Two kinds of sensitive text reach this file, and they are treated
    # differently on purpose. The policy's PAC file link arrives already
    # stripped of its query string (azure_resources._strip_query): a SAS URL is
    # a bearer credential, and in a file it grants whoever finds it access they
    # would not otherwise have. The inserted HTTP header values are stored in
    # full: the identity that wrote this cache can read them from ARM at any
    # time, so the file adds no access, and it is 0600 in a 0700 directory.
    # The views are where the values stay hidden until asked for.
    return {
        "firewall": asdict(snap.firewall),
        "policy": asdict(snap.policy) if snap.policy else None,
        "ip_groups": {k: asdict(v) for k, v in snap.ip_groups.items()},
        "subnet_cidrs": list(snap.subnet_cidrs),
        "fetched_at": snap.fetched_at,
        "diagnostics": [asdict(d) for d in snap.diagnostics],
        "subnets": [asdict(s) for s in snap.subnets],
        "nat_gateways": [asdict(n) for n in snap.nat_gateways],
        "maintenance": [asdict(m) for m in snap.maintenance],
        "maintenance_readable": snap.maintenance_readable,
    }


def _hydrate_rule(raw: dict[str, Any]) -> Rule:
    # tolerate cache entries written by older versions (missing keys)
    fields = {k: v for k, v in raw.items() if k in Rule.__dataclass_fields__}
    fields["http_headers"] = [HttpHeader(**h) for h in (fields.get("http_headers") or []) if isinstance(h, dict)]
    return Rule(**fields)


def _hydrate_policy(pol_raw: dict[str, Any] | None) -> FirewallPolicyInfo | None:
    if not pol_raw:
        return None
    rcg_list: list[RuleCollectionGroup] = []
    for g in pol_raw.get("rule_collection_groups") or []:
        rcs: list[RuleCollection] = []
        for rc in g.get("rule_collections") or []:
            rules = [_hydrate_rule(r) for r in (rc.get("rules") or [])]
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
    simple = {k: v for k, v in pol_raw.items()
              if k in FirewallPolicyInfo.__dataclass_fields__ and k not in ("rule_collection_groups", "parent")}
    return FirewallPolicyInfo(
        **simple,
        rule_collection_groups=rcg_list,
        parent=_hydrate_policy(pol_raw.get("parent")),
    )


def _hydrate(entry: dict[str, Any]) -> CachedSnapshot:
    fw_raw = dict(entry["firewall"])
    fw_raw["ip_configs"] = [IpConfig(**c) for c in (fw_raw.get("ip_configs") or [])]
    mgmt = fw_raw.get("management_ip")
    fw_raw["management_ip"] = IpConfig(**mgmt) if isinstance(mgmt, dict) else None
    fw = FirewallInfo(**{k: v for k, v in fw_raw.items() if k in FirewallInfo.__dataclass_fields__})
    policy = _hydrate_policy(entry.get("policy"))
    groups = {k: IpGroupInfo(**v) for k, v in (entry.get("ip_groups") or {}).items()}
    return CachedSnapshot(
        firewall=fw,
        policy=policy,
        ip_groups=groups,
        subnet_cidrs=list(entry.get("subnet_cidrs") or []),
        fetched_at=float(entry.get("fetched_at") or 0.0),
        diagnostics=[DiagnosticSetting(**d) for d in (entry.get("diagnostics") or [])],
        subnets=[SubnetInfo(**s) for s in (entry.get("subnets") or [])],
        nat_gateways=[NatGatewayInfo(**n) for n in (entry.get("nat_gateways") or [])],
        maintenance=[MaintenanceWindow(**m) for m in (entry.get("maintenance") or [])],
        maintenance_readable=bool(entry.get("maintenance_readable", True)),
    )
