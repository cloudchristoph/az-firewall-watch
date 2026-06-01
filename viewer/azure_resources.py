"""Typed dataclasses and fetchers for Azure Firewall management-plane data.

All functions take an :class:`viewer.arm.ArmClient` and return plain dataclasses
that are JSON-serialisable via :func:`dataclasses.asdict`. The cache layer
relies on this.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from .arm import ArmClient, ArmError


# API versions — pinned for predictable shapes.
_API_FW = "2024-01-01"          # azureFirewalls, firewallPolicies, ipGroups
_API_NET = "2024-01-01"         # virtualNetworks / subnets


@dataclass
class IpGroupInfo:
    id: str
    name: str
    location: str
    ip_addresses: list[str] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    rule_type: str = ""
    source_addresses: list[str] = field(default_factory=list)
    source_ip_groups: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    destination_ip_groups: list[str] = field(default_factory=list)
    destination_fqdns: list[str] = field(default_factory=list)
    destination_ports: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class RuleCollection:
    name: str
    priority: int = 0
    action: str = ""
    rule_collection_type: str = ""
    rules: list[Rule] = field(default_factory=list)


@dataclass
class RuleCollectionGroup:
    id: str
    name: str
    priority: int = 0
    rule_collections: list[RuleCollection] = field(default_factory=list)


@dataclass
class FirewallPolicyInfo:
    id: str
    name: str
    sku_tier: str = ""           # Standard | Premium | Basic
    threat_intel_mode: str = ""
    base_policy_id: str = ""
    rule_collection_groups: list[RuleCollectionGroup] = field(default_factory=list)


@dataclass
class FirewallInfo:
    id: str
    name: str
    subscription_id: str
    resource_group: str
    location: str
    sku_tier: str = ""
    private_ips: list[str] = field(default_factory=list)
    subnet_ids: list[str] = field(default_factory=list)
    subnet_cidrs: list[str] = field(default_factory=list)
    policy_id: str = ""


def parse_resource_id(resource_id: str) -> dict[str, str]:
    """Extract sub/RG/name from any ARM resource ID. Case-insensitive."""
    out: dict[str, str] = {}
    m = re.search(r"/subscriptions/([^/]+)", resource_id, re.IGNORECASE)
    if m:
        out["subscription_id"] = m.group(1)
    m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
    if m:
        out["resource_group"] = m.group(1)
    m = re.search(r"/providers/[^/]+/[^/]+/([^/]+)$", resource_id, re.IGNORECASE)
    if m:
        out["name"] = m.group(1)
    return out


async def fetch_firewall(arm: ArmClient, firewall_id: str) -> FirewallInfo:
    raw = await arm.get(firewall_id, _API_FW)
    props = raw.get("properties") or {}
    ids = parse_resource_id(firewall_id)

    private_ips: list[str] = []
    subnet_ids: list[str] = []
    for cfg in props.get("ipConfigurations") or []:
        cprops = cfg.get("properties") or {}
        pip = cprops.get("privateIPAddress")
        if pip:
            private_ips.append(pip)
        subnet = (cprops.get("subnet") or {}).get("id")
        if subnet and subnet not in subnet_ids:
            subnet_ids.append(subnet)
    for cfg in props.get("managementIpConfiguration") or []:
        # rare, but handle the singular field too below
        pass
    mgmt = props.get("managementIpConfiguration") or {}
    if isinstance(mgmt, dict):
        cprops = mgmt.get("properties") or {}
        subnet = (cprops.get("subnet") or {}).get("id")
        if subnet and subnet not in subnet_ids:
            subnet_ids.append(subnet)

    sku_tier = ((raw.get("sku") or {}).get("tier")) or ""
    policy_id = ((props.get("firewallPolicy") or {}).get("id")) or ""

    return FirewallInfo(
        id=raw.get("id") or firewall_id,
        name=raw.get("name") or ids.get("name", ""),
        subscription_id=ids.get("subscription_id", ""),
        resource_group=ids.get("resource_group", ""),
        location=raw.get("location") or "",
        sku_tier=sku_tier,
        private_ips=private_ips,
        subnet_ids=subnet_ids,
        policy_id=policy_id,
    )


async def fetch_subnet_cidrs(arm: ArmClient, subnet_id: str) -> list[str]:
    raw = await arm.get(subnet_id, _API_NET)
    props = raw.get("properties") or {}
    cidrs: list[str] = []
    prefix = props.get("addressPrefix")
    if prefix:
        cidrs.append(prefix)
    for p in props.get("addressPrefixes") or []:
        if p and p not in cidrs:
            cidrs.append(p)
    return cidrs


async def fetch_all_subnet_cidrs(arm: ArmClient, subnet_ids: list[str]) -> list[str]:
    if not subnet_ids:
        return []
    results = await asyncio.gather(
        *(fetch_subnet_cidrs(arm, sid) for sid in subnet_ids),
        return_exceptions=True,
    )
    out: list[str] = []
    for r in results:
        if isinstance(r, list):
            for c in r:
                if c not in out:
                    out.append(c)
    return out


def _parse_rule(raw: dict) -> Rule:
    return Rule(
        name=raw.get("name") or "",
        rule_type=raw.get("ruleType") or "",
        source_addresses=list(raw.get("sourceAddresses") or []),
        source_ip_groups=list(raw.get("sourceIpGroups") or []),
        destination_addresses=list(raw.get("destinationAddresses") or []),
        destination_ip_groups=list(raw.get("destinationIpGroups") or []),
        destination_fqdns=list(raw.get("destinationFqdns") or []),
        destination_ports=list(raw.get("destinationPorts") or []),
        protocols=[
            (p.get("protocolType") if isinstance(p, dict) else str(p))
            for p in (raw.get("ipProtocols") or raw.get("protocols") or [])
        ],
    )


def _parse_rule_collection(raw: dict) -> RuleCollection:
    action = ""
    act = raw.get("action") or {}
    if isinstance(act, dict):
        action = act.get("type") or ""
    return RuleCollection(
        name=raw.get("name") or "",
        priority=int(raw.get("priority") or 0),
        action=action,
        rule_collection_type=raw.get("ruleCollectionType") or "",
        rules=[_parse_rule(r) for r in (raw.get("rules") or [])],
    )


async def fetch_policy(arm: ArmClient, policy_id: str) -> FirewallPolicyInfo:
    raw = await arm.get(policy_id, _API_FW)
    props = raw.get("properties") or {}
    sku_tier = ((raw.get("sku") or props.get("sku") or {}).get("tier")) or ""
    threat_intel_mode = props.get("threatIntelMode") or ""
    base_policy_id = ((props.get("basePolicy") or {}).get("id")) or ""

    rcg_items = await arm.get_all(f"{policy_id}/ruleCollectionGroups", _API_FW)
    groups: list[RuleCollectionGroup] = []
    for item in rcg_items:
        gprops = item.get("properties") or {}
        groups.append(RuleCollectionGroup(
            id=item.get("id") or "",
            name=item.get("name") or "",
            priority=int(gprops.get("priority") or 0),
            rule_collections=[_parse_rule_collection(rc)
                              for rc in (gprops.get("ruleCollections") or [])],
        ))
    groups.sort(key=lambda g: g.priority)

    ids = parse_resource_id(policy_id)
    return FirewallPolicyInfo(
        id=raw.get("id") or policy_id,
        name=raw.get("name") or ids.get("name", ""),
        sku_tier=sku_tier,
        threat_intel_mode=threat_intel_mode,
        base_policy_id=base_policy_id,
        rule_collection_groups=groups,
    )


def collect_ip_group_ids(policy: FirewallPolicyInfo) -> list[str]:
    seen: set[str] = set()
    for g in policy.rule_collection_groups:
        for rc in g.rule_collections:
            for r in rc.rules:
                for i in r.source_ip_groups:
                    seen.add(i)
                for i in r.destination_ip_groups:
                    seen.add(i)
    return sorted(seen)


async def fetch_ip_group(arm: ArmClient, ip_group_id: str) -> IpGroupInfo:
    raw = await arm.get(ip_group_id, _API_FW)
    props = raw.get("properties") or {}
    ids = parse_resource_id(ip_group_id)
    return IpGroupInfo(
        id=raw.get("id") or ip_group_id,
        name=raw.get("name") or ids.get("name", ""),
        location=raw.get("location") or "",
        ip_addresses=list(props.get("ipAddresses") or []),
    )


async def fetch_ip_groups(arm: ArmClient, ip_group_ids: list[str]) -> dict[str, IpGroupInfo]:
    if not ip_group_ids:
        return {}
    results = await asyncio.gather(
        *(fetch_ip_group(arm, gid) for gid in ip_group_ids),
        return_exceptions=True,
    )
    out: dict[str, IpGroupInfo] = {}
    for gid, r in zip(ip_group_ids, results):
        if isinstance(r, IpGroupInfo):
            out[gid] = r
        # silently skip groups we couldn't read (likely RBAC)
    return out


__all__ = [
    "ArmError",
    "IpGroupInfo", "Rule", "RuleCollection", "RuleCollectionGroup",
    "FirewallPolicyInfo", "FirewallInfo",
    "parse_resource_id",
    "fetch_firewall", "fetch_subnet_cidrs", "fetch_all_subnet_cidrs",
    "fetch_policy", "fetch_ip_group", "fetch_ip_groups",
    "collect_ip_group_ids",
]
