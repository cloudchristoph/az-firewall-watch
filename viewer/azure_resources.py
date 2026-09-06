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
    rule_type: str = ""                     # NetworkRule | ApplicationRule | NatRule
    source_addresses: list[str] = field(default_factory=list)
    source_ip_groups: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    destination_ip_groups: list[str] = field(default_factory=list)
    destination_fqdns: list[str] = field(default_factory=list)
    destination_ports: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    # application-rule extras the trace cannot evaluate locally (reported as "unknown")
    fqdn_tags: list[str] = field(default_factory=list)
    web_categories: list[str] = field(default_factory=list)
    target_urls: list[str] = field(default_factory=list)
    # DNAT extras
    translated_address: str = ""
    translated_fqdn: str = ""
    translated_port: str = ""

    @property
    def kind(self) -> str:
        """``dnat`` | ``network`` | ``application`` derived from the ARM ruleType."""
        return _rule_kind(self.rule_type)


@dataclass
class RuleCollection:
    name: str
    priority: int = 0
    action: str = ""
    rule_collection_type: str = ""
    rules: list[Rule] = field(default_factory=list)

    @property
    def kind(self) -> str:
        """``dnat`` | ``network`` | ``application``.

        NAT collections have their own ARM type; filter collections are typed
        by their (homogeneous) rules.
        """
        if "nat" in (self.rule_collection_type or "").lower():
            return "dnat"
        for r in self.rules:
            if r.rule_type:
                return r.kind
        return "network"


def _rule_kind(rule_type: str) -> str:
    t = (rule_type or "").lower()
    if "nat" in t:
        return "dnat"
    if "application" in t:
        return "application"
    return "network"


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
    # Inherited (parent) policy, if any. Its groups are always evaluated
    # before this policy's groups, per rule type.
    parent: "FirewallPolicyInfo | None" = None

    def all_groups(self) -> list[tuple[str, RuleCollectionGroup]]:
        """Groups in firewall evaluation order within one rule-type pass:
        parent policy first (by priority), then this policy (by priority).
        Returns ``(policy_name, group)`` tuples."""
        out: list[tuple[str, RuleCollectionGroup]] = []
        if self.parent is not None:
            out.extend(self.parent.all_groups())
        out.extend((self.name, g) for g in sorted(self.rule_collection_groups, key=lambda g: g.priority))
        return out


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
    mgmt = props.get("managementIpConfiguration") or {}
    if isinstance(mgmt, dict):
        cprops = mgmt.get("properties") or {}
        subnet = (cprops.get("subnet") or {}).get("id")
        if subnet and subnet not in subnet_ids:
            subnet_ids.append(subnet)

    # The REST API returns the firewall SKU under properties.sku; the Azure
    # CLI flattens it to the top level, so accept both.
    sku_tier = ((raw.get("sku") or props.get("sku") or {}).get("tier")) or ""
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
    # Network rules: ipProtocols=["TCP"] + destinationPorts=["443"].
    # Application rules: protocols=[{"protocolType": "Https", "port": 443}] —
    # the port lives inside the protocol entry, so lift it into
    # destination_ports for uniform port matching.
    protocols: list[str] = []
    ports: list[str] = [str(p) for p in (raw.get("destinationPorts") or [])]
    for p in raw.get("ipProtocols") or raw.get("protocols") or []:
        if isinstance(p, dict):
            protocols.append(str(p.get("protocolType") or ""))
            port = p.get("port")
            if port is not None and str(port) not in ports:
                ports.append(str(port))
        else:
            protocols.append(str(p))
    return Rule(
        name=raw.get("name") or "",
        rule_type=raw.get("ruleType") or "",
        source_addresses=list(raw.get("sourceAddresses") or []),
        source_ip_groups=list(raw.get("sourceIpGroups") or []),
        destination_addresses=list(raw.get("destinationAddresses") or []),
        destination_ip_groups=list(raw.get("destinationIpGroups") or []),
        destination_fqdns=list(raw.get("destinationFqdns") or []),
        destination_ports=ports,
        protocols=protocols,
        fqdn_tags=list(raw.get("fqdnTags") or []),
        web_categories=list(raw.get("webCategories") or []),
        target_urls=list(raw.get("targetUrls") or []),
        translated_address=str(raw.get("translatedAddress") or ""),
        translated_fqdn=str(raw.get("translatedFqdn") or ""),
        translated_port=str(raw.get("translatedPort") or ""),
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
    """All IP-group IDs referenced by *policy* and its parent chain."""
    seen: set[str] = set()
    for _policy_name, g in policy.all_groups():
        for rc in g.rule_collections:
            for r in rc.rules:
                seen.update(r.source_ip_groups)
                seen.update(r.destination_ip_groups)
    return sorted(seen)


async def fetch_policy_chain(arm: ArmClient, policy_id: str, max_depth: int = 4) -> FirewallPolicyInfo:
    """Fetch a policy and, best effort, its parent chain (``basePolicy``).

    A parent that cannot be read (RBAC, deleted) is left as ``None``; the
    child is still returned so the viewer degrades gracefully.
    """
    policy = await fetch_policy(arm, policy_id)
    current = policy
    depth = 0
    while current.base_policy_id and depth < max_depth:
        try:
            parent = await fetch_policy(arm, current.base_policy_id)
        except ArmError:
            break
        current.parent = parent
        current = parent
        depth += 1
    return policy


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
    "fetch_policy", "fetch_policy_chain", "fetch_ip_group", "fetch_ip_groups",
    "collect_ip_group_ids",
]
