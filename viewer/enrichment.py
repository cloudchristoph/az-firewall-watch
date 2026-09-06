"""Pure enrichment helpers: subnet/IP-group matching. No I/O."""
from __future__ import annotations

import ipaddress
from typing import Iterable

from .azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup


def _parse_networks(cidrs: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def resolve_fw_instance(ip: str, subnet_cidrs: Iterable[str]) -> str | None:
    """Return ``"AzFw.<lastOctet>"`` if ``ip`` lies inside any firewall subnet.

    Returns ``None`` otherwise (e.g. for invalid IPs or no match).
    """
    if not ip or ip == "-":
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in _parse_networks(subnet_cidrs):
        if addr in net:
            # Derive the label from the parsed address, not the input string:
            # "fd00::" or "fd00::00ab" would otherwise yield "" / "00ab".
            if isinstance(addr, ipaddress.IPv4Address):
                last = str(int(addr) & 0xFF)
            else:
                last = format(int(addr) & 0xFFFF, "x")
            return f"AzFw.{last}"
    return None


def find_matching_ip_groups(ip: str, ip_groups: dict[str, IpGroupInfo]) -> list[str]:
    """Return names of IP groups whose ``ip_addresses`` contain ``ip``."""
    if not ip or ip == "-":
        return []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    matches: list[str] = []
    for grp in ip_groups.values():
        for entry in grp.ip_addresses:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if addr in net:
                matches.append(grp.name)
                break
    return matches


def _ip_in_any(ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
               addresses: Iterable[str],
               ip_group_ids: Iterable[str],
               ip_groups: dict[str, IpGroupInfo]) -> bool:
    for a in addresses:
        if a in ("*", "any", "Any"):
            return True
        try:
            if ip in ipaddress.ip_network(a, strict=False):
                return True
        except ValueError:
            continue
    for gid in ip_group_ids:
        grp = ip_groups.get(gid)
        if not grp:
            continue
        for entry in grp.ip_addresses:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
    return False


def _fqdn_matches(fqdn: str, patterns: Iterable[str]) -> bool:
    if not fqdn:
        return False
    fqdn = fqdn.lower()
    for p in patterns:
        if not p:
            continue
        p = p.lower()
        if p in ("*", fqdn):
            return True
        if p.startswith("*."):
            if fqdn == p[2:] or fqdn.endswith(p[1:]):
                return True
    return False


def find_rule(category: str, src_ip: str, dst_ip: str, dst_fqdn: str, port: str,
              policy: FirewallPolicyInfo | None,
              ip_groups: dict[str, IpGroupInfo]) -> tuple[Rule, RuleCollectionGroup, RuleCollection] | None:
    """Best-effort search for the matching rule. Returns the first match
    in priority order, or ``None``."""
    if policy is None:
        return None
    try:
        src = ipaddress.ip_address(src_ip) if src_ip and src_ip != "-" else None
    except ValueError:
        src = None
    try:
        dst = ipaddress.ip_address(dst_ip) if dst_ip and dst_ip != "-" else None
    except ValueError:
        dst = None
    cat = category.lower()
    for g in sorted(policy.rule_collection_groups, key=lambda x: x.priority):
        for rc in sorted(g.rule_collections, key=lambda x: x.priority):
            for r in rc.rules:
                if src is not None and not _ip_in_any(
                    src, r.source_addresses, r.source_ip_groups, ip_groups,
                ):
                    continue
                if cat in ("apprule",):
                    if dst_fqdn and not _fqdn_matches(dst_fqdn, r.destination_fqdns):
                        continue
                else:
                    if dst is not None and not _ip_in_any(
                        dst, r.destination_addresses, r.destination_ip_groups, ip_groups,
                    ):
                        continue
                if port and r.destination_ports:
                    if not any(_port_matches(port, p) for p in r.destination_ports):
                        continue
                return r, g, rc
    return None


def _port_matches(port: str, spec: str) -> bool:
    if spec in ("*", "any", "Any"):
        return True
    try:
        p = int(port)
    except ValueError:
        return False
    if "-" in spec:
        lo, _, hi = spec.partition("-")
        try:
            return int(lo) <= p <= int(hi)
        except ValueError:
            return False
    try:
        return p == int(spec)
    except ValueError:
        return False
