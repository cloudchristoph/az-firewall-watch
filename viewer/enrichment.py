"""Pure enrichment helpers: subnet/IP-group matching. No I/O."""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Iterable

from .azure_resources import IpGroupInfo


@lru_cache(maxsize=32)
def _parsed_networks(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse once per distinct CIDR list — resolve_fw_instance runs per table row."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _parse_networks(cidrs: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return _parsed_networks(tuple(cidrs))


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
