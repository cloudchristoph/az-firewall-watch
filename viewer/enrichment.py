"""Pure enrichment helpers: subnet/IP-group matching. No I/O."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import lru_cache

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


_Address = ipaddress.IPv4Address | ipaddress.IPv6Address
AddressRange = tuple[_Address, _Address]
ParsedEntry = tuple[str, AddressRange]


def _parse_address_entry(entry: str) -> AddressRange | None:
    """One address entry as an inclusive range, or ``None`` if it is not one.

    Azure accepts three notations wherever addresses are listed (IP groups,
    rule address lists): a single address ``10.0.0.0``, a CIDR block
    ``10.1.0.0/32`` and a range ``10.2.0.0-10.2.0.31``. Everything else is a
    service tag or a typo, and the caller has to say so instead of dropping it.

    Ranges keep their endpoints: expanding a large one into networks would cost
    a lot for a question that is a comparison.
    """
    text = entry.strip()
    if not text:
        return None
    start_text, sep, end_text = text.partition("-")
    if sep:
        try:
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
        except ValueError:
            return None
        # A reversed or mixed-family range describes no addresses at all, so it
        # is unreadable rather than empty: never let it answer a match question.
        if start.version != end.version or int(start) > int(end):
            return None
        return start, end
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return net.network_address, net.broadcast_address


@lru_cache(maxsize=64)
def _parsed_address_entries(entries: tuple[str, ...]) -> tuple[tuple[ParsedEntry, ...], tuple[str, ...]]:
    """Parse once per distinct entry list: the trace runs per rule and row."""
    parsed: list[ParsedEntry] = []
    unreadable: list[str] = []
    for entry in entries:
        rng = _parse_address_entry(entry)
        if rng is None:
            unreadable.append(entry)
        else:
            parsed.append((entry, rng))
    return tuple(parsed), tuple(unreadable)


def parse_address_entries(entries: Iterable[str]) -> tuple[tuple[ParsedEntry, ...], tuple[str, ...]]:
    """Split address entries into readable ``(entry, range)`` pairs and the rest.

    The second tuple is the point of this function: an entry nobody can
    interpret is not the same as an entry that does not contain the address.
    """
    return _parsed_address_entries(tuple(entries))


def find_containing_entry(addr: _Address, parsed: Iterable[ParsedEntry]) -> str | None:
    """The first entry whose range contains ``addr``, or ``None``."""
    for entry, (start, end) in parsed:
        # Endpoints of the other family would raise on comparison.
        if start.version == addr.version and int(start) <= int(addr) <= int(end):
            return entry
    return None


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
    """Return names of IP groups whose ``ip_addresses`` contain ``ip``.

    Entries this cannot read are left out silently: the caller shows a bare list
    of group names and has nowhere to put a doubt. Callers that do have that
    vocabulary use :func:`parse_address_entries` and report them (see the trace).
    """
    if not ip or ip == "-":
        return []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    matches: list[str] = []
    for grp in ip_groups.values():
        parsed, _unreadable = parse_address_entries(grp.ip_addresses)
        if find_containing_entry(addr, parsed) is not None:
            matches.append(grp.name)
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
