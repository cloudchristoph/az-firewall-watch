"""Address helpers shared by the parser, the filters, the table and the trace.

Azure Firewall can run dual-stack, so every place that once assumed ``a.b.c.d``
goes through here: splitting ``host:port`` tokens from legacy messages, joining
them back for display, and comparing addresses the way people type them
(compressed or expanded IPv6, a CIDR prefix, or just a fragment).

Pure functions on strings, no I/O.
"""
from __future__ import annotations

import ipaddress

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

NO_PORT = "-"


def parse_address(value: str) -> IPAddress | None:
    """``ipaddress.ip_address`` that answers ``None`` instead of raising."""
    if not value or value == NO_PORT:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def parse_network(value: str) -> IPNetwork | None:
    """``ipaddress.ip_network(strict=False)`` that answers ``None`` instead of raising.

    A bare address is a /32 or /128 network, so this also accepts what
    :func:`parse_address` accepts.
    """
    if not value:
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def is_ipv6(value: str) -> bool:
    return isinstance(parse_address(value), ipaddress.IPv6Address)


def normalise_address(value: str) -> str:
    """Canonical (compressed, lower-case) form of an address, or the input unchanged.

    ``fd00:0:0:0:0:0:0:1`` and ``FD00::1`` both become ``fd00::1``; a hostname or a
    fragment that is not an address is returned as is.
    """
    addr = parse_address(value)
    return addr.compressed if addr is not None else value


def split_endpoint(token: str, expect_port: bool = True) -> tuple[str, str]:
    """Split a legacy ``host:port`` token into ``(host, port)``.

    Handles ``10.1.1.1:1234``, ``example.com:443``, ``[fd00::1]:1234`` and the
    unbracketed ``fd00::1:1234`` that is ambiguous on its own: with
    ``expect_port`` (TCP/UDP messages always carry one) the last group is taken
    as the port when the rest still parses as an address; without it (ICMP) the
    whole token is tried as an address first. A missing port is ``"-"``, like the
    structured parser reports it. A trailing ``.`` (sentence end) is dropped.
    """
    token = token.strip().rstrip(".")
    if not token:
        return NO_PORT, NO_PORT

    # RFC 3986 style: [addr]:port or just [addr]
    if token.startswith("["):
        close = token.find("]")
        if close > 0:
            host = token[1:close]
            rest = token[close + 1:]
            port = rest[1:] if rest.startswith(":") and rest[1:] else NO_PORT
            return host, port

    colons = token.count(":")
    if colons == 0:
        return token, NO_PORT
    if colons == 1:
        host, port = token.rsplit(":", 1)  # IPv4 or FQDN, keeps dots in the name
        return host, port or NO_PORT

    # Two or more colons: an IPv6 literal, with or without a port glued on.
    head, _, tail = token.rpartition(":")
    if expect_port:
        if tail.isdigit() and parse_address(head) is not None:
            return head, tail
        return token, NO_PORT
    if parse_address(token) is not None:
        return token, NO_PORT
    if tail.isdigit() and parse_address(head) is not None:
        return head, tail
    return token, NO_PORT


def format_endpoint(address: str, port: str) -> str:
    """``10.1.1.1:443``, ``[fd00::1]:443``, or just the address when there is no port."""
    if not port or port == NO_PORT:
        return address
    if is_ipv6(address):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def address_matches(needle: str, value: str) -> bool:
    """Filter semantics for the Source / Destination inputs.

    ``needle`` is what the user typed (already lower-cased by the caller):

    * a CIDR (``10.0.0.0/8``, ``fd00:c1d0::/32``) matches every address inside it;
    * a full address matches the same address in any spelling
      (``fd00::1`` finds ``fd00:0:0:0:0:0:0:1``);
    * anything else is a substring match against the value as logged and, for
      IPv6, against its compressed form (``::10`` finds ``fd00:0:0:2:0:0:0:10``).

    Substring matching stays, so ``10.0.1.4`` still finds ``10.0.1.44`` as it
    always did; a CIDR is the precise tool. Only a CIDR is never a substring.
    """
    if not needle:
        return True
    haystack = (value or "").lower()
    if "/" in needle:
        net = parse_network(needle)
        if net is not None:
            addr = parse_address(haystack)
            return addr is not None and addr.version == net.version and addr in net
        return needle in haystack
    if needle in haystack:
        return True
    addr = parse_address(haystack)
    if addr is None:
        return False
    wanted = parse_address(needle)
    return wanted == addr or needle in addr.compressed
