"""Rules of a firewall policy chain as the firewall evaluates them, and questions about them.

Pure logic on the cached dataclasses, no I/O. The order is the one the
evaluation trace uses (:data:`viewer.trace.PASS_ORDER`): one pass per rule type
(DNAT, network, application); within a pass the inherited (parent) policy's
groups first, then groups by priority, then collections by priority, then the
rules in the order the collection lists them.
"""
from __future__ import annotations

import difflib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from viewer.azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup
from viewer.enrichment import parse_address_entries
from viewer.trace import PASS_ORDER

SEPARATOR = " » "
SIDES = ("source", "destination")
# The same wildcard spellings the trace accepts in an address list.
_WILDCARDS = ("*", "any")

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass
class RuleRef:
    """One rule with its place in the policy chain."""

    policy: str
    group: RuleCollectionGroup
    collection: RuleCollection
    rule: Rule
    position: int          # 1-based place in the overall evaluation order
    inherited: bool        # the rule comes from a parent policy

    @property
    def ref(self) -> str:
        return SEPARATOR.join((self.policy, self.group.name, self.collection.name, self.rule.name))

    @property
    def kind(self) -> str:
        # The collection's kind, not the rule's: the trace sorts collections into
        # passes by it, and a NAT collection's rules are evaluated as DNAT.
        return self.collection.kind

    @property
    def action(self) -> str:
        return self.collection.action

    def placement(self) -> dict[str, Any]:
        """Where the rule sits and what its collection does with a match."""
        return {
            "ref": self.ref,
            "position": self.position,
            "policy": self.policy,
            "inherited": self.inherited,
            "group": self.group.name,
            "group_priority": self.group.priority,
            "collection": self.collection.name,
            "collection_priority": self.collection.priority,
            "kind": self.kind,
            "action": self.action or None,
        }


def iter_rules(policy: FirewallPolicyInfo) -> list[RuleRef]:
    """Every rule of the chain in firewall evaluation order."""
    out: list[RuleRef] = []
    for kind in PASS_ORDER:
        for policy_name, group in policy.all_groups():
            for collection in sorted(group.rule_collections, key=lambda c: c.priority):
                if collection.kind != kind:
                    continue
                for rule in collection.rules:
                    out.append(RuleRef(policy=policy_name, group=group, collection=collection, rule=rule,
                                       position=len(out) + 1, inherited=policy_name != policy.name))
    return out


# ── lookup by name ───────────────────────────────────────────────────────────

def policy_chain_names(policy: FirewallPolicyInfo) -> list[str]:
    """Policy names from the outermost parent to ``policy`` itself."""
    names: list[str] = []
    current: FirewallPolicyInfo | None = policy
    while current is not None:
        names.insert(0, current.name)
        current = current.parent
    return names


def split_ref(ref: str) -> list[str]:
    """``policy » group » collection » rule`` (or the TUI's ``policy|group|collection|rule``) into its parts.

    Three parts leave the policy open. Surrounding blanks around each part are
    dropped, so ``a»b»c`` and ``a » b » c`` mean the same.
    """
    text = (ref or "").strip()
    sep = "»" if "»" in text else "|"
    parts = [p.strip() for p in text.split(sep)]
    if len(parts) not in (3, 4) or not all(parts):
        raise ValueError(f"ref must look like 'policy » group » collection » rule' (or without the policy), "
                         f"got {ref!r}.")
    return parts


def nearest_names(wanted: str, names: Iterable[str]) -> str:
    """A short list of names to offer when ``wanted`` is unknown: close matches first, else the first few."""
    unique = list(dict.fromkeys(n for n in names if n))
    if not unique:
        return "none exist"
    by_fold = {n.casefold(): n for n in unique}
    close = [by_fold[m] for m in difflib.get_close_matches(wanted.casefold(), list(by_fold), n=5, cutoff=0.5)]
    shown = close or unique[:5]
    more = "" if close or len(unique) <= 5 else f" (and {len(unique) - 5} more)"
    return ", ".join(shown) + more


def find_rule(policy: FirewallPolicyInfo, ref: str | None = None, *, group: str | None = None,
              collection: str | None = None, rule: str | None = None) -> RuleRef:
    """The rule named by ``ref`` or by ``group``, ``collection`` and ``rule``.

    Names compare case-insensitively, as ARM treats resource names. A caller
    mistake raises ``ValueError`` with the nearest existing names at the level
    that did not match, so the caller can correct the call.
    """
    policy_name: str | None = None
    if ref:
        parts = split_ref(ref)
        if len(parts) == 4:
            policy_name = parts.pop(0)
        group, collection, rule = parts
    if not (group and collection and rule):
        raise ValueError("Name the rule either by ref ('policy » group » collection » rule') or by group, "
                         "collection and rule together.")
    rules = iter_rules(policy)
    if policy_name is not None:
        known = policy_chain_names(policy)
        if policy_name.casefold() not in {p.casefold() for p in known}:
            raise ValueError(f"No policy {policy_name!r} in the loaded chain. Policies: {', '.join(known)}.")
        rules = [r for r in rules if r.policy.casefold() == policy_name.casefold()]

    in_group = [r for r in rules if r.group.name.casefold() == group.casefold()]
    if not in_group:
        raise ValueError(f"No rule collection group {group!r}. Nearest groups: "
                         f"{nearest_names(group, (r.group.name for r in rules))}.")
    in_collection = [r for r in in_group if r.collection.name.casefold() == collection.casefold()]
    if not in_collection:
        raise ValueError(f"No rule collection {collection!r} in group {in_group[0].group.name!r}. Nearest "
                         f"collections: {nearest_names(collection, (r.collection.name for r in in_group))}.")
    found = [r for r in in_collection if r.rule.name.casefold() == rule.casefold()]
    if not found:
        raise ValueError(f"No rule {rule!r} in {in_collection[0].group.name} » {in_collection[0].collection.name}. "
                         f"Nearest rules: {nearest_names(rule, (r.rule.name for r in in_collection))}.")
    if len(found) > 1:
        # A parent and a child policy may reuse group, collection and rule names.
        raise ValueError(f"{len(found)} rules match; add the policy to the ref: "
                         f"{'; '.join(r.ref for r in found)}.")
    return found[0]


# ── addresses and IP groups ──────────────────────────────────────────────────

def parse_network(value: str) -> _Network:
    """An address or CIDR as a network (an address becomes a /32 or /128)."""
    text = (value or "").strip()
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"address must be an IP address or a CIDR (10.1.2.3, 10.1.0.0/16, fd10::/64), "
                         f"got {value!r}.") from None


def _relation(start: _Address, end: _Address, net: _Network) -> str | None:
    """How an entry's inclusive range relates to ``net``: ``contains``, ``overlaps`` or ``None``."""
    if start.version != net.version:
        return None
    lo, hi = int(net.network_address), int(net.broadcast_address)
    if int(start) <= lo and hi <= int(end):
        return "contains"
    if int(start) <= hi and lo <= int(end):
        return "overlaps"
    return None


def _entry_match(entries: list[str], net: _Network) -> tuple[str, str] | None:
    """The first entry that covers ``net`` and how; a full containment wins over an overlap."""
    for entry in entries:
        if entry.strip().lower() in _WILDCARDS:
            return entry, "wildcard"
    parsed, _unreadable = parse_address_entries(entries)
    overlap: tuple[str, str] | None = None
    for entry, (start, end) in parsed:
        relation = _relation(start, end, net)
        if relation == "contains":
            return entry, relation
        if relation == "overlaps" and overlap is None:
            overlap = (entry, relation)
    return overlap


def lookup_ip_group(group_id: str, ip_groups: dict[str, IpGroupInfo]) -> IpGroupInfo | None:
    """The loaded IP group for an id as a rule spells it (ARM ids differ only in case at times)."""
    grp = ip_groups.get(group_id)
    if grp is not None:
        return grp
    folded = group_id.casefold()
    return next((g for gid, g in ip_groups.items() if gid.casefold() == folded), None)


def address_matches(rule: Rule, address_or_network: str | _Network,
                    ip_groups: dict[str, IpGroupInfo]) -> dict[str, dict[str, Any]]:
    """Per side (``source``, ``destination``), the entry that covers the address or network.

    Each value says ``entry`` (as written in the rule or the IP group),
    ``ip_group`` (the group's name, ``None`` for a direct address entry) and
    ``relation``: ``contains`` (the entry holds the whole address or network),
    ``overlaps`` (the entry shares part of the network, for example a /24 entry
    asked about with a /16) or ``wildcard`` (``*``). Service tags and IP groups
    that are not loaded cannot be compared and never count.
    """
    net = parse_network(address_or_network) if isinstance(address_or_network, str) else address_or_network
    out: dict[str, dict[str, Any]] = {}
    for side, addresses, group_ids in (
            ("source", rule.source_addresses, rule.source_ip_groups),
            ("destination", rule.destination_addresses, rule.destination_ip_groups)):
        hit = _entry_match(addresses, net)
        found: dict[str, Any] | None = None
        if hit is not None:
            found = {"entry": hit[0], "ip_group": None, "relation": hit[1]}
        if found is None or found["relation"] == "overlaps":
            for gid in group_ids:
                grp = lookup_ip_group(gid, ip_groups)
                if grp is None:
                    continue
                ghit = _entry_match(grp.ip_addresses, net)
                if ghit is None:
                    continue
                candidate = {"entry": ghit[0], "ip_group": grp.name, "relation": ghit[1]}
                if found is None or candidate["relation"] != "overlaps":
                    found = candidate
                if found["relation"] != "overlaps":
                    break
        if found is not None:
            out[side] = found
    return out


def rule_covers_address(rule: Rule, address_or_network: str | _Network,
                        ip_groups: dict[str, IpGroupInfo]) -> set[str]:
    """The sides (``source``, ``destination``) whose addresses or IP groups cover the address or network.

    A network counts as covered when an entry contains it or overlaps it; see
    :func:`address_matches` for which one it was.
    """
    return set(address_matches(rule, address_or_network, ip_groups))


def rule_ip_group_sides(rule: Rule, group_id: str) -> list[str]:
    """The sides on which ``rule`` references the IP group ``group_id``."""
    folded = group_id.casefold()
    sides: list[str] = []
    if any(g.casefold() == folded for g in rule.source_ip_groups):
        sides.append("source")
    if any(g.casefold() == folded for g in rule.destination_ip_groups):
        sides.append("destination")
    return sides


def rules_using_ip_group(policy: FirewallPolicyInfo, group_id: str) -> list[RuleRef]:
    """Rules that reference the IP group as source or destination, in evaluation order."""
    return [r for r in iter_rules(policy) if rule_ip_group_sides(r.rule, group_id)]


def referenced_ip_group_ids(policy: FirewallPolicyInfo) -> list[str]:
    """Every IP group id the chain's rules reference, first use first."""
    seen: dict[str, None] = {}
    for r in iter_rules(policy):
        for gid in (*r.rule.source_ip_groups, *r.rule.destination_ip_groups):
            seen.setdefault(gid, None)
    return list(seen)


__all__ = [
    "RuleRef", "SEPARATOR", "SIDES", "iter_rules", "policy_chain_names", "split_ref", "find_rule", "nearest_names",
    "parse_network", "address_matches", "rule_covers_address", "rule_ip_group_sides", "rules_using_ip_group",
    "referenced_ip_group_ids", "lookup_ip_group",
]
