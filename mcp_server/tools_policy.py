"""Policy-context tools: firewall, policy, rules and IP groups from the cached ARM snapshot.

Every tool reads ``state.context.snapshot``. While no snapshot is loaded (the
context is off, waits for a firewall id, is loading or failed) a tool answers
``context.unavailable_answer()`` instead of raising: a missing context is a
state to report, not a caller mistake. Caller mistakes (unknown rule, bad
address, bad port) are raised as ``ToolError`` with a sentence that names
what was wrong and, for names, the nearest existing ones.
"""
from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from viewer.azure_resources import FirewallPolicyInfo, IpGroupInfo
from viewer.cache import CachedSnapshot
from viewer.enrichment import _fqdn_matches, _port_matches

from .rules import (
    RuleRef,
    address_matches,
    find_rule,
    iter_rules,
    lookup_ip_group,
    nearest_names,
    parse_network,
    referenced_ip_group_ids,
    rule_ip_group_sides,
    rules_using_ip_group,
)
from .serialize import firewall_to_dict, ip_group_to_dict, policy_to_dict, rule_to_dict
from .state import AppState, get_state
from .tools_logs import DEFAULT_LIMIT, MAX_LIMIT, READ_ONLY, _call, _clamp

# A forced refresh reads ARM (outside this process) and rewrites the shared
# cache file, so it is neither read-only nor closed-world; repeating it is harmless.
REFRESH = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=True)

KINDS = ("dnat", "network", "application")
_KIND_ALIASES = {"nat": "dnat", "natrule": "dnat", "networkrule": "network", "net": "network",
                 "app": "application", "apprule": "application", "applicationrule": "application"}

NO_POLICY_REASON = ("The policy context is loaded, but carries no policy: the firewall has no policy attached "
                    "(classic rules), or the identity cannot read it.")
NO_POLICY_HINT = ("Check that the identity has Reader on the firewall policy (and its parent), then call "
                  "refresh_policy_context. get_firewall still answers from the loaded context.")


# ── shared helpers ───────────────────────────────────────────────────────────

def _snapshot(state: AppState) -> CachedSnapshot | None:
    return state.context.snapshot


def _no_policy_answer(snap: CachedSnapshot) -> dict[str, Any]:
    return {"available": False, "state": "loaded", "reason": NO_POLICY_REASON, "hint": NO_POLICY_HINT,
            "firewall": snap.firewall.name, "policy_id": snap.firewall.policy_id or None}


def _age(snap: CachedSnapshot) -> float:
    return round(snap.age_seconds(), 1)


def _normalise_kind(kind: str) -> str:
    key = kind.strip().lower().replace("_", "").replace(" ", "")
    key = _KIND_ALIASES.get(key, key)
    if key not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}, got {kind!r}.")
    return key


def _port_number(port: str | int) -> str:
    text = str(port).strip()
    if not text.isdigit() or not 0 <= int(text) <= 65535:
        raise ValueError(f"port must be a single port number 0..65535, got {port!r}.")
    return str(int(text))


def _fqdn_patterns(ref: RuleRef) -> list[str]:
    """Destination FQDN patterns of a rule: FQDNs, the host part of target URLs, a DNAT target FQDN."""
    rule = ref.rule
    hosts = [url.split("/", 1)[0] for url in rule.target_urls]
    return [p for p in (*rule.destination_fqdns, *hosts, rule.translated_fqdn) if p]


def _ip_group_names(snap: CachedSnapshot) -> list[str]:
    names = [g.name for g in snap.ip_groups.values()]
    if snap.policy is not None:
        names += [gid.rstrip("/").split("/")[-1] for gid in referenced_ip_group_ids(snap.policy)]
    return names


def _resolve_ip_group(snap: CachedSnapshot, wanted: str) -> tuple[str, IpGroupInfo | None]:
    """An IP group by name or id: ``(id as the rules spell it, the loaded group or None when unreadable)``.

    Unreadable groups (referenced by a rule, but not fetched) are found by id
    or by the name segment of the id.
    """
    text = wanted.strip()
    folded = text.casefold()
    referenced = referenced_ip_group_ids(snap.policy) if snap.policy is not None else []
    for gid, grp in snap.ip_groups.items():
        if folded in (grp.name.casefold(), grp.id.casefold(), gid.casefold()):
            return gid, grp
    for gid in referenced:
        if folded in (gid.casefold(), gid.rstrip("/").split("/")[-1].casefold()):
            return gid, lookup_ip_group(gid, snap.ip_groups)
    raise ValueError(f"No IP group {wanted!r} in the policy context. Nearest IP groups: "
                     f"{nearest_names(text, _ip_group_names(snap))}.")


def _check_name(kind: str, wanted: str, names: list[str]) -> None:
    if wanted.casefold() not in {n.casefold() for n in names}:
        raise ValueError(f"No {kind} {wanted!r} in the policy chain. Nearest: {nearest_names(wanted, names)}.")


def _unreadable_group(group_id: str, *, used_by: Any) -> dict[str, Any]:
    return {"id": group_id, "name": None, "location": None, "readable": False, "address_count": None,
            "used_by": used_by,
            "reason": "Referenced by a rule, but not loaded: the identity has no Reader on the IP group, "
                      "or it was deleted."}


# ── argument types (descriptions end up in the tool's JSON schema) ───────────
KindArg = Annotated[str | None, Field(
    description="Rule type: 'dnat', 'network' or 'application' (the firewall's three evaluation passes).")]
GroupArg = Annotated[str | None, Field(
    description="Rule collection group name, exact but case-insensitive. An unknown name is an error that "
                "lists the nearest names.")]
CollectionArg = Annotated[str | None, Field(description="Rule collection name, exact but case-insensitive.")]
RuleActionArg = Annotated[str | None, Field(
    description="Collection action, case-insensitive: Allow, Deny or Dnat.")]
NameArg = Annotated[str | None, Field(description="Substring of the rule name, case-insensitive.")]
AddressArg = Annotated[str | None, Field(
    description="An IP address or CIDR (IPv4 or IPv6). Keeps rules whose source or destination addresses, or "
                "the addresses of their IP groups, cover it: an entry that contains it, a wildcard '*', or for a "
                "CIDR also an entry that only overlaps it. Each rule then carries 'address_match' per side with "
                "the covering entry, the IP group it came from and relation 'contains', 'overlaps' or 'wildcard'. "
                "Service tags and unreadable IP groups cannot be compared and never match.")]
FqdnArg = Annotated[str | None, Field(
    description="A destination FQDN (www.example.com). Keeps rules whose destination FQDNs, target URL hosts or "
                "DNAT target FQDN match it as the firewall would ('*.example.com' covers www.example.com, '*' "
                "covers everything), or whose pattern text contains it as a substring.")]
PortArg = Annotated[str | int | None, Field(
    description="One destination port number. Keeps rules whose destination ports include it (single port, "
                "range such as 8000-8100, or '*').")]
IpGroupArg = Annotated[str | None, Field(
    description="IP group name or resource id. Keeps rules that use the group as source or destination.")]


def register(server: MCPServer) -> None:
    @server.tool(
        name="get_firewall",
        title="Firewall resource",
        description=(
            "The Azure Firewall resource from the cached ARM snapshot: SKU (sku_name, sku_tier), zones, "
            "provisioning_state, policy_id, ip_configs with private and public addresses, management_ip, subnets "
            "with CIDRs and attached NAT gateway, nat_gateways (readable=false: only the id is known; public IP "
            "names and addresses), maintenance_windows (maintenance_readable=false: the list could not be read, so "
            "an empty list means unknown, not none), diagnostic_settings (name, targets event_hub / workspace / "
            "storage, categories, all_logs), autoscale {min, max, mode: service_default | range | fixed | "
            "not_supported (Basic) | not_understood}, route_server_id, additional_properties, tags, cache_age_s "
            "(seconds since the snapshot was fetched). Answers available=false with a reason while the policy "
            "context is not loaded."),
        annotations=READ_ONLY,
    )
    async def get_firewall(ctx: Context[Any, Any]) -> dict[str, Any]:
        state = get_state(ctx)
        snap = _snapshot(state)
        if snap is None:
            return state.context.unavailable_answer()
        return firewall_to_dict(snap.firewall, snapshot=snap)

    @server.tool(
        name="get_policy",
        title="Firewall policy",
        description=(
            "The firewall policy's settings: sku_tier, threat_intel (mode, allow_fqdns, allow_ips), dns (proxy, "
            "servers), idps (mode, bypass and signature override counts), tls_inspection_ca, snat (private_ranges, "
            "auto_learn), explicit_proxy (ports; pac_file without its query string), parent (the inherited policy "
            "chain as nested settings), and 'groups': every rule collection group of the chain in evaluation order "
            "(inherited first) with policy, priority, collection_count, rule_count and per collection name, "
            "priority, action, kind, rule_count. include_rules=true adds each collection's rules in the get_rule "
            "shape (can be large; prefer list_rules with filters). Answers available=false with a reason while "
            "the policy context is not loaded."),
        annotations=READ_ONLY,
    )
    async def get_policy(
        ctx: Context[Any, Any],
        include_rules: Annotated[bool, Field(
            description="Add every rule to its collection (default false: counts only).")] = False,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        snap = _snapshot(state)
        if snap is None:
            return state.context.unavailable_answer()
        if snap.policy is None:
            return _no_policy_answer(snap)
        return {**policy_to_dict(snap.policy, include_rules=include_rules, ip_groups=snap.ip_groups),
                "cache_age_s": _age(snap)}

    @server.tool(
        name="list_rules",
        title="List and search policy rules",
        description=(
            "Rules of the policy chain in firewall evaluation order (DNAT, then network, then application; "
            "inherited groups first, then groups and collections by priority). Each rule: ref ('policy » group » "
            "collection » rule', pass it to get_rule), position in the evaluation order, policy, inherited, group "
            "and collection with priorities, kind, action, protocols, source and destination addresses, IP group "
            "names, FQDNs, ports, and the application or DNAT extras when present. Filters combine with AND. "
            f"Paging: limit (default {DEFAULT_LIMIT}, clamped to 1..{MAX_LIMIT}) and offset (default 0); the "
            "answer has total (matches before paging), returned, offset, has_more and next_offset. Answers "
            "available=false with a reason while the policy context is not loaded."),
        annotations=READ_ONLY,
    )
    async def list_rules(
        ctx: Context[Any, Any],
        kind: KindArg = None,
        group: GroupArg = None,
        collection: CollectionArg = None,
        action: RuleActionArg = None,
        name: NameArg = None,
        address: AddressArg = None,
        fqdn: FqdnArg = None,
        port: PortArg = None,
        ip_group: IpGroupArg = None,
        limit: Annotated[int, Field(description=f"Maximum rules returned, clamped to 1..{MAX_LIMIT}.")] = DEFAULT_LIMIT,
        offset: Annotated[int, Field(description="Matches to skip before the first returned rule.")] = 0,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        snap = _snapshot(state)
        if snap is None:
            return state.context.unavailable_answer()
        if snap.policy is None:
            return _no_policy_answer(snap)
        policy: FirewallPolicyInfo = snap.policy
        groups = policy.all_groups()
        want_kind = _call(lambda: _normalise_kind(kind)) if kind else None
        if group:
            _call(lambda: _check_name("rule collection group", group, [g.name for _, g in groups]))
        if collection:
            _call(lambda: _check_name("rule collection", collection,
                                      [rc.name for _, g in groups for rc in g.rule_collections]))
        net = _call(lambda: parse_network(address)) if address else None
        want_port = _call(lambda: _port_number(port)) if port is not None and str(port).strip() else None
        group_id = _call(lambda: _resolve_ip_group(snap, ip_group))[0] if ip_group else None

        matches: list[dict[str, Any]] = []
        for ref in iter_rules(policy):
            r = ref.rule
            if want_kind and ref.kind != want_kind:
                continue
            if group and ref.group.name.casefold() != group.casefold():
                continue
            if collection and ref.collection.name.casefold() != collection.casefold():
                continue
            if action and (ref.action or "").casefold() != action.strip().casefold():
                continue
            if name and name.casefold() not in r.name.casefold():
                continue
            if want_port is not None and not any(_port_matches(want_port, spec) for spec in r.destination_ports):
                continue
            if fqdn:
                patterns = _fqdn_patterns(ref)
                needle = fqdn.strip().casefold()
                if not (_fqdn_matches(needle, patterns) or any(needle in p.casefold() for p in patterns)):
                    continue
            if group_id is not None and not rule_ip_group_sides(r, group_id):
                continue
            covered: dict[str, Any] | None = None
            if net is not None:
                covered = address_matches(r, net, snap.ip_groups)
                if not covered:
                    continue
            entry = {**ref.placement(),
                     **rule_to_dict(r, ref=ref.ref, ip_groups=snap.ip_groups, sku_tier=policy.sku_tier, compact=True)}
            if covered is not None:
                entry["address_match"] = covered
            matches.append(entry)

        count = _clamp(limit, 1, MAX_LIMIT)
        start = max(0, int(offset))
        page = matches[start:start + count]
        has_more = start + len(page) < len(matches)
        echo = {"kind": want_kind, "group": group, "collection": collection, "action": action, "name": name,
                "address": address, "fqdn": fqdn, "port": want_port, "ip_group": ip_group}
        return {
            "rules": page,
            "total": len(matches),
            "returned": len(page),
            "offset": start,
            "has_more": has_more,
            "next_offset": start + len(page) if has_more else None,
            "filter": {k: v for k, v in echo.items() if v is not None},
            "cache_age_s": _age(snap),
        }

    @server.tool(
        name="get_rule",
        title="One policy rule in full",
        description=(
            "One rule with everything the policy holds about it. Name it by ref ('policy » group » collection » "
            "rule' as list_rules returns it; the policy part may be left out) or by group, collection and rule "
            "together; names compare case-insensitively. Returns the placement (position in evaluation order, "
            "priorities, kind, action, inherited), protocols, addresses, IP groups resolved to name and address "
            "count (readable=false keeps only the id of a group the identity cannot read), FQDNs, ports, FQDN tags, "
            "web categories, target URLs, the DNAT translated target, terminate_tls, http_headers (header NAMES "
            "only, values are never returned) and inserted_headers_land_in (which traffic gets those headers). An "
            "unknown name is an error that lists the nearest names. Answers available=false with a reason while "
            "the policy context is not loaded."),
        annotations=READ_ONLY,
    )
    async def get_rule(
        ctx: Context[Any, Any],
        ref: Annotated[str | None, Field(
            description="'policy » group » collection » rule' or 'group » collection » rule'.")] = None,
        group: Annotated[str | None, Field(description="Rule collection group name (with collection and rule).")] = None,
        collection: Annotated[str | None, Field(description="Rule collection name (with group and rule).")] = None,
        rule: Annotated[str | None, Field(description="Rule name (with group and collection).")] = None,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        snap = _snapshot(state)
        if snap is None:
            return state.context.unavailable_answer()
        if snap.policy is None:
            return _no_policy_answer(snap)
        policy = snap.policy
        found = _call(lambda: find_rule(policy, ref, group=group, collection=collection, rule=rule))
        return {**found.placement(),
                **rule_to_dict(found.rule, ref=found.ref, ip_groups=snap.ip_groups, sku_tier=policy.sku_tier),
                "cache_age_s": _age(snap)}

    @server.tool(
        name="list_ip_groups",
        title="List IP groups",
        description=(
            "IP groups the policy's rules reference: id, name, location, address_count and used_by (number of "
            "rules that use the group as source or destination). Groups a rule references but the identity could "
            "not read appear with readable=false and their id. 'name' filters by a case-insensitive substring of "
            "the name. Use get_ip_group for the addresses. Answers available=false with a reason while the policy "
            "context is not loaded."),
        annotations=READ_ONLY,
    )
    async def list_ip_groups(
        ctx: Context[Any, Any],
        name: Annotated[str | None, Field(description="Substring of the IP group name, case-insensitive.")] = None,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        snap = _snapshot(state)
        if snap is None:
            return state.context.unavailable_answer()
        policy = snap.policy

        def used_by(group_id: str) -> int:
            return len(rules_using_ip_group(policy, group_id)) if policy is not None else 0

        entries: list[dict[str, Any]] = [ip_group_to_dict(grp, used_by=used_by(gid), include_addresses=False)
                                         for gid, grp in snap.ip_groups.items()]
        for gid in referenced_ip_group_ids(policy) if policy is not None else []:
            if lookup_ip_group(gid, snap.ip_groups) is None:
                entries.append(_unreadable_group(gid, used_by=used_by(gid)))
        if name:
            needle = name.casefold()
            entries = [e for e in entries
                       if needle in (e["name"] or e["id"].rstrip("/").split("/")[-1]).casefold()]
        entries.sort(key=lambda e: (e["name"] or e["id"]).casefold())
        return {"ip_groups": entries, "total": len(entries), "cache_age_s": _age(snap)}

    @server.tool(
        name="get_ip_group",
        title="One IP group with its addresses",
        description=(
            "One IP group by name or resource id (case-insensitive): id, name, location, addresses (as written: "
            "addresses, CIDRs, ranges), address_count and used_by (the rules that reference it, each with ref, "
            "kind, action and the sides 'source' / 'destination'). A group a rule references but the identity "
            "cannot read answers readable=false without addresses. An unknown group is an error that lists the "
            "nearest names. Answers available=false with a reason while the policy context is not loaded."),
        annotations=READ_ONLY,
    )
    async def get_ip_group(
        ctx: Context[Any, Any],
        name: Annotated[str | None, Field(description="IP group name.")] = None,
        id: Annotated[str | None, Field(description="IP group resource id (instead of name).")] = None,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        snap = _snapshot(state)
        if snap is None:
            return state.context.unavailable_answer()
        wanted = id or name
        if not wanted or not wanted.strip():
            raise ToolError("Pass the IP group's name or id.")
        group_id, grp = _call(lambda: _resolve_ip_group(snap, wanted))
        refs = rules_using_ip_group(snap.policy, group_id) if snap.policy is not None else []
        used_by = [{"ref": r.ref, "kind": r.kind, "action": r.action or None,
                    "sides": rule_ip_group_sides(r.rule, group_id)} for r in refs]
        if grp is None:
            return {**_unreadable_group(group_id, used_by=used_by), "addresses": None, "cache_age_s": _age(snap)}
        return {**ip_group_to_dict(grp), "used_by": used_by, "cache_age_s": _age(snap)}

    @server.tool(
        name="refresh_policy_context",
        title="Re-fetch the policy context from Azure",
        description=(
            "Fetch firewall, policy chain and IP groups from Azure Resource Manager now, bypassing the cache, and "
            "rewrite the cache file the TUI shares. Read-only against Azure. Use it after a rule change, or when "
            "get_status shows the context unavailable. Returns the context state ('loaded', 'unavailable'), "
            "available, age_s, fetched_at (ISO 8601 UTC) and reason (why a fetch failed; a failed refresh keeps "
            "the previous snapshot). Answers available=false without fetching while the context is off or no "
            "firewall is known yet."),
        annotations=REFRESH,
    )
    async def refresh_policy_context(ctx: Context[Any, Any]) -> dict[str, Any]:
        state = get_state(ctx)
        context = state.context
        if context.state in ("off", "waiting_for_firewall_id"):
            return context.unavailable_answer()
        status = await context.refresh(force=True)
        return {**status, "available": context.snapshot is not None}


__all__ = ["register", "KINDS"]
