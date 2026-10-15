"""Analysis tools: summaries, evaluation traces, address lookup and log coverage.

``summarize_logs`` and the ``recent`` part of ``lookup_address`` only need the
log buffer. Everything that evaluates the policy (``explain_log_entry``,
``trace_flow``, the rule and IP-group parts of ``lookup_address``,
``get_log_coverage``) needs the policy context and answers with the context's
``unavailable_answer()`` while it is not loaded, instead of failing.
"""
from __future__ import annotations

import ipaddress
import re
import time
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Annotated, Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from helpers import address_matches
from viewer.azure_resources import DiagnosticSetting, IpGroupInfo
from viewer.cache import CachedSnapshot
from viewer.enrichment import ParsedEntry, parse_address_entries, resolve_fw_instance
from viewer.trace import (
    APP_PROTOCOLS,
    PASS_ORDER,
    Flow,
    build_trace,
    find_logged_rule,
    flow_from_row,
    logged_from_row,
    no_decision_reason,
)

from .buffer import BufferedRow
from .filters import LogFilter, parse_duration
from .serialize import iso_utc, row_to_dict, rule_path, with_replay_note
from .serialize_trace import (
    flow_to_dict,
    hypothetical_trace,
    matched_rule_to_dict,
    nearest_misses_to_dict,
    outcome_sentence,
    rule_ref,
    trace_to_dict,
    unevaluable_rules,
    verdict,
)
from .state import AppState, get_state
from .tools_logs import (
    READ_ONLY,
    ActionArg,
    CategoryArg,
    DestinationArg,
    DstPortArg,
    ProtocolArg,
    RuleArg,
    SourceArg,
    SrcPortArg,
    TextArg,
    UntilArg,
    _call,
    _clamp,
    _trace_reason,
)

DEFAULT_SINCE = "15m"
DEFAULT_BUCKET = "1m"
MIN_BUCKET_S = 10
MAX_BUCKET_S = 3600
DEFAULT_TOP = 10
MAX_TOP = 100
MAX_TIMELINE_BUCKETS = 500
RECENT_WINDOW_S = 15 * 60
NEAREST_MISSES = 3
DEFAULT_RULE_LIMIT = 100
MAX_RULE_LIMIT = 500

# Azure's category names (structured and legacy) as the viewer calls them.
AZURE_TO_DISPLAY = {
    "azfwnetworkrule": "NetworkRule",
    "azfwapplicationrule": "AppRule",
    "azfwnatrule": "NATRule",
    "azfwdnsquery": "DnsQuery",
    "azfwfqdnresolvefailure": "DnsFailure",
    "azfwidpssignature": "IDPS",
    "azfwthreatintel": "ThreatIntel",
    "azfwflowtrace": "FlowTrace",
    "azfwfatflow": "FatFlow",
    "azurefirewallnetworkrule": "NetworkRule",
    "azurefirewallapplicationrule": "AppRule",
    "azurefirewallnatrule": "NATRule",
    "azurefirewalldnsproxy": "DnsQuery",
}
DISPLAY_ORDER = ("NetworkRule", "AppRule", "NATRule", "ThreatIntel", "IDPS", "DnsQuery", "DnsFailure",
                 "FlowTrace", "FatFlow")

_FQDN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")
_DEFAULT_APP_PORTS = {"HTTP": "80", "HTTPS": "443", "MSSQL": "1433"}
_FLOW_PROTOCOLS = ("TCP", "UDP", "ICMP", *APP_PROTOCOLS)

SinceWindowArg = Annotated[str | None, Field(
    description="Start of the window: relative (30s, 15m, 2h, 1d back from now) or ISO 8601. Default 15m; "
                "pass an empty string for the whole buffer. Compared with the log's own timestamp.")]
TopArg = Annotated[int, Field(description=f"Entries per top list, clamped to 1..{MAX_TOP}.")]
BucketArg = Annotated[str, Field(
    description=f"Timeline bucket width: a duration from 10s to 1h (10s, 30s, 1m, 5m, 1h). Default {DEFAULT_BUCKET}.")]


# ── helpers ──────────────────────────────────────────────────────────────────

def _bucket_label(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _top(counter: Counter[str], key: str, top: int) -> list[dict[str, Any]]:
    return [{key: name, "count": count} for name, count in counter.most_common(top)]


def _missing_row(state: AppState, row_id: int) -> str:
    buf = state.buffer
    bounds = f"ids {buf.first_id} to {buf.last_id} are buffered" if buf.first_id is not None else "the buffer is empty"
    return f"No row with id {row_id}: {bounds}. Older rows are dropped when the buffer is full or after clear_logs."


def _no_policy_answer(state: AppState) -> dict[str, Any]:
    return {"available": False, "state": state.context.state,
            "reason": "The policy context is loaded, but carries no policy: the policy could not be read, "
                      "or the firewall uses classic rules.",
            "hint": "Call get_firewall to see which policy is attached, then refresh_policy_context."}


def _loaded_policy(state: AppState) -> tuple[CachedSnapshot | None, dict[str, Any] | None]:
    """The snapshot when it carries a policy, else the answer to give instead."""
    snap = state.context.snapshot
    if snap is None:
        return None, state.context.unavailable_answer()
    if snap.policy is None:
        return None, _no_policy_answer(state)
    return snap, None


# ── summarize_logs ───────────────────────────────────────────────────────────

def summarize(state: AppState, flt: LogFilter, *, top: int, bucket_s: int, now: float) -> dict[str, Any]:
    """Counts and top lists over the rows that match ``flt``; needs no policy context."""
    buffered = state.buffer.snapshot()
    rows = [item for item in buffered if flt.matches(item)]

    by_category: Counter[str] = Counter()
    by_action: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    denied_destinations: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    default_denies: Counter[tuple[str, str, str, str]] = Counter()
    default_reasons: Counter[str] = Counter()
    buckets: dict[float, list[int]] = {}
    denies = 0
    denied_without_rule = 0

    for item in rows:
        row = item.row
        is_deny = row.action.strip().lower() == "deny"
        by_category[row.category] += 1
        by_action[row.action if row.action not in ("", "-") else "(none)"] += 1
        if row.sourceip not in ("", "-"):
            sources[row.sourceip] += 1
        if row.targetip not in ("", "-"):
            destinations[row.targetip] += 1
        if row.targetport not in ("", "-"):
            ports[row.targetport] += 1
        if row.rule_name:
            rules[rule_path(row.policy) or row.rule_name] += 1
        if is_deny:
            denies += 1
            denied_destinations[row.targetip] += 1
            if not row.rule_name:
                denied_without_rule += 1
                default_denies[(row.sourceip, row.targetip, row.targetport, row.protocol)] += 1
                default_reasons[row.policy or "(no reason logged)"] += 1
        start = (item.effective_time // bucket_s) * bucket_s
        slot = buckets.setdefault(start, [0, 0])
        slot[0] += 1
        slot[1] += int(is_deny)

    timeline = [{"bucket": _bucket_label(start), "count": counts[0], "denies": counts[1]}
                for start, counts in sorted(buckets.items())]
    timeline_truncated = len(timeline) > MAX_TIMELINE_BUCKETS
    if timeline_truncated:
        timeline = timeline[-MAX_TIMELINE_BUCKETS:]

    oldest = buffered[0] if buffered else None
    oldest_inside = bool(oldest is not None and flt.since is not None and oldest.effective_time >= flt.since)
    window: dict[str, Any] = {
        "from": iso_utc(flt.since),
        "to": iso_utc(flt.until if flt.until is not None else now),
        "rows": len(rows),
        "buffer_oldest": iso_utc(oldest.effective_time) if oldest is not None else None,
        "buffer_oldest_in_window": oldest_inside,
    }
    if oldest_inside:
        window["note"] = ("The oldest buffered row lies inside the window: rows from the start of the window may "
                          "be missing (the server started later, or the buffer dropped them).")
    return {
        "window": window,
        "filter": flt.echo(),
        "denies": denies,
        "by_category": dict(by_category.most_common()),
        "by_action": dict(by_action.most_common()),
        "top_sources": _top(sources, "address", top),
        "top_destinations": _top(destinations, "address", top),
        "top_rules": _top(rules, "rule", top),
        "top_denied_destinations": _top(denied_destinations, "address", top),
        "top_dst_ports": _top(ports, "port", top),
        "denied_without_rule": {
            "count": denied_without_rule,
            "reasons": _top(default_reasons, "reason", top),
            "top": [{"source": src, "destination": dst, "dst_port": port if port != "-" else None,
                     "protocol": proto if proto != "-" else None, "count": count}
                    for (src, dst, port, proto), count in default_denies.most_common(top)],
        },
        "bucket_seconds": bucket_s,
        "timeline": timeline,
        "timeline_truncated": timeline_truncated,
    }


# ── explain_log_entry ────────────────────────────────────────────────────────

def explain(state: AppState, item: BufferedRow, *, full_tree: bool) -> dict[str, Any]:
    """The row, how the policy decided it and which rules came closest."""
    base = row_to_dict(item, "summary")
    reason = _trace_reason(state, item)
    if reason is not None:
        if state.context.snapshot is None:
            # A context that is not loaded explains itself; an observation row
            # (FlowTrace, DNS) has its own reason and is not a context problem.
            if no_decision_reason(item.row.category) is None:
                return {**base, "traceable": False, **state.context.unavailable_answer()}
        return {**base, "traceable": False, "reason": reason}

    snap = state.context.snapshot
    assert snap is not None and snap.policy is not None   # _trace_reason returned None
    flow = flow_from_row(item.row)
    logged = logged_from_row(item.row)
    trace = build_trace(flow, snap.policy, snap.ip_groups, logged)

    note = None
    if logged and find_logged_rule(snap.policy, logged) is None:
        refreshing = state.context.note_unknown_rule(item.row.rule_name)
        note = (f"The rule the firewall logged ({logged.group} » {logged.collection} » {logged.rule}) is not in the "
                "loaded policy snapshot, so the evaluation path cannot be shown. "
                + ("A refresh of the policy context was started; ask again in a few seconds."
                   if refreshing else "Call refresh_policy_context if the policy changed recently."))
    return {
        **base,
        "traceable": True,
        "verdict": verdict(trace),
        "outcome": outcome_sentence(trace, flow),
        "matched_rule": matched_rule_to_dict(trace),
        "nearest_misses": nearest_misses_to_dict(trace, NEAREST_MISSES, snap.ip_groups),
        "note": note,
        "trace": trace_to_dict(trace, full_tree=full_tree, ip_groups=snap.ip_groups),
        "policy_context": state.context.status(),
    }


# ── trace_flow ───────────────────────────────────────────────────────────────

def _fqdn_or_ip(destination: str) -> tuple[str, str]:
    """``(ip, fqdn)`` of a destination, one of them empty."""
    text = (destination or "").strip()
    if not text:
        raise ValueError("destination is empty: give an IP address or an FQDN.")
    try:
        return str(ipaddress.ip_address(text)), ""
    except ValueError:
        pass
    if "/" in text:
        raise ValueError(f"destination {destination!r} is a network or URL: give a single IP address or an FQDN "
                         "(for a CIDR use lookup_address).")
    name = text.rstrip(".").lower()
    if re.fullmatch(r"[\d.]+", name) or not _FQDN_RE.match(name):
        raise ValueError(f"destination {destination!r} is neither a valid IP address nor an FQDN.")
    return "", name


def build_flow(protocol: str, source: str, destination: str, dst_port: str | int | None, explicit_proxy: bool,
               tls_inspected: bool | None, destination_ip: str | None = None) -> Flow:
    """Validate the arguments of ``trace_flow`` and turn them into the flow the trace evaluates."""
    proto = (protocol or "").strip().upper()
    if proto not in _FLOW_PROTOCOLS:
        raise ValueError(f"protocol {protocol!r} is not one of {', '.join(_FLOW_PROTOCOLS)}.")
    try:
        src = str(ipaddress.ip_address((source or "").strip()))
    except ValueError:
        raise ValueError(f"source {source!r} is not an IP address (a single address, not a CIDR).") from None
    resolved = ""
    if destination_ip not in (None, ""):
        try:
            resolved = str(ipaddress.ip_address(str(destination_ip).strip()))
        except ValueError:
            raise ValueError(f"destination_ip {destination_ip!r} is not an IP address (a single address, "
                             "not a CIDR).") from None
    dst_ip, dst_fqdn = _fqdn_or_ip(destination)
    if resolved:
        if dst_ip:
            raise ValueError("destination_ip is for an FQDN destination: the destination is already an IP address.")
        dst_ip = resolved

    port = "" if dst_port is None else str(dst_port).strip()
    if proto == "ICMP":
        # ICMP has no port; "*" is what an ICMP rule lists, and it keeps the
        # port check from turning every ICMP rule into "unknown".
        port = "*"
    elif not port:
        if proto in _DEFAULT_APP_PORTS:
            port = _DEFAULT_APP_PORTS[proto]
        else:
            raise ValueError(f"dst_port is required for {proto}.")
    if port != "*" and not (port.isdigit() and 0 <= int(port) <= 65535):
        raise ValueError(f"dst_port {dst_port!r} is not a port number between 0 and 65535.")

    return Flow(
        category="AppRule" if proto in APP_PROTOCOLS else "NetworkRule",
        protocol=proto, src_ip=src, dst_ip=dst_ip, dst_fqdn=dst_fqdn, dst_port=port,
        explicit_proxy=bool(explicit_proxy), tls_inspected=tls_inspected,
    )


def _caveats(flow: Flow) -> list[str]:
    out = [
        "Service tags, FQDN tags, web categories and IP groups that cannot be read are not evaluated locally: "
        "rules that depend on them are 'unknown', and an unknown rule before the first match makes the verdict "
        "'unknown'.",
        "Threat Intelligence, IDPS and the built-in infrastructure FQDNs are not evaluated for a hypothetical flow.",
    ]
    if flow.category == "AppRule" and not flow.dst_fqdn:
        out.append("Application rules match on the host name, not the IP: with an IP destination they stay unknown. "
                   "Pass the FQDN as destination (and the IP as destination_ip) to evaluate them.")
    if flow.dst_fqdn and not flow.dst_ip:
        out.append("The destination is a name only: network and DNAT rules compare addresses and stay unknown "
                   "(except rules that list FQDNs). Pass destination_ip, the address the name resolves to, to "
                   "evaluate them.")
    if flow.protocol == "TCP" and flow.dst_port in ("80", "443", "1433"):
        out.append("Protocol TCP skips application rules. Use protocol HTTP, HTTPS or MSSQL (with the FQDN) to "
                   "include them.")
    if flow.protocol == "HTTP" and flow.tls_inspected is None:
        out.append("tls_inspected was not given: a rule that differs for plain HTTP and TLS-inspected HTTPS is "
                   "'unknown' for protocol HTTP.")
    return out


def trace_hypothetical(state: AppState, flow: Flow, *, full_tree: bool) -> dict[str, Any]:
    snap, unavailable = _loaded_policy(state)
    if snap is None or snap.policy is None:
        return {**(unavailable or {}), "flow": flow_to_dict(flow)}
    trace, uncertain = hypothetical_trace(flow, snap.policy, snap.ip_groups)
    return {
        "verdict": verdict(trace, uncertain=uncertain),
        "outcome": outcome_sentence(trace, flow, hypothetical=True, uncertain=uncertain),
        "matched_rule": matched_rule_to_dict(trace),
        "nearest_misses": (nearest_misses_to_dict(trace, NEAREST_MISSES, snap.ip_groups)
                           if trace.matched_rule is None else []),
        "unevaluable_rules": unevaluable_rules(trace),
        "caveats": _caveats(flow),
        "trace": trace_to_dict(trace, full_tree=full_tree, hypothetical=True, ip_groups=snap.ip_groups),
        "policy_context": state.context.status(),
    }


# ── lookup_address ───────────────────────────────────────────────────────────

Target = tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ipaddress.IPv4Address | ipaddress.IPv6Address]


def parse_target(address: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    text = (address or "").strip()
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"address {address!r} is neither an IP address nor a CIDR network "
                         "(10.0.0.5, 10.0.0.0/24, fd10::/16).") from None


def _relation(entry_range: tuple[Any, Any], target: Target) -> str | None:
    """How an address entry relates to the queried address or network, ``None`` when disjoint."""
    start, end = entry_range
    t_start, t_end = target
    if start.version != t_start.version:
        return None
    if int(start) <= int(t_start) and int(t_end) <= int(end):
        return "contains"
    if int(t_start) <= int(start) and int(end) <= int(t_end):
        return "inside"
    if int(start) <= int(t_end) and int(end) >= int(t_start):
        return "overlaps"
    return None


_RELATION_RANK = {"contains": 0, "inside": 1, "overlaps": 2}


def _best_entry(parsed: Iterable[ParsedEntry], target: Target) -> tuple[str, str] | None:
    """The entry that relates closest to ``target`` (contains, then inside, then overlaps)."""
    best: tuple[str, str] | None = None
    for entry, rng in parsed:
        relation = _relation(rng, target)
        if relation is None:
            continue
        if best is None or _RELATION_RANK[relation] < _RELATION_RANK[best[1]]:
            best = (entry, relation)
    return best


def _coverage(addresses: list[str], group_ids: list[str], target: Target,
              ip_groups: dict[str, IpGroupInfo]) -> tuple[str, str, bool] | None:
    """``(via, relation, wildcard)`` when a rule's address list or IP groups cover ``target``."""
    if any(a.strip().lower() in ("*", "any") for a in addresses):
        return "*", "contains", True
    parsed, _unreadable = parse_address_entries(addresses)
    hit = _best_entry(parsed, target)
    if hit is not None:
        return hit[0], hit[1], False
    for gid in group_ids:
        grp = ip_groups.get(gid)
        if grp is None:
            continue
        parsed, _unreadable = parse_address_entries(grp.ip_addresses)
        hit = _best_entry(parsed, target)
        if hit is not None:
            return f"ip-group:{grp.name} ({hit[0]})", hit[1], False
    return None


def _recent(state: AppState, address: str, now: float) -> dict[str, Any]:
    needle = address.lower()
    cutoff = now - RECENT_WINDOW_S
    as_source = as_destination = 0
    actions: Counter[str] = Counter()
    for item in state.buffer.snapshot():
        if item.effective_time < cutoff:
            continue
        row = item.row
        src = address_matches(needle, row.sourceip)
        dst = address_matches(needle, row.targetip)
        as_source += int(src)
        as_destination += int(dst)
        if src or dst:
            actions[row.action if row.action not in ("", "-") else "(none)"] += 1
    return {"window": "15m", "as_source": as_source, "as_destination": as_destination,
            "top_actions": _top(actions, "action", 5)}


def lookup(state: AppState, address: str, *, limit: int, now: float) -> dict[str, Any]:
    net = parse_target(address)
    host = net.num_addresses == 1
    target: Target = (net.network_address, net.broadcast_address)
    shown = str(net.network_address) if host else str(net)
    out: dict[str, Any] = {"address": shown, "kind": "host" if host else "network",
                           "recent": _recent(state, shown, now)}

    snap = state.context.snapshot
    if snap is None:
        out["policy_context"] = state.context.unavailable_answer()
        return out

    notes: list[str] = []
    out["fw_instance"] = resolve_fw_instance(shown, snap.subnet_cidrs) if host else None

    groups: list[dict[str, Any]] = []
    for grp in snap.ip_groups.values():
        parsed, unreadable = parse_address_entries(grp.ip_addresses)
        hit = _best_entry(parsed, target)
        if hit is not None:
            groups.append({"name": grp.name, "id": grp.id, "matching_entry": hit[0], "relation": hit[1]})
        elif unreadable:
            notes.append(f"IP group {grp.name} has entries that cannot be read ({', '.join(unreadable[:3])}); "
                         "it may cover this address.")
    out["ip_groups"] = groups

    if snap.policy is None:
        out["rules"], out["rules_total"], out["rules_truncated"] = [], 0, False
        notes.append(_no_policy_answer(state)["reason"])
        out["notes"] = notes
        return out

    found: list[dict[str, Any]] = []
    for kind in PASS_ORDER:
        for policy_name, group in snap.policy.all_groups():
            for rc in sorted(group.rule_collections, key=lambda c: c.priority):
                if rc.kind != kind:
                    continue
                for rule in rc.rules:
                    for role, addresses, group_ids in (
                        ("source", rule.source_addresses, rule.source_ip_groups),
                        ("destination", rule.destination_addresses, rule.destination_ip_groups),
                    ):
                        cover = _coverage(addresses, group_ids, target, snap.ip_groups)
                        if cover is None:
                            continue
                        via, relation, wildcard = cover
                        found.append({
                            "ref": rule_ref(policy_name, group.name, rc.name, rule.name),
                            "kind": kind,
                            "action": rc.action or None,
                            "as": role,
                            "via": via,
                            "relation": relation,
                            "wildcard": wildcard,
                            "group_priority": group.priority,
                            "collection_priority": rc.priority,
                        })
    # Rules that name the address (or a range around it) come before the ones
    # that merely say "any"; each half keeps the firewall's evaluation order.
    found.sort(key=lambda entry: entry["wildcard"])
    out["rules_total"] = len(found)
    out["rules_truncated"] = len(found) > limit
    out["rules"] = found[:limit]
    out["notes"] = notes
    return out


# ── get_log_coverage ─────────────────────────────────────────────────────────

def _display_names(setting: DiagnosticSetting) -> tuple[set[str], list[str]]:
    """The viewer categories a setting forwards, and the Azure categories this viewer has no row type for."""
    if setting.all_logs:
        return set(DISPLAY_ORDER), []
    shown: set[str] = set()
    other: list[str] = []
    for name in setting.categories:
        display = AZURE_TO_DISPLAY.get(name.lower())
        if display is None:
            other.append(name)
        else:
            shown.add(display)
    return shown, other


def _targets_hub(setting: DiagnosticSetting, namespace: str, hub: str) -> bool:
    """Whether the setting's Event Hub is the one this server reads (same rule as the TUI)."""
    if not setting.event_hub:
        return False
    if not hub:   # the connected hub cannot be identified: every Event Hub target counts
        return True
    t_ns, _, t_hub = setting.event_hub.rpartition("/")
    return t_hub.lower() == hub and (not namespace or not t_ns or t_ns.lower() == namespace)


def _switch(properties: dict[str, str], *needles: str) -> tuple[str | None, bool]:
    """``(key, on)`` of the first additionalProperties key that contains one of ``needles``."""
    for key, value in properties.items():
        if any(needle in key.lower() for needle in needles):
            return key, str(value).strip().lower() == "true"
    return None, False


def coverage(state: AppState) -> dict[str, Any]:
    """Which log categories the diagnostic settings forward against which ones actually arrived."""
    observed = {name: count for name, count in sorted(state.buffer.per_category.items(),
                                                      key=lambda kv: (-kv[1], kv[0])) if count > 0}
    snap = state.context.snapshot
    if snap is None:
        return {**state.context.unavailable_answer(), "observed": observed}

    raw_ns, raw_hub = state.config.eventhub.display_endpoint
    namespace, hub = raw_ns.split(".")[0].lower(), raw_hub.lower()
    settings: list[dict[str, Any]] = []
    forwarded: set[str] = set()
    other_forwarded: list[str] = []
    connected_count = 0
    for setting in snap.diagnostics:
        shown, other = _display_names(setting)
        connected = _targets_hub(setting, namespace, hub)
        if connected:
            connected_count += 1
            forwarded |= shown
            other_forwarded.extend(name for name in other if name not in other_forwarded)
        targets = [{"kind": kind, "name": name} for kind, name in
                   (("event_hub", setting.event_hub), ("workspace", setting.workspace), ("storage", setting.storage))
                   if name]
        settings.append({
            "name": setting.name,
            "targets": targets,
            "categories": list(setting.categories),
            "all_logs": setting.all_logs,
            "forwards": [name for name in DISPLAY_ORDER if name in shown],
            "feeds_connected_hub": connected,
        })

    forwarded_list = [name for name in DISPLAY_ORDER if name in forwarded]
    not_seen = [name for name in forwarded_list if observed.get(name, 0) == 0]
    # Without a setting for this hub the forwarded set is unknown, not empty.
    not_forwarded = [name for name in observed if name not in forwarded] if connected_count else []

    hints: list[dict[str, str]] = []
    if not connected_count:
        where = f"{raw_ns}/{raw_hub}" if raw_ns else (raw_hub or "the connected Event Hub")
        why = ("No diagnostic setting could be read for the firewall (the identity may lack Reader on them)."
               if not snap.diagnostics else "None of the diagnostic settings targets this hub.")
        hints.append({"code": "no_setting_targets_hub",
                      "message": f"{why} Logs arriving at {where} then come from a setting this server cannot see."})
    fat_key, fat_on = _switch(snap.firewall.additional_properties, "fatflow")
    if "FatFlow" in forwarded and not fat_on:
        hints.append({"code": "fat_flow_logging_off",
                      "message": "FatFlow is forwarded, but fat flow logging is switched off on the firewall"
                                 + (f" ({fat_key})" if fat_key else " (no EnableFatFlowLogging property)")
                                 + ", so no FatFlow record is produced."})
    dns_key, dns_on = _switch(snap.firewall.additional_properties, "dnstap", "dnsflow")
    if "DnsQuery" in not_seen:
        if snap.policy is not None and not snap.policy.dns_proxy:
            hints.append({"code": "dns_proxy_off",
                          "message": "DnsQuery is forwarded, but the DNS proxy is not enabled in the policy, so the "
                                     "firewall logs no DNS queries."})
        if not dns_on:
            hints.append({"code": "dns_flow_trace_off",
                          "message": "DNS flow trace logging is switched off on the firewall"
                                     + (f" ({dns_key})" if dns_key else " (no EnableDnstapLogging property)")
                                     + "; it adds the detailed DNS records."})
    if "FlowTrace" in not_seen:
        hints.append({"code": "flow_trace_never_seen",
                      "message": "FlowTrace is forwarded but no record has arrived. Flow trace logs need a feature "
                                 "registration on the subscription besides the diagnostic setting; without it the "
                                 "category stays empty."})
    return {
        "connected_hub": {"namespace": raw_ns or None, "hub": raw_hub or None},
        "diagnostic_settings": settings,
        "settings_feeding_hub": connected_count,
        "forwarded": forwarded_list,
        "forwarded_other_categories": other_forwarded,
        "observed": observed,
        "forwarded_not_seen": not_seen,
        "seen_not_forwarded": not_forwarded,
        "hints": hints,
        "policy_context": state.context.status(),
    }


# ── registration ─────────────────────────────────────────────────────────────

def register(server: MCPServer) -> None:
    @server.tool(
        name="summarize_logs",
        title="Summarise buffered firewall logs",
        description=(
            "Counts and top lists over a time window of the buffered rows; needs no policy context. Returns "
            "window (from, to, rows, buffer_oldest and buffer_oldest_in_window: true means the buffer may not "
            "reach back to the start of the window), denies, by_category, by_action, top_sources, "
            "top_destinations, top_rules, top_denied_destinations (rows whose action is Deny), top_dst_ports, "
            "denied_without_rule (denies that no rule decided: the default action, with their reasons and top "
            "flows) and timeline (one entry per bucket with count and denies). The filters are the ones of "
            "query_logs and combine with AND. Start here to see what is happening, then query_logs or "
            "explain_log_entry for single rows. While the server is still replaying the hub's retention after "
            "its start, the answer carries a 'note' and the counts are not final yet."),
        annotations=READ_ONLY,
    )
    async def summarize_logs(
        ctx: Context[Any, Any],
        category: CategoryArg = None,
        action: ActionArg = None,
        source: SourceArg = None,
        destination: DestinationArg = None,
        protocol: ProtocolArg = None,
        dst_port: DstPortArg = None,
        src_port: SrcPortArg = None,
        rule: RuleArg = None,
        text: TextArg = None,
        since: SinceWindowArg = DEFAULT_SINCE,
        until: UntilArg = None,
        top: TopArg = DEFAULT_TOP,
        bucket: BucketArg = DEFAULT_BUCKET,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        now = time.time()
        flt = _call(lambda: LogFilter.build(
            category=category, action=action, source=source, destination=destination, protocol=protocol,
            dst_port=dst_port, src_port=src_port, rule=rule, text=text, since=since or None, until=until, now=now))
        seconds = parse_duration(bucket or DEFAULT_BUCKET)
        if seconds is None or not MIN_BUCKET_S <= seconds <= MAX_BUCKET_S:
            raise ToolError(f"bucket must be a duration from 10s to 1h (for example 10s, 1m, 5m, 1h), got {bucket!r}.")
        return with_replay_note(state, summarize(state, flt, top=_clamp(top, 1, MAX_TOP), bucket_s=int(seconds),
                                                 now=now))

    @server.tool(
        name="explain_log_entry",
        title="Explain why a row was allowed or denied",
        description=(
            "Explains one buffered rule-decision row (NetworkRule, AppRule, NATRule, ThreatIntel) by replaying it "
            "through the loaded policy: Azure Firewall's order is Threat Intelligence, then the DNAT, Network and "
            "Application passes, the first matching rule decides, and no match means the default Deny. Returns the "
            "row, verdict (allow, deny, dnat, unknown), outcome (one sentence), matched_rule (ref "
            "'policy » group » collection » rule', priorities, action; null for a default-action deny), "
            "nearest_misses (up to 3 rules that came closest, each with the failing criterion, observed against "
            "expected) and trace (passes → collections → rules → checks with status match, miss, unknown or n/a). "
            "The trace is folded: collections that missed collapse into a count, collections after the deciding "
            "rule into a not_evaluated count; collections with an 'unknown' rule stay open. Pass full_tree=true to "
            "unfold everything. FlowTrace, FatFlow, DNS and IDPS rows are observations and answer traceable=false "
            "with the reason. Without the policy context the answer is the row plus available=false."),
        annotations=READ_ONLY,
    )
    async def explain_log_entry(
        ctx: Context[Any, Any],
        id: Annotated[int, Field(description="Row id from query_logs or tail_logs.")],
        full_tree: Annotated[bool, Field(
            description="true: list every collection and rule instead of the folded view.")] = False,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        item = state.buffer.get(id)
        if item is None:
            raise ToolError(_missing_row(state, id))
        return explain(state, item, full_tree=full_tree)

    @server.tool(
        name="trace_flow",
        title="Trace a hypothetical flow through the policy",
        description=(
            "Answers 'would this traffic pass?' for a flow that need not exist in the logs, by evaluating the "
            "loaded policy in the firewall's order (DNAT, Network, Application; the first matching rule decides; "
            "otherwise the default Deny). protocol: TCP, UDP, ICMP, HTTP, HTTPS or MSSQL; HTTP, HTTPS and MSSQL "
            "also run the application rules, which match on the FQDN, so pass the destination as a name for them "
            "(TCP never runs application rules). source: one IP address. destination: an IP address or an FQDN; for "
            "an FQDN pass destination_ip as well (the address it resolves to) so network rules can be judged. "
            "dst_port is required for TCP and UDP and defaults to 80, 443 and 1433 for HTTP, HTTPS and MSSQL. "
            "tls_inspected: leave it out when unknown. Returns verdict (allow, deny, dnat, unknown), outcome, "
            "matched_rule (the first rule that would match), nearest_misses when nothing matches, "
            "unevaluable_rules (why a verdict is unknown), caveats and the folded trace (same shape as "
            "explain_log_entry). Service tags, FQDN tags, web categories and unreadable IP groups cannot be "
            "evaluated: a rule that depends on one is 'unknown', and an unknown rule before the first match makes "
            "the verdict 'unknown'. Threat Intelligence and IDPS are not evaluated."),
        annotations=READ_ONLY,
    )
    async def trace_flow(
        ctx: Context[Any, Any],
        protocol: Annotated[str, Field(description="TCP, UDP, ICMP, HTTP, HTTPS or MSSQL.")],
        source: Annotated[str, Field(description="Source IP address (IPv4 or IPv6), a single address.")],
        destination: Annotated[str, Field(description="Destination IP address or FQDN (www.example.com).")],
        dst_port: Annotated[int | str | None, Field(
            description="Destination port. Required for TCP and UDP; default 80, 443, 1433 for HTTP, HTTPS, "
                        "MSSQL; ignored for ICMP.")] = None,
        explicit_proxy: Annotated[bool, Field(
            description="The request reaches the firewall as an explicit-proxy request.")] = False,
        tls_inspected: Annotated[bool | None, Field(
            description="Whether the firewall inspects the TLS session (an inspected HTTPS request is logged as "
                        "HTTP). Omit when unknown.")] = None,
        destination_ip: Annotated[str | None, Field(
            description="With an FQDN destination: the IP address the name resolves to, so network and DNAT rules "
                        "can be evaluated too.")] = None,
        full_tree: Annotated[bool, Field(
            description="true: list every collection and rule instead of the folded view.")] = False,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        flow = _call(lambda: build_flow(protocol, source, destination, dst_port, explicit_proxy, tls_inspected,
                                       destination_ip))
        return trace_hypothetical(state, flow, full_tree=full_tree)

    @server.tool(
        name="lookup_address",
        title="Everything known about an address",
        description=(
            "What the firewall context and the logs say about an IP address or CIDR. Returns fw_instance "
            "(AzFw.<n> when the address lies inside a firewall subnet), ip_groups that contain it (for a CIDR: "
            "groups with an entry that contains, lies inside or overlaps it; relation says which), rules whose "
            "source or destination cover it (ref 'policy » group » collection » rule', kind, action, as: "
            "source or destination, via: the matching entry or IP group, wildcard: true when the rule says "
            "'any'; specific rules first) and recent: log row counts over the last 15 minutes as source and as "
            "destination plus the top 5 actions. Without the policy context only recent is answered, plus "
            "policy_context with the reason. Service tags in rules cannot be resolved and are not listed."),
        annotations=READ_ONLY,
    )
    async def lookup_address(
        ctx: Context[Any, Any],
        address: Annotated[str, Field(description="An IPv4 or IPv6 address, or a CIDR (10.0.0.0/24, fd10::/16).")],
        limit: Annotated[int, Field(
            description=f"Maximum rule entries returned, clamped to 1..{MAX_RULE_LIMIT}.")] = DEFAULT_RULE_LIMIT,
    ) -> dict[str, Any]:
        state = get_state(ctx)
        return _call(lambda: lookup(state, address, limit=_clamp(limit, 1, MAX_RULE_LIMIT), now=time.time()))

    @server.tool(
        name="get_log_coverage",
        title="Which log categories are forwarded and seen",
        description=(
            "Compares what the firewall's diagnostic settings forward with what actually arrived. Returns each "
            "diagnostic setting (targets, categories, all_logs, whether it feeds the connected Event Hub), "
            "forwarded (viewer category names reaching the connected hub), observed (categories with counts "
            "since the server started), forwarded_not_seen (forwarded but no row yet: normal for IDPS or "
            "ThreatIntel on a quiet firewall), seen_not_forwarded (rows arrived although no setting for this hub "
            "forwards them: another setting feeds the hub, or the settings are outdated) and hints that explain "
            "gaps (fat flow logging or DNS flow trace switched off, DNS proxy off, FlowTrace never seen, no "
            "setting targets this hub). Without the policy context only observed is answered, plus the reason. "
            "A 'note' in the answer means the server is still replaying the hub's retention, so observed and "
            "forwarded_not_seen are not final yet."),
        annotations=READ_ONLY,
    )
    async def get_log_coverage(ctx: Context[Any, Any]) -> dict[str, Any]:
        state = get_state(ctx)
        return with_replay_note(state, coverage(state))


__all__ = ["register", "summarize", "explain", "lookup", "coverage", "build_flow", "trace_hypothetical"]
