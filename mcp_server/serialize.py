"""Dataclasses to JSON-friendly dicts for tool answers.

Two rules hold for everything here. Placeholders the TUI renders (``-`` for
"no port", empty strings) become ``None``, because an agent should not have to
know the table's conventions. And nothing secret leaves: no SAS connection
string, no inserted HTTP header *values* (only their names), no query string
of a PAC file URL.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .buffer import BufferedRow

if TYPE_CHECKING:
    from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, IpConfig, IpGroupInfo, Rule
    from viewer.cache import CachedSnapshot
    from viewer.trace import Trace

    from .state import AppState

DETAIL_LEVELS = ("summary", "full", "raw")

# Anything that looks like a SAS key or signature in an error text is cut out
# before it reaches an answer; SDK errors sometimes echo connection details.
_SECRET_RE = re.compile(r"(SharedAccessKey|SharedAccessSignature|sig)=[^;&\s]+", re.IGNORECASE)


def redact(text: str | None) -> str | None:
    if not text:
        return text
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)


def iso_utc(epoch: float | None) -> str | None:
    """Epoch seconds as ``2026-10-15T08:00:00.123Z`` (milliseconds, UTC)."""
    if epoch is None:
        return None
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _value(text: str | None) -> str | None:
    if text is None:
        return None
    text = str(text)
    return None if text in ("", "-") else text


def _flag(text: str) -> bool | None:
    return {"yes": True, "no": False}.get(text)


def rule_path(policy_text: str) -> str | None:
    """The parser's ``policy»group»collection»rule`` in the display form with spaced separators."""
    value = _value(policy_text)
    return value.replace("»", " » ") if value else None


def check_detail(detail: str) -> str:
    level = (detail or "summary").strip().lower()
    if level not in DETAIL_LEVELS:
        raise ValueError(f"detail must be one of {', '.join(DETAIL_LEVELS)}, got {detail!r}.")
    return level


def row_to_dict(item: BufferedRow, detail: str = "summary") -> dict[str, Any]:
    """One buffered row at ``summary``, ``full`` or ``raw`` detail."""
    level = check_detail(detail)
    row = item.row
    out: dict[str, Any] = {
        "id": item.id,
        "time": _value(row.time),
        "category": row.category,
        "protocol": _value(row.protocol),
        "source": _value(row.sourceip),
        "src_port": _value(row.srcport),
        "destination": _value(row.targetip),
        "dst_port": _value(row.targetport),
        "action": _value(row.action),
        "rule": rule_path(row.policy),
        "info": _value(row.moreinfo),
    }
    if level == "summary":
        return out
    out.update({
        "resource_id": _value(row.resource_id),
        "policy": _value(row.fw_policy),
        "rule_collection_group": _value(row.rule_collection_group),
        "rule_collection": _value(row.rule_collection),
        "rule_name": _value(row.rule_name),
        "nat_dst_ip": _value(row.nat_dst_ip),
        "nat_dst_port": _value(row.nat_dst_port),
        "explicit_proxy": _flag(row.explicit_proxy),
        "tls_inspected": _flag(row.tls_inspected),
        "received_at": iso_utc(item.received_at),
    })
    if level == "raw":
        out["raw"] = item.raw
    return out


def firewall_name_from_id(firewall_id: str | None) -> str | None:
    """The name segment of a resource id, lower-cased (diagnostics upper-case it; ARM has the real one)."""
    if not firewall_id:
        return None
    return firewall_id.rstrip("/").split("/")[-1].lower() or None


def status_to_dict(state: AppState, *, version: str) -> dict[str, Any]:
    """The ``get_status`` answer: connection, counters, buffer and policy context."""
    now = time.time()
    buf = state.buffer
    stream = state.stream
    namespace, hub = state.config.eventhub.display_endpoint
    snap = state.context.snapshot
    firewall_id = state.context.firewall_id or stream.firewall_id
    firewall_name = (snap.firewall.name if snap is not None and snap.firewall.name
                     else firewall_name_from_id(firewall_id))
    return {
        "server": {"name": "az-firewall-watch", "version": version, "started_at": iso_utc(state.started_at)},
        "event_hub": {
            "namespace": namespace or None,
            "hub": hub or None,
            "consumer_group": state.config.eventhub.consumer_group,
            "start_position": state.config.eventhub.start_position,
            "auth": "entra" if state.config.eventhub.use_entra else "sas",
            "state": stream.state,
            "last_error": redact(stream.last_error),
            "connected_since": iso_utc(stream.connected_since),
            "attempt": stream.attempt,
        },
        "events": {
            **buf.counters(),
            "last_event_at": iso_utc(buf.last_event_at),
            "last_event_age_s": round(now - buf.last_event_at, 1) if buf.last_event_at is not None else None,
            "newest_log_time": iso_utc(buf.last_log_time),
            "newest_log_lag_s": _round_lag(stream.newest_log_lag_s),
            "replaying": stream.replaying,
        },
        "buffer": {"size": buf.size, "capacity": buf.capacity, "first_id": buf.first_id,
                   "last_id": buf.last_id or None},
        "firewall_id": firewall_id,
        "firewall_name": firewall_name,
        "policy_context": state.context.status(),
    }


def _round_lag(lag: float | None) -> float | None:
    return None if lag is None else round(lag, 1)


def format_lag(seconds: float) -> str:
    """``5h 12m``, ``3m 20s`` or ``45s``: a lag an agent can repeat to a person."""
    total = int(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def replay_note(state: AppState) -> str | None:
    """The sentence the log tools add while the stream still replays the hub's retention, else ``None``.

    An agent that gets an empty or short answer right after the server started
    would otherwise conclude that the firewall is quiet; the note says that the
    counts are still growing and where to look.
    """
    stream = state.stream
    if not stream.replaying:
        return None
    lag = stream.newest_log_lag_s
    behind = f" (newest buffered log is {format_lag(lag)} behind now)" if lag is not None else ""
    return (f"The server is still replaying the hub's retention{behind}; counts will grow for a few more "
            "seconds. Call again shortly or check get_status (events.replaying).")


def with_replay_note(state: AppState, answer: dict[str, Any]) -> dict[str, Any]:
    """``answer`` with a top-level ``note`` while replaying; the key is absent otherwise."""
    note = replay_note(state)
    if note is not None:
        answer["note"] = note
    return answer


# ── Phase B: policy, firewall and trace shapes ──────────────────────────────
# The signatures are fixed here so the log tools and the policy tools agree on
# names; the bodies arrive with the policy and analysis tools.

def _opt(text: str | None) -> str | None:
    """An empty ARM string as ``None``: absent, not an empty value."""
    return text or None


def _strip_query(url: str) -> str | None:
    # The fetcher already drops the query of a PAC file URL (a SAS token); this
    # keeps it out even when a cache entry from elsewhere still carries one.
    if not url:
        return None
    return url.split("?", 1)[0] or None


def _ip_config_to_dict(cfg: IpConfig | None) -> dict[str, Any] | None:
    if cfg is None:
        return None
    return {
        "name": cfg.name,
        "private_ip": _opt(cfg.private_ip),
        "public_ip_name": _opt(cfg.public_ip_name),
        "public_ip_address": _opt(cfg.public_ip_address),
        "public_ip_id": _opt(cfg.public_ip_id),
        "subnet_id": _opt(cfg.subnet_id),
    }


def _autoscale(firewall: FirewallInfo) -> dict[str, Any]:
    """The four documented states plus the shapes the TUI calls "not understood".

    Absent configuration is the service default (autoscaling up to 20 capacity
    units); equal bounds fix the capacity and switch autoscaling off.
    """
    lo, hi = firewall.autoscale_min, firewall.autoscale_max
    if firewall.sku_tier == "Basic":
        return {"min": None, "max": None, "mode": "not_supported"}
    if lo == 0 and hi == 0:
        return {"min": None, "max": None, "mode": "service_default"}
    if lo > 0 and hi > 0 and lo == hi:
        return {"min": lo, "max": hi, "mode": "fixed"}
    if lo > 0 and hi > 0 and lo < hi:
        return {"min": lo, "max": hi, "mode": "range"}
    # min above max, or a single bound: 0 is also what an absent field parses
    # to, so nothing certain can be said about the other bound.
    return {"min": lo, "max": hi, "mode": "not_understood"}


def firewall_to_dict(firewall: FirewallInfo, *, cache_age_s: float | None = None,
                     snapshot: CachedSnapshot | None = None) -> dict[str, Any]:
    """The ``get_firewall`` shape (subnets, NAT gateways, public IPs, diagnostics, ...).

    Subnets, NAT gateways, maintenance windows and diagnostic settings live on
    the snapshot, not on :class:`FirewallInfo`; pass ``snapshot`` to include
    them (``cache_age_s`` then defaults to the snapshot's age).
    """
    if cache_age_s is None and snapshot is not None:
        cache_age_s = snapshot.age_seconds()
    out: dict[str, Any] = {
        "id": firewall.id,
        "name": firewall.name,
        "subscription_id": _opt(firewall.subscription_id),
        "resource_group": _opt(firewall.resource_group),
        "location": _opt(firewall.location),
        "sku_name": _opt(firewall.sku_name),
        "sku_tier": _opt(firewall.sku_tier),
        "zones": list(firewall.zones),
        "provisioning_state": _opt(firewall.provisioning_state),
        "threat_intel_mode": _opt(firewall.threat_intel_mode),
        "policy_id": _opt(firewall.policy_id),
        "private_ips": list(firewall.private_ips),
        "ip_configs": [_ip_config_to_dict(c) for c in firewall.ip_configs],
        "management_ip": _ip_config_to_dict(firewall.management_ip),
        "autoscale": _autoscale(firewall),
        "route_server_id": _opt(firewall.route_server_id),
        "additional_properties": dict(firewall.additional_properties),
        "tags": dict(firewall.tags),
        "cache_age_s": round(cache_age_s, 1) if cache_age_s is not None else None,
    }
    if snapshot is None:
        out["subnet_cidrs"] = list(firewall.subnet_cidrs)
        return out
    subnets = [{"id": sn.id, "name": _opt(sn.name), "cidrs": list(sn.cidrs), "nat_gateway_id": _opt(sn.nat_gateway_id)}
               for sn in snapshot.subnets]
    if not subnets:
        # An older cache entry knows only the ids and the flat CIDR list.
        subnets = [{"id": sid, "name": sid.rstrip("/").split("/")[-1] or None, "cidrs": [], "nat_gateway_id": None}
                   for sid in firewall.subnet_ids]
    out.update({
        "fetched_at": iso_utc(snapshot.fetched_at) if snapshot.fetched_at else None,
        "subnet_cidrs": list(snapshot.subnet_cidrs or firewall.subnet_cidrs),
        "subnets": subnets,
        "nat_gateways": [{
            "id": gw.id,
            "name": _opt(gw.name) or gw.id.rstrip("/").split("/")[-1],
            "subnet": _opt(gw.subnet_name),
            "readable": gw.readable,
            "public_ip_names": list(gw.public_ip_names),
            "public_ip_addresses": list(gw.public_ip_addresses),
            "public_ip_prefix_names": list(gw.public_ip_prefix_names),
        } for gw in snapshot.nat_gateways],
        # False: the assignment list itself could not be read, so an empty
        # list means "unknown", not "no maintenance window".
        "maintenance_readable": snapshot.maintenance_readable,
        "maintenance_windows": [{
            "assignment": mw.assignment_name,
            "configuration_name": _opt(mw.configuration_name),
            "configuration_id": _opt(mw.configuration_id),
            "readable": mw.readable,
            "start": _opt(mw.start),
            "duration": _opt(mw.duration),
            "time_zone": _opt(mw.time_zone),
            "recur_every": _opt(mw.recur_every),
            "expiration": _opt(mw.expiration),
            "scope": _opt(mw.scope),
            "sub_scope": _opt(mw.sub_scope),
        } for mw in snapshot.maintenance],
        "diagnostic_settings": [{
            "name": ds.name,
            "targets": {"event_hub": _opt(ds.event_hub), "workspace": _opt(ds.workspace),
                        "storage": _opt(ds.storage)},
            "categories": list(ds.categories),
            "all_logs": ds.all_logs,
        } for ds in snapshot.diagnostics],
    })
    return out


def _policy_settings(policy: FirewallPolicyInfo) -> dict[str, Any]:
    """The user-facing settings of one policy, without its rules and without its parent."""
    return {
        "id": policy.id,
        "name": policy.name,
        "sku_tier": _opt(policy.sku_tier),
        "provisioning_state": _opt(policy.provisioning_state),
        "base_policy_id": _opt(policy.base_policy_id),
        "child_policy_count": policy.child_policy_count,
        "threat_intel": {"mode": _opt(policy.threat_intel_mode),
                         "allow_fqdns": list(policy.threat_intel_allow_fqdns),
                         "allow_ips": list(policy.threat_intel_allow_ips)},
        "dns": {"proxy": policy.dns_proxy, "servers": list(policy.dns_servers)},
        "idps": {"mode": _opt(policy.idps_mode), "bypass_count": policy.idps_bypass_count,
                 "signature_override_count": policy.idps_override_count},
        "tls_inspection_ca": _opt(policy.tls_ca_name),
        "snat": {"private_ranges": list(policy.snat_private_ranges), "auto_learn": _opt(policy.snat_auto_learn)},
        "explicit_proxy": {
            "enabled": policy.explicit_proxy,
            "http_port": policy.explicit_proxy_http_port or None,
            "https_port": policy.explicit_proxy_https_port or None,
            "pac_enabled": policy.explicit_proxy_pac,
            "pac_port": policy.explicit_proxy_pac_port or None,
            "pac_file": _strip_query(policy.explicit_proxy_pac_file),
        },
    }


def _parent_summary(policy: FirewallPolicyInfo | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {**_policy_settings(policy), "parent": _parent_summary(policy.parent)}


def policy_to_dict(policy: FirewallPolicyInfo, *, include_rules: bool = False,
                   ip_groups: dict[str, IpGroupInfo] | None = None) -> dict[str, Any]:
    """The ``get_policy`` shape: summary always, the full group/collection/rule tree with ``include_rules``.

    ``groups`` lists the whole chain in evaluation order (inherited groups
    first, each marked with its ``policy``), so ``parent`` carries only the
    parents' settings.
    """
    groups: list[dict[str, Any]] = []
    for policy_name, group in policy.all_groups():
        collections: list[dict[str, Any]] = []
        for rc in sorted(group.rule_collections, key=lambda c: c.priority):
            entry: dict[str, Any] = {"name": rc.name, "priority": rc.priority, "action": _opt(rc.action),
                                     "kind": rc.kind, "rule_count": len(rc.rules)}
            if include_rules:
                prefix = " » ".join((policy_name, group.name, rc.name))
                entry["rules"] = [rule_to_dict(r, ref=f"{prefix} » {r.name}", ip_groups=ip_groups,
                                               sku_tier=policy.sku_tier) for r in rc.rules]
            collections.append(entry)
        groups.append({
            "name": group.name,
            "priority": group.priority,
            "policy": policy_name,
            "inherited": policy_name != policy.name,
            "collection_count": len(group.rule_collections),
            "rule_count": sum(len(rc.rules) for rc in group.rule_collections),
            "collections": collections,
        })
    return {
        **_policy_settings(policy),
        "parent": _parent_summary(policy.parent),
        "group_count": len(groups),
        "rule_count": sum(g["rule_count"] for g in groups),
        "groups": groups,
    }


def _ip_group_ref(group_id: str, ip_groups: dict[str, IpGroupInfo] | None) -> dict[str, Any]:
    from .rules import lookup_ip_group

    grp = lookup_ip_group(group_id, ip_groups or {})
    if grp is None:
        # No Reader on the group (or not fetched): the id is all there is.
        return {"id": group_id, "name": None, "readable": False, "address_count": None}
    return {"id": grp.id, "name": grp.name, "readable": True, "address_count": len(grp.ip_addresses)}


def headers_land_in(rule: Rule, sku_tier: str | None) -> str | None:
    """Which traffic gets the headers an application rule inserts; ``None`` without headers.

    Copied from ``PolicyView._header_insertion_scope_line`` (viewer/views/policy.py)
    without the Rich markup: that module imports Textual, which the server must
    not load. Keep both in step. Headers go into HTTP and into HTTPS the firewall
    decrypts (Premium with TLS inspection on the rule).
    """
    if not rule.http_headers:
        return None
    protocols = {p.lower() for p in rule.protocols}
    has_http, has_https = "http" in protocols, "https" in protocols
    if not has_https:
        return "inserted into HTTP"
    if not sku_tier:
        return "policy SKU unknown: whether HTTPS gets the headers cannot be told from here"
    if sku_tier != "Premium":
        why = "HTTPS on Standard/Basic"
    elif not rule.terminate_tls:
        why = "HTTPS without TLS inspection on this rule"
    else:
        return "inserted into HTTP and TLS-inspected HTTPS" if has_http else "inserted into TLS-inspected HTTPS"
    if has_http:
        return f"{why}: headers are inserted into HTTP only"
    return f"{why}: no traffic this rule matches gets the headers"


def rule_to_dict(rule: Rule, *, ref: str, ip_groups: dict[str, IpGroupInfo] | None = None,
                 sku_tier: str | None = None, compact: bool = False) -> dict[str, Any]:
    """One rule with its ``ref`` (``policy » group » collection » rule``); header values never included.

    ``compact`` (the list shape): IP groups as names (the id when unreadable),
    and the application and DNAT extras only when the rule has them.
    ``sku_tier`` is the policy's tier, needed for ``inserted_headers_land_in``.
    """
    src_groups = [_ip_group_ref(g, ip_groups) for g in rule.source_ip_groups]
    dst_groups = [_ip_group_ref(g, ip_groups) for g in rule.destination_ip_groups]
    translated = None
    if rule.translated_address or rule.translated_fqdn or rule.translated_port:
        translated = {"address": _opt(rule.translated_address), "fqdn": _opt(rule.translated_fqdn),
                      "port": _opt(rule.translated_port)}
    if compact:
        out: dict[str, Any] = {
            "ref": ref,
            "name": rule.name,
            "protocols": list(rule.protocols),
            "source_addresses": list(rule.source_addresses),
            "source_ip_groups": [g["name"] or g["id"] for g in src_groups],
            "destination_addresses": list(rule.destination_addresses),
            "destination_ip_groups": [g["name"] or g["id"] for g in dst_groups],
            "destination_fqdns": list(rule.destination_fqdns),
            "destination_ports": list(rule.destination_ports),
        }
        for key, values in (("target_urls", rule.target_urls), ("fqdn_tags", rule.fqdn_tags),
                            ("web_categories", rule.web_categories)):
            if values:
                out[key] = list(values)
        if translated is not None:
            out["translated"] = translated
        if rule.terminate_tls:
            out["terminate_tls"] = True
        if rule.http_headers:
            out["http_header_count"] = len(rule.http_headers)
        return out
    return {
        "ref": ref,
        "name": rule.name,
        "rule_type": _opt(rule.rule_type),
        "kind": rule.kind,
        "protocols": list(rule.protocols),
        "source_addresses": list(rule.source_addresses),
        "source_ip_groups": src_groups,
        "destination_addresses": list(rule.destination_addresses),
        "destination_ip_groups": dst_groups,
        "destination_fqdns": list(rule.destination_fqdns),
        "destination_ports": list(rule.destination_ports),
        "fqdn_tags": list(rule.fqdn_tags),
        "web_categories": list(rule.web_categories),
        "target_urls": list(rule.target_urls),
        "translated": translated,
        "terminate_tls": rule.terminate_tls,
        # Names only: a value can carry a token or a tenant id.
        "http_headers": [h.name for h in rule.http_headers],
        "inserted_headers_land_in": headers_land_in(rule, sku_tier),
    }


def ip_group_to_dict(group: IpGroupInfo, *, used_by: int | None = None,
                     include_addresses: bool = True) -> dict[str, Any]:
    """One IP group: id, name, location, addresses, how many rules use it."""
    out: dict[str, Any] = {
        "id": group.id,
        "name": group.name,
        "location": _opt(group.location),
        "readable": True,
        "address_count": len(group.ip_addresses),
    }
    if include_addresses:
        out["addresses"] = list(group.ip_addresses)
    if used_by is not None:
        out["used_by"] = used_by
    return out


def trace_to_dict(trace: Trace, *, full_tree: bool = False) -> dict[str, Any]:
    """An evaluation trace: passes → collections → rules → checks, folded like the dialog unless ``full_tree``."""
    raise NotImplementedError("trace_to_dict is implemented with the analysis tools (phase B2).")


__all__ = [
    "DETAIL_LEVELS", "row_to_dict", "status_to_dict", "iso_utc", "redact", "rule_path", "check_detail",
    "firewall_name_from_id", "firewall_to_dict", "policy_to_dict", "rule_to_dict", "ip_group_to_dict",
    "headers_land_in", "trace_to_dict",
]
