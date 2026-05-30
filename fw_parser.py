"""
Azure Firewall log parser.

Supports both the legacy (properties.msg) format and the structured log format
(AZFWNetworkRule, AZFWApplicationRule, AZFWNatRule, AZFWDnsQuery,
AZFWIdpsSignature, AZFWThreatIntel).

Ported from azure-firewall-mon/firewall-mon-app/src/app/services/event-hub-source.service.ts
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

_counter = 0


def _next_id() -> str:
    global _counter
    _counter += 1
    return str(_counter)


@dataclass
class FirewallDataRow:
    rowid: str
    time: str
    category: str
    protocol: str = "-"
    sourceip: str = "-"
    srcport: str = "-"
    targetip: str = "-"
    targetport: str = "-"
    action: str = "-"
    policy: str = ""
    moreinfo: str = ""
    # detail fields
    resource_id: str = ""
    fw_policy: str = ""
    rule_collection_group: str = ""
    rule_collection: str = ""
    rule_name: str = ""


def parse_record(record: dict) -> Optional[FirewallDataRow]:
    """Parse a single Azure Firewall log record into a FirewallDataRow.

    Returns None only if the record dict itself is malformed; skipped records
    are returned with a category starting with 'SKIP:' so callers can count them.
    """
    resource_id: str = record.get("resourceId", "")
    category: str = record.get("category", "")
    op_name: str = record.get("operationName", "")
    time: str = str(record.get("time", ""))

    if "/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/" not in resource_id.upper():
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category=f"SKIP:ResourceType",
        )

    # ── Structured log format (new) ──────────────────────────────────────────
    structured = {
        "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule",
        "AZFWDnsQuery", "AZFWIdpsSignature", "AZFWThreatIntel",
        "AZFWFqdnResolveFailure",
    }
    if category in structured:
        return _parse_structured(record, category, time, resource_id)

    # ── Legacy format ────────────────────────────────────────────────────────
    legacy = {
        "AzureFirewallNetworkRule", "AzureFirewallApplicationRule", "AzureFirewallDnsProxy",
    }
    if category in legacy:
        return _parse_legacy(record, op_name, time)

    return FirewallDataRow(rowid=_next_id(), time=time, category=f"SKIP:Category:{category}")


# ── helpers ───────────────────────────────────────────────────────────────────

def _s(props: dict, key: str) -> str:
    v = props.get(key)
    return str(v) if v is not None else ""


def _parse_structured(record: dict, category: str, time: str, resource_id: str = "") -> FirewallDataRow:
    props: dict = record.get("properties", {})

    if category == "AZFWDnsQuery":
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="DnsQuery",
            protocol=_s(props, "QueryType"),        # A/AAAA/MX/… → Proto column
            sourceip=_s(props, "SourceIp"),
            srcport=_s(props, "SourcePort"),
            targetip=_s(props, "QueryName"),        # queried hostname → Dest/FQDN column
            targetport="53",                        # DNS is always port 53
            action=_s(props, "ResponseCode") or "Request",  # NOERROR/NXDOMAIN/… → Action column
            moreinfo=_s(props, "ErrorMessage"),
            resource_id=resource_id,
        )

    if category == "AZFWApplicationRule":
        fw_policy = _s(props, "Policy")
        rcg = _s(props, "RuleCollectionGroup")
        rc = _s(props, "RuleCollection")
        rule = _s(props, "Rule")
        rule_path = "»".join(filter(None, [rcg, rc, rule]))
        full_policy = "»".join(filter(None, [fw_policy, rule_path]))
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="AppRule",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_s(props, "SourcePort"),
            targetip=_s(props, "Fqdn"),
            targetport=_s(props, "DestinationPort"),
            action=_s(props, "Action"),
            policy=full_policy,
            moreinfo=_s(props, "TargetUrl"),
            resource_id=resource_id,
            fw_policy=fw_policy,
            rule_collection_group=rcg,
            rule_collection=rc,
            rule_name=rule,
        )

    if category == "AZFWNetworkRule":
        fw_policy = _s(props, "Policy")
        rcg = _s(props, "RuleCollectionGroup")
        rc = _s(props, "RuleCollection")
        rule = _s(props, "Rule")
        if rcg:
            full_policy = "»".join(filter(None, [fw_policy, rcg, rc, rule]))
        else:
            full_policy = _s(props, "ActionReason")
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="NetworkRule",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_s(props, "SourcePort"),
            targetip=_s(props, "DestinationIp"),
            targetport=_s(props, "DestinationPort"),
            action=_s(props, "Action"),
            policy=full_policy,
            resource_id=resource_id,
            fw_policy=fw_policy,
            rule_collection_group=rcg,
            rule_collection=rc,
            rule_name=rule,
        )

    if category == "AZFWNatRule":
        fw_policy = _s(props, "Policy")
        rcg = _s(props, "RuleCollectionGroup")
        rc = _s(props, "RuleCollection")
        rule = _s(props, "Rule")
        if rcg:
            full_policy = "»".join(filter(None, [fw_policy, rcg, rc, rule]))
        else:
            full_policy = _s(props, "ActionReason")
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="NATRule",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_s(props, "SourcePort"),
            targetip=_s(props, "TranslatedIp"),
            targetport=_s(props, "TranslatedPort"),
            action="DNAT",
            policy=full_policy,
            resource_id=resource_id,
            fw_policy=fw_policy,
            rule_collection_group=rcg,
            rule_collection=rc,
            rule_name=rule,
        )

    if category == "AZFWIdpsSignature":
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="IDPS",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_s(props, "SourcePort"),
            targetip=_s(props, "DestinationIp"),
            targetport=_s(props, "DestinationPort"),
            action=_s(props, "Action"),
            moreinfo=(
                f"SEV:{_s(props, 'Severity')} "
                f"{_s(props, 'SignatureId')} "
                f"{_s(props, 'Category')} "
                f"{_s(props, 'Description')}"
            ).strip(),
            resource_id=resource_id,
        )

    if category == "AZFWThreatIntel":
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="ThreatIntel",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_s(props, "SourcePort"),
            targetip=_s(props, "DestinationIp"),
            targetport=_s(props, "DestinationPort"),
            action=_s(props, "Action"),
            moreinfo=_s(props, "ThreatDescription"),
            resource_id=resource_id,
        )

    if category == "AZFWFqdnResolveFailure":
        fw_policy = _s(props, "Policy")
        rcg = _s(props, "RuleCollectionGroup")
        rc = _s(props, "RuleCollection")
        rule = _s(props, "Rule")
        policy = "»".join(filter(None, [fw_policy, rcg, rc, rule]))
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="AppRule",
            targetip=_s(props, "Fqdn"),
            action="ResolveFail",
            policy=policy,
            moreinfo=_s(props, "Error"),
            resource_id=resource_id,
            fw_policy=fw_policy,
            rule_collection_group=rcg,
            rule_collection=rc,
            rule_name=rule,
        )

    return FirewallDataRow(rowid=_next_id(), time=time, category=f"SKIP:{category}")


def _parse_legacy(record: dict, op_name: str, time: str) -> FirewallDataRow:
    props: dict = record.get("properties", {})
    msg: str = props.get("msg", "")

    try:
        if op_name == "AzureFirewallNetworkRuleLog":
            # "TCP request from 10.1.1.1:1234 to 10.2.2.2:80. Action: Allow."
            # "ICMP Type=8 request from 10.1.1.1:0 to 10.2.2.2:0. Action: Deny."
            proto_part, rest = msg.split(" request from ", 1)
            words = rest.split(" ")
            src = words[0].split(":")
            dst = words[2].split(":")
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="NetworkRule",
                protocol=proto_part,
                sourceip=src[0],
                srcport=src[1] if len(src) > 1 else "-",
                targetip=dst[0],
                targetport=dst[1].rstrip(".") if len(dst) > 1 else "-",
                action=words[4].rstrip(".") if len(words) > 4 else "-",
            )

        if op_name == "AzureFirewallNatRuleLog":
            # "TCP request from 1.2.3.4:1234 to 5.6.7.8:3389 was DNAT'ed to 10.1.1.1:3389"
            words = msg.split(" ")
            src = words[3].split(":")
            dst = words[5].split(":")
            action = " ".join(words[7:])
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="NATRule",
                protocol=words[0],
                sourceip=src[0],
                srcport=src[1] if len(src) > 1 else "-",
                targetip=dst[0],
                targetport=dst[1] if len(dst) > 1 else "-",
                action=action.strip(),
            )

        if op_name == "AzureFirewallApplicationRuleLog":
            # "HTTPS request from 10.1.1.1:55583 to example.com:443. Action: Deny. Policy: ..."
            row = FirewallDataRow(rowid=_next_id(), time=time, category="AppRule")
            words = msg[6:].split(" ")  # strip leading padding
            src = words[2].split(":")
            dst = words[4].split(":")
            row.protocol = msg.split(" ")[0]
            row.sourceip = src[0]
            row.srcport = src[1] if len(src) > 1 else "-"
            row.targetip = dst[0]
            row.targetport = dst[1].rstrip(".") if len(dst) > 1 else "-"
            for sentence in msg.split(". "):
                kv = sentence.split(": ", 1)
                if len(kv) < 2:
                    if "No rule matched" in kv[0]:
                        row.policy = "N/A"
                    continue
                key, val = kv[0], kv[1]
                if key == "Action":
                    row.action = val
                elif key in ("Rule Collection Group", "Rule Collection", "Rule"):
                    row.policy += f">{val}"
                elif key == "Url":
                    row.moreinfo = val
            if row.policy.startswith(">"):
                row.policy = row.policy[1:]
            return row

        if op_name in ("AzureFirewallDnsProxyLog", "AzureFirewallDnsProxy"):
            # "DNS Request: 10.12.3.5:7943 - 8951 AAAA IN tsfe....com. udp 58 false 512 NOERROR ..."
            words = msg.split(" ")
            src_parts = words[2].split(":") if len(words) > 2 else ["-", "-"]
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="DnsProxy",
                action=words[1].rstrip(":") if len(words) > 1 else "-",
                sourceip=src_parts[0],
                srcport=src_parts[1] if len(src_parts) > 1 else "-",
                protocol=words[8] if len(words) > 8 else "-",
                moreinfo=" ".join(words[5:8]) if len(words) > 8 else msg,
            )

    except Exception:
        pass

    return FirewallDataRow(rowid=_next_id(), time=time, category=f"SKIP:ParseErr:{op_name}")
