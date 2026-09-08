"""
Azure Firewall log parser.

Supports both the legacy (properties.msg) format and the structured log format
(AZFWNetworkRule, AZFWApplicationRule, AZFWNatRule, AZFWDnsQuery,
AZFWIdpsSignature, AZFWThreatIntel, AZFWFqdnResolveFailure, AZFWFlowTrace,
AZFWFatFlow).

Ported from azure-firewall-mon/firewall-mon-app/src/app/services/event-hub-source.service.ts
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from helpers import split_endpoint

_counter = 0

# Legacy "AzureFirewallDNSResolutionFailureLog" message head (before " Rule Collection: ").
_RESOLVE_FAIL_RE = re.compile(
    r"Failed to resolve FQDN (?P<fqdn>\S+?)\.?(?:\s+Error\s+(?P<error>.*))?$",
    re.DOTALL,
)


_FLOWTRACE_BOILERPLATE = "Log Additional TCP Log"


def tcp_direction(flag: str, sport: str, dport: str) -> str:
    """Which way a FlowTrace packet went: ``client → server`` or ``server → client``.

    SYN and SYN-ACK are unambiguous. For everything else the side with the
    ephemeral (higher) port is taken as the client; equal ports give ``""``.
    """
    f = (flag or "").upper()
    if f == "SYN":
        return "client → server"
    if f == "SYN-ACK":
        return "server → client"
    try:
        s, d = int(sport), int(dport)
    except (TypeError, ValueError):
        return ""
    if s == d:
        return ""
    return "client → server" if s > d else "server → client"


def _capitalise(value: str) -> str:
    """'alert' → 'Alert'; values that are already cased stay as they are."""
    return value[:1].upper() + value[1:] if value else value


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
    # DNAT rows only: the public destination the client actually hit (the
    # DNAT rule matches on it); targetip/targetport carry the translated target.
    nat_dst_ip: str = ""
    nat_dst_port: str = ""
    # AZFWApplicationRule only: tri-state "yes" / "no" / "" (the legacy
    # properties.msg format never carries these columns).
    explicit_proxy: str = ""
    tls_inspected: str = ""


def parse_record(record: dict) -> FirewallDataRow | None:
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
            category="SKIP:ResourceType",
        )

    # ── Structured log format (new) ──────────────────────────────────────────
    structured = {
        "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule",
        "AZFWDnsQuery", "AZFWIdpsSignature", "AZFWThreatIntel",
        "AZFWFqdnResolveFailure", "AZFWInternalFqdnResolutionFailure", "AZFWFlowTrace", "AZFWFatFlow",
    }
    if category in structured:
        return _parse_structured(record, category, time, resource_id)

    # ── Legacy format ────────────────────────────────────────────────────────
    legacy = {
        "AzureFirewallNetworkRule", "AzureFirewallApplicationRule",
        "AzureFirewallNatRule", "AzureFirewallDnsProxy",
    }
    if category in legacy:
        return _parse_legacy(record, op_name, time)

    return FirewallDataRow(rowid=_next_id(), time=time, category=f"SKIP:Category:{category}")


# ── helpers ───────────────────────────────────────────────────────────────────

def _s(props: dict, key: str) -> str:
    v = props.get(key)
    return str(v) if v is not None else ""


def _format_mbps(rate: str) -> str:
    if not rate:
        return "-"
    try:
        value = float(rate)
    except ValueError:
        return f"{rate} Mbps"
    return f"{value:.1f} Mbps" if value >= 1 else f"{value:.3f} Mbps"


def _port(props: dict, key: str) -> str:
    """Port fields render as '-' when absent (e.g. ICMP has no ports)."""
    return _s(props, key) or "-"


def _flag(props: dict, key: str) -> str:
    """A tri-state boolean column: 'yes' / 'no' / '' when absent or unreadable.

    Accepts a JSON boolean or the strings 'true'/'false' (case-insensitive);
    anything else — missing key, null, other text — stays "" (unknown), never
    guessed as either state.
    """
    v = props.get(key)
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, str):
        low = v.strip().lower()
        if low == "true":
            return "yes"
        if low == "false":
            return "no"
    return ""


def _parse_structured(record: dict, category: str, time: str, resource_id: str = "") -> FirewallDataRow:
    props: dict = record.get("properties", {})

    if category == "AZFWDnsQuery":
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="DnsQuery",
            protocol=_s(props, "QueryType"),        # A/AAAA/MX/… → Proto column
            sourceip=_s(props, "SourceIp"),
            srcport=_port(props, "SourcePort"),
            targetip=_s(props, "QueryName").rstrip("."),  # hostname without trailing dot, like legacy
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
        if rcg:
            full_policy = "»".join(filter(None, [fw_policy, rcg, rc, rule]))
        else:
            full_policy = _s(props, "ActionReason")
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="AppRule",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_port(props, "SourcePort"),
            targetip=_s(props, "Fqdn"),
            targetport=_port(props, "DestinationPort"),
            action=_s(props, "Action"),
            policy=full_policy,
            moreinfo=_s(props, "TargetUrl"),
            resource_id=resource_id,
            fw_policy=fw_policy,
            rule_collection_group=rcg,
            rule_collection=rc,
            rule_name=rule,
            explicit_proxy=_flag(props, "IsExplicitProxyRequest"),
            tls_inspected=_flag(props, "IsTlsInspected"),
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
            srcport=_port(props, "SourcePort"),
            targetip=_s(props, "DestinationIp"),
            targetport=_port(props, "DestinationPort"),
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
            srcport=_port(props, "SourcePort"),
            targetip=_s(props, "TranslatedIp"),
            targetport=_port(props, "TranslatedPort"),
            action="DNAT",
            policy=full_policy,
            resource_id=resource_id,
            fw_policy=fw_policy,
            rule_collection_group=rcg,
            rule_collection=rc,
            rule_name=rule,
            nat_dst_ip=_s(props, "DestinationIp"),
            nat_dst_port=_port(props, "DestinationPort"),
        )

    if category == "AZFWIdpsSignature":
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="IDPS",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_port(props, "SourcePort"),
            targetip=_s(props, "DestinationIp"),
            targetport=_port(props, "DestinationPort"),
            action=_capitalise(_s(props, "Action")),  # the firewall sends "alert" / "deny"
            # " · " separated so the detail dialog can split it back into fields
            moreinfo=" · ".join(filter(None, [
                f"SEV:{_s(props, 'Severity')}" if _s(props, "Severity") else "",
                _s(props, "SignatureId"),
                _s(props, "Category"),
                _s(props, "Description"),
            ])),
            resource_id=resource_id,
        )

    if category == "AZFWThreatIntel":
        # HTTP/HTTPS hits carry the FQDN (DestinationIp is then empty); show it
        # like an application-rule row. IP-based indicators keep the address.
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="ThreatIntel",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=_port(props, "SourcePort"),
            targetip=_s(props, "Fqdn") or _s(props, "DestinationIp"),
            targetport=_port(props, "DestinationPort"),
            action=_capitalise(_s(props, "Action")),
            moreinfo=_s(props, "ThreatDescription"),
            resource_id=resource_id,
        )

    if category in ("AZFWFqdnResolveFailure", "AZFWInternalFqdnResolutionFailure"):
        # The diagnostic *category* is AZFWFqdnResolveFailure (what Event Hub
        # records carry); the Log Analytics *table* is named
        # AZFWInternalFqdnResolutionFailure. Accept both, just in case.
        fw_policy = _s(props, "Policy")
        rcg = _s(props, "RuleCollectionGroup")
        rc = _s(props, "RuleCollection")
        rule = _s(props, "Rule")
        policy = "»".join(filter(None, [fw_policy, rcg, rc, rule]))
        # The firewall's own DNS resolution of an FQDN used in a network/DNAT
        # rule failed — a DNS failure, but not a client DNS-proxy query, so it
        # gets its own category (and is not affected by the Hide-DNS toggle).
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="DnsFailure",
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

    if category == "AZFWFlowTrace":
        # Flag: FIN / FIN-ACK / SYN-ACK / RST / INVALID …. Source and destination
        # are the *packet's*, so a SYN-ACK lists the server as source. The info
        # column says which way the packet went; Azure's own Action/ActionReason
        # ("Log Additional TCP Log") is the same boilerplate on every row and is
        # only kept when it says something else.
        flag = _s(props, "Flag") or "-"
        sport, dport = _port(props, "SourcePort"), _port(props, "DestinationPort")
        reason = " ".join(filter(None, [_s(props, "Action"), _s(props, "ActionReason")]))
        info = tcp_direction(flag, sport, dport)
        if reason and reason != _FLOWTRACE_BOILERPLATE:
            info = f"{info} · {reason}" if info else reason
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="FlowTrace",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=sport,
            targetip=_s(props, "DestinationIp"),
            targetport=dport,
            action=flag,
            moreinfo=info,
            resource_id=resource_id,
        )

    if category == "AZFWFatFlow":
        # Top-talker flows; FlowRate is Mbit/s and arrives as a string with
        # float noise ("3.2930000000000001", "0.024"). Sub-Mbit flows are
        # common in practice, so keep three decimals below 1 Mbit/s.
        rate = _s(props, "FlowRate")
        rate_txt = _format_mbps(rate)
        sport, dport = _port(props, "SourcePort"), _port(props, "DestinationPort")
        return FirewallDataRow(
            rowid=_next_id(),
            time=time,
            category="FatFlow",
            protocol=_s(props, "Protocol"),
            sourceip=_s(props, "SourceIp"),
            srcport=sport,
            targetip=_s(props, "DestinationIp"),
            targetport=dport,
            action=rate_txt,
            moreinfo=tcp_direction("", sport, dport),  # like FlowTrace: which way this flow's packets go
            resource_id=resource_id,
        )

    return FirewallDataRow(rowid=_next_id(), time=time, category=f"SKIP:{category}")


def _parse_legacy(record: dict, op_name: str, time: str) -> FirewallDataRow:
    props: dict = record.get("properties", {})
    msg: str = props.get("msg", "")

    try:
        if op_name == "AzureFirewallNetworkRuleLog":
            # "TCP request from 10.1.1.1:1234 to 10.2.2.2:80. Action: Allow. [Rule Collection Group: X. Rule Collection: Y. Rule: Z.]"
            proto, rest = msg.split(" request from ", 1)
            first_sentence = rest.split(". ")[0]  # "src to dst:port"
            src_str, dst_str = first_sentence.split(" to ", 1)
            src_ip, src_port = split_endpoint(src_str)
            dst_ip, dst_port = split_endpoint(dst_str)

            action = rcg = rc = rule_name = ""
            for sentence in msg.split(". "):
                kv = sentence.split(": ", 1)
                if len(kv) < 2:
                    continue
                key, val = kv[0].strip(), kv[1].rstrip(".")
                if key == "Action":
                    action = val
                elif key == "Rule Collection Group":
                    rcg = val
                elif key == "Rule Collection":
                    rc = val
                elif key == "Rule":
                    rule_name = val

            policy = "»".join(filter(None, [rcg, rc, rule_name]))
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="NetworkRule",
                protocol=proto,
                sourceip=src_ip,
                srcport=src_port,
                targetip=dst_ip,
                # trailing "." survives when the message ends right after the port with no
                # following ". " sentence for split_endpoint's rpartition to stop before
                targetport=dst_port.rstrip("."),
                action=action or "-",
                policy=policy,
                rule_collection_group=rcg,
                rule_collection=rc,
                rule_name=rule_name,
            )

        if op_name == "AzureFirewallNatRuleLog":
            # "TCP request from 1.2.3.4:1234 to 5.6.7.8:3389 was DNAT'ed to 10.1.1.1:3389"
            # [0]=TCP [1]=request [2]=from [3]=src:port [4]=to [5]=fw:port [6]=was [7]=DNAT'ed [8]=to [9]=translated:port
            words = msg.split(" ")
            src_ip, src_port = split_endpoint(words[3])
            dst_ip, dst_port = split_endpoint(words[9])
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="NATRule",
                protocol=words[0],
                sourceip=src_ip,
                srcport=src_port,
                targetip=dst_ip,
                targetport=dst_port,
                action="DNAT",
            )

        if op_name == "AzureFirewallApplicationRuleLog":
            # "HTTPS request from 10.1.1.1:55583 to example.com:443. Action: Allow. Policy: P. Rule Collection Group: RCG. Rule Collection: RC. Rule: R."
            proto = msg.split(" ")[0]
            _, rest = msg.split(" request from ", 1)
            first_sentence = rest.split(". ")[0]  # "src to fqdn:port"
            src_str, dst_str = first_sentence.split(" to ", 1)
            src_ip, src_port = split_endpoint(src_str)
            dst = dst_str.rsplit(":", 1)  # rsplit so FQDNs with dots are preserved

            action = policy_name = rcg = rc = rule_name = moreinfo = ""
            for sentence in msg.split(". "):
                kv = sentence.split(": ", 1)
                if len(kv) < 2:
                    if "No rule matched" in kv[0]:
                        policy_name = "N/A"
                    continue
                key, val = kv[0].strip(), kv[1].rstrip(".")
                if key == "Action":
                    action = val
                elif key == "Policy":
                    policy_name = val
                elif key == "Rule Collection Group":
                    rcg = val
                elif key == "Rule Collection":
                    rc = val
                elif key == "Rule":
                    rule_name = val
                elif key in ("Url", "URL"):
                    moreinfo = val

            policy = "»".join(filter(None, [policy_name, rcg, rc, rule_name]))
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="AppRule",
                protocol=proto,
                sourceip=src_ip,
                srcport=src_port,
                targetip=dst[0] if dst else "-",
                targetport=dst[1] if len(dst) > 1 else "-",
                action=action or "-",
                policy=policy,
                moreinfo=moreinfo,
                fw_policy=policy_name,
                rule_collection_group=rcg,
                rule_collection=rc,
                rule_name=rule_name,
            )

        if op_name == "AzureFirewallDNSResolutionFailureLog":
            # "Failed to resolve FQDN example.com. Error lookup example.com on 127.0.0.53:53: ...;
            #  DNS resolution returned no IPv4 IPs. Rule Collection: policy:rcg:rc. Rule: r"
            # Legacy counterpart of AZFWFqdnResolveFailure — rendered the same way.
            head, _, tail = msg.partition(" Rule Collection: ")
            m = _RESOLVE_FAIL_RE.match(head)
            fqdn = m.group("fqdn") if m else "-"
            error = ((m.group("error") or "") if m else head).rstrip(".")
            rc_path, _, rule_part = tail.partition(". Rule: ")
            segments = rc_path.split(":")  # policy:rcg:rc (older firewalls may omit parts)
            fw_policy, rcg, rc = (segments + ["", "", ""])[:3] if len(segments) >= 3 else ("", "", rc_path)
            rule_name = rule_part.rstrip(".")
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="DnsFailure",
                targetip=fqdn,
                action="ResolveFail",
                policy="»".join(filter(None, [fw_policy, rcg, rc, rule_name])),
                moreinfo=error,
                fw_policy=fw_policy,
                rule_collection_group=rcg,
                rule_collection=rc,
                rule_name=rule_name,
            )

        if op_name in ("AzureFirewallDnsProxyLog", "AzureFirewallDnsProxy"):
            # "DNS Request: 10.2.0.6:5350 - 10407 A IN ifconfig.me. udp 40 false 1232 NOERROR qr,aa,rd,ra 56 0.000324423s"
            # pos: 0    1        2              3 4     5 6  7            8   9  10    11   12      13            14 15
            # words[12] is always the RCODE (NOERROR / NXDOMAIN / …)
            words = msg.split(" ")
            src_ip, src_port = split_endpoint(words[2]) if len(words) > 2 else ("-", "-")
            return FirewallDataRow(
                rowid=_next_id(),
                time=time,
                category="DnsQuery",
                sourceip=src_ip,
                srcport=src_port,
                protocol=words[5] if len(words) > 5 else "-",          # QueryType: A/AAAA/…
                targetip=words[7].rstrip(".") if len(words) > 7 else "-",  # QueryName
                targetport="53",
                action=words[12] if len(words) > 12 else "-",           # ResponseCode
            )

    except Exception:
        pass

    return FirewallDataRow(rowid=_next_id(), time=time, category=f"SKIP:ParseErr:{op_name}")
