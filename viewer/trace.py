"""Evaluation trace: the path one flow takes through a firewall policy.

Pure logic, no I/O. Mirrors Azure Firewall's documented processing order:

* Threat Intelligence first (before any rule).
* Three passes over all rule collection groups, one per rule type, in the
  order DNAT → Network → Application. Within a pass: inherited (parent)
  policy groups first, then groups by priority, then collections by priority.
* The first matching rule terminates evaluation.
* The Application pass only runs for HTTP, HTTPS and MSSQL flows.
* Without a match: infrastructure rule collection, then default deny.

Everything *before* the rule the firewall logged was really evaluated and
rejected; *why* it was rejected is computed locally per criterion and marked
``match`` / ``miss`` / ``unknown`` (service tags, FQDN tags, web categories and
unreadable IP groups cannot be evaluated here).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup
from .enrichment import _fqdn_matches, _port_matches

MATCH, MISS, UNKNOWN, NA = "match", "miss", "unknown", "n/a"
PASS_ORDER = ("dnat", "network", "application")
APP_PROTOCOLS = ("HTTP", "HTTPS", "MSSQL")
_WILDCARDS = ("*", "any")


@dataclass
class Flow:
    category: str = ""      # display category of the log row (NetworkRule, AppRule, NATRule, …)
    protocol: str = ""      # TCP / UDP / ICMP / HTTPS / HTTP/1.1 / MSSQL …
    src_ip: str = ""
    dst_ip: str = ""
    dst_fqdn: str = ""
    dst_port: str = ""
    action: str = ""        # the action the firewall logged (used for rows decided outside the rules)

    @property
    def threat_intel(self) -> bool:
        return self.category.lower() == "threatintel"

    @property
    def app_capable(self) -> bool:
        p = self.protocol.upper()
        return p.startswith(APP_PROTOCOLS) or self.category.lower() == "apprule"


@dataclass
class LoggedMatch:
    """The rule the firewall itself reported in the log row."""
    policy: str = ""
    group: str = ""
    collection: str = ""
    rule: str = ""
    action: str = ""

    def __bool__(self) -> bool:
        return bool(self.group and self.collection and self.rule)


@dataclass
class Check:
    name: str          # source | destination | port | protocol
    result: str        # match | miss | unknown | n/a
    detail: str = ""


@dataclass
class RuleTrace:
    rule: Rule
    checks: list[Check] = field(default_factory=list)
    verdict: str = UNKNOWN
    logged: bool = False     # this is the rule the firewall reported

    @property
    def ref(self) -> str:
        return self.rule.name


@dataclass
class CollectionTrace:
    policy_name: str
    group: RuleCollectionGroup
    collection: RuleCollection
    rules: list[RuleTrace] = field(default_factory=list)
    evaluated: bool = True
    verdict: str = MISS     # match | miss | unknown | not evaluated
    note: str = ""

    @property
    def rule_ref_prefix(self) -> str:
        return f"{self.group.name}|{self.collection.name}|"


@dataclass
class PassTrace:
    kind: str
    collections: list[CollectionTrace] = field(default_factory=list)
    evaluated: bool = True
    note: str = ""
    stopped_here: bool = False


@dataclass
class Trace:
    flow: Flow
    logged: LoggedMatch | None
    threat_intel: str
    passes: list[PassTrace]
    infrastructure: str | None   # note when reached, None otherwise
    outcome: str
    warnings: list[str] = field(default_factory=list)

    @property
    def matched_rule(self) -> RuleTrace | None:
        for p in self.passes:
            for c in p.collections:
                for r in c.rules:
                    if r.logged:
                        return r
        return None


# ── criteria ─────────────────────────────────────────────────────────────────

def _parse_ip(value: str):
    if not value or value == "-":
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _address_check(ip, addresses: list[str], group_ids: list[str],
                   ip_groups: dict[str, IpGroupInfo]) -> tuple[str, str]:
    """Return (result, detail) for an IP against address list + IP groups."""
    if ip is None:
        return NA, "no address in log"
    unknown: list[str] = []
    for a in addresses:
        if a.lower() in _WILDCARDS:
            return MATCH, a
        try:
            if ip in ipaddress.ip_network(a, strict=False):
                return MATCH, a
        except ValueError:
            unknown.append(a)   # service tag such as AzureMonitor
    for gid in group_ids:
        grp = ip_groups.get(gid)
        if grp is None:
            unknown.append(gid.rsplit("/", 1)[-1] + " (not loaded)")
            continue
        for entry in grp.ip_addresses:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return MATCH, grp.name
            except ValueError:
                continue
    if unknown:
        return UNKNOWN, "cannot evaluate: " + ", ".join(unknown)
    return MISS, str(ip)


def _protocol_check(rule: Rule, flow: Flow) -> Check:
    proto = flow.protocol.upper()
    if not proto or proto == "-":
        return Check("protocol", NA, "no protocol in log")
    rule_protos = [p.upper() for p in rule.protocols if p]
    if not rule_protos:
        return Check("protocol", MATCH, "any")
    if rule.kind == "application":
        for rp in rule_protos:
            if proto.startswith(rp):      # HTTP/1.1 vs Http, HTTPS vs Https
                return Check("protocol", MATCH, rp)
        return Check("protocol", MISS, f"{flow.protocol} not in {', '.join(rule.protocols)}")
    # Network / DNAT rules see layer 4: an application-rule log line says
    # HTTPS or HTTP/1.1, but on the wire that is TCP.
    l4 = "TCP" if proto.startswith(APP_PROTOCOLS) else proto
    for rp in rule_protos:
        if rp == "ANY" or rp == l4:
            return Check("protocol", MATCH, f"{rp} ({flow.protocol})" if l4 != proto else rp)
    return Check("protocol", MISS, f"{l4} not in {', '.join(rule.protocols)}")


def _port_check(rule: Rule, flow: Flow) -> Check:
    if not flow.dst_port or flow.dst_port == "-":
        return Check("port", NA, "no port in log")
    if not rule.destination_ports:
        return Check("port", MATCH, "any")
    if any(_port_matches(flow.dst_port, spec) for spec in rule.destination_ports):
        return Check("port", MATCH, flow.dst_port)
    return Check("port", MISS, f"{flow.dst_port} not in {', '.join(rule.destination_ports)}")


def _destination_check(rule: Rule, flow: Flow, ip_groups: dict[str, IpGroupInfo]) -> Check:
    if rule.kind == "application":
        fqdn = flow.dst_fqdn or flow.dst_ip
        if rule.destination_fqdns and fqdn and _fqdn_matches(fqdn, rule.destination_fqdns):
            return Check("destination", MATCH, fqdn)
        if rule.destination_addresses:
            result, detail = _address_check(_parse_ip(flow.dst_ip), rule.destination_addresses, [], ip_groups)
            if result == MATCH:
                return Check("destination", MATCH, detail)
        unevaluable = []
        if rule.fqdn_tags:
            unevaluable.append("FQDN tags " + ", ".join(rule.fqdn_tags))
        if rule.web_categories:
            unevaluable.append("web categories")
        if rule.target_urls:
            unevaluable.append("target URLs")
        if unevaluable:
            return Check("destination", UNKNOWN, "cannot evaluate: " + "; ".join(unevaluable))
        if not fqdn or fqdn == "-":
            return Check("destination", NA, "no FQDN in log")
        return Check("destination", MISS, f"{fqdn} not in {', '.join(rule.destination_fqdns) or '-'}")

    ip = _parse_ip(flow.dst_ip)
    result, detail = _address_check(ip, rule.destination_addresses, rule.destination_ip_groups, ip_groups)
    if result == MISS and rule.destination_fqdns:
        # FQDNs in network rules are resolved by the firewall's DNS; we cannot
        # know which IPs they resolved to at the time.
        return Check("destination", UNKNOWN, "cannot evaluate: FQDN " + ", ".join(rule.destination_fqdns))
    return Check("destination", result, detail)


def evaluate_rule(rule: Rule, flow: Flow, ip_groups: dict[str, IpGroupInfo]) -> RuleTrace:
    """Check every criterion of *rule* against *flow*."""
    src_result, src_detail = _address_check(_parse_ip(flow.src_ip), rule.source_addresses,
                                            rule.source_ip_groups, ip_groups)
    checks = [
        Check("source", src_result, src_detail),
        _destination_check(rule, flow, ip_groups),
        _port_check(rule, flow),
        _protocol_check(rule, flow),
    ]
    results = {c.result for c in checks}
    if MISS in results:
        verdict = MISS
    elif results == {MATCH}:
        verdict = MATCH
    else:
        # An unknown or a criterion the log does not carry (e.g. no destination
        # IP for an application-rule row) means we cannot claim a match.
        verdict = UNKNOWN
    return RuleTrace(rule=rule, checks=checks, verdict=verdict)


# ── ranking helpers for the compact view ─────────────────────────────────────

def rule_score(r: RuleTrace) -> int:
    """Number of matching criteria — higher means 'closer' to a match."""
    return sum(1 for c in r.checks if c.result == MATCH)


def first_problem(r: RuleTrace) -> Check | None:
    """The criterion to blame: the first miss, else the first unknown, else
    the first criterion the log does not carry."""
    for wanted in (MISS, UNKNOWN, NA):
        for c in r.checks:
            if c.result == wanted:
                return c
    return None


def nearest_miss(c: CollectionTrace) -> Check | None:
    """For a collection without a match: the problem of its closest rule."""
    candidates = [r for r in c.rules if r.verdict != MATCH]
    if not candidates:
        return None
    best = max(candidates, key=rule_score)
    return first_problem(best)


def nearest_rules(trace: "Trace", limit: int = 3) -> list[RuleTrace]:
    """Closest rules that did *not* match (miss or unknown) across all evaluated
    collections — the candidates to look at on a 'no rule matched' row.
    Computed matches are excluded; the view flags those separately."""
    rules = [r for p in trace.passes if p.evaluated for c in p.collections if c.evaluated
             for r in c.rules if not r.logged and r.verdict != MATCH]
    # Highest score first; on ties prefer a definite miss (actionable) over an
    # unknown we cannot evaluate locally.
    rules.sort(key=lambda r: (-rule_score(r), r.verdict == UNKNOWN))
    return rules[:limit]


# ── trace ────────────────────────────────────────────────────────────────────

def _is_logged(policy_name: str, group: RuleCollectionGroup, collection: RuleCollection,
               rule: Rule, logged: LoggedMatch | None) -> bool:
    if not logged:
        return False
    if logged.policy and policy_name and logged.policy != policy_name:
        return False
    return (group.name, collection.name, rule.name) == (logged.group, logged.collection, logged.rule)


def find_logged_rule(policy: FirewallPolicyInfo | None, logged: LoggedMatch | None
                     ) -> tuple[str, RuleCollectionGroup, RuleCollection, Rule] | None:
    """Exact lookup of the rule named in a log row (no heuristics)."""
    if policy is None or not logged:
        return None
    for policy_name, group in policy.all_groups():
        for rc in group.rule_collections:
            for rule in rc.rules:
                if _is_logged(policy_name, group, rc, rule, logged):
                    return policy_name, group, rc, rule
    return None


def build_trace(flow: Flow, policy: FirewallPolicyInfo, ip_groups: dict[str, IpGroupInfo],
                logged: LoggedMatch | None = None) -> Trace:
    warnings: list[str] = []
    logged_found = find_logged_rule(policy, logged) is not None
    if logged and not logged_found:
        warnings.append(
            f"Logged rule {logged.group} » {logged.collection} » {logged.rule} is not in the "
            "loaded policy — the cache may be stale (Ctrl+R) or the rule was renamed."
        )
        logged = None

    if flow.threat_intel:
        # Threat Intelligence runs before any rule; a ThreatIntel row means the
        # decision was made there. In Alert mode the rules still run afterwards
        # for the same packet, but that produces its own log row.
        threat_intel = f"hit — {flow.action or 'logged'} by Threat Intelligence (mode {policy.threat_intel_mode or '?'})"
        passes = [PassTrace(kind=kind, evaluated=False,
                            note="not evaluated — Threat Intelligence decided before rule processing")
                  for kind in PASS_ORDER]
        return Trace(flow=flow, logged=None, threat_intel=threat_intel, passes=passes,
                     infrastructure=None, outcome=f"{flow.action or 'handled'} by Threat Intelligence",
                     warnings=warnings)
    threat_intel = f"mode {policy.threat_intel_mode or 'Off'} — no hit"

    passes: list[PassTrace] = []
    stopped = False
    for kind in PASS_ORDER:
        ptrace = PassTrace(kind=kind)
        if stopped:
            ptrace.evaluated = False
            ptrace.note = "not evaluated — a rule already matched"
            passes.append(ptrace)
            continue
        if kind == "application" and not flow.app_capable:
            ptrace.evaluated = False
            ptrace.note = f"skipped — protocol {flow.protocol or '?'} is not HTTP, HTTPS or MSSQL"
            passes.append(ptrace)
            continue
        for policy_name, group in policy.all_groups():
            for rc in sorted(group.rule_collections, key=lambda c: c.priority):
                if rc.kind != kind:
                    continue
                ctrace = CollectionTrace(policy_name=policy_name, group=group, collection=rc)
                if stopped:
                    ctrace.evaluated = False
                    ctrace.verdict = "not evaluated"
                    ptrace.collections.append(ctrace)
                    continue
                for rule in rc.rules:
                    rtrace = evaluate_rule(rule, flow, ip_groups)
                    if _is_logged(policy_name, group, rc, rule, logged):
                        rtrace.logged = True
                        rtrace.verdict = MATCH
                        ctrace.verdict = MATCH
                        stopped = True
                        ptrace.stopped_here = True
                    ctrace.rules.append(rtrace)
                    if stopped:
                        break
                if ctrace.verdict != MATCH:
                    verdicts = {r.verdict for r in ctrace.rules}
                    if MATCH in verdicts and logged:
                        # Firewall says another rule matched later; our local check
                        # disagrees — most likely a service tag / resolved FQDN.
                        # Downgrade the rules too so the UI never shows a green
                        # match the firewall demonstrably did not stop at.
                        ctrace.verdict = UNKNOWN
                        ctrace.note = "local check would match, but the firewall continued — probably an unevaluable criterion"
                        for rt in ctrace.rules:
                            if rt.verdict == MATCH:
                                rt.verdict = UNKNOWN
                                rt.checks.append(Check("firewall", UNKNOWN, "would match locally, but the firewall continued to a later rule"))
                    elif MATCH in verdicts:
                        ctrace.verdict = MATCH
                        ctrace.note = "computed match — the firewall logged no rule; verify"
                    elif UNKNOWN in verdicts:
                        ctrace.verdict = UNKNOWN
                    else:
                        ctrace.verdict = MISS
                ptrace.collections.append(ctrace)
        if not ptrace.collections:
            ptrace.note = "no collections of this type"
        passes.append(ptrace)

    if stopped:
        infrastructure = None
        outcome = f"{logged.action or 'matched'} by {logged.group} » {logged.collection} » {logged.rule}"
    else:
        infrastructure = "no match assumed — infrastructure FQDNs are not evaluated locally"
        outcome = "default action: Deny (no rule matched)"
    return Trace(flow=flow, logged=logged, threat_intel=threat_intel, passes=passes,
                 infrastructure=infrastructure, outcome=outcome, warnings=warnings)
