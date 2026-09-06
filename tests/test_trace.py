"""Evaluation trace (viewer/trace.py): processing order and per-criterion checks."""
from __future__ import annotations

import pytest

from viewer.azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection, RuleCollectionGroup
from viewer.trace import (
    MATCH, MISS, NA, UNKNOWN,
    Flow, LoggedMatch, build_trace, evaluate_rule, find_logged_rule,
)

G_SPOKES = "/g/spokes"
GROUPS = {G_SPOKES: IpGroupInfo(id=G_SPOKES, name="ipgroup-all-spokes", location="gwc", ip_addresses=["10.3.0.0/16"])}


def rc(name, priority, action, *rules, rc_type="FirewallPolicyFilterRuleCollection"):
    return RuleCollection(name=name, priority=priority, action=action, rule_collection_type=rc_type, rules=list(rules))


def net(name, **kw):
    base = dict(rule_type="NetworkRule", source_addresses=["*"], destination_addresses=["*"], destination_ports=["*"], protocols=["Any"])
    base.update(kw)
    return Rule(name=name, **base)


def app(name, **kw):
    base = dict(rule_type="ApplicationRule", source_addresses=["*"], destination_fqdns=[], protocols=["Https"], destination_ports=["443"])
    base.update(kw)
    return Rule(name=name, **base)


def nat(name, **kw):
    base = dict(rule_type="NatRule", source_addresses=["*"], destination_addresses=["20.1.1.1"], destination_ports=["3389"],
                protocols=["TCP"], translated_address="10.3.5.4", translated_port="3389")
    base.update(kw)
    return Rule(name=name, **base)


def policy(*groups, name="pol", parent=None, ti="Alert"):
    return FirewallPolicyInfo(id=f"/{name}", name=name, sku_tier="Premium", threat_intel_mode=ti,
                              rule_collection_groups=list(groups), parent=parent)


def rcg(name, priority, *collections):
    return RuleCollectionGroup(id=f"/{name}", name=name, priority=priority, rule_collections=list(collections))


LAB = policy(
    rcg("rcg-app", 100, rc("app-web", 200, "Allow", app("allow-web", destination_fqdns=["*.duckduckgo.com"]))),
    rcg("rcg-net", 2000,
        rc("net-deny", 100, "Deny", net("deny-bad", destination_addresses=["203.0.113.0/24"])),
        rc("net-allow", 200, "Allow",
           net("allow-monitor", source_ip_groups=[G_SPOKES], source_addresses=[], destination_addresses=["AzureMonitor"], destination_ports=["443"], protocols=["TCP"]),
           net("allow-web", source_ip_groups=[G_SPOKES], source_addresses=[], destination_ports=["443"], protocols=["TCP"]))),
)
TCP443 = Flow(category="NetworkRule", protocol="TCP", src_ip="10.3.5.4", dst_ip="51.116.242.155", dst_port="443")


def collections(trace, kind):
    return next(p for p in trace.passes if p.kind == kind).collections


# ── criteria ─────────────────────────────────────────────────────────────────

def test_evaluate_rule_all_match():
    r = evaluate_rule(net("r", source_ip_groups=[G_SPOKES], source_addresses=[], destination_ports=["400-500"], protocols=["TCP"]), TCP443, GROUPS)
    assert r.verdict == MATCH
    assert {c.name: c.result for c in r.checks} == {"source": MATCH, "destination": MATCH, "port": MATCH, "protocol": MATCH}
    assert next(c for c in r.checks if c.name == "source").detail == "ipgroup-all-spokes"


def test_evaluate_rule_port_and_protocol_miss():
    r = evaluate_rule(net("r", destination_ports=["22"], protocols=["UDP"]), TCP443, GROUPS)
    assert r.verdict == MISS
    checks = {c.name: c for c in r.checks}
    assert checks["port"].result == MISS and "443 not in 22" in checks["port"].detail
    assert checks["protocol"].result == MISS and "TCP not in UDP" in checks["protocol"].detail


@pytest.mark.parametrize("l7", ["HTTPS", "HTTP/1.1", "MSSQL"])
def test_network_rule_sees_application_flows_as_tcp(l7):
    """A lab flow logged as HTTPS by an app rule was wrongly reported as 'HTTPS not in TCP'."""
    flow = Flow(category="AppRule", protocol=l7, src_ip="10.3.5.4", dst_fqdn="www.bing.com", dst_port="443")
    r = evaluate_rule(net("r", destination_addresses=["*"], protocols=["TCP"]), flow, GROUPS)
    proto = next(c for c in r.checks if c.name == "protocol")
    assert proto.result == MATCH and proto.detail == f"TCP ({l7})"
    r_udp = evaluate_rule(net("r", protocols=["UDP"]), flow, GROUPS)
    assert next(c for c in r_udp.checks if c.name == "protocol").detail == "TCP not in UDP"


def test_service_tag_and_unloaded_group_are_unknown():
    r = evaluate_rule(net("r", destination_addresses=["AzureMonitor"], source_ip_groups=["/g/missing"], source_addresses=[]), TCP443, GROUPS)
    assert r.verdict == UNKNOWN
    checks = {c.name: c for c in r.checks}
    assert checks["destination"].result == UNKNOWN and "AzureMonitor" in checks["destination"].detail
    assert checks["source"].result == UNKNOWN and "missing (not loaded)" in checks["source"].detail


def test_network_rule_with_fqdn_destination_is_unknown():
    r = evaluate_rule(net("r", destination_addresses=[], destination_fqdns=["time.windows.com"]), TCP443, GROUPS)
    assert next(c for c in r.checks if c.name == "destination").result == UNKNOWN


def test_application_rule_fqdn_and_protocol():
    flow = Flow(category="AppRule", protocol="HTTPS", src_ip="10.3.5.4", dst_fqdn="html.duckduckgo.com", dst_port="443")
    ok = evaluate_rule(app("r", destination_fqdns=["*.duckduckgo.com"]), flow, GROUPS)
    assert ok.verdict == MATCH
    miss = evaluate_rule(app("r", destination_fqdns=["*.microsoft.com"]), flow, GROUPS)
    assert next(c for c in miss.checks if c.name == "destination").result == MISS
    http11 = evaluate_rule(app("r", destination_fqdns=["*"], protocols=["Http"], destination_ports=["80"]),
                           Flow(category="AppRule", protocol="HTTP/1.1", src_ip="10.3.5.4", dst_fqdn="x.example", dst_port="80"), GROUPS)
    assert http11.verdict == MATCH


def test_application_rule_tags_and_categories_are_unknown():
    flow = Flow(category="AppRule", protocol="HTTPS", src_ip="10.3.5.4", dst_fqdn="update.microsoft.com", dst_port="443")
    r = evaluate_rule(app("r", fqdn_tags=["WindowsUpdate"], web_categories=["Business"]), flow, GROUPS)
    dest = next(c for c in r.checks if c.name == "destination")
    assert dest.result == UNKNOWN and "WindowsUpdate" in dest.detail


def test_missing_flow_values_are_not_applicable():
    r = evaluate_rule(net("r"), Flow(category="NetworkRule", src_ip="-", dst_ip="", dst_port="-", protocol="-"), GROUPS)
    assert {c.result for c in r.checks} == {NA, MATCH} or all(c.result in (NA, MATCH) for c in r.checks)
    assert r.verdict == MATCH  # nothing contradicts


# ── exact lookup ─────────────────────────────────────────────────────────────

def test_find_logged_rule_exact_and_missing():
    logged = LoggedMatch(policy="pol", group="rcg-net", collection="net-allow", rule="allow-web", action="Allow")
    found = find_logged_rule(LAB, logged)
    assert found is not None and found[3].name == "allow-web" and found[1].priority == 2000 and found[2].priority == 200
    assert find_logged_rule(LAB, LoggedMatch(group="rcg-net", collection="net-allow", rule="renamed")) is None
    assert find_logged_rule(LAB, None) is None
    assert find_logged_rule(None, logged) is None


# ── order and termination ────────────────────────────────────────────────────

def test_trace_with_logged_match_stops_and_skips_app_pass():
    logged = LoggedMatch(policy="pol", group="rcg-net", collection="net-allow", rule="allow-web", action="Allow")
    t = build_trace(TCP443, LAB, GROUPS, logged)
    assert t.threat_intel.startswith("mode Alert")
    assert [p.kind for p in t.passes] == ["dnat", "network", "application"]
    dnat, network, application = t.passes
    assert dnat.evaluated and dnat.collections == [] and "no collections" in dnat.note
    names = [c.collection.name for c in network.collections]
    assert names == ["net-deny", "net-allow"]              # RC priority order
    assert network.collections[0].verdict == MISS           # deny-bad: destination miss
    assert network.collections[1].verdict == MATCH
    rules = network.collections[1].rules
    assert [r.rule.name for r in rules] == ["allow-monitor", "allow-web"]  # stops at the logged rule
    assert rules[0].verdict == UNKNOWN                      # AzureMonitor service tag
    assert rules[1].logged and rules[1].verdict == MATCH
    assert network.stopped_here
    assert not application.evaluated and "already matched" in application.note
    assert t.infrastructure is None
    assert t.outcome == "Allow by rcg-net » net-allow » allow-web"
    assert t.matched_rule is rules[1]
    assert t.warnings == []


def test_trace_no_rule_matched_reaches_default_deny_and_names_the_near_miss():
    flow = Flow(category="NetworkRule", protocol="TCP", src_ip="10.3.5.4", dst_ip="51.116.242.155", dst_port="8443")
    t = build_trace(flow, LAB, GROUPS, None)
    network = t.passes[1]
    allow = network.collections[1]
    assert allow.verdict == MISS                             # both rules miss on port (8443); a miss beats an unknown
    monitor = allow.rules[0]
    assert monitor.verdict == MISS
    assert next(c for c in monitor.checks if c.name == "destination").result == UNKNOWN  # service tag, reported anyway
    web = allow.rules[1]
    assert web.verdict == MISS
    port = next(c for c in web.checks if c.name == "port")
    assert port.result == MISS and "8443 not in 443" in port.detail
    assert not t.passes[2].evaluated and "not HTTP, HTTPS or MSSQL" in t.passes[2].note
    assert t.infrastructure is not None
    assert t.outcome.startswith("default action: Deny")
    assert t.matched_rule is None


def test_trace_app_pass_runs_for_https_flow_without_network_match():
    flow = Flow(category="AppRule", protocol="HTTPS", src_ip="10.3.5.4", dst_fqdn="html.duckduckgo.com", dst_port="443")
    logged = LoggedMatch(group="rcg-app", collection="app-web", rule="allow-web", action="Allow")
    t = build_trace(flow, LAB, GROUPS, logged)
    network = t.passes[1]
    assert network.evaluated and not network.stopped_here
    assert all(c.evaluated for c in network.collections)   # all network collections were really evaluated
    application = t.passes[2]
    assert application.evaluated and application.stopped_here
    assert application.collections[0].rules[0].logged


def test_trace_computed_match_before_logged_rule_is_downgraded_to_unknown():
    # deny-bad would match locally, but the firewall reports allow-web → we must not claim a deny
    flow = Flow(category="NetworkRule", protocol="TCP", src_ip="10.3.5.4", dst_ip="203.0.113.9", dst_port="443")
    logged = LoggedMatch(group="rcg-net", collection="net-allow", rule="allow-web", action="Allow")
    t = build_trace(flow, LAB, GROUPS, logged)
    deny = t.passes[1].collections[0]
    assert deny.verdict == UNKNOWN and "firewall continued" in deny.note


def test_trace_computed_match_without_log_is_flagged():
    flow = Flow(category="NetworkRule", protocol="TCP", src_ip="10.3.5.4", dst_ip="203.0.113.9", dst_port="443")
    t = build_trace(flow, LAB, GROUPS, None)
    deny = t.passes[1].collections[0]
    assert deny.verdict == MATCH and "computed match" in deny.note


def test_trace_parent_policy_groups_come_first_per_pass():
    parent = policy(rcg("base-net", 9000, rc("base-allow", 100, "Allow", net("base-rule"))), name="base")
    child = policy(rcg("child-net", 100, rc("child-allow", 100, "Allow", net("child-rule"))), name="child", parent=parent)
    logged = LoggedMatch(policy="child", group="child-net", collection="child-allow", rule="child-rule", action="Allow")
    t = build_trace(TCP443, child, GROUPS, logged)
    cols = t.passes[1].collections
    assert [(c.policy_name, c.collection.name) for c in cols] == [("base", "base-allow"), ("child", "child-allow")]
    # the parent rule would match locally, but the log names the child rule → downgraded, never claimed as the match
    assert cols[0].verdict == UNKNOWN and "firewall continued" in cols[0].note
    assert cols[1].rules[0].logged


def test_trace_dnat_pass_comes_first_and_terminates():
    pol = policy(
        rcg("rcg-nat", 5000, rc("nat", 100, "Dnat", nat("rdp"), rc_type="FirewallPolicyNatRuleCollection")),
        rcg("rcg-net", 100, rc("net", 100, "Allow", net("everything"))),
    )
    flow = Flow(category="NATRule", protocol="TCP", src_ip="1.2.3.4", dst_ip="10.3.5.4", dst_port="3389")
    logged = LoggedMatch(group="rcg-nat", collection="nat", rule="rdp", action="DNAT")
    t = build_trace(flow, pol, GROUPS, logged)
    assert t.passes[0].kind == "dnat" and t.passes[0].stopped_here
    assert t.passes[0].collections[0].collection.kind == "dnat"
    assert not t.passes[1].evaluated and not t.passes[2].evaluated
    assert t.outcome.startswith("DNAT by")


def test_trace_stale_cache_warning_when_logged_rule_missing():
    logged = LoggedMatch(group="rcg-net", collection="net-allow", rule="renamed-rule", action="Allow")
    t = build_trace(TCP443, LAB, GROUPS, logged)
    assert t.warnings and "renamed-rule" in t.warnings[0] and "Ctrl+R" in t.warnings[0]
    assert t.logged is None                                   # evaluated heuristically instead
    assert t.matched_rule is None


def test_trace_threat_intel_hit():
    flow = Flow(category="ThreatIntel", protocol="TCP", src_ip="10.3.5.4", dst_ip="1.1.1.1", dst_port="80")
    t = build_trace(flow, LAB, GROUPS, None)
    assert t.threat_intel.startswith("hit")


def test_collection_kind_detection():
    assert rc("n", 1, "Allow", net("x")).kind == "network"
    assert rc("a", 1, "Allow", app("x")).kind == "application"
    assert rc("d", 1, "Dnat", nat("x"), rc_type="FirewallPolicyNatRuleCollection").kind == "dnat"
    assert rc("empty", 1, "Allow").kind == "network"
