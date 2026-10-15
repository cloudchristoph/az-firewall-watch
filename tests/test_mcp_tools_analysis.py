"""Analysis tools through the MCP protocol (in-memory client against the real server object)."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from mcp.client.client import Client

from mcp_server.context import ContextHolder
from mcp_server.server import build_server
from mcp_server.state import AppState
from tests.test_mcp_tools_logs import Seeder, call, call_error, make_state
from tests.test_trace import app, nat, net, policy, rc, rcg
from viewer.azure_resources import DiagnosticSetting, FirewallInfo, IpGroupInfo
from viewer.cache import CachedSnapshot
from viewer.eventhub import EventHubSettings

ANALYSIS_TOOLS = {"summarize_logs", "explain_log_entry", "trace_flow", "lookup_address", "get_log_coverage"}
G_SPOKES, G_JUNK = "/g/spokes", "/g/junk"
IP_GROUPS = {
    G_SPOKES: IpGroupInfo(id=G_SPOKES, name="ipg-spokes", location="gwc", ip_addresses=["10.0.0.0/16"]),
    G_JUNK: IpGroupInfo(id=G_JUNK, name="ipg-junk", location="gwc", ip_addresses=["10.9.0.0-oops"]),
}
RULE_PATH = "fw-pol » rcg-net » rc-allow » allow-web"

POLICY = policy(
    rcg("rcg-dnat", 50,
        rc("rc-dnat", 100, "Dnat", nat("rdp-in", destination_addresses=["20.1.1.1"]),
           rc_type="FirewallPolicyNatRuleCollection")),
    rcg("rcg-net", 100,
        rc("rc-deny", 100, "Deny", net("deny-bad", destination_addresses=["203.0.113.0/24"])),
        rc("rc-dns", 120, "Allow",
           net("allow-dns", source_addresses=["10.0.0.0/8"], destination_addresses=["168.63.129.16"],
               destination_ports=["53"], protocols=["UDP"])),
        rc("rc-tags", 150, "Allow",
           net("allow-monitor", source_addresses=["10.0.0.0/8"], destination_addresses=["AzureMonitor"],
               destination_ports=["443"], protocols=["TCP"])),
        rc("rc-allow", 200, "Allow",
           net("allow-web", source_addresses=[], source_ip_groups=[G_SPOKES], destination_ports=["443"],
               protocols=["TCP"]))),
    rcg("rcg-app", 200, rc("rc-app", 100, "Allow", app("allow-ddg", destination_fqdns=["*.duckduckgo.com"]))),
    name="fw-pol",
)


@pytest.fixture
def state() -> AppState:
    return make_state(context=ContextHolder(enabled=False))


@pytest.fixture
def seed(state, structured_record) -> Seeder:
    return Seeder(state, structured_record)


def snapshot(*, diagnostics: list[DiagnosticSetting] | None = None, props: dict[str, str] | None = None,
             with_policy: bool = True, fetched_at: float | None = None) -> CachedSnapshot:
    fw = FirewallInfo(id="/fw", name="fw-hub", subscription_id="sub", resource_group="rg", location="gwc",
                      additional_properties=props or {})
    return CachedSnapshot(firewall=fw, policy=POLICY if with_policy else None, ip_groups=dict(IP_GROUPS),
                          subnet_cidrs=["10.1.0.0/26"], fetched_at=fetched_at or time.time(),
                          diagnostics=diagnostics or [])


def loaded_state(structured_record, firewall_id, **kw: Any) -> tuple[AppState, Seeder]:
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    holder.snapshot = snapshot(**kw)
    state = make_state(context=holder)
    return state, Seeder(state, structured_record)


def ruled(seed: Seeder, collection: str, rule: str, **kw: Any):
    return seed.network(Policy="fw-pol", RuleCollectionGroup="rcg-net", RuleCollection=collection, Rule=rule, **kw)


def iso(delta_s: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def walk(trace: dict[str, Any], kind: str) -> dict[str, Any]:
    return next(p for p in trace["passes"] if p["kind"] == kind)


def open_collections(pass_: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in pass_["collections"] if not c.get("folded")]


def folds(pass_: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in pass_["collections"] if c.get("folded")]


# ── tool list ────────────────────────────────────────────────────────────────

async def test_analysis_tools_are_listed_read_only_and_documented():
    state = make_state(context=ContextHolder(enabled=False))
    async with Client(build_server(state.config, state=state)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert ANALYSIS_TOOLS <= set(tools)
    for name in ANALYSIS_TOOLS:
        ann = tools[name].annotations
        assert ann is not None and ann.read_only_hint is True and ann.destructive_hint is False
        assert tools[name].description and "ctx" not in tools[name].input_schema["properties"]
    props = tools["summarize_logs"].input_schema["properties"]
    assert {"category", "action", "source", "destination", "since", "top", "bucket"} <= set(props)
    assert props["since"]["default"] == "15m" and props["bucket"]["default"] == "1m"
    assert set(tools["trace_flow"].input_schema["required"]) == {"protocol", "source", "destination"}
    assert "unknown" in tools["trace_flow"].description


# ── summarize_logs ───────────────────────────────────────────────────────────

SINCE = "2026-09-05T08:00:00Z"


def seed_summary(seed: Seeder) -> None:
    deny = {"Policy": "fw-pol", "RuleCollectionGroup": "rcg-net", "RuleCollection": "rc-deny", "Rule": "deny-bad"}
    seed.network(source="10.0.0.1", dest="10.1.0.2", time="2026-09-05T08:00:10Z")
    seed.network(source="10.0.0.1", time="2026-09-05T08:00:20Z", **{**deny, "RuleCollection": "rc-allow",
                                                                      "Rule": "allow-web"})
    seed.network(source="10.0.0.2", dest="203.0.113.7", action="Deny", time="2026-09-05T08:00:30Z", **deny)
    seed.network(source="10.0.0.2", dest="203.0.113.7", action="Deny", time="2026-09-05T08:01:05Z", **deny)
    for _ in range(3):   # default action: no rule named
        seed.network(source="10.0.0.9", dest="10.1.0.99", port=22, action="Deny", time="2026-09-05T08:01:40Z",
                     ActionReason="Default Action")
    seed._add(seed.record("AZFWFlowTrace", time="2026-09-05T08:02:05Z", Protocol="TCP", SourceIp="10.0.0.9",
                          SourcePort=1, DestinationIp="10.1.0.1", DestinationPort=443, Flag="SYN"))


async def test_summary_counts_tops_and_timeline(state, seed):
    seed_summary(seed)
    out = await call(state, "summarize_logs", {"since": SINCE, "until": "2026-09-05T09:00:00Z"})
    assert out["window"]["rows"] == 8 and out["window"]["from"] == "2026-09-05T08:00:00.000Z"
    assert out["window"]["to"] == "2026-09-05T09:00:00.000Z"
    assert out["by_category"] == {"NetworkRule": 7, "FlowTrace": 1}
    assert out["by_action"] == {"Deny": 5, "Allow": 2, "SYN": 1}
    assert out["denies"] == 5
    assert out["top_sources"][0] == {"address": "10.0.0.9", "count": 4}
    assert out["top_destinations"][0] == {"address": "10.1.0.99", "count": 3}
    assert out["top_rules"] == [{"rule": "fw-pol » rcg-net » rc-deny » deny-bad", "count": 2},
                                {"rule": "fw-pol » rcg-net » rc-allow » allow-web", "count": 1}]
    assert out["top_denied_destinations"] == [{"address": "10.1.0.99", "count": 3},
                                              {"address": "203.0.113.7", "count": 2}]
    assert out["top_dst_ports"][0] == {"port": "443", "count": 5}
    assert {"port": "22", "count": 3} in out["top_dst_ports"]
    assert out["bucket_seconds"] == 60
    assert out["timeline"] == [
        {"bucket": "2026-09-05T08:00:00Z", "count": 3, "denies": 1},
        {"bucket": "2026-09-05T08:01:00Z", "count": 4, "denies": 4},
        {"bucket": "2026-09-05T08:02:00Z", "count": 1, "denies": 0},
    ]
    assert out["timeline_truncated"] is False


async def test_summary_names_default_action_denies(state, seed):
    seed_summary(seed)
    out = await call(state, "summarize_logs", {"since": SINCE, "until": "2026-09-05T09:00:00Z"})
    dwr = out["denied_without_rule"]
    assert dwr["count"] == 3
    assert dwr["reasons"] == [{"reason": "Default Action", "count": 3}]
    assert dwr["top"] == [{"source": "10.0.0.9", "destination": "10.1.0.99", "dst_port": "22", "protocol": "TCP",
                           "count": 3}]


async def test_summary_bucket_width_and_top(state, seed):
    seed_summary(seed)
    args = {"since": SINCE, "until": "2026-09-05T09:00:00Z", "bucket": "10s", "top": 1}
    out = await call(state, "summarize_logs", args)
    assert out["bucket_seconds"] == 10
    assert [b["bucket"] for b in out["timeline"]] == [
        "2026-09-05T08:00:10Z", "2026-09-05T08:00:20Z", "2026-09-05T08:00:30Z", "2026-09-05T08:01:00Z",
        "2026-09-05T08:01:40Z", "2026-09-05T08:02:00Z"]
    assert len(out["top_sources"]) == 1 and len(out["top_destinations"]) == 1
    assert len((await call(state, "summarize_logs", {**args, "top": 5000}))["top_sources"]) == 3   # clamped, not rejected


async def test_summary_filters_narrow_the_rows(state, seed):
    seed_summary(seed)
    out = await call(state, "summarize_logs", {"since": SINCE, "source": "10.0.0.0/30", "action": "deny"})
    assert out["window"]["rows"] == 2 and out["filter"]["source"] == "10.0.0.0/30"
    assert out["top_sources"] == [{"address": "10.0.0.2", "count": 2}]


async def test_summary_default_window_is_fifteen_minutes(state, seed):
    seed.network(source="10.0.0.1", time=iso(-60))
    seed.network(source="10.0.0.2", time=iso(-3600))
    out = await call(state, "summarize_logs")
    assert out["window"]["rows"] == 1 and out["top_sources"] == [{"address": "10.0.0.1", "count": 1}]
    assert out["filter"]["since"] is not None
    wide = await call(state, "summarize_logs", {"since": "2h"})
    assert wide["window"]["rows"] == 2
    whole = await call(state, "summarize_logs", {"since": ""})
    assert whole["window"]["rows"] == 2 and whole["window"]["from"] is None


async def test_summary_says_when_the_window_reaches_beyond_the_buffer(state, seed):
    seed.network(time=iso(-120))
    inside = (await call(state, "summarize_logs", {"since": "15m"}))["window"]
    assert inside["buffer_oldest_in_window"] is True and "may be missing" in inside["note"]
    # The oldest row is older than the window start: nothing can be missing.
    outside = (await call(state, "summarize_logs", {"since": "30s"}))["window"]
    assert outside["buffer_oldest_in_window"] is False and "note" not in outside
    state.buffer.clear()
    empty = await call(state, "summarize_logs")
    assert empty["window"]["rows"] == 0 and empty["window"]["buffer_oldest"] is None
    assert empty["timeline"] == [] and empty["denied_without_rule"]["count"] == 0


async def test_summary_works_without_policy_context(state, seed):
    seed.network(time=iso(-10))
    assert state.context.state == "off"
    out = await call(state, "summarize_logs")
    assert out["window"]["rows"] == 1 and "available" not in out


@pytest.mark.parametrize("args, message", [
    ({"bucket": "5s"}, "bucket must be a duration from 10s to 1h"),
    ({"bucket": "2h"}, "bucket must be a duration from 10s to 1h"),
    ({"bucket": "soon"}, "bucket must be a duration from 10s to 1h"),
    ({"since": "yesterday-ish"}, "neither a relative duration"),
    ({"source": "10.0.0.0/40"}, "not a valid network"),
    ({"since": "1h", "until": "2h"}, "since lies after until"),
])
async def test_summary_rejects_bad_arguments_readably(state, args, message):
    assert message in await call_error(state, "summarize_logs", args)


# ── explain_log_entry ────────────────────────────────────────────────────────

async def test_explain_allow_by_rule(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    ruled(seed, "rc-allow", "allow-web", source="10.0.0.5", dest="51.116.1.1")
    out = await call(state, "explain_log_entry", {"id": 1})

    assert out["id"] == 1 and out["traceable"] is True and out["verdict"] == "allow"
    assert out["source"] == "10.0.0.5" and out["rule"] == RULE_PATH
    assert out["matched_rule"] == {
        "ref": RULE_PATH, "policy": "fw-pol", "group": "rcg-net", "collection": "rc-allow", "rule": "allow-web",
        "kind": "network", "group_priority": 100, "collection_priority": 200, "action": "Allow"}
    assert RULE_PATH in out["outcome"] and "10.0.0.5" in out["outcome"] and "51.116.1.1:443" in out["outcome"]
    assert out["note"] is None and out["policy_context"]["state"] == "loaded"

    trace = out["trace"]
    assert trace["folded"] is True and trace["threat_intel"].startswith("mode Alert")
    dnat = walk(trace, "dnat")
    assert dnat["result"] == "no_match" and folds(dnat) == [
        {"folded": True, "position": "no_match", "collections": 1, "all_miss": True}]
    net_pass = walk(trace, "network")
    assert net_pass["result"] == "matched" and net_pass["collections_total"] == 4
    # rc-deny and rc-dns missed and fold into one count; the collection with an
    # unknown rule stays open, and so does the one that matched.
    assert folds(net_pass) == [{"folded": True, "position": "before_match", "collections": 2, "all_miss": True}]
    tags, allow = open_collections(net_pass)
    assert (tags["collection"], tags["status"]) == ("rc-tags", "unknown")
    assert (allow["collection"], allow["status"], allow["priority"], allow["group_priority"]) == \
        ("rc-allow", "match", 200, 100)
    monitor = tags["rules"][0]
    assert monitor["status"] == "unknown" and monitor["logged"] is False
    unknown_check = next(c for c in monitor["checks"] if c["status"] == "unknown")
    assert unknown_check == {"criterion": "destination", "status": "unknown", "observed": "51.116.1.1",
                             "expected": ["AzureMonitor"], "detail": "cannot evaluate: AzureMonitor"}
    web = allow["rules"][0]
    assert web["logged"] is True and web["status"] == "match"
    assert [(c["criterion"], c["status"]) for c in web["checks"]] == [
        ("source", "match"), ("destination", "match"), ("port", "match"), ("protocol", "match")]
    assert web["checks"][0]["observed"] == "10.0.0.5" and web["checks"][0]["expected"] == ["ip-group:ipg-spokes"]
    assert web["checks"][2] == {"criterion": "port", "status": "match", "observed": "443", "expected": ["443"],
                                "detail": "443"}
    assert walk(trace, "application")["result"] == "not_evaluated"

    # Three of four criteria match for deny-bad and allow-monitor; on a tie the definite miss comes first.
    near = out["nearest_misses"]
    assert [n["ref"] for n in near[:2]] == ["fw-pol » rcg-net » rc-deny » deny-bad",
                                            "fw-pol » rcg-net » rc-tags » allow-monitor"]
    assert near[0]["status"] == "miss" and near[0]["action"] == "Deny" and near[0]["matching_criteria"] == 3
    assert near[0]["failing_criterion"]["criterion"] == "destination"
    assert near[0]["failing_criterion"]["status"] == "miss" and near[0]["failing_criterion"]["expected"] == ["203.0.113.0/24"]
    assert near[1]["status"] == "unknown" and near[1]["failing_criterion"]["status"] == "unknown"
    assert len(near) == 3


async def test_explain_deny_by_rule_folds_what_was_never_evaluated(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    ruled(seed, "rc-deny", "deny-bad", source="10.0.0.5", dest="203.0.113.7", action="Deny")
    out = await call(state, "explain_log_entry", {"id": 1})
    assert out["verdict"] == "deny" and out["matched_rule"]["action"] == "Deny"
    assert out["outcome"].startswith("TCP 10.0.0.5 to 203.0.113.7:443: Deny by fw-pol » rcg-net » rc-deny » deny-bad")
    net_pass = walk(out["trace"], "network")
    assert [c["collection"] for c in open_collections(net_pass)] == ["rc-deny"]
    assert folds(net_pass) == [{"folded": True, "position": "after_match", "not_evaluated": 3}]
    assert open_collections(net_pass)[0]["rules"][0]["logged"] is True


async def test_explain_default_action_deny_has_no_rule_and_names_the_nearest_misses(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    seed.network(source="172.16.0.1", dest="51.1.1.1", port=22, action="Deny", ActionReason="Default Action")
    out = await call(state, "explain_log_entry", {"id": 1})
    assert out["verdict"] == "deny" and out["matched_rule"] is None and out["rule"] == "Default Action"
    assert "default action: Deny (no rule matched)" in out["outcome"]
    near = out["nearest_misses"]
    assert 1 <= len(near) <= 3
    for entry in near:
        crit = entry["failing_criterion"]
        assert crit["status"] in ("miss", "unknown") and crit["observed"] is not None and "expected" in crit
    # No rule matched, so every pass was evaluated and nothing is cut off at a match.
    net_pass = walk(out["trace"], "network")
    assert net_pass["result"] in ("no_match", "unknown")
    assert not any("not_evaluated" in f for f in folds(net_pass))
    assert out["trace"]["result"] == "default action: Deny (no rule matched)"
    assert out["trace"]["infrastructure"].startswith("no match assumed")


async def test_explain_dnat_row(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    seed._add(seed.record("AZFWNatRule", Protocol="TCP", SourceIp="8.8.8.8", SourcePort=40000,
                          DestinationIp="20.1.1.1", DestinationPort=3389, TranslatedIp="10.3.5.4",
                          TranslatedPort=3389, Policy="fw-pol", RuleCollectionGroup="rcg-dnat",
                          RuleCollection="rc-dnat", Rule="rdp-in"))
    out = await call(state, "explain_log_entry", {"id": 1})
    assert out["verdict"] == "dnat" and out["category"] == "NATRule"
    assert out["matched_rule"]["kind"] == "dnat" and out["matched_rule"]["group_priority"] == 50
    assert out["trace"]["flow"]["destination"] == "20.1.1.1"      # the public address the rule matches on
    assert walk(out["trace"], "dnat")["result"] == "matched"
    assert walk(out["trace"], "network")["result"] == "not_evaluated"


async def test_explain_application_rule_row(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    seed._add(seed.record("AZFWApplicationRule", Protocol="HTTPS", SourceIp="172.16.0.9", SourcePort=40000,
                          Fqdn="www.duckduckgo.com", DestinationPort=443, Action="Allow", Policy="fw-pol",
                          RuleCollectionGroup="rcg-app", RuleCollection="rc-app", Rule="allow-ddg",
                          IsTlsInspected="false", IsExplicitProxyRequest="false"))
    out = await call(state, "explain_log_entry", {"id": 1})
    assert out["verdict"] == "allow" and out["matched_rule"]["rule"] == "allow-ddg"
    rule = walk(out["trace"], "application")["collections"][0]["rules"][0]
    dest = next(c for c in rule["checks"] if c["criterion"] == "destination")
    assert dest["status"] == "match" and dest["observed"] == "www.duckduckgo.com"
    assert dest["expected"] == ["*.duckduckgo.com"]


async def test_explain_full_tree_unfolds_everything(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    ruled(seed, "rc-deny", "deny-bad", source="10.0.0.5", dest="203.0.113.7", action="Deny")
    out = await call(state, "explain_log_entry", {"id": 1, "full_tree": True})
    assert out["trace"]["folded"] is False
    net_pass = walk(out["trace"], "network")
    assert not folds(net_pass)
    assert [(c["collection"], c["status"], c["evaluated"]) for c in net_pass["collections"]] == [
        ("rc-deny", "match", True), ("rc-dns", "not_evaluated", False), ("rc-tags", "not_evaluated", False),
        ("rc-allow", "not_evaluated", False)]
    assert all(c["rules"] == [] for c in net_pass["collections"][1:])
    assert walk(out["trace"], "dnat")["collections"][0]["rules"][0]["status"] == "miss"


async def test_explain_rule_missing_from_the_policy_asks_for_a_refresh(structured_record, firewall_id, monkeypatch):
    state, seed = loaded_state(structured_record, firewall_id)
    seed.network(source="10.0.0.5", Policy="fw-pol", RuleCollectionGroup="rcg-net", RuleCollection="rc-new",
                 Rule="brand-new")
    asked: list[str] = []
    monkeypatch.setattr(state.context, "note_unknown_rule", lambda name="": asked.append(name) or True)
    out = await call(state, "explain_log_entry", {"id": 1})
    assert asked == ["brand-new"]
    assert out["traceable"] is True and out["matched_rule"] is None
    assert out["verdict"] == "allow"      # what the firewall logged, never a guessed default deny
    assert "rcg-net » rc-new » brand-new" in out["note"] and "refresh" in out["note"]
    assert "rule not in loaded policy" in out["outcome"] or "not contain the logged rule" in out["outcome"]
    assert out["trace"]["warnings"]


async def test_explain_observation_rows_say_why_not(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    seed.flow()
    seed.dns()
    flow = await call(state, "explain_log_entry", {"id": 1})
    assert flow["traceable"] is False and "FlowTrace records the handshake" in flow["reason"]
    assert "trace" not in flow and flow["category"] == "FlowTrace"
    assert "DNS proxy rows" in (await call(state, "explain_log_entry", {"id": 2}))["reason"]


async def test_explain_without_context_gives_the_row_and_the_unavailable_answer(state, seed):
    seed.network(source="10.0.0.5")
    out = await call(state, "explain_log_entry", {"id": 1})
    assert out["source"] == "10.0.0.5" and out["traceable"] is False
    assert out["available"] is False and out["state"] == "off" and out["hint"]
    assert "trace" not in out and "verdict" not in out


async def test_explain_context_without_a_policy(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id, with_policy=False)
    seed.network()
    out = await call(state, "explain_log_entry", {"id": 1})
    assert out["traceable"] is False and "carries no policy" in out["reason"]


async def test_explain_unknown_id(state, seed):
    seed.network()
    message = await call_error(state, "explain_log_entry", {"id": 42})
    assert "No row with id 42" in message and "ids 1 to 1 are buffered" in message
    state.buffer.clear()
    assert "the buffer is empty" in await call_error(state, "explain_log_entry", {"id": 1})


# ── trace_flow ───────────────────────────────────────────────────────────────

FLOW = {"protocol": "TCP", "source": "10.0.0.5", "destination": "203.0.113.7", "dst_port": 443}


async def flow_state(structured_record, firewall_id) -> AppState:
    return loaded_state(structured_record, firewall_id)[0]


async def test_trace_flow_allow(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {"protocol": "UDP", "source": "10.0.0.5", "destination": "168.63.129.16",
                                            "dst_port": 53})
    assert out["verdict"] == "allow" and out["matched_rule"]["ref"] == "fw-pol » rcg-net » rc-dns » allow-dns"
    assert out["outcome"].startswith("UDP 10.0.0.5 to 168.63.129.16:53: first matching rule is")
    assert out["unevaluable_rules"] == [] and out["nearest_misses"] == []
    rules = [r for c in open_collections(walk(out["trace"], "network")) for r in c["rules"]]
    assert [r["name"] for r in rules] == ["allow-dns"] and rules[0]["would_match"] is True and "logged" not in rules[0]
    assert walk(out["trace"], "application")["result"] == "not_evaluated"      # nothing runs after the first match
    assert any("Threat Intelligence" in c for c in out["caveats"])


async def test_trace_flow_deny_by_rule(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", FLOW)
    assert out["verdict"] == "deny" and out["matched_rule"]["action"] == "Deny"
    assert out["matched_rule"]["rule"] == "deny-bad"


async def test_trace_flow_default_deny(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {**FLOW, "source": "172.16.0.1", "destination": "51.1.1.1", "dst_port": 22})
    assert out["verdict"] == "deny" and out["matched_rule"] is None
    assert out["outcome"] == "TCP 172.16.0.1 to 51.1.1.1:22: no rule matches, so the default action applies: Deny."
    assert out["unevaluable_rules"] == []
    assert 1 <= len(out["nearest_misses"]) <= 3
    assert out["trace"]["result"] == "default action: Deny (no rule matched)"


async def test_trace_flow_dnat(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {"protocol": "TCP", "source": "8.8.8.8", "destination": "20.1.1.1",
                                            "dst_port": 3389})
    assert out["verdict"] == "dnat" and out["matched_rule"]["kind"] == "dnat"
    assert out["matched_rule"]["rule"] == "rdp-in"
    assert walk(out["trace"], "dnat")["result"] == "matched" and walk(out["trace"], "network")["result"] == "not_evaluated"


async def test_trace_flow_unknown_criterion_before_the_match(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    # allow-monitor (a service tag) could take this flow before allow-web does.
    out = await call(state, "trace_flow", {"protocol": "TCP", "source": "10.0.0.5", "destination": "51.116.1.1",
                                            "dst_port": 443})
    assert out["verdict"] == "unknown"
    assert out["matched_rule"]["rule"] == "allow-web"      # the first rule that would match
    assert "not certain" in out["outcome"]
    assert out["unevaluable_rules"] == [{"ref": "fw-pol » rcg-net » rc-tags » allow-monitor", "criterion": "destination",
                                         "detail": "cannot evaluate: AzureMonitor"}]
    assert any("Service tags" in c for c in out["caveats"])


async def test_trace_flow_unknown_without_any_match(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {"protocol": "TCP", "source": "10.1.2.3", "destination": "51.116.1.1",
                                            "dst_port": 443})
    assert out["verdict"] == "unknown" and out["matched_rule"] is None
    assert "no rule matches with certainty" in out["outcome"]
    assert [u["ref"] for u in out["unevaluable_rules"]] == ["fw-pol » rcg-net » rc-tags » allow-monitor"]


async def test_trace_flow_application_rule_by_fqdn(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    args = {"protocol": "https", "source": "172.16.0.9", "destination": "WWW.DuckDuckGo.com.",
            "destination_ip": "52.1.1.1"}
    out = await call(state, "trace_flow", args)       # port defaults to 443, the name is normalised
    assert out["verdict"] == "allow" and out["matched_rule"]["rule"] == "allow-ddg"
    assert out["trace"]["flow"] == {"category": "AppRule", "protocol": "HTTPS", "source": "172.16.0.9",
                                    "destination": "www.duckduckgo.com", "dst_port": "443", "explicit_proxy": False,
                                    "tls_inspected": None}
    # Without the resolved IP the network rules cannot be judged against a name.
    nameonly = await call(state, "trace_flow", {k: v for k, v in args.items() if k != "destination_ip"})
    assert nameonly["verdict"] == "unknown" and nameonly["unevaluable_rules"]
    assert any("destination_ip" in c for c in nameonly["caveats"])


async def test_trace_flow_tcp_skips_application_rules(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {"protocol": "TCP", "source": "172.16.0.9",
                                            "destination": "www.duckduckgo.com", "dst_port": 443})
    app_pass = walk(out["trace"], "application")
    assert app_pass["evaluated"] is False and "not HTTP, HTTPS or MSSQL" in app_pass["note"]
    assert any("Protocol TCP skips application rules" in c for c in out["caveats"])


async def test_trace_flow_icmp_needs_no_port(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {"protocol": "ICMP", "source": "172.16.0.1", "destination": "203.0.113.7"})
    assert out["verdict"] == "deny" and out["matched_rule"]["rule"] == "deny-bad"


async def test_trace_flow_ipv6_and_proxy_flags(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {"protocol": "HTTP", "source": "FD00::5", "destination": "example.com",
                                            "explicit_proxy": True, "tls_inspected": False})
    assert out["trace"]["flow"]["source"] == "fd00::5" and out["trace"]["flow"]["explicit_proxy"] is True
    assert out["trace"]["flow"]["tls_inspected"] is False and out["trace"]["flow"]["dst_port"] == "80"


async def test_trace_flow_full_tree(structured_record, firewall_id):
    state = await flow_state(structured_record, firewall_id)
    out = await call(state, "trace_flow", {**FLOW, "full_tree": True})
    assert out["trace"]["folded"] is False and not folds(walk(out["trace"], "network"))


async def test_trace_flow_without_context_and_without_policy(state, structured_record, firewall_id):
    out = await call(state, "trace_flow", FLOW)
    assert out["available"] is False and out["state"] == "off" and out["flow"]["destination"] == "203.0.113.7"
    assert "verdict" not in out
    nopolicy, _ = loaded_state(structured_record, firewall_id, with_policy=False)
    out = await call(nopolicy, "trace_flow", FLOW)
    assert out["available"] is False and "carries no policy" in out["reason"]


@pytest.mark.parametrize("args, message", [
    ({**FLOW, "protocol": "GRE"}, "protocol 'GRE' is not one of TCP, UDP, ICMP, HTTP, HTTPS, MSSQL"),
    ({**FLOW, "source": "10.0.0.0/24"}, "source '10.0.0.0/24' is not an IP address"),
    ({**FLOW, "source": "host1"}, "is not an IP address"),
    ({**FLOW, "destination": "10.0.0.0/24"}, "is a network or URL"),
    ({**FLOW, "destination": "https://x.example/a"}, "is a network or URL"),
    ({**FLOW, "destination": "bad host!"}, "neither a valid IP address nor an FQDN"),
    ({**FLOW, "destination": "10.0.0"}, "neither a valid IP address nor an FQDN"),
    ({**FLOW, "destination": ""}, "destination is empty"),
    ({**FLOW, "dst_port": None}, "dst_port is required for TCP"),
    ({**FLOW, "dst_port": 70000}, "not a port number between 0 and 65535"),
    ({**FLOW, "dst_port": "http"}, "not a port number between 0 and 65535"),
    ({**FLOW, "destination_ip": "not-an-ip"}, "destination_ip 'not-an-ip' is not an IP address"),
    ({**FLOW, "destination_ip": "10.0.0.0/8"}, "destination_ip '10.0.0.0/8' is not an IP address"),
])
async def test_trace_flow_rejects_bad_arguments_readably(structured_record, firewall_id, args, message):
    state = await flow_state(structured_record, firewall_id)
    assert message in await call_error(state, "trace_flow", args)


# ── lookup_address ───────────────────────────────────────────────────────────

async def test_lookup_host_with_context(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    seed.network(source="10.0.0.5", time=iso(-30))
    seed.network(source="10.0.0.5", action="Deny", time=iso(-20))
    seed.network(source="10.7.7.7", dest="10.0.0.5", time=iso(-10))
    seed.network(source="10.0.0.5", time=iso(-3600))             # older than the recent window
    seed.network(source="10.0.0.6", time=iso(-10))               # another address
    out = await call(state, "lookup_address", {"address": "10.0.0.5"})

    assert out["address"] == "10.0.0.5" and out["kind"] == "host" and out["fw_instance"] is None
    assert out["ip_groups"] == [{"name": "ipg-spokes", "id": G_SPOKES, "matching_entry": "10.0.0.0/16",
                                 "relation": "contains"}]
    assert out["recent"]["window"] == "15m"
    assert (out["recent"]["as_source"], out["recent"]["as_destination"]) == (2, 1)
    assert out["recent"]["top_actions"] == [{"action": "Allow", "count": 2}, {"action": "Deny", "count": 1}]

    refs = [(r["ref"], r["as"], r["via"], r["wildcard"]) for r in out["rules"]]
    assert refs[:3] == [
        ("fw-pol » rcg-net » rc-dns » allow-dns", "source", "10.0.0.0/8", False),
        ("fw-pol » rcg-net » rc-tags » allow-monitor", "source", "10.0.0.0/8", False),
        ("fw-pol » rcg-net » rc-allow » allow-web", "source", "ip-group:ipg-spokes (10.0.0.0/16)", False),
    ]
    # Rules that merely say "any" follow the specific ones, in evaluation order.
    wildcards = [r for r in out["rules"] if r["wildcard"]]
    assert wildcards and out["rules"][len(out["rules"]) - len(wildcards):] == wildcards
    assert ("fw-pol » rcg-net » rc-deny » deny-bad", "source", "*", True) in \
        [(r["ref"], r["as"], r["via"], r["wildcard"]) for r in wildcards]
    first = out["rules"][0]
    assert first["kind"] == "network" and first["action"] == "Allow"
    assert (first["group_priority"], first["collection_priority"]) == (100, 120)
    assert out["rules_total"] == len(out["rules"]) and out["rules_truncated"] is False
    assert any("ipg-junk" in n and "10.9.0.0-oops" in n for n in out["notes"])


async def test_lookup_firewall_instance_and_destination_rules(structured_record, firewall_id):
    state, _ = loaded_state(structured_record, firewall_id)
    out = await call(state, "lookup_address", {"address": "10.1.0.5"})
    assert out["fw_instance"] == "AzFw.5"
    dest = await call(state, "lookup_address", {"address": "203.0.113.7"})
    assert [(r["ref"], r["as"], r["via"]) for r in dest["rules"] if not r["wildcard"]] == [
        ("fw-pol » rcg-net » rc-deny » deny-bad", "destination", "203.0.113.0/24")]
    assert dest["fw_instance"] is None and dest["ip_groups"] == []


async def test_lookup_cidr_matches_overlapping_entries(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    seed.network(source="10.0.1.1", time=iso(-5))
    seed.network(source="192.168.0.1", time=iso(-5))
    out = await call(state, "lookup_address", {"address": "10.0.0.0/8"})
    assert out["kind"] == "network" and out["address"] == "10.0.0.0/8" and out["fw_instance"] is None
    assert out["ip_groups"][0]["name"] == "ipg-spokes" and out["ip_groups"][0]["relation"] == "inside"
    assert out["recent"]["as_source"] == 1
    monitor = next(r for r in out["rules"] if r["ref"].endswith("allow-monitor"))
    assert monitor["relation"] == "contains"
    web = next(r for r in out["rules"] if r["ref"].endswith("allow-web"))
    assert web["relation"] == "inside" and web["via"] == "ip-group:ipg-spokes (10.0.0.0/16)"
    partial = await call(state, "lookup_address", {"address": "10.0.0.0/15"})
    assert partial["ip_groups"][0]["relation"] == "inside"
    other = await call(state, "lookup_address", {"address": "10.4.0.0/14"})   # 10.4.0.0 to 10.7.255.255
    assert other["ip_groups"] == []
    v6 = await call(state, "lookup_address", {"address": "fd00::/8"})
    assert v6["ip_groups"] == [] and v6["kind"] == "network"


async def test_lookup_limit_and_truncation(structured_record, firewall_id):
    state, _ = loaded_state(structured_record, firewall_id)
    full = await call(state, "lookup_address", {"address": "10.0.0.5"})
    out = await call(state, "lookup_address", {"address": "10.0.0.5", "limit": 2})
    assert len(out["rules"]) == 2 and out["rules_truncated"] is True and out["rules_total"] == full["rules_total"]


async def test_lookup_without_context_answers_recent_only(state, seed):
    seed.network(source="10.0.0.5", time=iso(-5))
    out = await call(state, "lookup_address", {"address": "10.0.0.0/24"})
    assert out["recent"]["as_source"] == 1
    assert out["policy_context"]["available"] is False and out["policy_context"]["state"] == "off"
    assert "rules" not in out and "ip_groups" not in out


async def test_lookup_context_without_a_policy_keeps_the_groups(structured_record, firewall_id):
    state, _ = loaded_state(structured_record, firewall_id, with_policy=False)
    out = await call(state, "lookup_address", {"address": "10.0.0.5"})
    assert out["ip_groups"][0]["name"] == "ipg-spokes" and out["rules"] == []
    assert any("carries no policy" in n for n in out["notes"])


@pytest.mark.parametrize("address", ["www.example.com", "10.0.0.0/40", "", "10.0.0"])
async def test_lookup_rejects_bad_addresses(state, address):
    assert "neither an IP address nor a CIDR" in await call_error(state, "lookup_address", {"address": address})


# ── get_log_coverage ─────────────────────────────────────────────────────────

HUB_SETTING = DiagnosticSetting(
    name="to-hub", event_hub="lab-ns/firewall-logs",
    categories=["AZFWNetworkRule", "AZFWApplicationRule", "AZFWFlowTrace", "AZFWFatFlow", "AzureFirewallDnsProxy",
                "AZFWSomethingNew"])
LAW_SETTING = DiagnosticSetting(name="to-law", workspace="law-hub", all_logs=True)


async def test_coverage_forwarded_against_observed(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id, diagnostics=[HUB_SETTING, LAW_SETTING],
                               props={"Network.AdditionalLogs.EnableFatFlowLogging": "false"})
    seed.network()
    seed.network()
    seed._add(seed.record("AZFWThreatIntel", Protocol="TCP", SourceIp="10.0.0.5", SourcePort=1,
                          DestinationIp="198.51.100.1", DestinationPort=80, Action="Alert"))
    out = await call(state, "get_log_coverage")

    assert out["connected_hub"] == {"namespace": "lab-ns.servicebus.windows.net", "hub": "firewall-logs"}
    assert out["settings_feeding_hub"] == 1
    assert out["forwarded"] == ["NetworkRule", "AppRule", "DnsQuery", "FlowTrace", "FatFlow"]
    assert out["forwarded_other_categories"] == ["AZFWSomethingNew"]
    assert out["observed"] == {"NetworkRule": 2, "ThreatIntel": 1}
    assert out["forwarded_not_seen"] == ["AppRule", "DnsQuery", "FlowTrace", "FatFlow"]
    assert out["seen_not_forwarded"] == ["ThreatIntel"]      # the all-logs setting goes to a workspace, not this hub

    hub, law = out["diagnostic_settings"]
    assert hub["name"] == "to-hub" and hub["feeds_connected_hub"] is True
    assert hub["targets"] == [{"kind": "event_hub", "name": "lab-ns/firewall-logs"}]
    assert hub["forwards"] == ["NetworkRule", "AppRule", "DnsQuery", "FlowTrace", "FatFlow"]
    assert law["feeds_connected_hub"] is False and law["all_logs"] is True and len(law["forwards"]) == 9
    assert law["targets"] == [{"kind": "workspace", "name": "law-hub"}]

    codes = {h["code"]: h["message"] for h in out["hints"]}
    assert "EnableFatFlowLogging" in codes["fat_flow_logging_off"]
    assert "flow_trace_never_seen" in codes and "feature registration" in codes["flow_trace_never_seen"]
    assert "dns_flow_trace_off" in codes and "EnableDnstapLogging" in codes["dns_flow_trace_off"]
    assert "no_setting_targets_hub" not in codes


async def test_coverage_hub_match_ignores_case_and_all_logs_forwards_everything(structured_record, firewall_id):
    setting = DiagnosticSetting(name="all", event_hub="LAB-NS/FIREWALL-LOGS", all_logs=True)
    state, seed = loaded_state(structured_record, firewall_id, diagnostics=[setting],
                               props={"Network.AdditionalLogs.EnableFatFlowLogging": "true"})
    seed.network()
    out = await call(state, "get_log_coverage")
    assert len(out["forwarded"]) == 9 and out["seen_not_forwarded"] == []
    assert "fat_flow_logging_off" not in {h["code"] for h in out["hints"]}      # the switch is on


async def test_coverage_other_namespace_does_not_count(structured_record, firewall_id):
    setting = DiagnosticSetting(name="elsewhere", event_hub="other-ns/firewall-logs", all_logs=True)
    state, seed = loaded_state(structured_record, firewall_id, diagnostics=[setting])
    seed.network()
    out = await call(state, "get_log_coverage")
    assert out["settings_feeding_hub"] == 0 and out["forwarded"] == [] and out["seen_not_forwarded"] == []
    assert [h["code"] for h in out["hints"]] == ["no_setting_targets_hub"]
    assert "None of the diagnostic settings targets this hub" in out["hints"][0]["message"]
    assert "lab-ns.servicebus.windows.net/firewall-logs" in out["hints"][0]["message"]


async def test_coverage_without_readable_settings(structured_record, firewall_id):
    state, _ = loaded_state(structured_record, firewall_id)
    out = await call(state, "get_log_coverage")
    assert out["diagnostic_settings"] == [] and "could be read" in out["hints"][0]["message"]


async def test_coverage_dns_hints_follow_the_policy(structured_record, firewall_id):
    setting = DiagnosticSetting(name="dns", event_hub="lab-ns/firewall-logs", categories=["AZFWDnsQuery"])
    state, _ = loaded_state(structured_record, firewall_id, diagnostics=[setting])
    out = await call(state, "get_log_coverage")
    codes = [h["code"] for h in out["hints"]]
    assert codes == ["dns_proxy_off", "dns_flow_trace_off"]      # POLICY has the DNS proxy disabled
    POLICY.dns_proxy = True
    try:
        assert [h["code"] for h in (await call(state, "get_log_coverage"))["hints"]] == ["dns_flow_trace_off"]
    finally:
        POLICY.dns_proxy = False


async def test_coverage_without_context_reports_what_arrived(state, seed):
    seed.network()
    seed.flow()
    out = await call(state, "get_log_coverage")
    assert out["available"] is False and out["state"] == "off"
    assert out["observed"] == {"FlowTrace": 1, "NetworkRule": 1}


async def test_coverage_with_an_unidentified_hub_counts_every_event_hub(structured_record, firewall_id):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    holder.snapshot = snapshot(diagnostics=[HUB_SETTING])
    state = make_state(settings=EventHubSettings(), context=holder)
    out = await call(state, "get_log_coverage")
    assert out["settings_feeding_hub"] == 1 and out["connected_hub"] == {"namespace": None, "hub": None}
