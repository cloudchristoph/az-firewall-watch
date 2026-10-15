"""Log tools through the MCP protocol (in-memory client against the real server object)."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pytest
from mcp.client.client import Client

from fw_parser import parse_record
from mcp_server.config import ServerConfig
from mcp_server.context import ContextHolder
from mcp_server.server import build_server
from mcp_server.state import AppState
from viewer.azure_resources import (
    FirewallInfo,
    FirewallPolicyInfo,
    IpGroupInfo,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
)
from viewer.cache import CachedSnapshot
from viewer.eventhub import EventHubSettings

SAS_CONN = ("Endpoint=sb://lab-ns.servicebus.windows.net/;SharedAccessKeyName=listen;"
            "SharedAccessKey=SUPERSECRET;EntityPath=firewall-logs")

SUMMARY_KEYS = {"id", "time", "category", "protocol", "source", "src_port", "destination", "dst_port", "action",
                "rule", "info"}
FULL_KEYS = SUMMARY_KEYS | {"resource_id", "policy", "rule_collection_group", "rule_collection", "rule_name",
                            "nat_dst_ip", "nat_dst_port", "explicit_proxy", "tls_inspected", "received_at"}


def snapshot(*, with_policy: bool = True) -> CachedSnapshot:
    policy = None
    if with_policy:
        rule = Rule(name="allow-web", rule_type="NetworkRule", source_addresses=["10.0.0.0/8"],
                    destination_addresses=["*"], destination_ports=["443"], protocols=["TCP"])
        rc = RuleCollection(name="rc-allow", priority=200, action="Allow",
                            rule_collection_type="FirewallPolicyFilterRuleCollection", rules=[rule])
        policy = FirewallPolicyInfo(id="/pol", name="fw-pol", rule_collection_groups=[
            RuleCollectionGroup(id="/rcg", name="rcg-net", priority=100, rule_collections=[rc])])
    fw = FirewallInfo(id="/fw", name="fw-hub", subscription_id="sub", resource_group="rg", location="gwc")
    groups = {"/g/spokes": IpGroupInfo(id="/g/spokes", name="ipg-spokes", location="gwc", ip_addresses=["10.0.0.0/16"])}
    return CachedSnapshot(firewall=fw, policy=policy, ip_groups=groups, subnet_cidrs=["10.1.0.0/26"],
                          fetched_at=time.time())


class Seeder:
    def __init__(self, state: AppState, structured_record) -> None:
        self.state = state
        self.record = structured_record

    def network(self, source: str = "10.0.0.1", action: str = "Allow", port: int = 443, src_port: int = 50000,
                time: str = "2026-09-05T08:00:00Z", dest: str = "10.1.0.1", **extra: Any):
        rec = self.record("AZFWNetworkRule", time=time, Protocol="TCP", SourceIp=source, SourcePort=src_port,
                          DestinationIp=dest, DestinationPort=port, Action=action, **extra)
        return self._add(rec)

    def ruled(self, **kw: Any):
        return self.network(Policy="fw-pol", RuleCollectionGroup="rcg-net", RuleCollection="rc-allow",
                            Rule="allow-web", **kw)

    def flow(self):
        return self._add(self.record("AZFWFlowTrace", Protocol="TCP", SourceIp="10.0.0.9", SourcePort=1,
                                     DestinationIp="10.1.0.1", DestinationPort=443, Flag="SYN"))

    def dns(self):
        return self._add(self.record("AZFWDnsQuery", SourceIp="fd10:3:5:1::4", SourcePort=40000, QueryType="AAAA",
                                     QueryName="example.com.", ResponseCode="NOERROR"))

    def _add(self, rec: dict):
        row = parse_record(rec)
        assert row is not None
        return self.state.buffer.append(row, rec)


def make_state(*, settings: EventHubSettings | None = None, context: ContextHolder | None = None) -> AppState:
    config = ServerConfig(eventhub=settings or EventHubSettings(fq_namespace="lab-ns.servicebus.windows.net",
                                                                hub_name="firewall-logs"),
                          policy_context=context is not None and context.enabled, buffer_size=1000)
    state = AppState.create(config)
    if context is not None:
        state.context = context
    return state


@pytest.fixture
def state() -> AppState:
    return make_state(context=ContextHolder(enabled=False))


@pytest.fixture
def seed(state, structured_record) -> Seeder:
    return Seeder(state, structured_record)


async def call(state: AppState, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    async with Client(build_server(state.config, state=state)) as client:
        result = await client.call_tool(name, args or {})
    assert not result.is_error, result.content
    assert result.structured_content is not None
    return result.structured_content


async def call_error(state: AppState, name: str, args: dict[str, Any]) -> str:
    async with Client(build_server(state.config, state=state)) as client:
        result = await client.call_tool(name, args)
    assert result.is_error
    return " ".join(getattr(c, "text", "") for c in result.content)


# ── tool list ────────────────────────────────────────────────────────────────

async def test_tools_carry_annotations_and_argument_docs(state):
    async with Client(build_server(state.config, state=state)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    # The policy and analysis modules register their own tools next to these.
    assert {"get_status", "query_logs", "tail_logs", "get_log_entry", "clear_logs"} <= set(tools)
    for name in ("get_status", "query_logs", "tail_logs", "get_log_entry"):
        ann = tools[name].annotations
        assert ann is not None and ann.read_only_hint is True and ann.destructive_hint is False
    clear = tools["clear_logs"].annotations
    assert clear is not None and clear.destructive_hint is True and clear.read_only_hint is False
    props = tools["query_logs"].input_schema["properties"]
    assert {"category", "action", "source", "destination", "protocol", "dst_port", "src_port", "rule", "text",
            "since", "until", "after_id", "limit", "order", "detail"} <= set(props)
    assert "CIDR" in props["source"]["description"]
    assert "ctx" not in props
    assert "detail" in tools["tail_logs"].input_schema["properties"]
    assert all(t.description for t in tools.values())


# ── get_status ───────────────────────────────────────────────────────────────

async def test_get_status_shape(state, seed, firewall_id):
    seed.network()
    state.buffer.count_skip("ResourceType")
    state.stream.firewall_id = firewall_id
    status = await call(state, "get_status")
    eh = status["event_hub"]
    assert eh["namespace"] == "lab-ns.servicebus.windows.net" and eh["hub"] == "firewall-logs"
    assert (eh["auth"], eh["consumer_group"], eh["start_position"], eh["state"]) == ("entra", "$Default", "@latest",
                                                                                    "stopped")
    assert status["events"]["received"] == 1
    assert status["events"]["skipped"] == {"ResourceType": 1}
    assert status["events"]["per_category"] == {"NetworkRule": 1}
    assert status["events"]["last_event_age_s"] >= 0
    assert status["buffer"] == {"size": 1, "capacity": 1000, "first_id": 1, "last_id": 1}
    assert status["firewall_id"] == firewall_id and status["firewall_name"] == "fw-hub"
    assert status["policy_context"]["state"] == "off"
    assert status["server"]["name"] == "az-firewall-watch" and status["server"]["version"]


async def test_get_status_never_returns_the_sas_key():
    state = make_state(settings=EventHubSettings(connection_string=SAS_CONN))
    state.stream.last_error = f"connect failed for {SAS_CONN}"
    status = await call(state, "get_status")
    assert status["event_hub"]["auth"] == "sas"
    assert (status["event_hub"]["namespace"], status["event_hub"]["hub"]) == ("lab-ns.servicebus.windows.net",
                                                                              "firewall-logs")
    assert "SUPERSECRET" not in json.dumps(status)
    assert "SharedAccessKey=<redacted>" in status["event_hub"]["last_error"]


async def test_get_status_uses_the_arm_name_once_loaded(firewall_id):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    holder.snapshot = snapshot()
    state = make_state(context=holder)
    status = await call(state, "get_status")
    assert status["firewall_name"] == "fw-hub" and status["policy_context"]["state"] == "loaded"


# ── query_logs ───────────────────────────────────────────────────────────────

async def test_query_defaults_newest_first_summary(state, seed):
    for i in range(3):
        seed.network(source=f"10.0.0.{i}")
    out = await call(state, "query_logs")
    assert [r["id"] for r in out["rows"]] == [3, 2, 1]
    assert set(out["rows"][0]) == SUMMARY_KEYS
    assert (out["matched"], out["returned"], out["has_more"], out["order"]) == (3, 3, False, "desc")
    assert (out["first_id"], out["last_id"], out["next_after_id"], out["next_before_id"]) == (3, 1, 3, None)
    assert out["buffer"] == {"size": 3, "capacity": 1000, "first_id": 1, "last_id": 3}
    assert out["filter"] == {}


async def test_query_row_values_drop_placeholders(state, seed):
    seed.ruled()
    seed.flow()
    out = await call(state, "query_logs", {"order": "asc"})
    first, flow = out["rows"]
    assert first["rule"] == "fw-pol » rcg-net » rc-allow » allow-web"
    assert first["src_port"] == "50000" and first["info"] is None
    assert flow["rule"] is None and flow["action"] == "SYN"


@pytest.mark.parametrize("args, expected", [
    ({"category": "NetworkRule"}, [1, 2, 3, 4]),
    ({"category": "traffic"}, [5]),
    ({"category": ["dns", "flowtrace"]}, [5, 6]),
    ({"action": "deny"}, [2]),
    ({"source": "10.0.0.0/30"}, [1, 2]),
    ({"source": "fd10::/16"}, [6]),
    ({"destination": "example.com"}, [6]),
    ({"protocol": "udp"}, []),
    ({"dst_port": "8443"}, [3]),
    ({"dst_port": 443}, [1, 2, 3, 4, 5]),     # substring, like the TUI
    ({"src_port": 61000}, [4]),
    ({"rule": "rc-allow"}, [4]),
    ({"text": "allow-web"}, [4]),
    ({"since": "2026-09-05T08:30:00Z", "until": "2026-09-05T09:00:00Z"}, [3, 4, 5, 6]),
    ({"after_id": 4}, [5, 6]),
    ({"before_id": 3}, [1, 2]),
    ({"source": "10.0.0.0/8", "action": "allow", "dst_port": "443"}, [1, 3, 4]),   # FlowTrace logs SYN, not Allow
])
async def test_query_filters(state, seed, args, expected):
    seed.network(source="10.0.0.1")
    seed.network(source="10.0.0.2", action="Deny")
    seed.network(source="10.0.0.10", port=8443, time="2026-09-05T08:30:00Z")
    seed.ruled(source="10.0.1.1", src_port=61000, time="2026-09-05T08:40:00Z")
    seed._add(seed.record("AZFWFlowTrace", time="2026-09-05T08:50:00Z", Protocol="TCP", SourceIp="10.0.0.9",
                          SourcePort=1, DestinationIp="10.1.0.1", DestinationPort=443, Flag="SYN"))
    seed._add(seed.record("AZFWDnsQuery", time="2026-09-05T08:55:00Z", SourceIp="fd10:3:5:1::4", SourcePort=40000,
                          QueryType="AAAA", QueryName="example.com.", ResponseCode="NOERROR"))
    out = await call(state, "query_logs", {**args, "order": "asc"})
    assert [r["id"] for r in out["rows"]] == expected
    assert out["matched"] == len(expected)


async def test_query_paging_desc_and_asc(state, seed):
    for i in range(7):
        seed.network(source=f"10.0.0.{i}")
    page = await call(state, "query_logs", {"limit": 3})
    assert [r["id"] for r in page["rows"]] == [7, 6, 5] and page["has_more"] and page["next_before_id"] == 5
    page = await call(state, "query_logs", {"limit": 3, "before_id": page["next_before_id"]})
    assert [r["id"] for r in page["rows"]] == [4, 3, 2]
    page = await call(state, "query_logs", {"limit": 3, "order": "asc"})
    assert [r["id"] for r in page["rows"]] == [1, 2, 3] and page["next_after_id"] == 3
    page = await call(state, "query_logs", {"limit": 3, "order": "asc", "after_id": page["next_after_id"]})
    assert [r["id"] for r in page["rows"]] == [4, 5, 6] and page["has_more"]
    page = await call(state, "query_logs", {"limit": 3, "order": "asc", "after_id": page["next_after_id"]})
    assert [r["id"] for r in page["rows"]] == [7] and not page["has_more"] and page["next_after_id"] == 7


async def test_query_limits_are_clamped(state, seed):
    for _ in range(3):
        seed.network()
    assert (await call(state, "query_logs", {"limit": 0}))["returned"] == 1
    assert (await call(state, "query_logs", {"limit": 50000}))["returned"] == 3


async def test_query_detail_levels(state, seed):
    item = seed.ruled()
    full = (await call(state, "query_logs", {"detail": "full"}))["rows"][0]
    assert set(full) == FULL_KEYS
    assert (full["policy"], full["rule_collection_group"], full["rule_collection"], full["rule_name"]) == \
        ("fw-pol", "rcg-net", "rc-allow", "allow-web")
    assert full["received_at"].endswith("Z")
    raw = (await call(state, "query_logs", {"detail": "RAW"}))["rows"][0]
    assert set(raw) == FULL_KEYS | {"raw"}
    assert raw["raw"] == item.raw


@pytest.mark.parametrize("args, message", [
    ({"detail": "verbose"}, "detail must be one of summary, full, raw"),
    ({"order": "sideways"}, "order must be 'asc' or 'desc'"),
    ({"since": "a while ago"}, "neither a relative duration"),
    ({"source": "10.0.0.0/40"}, "not a valid network"),
    ({"category": "bogus"}, "Unknown category"),
])
async def test_query_rejects_bad_arguments_readably(state, args, message):
    assert message in await call_error(state, "query_logs", args)


# ── tail_logs ────────────────────────────────────────────────────────────────

async def test_tail_returns_when_a_row_arrives(state, seed):
    seed.network()   # already buffered: not part of the tail

    async def later():
        await asyncio.sleep(0.2)
        seed.network(source="10.9.9.9")

    task = asyncio.create_task(later())
    started = time.monotonic()
    out = await call(state, "tail_logs", {"timeout_s": 10, "detail": "full"})
    await task
    assert time.monotonic() - started < 5
    assert [r["id"] for r in out["rows"]] == [2] and set(out["rows"][0]) == FULL_KEYS
    assert out["timed_out"] is False and out["next_after_id"] == 2


async def test_tail_respects_the_filter(state, seed):
    async def later():
        await asyncio.sleep(0.1)
        seed.network(action="Allow")
        await asyncio.sleep(0.1)
        seed.network(action="Deny")

    task = asyncio.create_task(later())
    out = await call(state, "tail_logs", {"action": "deny", "timeout_s": 10})
    await task
    assert [r["action"] for r in out["rows"]] == ["Deny"]
    assert out["filter"] == {"action": "deny"}


async def test_tail_times_out_and_moves_the_cursor(state, seed):
    seed.network(action="Allow")
    out = await call(state, "tail_logs", {"after_id": 0, "action": "deny", "timeout_s": 0})   # clamped to 1 s
    assert out == {**out, "rows": [], "returned": 0, "timed_out": True, "next_after_id": 1}


async def test_tail_with_after_id_returns_buffered_rows_at_once(state, seed):
    for _ in range(4):
        seed.network()
    out = await call(state, "tail_logs", {"after_id": 1, "limit": 2})
    assert [r["id"] for r in out["rows"]] == [2, 3] and out["next_after_id"] == 3


# ── get_log_entry ────────────────────────────────────────────────────────────

async def test_entry_unknown_id_is_a_readable_error(state, seed):
    seed.network()
    message = await call_error(state, "get_log_entry", {"id": 99})
    assert "No row with id 99" in message and "ids 1 to 1 are buffered" in message


async def test_entry_without_context(state, seed):
    seed.network()
    out = await call(state, "get_log_entry", {"id": 1})
    assert set(out) >= FULL_KEYS | {"raw", "enrichment", "traceable", "trace_unavailable_reason", "policy_context"}
    assert out["enrichment"] is None and out["traceable"] is False
    assert "not loaded (state: off)" in out["trace_unavailable_reason"]


async def test_entry_with_context_is_enriched_and_traceable(firewall_id, structured_record):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    holder.snapshot = snapshot()
    state = make_state(context=holder)
    seed = Seeder(state, structured_record)
    seed.ruled(source="10.0.0.5", dest="10.1.0.4")
    out = await call(state, "get_log_entry", {"id": 1})
    assert out["enrichment"] == {"dest_fw_instance": "AzFw.4", "source_ip_groups": ["ipg-spokes"],
                                 "rule_priority": "RCG:100 » RC:200", "rule_action": "Allow"}
    assert out["traceable"] is True and out["trace_unavailable_reason"] is None


async def test_entry_observation_rows_are_not_traceable(firewall_id, structured_record):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    holder.snapshot = snapshot()
    state = make_state(context=holder)
    seed = Seeder(state, structured_record)
    seed.flow()
    seed.dns()
    flow = await call(state, "get_log_entry", {"id": 1})
    assert flow["traceable"] is False and "FlowTrace records the handshake" in flow["trace_unavailable_reason"]
    dns = await call(state, "get_log_entry", {"id": 2})
    assert "DNS proxy rows" in dns["trace_unavailable_reason"]


async def test_entry_context_without_policy(firewall_id, structured_record):
    holder = ContextHolder(enabled=True, firewall_id=firewall_id)
    holder.snapshot = snapshot(with_policy=False)
    state = make_state(context=holder)
    Seeder(state, structured_record).network()
    out = await call(state, "get_log_entry", {"id": 1})
    assert out["traceable"] is False and "carries no policy" in out["trace_unavailable_reason"]


# ── clear_logs ───────────────────────────────────────────────────────────────

async def test_clear_logs(state, seed):
    for _ in range(3):
        seed.network()
    assert await call(state, "clear_logs") == {"cleared": 3, "next_after_id": 3}
    out = await call(state, "query_logs")
    assert out["rows"] == [] and out["buffer"]["size"] == 0 and out["buffer"]["last_id"] == 3
    assert seed.network().id == 4
    assert (await call(state, "get_status"))["events"]["received"] == 4
