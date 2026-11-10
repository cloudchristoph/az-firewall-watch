"""Resources and prompts through the MCP protocol (in-memory client against the real server object)."""
from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.client.client import Client
from mcp.shared.exceptions import MCPError

from mcp_server.context import ContextHolder
from mcp_server.server import build_server
from mcp_server.state import AppState
from tests.test_mcp_tools_analysis import loaded_state, ruled
from tests.test_mcp_tools_logs import Seeder, make_state

STATIC_URIS = {"azfw://status", "azfw://firewall", "azfw://policy", "azfw://policy/rules", "azfw://ip-groups",
               "azfw://logs/recent"}


async def read(state: AppState, uri: str) -> tuple[Any, str]:
    """``(parsed JSON, mime type)`` of a resource."""
    async with Client(build_server(state.config, state=state)) as client:
        result = await client.read_resource(uri)
    (content,) = result.contents
    return json.loads(content.text), content.mime_type


async def read_error(state: AppState, uri: str) -> MCPError:
    async with Client(build_server(state.config, state=state)) as client:
        with pytest.raises(MCPError) as caught:
            await client.read_resource(uri)
    return caught.value


@pytest.fixture
def plain() -> AppState:
    return make_state(context=ContextHolder(enabled=False))


# ── listing ──────────────────────────────────────────────────────────────────

async def test_resources_and_template_are_listed(plain):
    async with Client(build_server(plain.config, state=plain)) as client:
        resources = (await client.list_resources()).resources
        templates = (await client.list_resource_templates()).resource_templates
    assert {str(r.uri) for r in resources} == STATIC_URIS
    assert all(r.mime_type == "application/json" and r.description and r.title for r in resources)
    assert [t.uri_template for t in templates] == ["azfw://logs/{id}"]
    assert templates[0].mime_type == "application/json" and "get_log_entry" in templates[0].description


# ── static resources ─────────────────────────────────────────────────────────

async def test_status_resource_is_the_status_tool(plain, structured_record):
    Seeder(plain, structured_record).network()
    body, mime = await read(plain, "azfw://status")
    assert mime == "application/json"
    assert body["server"]["name"] == "az-firewall-watch" and body["buffer"]["size"] == 1
    assert body["events"]["per_category"] == {"NetworkRule": 1}
    assert body["event_hub"]["hub"] == "firewall-logs" and "SharedAccessKey" not in json.dumps(body)


@pytest.mark.parametrize("uri", ["azfw://firewall", "azfw://policy", "azfw://policy/rules", "azfw://ip-groups"])
async def test_policy_resources_without_context_say_so(plain, uri):
    body, mime = await read(plain, uri)
    assert mime == "application/json"
    assert body["available"] is False and body["state"] == "off" and body["hint"]


async def test_policy_resources_equal_their_tools(structured_record, firewall_id):
    state, _ = loaded_state(structured_record, firewall_id)
    async with Client(build_server(state.config, state=state)) as client:
        rules_tool = (await client.call_tool("list_rules", {})).structured_content
        groups_tool = (await client.call_tool("list_ip_groups", {})).structured_content
        rules_res = json.loads((await client.read_resource("azfw://policy/rules")).contents[0].text)
        groups_res = json.loads((await client.read_resource("azfw://ip-groups")).contents[0].text)
        firewall = json.loads((await client.read_resource("azfw://firewall")).contents[0].text)
        policy = json.loads((await client.read_resource("azfw://policy")).contents[0].text)
    # cache_age_s is measured at call time, so two calls a few milliseconds apart may differ in it.
    for answer in (rules_res, rules_tool, groups_res, groups_tool):
        answer.pop("cache_age_s", None)
    assert rules_res == rules_tool and groups_res == groups_tool
    assert rules_res["total"] == 6 and rules_res["rules"][0]["ref"] == "fw-pol » rcg-dnat » rc-dnat » rdp-in"
    assert {g["name"] for g in groups_res["ip_groups"]} >= {"ipg-spokes"}
    assert firewall["name"] == "fw-hub" and policy["name"] == "fw-pol"
    assert "available" not in firewall and "available" not in policy


async def test_recent_logs_resource_is_the_newest_hundred(plain, structured_record):
    seed = Seeder(plain, structured_record)
    for i in range(120):
        seed.network(source=f"10.0.{i // 250}.{i % 250}")
    body, mime = await read(plain, "azfw://logs/recent")
    assert mime == "application/json"
    assert body["returned"] == 100 and body["matched"] == 120 and body["has_more"] is True
    assert [r["id"] for r in body["rows"]][:2] == [120, 119] and body["rows"][-1]["id"] == 21
    assert set(body["rows"][0]) == {"id", "time", "category", "protocol", "source", "src_port", "destination",
                                    "dst_port", "action", "rule", "info"}


async def test_recent_logs_resource_on_an_empty_buffer(plain):
    body, _ = await read(plain, "azfw://logs/recent")
    assert body["rows"] == [] and body["matched"] == 0


# ── the template ─────────────────────────────────────────────────────────────

async def test_log_entry_template_resolves_to_the_entry_tool(structured_record, firewall_id):
    state, seed = loaded_state(structured_record, firewall_id)
    ruled(seed, "rc-allow", "allow-web", source="10.0.0.5", dest="10.1.0.4")
    seed.network()
    body, mime = await read(state, "azfw://logs/1")
    assert mime == "application/json" and body["id"] == 1 and body["source"] == "10.0.0.5"
    assert body["raw"]["properties"]["Rule"] == "allow-web"
    assert body["enrichment"]["dest_fw_instance"] == "AzFw.4" and body["enrichment"]["source_ip_groups"] == ["ipg-spokes"]
    assert body["traceable"] is True
    assert (await read(state, "azfw://logs/2"))[0]["id"] == 2


async def test_log_entry_template_without_context(plain, structured_record):
    Seeder(plain, structured_record).network()
    body, _ = await read(plain, "azfw://logs/1")
    assert body["enrichment"] is None and body["traceable"] is False


async def test_recent_is_not_taken_for_an_id(plain, structured_record):
    Seeder(plain, structured_record).network()
    body, _ = await read(plain, "azfw://logs/recent")
    assert "rows" in body and "raw" not in body


async def test_log_entry_unknown_id_is_a_readable_error(plain, structured_record):
    Seeder(plain, structured_record).network()
    error = await read_error(plain, "azfw://logs/99")
    assert "No row with id 99" in error.error.message and "ids 1 to 1 are buffered" in error.error.message
    assert "Error executing tool" not in error.error.message


async def test_log_entry_id_must_be_a_number(plain):
    error = await read_error(plain, "azfw://logs/yesterday")
    assert "must be a whole number" in error.error.message


async def test_unknown_resource(plain):
    error = await read_error(plain, "azfw://nothing-here")
    assert "Unknown resource" in error.error.message


async def test_each_read_sees_its_own_server_state(structured_record):
    """The request context is parked per read, so two servers never share a state."""
    first = make_state(context=ContextHolder(enabled=False))
    second = make_state(context=ContextHolder(enabled=False))
    Seeder(second, structured_record).network()
    assert (await read(first, "azfw://logs/recent"))[0]["matched"] == 0
    assert (await read(second, "azfw://logs/recent"))[0]["matched"] == 1
    assert (await read(first, "azfw://logs/recent"))[0]["matched"] == 0


# ── prompts ──────────────────────────────────────────────────────────────────

async def prompt_text(state: AppState, name: str, arguments: dict[str, str] | None = None) -> str:
    async with Client(build_server(state.config, state=state)) as client:
        result = await client.get_prompt(name, arguments)
    (message,) = result.messages
    assert message.role == "user"
    return message.content.text


async def test_prompts_are_listed_with_their_arguments(plain):
    async with Client(build_server(plain.config, state=plain)) as client:
        prompts = {p.name: p for p in (await client.list_prompts()).prompts}
    assert set(prompts) == {"investigate_denies", "explain_entry", "firewall_health_check"}
    assert all(p.description and p.title for p in prompts.values())
    since = {a.name: a.required for a in prompts["investigate_denies"].arguments or []}
    assert since == {"since": False}
    assert {a.name: a.required for a in prompts["explain_entry"].arguments or []} == {"id": True}
    assert not prompts["firewall_health_check"].arguments


async def test_investigate_denies_defaults_and_takes_a_window(plain):
    text = await prompt_text(plain, "investigate_denies")
    assert 'since="15m"' in text and "last 15m" in text
    for tool in ("summarize_logs", "query_logs", "explain_log_entry", "lookup_address", "trace_flow"):
        assert tool in text
    assert "denied_without_rule" in text and "narrowest rule" in text and "scanning" in text
    longer = await prompt_text(plain, "investigate_denies", {"since": "2h"})
    assert 'since="2h"' in longer and "last 2h" in longer and "15m" not in longer
    assert 'since="2026-09-05T08:00:00Z"' in await prompt_text(plain, "investigate_denies",
                                                                  {"since": "2026-09-05T08:00:00Z"})


async def test_explain_entry_names_the_row_and_the_tool(plain):
    text = await prompt_text(plain, "explain_entry", {"id": "17"})
    assert "log row 17" in text and "explain_log_entry with id=17" in text
    assert "matched_rule" in text and "nearest_misses" in text and "trace_flow" in text


async def test_health_check_names_status_coverage_and_policy_tools(plain):
    text = await prompt_text(plain, "firewall_health_check")
    for needle in ("get_status", "get_log_coverage", "get_firewall", "get_policy", "summarize_logs",
                   "auto-learn", "route server", "maintenance", "capacity", "missing", "forwarded_not_seen"):
        assert needle.lower() in text.lower(), needle


@pytest.mark.parametrize("name, arguments, message", [
    ("investigate_denies", {"since": "a while"}, "neither a relative duration"),
    ("explain_entry", {"id": "seven"}, "id must be the numeric row id"),
])
async def test_prompt_arguments_are_checked_with_a_readable_message(plain, name, arguments, message):
    async with Client(build_server(plain.config, state=plain)) as client:
        with pytest.raises(MCPError) as caught:
            await client.get_prompt(name, arguments)
    assert message in caught.value.error.message


async def test_explain_entry_requires_an_id(plain):
    async with Client(build_server(plain.config, state=plain)) as client:
        with pytest.raises(MCPError):
            await client.get_prompt("explain_entry", {})

