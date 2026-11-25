"""Optional live test of the MCP server against a real Event Hub and firewall.

Skipped unless AZFW_LIVE_EVENTHUB_NAMESPACE and AZFW_LIVE_EVENTHUB_NAME are set.
Run it explicitly, e.g.::

    AZFW_LIVE_FIREWALL_ID=/subscriptions/.../azureFirewalls/fw-hub \\
    AZFW_LIVE_EVENTHUB_NAMESPACE=my-ns.servicebus.windows.net \\
    AZFW_LIVE_EVENTHUB_NAME=firewall-logs \\
    pytest tests/live/test_live_mcp.py -m live

The server is started in memory with the settings from these variables only (no
``.env``, no SAS string) and reads with the same identity as the viewer:
``DefaultAzureCredential``, Reader on the firewall and its policy, and Azure Event
Hubs Data Receiver on the hub. Only read operations are made. The metadata cache
is redirected to a temporary directory.

Set AZFW_LIVE_CONSUMER_GROUP when another reader already uses ``$Default``. The
viewer and this server must not share a consumer group, or each sees only part
of the stream.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from typing import Any

import pytest
from mcp.client.client import Client

from mcp_server.config import ServerConfig
from mcp_server.server import build_server

pytestmark = pytest.mark.live

FIREWALL_ID = os.environ.get("AZFW_LIVE_FIREWALL_ID", "")
EH_NAMESPACE = os.environ.get("AZFW_LIVE_EVENTHUB_NAMESPACE", "")
EH_NAME = os.environ.get("AZFW_LIVE_EVENTHUB_NAME", "")
CONSUMER_GROUP = os.environ.get("AZFW_LIVE_CONSUMER_GROUP", "")

needs_eventhub = pytest.mark.skipif(
    not (EH_NAMESPACE and EH_NAME), reason="set AZFW_LIVE_EVENTHUB_NAMESPACE and AZFW_LIVE_EVENTHUB_NAME to run",
)

CONNECT_TIMEOUT_S = 90
CONTEXT_TIMEOUT_S = 120
TAIL_TIMEOUT_S = 60
POLL_INTERVAL_S = 2.0


@pytest.fixture
def private_cache(tmp_path, monkeypatch):
    """Never touch the developer's real ~/.az-firewall-watch/cache.json."""
    import viewer.cache as cache

    monkeypatch.setattr(cache, "cache_path", lambda: tmp_path / "cache.json")
    return tmp_path / "cache.json"


def _live_environ() -> dict[str, str]:
    """The server's settings, built from the live variables only."""
    environ = {
        "EVENT_HUB_NAMESPACE": EH_NAMESPACE,
        "EVENT_HUB_NAME": EH_NAME,
        "EVENT_HUB_START_POSITION": "earliest",
    }
    if CONSUMER_GROUP:
        environ["EVENT_HUB_CONSUMER_GROUP"] = CONSUMER_GROUP
    if FIREWALL_ID:
        environ["AZFW_FIREWALL_ID"] = FIREWALL_ID
    return environ


async def _tool(client: Client, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call a tool through the protocol and return its structured answer."""
    result = await client.call_tool(name, args or {})
    assert not result.is_error, result.content
    assert result.structured_content is not None, f"{name} returned no structured content"
    return result.structured_content


async def _wait_for_status(client: Client, done: Callable[[dict[str, Any]], bool], timeout_s: float,
                           what: str) -> dict[str, Any]:
    """Poll get_status until ``done`` accepts it; stop early when the stream has given up."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = await _tool(client, "get_status")
        if status["event_hub"]["state"] == "failed":
            pytest.fail(f"The Event Hub stream failed: {status['event_hub']['last_error']}")
        if done(status):
            return status
        if time.monotonic() >= deadline:
            pytest.fail(f"{what} was not reached within {timeout_s:.0f} s; last status: {status}")
        await asyncio.sleep(POLL_INTERVAL_S)


@needs_eventhub
async def test_mcp_server_streams_firewall_logs_and_explains_them(private_cache):
    """One server, one client session: the stream, the policy context and the analysis tools agree with Azure."""
    server = build_server(ServerConfig.from_env(_live_environ(), []))
    # Every Client(server) block starts its own lifespan and stream, so the whole test stays in one block.
    async with Client(server) as client:
        status = await _wait_for_status(
            client, lambda s: s["event_hub"]["state"] == "connected", CONNECT_TIMEOUT_S,
            "the Event Hub connection")
        assert status["event_hub"]["auth"] == "entra"

        tail = await _tool(client, "tail_logs", {"after_id": 0, "timeout_s": TAIL_TIMEOUT_S})
        assert tail["returned"] > 0 and tail["rows"], \
            f"no firewall rows arrived within {TAIL_TIMEOUT_S} s: is the diagnostic setting active?"

        if FIREWALL_ID:
            await _wait_for_status(
                client, lambda s: s["policy_context"]["state"] == "loaded", CONTEXT_TIMEOUT_S,
                "the policy context")
            firewall = await _tool(client, "get_firewall")
            expected = FIREWALL_ID.rstrip("/").rsplit("/", 1)[-1]
            assert firewall["name"].lower() == expected.lower(), firewall["name"]

        # A real deny, if the hub has seen one; the trace needs the policy context.
        denies = await _tool(client, "query_logs", {"action": "Deny", "limit": 1})
        if denies["rows"]:
            await _wait_for_status(
                client, lambda s: s["policy_context"]["state"] == "loaded", CONTEXT_TIMEOUT_S,
                "the policy context")
            explained = await _tool(client, "explain_log_entry", {"id": denies["rows"][0]["id"]})
            assert "trace" in explained, sorted(explained)

        coverage = await _tool(client, "get_log_coverage")
        assert "forwarded" in coverage and "observed" in coverage, sorted(coverage)
