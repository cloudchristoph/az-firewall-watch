"""Builds the MCP server object and its lifespan."""
from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import Any

from mcp.server.mcpserver import MCPServer

from viewer.config import VERSION

from . import SERVER_NAME, prompts, resources, tools_analysis, tools_logs, tools_policy
from .config import ServerConfig
from .context import ContextHolder
from .state import AppState

log = logging.getLogger(__name__)

# The TUI checks the cache age once a minute; the server does the same.
CACHE_CHECK_INTERVAL_S = 60.0

INSTRUCTIONS = """\
az-firewall-watch streams one Azure Firewall's diagnostic logs from Event Hub into memory and, with the policy \
context from Azure Resource Manager, explains them. Everything is read-only against Azure.
Start with get_status: it says whether the stream is connected, how many rows are buffered and whether the policy \
context (firewall, policy, IP groups) is loaded.
Logs: query_logs searches the buffer (category, action, addresses incl. CIDR and IPv6, ports, rule path, time \
window; page with after_id / before_id), tail_logs waits for new rows, get_log_entry returns one row with enrichment, \
summarize_logs aggregates a time window (top sources, destinations, rules, denies, timeline).
Decisions: explain_log_entry traces one logged row through the policy and names the rule and criterion that decided \
it; trace_flow does the same for a flow you describe; lookup_address says which IP groups, rules and recent rows \
an address appears in.
Policy context: get_firewall, get_policy, list_rules (filter by kind, group, action, address, FQDN, port, IP group), \
get_rule, list_ip_groups, get_ip_group, get_log_coverage (which categories the diagnostic settings forward versus \
what arrives), refresh_policy_context.
Rows only exist from the moment the server started (or from EVENT_HUB_START_POSITION); older traffic is not here. \
Row ids are the server's own counter and stay valid for its lifetime.\
"""


async def _watch_cache_age(context: ContextHolder) -> None:
    while True:
        await asyncio.sleep(CACHE_CHECK_INTERVAL_S)
        context.check_cache_age()


def build_server(config: ServerConfig, *, state: AppState | None = None,
                 start_stream: bool | None = None) -> MCPServer[AppState]:
    """The configured server.

    ``state``: use this :class:`AppState` instead of building one (tests seed a
    buffer this way). ``start_stream``: start the Event Hub worker and the policy
    context in the lifespan; defaults to ``True`` without ``state`` and to
    ``False`` with it, so a seeded test server never reaches Azure.
    """
    run_background = (state is None) if start_stream is None else start_stream

    @contextlib.asynccontextmanager
    async def lifespan(_server: MCPServer[AppState]) -> AsyncIterator[AppState]:
        app_state = state if state is not None else AppState.create(config)
        watcher: asyncio.Task[Any] | None = None
        if run_background:
            app_state.stream.start()
            app_state.context.start()
            watcher = asyncio.create_task(_watch_cache_age(app_state.context), name="azfw-cache-age")
        try:
            yield app_state
        finally:
            if watcher is not None:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
            if run_background:
                await app_state.stream.stop()
                await app_state.context.aclose()

    server: MCPServer[AppState] = MCPServer(
        name=SERVER_NAME,
        title="Azure Firewall log watch",
        instructions=INSTRUCTIONS,
        version=VERSION,
        lifespan=lifespan,
        log_level=config.log_level,  # type: ignore[arg-type]  # validated in ServerConfig
    )
    for module in (tools_logs, tools_policy, tools_analysis, resources, prompts):
        module.register(server)
    return server


__all__ = ["build_server", "INSTRUCTIONS"]
