"""Resources: read-only views for clients that attach context instead of calling tools.

Every resource is the answer of one tool, so a client sees the same thing
either way and there is a single place where a shape is defined:

====================  ================================================
URI                   Tool answer
====================  ================================================
azfw://status         ``get_status``
azfw://firewall       ``get_firewall``
azfw://policy         ``get_policy`` (summary)
azfw://policy/rules   ``list_rules`` without a filter
azfw://ip-groups      ``list_ip_groups``
azfw://logs/recent    ``query_logs`` with the newest 100 rows
azfw://logs/{id}      ``get_log_entry``
====================  ================================================

The SDK refuses a request context for a resource without URI variables, and
the tools need one to reach the shared state. :func:`register` therefore wraps
the server's ``read_resource`` once: it parks the request's context in a
context variable for the duration of the read, and the handlers pick it up
from there. The template resource ``azfw://logs/{id}`` gets its context the
normal way.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from contextvars import ContextVar
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp.types import TextContent

JSON = "application/json"
RECENT_ROWS = 100

# The request context of the resource being read; set by the wrapper in register().
_REQUEST: ContextVar[Context[Any, Any] | None] = ContextVar("azfw_resource_request", default=None)


_TOOL_PREFIX_RE = re.compile(r"^Error executing tool \S+: ")


def _text_of(content: Iterable[Any]) -> str:
    return " ".join(part.text for part in content if isinstance(part, TextContent)).strip()


def _render(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


async def _answer(server: MCPServer, tool: str, arguments: dict[str, Any], ctx: Context[Any, Any] | None) -> str:
    """The structured answer of ``tool`` as JSON text; a failed tool becomes a resource error."""
    if ctx is None:
        raise ResourceError("This resource can only be read through a request.")
    try:
        result = await server.call_tool(tool, arguments, ctx)
    except ToolError as exc:
        # The SDK prefixes the tool's own sentence; a resource reader has no use for the tool name.
        raise ResourceError(_TOOL_PREFIX_RE.sub("", str(exc))) from exc
    # ``call_tool`` converts the tool's dict into a CallToolResult; an
    # InputRequiredResult has no meaning for a read-only view.
    structured = getattr(result, "structured_content", None)
    if getattr(result, "is_error", False):
        raise ResourceError(_text_of(getattr(result, "content", ())) or f"{tool} failed.")
    if structured is None:
        raise ResourceError(f"{tool} returned no structured answer.")
    return _render(structured)


def register(server: MCPServer) -> None:
    original = server.read_resource

    async def read_resource(uri: Any, context: Context[Any, Any] | None = None) -> Any:
        token = _REQUEST.set(context)
        try:
            return await original(uri, context)
        finally:
            _REQUEST.reset(token)

    server.read_resource = read_resource  # type: ignore[method-assign]

    @server.resource(
        "azfw://status", name="status", title="Stream and server status", mime_type=JSON,
        description="Connection state of the Event Hub, counters, buffer bounds, firewall and policy context state "
                    "(the get_status tool).")
    async def status() -> str:
        return await _answer(server, "get_status", {}, _REQUEST.get())

    @server.resource(
        "azfw://firewall", name="firewall", title="The firewall", mime_type=JSON,
        description="The firewall from the policy context: SKU, subnets, public IPs, diagnostic settings "
                    "(the get_firewall tool). available=false while the context is not loaded.")
    async def firewall() -> str:
        return await _answer(server, "get_firewall", {}, _REQUEST.get())

    @server.resource(
        "azfw://policy", name="policy", title="The firewall policy (summary)", mime_type=JSON,
        description="Policy settings, parent chain and rule groups without the rules "
                    "(the get_policy tool). available=false while the context is not loaded.")
    async def policy() -> str:
        return await _answer(server, "get_policy", {}, _REQUEST.get())

    @server.resource(
        "azfw://policy/rules", name="policy-rules", title="Policy rules in evaluation order", mime_type=JSON,
        description="Every rule in evaluation order with its ref, priorities and action "
                    "(the list_rules tool without a filter).")
    async def policy_rules() -> str:
        return await _answer(server, "list_rules", {}, _REQUEST.get())

    @server.resource(
        "azfw://ip-groups", name="ip-groups", title="IP groups", mime_type=JSON,
        description="The IP groups the policy references (the list_ip_groups tool).")
    async def ip_groups() -> str:
        return await _answer(server, "list_ip_groups", {}, _REQUEST.get())

    @server.resource(
        "azfw://logs/recent", name="recent-logs", title="Newest 100 log rows", mime_type=JSON,
        description=f"The newest {RECENT_ROWS} buffered rows at summary detail, newest first "
                    "(the query_logs tool without filters).")
    async def recent_logs() -> str:
        return await _answer(server, "query_logs", {"limit": RECENT_ROWS}, _REQUEST.get())

    @server.resource(
        "azfw://logs/{id}", name="log-entry", title="One log row", mime_type=JSON,
        description="One buffered row by id at raw detail with its enrichment and whether it can be traced "
                    "(the get_log_entry tool). Ids come from azfw://logs/recent or the log tools.")
    async def log_entry(id: str, ctx: Context[Any, Any]) -> str:
        try:
            row_id = int(id)
        except ValueError:
            raise ResourceError(f"The row id must be a whole number, got {id!r}.") from None
        return await _answer(server, "get_log_entry", {"id": row_id}, ctx)


__all__ = ["register"]
