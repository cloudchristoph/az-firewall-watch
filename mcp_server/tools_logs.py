"""Stream and log tools: status, query, long-poll tail, single entry, clear.

Every tool reads the shared :class:`~mcp_server.state.AppState` through
``get_state(ctx)``. Caller mistakes are raised as ``ToolError``: the SDK hides
the text of any other exception from the client, and a model can only correct
a call when it reads what was wrong.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, TypeVar

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from viewer.config import VERSION
from viewer.enrichment import enrich_row
from viewer.trace import no_decision_reason

from .buffer import BufferedRow
from .filters import LogFilter
from .serialize import check_detail, row_to_dict, status_to_dict, with_replay_note
from .state import AppState, get_state

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
DEFAULT_TAIL_TIMEOUT_S = 20
MAX_TAIL_TIMEOUT_S = 60

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
# tail_logs waits for new rows, so the same call can answer differently; still read-only.
READ_ONLY_LIVE = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=False,
                                 open_world_hint=False)
LOCAL_DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True,
                                    open_world_hint=False)

T = TypeVar("T")

# ── argument types (descriptions end up in the tool's JSON schema) ───────────
CategoryArg = Annotated[str | list[str] | None, Field(
    description="Category name or list of names (NetworkRule, AppRule, NATRule, DnsQuery, DnsFailure, IDPS, "
                "ThreatIntel, FlowTrace, FatFlow; case-insensitive substring), or a preset: 'decisions' (rule "
                "hits, ThreatIntel, IDPS), 'traffic' (FlowTrace, FatFlow), 'dns' (DnsQuery, DnsFailure).")]
ActionArg = Annotated[str | None, Field(
    description="Substring of the action, case-insensitive: Allow, Deny, Alert, Drop, DNAT; for DNS rows the "
                "response code (NOERROR, NXDOMAIN).")]
SourceArg = Annotated[str | None, Field(
    description="Source address: a CIDR (10.0.0.0/16, fd10::/16) matches every address inside it; a full "
                "address matches it in any IPv6 spelling; anything else is a substring.")]
DestinationArg = Annotated[str | None, Field(
    description="Destination address or FQDN, same matching as source (CIDR, exact address, else substring). "
                "DNAT rows carry the translated target here.")]
ProtocolArg = Annotated[str | None, Field(
    description="Substring of the protocol, case-insensitive (TCP, UDP, ICMP, HTTPS, ...; for DNS rows the "
                "query type A, AAAA, ...).")]
DstPortArg = Annotated[str | int | None, Field(
    description="Destination port as a substring, like the TUI filter: '443' also matches 4433.")]
SrcPortArg = Annotated[str | int | None, Field(description="Source port as a substring.")]
RuleArg = Annotated[str | None, Field(
    description="Substring of the rule path 'policy » group » collection » rule' (or the action reason when "
                "no rule matched), case-insensitive.")]
TextArg = Annotated[str | None, Field(description="Substring searched in every column of the row, case-insensitive.")]
SinceArg = Annotated[str | None, Field(
    description="Only rows logged at or after this time: relative (30s, 15m, 2h, 1d back from now) or ISO 8601 "
                "(2026-10-15T08:00:00Z). Compared with the log's own timestamp.")]
UntilArg = Annotated[str | None, Field(description="Only rows logged at or before this time; same formats as since.")]
LimitArg = Annotated[int, Field(description=f"Maximum rows returned, clamped to 1..{MAX_LIMIT}.")]
DetailArg = Annotated[str, Field(
    description="Row shape: 'summary' (id, time, category, protocol, source, src_port, destination, dst_port, "
                "action, rule, info), 'full' (adds rule parts, NAT target, proxy/TLS flags, resource id, "
                "received_at), 'raw' (adds the diagnostic record as received).")]


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _call(fn: Callable[[], T]) -> T:
    """Run ``fn`` and turn a caller mistake (``ValueError``) into a readable tool error."""
    try:
        return fn()
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def _buffer_bounds(state: AppState) -> dict[str, Any]:
    buf = state.buffer
    return {"size": buf.size, "capacity": buf.capacity, "first_id": buf.first_id, "last_id": buf.last_id or None}


def _trace_reason(state: AppState, item: BufferedRow) -> str | None:
    """Why no evaluation trace can be built for this row, ``None`` when one can."""
    why = no_decision_reason(item.row.category)
    if why is not None:
        return why
    snap = state.context.snapshot
    if snap is None:
        return (f"The trace needs the policy context, which is not loaded (state: {state.context.state}). "
                f"{state.context.status()['reason'] or ''}").strip()
    if snap.policy is None:
        return ("The policy context is loaded, but carries no policy: the policy could not be read, "
                "or the firewall uses classic rules.")
    return None


def register(server: MCPServer) -> None:
    @server.tool(
        name="get_status",
        title="Stream and server status",
        description=(
            "Health of the log stream and the server. Answers: is the Event Hub connected (state connecting, "
            "verifying, connected, reconnecting, failed, stopped; last_error), how many records arrived "
            "(received, skipped by reason, per_category), how old the newest event is (last_event_age_s in "
            "seconds), whether the stream is still replaying the hub's retention after the start (replaying, "
            "with newest_log_lag_s: how far the newest buffered log is behind now), the buffer bounds (first_id, "
            "last_id, size, capacity), the firewall the logs come from and the policy context state. Call it "
            "first when an answer looks empty."),
        annotations=READ_ONLY,
    )
    async def get_status(ctx: Context[Any, Any]) -> dict[str, Any]:
        return status_to_dict(get_state(ctx), version=VERSION)

    @server.tool(
        name="query_logs",
        title="Query buffered firewall logs",
        description=(
            "Search the firewall log rows held in memory (the newest rows since the server started, up to the "
            "buffer capacity). All filters combine with AND; omitted filters match everything. Returns rows "
            "newest first by default, 'matched' (total before the limit), 'returned', 'has_more' and cursors. "
            "Paging: with order='desc' pass next_before_id as before_id for older rows; with order='asc' pass "
            "next_after_id as after_id. To fetch only rows newer than a previous answer, pass its next_after_id "
            "as after_id. Row ids are stable for the life of the server. While the server is still replaying "
            "the hub's retention after its start, the answer carries a 'note' and the counts are not final yet."),
        annotations=READ_ONLY,
    )
    async def query_logs(
        ctx: Context[Any, Any],
        category: CategoryArg = None,
        action: ActionArg = None,
        source: SourceArg = None,
        destination: DestinationArg = None,
        protocol: ProtocolArg = None,
        dst_port: DstPortArg = None,
        src_port: SrcPortArg = None,
        rule: RuleArg = None,
        text: TextArg = None,
        since: SinceArg = None,
        until: UntilArg = None,
        after_id: Annotated[int | None, Field(description="Only rows with a larger id.")] = None,
        before_id: Annotated[int | None, Field(description="Only rows with a smaller id (page back in desc order).")] = None,
        limit: LimitArg = DEFAULT_LIMIT,
        order: Annotated[str, Field(description="'desc' (newest first, default) or 'asc' (oldest first).")] = "desc",
        detail: DetailArg = "summary",
    ) -> dict[str, Any]:
        state = get_state(ctx)
        flt = _call(lambda: LogFilter.build(
            category=category, action=action, source=source, destination=destination, protocol=protocol,
            dst_port=dst_port, src_port=src_port, rule=rule, text=text, since=since, until=until,
            after_id=after_id, before_id=before_id))
        level = _call(lambda: check_detail(detail))
        direction = (order or "desc").strip().lower()
        if direction not in ("asc", "desc"):
            raise ToolError(f"order must be 'asc' or 'desc', got {order!r}.")
        count = _clamp(limit, 1, MAX_LIMIT)

        matches = [item for item in state.buffer.snapshot() if flt.matches(item)]
        if direction == "desc":
            matches.reverse()
        selected = matches[:count]
        has_more = len(matches) > count
        return with_replay_note(state, {
            "rows": [row_to_dict(item, level) for item in selected],
            "matched": len(matches),
            "returned": len(selected),
            "has_more": has_more,
            "order": direction,
            "first_id": selected[0].id if selected else None,
            "last_id": selected[-1].id if selected else None,
            "next_after_id": selected[-1].id if (direction == "asc" and has_more) else state.buffer.last_id,
            "next_before_id": selected[-1].id if (direction == "desc" and has_more) else None,
            "buffer": _buffer_bounds(state),
            "filter": flt.echo(),
        })

    @server.tool(
        name="tail_logs",
        title="Wait for new firewall logs",
        description=(
            "Long-poll for new rows: returns as soon as at least one row newer than after_id matches the filters, "
            "or after timeout_s seconds with timed_out=true and no rows. Rows come oldest first. Loop by passing "
            "next_after_id back as after_id; without after_id the tail starts at the newest row now (only rows "
            "that arrive after the call). Same filters as query_logs. A 'note' in the answer means the server is "
            "still replaying the hub's retention, so the rows may be old ones being caught up on."),
        annotations=READ_ONLY_LIVE,
    )
    async def tail_logs(
        ctx: Context[Any, Any],
        category: CategoryArg = None,
        action: ActionArg = None,
        source: SourceArg = None,
        destination: DestinationArg = None,
        protocol: ProtocolArg = None,
        dst_port: DstPortArg = None,
        src_port: SrcPortArg = None,
        rule: RuleArg = None,
        text: TextArg = None,
        since: SinceArg = None,
        until: UntilArg = None,
        after_id: Annotated[int | None, Field(
            description="Return rows with a larger id; default: the newest id at the time of the call.")] = None,
        timeout_s: Annotated[float, Field(
            description=f"Seconds to wait for a matching row, clamped to 1..{MAX_TAIL_TIMEOUT_S}.")] = DEFAULT_TAIL_TIMEOUT_S,
        limit: LimitArg = DEFAULT_LIMIT,
        detail: DetailArg = "summary",
    ) -> dict[str, Any]:
        state = get_state(ctx)
        flt = _call(lambda: LogFilter.build(
            category=category, action=action, source=source, destination=destination, protocol=protocol,
            dst_port=dst_port, src_port=src_port, rule=rule, text=text, since=since, until=until))
        level = _call(lambda: check_detail(detail))
        count = _clamp(limit, 1, MAX_LIMIT)
        wait_s = max(1.0, min(float(MAX_TAIL_TIMEOUT_S), float(timeout_s)))
        cursor = state.buffer.last_id if after_id is None else after_id
        rows = await state.buffer.wait_for(cursor, wait_s, predicate=flt.matches, limit=count)
        # A full page may leave matches behind: continue right after it. Otherwise
        # everything up to the newest row has been looked at.
        next_after = rows[-1].id if len(rows) >= count else max(cursor, state.buffer.last_id)
        return with_replay_note(state, {
            "rows": [row_to_dict(item, level) for item in rows],
            "returned": len(rows),
            "timed_out": not rows,
            "next_after_id": next_after,
            "buffer": _buffer_bounds(state),
            "filter": flt.echo(),
        })

    @server.tool(
        name="get_log_entry",
        title="One log row with enrichment",
        description=(
            "One buffered row by id at 'raw' detail (every field plus the diagnostic record as received), with "
            "'enrichment' from the policy context: source_fw_instance / dest_fw_instance (AzFw.<n> when the address "
            "is a firewall instance), source_ip_groups / dest_ip_groups, rule_priority, rule_action and "
            "rule_policy for inherited rules. enrichment is null while the policy context is not loaded. "
            "'traceable' says whether an evaluation trace can be built and 'trace_unavailable_reason' why not."),
        annotations=READ_ONLY,
    )
    async def get_log_entry(
        ctx: Context[Any, Any],
        id: Annotated[int, Field(description="Row id from query_logs or tail_logs.")],
    ) -> dict[str, Any]:
        state = get_state(ctx)
        item = state.buffer.get(id)
        if item is None:
            buf = state.buffer
            bounds = (f"ids {buf.first_id} to {buf.last_id} are buffered" if buf.first_id is not None
                      else "the buffer is empty")
            raise ToolError(f"No row with id {id}: {bounds}. Older rows are dropped when the buffer is full "
                            "or after clear_logs.")
        snap = state.context.snapshot
        enrichment = None
        if snap is not None:
            enrichment = enrich_row(item.row, subnet_cidrs=snap.subnet_cidrs, ip_groups=snap.ip_groups,
                                    policy=snap.policy)
        reason = _trace_reason(state, item)
        return {
            **row_to_dict(item, "raw"),
            "enrichment": enrichment,
            "traceable": reason is None,
            "trace_unavailable_reason": reason,
            "policy_context": state.context.status(),
        }

    @server.tool(
        name="clear_logs",
        title="Clear the log buffer",
        description=(
            "Drop every row from this server's in-memory buffer. Touches nothing in Azure and affects no other "
            "client of the Event Hub. Row ids keep counting, so cursors stay valid. Returns 'cleared' (rows dropped)."),
        annotations=LOCAL_DESTRUCTIVE,
    )
    async def clear_logs(ctx: Context[Any, Any]) -> dict[str, Any]:
        state = get_state(ctx)
        cleared = state.buffer.clear()
        return {"cleared": cleared, "next_after_id": state.buffer.last_id}


__all__ = ["register"]
