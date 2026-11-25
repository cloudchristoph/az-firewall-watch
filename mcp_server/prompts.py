"""Prompts: three ready-made investigations that tell the agent which tools to call, and in what order.

The texts name the tools instead of describing the data, so the agent works
from the live answers and not from what the prompt guesses.
"""
from __future__ import annotations

import time

from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from .filters import parse_time

DEFAULT_SINCE = "15m"


# The SDK hides the text of an ordinary exception raised by a prompt behind
# "Internal server error"; an MCPError is passed to the client unchanged, so a
# wrong argument is reported this way and the caller can correct it.
def _bad_argument(message: str) -> MCPError:
    return MCPError(code=INVALID_PARAMS, message=message)


def _check_since(since: str) -> str:
    text = (since or "").strip() or DEFAULT_SINCE
    try:
        parse_time(text, now=time.time(), name="since")
    except ValueError as exc:
        raise _bad_argument(str(exc)) from exc
    return text


def investigate_denies_text(since: str) -> str:
    return f"""\
Investigate what the Azure Firewall has been denying over the last {since}. Use the az-firewall-watch tools; do not \
guess at traffic you have not looked up.

1. Call summarize_logs with since="{since}". Read denies, top_denied_destinations, top_sources, top_rules, \
top_dst_ports, denied_without_rule and the timeline. If window.buffer_oldest_in_window is true, say that the buffer \
does not reach back to the start of the window and that the numbers cover less than {since}.
2. Group the denies by destination and by deciding rule. Name the default-action denies separately: \
denied_without_rule counts flows that no rule allowed or denied, they fell through to the implicit Deny. List its top \
flows with source, destination, port and protocol.
3. For the largest groups, call query_logs with action="deny" and the destination or source as filter, then \
explain_log_entry on one representative row each. Quote the verdict, the matched_rule (or that none matched) and the \
nearest_misses with the failing criterion.
4. For traffic that looks legitimate, propose the narrowest rule that would allow it: the exact source (an IP group \
or the smallest CIDR; use lookup_address to see which IP groups and rules already cover the source), the destination \
as an FQDN where possible (an application rule for HTTP, HTTPS or MSSQL, otherwise a network rule), one port and \
one protocol. Check the proposal with trace_flow: it must come out as deny today, and say which existing rule or \
collection the new rule would have to sit before. Do not propose anything broader than the denied flows need.
5. Flag anything that looks like scanning or abuse: one source hitting many destinations or many ports, sequential \
ports, denies to administrative ports (22, 23, 135, 445, 3389) from unexpected sources, a burst in the timeline.
6. Finish with a short list: what is blocked on purpose, what should probably be allowed (with the rule you propose), \
what to watch. State what you could not determine, for example an unavailable policy context or criteria reported \
as unknown.
"""


def explain_entry_text(row_id: int) -> str:
    return f"""\
Explain log row {row_id} of the Azure Firewall in plain words.

1. Call explain_log_entry with id={row_id}. If it fails because the id is gone, say so and stop: the buffer drops \
old rows.
2. Say what happened: source, destination, port and protocol, and whether the traffic was allowed, denied or \
translated (verdict).
3. Name the criterion that decided it. With a matched_rule: its ref, priorities and action, and that evaluation \
stopped there. Without one: the default action applied, and explain why the nearest_misses did not match by quoting \
each failing criterion (observed against expected).
4. If the answer says traceable is false, available is false or the note says the rule is not in the loaded policy, \
report that instead of guessing, and say what would fix it (refresh_policy_context, a loaded policy context).
5. If any rule in the trace is unknown, say which criterion could not be evaluated locally (service tag, FQDN tag, \
web category, unreadable IP group) and that the real firewall may have decided differently.
6. Close with one sentence on what to change if this outcome is not what was intended. Use trace_flow to check a \
proposed change against the current policy before you suggest it.
"""


FIREWALL_HEALTH_CHECK_TEXT = """\
Check the health of the Azure Firewall and of the log pipeline that feeds this server.

1. Call get_status. Report the Event Hub connection state, last_error, how old the newest event is \
(last_event_age_s), the received and skipped counts, and the buffer size against its capacity. A stream that is not \
connected, or a newest event older than a few minutes on a busy firewall, comes first.
2. Call get_log_coverage. Report forwarded, observed, forwarded_not_seen and seen_not_forwarded, and repeat its hints. \
Name every category that is missing and what it would cost to be blind to it.
3. Call get_firewall and get_policy. Summarise the SKU, the policy and its parents, threat intelligence mode, DNS \
proxy, IDPS mode and TLS inspection, and the number of rule groups and rules. If the policy context is not available, \
say why and continue with what you have.
4. Look for these specific problems and report each one found, with the evidence from the tools: SNAT auto-learn \
enabled without a route server; a fixed capacity where autoscale is expected (or the other way round); maintenance \
windows that have expired; a diagnostic setting that does not target the connected hub; DNS proxy off while DnsQuery \
is forwarded; fat flow logging off while FatFlow is forwarded; a policy context that is old or failed to refresh.
5. Call summarize_logs for the last 15 minutes and mention a clear anomaly (a spike in denies, a single source \
dominating), without investigating it further.
6. Finish with a verdict (healthy, degraded, blind) and an ordered list of fixes, most urgent first.
"""


def register(server: MCPServer) -> None:
    @server.prompt(
        name="investigate_denies",
        title="Investigate denied traffic",
        description="Summarise what the firewall denied, group it by destination and rule, name default-action "
                    "denies, propose the narrowest rule for legitimate traffic and flag scanning.")
    def investigate_denies(since: str = DEFAULT_SINCE) -> str:
        return investigate_denies_text(_check_since(since))

    @server.prompt(
        name="explain_entry",
        title="Explain one log row",
        description="Explain a buffered log row in plain words from explain_log_entry and name the criterion "
                    "that decided it.")
    def explain_entry(id: str) -> str:
        try:
            row_id = int(str(id).strip())
        except ValueError:
            raise _bad_argument(f"id must be the numeric row id from query_logs, got {id!r}.") from None
        return explain_entry_text(row_id)

    @server.prompt(
        name="firewall_health_check",
        title="Firewall and log pipeline health check",
        description="Check the stream, the log coverage and the policy summary; report connection state, missing "
                    "categories, auto-learn without a route server, fixed capacity and expired maintenance windows.")
    def firewall_health_check() -> str:
        return FIREWALL_HEALTH_CHECK_TEXT


__all__ = ["register", "investigate_denies_text", "explain_entry_text", "FIREWALL_HEALTH_CHECK_TEXT"]
