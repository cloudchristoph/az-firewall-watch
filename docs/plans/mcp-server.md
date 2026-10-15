# MCP server: plan

An MCP (Model Context Protocol) server that runs az-firewall-watch headless,
streams the firewall's logs into a ring buffer and lets an AI agent query the
live log stream, the policy context and the evaluation trace through typed
tools. Same `.env`, same parser, same ARM fetchers, same cache as the TUI.
Everything the server does is read-only against Azure.

Status: planned 2026-10-15, implementation on branch
`cc/mcp-azure-firewall-server-238903`. This page is the design; it is folded
into the changelog and `docs/mcp-server.md` once the feature ships.

## Goals

- An agent (Claude Desktop, Claude Code, any MCP client) connects to one local
  process and can answer questions such as *what is being denied right now*,
  *why did this flow get denied*, *would 10.1.2.3 reach example.com:443*,
  *which rules mention this address*, *are FatFlow logs even being forwarded*.
- No second configuration: the server reads the same `.env` the wizard writes
  and uses the same cache file as the TUI.
- Nothing new on the Azure side: Reader plus Data Receiver, exactly like the
  viewer. The server never calls an ARM action, never returns a SAS string or
  a header value.
- The TUI stays untouched in behaviour. Shared logic moves into TUI-free
  modules; the app keeps thin wrappers so the existing tests keep passing.

## Non-goals

- Writing to the firewall or the policy. Not in this feature, and the tool
  annotations say so (`readOnlyHint`).
- Multi-firewall. One server process serves one Event Hub, like one TUI
  session does.
- Remote exposure. The default transport is stdio; the optional streamable
  HTTP transport binds to `127.0.0.1` and has no authentication, so it is
  documented as local-only.
- Pause/resume of the stream. An agent filters by time instead.

## Architecture

```text
.env ──► mcp_server.config ──► lifespan
                                 ├── StreamWorker  (Event Hub → fw_parser → LogBuffer)
                                 ├── ContextHolder (firewall id → viewer.management.load_management_data)
                                 └── MCPServer (mcp 2.x): tools · resources · prompts
                                        stdio (default) │ streamable-http 127.0.0.1
```

### New package `mcp_server/`

| Module | Responsibility |
| --- | --- |
| `__main__.py`, `cli.py` | `python -m mcp_server [--transport stdio\|http] [--host] [--port] [--env-file] [--no-policy-context] [--firewall-id]`; `main.py --mcp` delegates here, so the frozen binary can be an MCP server too |
| `config.py` | `ServerConfig` from environment and argv: Event Hub settings (reused keys), `POLICY_CONTEXT`, `AZFW_FIREWALL_ID`, `AZFW_MCP_BUFFER_SIZE` (default 20000), `AZFW_MCP_TRANSPORT`, `AZFW_MCP_HOST`, `AZFW_MCP_PORT`, `AZFW_MCP_LOG_LEVEL` |
| `buffer.py` | `LogBuffer`: bounded deque of `BufferedRow(row: FirewallDataRow, raw: dict, received_at: float, time_epoch: float \| None)`, id cursor (`row.rowid`, monotonic), counters (received, skipped by reason, per category), last event time, `wait_for(after_id, timeout)` via `asyncio.Condition` |
| `filters.py` | `LogFilter` dataclass and `parse_window(since, until)`: the TUI's filter semantics (`helpers.address_matches` for CIDR/substring/IPv6 spelling, `CATEGORY_GROUPS` presets, substring on action/protocol/port) plus `src_port`, `rule` (substring on the rule path), `text` (any column), `since`/`until` (ISO 8601 or relative `30s`, `15m`, `2h`, `1d`), `after_id` |
| `stream.py` | `StreamWorker`: connect (SAS or Entra ID), probe, verify data-plane role, receive, reconnect with the TUI's backoff tables, count skips, detect the firewall id from the first record and hand it to the context holder. Reports `state` (`connecting`, `verifying`, `connected`, `reconnecting`, `failed`, `stopped`) and `last_error` |
| `context.py` | `ContextHolder`: wraps `viewer.management.load_management_data`; state `off`, `waiting_for_firewall_id`, `loading`, `loaded`, `unavailable` with reason, age, `refresh(force)`, one automatic refresh when a logged rule is missing from the loaded policy and the snapshot is older than 60 s (mirrors the TUI) |
| `serialize.py` | Dataclass → JSON-friendly dicts: rows at three detail levels (`summary`, `full`, `raw`), firewall, policy (summary and full), rule with path and priorities, IP group, trace (passes → collections → rules → checks), status. Header *values* of inserting rules are never serialised, only names |
| `state.py` | `AppState(config, buffer, stream, context)` held in the lifespan context |
| `server.py` | builds the `MCPServer`, lifespan, registers the modules below |
| `tools_logs.py` | stream and log tools |
| `tools_policy.py` | policy-context tools |
| `tools_analysis.py` | summaries, address lookup, trace tools |
| `resources.py`, `prompts.py` | resources and prompts |

### Extractions from the TUI (behaviour-preserving)

- `viewer/eventhub.py` (new): `build_consumer_client(env) -> ConsumerHandle`
  (client, credential, display namespace, display hub, `use_entra`),
  `resolve_start_position`, `verify_data_plane_access`, `is_configuration_error(exc)`,
  the backoff tables. `viewer/streaming.py` imports these names back
  (`resolve_start_position`, `_verify_data_plane_access`, `_AUTH_KEYWORDS`,
  `_BACKOFF`, `_RECONNECT_BACKOFF` stay importable from `viewer.streaming`;
  `tests/test_streaming.py` monkeypatches `streaming._BACKOFF`, so the names
  the loop reads must be the module globals of `streaming`).
- `viewer/trace.py`: `flow_from_row(row)` and `logged_from_row(row)` move here
  from `FirewallLogApp._flow_from_row` / `_logged_from_row`; the app's static
  methods become one-line wrappers.
- `viewer/enrichment.py`: `enrich_row(row, snapshot) -> dict` carries the body
  of `FirewallLogApp._compute_enrichment` so the MCP server and the dialog
  compute the same thing.
- `mcp_server` must never import `textual` or `dialogs`. A test imports the
  package in a subprocess and asserts `textual` is absent from `sys.modules`.

### Lifespan

1. Load `.env` (unless `--env-file` points elsewhere), build `ServerConfig`.
   Missing Event Hub credentials: exit code 2 with a message on stderr that
   names the TUI wizard (`./az-firewall-watch` or `--reconfigure`). The MCP
   server never runs the wizard.
2. Start `StreamWorker` as a task. Start `ContextHolder`; if
   `AZFW_FIREWALL_ID` is set it loads immediately, otherwise it waits for the
   first record's `resourceId`.
3. Yield `AppState`. Tools reach it via `ctx.request_context.lifespan_context`.
4. On shutdown cancel the worker, close the credential.

All logging goes to stderr through `logging`; nothing in the server path may
write to stdout, because stdio is the MCP channel.

## Tools

All tools return structured JSON (dicts). Caller mistakes (unknown id, bad
CIDR, bad time) raise `ValueError` with a sentence that says what was wrong;
the SDK turns that into an `isError` result. Missing policy context is not an
error: the tool returns `{"available": false, "reason": "...", "hint": "..."}`.
Limits are clamped, never rejected (`limit` 1 to 1000, default 100).

Row shapes (`detail`):

- `summary`: `id, time, category, protocol, source, src_port, destination, dst_port, action, rule, info`
- `full`: summary plus `resource_id, policy, rule_collection_group, rule_collection, rule_name, nat_dst_ip, nat_dst_port, explicit_proxy, tls_inspected, received_at`
- `raw`: full plus `raw` (the diagnostic record as received)

### Stream and logs (`tools_logs.py`)

| Tool | Arguments | Returns | Hints |
| --- | --- | --- | --- |
| `get_status` | – | server version; Event Hub `namespace`, `hub`, `consumer_group`, `start_position`, `auth` (`entra`/`sas`), `state`, `last_error`, `connected_since`; events `received`, `skipped` (by reason), `per_category`, `last_event_at`, `last_event_age_s`; buffer `size`, `capacity`, `first_id`, `last_id`; `firewall_id`, `firewall_name`; policy context `state`, `age_s`, `reason` | read-only |
| `query_logs` | `category` (name, list, or preset `decisions`/`traffic`/`dns`), `action`, `source`, `destination`, `protocol`, `dst_port`, `src_port`, `rule`, `text`, `since`, `until`, `after_id`, `limit`, `order` (`desc` default, `asc`), `detail` | `rows`, `matched` (total before limit), `returned`, `first_id`, `last_id`, `next_after_id`, `buffer` bounds, `filter` echo | read-only |
| `tail_logs` | same filter fields, `after_id` (default: current `last_id`), `timeout_s` (1 to 60, default 20), `limit` | `rows` in arrival order, `next_after_id`, `timed_out` | read-only; long-poll, returns as soon as one matching row arrives |
| `get_log_entry` | `id` | the row at `raw` detail plus `enrichment` (`source_fw_instance`, `dest_fw_instance`, `source_ip_groups`, `dest_ip_groups`, `rule_priority`, `rule_action`, `rule_policy`) and `traceable` with the reason when not | read-only |
| `clear_logs` | – | `cleared` count | destructive (local buffer only) |

### Analysis (`tools_analysis.py`)

| Tool | Arguments | Returns | Hints |
| --- | --- | --- | --- |
| `summarize_logs` | filter fields, `since` (default `15m`), `top` (default 10), `bucket` (`1m` default, `10s` to `1h`) | `window` (from, to, rows), `by_category`, `by_action`, `top_sources`, `top_destinations`, `top_rules`, `top_denied_destinations`, `top_dst_ports`, `denied_without_rule` (default-action denies), `timeline` (bucket → count, denies) | read-only |
| `explain_log_entry` | `id`, `full_tree` (default false) | the row, `outcome` sentence, `matched_rule` with path and priorities, `nearest_misses` (up to 3 with the failing criterion), `trace` (passes → collections → rules → checks with `match`/`miss`/`unknown`/`n/a`; folded by default like the dialog) | read-only |
| `trace_flow` | `protocol`, `source`, `destination` (ip or fqdn), `dst_port`, `explicit_proxy`, `tls_inspected` | same trace shape for a hypothetical flow; `verdict` (`allow`/`deny`/`dnat`/`unknown`) with the caveat that service tags, FQDN tags, web categories and unreadable IP groups are `unknown` | read-only |
| `lookup_address` | `address` (ip or CIDR) | `fw_instance` label when inside a firewall subnet, `ip_groups` containing it, `rules` whose source or destination cover it (path, kind, action), `recent` log counts as source and destination over the last 15 minutes | read-only |
| `get_log_coverage` | – | per diagnostic setting: target and categories; for the connected hub: `forwarded` categories, `observed` categories with counts, `forwarded_not_seen`, `seen_not_forwarded`; switches from `additionalProperties` that explain gaps (fat flow logging, DNS flow trace) | read-only |

### Policy context (`tools_policy.py`)

| Tool | Arguments | Returns | Hints |
| --- | --- | --- | --- |
| `get_firewall` | – | `FirewallInfo` plus subnets with CIDRs, NAT gateways, public IPs, maintenance windows, diagnostic settings, autoscale state, route server, additional properties, tags, `cache_age_s` | read-only |
| `get_policy` | `include_rules` (default false) | name, tier, threat intel mode and allow lists, DNS proxy and servers, IDPS mode and counts, TLS CA, SNAT ranges and auto-learn, explicit proxy ports (PAC URL without query), parent chain, groups with priority, collection count and rule count; with `include_rules` the full tree | read-only |
| `list_rules` | `kind` (`dnat`/`network`/`application`), `group`, `collection`, `action`, `name`, `address` (ip or CIDR the rule's addresses or IP groups cover), `fqdn`, `port`, `ip_group`, `limit`, `offset` | rules in evaluation order with `ref` (`policy » group » collection » rule`), priorities, action, protocols, sources, destinations, ports; `total` | read-only |
| `get_rule` | `ref` or (`group`, `collection`, `rule`) | the full rule: addresses, IP groups resolved to names, FQDNs, ports, protocols, FQDN tags, web categories, target URLs, translated target, `terminate_tls`, `http_headers` (names only), where inserted headers land (the TUI's sentence) | read-only |
| `list_ip_groups` | `name` | id, name, location, address count, `used_by` rule count | read-only |
| `get_ip_group` | `name` or `id` | addresses, referencing rules by `ref` | read-only |
| `refresh_policy_context` | – | the new context state and `fetched_at`; forces an ARM fetch and rewrites the shared cache | idempotent |

### Resources

Read-only views for clients that attach context instead of calling tools:

| URI | Content |
| --- | --- |
| `azfw://status` | `get_status` |
| `azfw://firewall` | `get_firewall` |
| `azfw://policy` | `get_policy` summary |
| `azfw://policy/rules` | `list_rules` without filter |
| `azfw://ip-groups` | `list_ip_groups` |
| `azfw://logs/recent` | the newest 100 rows, `summary` detail |
| `azfw://logs/{id}` | template: `get_log_entry` |

### Prompts

| Prompt | Arguments | Text |
| --- | --- | --- |
| `investigate_denies` | `since` (default `15m`) | summarise denies, group by destination and rule, name default-action denies, propose the narrowest rule that would allow legitimate traffic, flag anything that looks like scanning |
| `explain_entry` | `id` | explain the row in plain words from `explain_log_entry`, name the criterion that decided it |
| `firewall_health_check` | – | status, coverage, policy summary; report connection state, missing categories, auto-learn without route server, fixed capacity, expired maintenance windows |

## Configuration

Reused as-is: `EVENT_HUB_CONNECTION_STRING`, `EVENT_HUB_NAMESPACE`,
`EVENT_HUB_NAME`, `EVENT_HUB_CONSUMER_GROUP`, `EVENT_HUB_START_POSITION`,
`POLICY_CONTEXT`.

New:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AZFW_FIREWALL_ID` | – | Load the policy context at start instead of waiting for the first record |
| `AZFW_MCP_BUFFER_SIZE` | `20000` | Rows kept in memory |
| `AZFW_MCP_TRANSPORT` | `stdio` | `stdio` or `http` (streamable HTTP) |
| `AZFW_MCP_HOST` / `AZFW_MCP_PORT` | `127.0.0.1` / `8765` | HTTP transport only |
| `AZFW_MCP_LOG_LEVEL` | `INFO` | stderr log level |

Consumer group: a second reader on `$Default` next to the TUI shares the
partition load and each sees only part of the stream. The docs say to give the
MCP server its own consumer group when the TUI runs at the same time.

Client configuration examples (documented in `docs/mcp-server.md`):

```json
{ "mcpServers": { "az-firewall-watch": {
    "command": "/path/to/az-firewall-watch", "args": ["--mcp"] } } }
```

```bash
claude mcp add az-firewall-watch -- python -m mcp_server
```

## Tests

Unit tests run without Azure, like the rest of the suite. The in-memory
client of the SDK (`mcp.client.client.Client(server)`) drives the real server
object, so every tool is tested through the protocol, not by calling the
Python function.

| File | Covers |
| --- | --- |
| `tests/test_mcp_buffer.py` | append, capacity trim, ids stay monotonic across trims, counters, `wait_for` wakes on a matching row and times out otherwise, time parsing with Azure's 7-digit fractions |
| `tests/test_mcp_filters.py` | parity with the TUI for CIDR, IPv6 spellings, substring, presets; `rule`, `text`, `src_port`; relative and absolute windows; invalid values raise with a clear message; the 138 IPv6 fixture records queried by `fd10::/16` |
| `tests/test_mcp_stream.py` | `StreamWorker` against the fake client pattern of `test_streaming.py`: SAS and Entra paths, skip counting, firewall id detection, reconnect after a drop, configuration error stops retrying, `state` transitions, nothing written to stdout |
| `tests/test_mcp_context.py` | `ContextHolder` states with `load_management_data` mocked: off, waiting, loaded, unavailable with reason, forced refresh, automatic refresh on unknown rule only once per minute |
| `tests/test_mcp_tools_logs.py` | `get_status`, `query_logs` (every filter, limits, order, cursor, detail levels), `tail_logs` (returns on arrival, times out, respects filter), `get_log_entry` (enrichment, not traceable reasons), `clear_logs`; tool list carries the annotations |
| `tests/test_mcp_tools_policy.py` | canned snapshot (reuse the builders in `test_trace.py` / `test_arm.py`): `get_firewall`, `get_policy` with and without rules, `list_rules` filters and paging, `get_rule` resolves IP-group names and hides header values, IP-group tools, `refresh_policy_context`, every tool's `available: false` answer without context |
| `tests/test_mcp_tools_analysis.py` | `summarize_logs` buckets and tops, `explain_log_entry` on allow, deny-with-rule and default-action deny, `trace_flow` for allow, deny, DNAT and unknown criteria, `lookup_address`, `get_log_coverage` with forwarded-not-seen and seen-not-forwarded |
| `tests/test_mcp_resources_prompts.py` | every resource reads, template resolves, unknown id errors, prompts render with arguments |
| `tests/test_mcp_entry.py` | `main.py --mcp` dispatches without starting Textual, `--no-policy-context`, missing credentials exits 2 with the hint, `mcp_server` imports without `textual` (subprocess) |
| `tests/test_streaming.py`, `tests/test_trace.py` | unchanged and green after the extractions |

Live tests, opt-in, in `tests/live/test_live_mcp.py` (marker `live`, same
`AZFW_LIVE_*` variables): start the server in-memory on the real `.env`,
wait for `connected`, `tail_logs` delivers rows, `get_firewall` names the
firewall, `explain_log_entry` on a real deny row returns a trace, `trace_flow`
against the real policy, `get_log_coverage` agrees with the diagnostic
settings. The metadata cache is redirected to a temporary directory.

Lint and types: `mcp_server` joins the `mypy` file list; `ruff` covers it by
default. CI is unchanged otherwise; `requirements.txt` gains `mcp>=2.3,<3`
(Python 3.10 or newer, as the project already requires).

## Documentation

- `docs/mcp-server.md`: what it is, client configuration for Claude Desktop
  and Claude Code, the tool reference, resources and prompts, environment
  variables, consumer-group advice, security notes (read-only, stdio, no
  secrets in any answer, HTTP is local-only).
- `README.md`: a feature bullet, a docs table row and a short section.
- `docs/configuration.md`: the new variables and `--mcp`.
- `docs/development.md`: `mcp_server/` in the layout table, the test files.
- `CHANGELOG.md`: an *Added* entry under Unreleased.
- `.github/workflows/release.yml`: `--collect-all mcp` so the binary carries
  the server; verified only by the next release build.

## Implementation phases

| Phase | Agent | Writes | Done when |
| --- | --- | --- | --- |
| A core | opus | `viewer/eventhub.py`, `viewer/streaming.py` (imports), `viewer/trace.py` + `viewer/enrichment.py` (extractions), `viewer/app.py` (wrappers), `mcp_server/{__init__,__main__,cli,config,buffer,filters,stream,context,serialize,state,server,tools_logs}.py`, empty `tools_policy.py`, `tools_analysis.py`, `resources.py`, `prompts.py` with `register(server)`, tests for buffer, filters, stream, context, log tools, entry | suite green, `python -m mcp_server` serves `get_status` over stdio |
| B1 policy | opus | `tools_policy.py`, policy parts of `serialize.py`, `test_mcp_tools_policy.py` | |
| B2 analysis | sonnet | `tools_analysis.py`, `resources.py`, `prompts.py`, their tests | |
| B3 docs | sonnet | `docs/mcp-server.md`, `README.md`, `CHANGELOG.md` | written from this plan, checked against the code at the end |
| B4 plumbing | haiku | `requirements.txt`, `pyproject.toml`, `release.yml`, `docs/configuration.md`, `docs/development.md`, `tests/live/test_live_mcp.py` | |
| C verify | main session | run `ruff`, `mypy`, `pytest`; live run against the lab firewall; fix; commit | |

B1, B2 and B4 run in parallel after A; B3 runs alongside A. Files are
disjoint between concurrent agents.

## Open decisions (defaults in use)

- **Package name** `mcp_server` next to `viewer` and `setup`. Default: keep.
- **Binary** carries the server (`--mcp`). Adds the `mcp` dependency tree
  (starlette, uvicorn, pydantic) to the single binary. Default: yes, one
  binary is the point of the project.
- **`clear_logs`** exists although it only touches the local buffer. Default:
  keep, marked destructive.

## Outcome (2026-10-15)

Implemented on the branch as planned, with these deviations:

- **No TUI file was edited.** Open PR #35 rewrites `viewer/streaming.py` and
  `viewer/management.py`, so `viewer/eventhub.py`, `flow_from_row` and
  `logged_from_row` in `viewer/trace.py` and `enrich_row` in
  `viewer/enrichment.py` are copies for now. `tests/test_mcp_extractions.py`
  pins them to the originals; the originals are replaced by imports once PR #35
  has landed. `viewer/__init__.py` loads the app class lazily so that importing
  `viewer.*` no longer pulls in Textual.
- **Caller mistakes raise `ToolError`,** not `ValueError`: the SDK hides the
  text of any other exception from the client.
- **Row ids are the buffer's own counter** (1, 2, 3, ...), stable across trims
  and `clear_logs`; the parser's `rowid` also counts skipped records.
- **Extras:** `query_logs` has `before_id`, `has_more` and `next_before_id`;
  `tail_logs` has `detail`; `trace_flow` has `destination_ip`, `full_tree`,
  `would_match`, `unevaluable_rules` and `caveats`; `lookup_address` has
  `limit`; `list_rules` returns `address_match`, `has_more` and `next_offset`
  and treats an unknown group, collection or IP group as an error; autoscale
  has a fifth mode `not_understood`; coverage hints are `{code, message}`.
- **Resources** call the matching tool through `server.call_tool`; since a
  static resource function cannot take a `Context`, `register` wraps the
  server's `read_resource` once and parks the request context in a context
  variable for the duration of the read.
- **Verified live** against `fw-hub-gwc`: `tests/live/test_live_mcp.py` passes,
  and a stdio session through `main.py --mcp` answered every tool group on
  real records (2768 rows replayed from retention, a default-action deny
  explained with its nearest misses, a flow with a service-tag rule reported as
  `unknown`, 23 rules found for one address).
