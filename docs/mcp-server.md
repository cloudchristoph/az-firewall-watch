# MCP server

The MCP server is az-firewall-watch without the terminal UI. It runs headless,
reads the firewall's logs from the same Event Hub as the viewer, keeps the most
recent ones in memory and lets an AI agent query them through typed tools. It
speaks the [Model Context Protocol](https://modelcontextprotocol.io), so any
MCP client can use it: Claude Desktop, Claude Code, or your own.

With [policy context](policy-context.md) on, which is the default, the agent
also sees the firewall, its policy and the IP groups, and it can run the same
evaluation trace as the detail dialog. That turns "what was denied?" into "why
was it denied, and which rule would let it through?".

It is **read-only**, it needs **no new configuration** (it reads the `.env` you
already have), and it needs **no new Azure permissions**.

## What an agent can do with it

Connect a client, then ask in plain language. Questions the tools are built to
answer:

- *What is being denied right now?*
- *Why did this flow get denied, and which rule came closest?*
- *Would 10.1.2.3 reach example.com on port 443?*
- *Which rules mention this address?*
- *Which IP groups contain 10.2.0.0/24, and which rules use them?*
- *Are FatFlow logs even being forwarded to this Event Hub?*
- *Summarise the last hour: top sources, top destinations, top denied
  destinations, and the denies that no rule explains.*
- *Wait for the next deny from 10.1.2.3 and tell me what it was.*

The agent does not need to know the log format or the policy model. It calls
tools such as `query_logs`, `explain_log_entry` or `trace_flow` and gets
structured JSON back.

## How it relates to the viewer

| | Viewer (TUI) | MCP server |
| --- | --- | --- |
| Configuration | `.env` next to the binary | The same `.env`, the same keys |
| Log source | One Event Hub, one consumer group | The same Event Hub, ideally its own consumer group |
| Policy context | ARM reads, cached for an hour | The same ARM reads, the same cache file |
| Parser and filters | `fw_parser.py`, the filter bar | The same parser, the same filter semantics |
| Azure access | Read-only | Read-only |
| Scope | One firewall per session | One firewall per process |
| Output | A terminal screen | JSON over MCP |

Four things are worth knowing:

- **Same `.env`.** The server uses the file the setup wizard wrote, and the
  plain environment variables [described in the configuration page](configuration.md#without-a-env-file)
  work too. It never runs the wizard. If no Event Hub is configured it exits
  with code 2 and a message on stderr that tells you to start the viewer once
  (`./az-firewall-watch`, or `--reconfigure`).
- **Same cache.** The policy context goes into the cache file the viewer uses
  (see [Caching and staying current](policy-context.md#caching-and-staying-current)).
  A fresh cache written by either of them saves the other an ARM round trip.
- **One firewall per process.** The server takes the firewall from the first
  log record, or from `AZFW_FIREWALL_ID`. To watch a second firewall, start a
  second server with its own `.env`.
- **A ring buffer, not a database.** The server keeps the newest
  `AZFW_MCP_BUFFER_SIZE` rows (20000 by default) in memory. Older rows fall out,
  and everything is gone when the process ends. Row ids keep counting up across
  trims, so an id never points at a different row later.

## Starting it

From the binary:

```bash
./az-firewall-watch --mcp
```

From source (Python 3.10+, with `requirements.txt` installed):

```bash
python -m mcp_server
```

The server reads its `.env` like the viewer does: next to the binary, or in the
repo root when running from source. Point it elsewhere with `--env-file`.

> [!NOTE]
> Nothing the server does may write to standard output, because with the
> default transport that is the MCP channel. Log messages go to standard error.
> If you wrap the server in a script, keep it that way.

### Command-line options

| Option | Effect |
| --- | --- |
| `--transport stdio` or `--transport http` | `stdio` (default) talks to the client that started the process. `http` serves streamable HTTP, see [Security notes](#security-notes) |
| `--host` | Address for the HTTP transport. Default `127.0.0.1` |
| `--port` | Port for the HTTP transport. Default `8765` |
| `--env-file` | Read this file instead of the default `.env` |
| `--no-policy-context` | Policy context off for this run: no ARM requests, no cache, and the policy tools answer that the context is off |
| `--firewall-id` | Load the policy context for this firewall at start, instead of waiting for the first log record. Same as `AZFW_FIREWALL_ID` |

Command-line options win over the environment, and they are never written
anywhere. `--mcp` on the binary hands over to the server, which takes the same
options.

## Connecting a client

### Claude Desktop

Add the server to `claude_desktop_config.json` (Settings, Developer, Edit
Config), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "az-firewall-watch": {
      "command": "/path/to/az-firewall-watch",
      "args": ["--mcp"]
    }
  }
}
```

On Windows the command is the full path of the executable, with the backslashes
doubled: `"C:\\Tools\\az-firewall-watch.exe"`.

### Claude Code

```bash
claude mcp add az-firewall-watch -- /path/to/az-firewall-watch --mcp
```

From a source checkout, run this in the repo root:

```bash
claude mcp add az-firewall-watch -- python -m mcp_server
```

### Where the `.env` has to be

The binary looks for its `.env` **next to itself**, not in the directory the
client happens to start it from. Put the binary and its `.env` in the same
folder, and the client config above is all you need. If the two live apart, or
you run from source in an environment the client starts somewhere else, pass the
file explicitly:

```json
{
  "mcpServers": {
    "az-firewall-watch": {
      "command": "/path/to/az-firewall-watch",
      "args": ["--mcp", "--env-file", "/path/to/.env"]
    }
  }
}
```

A client that starts the server for you also stops it again, so there is nothing
to run in a terminal.

### Running next to the viewer

The viewer and the MCP server can read the same hub on the same consumer group
at the same time, and both see every record. The SDK opens its receivers
without an owner level, so they are not exclusive, and it keeps its partition
ownership in memory, so one process never takes a partition away from another.
Event Hubs allows five such readers per partition and consumer group; the sixth
is refused with a quota error. Verified on the lab hub with two servers started
together on `$Default`: identical rows, identical counts.

A consumer group of its own is only needed when more than five readers share a
hub. Set it in the `.env` the server reads or in the client config:

```json
{
  "mcpServers": {
    "az-firewall-watch": {
      "command": "/path/to/az-firewall-watch",
      "args": ["--mcp"],
      "env": { "EVENT_HUB_CONSUMER_GROUP": "mcp" }
    }
  }
}
```

Create the group on the hub first, for example with
`az eventhubs eventhub consumer-group create`. The Basic tier has only
`$Default`; several consumer groups need the Standard tier, see
[what it costs](event-hub.md#-what-it-costs).

## Using the answers

### Row shapes

Every tool that returns log rows takes the same three levels of detail, through
the `detail` argument:

| `detail` | Fields |
| --- | --- |
| `summary` (default) | `id`, `time`, `category`, `protocol`, `source`, `src_port`, `destination`, `dst_port`, `action`, `rule`, `info` |
| `full` | `summary` plus `resource_id`, `policy`, `rule_collection_group`, `rule_collection`, `rule_name`, `nat_dst_ip`, `nat_dst_port`, `explicit_proxy`, `tls_inspected`, `received_at` |
| `raw` | `full` plus `raw`: the diagnostic record exactly as it was received |

`summary` is what an agent should start with. It is small, and the `id` is all it
needs to ask for more with `get_log_entry` or `explain_log_entry`.

### Paging with `after_id`

Every row has an `id` that only ever grows; it is the server's own counter, so it
stays valid for the life of the process, across buffer trims and `clear_logs`.
`query_logs` and `tail_logs` return `next_after_id`; pass it back as `after_id`
and you get the rows that arrived since, without repeats and without gaps. In
the default newest-first order, `query_logs` returns `has_more` and
`next_before_id`; pass that back as `before_id` to page towards older rows. `query_logs` also returns `first_id`,
`last_id`, the bounds of the buffer, and `matched`, the number of matching rows
before `limit` was applied, so the agent can tell whether it saw everything.

### Time arguments

`since` and `until` accept either:

- an **ISO 8601** timestamp, such as `2026-10-15T09:30:00Z`, or
- a **relative** time counted back from now: `30s`, `15m`, `2h` or `1d`.

### Limits

`limit` is clamped to the range 1 to 1000 and defaults to 100. A value outside
the range is not an error; the server uses the nearest one. A mistake the
server cannot repair (an unknown id, a bad CIDR, an unreadable time) is an
error result with a sentence that says what was wrong, so the agent can correct
itself.

### When the policy context is missing

A tool that needs the policy context but has none does not fail. It answers

```json
{ "available": false, "reason": "...", "hint": "..." }
```

so the agent can say why, and carry on with the log tools. See
[Troubleshooting](#troubleshooting).

## Tool reference

All tools return JSON. Every tool carries the MCP `readOnlyHint` annotation
except two: `clear_logs` is marked destructive (it empties the local buffer and
nothing else), and `refresh_policy_context` is marked idempotent.

### Stream and logs

The log filters are the viewer's, so the same inputs mean the same thing:
`source` and `destination` take a CIDR prefix, an IPv4 or IPv6 address in any
spelling, or a substring. `action`, `protocol`, `dst_port` and `src_port` are
substring matches. `category` takes a category name, a list of names, or one of
the presets `decisions`, `traffic` and `dns`. `rule` is a substring of the rule
path, and `text` searches every column.

| Tool | What it answers | Arguments | Returns |
| --- | --- | --- | --- |
| `get_status` | Is the server connected, and what has it seen so far? | none | Server version. Event Hub: `namespace`, `hub`, `consumer_group`, `start_position`, `auth` (`entra` or `sas`), `state`, `last_error`, `connected_since`. Events: `received`, `skipped` (by reason), `per_category`, `last_event_at`, `last_event_age_s`. Buffer: `size`, `capacity`, `first_id`, `last_id`. `firewall_id`, `firewall_name`. Policy context: `state`, `age_s`, `reason` |
| `query_logs` | Which rows in the buffer match? | `category`, `action`, `source`, `destination`, `protocol`, `dst_port`, `src_port`, `rule`, `text`, `since`, `until`, `after_id`, `before_id`, `limit` (default 100), `order` (`desc` default, or `asc`), `detail` | `rows`, `matched` (total before `limit`), `returned`, `has_more`, `first_id`, `last_id`, `next_after_id`, `next_before_id` (page back in `desc` order), the `buffer` bounds, and a `filter` echo |
| `tail_logs` | Wait for new matching rows | The same filter fields, `after_id` (default: the current `last_id`), `timeout_s` (1 to 60, default 20), `limit`, `detail` | `rows` in arrival order, `next_after_id`, `timed_out`. A long poll: it returns as soon as one matching row arrives |
| `get_log_entry` | Everything about one row | `id` | The row at `raw` detail, plus `enrichment` (`source_fw_instance`, `dest_fw_instance`, `source_ip_groups`, `dest_ip_groups`, `rule_priority`, `rule_action`, `rule_policy`) and `traceable`, with the reason when the row cannot be traced |
| `clear_logs` | Forget the rows seen so far | none | `cleared`, the number of rows removed from the local buffer |

### Analysis

| Tool | What it answers | Arguments | Returns |
| --- | --- | --- | --- |
| `summarize_logs` | What does the traffic look like? | The log filter fields, `since` (default `15m`), `top` (default 10), `bucket` (`1m` default, from `10s` to `1h`) | `window` (from, to, rows), `by_category`, `by_action`, `top_sources`, `top_destinations`, `top_rules`, `top_denied_destinations`, `top_dst_ports`, `denied_without_rule` (denies by the default action), `timeline` (per bucket: count and denies) |
| `explain_log_entry` | Why did this row end the way it did? | `id`, `full_tree` (default `false`) | The row, an `outcome` sentence, `matched_rule` with its path and priorities, `nearest_misses` (up to 3, each with the failing criterion), and the `trace`: passes, collections, rules, checks, each `match`, `miss`, `unknown` or `n/a`. Folded by default like the detail dialog |
| `trace_flow` | What would happen to this flow? | `protocol`, `source`, `destination` (IP address or FQDN), `dst_port`, `explicit_proxy`, `tls_inspected`, `destination_ip` (the resolved address of an FQDN destination, so network and DNAT rules can be evaluated too), `full_tree` | The same trace shape for a flow you describe, the rule that `would_match`, `unevaluable_rules`, `caveats`, and a `verdict`: `allow`, `deny`, `dnat` or `unknown`. Service tags, FQDN tags, web categories and IP groups that could not be read are `unknown`, and so is a verdict that depends on them |
| `lookup_address` | What does the firewall know about this address? | `address` (IP address or CIDR), `limit` (default 100) | `fw_instance` label when it lies inside a firewall subnet, the `ip_groups` that contain it, the `rules` whose source or destination cover it (path, kind, action), and `recent` log counts as source and as destination over the last 15 minutes |
| `get_log_coverage` | Does the Event Hub carry every category it should? | none | Per diagnostic setting: its target and categories. For the connected hub: `forwarded` categories, `observed` categories with counts, `forwarded_not_seen`, `seen_not_forwarded`. The switches in the firewall's `additionalProperties` that explain gaps (fat flow logging, DNS flow trace) |

`trace_flow` and `explain_log_entry` follow the same rules as the viewer's
evaluation trace: Threat Intelligence first, then DNAT, Network and Application
in that order, stopping at the first match. What `unknown` means is explained
under [What `?` means](policy-context.md#what--means).

### Policy context

These tools read the firewall, policy and IP groups loaded from Azure Resource
Manager. They answer from the snapshot the server holds. The server refreshes it
on its own when a logged rule is missing (see [Troubleshooting](#troubleshooting)),
and on request through `refresh_policy_context`.

| Tool | What it answers | Arguments | Returns |
| --- | --- | --- | --- |
| `get_firewall` | What is the firewall? | none | The firewall's details, plus its subnets with CIDRs, NAT gateways, public IPs, maintenance windows, diagnostic settings, autoscale state, route server, additional properties, tags, and `cache_age_s` |
| `get_policy` | How is the policy set up? | `include_rules` (default `false`) | Name, tier, Threat Intelligence mode and allow lists, DNS proxy and servers, IDPS mode and counts, TLS CA, SNAT ranges and auto-learn, explicit proxy ports (PAC URL without its query string), the parent chain (settings only), and the rule collection groups of the whole chain in evaluation order, each tagged with its policy, with priority, collection count and rule count. With `include_rules` the full tree |
| `list_rules` | Which rules exist, and which match this filter? | `kind` (`dnat`, `network` or `application`), `group`, `collection`, `action`, `name`, `address` (IP address or CIDR that the rule's addresses or IP groups cover), `fqdn`, `port`, `ip_group`, `limit` (default 100), `offset` (default 0) | Rules in evaluation order, each with a `ref` (`policy » group » collection » rule`), priorities, action, protocols, sources, destinations and ports; a rule matched by `address` carries `address_match` with the covering entry and whether it `contains`, `overlaps` or is a `wildcard`. Plus `total`, `has_more` and `next_offset`. An unknown `group`, `collection` or `ip_group` is an error that names the nearest names |
| `get_rule` | What exactly does this rule say? | `ref`, or `group`, `collection` and `rule` | The full rule: addresses, IP groups resolved to names, FQDNs, ports, protocols, FQDN tags, web categories, target URLs, translated target, `terminate_tls`, `http_headers` (names only), and where inserted headers land, in the viewer's wording |
| `list_ip_groups` | Which IP groups does the policy use? | `name` | Per group: id, name, location, address count, and `used_by`, the number of rules that reference it |
| `get_ip_group` | What is in this IP group? | `name`, or `id` | The addresses, and the rules that reference the group, by `ref` |
| `refresh_policy_context` | Fetch the policy again, now | none | The new context state and `fetched_at`. Forces an ARM fetch and rewrites the shared cache |

## Resources

For clients that attach context to a conversation instead of calling tools.
Each resource returns what the tool named in the table returns.

| URI | Content |
| --- | --- |
| `azfw://status` | `get_status` |
| `azfw://firewall` | `get_firewall` |
| `azfw://policy` | The `get_policy` summary |
| `azfw://policy/rules` | `list_rules` without a filter |
| `azfw://ip-groups` | `list_ip_groups` |
| `azfw://logs/recent` | The newest 100 rows, at `summary` detail |
| `azfw://logs/{id}` | A template: `get_log_entry` for the row with that id |

## Prompts

Prompts are ready-made instructions a client can offer to the user, for example
as slash commands. They send the agent through the tools above in a useful order.

| Prompt | Arguments | What it asks the agent to do |
| --- | --- | --- |
| `investigate_denies` | `since` (default `15m`) | Summarise the denies, group them by destination and rule, name the default-action denies, propose the narrowest rule that would allow the legitimate traffic, and flag anything that looks like scanning |
| `explain_entry` | `id` | Explain the row in plain words from `explain_log_entry`, and name the criterion that decided it |
| `firewall_health_check` | none | Read status, coverage and the policy summary, then report the connection state, missing categories, auto-learn without a route server, fixed capacity and expired maintenance windows |

## Environment variables

The Event Hub variables and `POLICY_CONTEXT` are the viewer's own, with the same
meaning; see the [environment variables table](configuration.md#environment-variables).
These are new:

| Variable | Description | Default |
| --- | --- | --- |
| `AZFW_FIREWALL_ID` | Resource ID of the firewall. Loads the policy context at start instead of waiting for the first log record | none |
| `AZFW_MCP_BUFFER_SIZE` | Number of rows kept in memory | `20000` |
| `AZFW_MCP_TRANSPORT` | `stdio` or `http` (streamable HTTP) | `stdio` |
| `AZFW_MCP_HOST` | Address for the HTTP transport | `127.0.0.1` |
| `AZFW_MCP_PORT` | Port for the HTTP transport | `8765` |
| `AZFW_MCP_LOG_LEVEL` | Log level on standard error | `INFO` |

## Permissions

The same as the viewer, and nothing more:

| Scope | Role | When |
| --- | --- | --- |
| Event Hub namespace or hub | **Azure Event Hubs Data Receiver** | Entra ID auth. Not needed with a SAS connection string |
| Firewall, its policy, its IP groups, its subnets and public IPs | **Reader** | Policy context. Not needed with `POLICY_CONTEXT=off` or `--no-policy-context` |

Without Reader the log tools keep working and the policy tools answer that the
context is unavailable. The full list, including the optional reads, is in
[required Azure permissions](configuration.md#required-azure-permissions).

## Security notes

- **Read-only against Azure.** Every ARM request the server makes is a `GET`.
  It never calls an ARM action, never creates or changes anything, and the tools
  say so with the `readOnlyHint` annotation. The two tools that are not marked
  that way touch local state only: `clear_logs` empties the buffer in memory, and
  `refresh_policy_context` fetches again and rewrites the local cache file.
- **No secrets in answers.** No tool returns a SAS string or a connection
  string. HTTP headers that a rule inserts are listed by name, never by value,
  and the explicit proxy's PAC file URL comes without its query string, since
  Azure stores it as a SAS URL.
- **stdio by default.** The client starts the process and talks to it over
  standard input and output. Nothing listens on the network.
- **The HTTP transport is local-only.** `--transport http` serves streamable HTTP
  on `127.0.0.1`, and it has **no authentication**. Anything on the machine that
  can reach the port can read your firewall's logs and policy. Do not bind it to
  another address, do not forward the port, and do not put it behind a proxy
  that exposes it. Use stdio unless you have a reason not to.
- **The agent sees your traffic.** Log rows carry source and destination
  addresses, FQDNs and rule names, and they go to whatever model your client
  uses. Treat the connection like any other place you would paste firewall logs.

> [!CAUTION]
> `--host` accepts any address, but the HTTP transport has no authentication.
> Changing it from `127.0.0.1` makes your firewall data readable to everyone who
> can reach that address.

## Troubleshooting

**The agent says nothing is connected, or `query_logs` returns no rows.**
Call `get_status` and read `state` and `last_error`. `connecting`, `verifying` and
`reconnecting` are on their way; the server retries with the same backoff as the
viewer. `failed` means the configuration is wrong (a rejected credential, a
missing role, an unknown hub) and the server has stopped retrying: `last_error`
says which, and the fix is the same as for the viewer, see
[required Azure permissions](configuration.md#required-azure-permissions).
If `state` is `connected` but `received` stays at 0, the start position is probably
`latest` and nothing has been logged since; set `EVENT_HUB_START_POSITION=earliest`
to replay the hub's retention first, and check `skipped` for records the parser
could not use.

**The server exits at start with code 2.**
No Event Hub is configured in the `.env` it found. Check that the file is next to
the binary, or pass `--env-file`, and run the viewer once to use the wizard.

**Rows are missing while the viewer is open.**
Both are reading in the same consumer group and splitting the partitions. See
[Use your own consumer group](#use-your-own-consumer-group).

**A category never shows up.**
Call `get_log_coverage`. `forwarded_not_seen` lists categories the diagnostic
setting sends that have not arrived, and the switches it reports (fat flow
logging, DNS flow trace) explain most gaps. See [Log categories](log-categories.md).

**The policy tools answer `available: false`.**
The policy context is not loaded. The `reason` in the answer, and the policy
context `state` in `get_status`, say why:

| `state` | Meaning |
| --- | --- |
| `off` | Policy context is switched off: `POLICY_CONTEXT=off` or `--no-policy-context` |
| `waiting_for_firewall_id` | The server has not seen a log record yet and `AZFW_FIREWALL_ID` is not set. It loads as soon as the first record arrives |
| `loading` | The ARM fetch is running |
| `loaded` | The context is available, with its age in `age_s` |
| `unavailable` | The fetch failed. `reason` carries the error, for instance a missing Reader role or an unreachable host. `refresh_policy_context` tries again |

**A rule in the logs is not in the policy the agent sees.**
You changed the policy after the snapshot was taken. When a logged rule is missing
from the loaded policy, the server fetches again by itself, at most once a minute
and only when the snapshot is older than that. To get the new rule at once, call
`refresh_policy_context`.
