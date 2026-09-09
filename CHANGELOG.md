<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to **Azure Firewall Watch** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

0.5.1 took back the verdicts the trace had no grounds for. This release goes after the next category: places where the viewer knew something and said nothing. Almost every item below is one more field from an ARM call the viewer already makes, read into the Firewall and Policy tabs, and every one of them replaces an answer that looked complete and was not. Nothing here writes to Azure, and nothing needs more than Reader; where Azure only offers a POST action for a piece of information, the tab says the information is not readable from here rather than fetching it.

### Added

- **Explicit proxy with its ports and PAC file.** The Policy block used to say `on` or `off`. It now names the HTTP and HTTPS ports, or the single port Azure allows for both, and whether the firewall serves a PAC file and on which port. The PAC file URL is shown and cached without its query string: Azure stores it as a SAS URL, and the token has no business in a cache file or a `Ctrl+S` screenshot. Application-rule rows that came in through the proxy carry `IsExplicitProxyRequest` in the log; the detail dialog shows the flag (with `IsTlsInspected`), and the trace's port criterion names it. The open question whether such a row records the proxy port or the real destination port was settled against real records: proxied HTTP and proxied CONNECT, logged seconds apart from the transparent request to the same target, all carry the destination port (`80`, `443`), so the port compares like on any other row.
- **Auto-learn SNAT and its Route Server.** With `autoLearnPrivateRanges` enabled the configured SNAT ranges are not the effective ones: the firewall learns them every 30 minutes by BGP from an associated Azure Route Server, and the viewer used to show the configured list as if it were the whole truth. The Policy block now shows the auto-learn state, the Route Server the firewall is associated with (from `additionalProperties`, the only place ARM keeps it), and the one misconfiguration worth a warning: auto-learn on, but no Route Server on the firewall, so nothing is ever learned. The learned prefixes themselves stay off screen on purpose; listing them is a POST action, and this tool only reads. The block also says what the docs say: private ranges apply to network rules only, application rules are always SNATed. The default is named correctly as RFC 1918 and RFC 6598.
- **NAT gateway on the firewall subnet.** The Networking block listed the firewall's public IPs and thereby answered "which address does the far end see" wrongly whenever a NAT gateway sits on the subnet: outbound traffic then leaves with the gateway's public IPs, while DNAT and the firewall's management traffic stay on the firewall's own. The subnet is read anyway for the `AzFw.<n>` rendering; its `natGateway` reference is one field more, followed by an optional `GET` on the gateway for its public IPs. A Virtual WAN hub firewall gets *not supported* rather than an empty line, an unreadable gateway is named as unreadable.
- **Scaling.** `autoscaleConfiguration` distinguishes three states the portal shows as one page: no configuration (service default, autoscaling up to 20 capacity units), a prescaled range with autoscaling inside it, and minimum equal to maximum, which means a fixed capacity with autoscaling off. The third is the one people overlook, so it is the one in yellow. Basic does not scale and says so.
- **Customer-controlled maintenance window.** When an instance goes away for maintenance the firewall resets existing connections, and the RST burst in the log looks like an incident. The Instance block now reads the `Microsoft.Maintenance` assignment under the firewall and its configuration, and shows the daily window with duration and time zone as Azure wrote them, with the caveat the docs attach: the window covers guest OS and service updates, while host updates and urgent security fixes can fall outside it. An unregistered provider means there is nothing to read, not an error; an assignment list that cannot be read is reported as unknown rather than as no window; a configuration that cannot be read is named as assigned but unreadable.
- **HTTP header insertion on application rules.** A rule that inserts headers writes into other people's traffic, and the Policy tab showed it as if it did nothing of the sort. The rule detail now lists the inserted headers by name (`httpHeadersToInsert`, verified against a real policy: the entries are `headerName` and `headerValue`), together with the rule's TLS inspection and a line that says where the headers really land: HTTP only on Standard and Basic, HTTP only on Premium as long as the rule does not terminate TLS, HTTP and inspected HTTPS otherwise. Header values can carry tokens and tenant ids, so they are hidden behind `v` and hidden again on every refresh; the rule definition in the row detail dialog names the headers, never the values.
- **The firewall's own reason on rule-less application-rule rows.** An application-rule row that no rule matched carried an empty Rule Info column, while the same case on a network rule showed the log's `ActionReason` (usually `Default Action`). Both show it now.
- The metadata cache moves to version 5 and is fetched once more on first start; the required roles are unchanged (Reader, plus Reader on the NAT gateway and the maintenance configuration for their two optional lines).
- The firewall, policy and IP-group reads use ARM API version `2024-03-01` instead of `2024-01-01`. That is the first version that returns `autoscaleConfiguration`; with the old pin a prescaled firewall would have read as *service default*, which is a wrong statement of exactly the kind this release is meant to end. Policies and IP groups are unchanged between the two versions.
- 733 tests (583 in 0.5.1); every new fact has tests for the field being present, absent and unreadable, and the explicit-proxy and TLS-inspection cases are modelled on the lab's real records.

### Fixed

- **A TLS-inspected HTTPS request no longer misses an HTTPS-only rule.** The firewall logs an inspected request as the decrypted inner one: `Protocol` is `HTTP/1.1` and `IsTlsInspected` is true, while an uninspected request says `HTTPS`. The trace compared the bare `HTTP` against the rule's `Https` and marked the protocol as a miss, which on the very rule that terminates TLS was a confident wrong verdict. With the flag the trace treats the row as HTTPS and says so (`HTTPS (TLS inspected, logged as HTTP/1.1)`). Found on real records during the 0.6.0 lab pass; the legacy `properties.msg` format has no such flag and keeps its old reading.

### Known limitations

- **A rejection without a rule is still not modelled.** Azure drops an application-rule request whose TCP port disagrees with the port in its `Host` header without involving any rule, and the trace still ends such a row in the default deny. The roadmap had this down as a small structural change, but the `AZFWApplicationRule` log carries no column with the `Host` header's port (`Fqdn`, `DestinationPort`, `TargetUrl` and `ActionReason` are what there is), so the mismatch cannot be told from the log, and claiming it without evidence would be a guess. What the viewer can do it now does: show the firewall's own `ActionReason` on such rows. Whether Azure logs the case at all, and with which reason, is open.

## [0.5.1] - 2026-09-08

0.5.0 gave the viewer an opinion: it reads the policy and marks every criterion of every rule on the flow's path as a match, a miss, or not decidable from here. An opinion is only worth having if it is right, and one of its founding principles is that what cannot be evaluated locally is marked `?` and never `✓`.

This release takes back the judgements that broke that promise: three places where the trace claimed a match or a miss it had no grounds for, and the parser bug underneath one of them. None of them looked like an error on screen, which is what made them worth a release of their own rather than a line in the next feature.

Two of the fixes change what the viewer says about a policy it already read, so a rule you looked at yesterday can read differently today. Both are called out below.

### Fixed

- **Address ranges in IP groups were skipped silently.** Azure accepts three notations wherever addresses are listed: a single address `10.0.0.0`, a CIDR block `10.1.0.0/32` and a range `10.2.0.0-10.2.0.31`. The viewer parsed the first two and dropped the third without a word, so a flow whose address the group covered *as a range* was reported as `✗ destination` on the very rule that had matched it. Ranges are evaluated now, endpoints included, in IP groups and in a rule's own address lists, for IPv4 and IPv6 alike.

  A range written straight into a rule's `sourceAddresses` or `destinationAddresses`, without an IP group, was never a wrong verdict: there the same `ValueError` landed in the same bucket as a service tag, so the criterion showed `cannot evaluate: 10.0.1.0-10.0.1.254`. Honest, but needlessly ignorant. **This is the one change in this release that makes the viewer claim more than before**: an address outside such a range is now a miss where it used to be a question mark.
- **An address entry the viewer cannot read is a `?`, not a miss.** The same silent `continue` also swallowed typos. An unreadable entry now names itself and its group in the trace (`cannot evaluate: ipgroup-dmz entry "10.4.0.0-oops"`) instead of quietly shrinking the group; a reversed or mixed-family range counts as unreadable rather than as an empty set, so it can never answer a match question. An entry that does answer the question still wins over one that does not.
- **The legacy log parser cut IPv6 addresses in half.** Azure's `properties.msg` format writes endpoints as plain `host:port`, and the parser split them at the *first* colon, which turns `fd00::1:1234` into `fd00`. A `split_endpoint` / `format_endpoint` pair in `helpers.py` replaces all six split sites (network rule source and destination, NAT rule source and translated address, application rule client, DNS proxy client) and handles both the bracketed and the unbracketed form, since it is not known whether Azure ever brackets an IPv6 host there itself. Addresses render as `[fd00::1]:1234` in the table and the row detail dialog; IPv4 and FQDNs are untouched.
- **An application rule's client address was truncated too.** The sixth split site sat one line above the `rsplit` the other five were modelled on, so it survived every earlier reading of this code. Unlike the destination above, this one never produced a wrong verdict: `fd00` fails to parse, and the source criterion answers `n/a — no address in log`. It is what the table showed, though, and what IP-group membership was looked up with, so an IPv6 client silently belonged to no group.
- **A truncated IPv6 destination was evaluated as an FQDN.** The consequence of the split above: `fd00` does not parse as an address, so the row ran against the rule's `targetFqdns` instead of its address ranges and came back with a verdict that was confident and wrong. With the address intact the destination is evaluated as an address again.
- **Application rules no longer match on the packet's destination IP.** Azure matches an application rule on the `Host` header (HTTP) or the SNI (HTTPS) and *ignores the packet's destination IP* in favour of the address it resolved from the name itself. The trace nevertheless compared the logged IP against the rule's `destinationAddresses`, which could only ever be right by accident. That comparison is gone. Because addresses remain a valid destination type on an application rule, a rule that lists them is now `?` with the reason, rather than a miss: the firewall's own resolution is nowhere in the log, so neither a match nor a miss can be claimed. **This is the second change that alters an existing reading**, and it goes the other way: an application rule with `destinationAddresses` gives up a verdict it should never have offered.

### Known limitations

- **IPv6 is parsed and matched, but not filtered.** Endpoints survive the legacy parser, render as `[fd00::1]:1234`, and the trace matches them against addresses, CIDR blocks and ranges like any IPv4 address. The filter bar is untouched and still compares plain substrings: `fd00::1` also brings in `fd00::17` and `fd00::100`, and it will not find an address Azure wrote out in full as `fd00:0:0:0:0:0:0:1`. That is a missing capability rather than a false statement, so it is not part of this release; dual-stack as a feature is tracked separately.
- **IP groups cannot hold IPv6 in the current Azure preview**, along with application rules, DNAT, IDPS, Explicit Proxy and Threat Intelligence. The viewer evaluates IPv6 entries in an IP group correctly and has tests for it, but no firewall can produce that case today.
- **A port that disagrees with the `Host` header is not modelled.** Azure drops such traffic without attributing it to any rule. The trace has no place for a rejection without a rule, so such a row still ends in the default deny like any other unmatched flow.

## [0.5.0] - 2026-09-07

Until now the viewer showed what the firewall logged and nothing else. A row said *Allow by rcg-net » rc-web » allow-web* and left the rest to you: which other rules the packet passed on the way, why the deny above did not fire, what that IP group actually contains, whether the firewall would have allowed the flow at all if the logged rule were not there.

0.5.0 adds the **policy context**: the viewer reads the firewall, its policy with the inherited parent chain, the referenced IP groups, the public IPs and the diagnostic settings from Azure Resource Manager, keeps them in a local cache, and uses them to explain the rows. Press `Enter` on a row and the dialog shows, next to the row's own fields, the path the flow took through the policy in the order Azure Firewall really uses — Threat Intelligence first, then DNAT, network and application rules by priority — with every criterion of every rule on the way marked as match, miss, or not decidable from here. What the viewer cannot know locally (service tags, FQDN tags, web categories) it marks as unknown rather than guessing. Three new tabs show the firewall, the policy tree and the IP groups; the log rows themselves gain the firewall's own addresses as `AzFw.<n>` and the IP groups a row belongs to.

All of it is one switch, `POLICY_CONTEXT`, on by default: the setup wizard asks before writing `.env`, an existing `.env` triggers a one-time notice, and with the switch off the viewer never leaves the Event Hub — no ARM requests, no Azure CLI token, no cache file, and the Logs tab looks like 0.4.1.

### Added

- **Row detail dialog with the evaluation trace.** `Enter` shows the log entry's fields on the left and, when policy context is loaded, the trace on the right: Threat Intelligence, then DNAT → Network → Application rules, inherited policy first, by priority, stopping at the logged rule. Each rule shows ✓ / ✗ / ? for source, destination, port and protocol; on *no rule matched* rows the nearest misses are marked so the failing criterion is one glance away. Collection actions are coloured tags (`deny` red, `allow` dimmed, `dnat` yellow). `Enter` unfolds a rule, `Enter` on an unfolded rule opens it in the Policy tab, `Space` folds, `a` expands everything. Threat Intelligence rows short-circuit to two lines; FlowTrace, FatFlow, DNS and IDPS rows are observations, not decisions, and get no tree.
- **Firewall tab** — a 2×2 grid: *Instance* (SKU name and tier, zones, provisioning state, resource group, subscription, location, tags, additional properties such as fat-flow logging), *Networking* (every IP configuration — IPv6 ones included — with private IP, public IP name and address, the management IP for forced tunneling, subnets and CIDRs), *Policy* (base policy, rule collection groups, Threat Intelligence mode and allowlist, DNS proxy and servers, IDPS mode with bypass and override counts, TLS inspection CA, SNAT ranges, explicit proxy, child policies) and *Logging* (the firewall's diagnostic settings with targets and category counts, plus the viewer categories that reach no Event Hub — the usual reason a category never shows up). Classic rules attached directly to the firewall are ignored on purpose.
- **Policy tab** — the rule collection groups → collections → rules as a tree, inherited parent policy first, exactly as the firewall evaluates it, with a detail pane per node. Groups open on demand, so large policies stay fast.
- **IP Groups tab** — every group with its member count and usage count and, per group, the rules that reference it; selecting a rule jumps to it in the Policy tab.
- **Enriched log rows.** Addresses inside the firewall's own subnets render as `AzFw.<last octet>` so traffic from the firewall instances (DNS proxy, probes, SNAT return traffic) stands out. The detail dialog adds the IP groups containing source and destination and the logged rule's definition with IP groups resolved to names.
- **`POLICY_CONTEXT` feature flag** (default `on`), also `--policy-context` / `--no-policy-context` per run. The setup wizard asks on every path before writing `.env`, shows the choice in the Deploy summary, and writes the key with a two-line comment explaining what it switches on. A `.env` from 0.4.x has no such key, so the viewer shows a one-time notice that says what policy context does and offers to disable it; the answer is saved to `.env`, and nothing reaches ARM before it is given.
- **Metadata cache** at `~/.az-firewall-watch/cache.json` (mode `0600`, 1 h TTL), falling back to `.azfw-cache.json` next to the binary when the home directory is not writable. It keeps itself current: a log row naming a rule the cached policy does not know triggers a re-fetch (at most every five minutes), a minute timer refreshes the cache age in the status bar and re-fetches once the TTL is over, and `Ctrl+R` forces one at any time.
- **Status bar segment** `Policy: Premium · 11 IP groups · cache 3m` next to the untouched connection status; the title shows the firewall's real, case-preserved name from ARM instead of the upper-cased one from the diagnostic records.
- **ARM client** on `DefaultAzureCredential` with a fallback to a token from the Azure CLI (`az account get-access-token`), so policy context also works when the Event Hub is read with a SAS connection string. The identity needs **Reader** on the firewall, its policy (and base policy), the IP groups and the public IPs; nothing is ever written. Every read beyond the firewall itself is optional: without ARM access the status bar says *metadata unavailable*; without rights on a public IP or the diagnostic settings only those details are missing.
- **Category presets** in the filter dropdown — *Decisions* (rules, Threat Intelligence, IDPS), *Traffic* (FlowTrace, FatFlow) and *DNS* — so a flood of FlowTrace or DNS rows is one pick away from gone, without another switch. Picking *DNS* turns the Hide-DNS toggle off for you.
- **Optional live integration tests** (`tests/live`, gated by `AZFW_LIVE_*` environment variables) against a real firewall and Event Hub; **ruff and mypy** as a lint job in CI, configured in `pyproject.toml`.
- 378 test functions (207 in 0.4.1; 527 cases with parametrisation).

### Changed

- **Row detail dialog.** Labels follow the category: *Flag*, *Rate*, *Response*, *Result* instead of *Action*; *Query type*, *Client*, *Query* for DNS rows; *Threat*, *Error* and the IDPS signature split into *Severity*, *Signature*, *Class*, *Description* instead of *More Info*. Source and destination show the address alone and the ports on one line (`47972 → 443`), so long FQDNs no longer break mid-word. FlowTrace and FatFlow rows show the connection client → server and the packet direction (SYN and SYN-ACK are certain, otherwise the ephemeral-port side is taken as the client). DNAT rows show the public destination the client hit, the ports and the translated target. Timestamps are trimmed to seconds, long values get their own line, the Close button is small and right-aligned.
- **Info column** for FlowTrace rows shows the packet direction (`server → client`) instead of Azure's boilerplate `Log Additional TCP Log`; for FatFlow rows the direction instead of `Top flow by bandwidth`. The IDPS signature is `SEV:2 · 2032081 · Potentially Bad Traffic · …`.
- **Filter bar** sits inside the Logs tab now that there are tabs, so the tab strip never moves. `q` is advertised in the footer; `Ctrl+Q` remains the alias that also works inside inputs.
- **Firewall FQDN-resolution failures** are also recognised under the Log Analytics table name `AZFWInternalFqdnResolutionFailure` (the diagnostic category stays `AZFWFqdnResolveFailure`).
- `aiohttp` is now an explicit runtime dependency (used by the ARM client).
- **Documentation restructured.** The README is now a landing page (what it does, how it works, quick start, doc index); the details moved into `docs/`: [getting-started](docs/getting-started.md), [using-the-viewer](docs/using-the-viewer.md), [policy-context](docs/policy-context.md), [configuration](docs/configuration.md), [log-categories](docs/log-categories.md), [event-hub](docs/event-hub.md) and [development](docs/development.md). `POLICY_CONTEXT` is documented in one place, the required Azure roles are collected in a single table, and the command-line options are documented at all.

### Fixed

- **Threat Intelligence rows for HTTP/HTTPS hits had an empty destination**: the firewall puts the name into `Fqdn` and leaves `DestinationIp` empty. The FQDN is shown now, like on application-rule rows.
- **Threat Intelligence and IDPS actions arrived lower-case** (`alert`, `deny`) and were the only ones rendered that way; they are capitalised like every other action.

### Known limitations

- **One firewall per session.** The policy context is loaded for the first firewall `resourceId` seen on the stream; a hub whose Event Hub carries several firewalls gets the first one's context for every row.
- **Not everything can be evaluated locally.** Service tags (`AzureMonitor`, …), FQDN tags, web categories, target URLs, the built-in infrastructure FQDNs and IP groups the identity cannot read are shown as `?`, never as a match or a miss. Network rules with FQDN targets are compared by name only when the log row itself carries an FQDN.
- **The trace explains the cached policy.** Rules changed after the last fetch are explained as they were; a log row naming an unknown rule triggers a re-fetch, and a warning in the trace says when the logged rule is missing from the cache.
- **Classic rules** attached directly to the firewall (outside a policy) are ignored, in the trace and on the Firewall tab.
- **No IPv6 support in the log parser yet.** IPv6 addresses in structured rows are shown as logged, but the legacy log parser splits `host:port` at the first colon and the filters compare substrings; a plan is in `docs/ipv6-plan.md`.

## [0.4.1] - 2026-09-05

Patch release for three findings from the GitHub Copilot review of 0.4.0.

### Fixed

- Legacy `AzureFirewallDNSResolutionFailureLog` messages without an `Error …` part crashed the parser and were counted as parse errors.
- The row index used by the detail dialog grew without bound when a restrictive filter kept rows out of the table for a long session; it now only holds rows that are actually in the table.
- `EVENT_HUB_START_POSITION` is case-insensitive (`LATEST`, `Earliest`), and any other value is passed to the SDK unchanged so a raw offset or sequence number can be used.

## [0.4.0] - 2026-09-05

New log categories (`FlowTrace`, `FatFlow`, `DnsFailure`), automatic reconnects, a much cheaper table refresh, a full test suite with CI, and a batch of bugs the tests and a lab firewall surfaced — including `earliest` never delivering events and `Escape`/`q` misbehaving in dialogs.

### Added

- **`FlowTrace` and `FatFlow` categories.** `AZFWFlowTrace` rows show the TCP flag (`SYN-ACK`, `FIN`, `RST`, `INVALID`, …) in the Action column with the log reason as rule info; `AZFWFatFlow` rows show the flow rate in Mbit/s. Both need the corresponding logging enabled on the firewall and the category in the diagnostic setting.
- **`DnsFailure` category** for FQDN resolution failures (`AZFWFqdnResolveFailure` and legacy `AzureFirewallDNSResolutionFailureLog`). These were shown as `AppRule`; they are the firewall's own DNS lookups for FQDNs in network/DNAT rules failing, so they now have their own category that the *Hide DNS* toggle does not suppress.
- **Test suite** (`tests/`, pytest) covering the structured and legacy log parser, the filter logic, rendering helpers, the Event Hub streaming worker (fake client), the GitHub update check, the dialogs, and headless Textual runs of the viewer and the whole setup wizard with the Azure CLI mocked out. Run with `pytest` after installing `requirements-dev.txt`.
- **CI workflow** `.github/workflows/test.yml` that runs the suite on Linux (Python 3.10–3.13), Windows and macOS for every push and pull request.

### Changed

- **Wizard deployment enables only the categories the viewer displays** (`VIEWER_CATEGORIES`): the three `*Aggregation` categories for Policy Analytics and `AZFWDnsAdditional` are skipped, with a note in the deployment log, since they would only add Event Hub volume.
- **Firewall name in the title bar is lower-cased.** Azure upper-cases resource IDs in diagnostic records, so `FW-HUB-GWC` becomes `fw-hub-gwc`, which matches the usual kebab-case naming.
- **Endless reconnect after a connection drop.** Once a connection has been established, a later failure (network blip, Event Hub maintenance, link detach) no longer ends in the error dialog after three attempts. The viewer keeps reconnecting with a capped backoff (2 s → 5 s → 10 s → 30 s → 60 s) and shows *Connection lost … reconnect attempt N in Ns* in the status bar until it is back. The three-attempt limit still applies to the initial connection, and authentication errors still stop immediately.
- **Incremental table updates.** New events are appended to the table and re-ordered in place instead of clearing and re-adding every row each second. With 5,000 visible rows a tick dropped from ~330 ms to ~45 ms (Python + render). The buffer merge is now O(n) instead of a full re-sort. Full rebuilds still happen on filter changes, when a second firewall policy appears (rule-info rendering changes), and periodically to trim the table back to the row limit.
- `load_env` (UTF-8 with latin-1 fallback) now lives once in `helpers.py`; the wizard and the viewer share it.

### Fixed

- **`EVENT_HUB_START_POSITION=earliest` delivered nothing.** The SDK expects `"-1"` for the beginning of the stream; the app passed `"@earliest"`, which the SDK treated as a raw offset that matched no event. Found while testing against a lab firewall.
- **Legacy `AzureFirewallDNSResolutionFailureLog` records** (category `AzureFirewallNetworkRule`) were counted as parse errors. They are now rendered like their structured counterpart `AZFWFqdnResolveFailure`: category `DnsFailure`, action `ResolveFail`, with FQDN, error text and the policy » rule collection group » rule collection » rule path.
- **Parser consistency.** Structured `AZFWDnsQuery` names no longer carry the trailing dot (`ifconfig.me.` → `ifconfig.me`, matching the legacy parser), and rows without ports (ICMP) show `-` instead of an empty port.
- **Deployment fallback categories** no longer list the non-existent `AZFWDnsProxy`; `AZFWFqdnResolveFailure` is included instead.
- **`Escape` now closes dialogs.** The app-level *Clear Filters* binding was registered with priority, which Textual resolves before modal screens — so `Escape` never reached the Detail, Update, Error or Connecting dialog. The binding is now a regular one; it still clears the filters from the main screen, including while a filter input is focused.
- **Local time on Python 3.10.** Azure timestamps carry seven fractional-second digits, which `datetime.fromisoformat` only accepts from Python 3.11 on; on 3.10 the Time column silently fell back to the raw UTC string. Fractions are now trimmed before parsing.
- **`q` inside the detail dialog no longer quits the app.** After the dialog closed, the key event bubbled on to the app's quit binding. Dialog key handlers now stop the event. Likewise `Escape` in a dialog no longer clears the filters underneath.

## [0.3.0] - 2026-05-30

This release adds passwordless Entra ID authentication, better Azure Firewall log parsing, a more polished live viewer experience, and a full Textual setup wizard.

### Added

- **Entra ID (passwordless) authentication** via `DefaultAzureCredential`, alongside the existing SAS connection string flow. Huge thanks to [@kyjones03](https://github.com/kyjones03) for providing this.
- **Full Textual setup wizard** replacing the old line-based prompts, with a grouped Welcome screen, confirmation dialogs, and a dedicated auth-method screen for choosing between Entra ID and SAS.
- **New Event Hub deployment improvements** — the wizard can create Event Hub resources, configure Azure Firewall diagnostic settings, and for Entra ID flows attempt to assign the *Azure Event Hubs Data Receiver* role.
- **Auth-rule discovery** — when SAS auth is picked, the wizard scans for a reusable Listen auth rule and only offers to create a new one, after explicit confirmation, if none exists.
- **`AZFWFqdnResolveFailure` parser** — resolution failures are surfaced as `AppRule` rows with action `ResolveFail`, including the failed FQDN and error message.
- **Hide DNS toggle** in the filter bar, enabled by default, to suppress noisy `DnsQuery` rows
- **Screenshot binding** — `Ctrl+S` saves an SVG snapshot of the current TUI view.
- **Visible-row counter** in the status bar that activates whenever a filter is in effect; the *Skipped* counter is hidden when nothing was skipped.
- **Styled rule-info segments** — Policy » RuleCollectionGroup » RuleCollection » Rule is rendered with progressively stronger styling for easier scanning.
- **New default theme** and a distinctive color for `DnsQuery` rows.

### Changed

- Legacy `AzureFirewallDnsProxy` log records are now normalized to the `DnsQuery` category so users see a single display name regardless of diagnostic mode.
- **Viewer extracted into its own `viewer/` package** with dedicated modules for the app, configuration, streaming, and update checks.
- **Setup wizard restructured** into a dedicated `setup/` package with separate modules for screens, Azure operations, services, and utilities.
- `Ctrl+P` is now reserved for **Pause/Resume**; the built-in command palette binding was removed so the shortcut also works while a filter input is focused.
- Build and runtime dependency minimums were updated to the versions required by the new wizard, viewer, and Entra ID support.

### Fixed

- DNS proxy `action` values now correctly show the DNS response code, such as `NOERROR` or `NXDOMAIN`, instead of unrelated trailing query data.
- Legacy parser data extraction was reworked for `AzureFirewallNetworkRule`, `AzureFirewallApplicationRule`, `AzureFirewallNatRule`, and `AzureFirewallDnsProxy`.
- Status-bar `visible_count` is now reset when the log table is cleared, avoiding stale `Events (filtered): N/0` output.
- Screen stack handling is now correct when the streaming worker is cancelled or fails while the *Update available* dialog is shown above the connecting splash.
- Streaming no longer leaks `DefaultAzureCredential` instances on exception paths.
- `AsyncioRequestsTransport` is used for the Entra ID credential to avoid event-loop conflicts.
- Resource Graph response parsing was fixed for the ARM permission check, and receive-permission matching now includes parent-scope role assignments.
- Several UI regressions were fixed, including row sorting, table row handling, auto-scroll behavior, clear-filter behavior, header-row selection, and the update-check naming collision with Textual’s internal `flush` method.

## [0.2.1] - 2026-05-11

### Added

- **Update check on startup** — the app checks for a newer GitHub release on launch and shows a dialog linking to the release page.
- **Version display in title bar** — the current version is read from `version.txt` and shown in the TUI title.

### Changed

- `helpers.py` and `dialogs.py` extracted from `main.py` for better maintainability.

### Fixed

- Windows crash when `.env` was saved with cp1252 encoding instead of UTF-8.

[Full diff](https://github.com/cloudchristoph/az-firewall-watch/compare/v0.2.0...v0.2.1)

## [0.2.0] - 2026-05-09

### Added

- **Row detail dialog** — press `Enter` on any log row to see all parsed fields (time UTC + local, category, protocol, source, destination, action, firewall policy, rule collection group, rule collection, rule, extra info).
- **Category colour coding** — NetworkRule, AppRule, NATRule, DnsQuery, IDPS and ThreatIntel each get a distinct colour in the table.
- **Port filter** — new filter input for destination port next to the existing filters.
- **Pause / resume** — shortcut changed to `Ctrl+P` (works even when a filter input is focused); the status bar is also clickable to toggle pause, and the paused state is shown with a distinct background colour.
- **Connection dialog** — shows namespace and hub name (never the key); keeps the spinner running after a successful probe and dismisses automatically once the first real log event arrives.
- **Error dialog** — distinguishes auth errors (bad credentials) from network errors with specific hints.

### Changed

- DnsQuery rows now show the query type (`A`, `AAAA`, `MX`, …) in the Protocol column and port `53` in the Port column.
- `»` separator used consistently across all rule types in the Policy column.
- Time column shows local time in `YYYY-MM-DD HH:MM:SS` format instead of the raw UTC ISO string.
- Status bar shows `Connected` instead of perpetual `Connected — waiting for events`.

[Full diff](https://github.com/cloudchristoph/az-firewall-watch/compare/v0.1.0...v0.2.0)

## [0.1.0] - 2026-05-09

### Added

- Initial public release: streaming TUI for Azure Firewall logs from Event Hubs with filtering, search, and prebuilt binaries for Linux (x86_64), macOS (Apple Silicon) and Windows.

[Full diff](https://github.com/cloudchristoph/az-firewall-watch/commits/v0.1.0)

[Unreleased]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.3.0
[0.2.1]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.2.1
[0.2.0]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.2.0
[0.1.0]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.1.0
