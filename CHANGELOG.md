<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to **Azure Firewall Watch** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **IPv6 (dual-stack firewalls).** Azure Firewall can run dual-stack (preview); the viewer now handles IPv6 addresses everywhere they can appear: `NetworkRule`, `DnsQuery`, `FlowTrace` and `FatFlow` rows in both log formats, the Source column and the detail dialog (`[fd10:2:0:2::10]:51000`, so the port is not mistaken for the last address group), the `AzFw.<n>` instance labels, and the evaluation trace, which compares IPv6 flows against IPv6 prefixes in rules and IP groups exactly like IPv4 ones. Application, DNAT, IDPS and Threat Intelligence rules do not support IPv6 in the preview, so those rows stay IPv4.
- **CIDR in the Source and Dest / FQDN filters.** `10.3.0.0/16` or `fd10:2::/32` keeps only rows whose address lies inside the prefix, for IPv4 and IPv6. A full address matches in any spelling (`fd10::10` finds `fd10:0:0:0:0:0:0:10`); fragments still match as substrings.

### Fixed

- **Legacy log messages with IPv6 endpoints were parsed wrongly.** The legacy parser split `host:port` at the first colon, so `fd10:2:0:2::10:51000` became source `fd10` with port `2`, and the trace then treated the destination as an FQDN and reported a confident wrong verdict. All five split sites (network, DNAT, application, DNS proxy) now split at the last colon and accept the bracketed `[addr]:port` form as well. Which of the two spellings Azure emits is still unverified against a live dual-stack firewall; both are supported.

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
