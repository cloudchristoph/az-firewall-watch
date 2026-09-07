<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to **Azure Firewall Watch** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.5.0] - 2026-09-07

**Policy context.** The viewer now reads the firewall, its policy, the referenced IP groups, the public IPs and the diagnostic settings from Azure Resource Manager and uses them to explain what the log rows show: which rule matched, why the near misses missed, what the firewall is configured to do, and which log categories never reach the Event Hub. Everything beyond the Event Hub sits behind one switch, `POLICY_CONTEXT`, on by default and asked about once.

### Added

- **Firewall tab** — a 2×2 grid of *Instance* (SKU name and tier, zones, provisioning state, resource group, subscription, location, tags, additional properties such as fat-flow logging), *Networking* (every IP configuration with private IP, public IP name and address, the management IP for forced tunneling, subnets and CIDRs), *Policy* (base policy, rule collection groups, Threat Intelligence mode and allowlist, DNS proxy and servers, IDPS mode with bypass and override counts, TLS inspection CA, SNAT ranges, explicit proxy, child policies) and *Logging* (the firewall's diagnostic settings with their targets and category counts, plus the viewer categories that are not forwarded to any Event Hub — the usual reason a category never shows up). Classic rules attached directly to the firewall are ignored on purpose.
- **Policy tab** — a tree of rule collection groups → collections → rules (inherited parent policy first, exactly as the firewall evaluates it) with a detail pane; groups open on demand, so large policies stay fast.
- **IP Groups tab** — every group with its usage count and, per group, the rules that reference it; selecting one jumps to that rule in the Policy tab.
- **Evaluation trace in the row detail dialog.** `Enter` on a log row shows the entry's fields on the left and, when policy context is loaded, the path the row took through the policy on the right — in Azure Firewall's real processing order: Threat Intelligence, then DNAT → Network → Application rules, inherited policy first, by priority, stopping at the logged rule. Every criterion (source, destination, port, protocol) is marked ✓ / ✗ / ? per rule, so near misses on *no rule matched* rows show exactly what failed; what cannot be evaluated locally (service tags, FQDN tags, web categories, target URLs, unreadable IP groups) is marked `?`, never guessed. Collection actions are coloured tags (`deny` red, `allow` dimmed, `dnat` yellow). `Enter` unfolds a rule, `Enter` on an unfolded rule opens it in the Policy tab, `Space` folds, `a` expands the whole tree. Threat Intelligence rows short-circuit to two lines; observation rows (FlowTrace, FatFlow, DNS, IDPS) get no tree and the status bar says why.
- **Enriched log rows.** Addresses inside the firewall's own subnets render as `AzFw.<last octet>` so traffic from the firewall instances (DNS proxy, probes, SNAT return traffic) stands out. The detail dialog adds the IP groups containing source and destination and the logged rule's definition with IP groups resolved to names.
- **Detail dialog per category.** Labels say what a value really is: *Flag*, *Rate*, *Response*, *Result* instead of *Action*; *Query type*, *Client*, *Query* for DNS; *Threat*, *Error*, and the IDPS signature split into *Severity*, *Signature*, *Class*, *Description*. FlowTrace and FatFlow rows show the connection client → server and the packet direction (SYN and SYN-ACK are certain, otherwise the ephemeral-port side is the client); DNAT rows show the public destination the client hit, the ports, and the translated target. Timestamps are trimmed to seconds, long values get their own line.
- **`POLICY_CONTEXT` feature flag** (default `on`). The setup wizard asks on every path before writing `.env`; `--policy-context` / `--no-policy-context` override it per run. With policy context off the viewer never leaves the Event Hub: no ARM requests, no Azure CLI token, no cache file, Logs tab only. A `.env` from 0.4.x has no such key, so the viewer shows a one-time notice that says what policy context does and offers to disable it; the answer is saved to `.env`. Nothing reaches ARM before that notice is answered.
- **Metadata cache** at `~/.az-firewall-watch/cache.json` (mode `0600`, 1 h TTL), falling back to `.azfw-cache.json` next to the binary when the home directory is not writable. The cache keeps itself current: a log row naming a rule the cached policy does not know triggers a re-fetch (at most every five minutes), a minute timer refreshes the cache age in the status bar and re-fetches once the TTL is over, and `Ctrl+R` forces one at any time.
- **Status bar metadata segment** — `Policy: Premium · 11 IP groups · cache 3m` — next to the untouched connection status; the title shows the firewall's real, case-preserved name from ARM.
- **ARM client** on `DefaultAzureCredential` with a fallback to a token from the Azure CLI (`az account get-access-token`), so policy context also works when the Event Hub itself is read with a SAS connection string. Every extra read is optional: without ARM access the status bar says *metadata unavailable* and the viewer behaves like 0.4.x; without rights on a public IP or the diagnostic settings only those details are missing.
- **Category presets** in the filter dropdown — *Decisions* (rules, Threat Intelligence, IDPS), *Traffic* (FlowTrace, FatFlow) and *DNS* — so a flood of FlowTrace or DNS rows is one pick away from gone, without another switch. Picking *DNS* turns the Hide-DNS toggle off for you.
- **Optional live integration tests** (`tests/live`, gated by `AZFW_LIVE_*` environment variables) against a real firewall and Event Hub, and **ruff + mypy** as a lint job in CI with their configuration in `pyproject.toml`.
- 378 test functions (207 in 0.4.1; 527 cases with parametrisation) across the ARM client, resource parsing, cache, matching, trace, orchestration, the tabs, the dialogs, the feature flag and the wizard.

### Changed

- **One dialog for a row.** `Enter` shows fields and trace together; the separate trace key `t` is gone. With the trace beside them, the fields no longer repeat the policy path, priorities and action, and the *Policy SKU* row is gone everywhere (the status bar carries it).
- **Filter bar** lives inside the Logs tab, so the tab strip no longer jumps when switching tabs. `q` is advertised in the footer; `Ctrl+Q` remains the alias that also works inside inputs.
- **Row info column.** FlowTrace rows show the packet direction (`server → client`) instead of Azure's `Log Additional TCP Log`, FatFlow rows the direction instead of `Top flow by bandwidth`; Threat Intelligence rows show the FQDN of HTTP/HTTPS hits as destination (was empty); Threat Intelligence and IDPS actions are capitalised (`Alert`, `Deny`) like every other action; the IDPS signature is `SEV:2 · 2032081 · Potentially Bad Traffic · …`.
- **Firewall FQDN-resolution failures** are also recognised under the Log Analytics table name `AZFWInternalFqdnResolutionFailure` (the diagnostic category stays `AZFWFqdnResolveFailure`).
- **Trace header** shows the flow on one line and the verdict on the next, each led by a symbol.
- `aiohttp` is now an explicit runtime dependency (used by the ARM client).
- **Documentation restructured.** The README is now a landing page (what it does, how it works, quick start, doc index); the details moved into `docs/`: [getting-started](docs/getting-started.md), [using-the-viewer](docs/using-the-viewer.md), [policy-context](docs/policy-context.md), [configuration](docs/configuration.md), [log-categories](docs/log-categories.md), [event-hub](docs/event-hub.md) and [development](docs/development.md). `POLICY_CONTEXT` is documented in one place instead of four, the required Azure roles are collected in a single table, and the command-line options are documented at all.

### Fixed

- **Application rules lost their targets**: ARM names them `targetFqdns`, the parser read `destinationFqdns`. The trace showed `destination: … not in –` and the rule definition `to any` for every application rule; both names are read now.
- **HTTPS matched Http-only rules** in the trace because protocols were compared by prefix; they are compared by name now, and a `Http, Https` rule reports the protocol that actually matched.
- **DNAT rows were marked as misses on their own rule**: `AZFWNatRule` logs the translated target, the rule matches the public one. The row keeps both; the trace evaluates the public destination and port.
- **A network rule with FQDN targets** reported *no address in log* for application-rule rows; it now compares the logged FQDN with the rule's FQDNs.
- **The first event closed the wrong dialog**: the connecting splash was removed by popping the topmost screen, which dismissed the update or policy-context notice and left the splash behind. The splash now sits beneath start-up dialogs and is removed from wherever it is.
- **Consent came second**: the metadata load could start while the first-run notice was still open. The firewall id seen during the dialog is parked and loaded only after *Keep enabled*.
- **Logs-only mode** (`POLICY_CONTEXT=off`) crashed on `c`, `Escape` and `f`, which queried tabs that were never composed.
- The cache treats malformed-but-valid JSON as a miss and resets it, tolerates a read-only file on invalidation, and stores its temp file and directory with private permissions; the ARM client raises a proper error on non-JSON 2xx bodies and on non-object error payloads; duplicate keys in `.env` collapse on update.
- The logged verdict survives when the logged rule is missing from the cached policy (with a warning that suggests `Ctrl+R`); overruled matches are downgraded to `?`; Rich markup in ARM-provided names is escaped everywhere; rule references are qualified with the policy name so inherited chains cannot collide.

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
