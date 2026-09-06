<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to **Azure Firewall Watch** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release introduces Azure management-plane enrichment. The viewer now reads the firewall, policy and IP-group resources via ARM (using `DefaultAzureCredential` or the Azure CLI), so source/destination IPs and rule context can be rendered in human-friendly terms.

### Added

- **Management-plane enrichment** — viewer now reads the firewall, its policy, and any referenced IP groups via ARM REST. Works with `DefaultAzureCredential` (Entra ID) or falls back to the Azure CLI for users on SAS connection strings.
- **FwInstance.N naming** — source IPs that fall inside the firewall's own subnet are rendered as `FwInstance.<lastOctet>` so backend-instance traffic stands out from regular client traffic.
- **IP-group context in the detail dialog** — matching IP-group names are shown for source and destination, alongside the matching rule's priority, action and the policy SKU tier.
- **SKU-aware category dropdown** — `ThreatIntel` and `IDPS` are hidden from the filter dropdown when the policy SKU is Standard or Basic.
- **Persistent metadata cache** at `~/.az-firewall-watch/cache.json` (`0600`), with a 24 h TTL. Falls back to `BASE_DIR/.azfw-cache.json` when the home directory is not writable.
- **Ctrl+R — Refresh metadata** binding to force a re-fetch of firewall / policy / IP-groups, bypassing the cache.

### Changed

- `requirements.txt` now lists `aiohttp` explicitly (was previously transitive via `azure-eventhub`).

### Fixed

- _(none yet)_

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

[Unreleased]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/cloudchristoph/az-firewall-watch/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.3.0
[0.2.1]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.2.1
[0.2.0]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.2.0
[0.1.0]: https://github.com/cloudchristoph/az-firewall-watch/releases/tag/v0.1.0
