# IPv6 (dual-stack firewall) support — plan

Status: steps 1–7 implemented on `feat/ipv6` (2026-09-08), step 8 (lab verification) open · Base: 0.5.0 (`5dde806`)

Azure Firewall can now run in dual-stack mode (IPv4 + IPv6), currently in preview:
<https://learn.microsoft.com/en-us/azure/firewall/deploy-dual-stack-firewall>

az-firewall-watch has never seen an IPv6 address in a log record. This plan lists what breaks, what to change, and how to verify against the lab firewall. The 0.5.0 changelog already lists the gap under *Known limitations*.

## What the preview supports (relevant for log content)

| Feature | IPv6 | Log category we will see |
| --- | --- | --- |
| Network rules | yes | `AZFWNetworkRule`, legacy `AzureFirewallNetworkRuleLog` |
| DNS proxy | yes | `AZFWDnsQuery`, legacy `AzureFirewallDnsProxyLog` |
| Flow trace / fat flow | unknown, probably | `AZFWFlowTrace`, `AZFWFatFlow` |
| Application rules, DNAT | **no** | none |
| Threat Intel, IDPS, IP Groups | **no** | none |

So the realistic scope is NetworkRule, DnsQuery, FlowTrace, FatFlow with IPv6 `SourceIp` / `DestinationIp`. Outbound traffic is SNATed to the firewall's IPv6 address unless the destination is ULA (`fc00::/7`).

## Where the code assumes IPv4

### 1. Legacy parser splits `host:port` on the first colon — breaks completely

`fw_parser.py`, `_parse_legacy`, five split sites:

| Line | Message | Token |
| --- | --- | --- |
| 369 / 370 | `AzureFirewallNetworkRuleLog` | source **and** destination |
| 408 / 409 | `AzureFirewallNatRuleLog` | source and translated address (`words[9]`) |
| 428 | `AzureFirewallApplicationRuleLog` | source (destination already uses `rsplit(":", 1)` on 429 so FQDNs survive) |
| 502 | `AzureFirewallDnsProxyLog` | source (`words[2]`) |

Verified on 0.4.1 and unchanged on 0.5.0: `fd00:c1d0:3f1f:2::10:51000` yields source `fd00` and port `c1d0`. Worse, the garbled `fd00` then reaches `_flow_from_row`, fails `ipaddress.ip_address`, and is treated as an FQDN, so the trace evaluates the wrong thing without a warning (see 5).

Open question that decides the fix: does Azure write `[fd00::1]:1234` (bracketed) or `fd00::1:1234` (ambiguous) in legacy messages? We need real records from the lab before coding this. Plan for both:

- bracketed → strip `[`/`]` and `rsplit(":", 1)`;
- unbracketed → `rsplit(":", 1)` and validate the head with `ipaddress.ip_address`; if that fails, treat the whole token as address without port.

A single helper `split_endpoint(token) -> (ip, port)` replaces the five ad-hoc splits. Line 429 (`rsplit` for FQDN targets) is the existing precedent and becomes a test case of the helper. Tests for IPv4, bracketed IPv6, unbracketed IPv6, FQDN with dots, and no port (ICMP).

### 2. Structured parser — works, but only by accident

`SourceIp`, `DestinationIp` are plain strings and are passed through unchanged. Nothing to fix for parsing, but tests must cover IPv6 values for `AZFWNetworkRule`, `AZFWDnsQuery`, `AZFWFlowTrace`, `AZFWFatFlow`, and `QueryType=AAAA`.

### 3. Rendering `ip:port` — ambiguous for IPv6

Since 0.5.0 the row dialog is `viewer/views/detail_screen.py` (`dialogs.py` still exists but no longer holds it). Sites that join address and port:

- `detail_screen.py:35` `_ports_join(address, port)` — used for the DNAT *Translated* field (161) and both sides of the FlowTrace/FatFlow *Flow* line (210/211). This is the one central helper; give it the IPv6 branch (`[fd00::1]:1234`) and the *Packet* line (219/221) stays address-only and needs nothing.
- `viewer/app.py:575` `_source_text` renders `sourceip + ":" + srcport` in the table. Its input is already `self._format_ip(row.sourceip)` (463), i.e. `AzFw.<n>` for firewall-subnet addresses, so the bracket decision must be made on the *original* address, not the label: bracket when the raw `row.sourceip` parses as `IPv6Address`, whatever `_format_ip` turned it into.

`format_endpoint(ip, port)` in `helpers.py` serves both; `_ports_join` becomes a thin wrapper or is replaced.

### 4. `AzFw.<n>` labels — already done

`viewer/enrichment.py:resolve_fw_instance` parses the address, distinguishes v4/v6 and uses the last 16 bits as hex for IPv6, with a comment explaining why the label is derived from the parsed value. Nothing to do here beyond one test with an IPv6 firewall subnet CIDR, which already exists in `tests/test_enrichment_match.py` (`test_resolve_fw_instance_ipv6_uses_last_hextet`).

### 5. Evaluation trace — structurally v6-capable, zero IPv6 tests

`viewer/trace.py` (new in 0.5.0) matches addresses with `ipaddress.ip_address` / `ip_network(strict=False)` (132–162), so an IPv6 flow against an IPv6 rule prefix works, a v4 address against a v6 prefix is a clean MISS, and wildcards / service tags behave as for v4. `_flow_from_row` (`app.py:731`) passes the raw row IPs, not the `AzFw` labels, so the trace sees real addresses.

Why this ranks above rendering: a wrong assumption here does not crash, it shows a confident ✓ or ✗ on a rule that in truth does not apply. Needed tests in `tests/test_trace.py`:

- network rule with `source_addresses=["fd00:c1d0:3f1f::/48"]` and an IPv6 flow → MATCH; v4 flow → MISS;
- rule with mixed v4 and v6 prefixes;
- IP group containing IPv6 prefixes (the service does not support them yet, but the code path must not blow up);
- `*` wildcard with an IPv6 flow;
- an IPv6 flow against the lab-shaped policy fixture (`LAB`) to confirm the *nearest miss* logic reports the address, not the port;
- a garbled legacy address (`fd00`), one case per direction, because source and destination fail differently:
  - **destination** — `_flow_from_row` (`app.py:731`) decides `is_fqdn` by `ipaddress.ip_address(target)`; on `fd00` the parse fails, the flow enters the trace with `dst_fqdn="fd00"` and empty `dst_ip`, and the destination check runs against `targetFqdns` instead of address ranges. That is a confident wrong verdict, not a `?`. The test must assert that the destination check does *not* take the FQDN branch, otherwise this regression stays invisible.
  - **source** — `src_ip` is passed through unchanged, `trace.py:_parse_ip` returns `None` on `ValueError`, and `_address_check` answers `NA, "no address in log"`. Wrong, but honest: no match and no miss is claimed.
  Both cases document today's failure mode and turn into the fixed behaviour once step 1 lands.

### 6. Column width

IPv6 addresses are up to 39 characters, plus brackets and port up to 47. Check DataTable auto-width behaviour with mixed rows; if the table becomes unreadable on narrow terminals, use `IPv6Address.compressed` (Azure may already emit compressed form; verify with lab data).

### 7. Filters

`_matches` (`app.py:637`) does a case-insensitive substring match on `sourceip` / `targetip`. That works for IPv6 as-is, but the user experience is poor:

- Typing `fd00:c1d0:3f1f:2::10` will not match if Azure emits the uncompressed form (or the other way round). Normalise both sides with `ipaddress.ip_address(...).compressed` when the value parses as an address; fall back to substring otherwise.
- Prefix filtering: accept a CIDR (`fd00:c1d0::/32`, also `10.0.0.0/8`) in the Source and Dest filters and match with `ip_network(..., strict=False)`. This is the one genuinely new feature in the branch and is useful for IPv4 too.

Filter placeholder texts stay as they are.

The trace is where the CIDR filter and the compressed/expanded normalisation meet again: `_address_check` already does `ip in ip_network(...)`. One shared helper (`normalise_address` / `address_in_prefix` in `helpers.py`) serves both the filter and the trace rather than two implementations.

### 8. Firewall tab and setup wizard

The Firewall tab already lists IPv6 ip-configurations (0.5.0 changelog). `setup/` only deals with Event Hub, diagnostic settings and categories; nothing to change.

### 9. Docs

- README: note that dual-stack firewalls are supported, which categories carry IPv6 in the preview, and the CIDR filter syntax.
- CHANGELOG `Unreleased`: Added (IPv6 endpoints, CIDR filter, trace coverage), Fixed (legacy parser on IPv6); remove the *Known limitations* entry from 0.5.0's successor.

## Work breakdown

Ordered so each step is independently mergeable and testable without lab access, except the last one.

1. **Endpoint helpers + tests** — `split_endpoint`, `format_endpoint` in `helpers.py`, pure functions, full coverage for IPv4/IPv6/bracketed/FQDN/no-port.
2. **Trace tests with IPv6** — the list in 5; expected to pass without code changes, and if not, fix `trace.py` first.
3. **Legacy parser on helpers** — replace the five split sites; tests with synthetic IPv6 messages in both candidate formats, marked as unverified until lab records exist.
4. **Structured parser tests** — IPv6 fixtures for NetworkRule, DnsQuery (AAAA, IPv6 source), FlowTrace, FatFlow. No code change expected.
5. **Rendering** — `_ports_join` and `_source_text` via `format_endpoint`, respecting the `_format_ip` order; assertions in `test_views.py` / `test_app_filtering.py`.
6. **Filter normalisation + CIDR** — `_matches` gains address-aware matching; tests for compressed vs. expanded input, CIDR v4/v6, and plain substring fallback (FQDNs in Dest).
7. **Docs + changelog.**
8. **Lab verification** — run against `fw-hub-gwc` once it is dual-stack: confirm legacy format, confirm which categories actually emit IPv6, capture the raw records into `tests/` fixtures, and fix whatever step 3 guessed wrong.

Steps 1–7 are done on `feat/ipv6`: the helpers live in `ip_utils.py` (`split_endpoint`, `format_endpoint`, `address_matches`, `parse_address`, `parse_network`), the legacy parser, the table, the detail dialog, the filters and the trace all go through them, and `tests/test_ip_utils.py` plus IPv6 cases in the parser, filter, dialog, view and trace suites cover both candidate legacy spellings. Step 8 waits for the lab records; whichever spelling turns out wrong is a one-line change in `split_endpoint` and its tests.

## Lab prerequisites (CC-AzureLab)

- **Done (2026-09-07 21:12 UTC):** hub VNet `vnet-hub-gwc` has `fd10:2::/48`, `AzureFirewallSubnet` has `fd10:2:0:1::/64`, and `fw-hub-gwc` carries a second ip-config with the public IPv6 `pip-fw-hub-gwc-ipv6-001` (`2603:1020:c01:16::275`). Verified with `az network firewall show` on 2026-09-08.
- **No feature registration needed.** `Microsoft.Network/AFWEnableIPv6` is `NotRegistered` on `cclab-connectivity` and the dual-stack update succeeded anyway; the Learn article lists no registration step either. An earlier revision of this plan claimed the opposite.
- Dual-stack spokes with a `::/0` UDR to the firewall's private IPv6 address.
- IPv6 network rules (allow + targeted deny) and DNS proxy over IPv6. The lab session reports five IPv6 rules live in the policy; whether `firewall-policy-management/local.ipv6.tf` tracks them is unresolved and blocks other applies there until a `terraform plan` settles it.
- Diagnostic settings unchanged; both Event Hubs (`firewall-logs`, `firewall-logs-legacy`) receive the records.
- The upgrade to dual-stack cannot be reverted in the preview; Christoph approves the `terraform plan` explicitly before apply.

Deliverable from the lab: raw JSON records (structured and legacy) with IPv6 addresses, to be checked into `tests/` as fixtures.

## Out of scope

- IPv6 for the Event Hub connection itself (SDK concern, works today over whatever the OS offers).
- App rule / DNAT / IDPS / Threat Intel records with IPv6 — the service does not produce them yet. Revisit when the preview widens.
- Reverse DNS.
