# IPv6 (dual-stack firewall) support — plan and status

Status: code complete on `feat/ipv6` against 0.6.0 (`2e36b67`), verified on real records and headless viewer runs · Revised 2026-09-14

Azure Firewall can run dual-stack (IPv4 + IPv6), currently in preview:
<https://learn.microsoft.com/en-us/azure/firewall/deploy-dual-stack-firewall>

This document started as the gap analysis before any IPv6 work existed. Most of
the gaps were closed in 0.5.1 and 0.6.0 on the way; what is left here is the
record of what was found, where it was fixed, and what still has to be checked
against a real dual-stack firewall.

## What the preview supports (relevant for log content)

| Feature | IPv6 | Log category we will see |
| --- | --- | --- |
| Network rules | yes | `AZFWNetworkRule`, legacy `AzureFirewallNetworkRuleLog` |
| DNS proxy | yes | `AZFWDnsQuery`, legacy `AzureFirewallDnsProxyLog` |
| Flow trace / fat flow | **no** (confirmed 2026-09-07: 0 IPv6 in 424 FlowTrace rows, a matched IPv4/IPv6 fat-flow test sampled only IPv4) | none |
| Application rules, DNAT | **no** | none |
| Threat Intel, IDPS, IP Groups | **no** | none |

So the scope is NetworkRule and DnsQuery with IPv6 `SourceIp` /
`DestinationIp`, in both log formats; the parser handles IPv6 in FlowTrace and
FatFlow rows too, but the preview does not produce them. Outbound traffic is
SNATed to the firewall's IPv6 address unless the destination is ULA (`fc00::/7`).

## Findings and where they were fixed

| # | Finding | Fixed in | Where |
| --- | --- | --- | --- |
| 1 | Legacy parser split `host:port` at the first colon at five sites; `fd10:2:0:2::10:51000` became source `fd10`, port `2`. | 0.5.1 (`fd81707`) | `helpers.split_endpoint`, all call sites in `fw_parser._parse_legacy` |
| 2 | The garbled destination reached `_flow_from_row`, failed the address parse and ran the trace's FQDN branch: a confident wrong verdict. | 0.5.1 | follows from 1; regression test `test_flow_from_legacy_ipv6_network_rule_keeps_full_address` |
| 3 | `ip:port` rendering was ambiguous for IPv6 in the table and the detail dialog. | 0.5.1 | `helpers.format_endpoint`, `_source_text`, `_ports_join` |
| 4 | `AzFw.<n>` labels for firewall-subnet addresses. | 0.5.0 | `enrichment.resolve_fw_instance`, already v6-aware |
| 5 | Address ranges (`a-b`) in rules and IP groups were dropped silently. | 0.6.0 | `enrichment.parse_address_entries`, `find_containing_entry` |
| 6 | Filters compared substrings only: no CIDR, no match across compressed and expanded IPv6 spellings. | **this branch** | `helpers.address_matches`, `FirewallLogApp._matches` |
| 7 | No IPv6 tests for the structured parser and only range tests for the trace. | **this branch** | `tests/test_fw_parser_structured.py`, `tests/test_trace.py` |
| 8 | Docs did not mention dual-stack or the filter syntax. | **this branch** | README, `docs/using-the-viewer.md`, `docs/log-categories.md`, CHANGELOG |
| 9 | Structured `AZFWNetworkRule` rows carry IPv6 bracketed and expanded; the brackets reached the flow builder, the filters and the labels. | **this branch** | `helpers.normalise_address`, `fw_parser._ip` / `_endpoint`, fixtures in `tests/fixtures/ipv6/` |
| 10 | Legacy network-rule messages from dual-stack firewalls carry `Policy:`, which the parser skipped. | **this branch** | `fw_parser._parse_legacy` |

## Legacy spelling: confirmed

`split_endpoint` accepts both `[fd00::1]:1234` and the bare `fd00::1:1234`; which
one Azure actually writes in `properties.msg` for a dual-stack firewall was
undocumented. 63 legacy records captured against `fw-hub-gwc` on 2026-09-07
(CC-AzureLab, `firewall-mon-app/samples/ipv6/README.md`) settle it: Azure always
writes the bracketed form, `[addr]:port`, never the bare one. The address itself
is spelled differently per category — `AzureFirewallNetworkRuleLog` writes it
**fully expanded** (`[fd10:0003:0005:0001:0000:0000:0000:0004]:38238`),
`AzureFirewallDnsProxyLog` **compressed** (`[fd10:3:5:1::4]:34791`); ICMPv6
records carry no real port and write `:0`. The legacy parser needed no change
for that: the bracketed branch was already there and is now the only one
exercised in practice.

The **structured** format did need one. `AZFWNetworkRule` writes `SourceIp` and
`DestinationIp` as `[fd10:0003:0005:0001:0000:0000:0000:0004]`, bracketed and
fully expanded, and the parser passed that through unchanged: the destination
failed the address parse, the trace took the FQDN branch, CIDR filters and
`AzFw.<n>` labels never matched. `helpers.normalise_address` now strips the
brackets and compresses every IPv6 address the parser emits, structured and
legacy alike, so one flow has one spelling everywhere. The captured records live
in `tests/fixtures/ipv6/` and `tests/test_ipv6_samples.py` runs all 138 of them
through parser, flow builder, filters and labels. The same messages also carry a
`Policy:` sentence the legacy network-rule parser used to skip; it is read now.

## Open: lab verification

The lab firewall `fw-hub-gwc` is dual-stack since 2026-09-07 21:12 UTC (hub VNet
`fd10:2::/48`, `AzureFirewallSubnet` `fd10:2:0:1::/64`, public IPv6
`pip-fw-hub-gwc-ipv6-001`). No provider feature registration was needed
(`Microsoft.Network/AFWEnableIPv6` is NotRegistered and the update succeeded).

Done, in the CC-AzureLab repo (`firewall-mon-app/samples/ipv6/README.md`,
captured 2026-09-07):

- dual-stack spokes with a `::/0` route to the firewall's private IPv6 address,
  IPv6 network rules (allow and a targeted deny) and DNS proxy over IPv6, so
  that Allow, Deny and default-action records exist;
- raw JSON records from **both** Event Hubs (`firewall-logs`,
  `firewall-logs-legacy`): `AZFWNetworkRule` and `AZFWDnsQuery` carry IPv6, both
  structured and legacy (65 + 4 records each side), copied verbatim into
  `tests/fixtures/ipv6/` and exercised by `tests/test_ipv6_samples.py`;
- which categories actually emit IPv6: `AZFWNetworkRule` and `AZFWDnsQuery` do;
  `AZFWFlowTrace` and `AZFWFatFlow` confirmed **do not** in the preview (424
  IPv4 flow-trace records in a 45 min window, 0 IPv6; a controlled fat-flow test
  with matched IPv4/IPv6 load only sampled the IPv4 flow) — `Application rule`,
  `NAT`, `Threat Intel`, `IDPS` stay IPv4-only as expected.

Viewer checks, done 2026-09-14 headless (Textual `run_test`, SVG screenshots)
on the 138 fixture records plus three IPv4 rows, with a policy context shaped
like the lab's IPv6 rule collections:

- **Column width.** Addresses arrive compressed after normalisation, so the
  Source column holds `[fd10:3:5:1::4]:48812` next to `10.3.5.4:51234` and
  `AzFw.6:13590` without stretching; at 160 columns every column is visible, at
  100 columns the table scrolls horizontally exactly as it does with IPv4-only
  rows. The one wide value is the real protocol string `ICMPv6 Type=128`, which
  widens the Proto column from 5 to 15; left as logged.
- **CIDR filter.** `fd10:3::/32` in Source keeps 65 of 68 rows (the three IPv4
  rows drop out, DNS rows are hidden by the default toggle); `10.3.0.0/16` keeps
  the two IPv4 spoke rows and nothing else.
- **Trace dialog** on a `deny-ipv6-cloudflare-web` row: header
  `[fd10:3:5:1::4]:38238 → [2606:4700:4700::1111]:80 TCP Deny`, the network pass
  stops at the logged rule with source ✓ `fd10:3::/32`, destination ✓
  `2606:4700:4700::1111`, port ✓ `80`, protocol ✓ `TCP`.

Not reproducible offline and therefore still open: an `AzFw.<n>` label on an
IPv6 firewall-subnet address, because no captured record carries the hub's own
IPv6 as source or destination. A `dig @fd10:2:0:1::4` from a spoke would log the
firewall instance resolving upstream; nice to have, not blocking.

## Out of scope

- IPv6 for the Event Hub connection itself (SDK concern, works over whatever the OS offers).
- App rule / DNAT / IDPS / Threat Intel records with IPv6: the service does not produce them yet.
- Reverse DNS.
