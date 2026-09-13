# IPv6 (dual-stack firewall) support — plan and status

Status: code complete on `feat/ipv6` against 0.6.0 (`2e36b67`), lab verification open · Revised 2026-09-14

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
| Flow trace / fat flow | unknown, probably | `AZFWFlowTrace`, `AZFWFatFlow` |
| Application rules, DNAT | **no** | none |
| Threat Intel, IDPS, IP Groups | **no** | none |

So the realistic scope is NetworkRule, DnsQuery, FlowTrace, FatFlow with IPv6
`SourceIp` / `DestinationIp`. Outbound traffic is SNATed to the firewall's IPv6
address unless the destination is ULA (`fc00::/7`).

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

## Legacy spelling: still unverified

`split_endpoint` accepts both `[fd00::1]:1234` and the bare `fd00::1:1234`.
Which one Azure writes in `properties.msg` for a dual-stack firewall is not
documented and has not been observed yet. The bare form is ambiguous on its own
(`fd00::1:1234` is also a complete address), so the parser prefers the port
reading because every TCP/UDP legacy endpoint carries a port. If lab records
show a third spelling, the fix is confined to `split_endpoint` and its tests.

## Open: lab verification

The lab firewall `fw-hub-gwc` is dual-stack since 2026-09-07 21:12 UTC (hub VNet
`fd10:2::/48`, `AzureFirewallSubnet` `fd10:2:0:1::/64`, public IPv6
`pip-fw-hub-gwc-ipv6-001`). No provider feature registration was needed
(`Microsoft.Network/AFWEnableIPv6` is NotRegistered and the update succeeded).

Still needed from the lab, handled in the CC-AzureLab repo:

- dual-stack spokes with a `::/0` route to the firewall's private IPv6 address,
  IPv6 network rules (allow and a targeted deny) and DNS proxy over IPv6, so
  that Allow, Deny and default-action records exist;
- raw JSON records from **both** Event Hubs (`firewall-logs`,
  `firewall-logs-legacy`) with IPv6 addresses: `AZFWNetworkRule`, `AZFWDnsQuery`,
  `AZFWFlowTrace`, `AZFWFatFlow`, and the legacy `AzureFirewallNetworkRuleLog`
  and `AzureFirewallDnsProxyLog`, exact strings, to be checked into `tests/` as
  fixtures;
- a note on which categories actually emit IPv6 (FlowTrace and FatFlow are
  unconfirmed).

Then: run the viewer against the lab, check the Source column width with mixed
v4/v6 rows on a narrow terminal, the detail dialog, a CIDR filter, and the trace
on an IPv6 `NetworkRule` row, and fix whatever the records contradict.

## Out of scope

- IPv6 for the Event Hub connection itself (SDK concern, works over whatever the OS offers).
- App rule / DNAT / IDPS / Threat Intel records with IPv6: the service does not produce them yet.
- Reverse DNS.
