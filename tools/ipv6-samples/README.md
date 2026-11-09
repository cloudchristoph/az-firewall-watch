# IPv6 log samples from `fw-hub-gwc` (dual-stack preview)

Capture tooling and findings behind `tests/fixtures/ipv6/`, moved here from the lab repo in 2026-10.
The captured records themselves live in `tests/fixtures/ipv6/`.

Raw JSON records with IPv6 addresses, captured from **both** Event Hubs of `ehns-fw-gwc`
(`rg-hub-firewallmon-gwc`, subscription `cclab-connectivity`), for the IPv6
work in this repo. The strings are kept **verbatim** — no anonymisation —
because the exact legacy `msg` format (`[fd10::1]:1234` vs `fd10::1:1234`) decides the parser.

| Event Hub | Diagnostic setting | Format | Categories expected to carry IPv6 |
| --- | --- | --- | --- |
| `firewall-logs` | `firewall-diagnostics-to-eventhub` (Terraform) | structured `AZFW*` | `AZFWNetworkRule`, `AZFWDnsQuery`, `AZFWFatFlow`, `AZFWFlowTrace`\* |
| `firewall-logs-legacy` | `firewall-diagnostics-legacy-test` (Terraform, imported) | legacy `AzureFirewall*` (`properties.msg`) | `AzureFirewallNetworkRuleLog`, `AzureFirewallDnsProxyLog` |

\* `AZFWFlowTrace` turned out to be emitted (IPv4) although `AFWEnableTcpConnectionLogging` is not
registered on this subscription. `AZFWApplicationRule`, `AZFWNatRule`, `AZFWThreatIntel` and
`AZFWIdpsSignature` cannot contain IPv6 in the preview (those engines are IPv4-only). Actual
results per category: see the findings table below.

## Layout

```
tools/ipv6-samples/
├── README.md                  (this file — fill in the findings table below after capture)
├── collect_ipv6_samples.py    (capture script)
├── structured/<Category>.jsonl   one raw record per line, exactly as received
└── legacy/<category>.jsonl
```

## Capturing

1. Bring the lab up (firewall dual-stack, `fw-demo-baseline` running) and generate traffic with the
   commands in [`docs/adr/001-ipv6-dual-stack.md` §8 of the private lab repo CC-AzureLab.
2. Get the Listen connection strings (both hubs have a `firewall-mon-listen` rule managed by the
   connectivity stack):

   ```bash
   export EH_STRUCTURED_CONN="$(terraform -chdir=<CC-AzureLab>/platform/connectivity output -raw firewall_mon_eventhub_listen_connection_string)"
   export EH_LEGACY_CONN="$(terraform -chdir=<CC-AzureLab>/platform/connectivity output -raw firewall_mon_eventhub_legacy_listen_connection_string)"
   ```

3. Run the collector (reads from the start of retention, filters on IPv6 literals, writes JSONL):

   ```bash
   python3 -m venv .venv && . .venv/bin/activate && pip install azure-eventhub
   python3 collect_ipv6_samples.py --minutes 120 --out .
   ```

   Use `--from-latest` and leave it running while you generate traffic if you prefer a live capture.

4. Review, then fill in the table below and copy the `.jsonl` files into
   `tests/fixtures/ipv6/`.

## Findings (captured 2026-09-07, `fw-hub-gwc` Premium, dual-stack)

| Category | Hub | IPv6 records | Address / port format | Notes |
| --- | --- | --- | --- | --- |
| `AZFWNetworkRule` | structured | **yes** — Allow (`allow-ipv6-web`, `allow-ipv6-ifconfig-me`, `allow-ipv6-lab-internal`, `allow-ipv6-icmp-internet`), explicit Deny (`deny-ipv6-cloudflare-web`), default Deny (`Rule` empty) | `SourceIp`/`DestinationIp` are **bracketed and fully expanded**: `[fd10:0003:0005:0001:0000:0000:0000:0004]`; `SourcePort`/`DestinationPort` separate columns | `Protocol` is `TCP` or `ICMPv6 Type=128`; ICMP has `DestinationPort = 0` |
| `AZFWDnsQuery` | structured | **yes** — client queries sent to the firewall's IPv6 (`dig @fd10:2:0:1::4`) | `SourceIp` plain **compressed** `fd10:3:5:1::4`, `SourcePort` separate | `QueryType` `A`/`AAAA`, `Protocol` `udp`/`tcp`. AAAA queries via the IPv4 proxy address log the IPv4 source, plus the firewall instances (10.2.0.5/.6) resolving `ifconfig.me AAAA` for the FQDN network rule |
| `AZFWFatFlow` | structured | **no** | | Controlled test 2026-09-07 10:11–10:18 UTC: an IPv6 flow and an IPv4 flow from the same VM, same source site, same rate (~10 Mbit/s, 7 min). The IPv4 flow (`80.249.99.148:80 → 10.2.0.6`) appears in two consecutive 3-minute samples, the IPv6 flow never does. Fat-flow logging itself was verified on (it had been switched off by the runbook's `Set-AzFirewall` after `Allocate()`; fixed). The preview evidently does not sample IPv6 flows |
| `AZFWFlowTrace` | structured | **no** (424 IPv4 records in the same 45 min, 0 with IPv6) | | logs exist although `AFWEnableTcpConnectionLogging` is not registered on the subscription |
| `AZFWApplicationRule`, `AZFWNatRule`, `AZFWThreatIntel`, `AZFWIdpsSignature` | structured | **no** | | engines are IPv4-only in the preview |
| `AzureFirewallNetworkRule` (category `AzureFirewallNetworkRule`, `msg`) | legacy | **yes** (63 records, same Allow/Deny/default mix) | `[addr]:port`, address **fully expanded**: `TCP request from [fd10:0003:0005:0001:0000:0000:0000:0004]:38238 to [2606:4700:4700:0000:0000:0000:0000:1111]:80. Action: Deny.` | ICMPv6: `ICMPv6 Type=128 request from [fd10:0003:0005:0001:0000:0000:0000:0004]:0 to [2606:4700:4700:0000:0000:0000:0000:1111]:0. Action: Allow.` — port written as `:0` |
| `AzureFirewallDnsProxy` (category `AzureFirewallDnsProxy`, `msg`) | legacy | **yes** | `[addr]:port`, address **compressed**: `DNS Request: [fd10:3:5:1::4]:34791 - 43650 AAAA IN ifconfig.me. udp 52 false 1232 NOERROR qr,aa,rd,ra 68 0.000092102s` | |

Parser consequences for az-firewall-watch:

1. Endpoints are always bracketed for IPv6 → `split_endpoint()` can rely on `[`…`]:port`; bare `addr:port` was never observed.
2. The same address appears expanded (`fd10:0003:0005:0001:0000:0000:0000:0004`) in NetworkRule and compressed (`fd10:3:5:1::4`) in DnsQuery/DnsProxy → normalise with `ipaddress.IPv6Address(...).compressed` before comparing or filtering, and strip brackets in the **structured** `SourceIp`/`DestinationIp` too.
3. Structured `Protocol` for ICMPv6 is `ICMPv6 Type=128`, not `ICMP`.

`summarize_samples.py` prints these counts and the endpoint spelling for any capture.
