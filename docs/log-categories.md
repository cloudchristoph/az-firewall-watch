# Log categories

Both log formats Azure Firewall produces are parsed: the **legacy**
(single-message) and the **structured** (typed JSON) diagnostic categories. Legacy
`AzureFirewallDnsProxy` entries are normalised into the `DnsQuery` category, so you
deal with one display name regardless of which diagnostic mode is enabled.

## What is shown

| Category shown | Azure category (structured / legacy)                                                              |
| -------------- | ------------------------------------------------------------------------------------------------- |
| NetworkRule    | `AZFWNetworkRule` / `AzureFirewallNetworkRule`                                                    |
| AppRule        | `AZFWApplicationRule` / `AzureFirewallApplicationRule`                                            |
| NATRule        | `AZFWNatRule` / `AzureFirewallNatRuleLog`                                                         |
| DnsQuery       | `AZFWDnsQuery` / `AzureFirewallDnsProxy`                                                          |
| DnsFailure     | `AZFWFqdnResolveFailure` / `AzureFirewallDNSResolutionFailureLog`: the firewall could not resolve an FQDN used in a network or DNAT rule; action `ResolveFail`, with FQDN and error |
| IDPS           | `AZFWIdpsSignature`                                                                               |
| ThreatIntel    | `AZFWThreatIntel`                                                                                 |
| FlowTrace      | `AZFWFlowTrace`: TCP flow flags (`SYN-ACK`, `FIN`, `RST`, `INVALID`, …) in the Action column      |
| FatFlow        | `AZFWFatFlow`: top flows by bandwidth, rate in Mbit/s in the Action column                       |

Unknown or non-firewall categories (for example the Policy Analytics
`*Aggregation` logs) are counted in the status bar as *skipped* rather than
displayed.

> [!NOTE]
> **Reading FatFlow rows.** Records are sampled every 3 minutes, and rates well
> below 1 Mbit/s do appear. Most records describe the return direction, i.e.
> `<internet>:443 → <firewall instance>:<SNAT port>`, so the spoke client often
> shows up only as the destination, or not at all.

## Enabling flow trace and fat flow

`FlowTrace` and `FatFlow` need the corresponding logging switched on at the
firewall, *in addition* to the category in the diagnostic setting:

```bash
# Top flows (fat flow): flows above 1 Mbit/s, sampled every 3 minutes
az network firewall update --ids <firewall-resource-id> --enable-fat-flow-logging true
```

Flow trace additionally requires the preview feature
`AFWEnableTcpConnectionLogging` to be registered on the subscription first, see
[Azure Firewall flow trace logs](https://learn.microsoft.com/azure/firewall/monitor-firewall-reference#flow-trace).

Both are troubleshooting features and add real volume to the Event Hub; leave them
off during normal operation.

## Filtering the noise

Once several categories are flowing, the **Traffic** and **Decisions** presets in
the Category dropdown are the fastest way to separate observations from verdicts,
see [category presets](using-the-viewer.md#category-presets).
