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
> `<internet>:443 → <firewall instance>:<SNAT port>`, so in the table the spoke
> client often shows up only as the destination, or not at all. Open the row with
> `Enter`: the dialog reads the direction and shows the connection as
> `client → server` regardless of which way the logged packet went.

## Enabling flow trace and fat flow

`FlowTrace` and `FatFlow` need the corresponding logging switched on at the
firewall, *in addition* to the category in the diagnostic setting. They work
differently, so the two are not interchangeable.

**Fat flow** is a property of the firewall resource:

```bash
# Top flows (fat flow): flows above 1 Mbit/s, sampled every 3 minutes
az network firewall update --ids <firewall-resource-id> --enable-fat-flow-logging true
```

Microsoft documents the same switch as `EnableFatFlowLogging` via
`Set-AzFirewall`, which is the path to use if the `azure-firewall` CLI extension
is not available to you.

**Flow trace** is *not* a firewall property. It is a subscription-level provider
feature, and trying to set it as an additional property on the firewall is
rejected:

```powershell
Register-AzProviderFeature -FeatureName AFWEnableTcpConnectionLogging -ProviderNamespace Microsoft.Network
Register-AzResourceProvider -ProviderNamespace Microsoft.Network
```

Registration takes several minutes. Perform any update on the firewall afterwards
to make it take effect immediately. In the portal the same switch is called
**Enable TCP Connection Logging**. To turn it off again, use
`Unregister-AzProviderFeature` followed by another firewall update.
→ [Azure Firewall flow trace logs](https://learn.microsoft.com/azure/firewall/monitor-firewall-reference#flow-trace)

> [!NOTE]
> Flow trace covers traffic evaluated by **network and NAT rules** (layer 3/4).
> Application rule traffic (layer 7) never shows up in `FlowTrace` rows, so use
> the `AppRule` category for that.

Both are troubleshooting features and add real volume to the Event Hub; leave them
off during normal operation.

## Two names for the same thing

If you also route these logs to a Log Analytics workspace, be aware that the
diagnostic **category** and the resulting **table** are not always named alike.
The FQDN resolution failures are the one case where they differ:

| Diagnostic category (what this viewer sees) | Log Analytics table (what KQL queries) |
| ------------------------------------------- | -------------------------------------- |
| `AZFWFqdnResolveFailure`                    | `AZFWInternalFqdnResolutionFailure`     |

A KQL query against `AZFWFqdnResolveFailure` fails with `SEM0100` because no such
table exists, and a diagnostic setting for `AZFWInternalFqdnResolutionFailure` is
equally invalid. Every other category keeps its name as the table name.

The parser accepts both spellings, so a record arriving under either name is
rendered as a `DnsFailure` row. What you put in the diagnostic setting still has
to be `AZFWFqdnResolveFailure`, since that is the only one Azure offers there.

> [!NOTE]
> `NATRule` rows only appear when a DNAT rule actually matches. A firewall with
> DNAT rules that nothing hits produces no `AZFWNatRule` records at all, so an
> empty category is not necessarily a configuration mistake.

## Filtering the noise

Once several categories are flowing, the **Traffic** and **Decisions** presets in
the Category dropdown are the fastest way to separate observations from verdicts,
see [category presets](using-the-viewer.md#category-presets).
