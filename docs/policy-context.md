# Policy context

Policy context is the viewer's second data source: alongside the log stream from
the Event Hub, it reads the firewall, its policy and the referenced IP groups from
**Azure Resource Manager (ARM)**. That turns log rows from "something was denied"
into "this rule denied it, here is what the rule says, and here is everything the
firewall evaluated before it".

It is **read-only**, **on by default**, and can be switched off completely
(see [Turning it off](#turning-it-off)).

No configuration is needed to point it at your firewall: the viewer takes the
resource ID from the first log record it receives and fetches from there.

## What you get

### Three extra tabs

- **Firewall**: four blocks about the instance itself.
  - *Instance*: SKU tier and name, zones, provisioning state, how the firewall
    scales (service default, prescaled range, or fixed capacity with autoscaling
    off), the customer-controlled maintenance window if one is assigned, resource
    group, subscription, location, tags.
  - *Networking*: a table with one row per IP configuration, each with its
    private IP and the name and address of its public IP, plus the management IP
    when the firewall uses forced tunnelling. Underneath: subnets, their CIDRs,
    whether forced tunnelling is on, and whether a NAT gateway sits on the
    firewall subnet. With a gateway, outbound traffic leaves with the gateway's
    public IPs while DNAT and management traffic stay on the firewall's own, and
    the line says so.
  - *Policy*: the attached policy with its number of rule collection groups
    including inherited ones, base policy, Threat Intelligence mode and allowlist,
    DNS proxy and its servers, IDPS mode with bypass and override counts, TLS
    inspection with the CA name, SNAT ranges with the auto-learn state and its
    Route Server, explicit proxy with its ports and PAC file, child policies.
  - *Logging*: a table of the firewall's diagnostic settings, each with its
    target (Event Hub, Log Analytics, Storage) and how many categories it
    forwards, including how many of those the viewer understands. Below it, a
    **Not to Event Hub** line names the categories this viewer understands that
    no setting forwards at all. That line answers the most common question about
    a missing category before you start looking for a bug.
- **Policy**: a tree of rule collection groups → rule collections → rules, ordered
  by priority, with a detail pane showing sources, destinations, ports, protocols,
  IP groups resolved to their actual addresses and, on application rules, TLS
  inspection and the HTTP headers the rule inserts. Header names are always shown;
  the values can carry tokens or tenant ids, so they stay hidden until you press
  `v`, and a refresh hides them again.
- **IP Groups**: every IP group the policy references, how many rules use it, and
  for the selected group the rules that reference it. `Enter` on a rule jumps to it
  in the Policy tab.

![The Firewall tab in four blocks: Instance, Networking, Policy and Logging, the last one ending in the Not to Event Hub line. Subscription ID and public IP addresses are blacked out](images/firewall-tab.png)

![The Policy tab: rule collection groups and collections in priority order on the left, the selected rule's definition on the right](images/policy-tab.png)

![The IP Groups tab: every group with its entry and usage count, and the rules that reference the selected group](images/ip-groups-tab.png)

### Richer log rows

The metadata also feeds back into the **Logs** tab:

- Addresses inside the firewall's own subnets are rendered as `AzFw.<last octet>`,
  so traffic from the firewall instances themselves (DNS proxy, probes) stands out.
- The row detail dialog lists the IP groups that contain source and destination
  and the definition of the rule the firewall logged, looked up by name, never
  guessed. Whatever the trace beside it already shows (policy path, priorities,
  action, SKU) is left out rather than printed twice.
- The status bar shows a short summary: `Policy: Premium · 11 IP groups · fresh`.

## Evaluation trace

Press `Enter` on a log row to open its details with the trace beside them: the path
that flow took through the policy, in the order Azure Firewall actually uses.
Threat Intelligence first, then three passes over all rule collection groups
(DNAT, Network, Application), each in inherited-policy-first, then priority order,
stopping at the first match. The Application pass only runs for HTTP, HTTPS and
MSSQL flows.

![The detail dialog: the log entry's fields on the left, the evaluation trace on the right, ending at the rule the firewall logged](images/evaluation-trace.png)

The log entry's own fields sit on the left, the trace on the right. Each pass
reports its own verdict (`✓ matched`, `✗ no match`, `? no certain match`), and
under it the rule collection groups with their collections in priority order.
The collection's own action is the short tag after its name (`deny` in red,
`allow` quiet, `dnat` in yellow): the ✓ or ✗ in front says whether the flow
matched, the tag says what a match would have meant. Collections that did not
match name their nearest miss, so you can see how close each one came.

### What you are looking at

Everything before the logged rule was really evaluated and rejected by the
firewall. That part is fact, taken from the policy and the firewall's own verdict.
*Why* each rule failed is computed locally, criterion by criterion.

For `Deny · no rule matched` rows the whole path is computed, and the near misses
show which criterion failed, for example `port: 8443 not in 443`. That is usually
the fastest way to find the rule you *meant* to write.

### What `?` means

`?` marks criteria that cannot be evaluated locally, so the trace neither confirms
nor rejects them:

- service tags such as `AzureMonitor`
- FQDNs in network rules, FQDN tags and web categories
- target URLs
- IP groups your identity is not allowed to read
- an address entry the viewer cannot read, in a rule's address list or in an IP
  group. The entry is named, so a typo is visible instead of silently dropped
- destination addresses on an **application** rule: Azure matches those against
  the address the firewall resolved from the `Host` header or the SNI, and that
  resolution is nowhere in the log

Two things the log writes differently from what the rule says, and the trace
translates rather than marks: a request through the **explicit proxy** is logged
with the real destination port, not the proxy port, so the port compares as usual
and the criterion only notes *via explicit proxy*; a **TLS-inspected** HTTPS
request is logged as the decrypted inner request, `Protocol` `HTTP/1.1` with
`IsTlsInspected` true, and the trace reads it as HTTPS for the rule. Both were
checked against real records rather than the documentation.

### Navigating it

| Key            | In the trace tree                                             |
| -------------- | ------------------------------------------------------------- |
| `Enter`        | Unfold a rule; on an unfolded rule, open it in the Policy tab |
| `Space`        | Fold it again                                                 |
| `a`            | Expand the whole tree, including collections that were skipped |
| `Escape` / `q` | Close the dialog                                              |

The trace is built only for rows that are a policy decision: `NetworkRule`,
`AppRule`, `NATRule` and `ThreatIntel`. For anything else the dialog shows the
row's fields alone and the status bar says why, either
*no policy evaluation for `<category>` rows* or
*trace needs policy metadata (not loaded)*.

> [!NOTE]
> The trace explains the **cached** policy. If the rule the firewall logged is
> missing from it, the trace says so and suggests `Ctrl` + `R`, since the rule may
> just have been renamed. A row naming an unknown rule also triggers a re-fetch on
> its own, see [Caching and staying current](#caching-and-staying-current).

## Authentication and permissions

The ARM client uses `DefaultAzureCredential` (Azure CLI login, managed identity,
environment credentials, …) and falls back to a token from the Azure CLI. That
means policy context also works when the Event Hub itself is read with a SAS
connection string.

Your identity needs **Reader** on the firewall, its policy, the IP groups it
references, and the firewall's subnets and public IPs. See
[required Azure permissions](configuration.md#required-azure-permissions).

Four of the reads are optional and fail quietly, because they only add detail to
the Firewall tab: one `GET` per public IP for its address, one on the firewall's
`Microsoft.Insights/diagnosticSettings`, one on a NAT gateway attached to the
firewall subnet, and one per maintenance configuration assigned to the firewall.
Without the first you still get the public IP's name, without the second the
Logging block says *no diagnostic settings readable*, and the other two say the
gateway or the window is *not readable* instead of pretending there is none.
If the `Microsoft.Maintenance` provider is not registered in the subscription
there is simply no assignment to read, and the tab says *no customer-controlled
window*.

Without ARM access at all nothing breaks: the status bar says *metadata
unavailable (no ARM access)*, the extra tabs stay empty and the viewer behaves
exactly as it does with policy context switched off.

## Caching and staying current

Metadata is cached for **one hour** in `~/.az-firewall-watch/cache.json` (file mode
`0600`, directory `0700`). If your home directory is not writable, the cache falls
back to `.azfw-cache.json` next to the binary. The file carries a version, so a
release that collects more metadata discards the old cache and fetches once on
first start rather than showing you a half-filled tab.

You rarely have to think about it, because the viewer keeps the cache current on
its own:

| Trigger                                                    | What happens                                                                 |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| A log row names a rule the loaded policy does not know      | Re-fetch, status bar *refreshing metadata (new rule …)…*                      |
| The one-hour TTL runs out (checked once a minute)           | Re-fetch, status bar *refreshing metadata (cache expired)…*                   |
| `Ctrl` + `R`                                                | Re-fetch on demand, for instance right after you changed a rule in the portal |

Automatic re-fetches are rate-limited to one every five minutes, so a burst of
rows against a stale policy does not turn into a burst of ARM requests. `Ctrl` + `R`
is not rate-limited.

The status bar carries the cache age (`fresh` under a minute, then `cache 12m`),
so you can always see how old the policy behind the tabs and the trace is. Two
more states worth recognising:

- *refresh failed · showing previous metadata*: the re-fetch did not work, for
  example because the token expired. The previous data stays on screen rather
  than disappearing, so remember it is the older picture.
- *refresh skipped: no firewall seen yet*, meaning `Ctrl` + `R` came before the first log
  record arrived. The viewer learns the firewall from the records, so there is
  nothing to refresh yet.

## Turning it off

Policy context is a feature flag with three ways to set it, in this order of
precedence:

| Where            | How                                                | Scope        |
| ---------------- | -------------------------------------------------- | ------------ |
| Command line     | `--policy-context` / `--no-policy-context`          | One run      |
| `.env`           | `POLICY_CONTEXT=on` / `POLICY_CONTEXT=off`          | Persistent   |
| Setup wizard     | *Policy context* step, writes the `.env` key for you | Persistent   |

**What "off" actually means:** no ARM requests, no Azure CLI token, no cache file,
and the Logs tab only. `Enter` then shows the plain row details, and `Ctrl` + `R`
answers in the status bar with *policy context off (POLICY_CONTEXT=on or
--policy-context to enable)*.

**Upgrading from an earlier release:** a `.env` written before this feature existed
has no `POLICY_CONTEXT` key. The viewer then shows a one-time notice at start-up
explaining what policy context does (it is on by default) with a *Disable* button,
and saves your choice to `.env`, so you are only asked once.

While that notice is open **nothing is read from Azure**: no token, no ARM request,
no cache file. Logs keep streaming, and the firewall the records point at is simply
remembered. Answering *Keep enabled* fetches it once; *Disable* discards it and
ignores every firewall seen later.
