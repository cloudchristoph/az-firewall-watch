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

- **Firewall**: name, resource group, location, SKU, attached policy, private IPs
  and the firewall subnets.
- **Policy**: a tree of rule collection groups → rule collections → rules, ordered
  by priority, with a detail pane showing sources, destinations, ports, protocols,
  and IP groups resolved to their actual addresses.
- **IP Groups**: every IP group the policy references, how many rules use it, and
  for the selected group the rules that reference it. `Enter` on a rule jumps to it
  in the Policy tab.

![The Policy tab: rule collection groups and collections in priority order on the left, the selected rule's definition on the right](policy-tab.png)

![The IP Groups tab: every group with its entry and usage count, and the rules that reference the selected group](ip-groups-tab.png)

### Richer log rows

The metadata also feeds back into the **Logs** tab:

- Addresses inside the firewall's own subnets are rendered as `AzFw.<last octet>`,
  so traffic from the firewall instances themselves (DNS proxy, probes) stands out.
- The row detail dialog lists the IP groups that contain source and destination
  and the definition of the rule the firewall logged, looked up by name, never
  guessed. Whatever the trace beside it already shows (policy path, priorities,
  action, SKU) is left out rather than printed twice.
- The status bar shows a short summary: `policy Premium · 11 IP groups · fresh`.

## Evaluation trace

Press `Enter` on a log row to open its details with the trace beside them: the path
that flow took through the policy, in the order Azure Firewall actually uses.
Threat Intelligence first, then three passes over all rule collection groups
(DNAT, Network, Application), each in inherited-policy-first, then priority order,
stopping at the first match. The Application pass only runs for HTTP, HTTPS and
MSSQL flows.

![The detail dialog: the log entry's fields on the left, the evaluation trace on the right, ending at the rule the firewall logged](evaluation-trace.png)

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
> missing from it (because the policy changed since the last fetch), the dialog
> warns you and suggests `Ctrl` + `R`.

## Authentication and permissions

The ARM client uses `DefaultAzureCredential` (Azure CLI login, managed identity,
environment credentials, …) and falls back to a token from the Azure CLI. That
means policy context also works when the Event Hub itself is read with a SAS
connection string.

Your identity needs **Reader** on the firewall, its policy and the IP groups. See
[required Azure permissions](configuration.md#required-azure-permissions).

Without ARM access nothing breaks: the status bar says *metadata unavailable
(no ARM access)*, the extra tabs stay empty and the viewer behaves exactly as it
does with policy context switched off.

## Caching

Metadata is cached for **one hour** in `~/.az-firewall-watch/cache.json` (file mode
`0600`, directory `0700`). If your home directory is not writable, the cache falls
back to `.azfw-cache.json` next to the binary.

Press `Ctrl` + `R` to invalidate the cache and re-fetch. Do this after changing
rules or IP groups, or when the trace warns that the logged rule is unknown to it.

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
