# 🔥 Azure Firewall Watch

Azure Firewall Watch is a terminal UI for **live log monitoring of Azure Firewall**. It streams logs from an Event Hub in real time and lets you filter and inspect them directly in your terminal. With access to Azure Resource Manager it also shows the firewall's policy and IP groups and explains which rule a log row matched.

Built by [CloudChristoph](https://github.com/cloudchristoph).

> This project is based on the excellent work by [Nicola Delfino](https://github.com/nicolgit) and his
> [azure-firewall-mon](https://github.com/nicolgit/azure-firewall-mon) project.

![Azure Firewall Watch screenshot](https://raw.githubusercontent.com/cloudchristoph/az-firewall-watch/main/docs/screenshot.png)

## 🏗️ How it works

Azure Firewall Watch reads logs from an **Azure Event Hub** that receives firewall events via **Diagnostic Settings**:

```text
Azure Firewall
    └─▶ Diagnostic Settings
            └─▶ Event Hub  ◀─── az-firewall-watch (streams in real time)
```

1. **Diagnostic Settings** on your Azure Firewall forward the structured log categories (NetworkRule, AppRule, DnsQuery, IDPS, …) to an Event Hub namespace. The legacy `AzureFirewall*` categories work too.  
   → [Configure Azure Firewall diagnostics](https://learn.microsoft.com/en-us/azure/firewall/monitor-firewall#enable-structured-logs)

2. **Event Hub** buffers the events (default retention: 1 day) so az-firewall-watch can consume them live.  
   → [Azure Event Hubs overview](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-about)

## 🚀 Getting started

### Option 1 - Download the binary *(recommended)*

Download the binary for your platform from the [latest release](../../releases/latest):

<!-- markdownlint-disable MD060 -->
| Platform            | File                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------- |
| Windows             | [`az-firewall-watch.exe`](../../releases/latest/download/az-firewall-watch.exe)                   |
| macOS Apple Silicon | [`az-firewall-watch-macos.tar.gz`](../../releases/latest/download/az-firewall-watch-macos.tar.gz) |
| Linux x86_64        | [`az-firewall-watch-linux.tar.gz`](../../releases/latest/download/az-firewall-watch-linux.tar.gz) |
<!-- markdownlint-enable MD060 -->

**Windows:**

Double-click `az-firewall-watch.exe` or run from PowerShell:

```powershell
.\az-firewall-watch.exe
```

> [!NOTE]
> **Windows SmartScreen** may warn on first launch - click **More info → Run anyway**.  
> This is expected for unsigned binaries.

**macOS:**

```bash
# 1. Extract (preserves execute permission)
tar -xzf az-firewall-watch-macos.tar.gz

# 2. Remove the Gatekeeper quarantine flag (required for unsigned binaries)
xattr -d com.apple.quarantine az-firewall-watch

# 3. Run — the setup wizard launches automatically on first start
./az-firewall-watch
```

**Linux:**

```bash
# 1. Extract (preserves execute permission)
tar -xzf az-firewall-watch-linux.tar.gz

# 2. Run — the setup wizard launches automatically on first start
./az-firewall-watch
```

### Option 2 — Run from source *(Python 3.10+)*

```bash
git clone https://github.com/cloudchristoph/az-firewall-watch.git
cd az-firewall-watch

# Linux / macOS
./start.sh

# Windows
start.bat
```

The scripts create a virtual environment, install dependencies, and launch the app — the setup wizard runs automatically if `.env` is not yet configured.

### 🧙 First-run setup wizard

The setup wizard runs automatically the first time you launch the app (or whenever `.env` is missing). It's a full TUI — navigate with arrow keys, `Enter` to confirm, `Escape` or `Q` to go back.

You have two main options for connecting your firewall logs Event Hub:

#### Existing Event Hub

<!-- markdownlint-disable MD060 -->
| Option                               | What it does                                                                                          | Azure CLI required |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------ |
| **Discover Event Hub automatically** | Lists your subscriptions, namespaces and hubs so you can pick one from a menu                         | ✅                  |
| **Enter existing Event Hub data**    | Type namespace + hub name manually (handy when your identity can read the hub but not list resources) | —                  |
| **Paste SAS connection string**      | Paste a full `Endpoint=sb://…;EntityPath=…` string — written verbatim to `.env`                       | —                  |
<!-- markdownlint-enable MD060 -->

#### New Event Hub

> [!NOTE]
> If your environment uses Azure Policy to enforce specific naming conventions, settings, or resource tags (as it should 😉), the automatic deployment may fail since it creates a new Event Hub with default settings within the same subscription as the firewall.
>
> In that case, you should create the Event Hub manually or via IaC according to your policies and then use the "Discover" or "Enter existing" options to connect it to the app.

<!-- markdownlint-disable MD060 -->
| Option                                            | What it does                                                                                                                                                             | Azure CLI required |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------ |
| **Deploy new Event Hub and Diagnostics settings** | Discovers your Azure Firewall, creates a Basic-tier Event Hub namespace + `firewall-logs` hub, and wires up Diagnostic Settings for exactly the log categories the viewer displays (no Policy Analytics aggregation logs) | ✅                  |

> [!NOTE]
> The deployment will require permissions to create an Event Hub namespace and hub, and to update Diagnostic Settings on the firewall. Also keep in mind that it can take *up to 10-15 minutes at the first launch* for the Event Hub to be fully provisioned and start receiving logs from the firewall.

#### Metadata enrichment step

Right before `.env` is written, every wizard path asks whether the viewer may
read the firewall, its policy and IP groups via Azure Resource Manager (see
[Firewall, Policy and IP Groups tabs](#-firewall-policy-and-ip-groups-tabs)).
It is **on by default** and saved as `ENRICHMENT=on|off`. Choose *Disable* if
the viewer must not touch anything beyond the Event Hub — you then get the
Logs tab only, no ARM requests, no Azure CLI token and no cache file.

### 🔑 Authentication methods

After picking a hub (Discover, Enter existing, or Deploy new), a follow-up screen asks **how** to authenticate:

- **Entra ID** *(recommended)* — uses passwordless auth via logged in Azure CLI login, managed identity, environment credentials, etc. Nothing secret is written to `.env`. Requires the **Azure Event Hubs Data Receiver** role on the namespace or hub; the wizard verifies your assignment up-front.
- **SAS auth rule** — looks for a reusable Listen-only authorization rule on the hub; if none exists you'll be asked to confirm the creation of a new one before the connection string is written to `.env`.

> The *Paste connection string* path skips the auth-method screen since SAS is already implied.

> [!CAUTION]
> SAS keys are powerful secrets that grant access to your Event Hub. If you choose the SAS auth method, make sure to protect the generated connection string and `.env` file, and rotate keys regularly.
>
> Never commit your `.env` file to source control or share it with unauthorized parties.

Run with `--reconfigure` to redo setup at any time:

```bash
./az-firewall-watch --reconfigure
```

## ⚙️ Configuration

### Manual setup (skip the wizard)

If you already have an Event Hub connection string, create `.env` next to the binary (or in the repo root):

```ini
EVENT_HUB_CONNECTION_STRING=Endpoint=sb://your-ns.servicebus.windows.net/;SharedAccessKeyName=...;EntityPath=your-hub-name
EVENT_HUB_CONSUMER_GROUP=$Default
EVENT_HUB_START_POSITION=latest   # or: earliest
```

Alternatively, for **Entra ID (passwordless) authentication** — required when SAS keys are disabled on the namespace:

```ini
EVENT_HUB_NAMESPACE=your-ns.servicebus.windows.net
EVENT_HUB_NAME=your-hub-name
EVENT_HUB_CONSUMER_GROUP=$Default
EVENT_HUB_START_POSITION=latest
```

> **Note:** Entra ID auth uses `DefaultAzureCredential` which picks up Azure CLI login, managed identity, environment variables, etc. Your identity must have the **Azure Event Hubs Data Receiver** role on the namespace or hub.

### Environment variables

<!-- markdownlint-disable MD060 -->
| Variable                      | Description                                                                               | Default    |
| ----------------------------- | ----------------------------------------------------------------------------------------- | ---------- |
| `EVENT_HUB_CONNECTION_STRING` | Primary connection string incl. `EntityPath=<your-hub-name>`                              | —          |
| `EVENT_HUB_NAMESPACE`         | Fully qualified namespace (e.g. `mynamespace.servicebus.windows.net`) — for Entra ID auth | —          |
| `EVENT_HUB_NAME`              | Event Hub name — for Entra ID auth                                                        | —          |
| `EVENT_HUB_CONSUMER_GROUP`    | Consumer group                                                                            | `$Default` |
| `EVENT_HUB_START_POSITION`    | `latest` (only new events) or `earliest` (replay the hub's full retention first); other values are passed to the SDK as a raw offset | `latest`   |
| `ENRICHMENT`                  | `on` / `off` — metadata enrichment via Azure Resource Manager (tabs, trace, cache). `--enrichment` / `--no-enrichment` override it for one run. If the key is missing, the viewer asks once at start-up and saves the answer | `on`       |
<!-- markdownlint-enable MD060 -->

> When both `EVENT_HUB_NAMESPACE`/`EVENT_HUB_NAME` and `EVENT_HUB_CONNECTION_STRING` are set, Entra ID is preferred.
> **Tip:** If you deploy the Event Hub manually, configure [Diagnostic Settings](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings) on your Azure Firewall to forward logs to the `firewall-logs` Event Hub.

## ⌨️ Key bindings

| Key          | Action                                |
| ------------ | ------------------------------------- |
| `Ctrl` + `q` | Quit                                  |
| `Ctrl` + `p` | Pause / resume streaming              |
| `Ctrl` + `s` | Save a screenshot of the current view |
| `Escape`     | Clear all filter inputs               |
| `f`          | Jump focus to the filters             |
| `Tab`        | Move between filter inputs            |
| `Enter`      | Open detail view for the selected row (`Escape` or `q` closes it) |
| `c`          | Clear all rows from the table         |
| `t`          | Open the evaluation trace for the selected row (needs metadata) |
| `Ctrl` + `r` | Re-fetch firewall / policy / IP-group metadata (bypasses the cache) |

The status bar at the bottom shows the connection state, total events received,
the currently visible count when a filter is active, and how many records were
skipped (e.g. unknown categories).

If an established connection drops, the app reconnects on its own with a
capped backoff (up to 60 s between attempts) and reports the countdown in the
status bar. Only the very first connection gives up after three attempts, and
authentication errors stop immediately with a hint.

## 🧭 Firewall, Policy and IP Groups tabs

Next to the **Logs** tab the viewer shows what it learned about the firewall from
Azure Resource Manager (ARM):

- **Firewall** — name, resource group, location, SKU, policy, private IPs and
  the firewall subnets.
- **Policy** — a tree of rule collection groups → rule collections → rules,
  ordered by priority, with a detail pane (sources, destinations, ports,
  protocols, IP groups resolved to their addresses).
- **IP Groups** — every IP group the policy references, how many rules use it,
  and for the selected group the rules that reference it. `Enter` on a rule
  jumps to it in the Policy tab.

The metadata also enriches the **Logs** tab: addresses inside the firewall's
own subnets are rendered as `AzFw.<last octet>` so traffic from the firewall
instances themselves (DNS proxy, probes) stands out, and the row detail dialog
lists the IP groups that contain source and destination, the definition and
priorities of the rule the firewall logged (looked up by name, never guessed),
and the policy SKU tier. The status bar shows a short summary
(`policy Premium · 11 IP groups · fresh`).

### Evaluation trace (`t`)

Press `t` on a log row to see the path that flow took through the policy,
in the order Azure Firewall actually uses: Threat Intelligence first, then
three passes over all rule collection groups — DNAT, Network, Application —
each in inherited-policy-first, then priority order, stopping at the first
match. The Application pass is only run for HTTP, HTTPS and MSSQL flows.

```text
Policy evaluation
├─ Threat Intelligence   mode Alert — no hit
├─ Pass 1 · DNAT rules   no collections of this type
├─ Pass 2 · Network rules
│  ├─ ✗ [2000] cclab-network-rule-collection-group » [100] priority-demo-net-rules (Deny)
│  │   └─ ✗ deny-bad   ✓ source  ✗ destination  ✓ port  ✓ protocol
│  ├─ ✓ [2000] cclab-network-rule-collection-group » [200] azure-monitor-access (Allow)
│  │   ├─ ? allow-azure-monitor   ✓ source  ? destination  ✓ port  ✓ protocol
│  │   └─ ✓ allow-web   ✓ source  ✓ destination  ✓ port  ✓ protocol   ← logged match
│  └─ evaluation stops here — rule matched
├─ Pass 3 · Application rules   not evaluated — a rule already matched
└─ ✓ Allow by cclab-network-rule-collection-group » azure-monitor-access » allow-web
```

Everything before the logged rule was really evaluated and rejected by the
firewall; *why* is computed locally per criterion. `?` marks criteria that
cannot be evaluated here — service tags such as `AzureMonitor`, FQDNs in
network rules, FQDN tags, web categories, target URLs, and IP groups your
identity cannot read. For `Deny · no rule matched` rows the whole path is
computed and the near misses show which criterion failed (for example
`port: 8443 not in 443`). `Enter` on a rule opens it in the Policy tab. The
trace explains the *cached* policy; if the logged rule is missing from it, a
warning suggests `Ctrl+R`.

**How it authenticates.** The ARM client uses `DefaultAzureCredential` (Azure
CLI login, managed identity, environment credentials, …) and falls back to a
token from the Azure CLI, so this also works when the Event Hub itself is read
with a SAS connection string. Your identity needs **Reader** on the firewall,
its policy and the IP groups. Without ARM access the status bar says
*metadata unavailable* and the viewer works exactly as before.

**Cache.** Metadata is cached for one hour in `~/.az-firewall-watch/cache.json`
(file mode `0600`; falls back to `.azfw-cache.json` next to the binary if the
home directory is not writable). Press `Ctrl+R` to re-fetch after changing
rules or IP groups.

**Switching it off.** Enrichment is a feature flag: `ENRICHMENT=off` in `.env`
(or `--no-enrichment` for a single run) turns everything in this section off —
no ARM requests, no Azure CLI token, no cache file, Logs tab only; `t` and
`Ctrl+R` then just say so in the status bar. The wizard asks for this when it
writes `.env`. A `.env` from an earlier release has no `ENRICHMENT` key, so the
viewer shows a one-time notice explaining what enrichment does (on by default)
with a *Disable* button; the choice is saved to `.env`.

## 🔍 Filters

All filters are **case-insensitive substring matches** applied instantly as you type.

<!-- markdownlint-disable MD060 -->
| Filter      | Matches against                                                                        |
| ----------- | -------------------------------------------------------------------------------------- |
| Source IP   | `sourceip` field                                                                       |
| Dest / FQDN | `targetip` / FQDN field                                                                |
| Action      | `allow`, `deny`, `dnat`, `alert`, `resolvefail`, DNS RCODEs (`noerror`, `nxdomain`, …), flow flags (`rst`, `invalid`, …), `mbps` |
| Category    | `NetworkRule`, `AppRule`, `NATRule`, `DnsQuery`, `DnsFailure`, `IDPS`, `ThreatIntel`, `FlowTrace`, `FatFlow` |
| Protocol    | `TCP`, `UDP`, `HTTPS`, `HTTP`, DNS query types (`A`, `AAAA`, `MX`, …)                  |
| Port        | Destination port (e.g. `443`, `80`, `53`)                                              |
<!-- markdownlint-enable MD060 -->

### Hide DNS toggle

DNS proxy traffic can dominate the log volume on busy firewalls. A **Hide DNS**
switch sits at the end of the filter bar and is **on by default**, so `DnsQuery`
rows are filtered out until you explicitly want to see them. `DnsFailure` rows
(the firewall failing to resolve an FQDN from a rule) stay visible regardless.

The toggle is smart:

- Flipping it **off** instantly shows all DNS rows.
- Picking **DnsQuery** in the Category dropdown automatically flips it off — so
  you never end up with an empty table after asking to see DNS entries.
- Pressing `Escape` to clear all filters resets the toggle back to **on**.

Press `Escape` to clear all filters at once, or `f` to jump directly into the filter bar.

---

## 📋 Supported log categories

Both the **legacy** (single-message) and the **structured** (typed JSON) log
formats produced by Azure Firewall are parsed. Legacy `AzureFirewallDnsProxy`
entries are normalised into the `DnsQuery` category so you only deal with one
display name regardless of which diagnostic mode is enabled.

| Category shown | Azure category (structured / legacy)                                                              |
| -------------- | ------------------------------------------------------------------------------------------------- |
| NetworkRule    | `AZFWNetworkRule` / `AzureFirewallNetworkRule`                                                    |
| AppRule        | `AZFWApplicationRule` / `AzureFirewallApplicationRule`                                            |
| NATRule        | `AZFWNatRule` / `AzureFirewallNatRuleLog`                                                         |
| DnsQuery       | `AZFWDnsQuery` / `AzureFirewallDnsProxy`                                                          |
| DnsFailure     | `AZFWFqdnResolveFailure` / legacy `AzureFirewallDNSResolutionFailureLog` — the firewall could not resolve an FQDN used in a network or DNAT rule; action `ResolveFail`, FQDN and error shown |
| IDPS           | `AZFWIdpsSignature`                                                                               |
| ThreatIntel    | `AZFWThreatIntel`                                                                                 |
| FlowTrace      | `AZFWFlowTrace` — TCP flow flags (`SYN-ACK`, `FIN`, `RST`, `INVALID`, …) in the Action column; requires flow-trace logging on the firewall |
| FatFlow        | `AZFWFatFlow` — top flows by bandwidth, rate in Mbit/s in the Action column (sampled every 3 min; rates well below 1 Mbit/s do appear); requires fat-flow logging on the firewall. Most records describe the return direction, i.e. `<internet>:443 → <firewall instance>:<SNAT port>`, so the spoke client often shows up only as destination or not at all |

Unknown or non-firewall categories (for example the Policy Analytics
`*Aggregation` logs) are counted in the status bar as *skipped* rather than
displayed.

`FlowTrace` and `FatFlow` only produce data when the corresponding logging is
switched on at the firewall, in addition to the diagnostic-setting category:

```bash
# Top flows (fat flow) — flows above 1 Mbit/s, sampled every 3 minutes
az network firewall update --ids <firewall-resource-id> --enable-fat-flow-logging true
```

Flow trace requires the preview feature `AFWEnableTcpConnectionLogging` to be
registered on the subscription first — see
[Azure Firewall flow trace logs](https://learn.microsoft.com/azure/firewall/monitor-firewall-reference#flow-trace).
Both are meant for troubleshooting; leave them off during normal operation.

## 🔨 Building locally

```bash
pip install -r requirements.txt -r requirements-build.txt

pyinstaller \
  --onefile \
  --name az-firewall-watch \
  --collect-all textual \
  --hidden-import azure.eventhub \
  --hidden-import azure.eventhub.aio \
  --hidden-import azure.eventhub._transport._pyamqp_transport \
  --add-data "fw_parser.py:." \
  --add-data "version.txt:." \
  main.py

# Binary is at dist/az-firewall-watch  (or dist/az-firewall-watch.exe on Windows)
```

### 🧪 Running tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

The suite covers the log parser (structured and legacy formats), the filter
logic, the Event Hub streaming worker (against a fake client), the update
check, the ARM client and metadata enrichment (against canned ARM payloads),
and headless runs of both the viewer and the setup wizard via Textual's
test pilot with the Azure CLI mocked out. No Azure connection is required. The
same suite runs in CI on every push and pull request.

**Live integration tests** (optional, never run in CI) exercise the real ARM
round trip and a real Event Hub. They are skipped unless you point them at
your environment; only read operations are made, and the metadata cache is
redirected to a temporary directory:

```bash
AZFW_LIVE_FIREWALL_ID=/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/azureFirewalls/<fw> \
AZFW_LIVE_EVENTHUB_NAMESPACE=<ns>.servicebus.windows.net \
AZFW_LIVE_EVENTHUB_NAME=firewall-logs \
pytest tests/live -m live
```

Your identity needs Reader on the firewall, its policy and IP groups, and the
*Azure Event Hubs Data Receiver* role on the hub.

### 💰 Cost considerations

An Event Hub for firewall logs is typically inexpensive:

| Tier                | ~Rough monthly cost                                                       |
| ------------------- | ------------------------------------------------------------------------- |
| **Basic** (1 TU)    | ~$10 + ~$0.028 per million events                                         |
| **Standard** (1 TU) | ~$22 + ~$0.028 per million events — required for multiple consumer groups |

Firewall log volume depends on traffic intensity — most environments stay comfortably within a single Throughput Unit.  
→ [Event Hubs pricing](https://azure.microsoft.com/pricing/details/event-hubs/)

> **Tip:** The built-in setup wizard can deploy a new Event Hub and configure diagnostic settings automatically in ~2–3 minutes.

## 📄 License

MIT
