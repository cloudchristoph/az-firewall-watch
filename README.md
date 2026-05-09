# 🔥 Azure Firewall Watch

Azure Firewall Watch is a terminal UI for **live log monitoring of Azure Firewall**. It streams logs from an Event Hub in real time and lets you filter and inspect them directly in your terminal.

Built by [CloudChristoph](https://github.com/cloudchristoph).

> This project is based on the excellent work by [Nicola Delfino](https://github.com/nicolgit) and his
> [azure-firewall-mon](https://github.com/nicolgit/azure-firewall-mon) project.

![Azure Firewall Watch screenshot](https://raw.githubusercontent.com/cloudchristoph/az-firewall-watch/main/docs/screenshot.png)

---

## 🏗️ How it works

Azure Firewall Watch reads logs from an **Azure Event Hub** that receives firewall events via **Diagnostic Settings**:

```text
Azure Firewall
    └─▶ Diagnostic Settings
            └─▶ Event Hub  ◀─── az-firewall-watch (streams in real time)
```

1. **Diagnostic Settings** on your Azure Firewall forward structured log categories (NetworkRule, AppRule, IDPS, …) to an Event Hub namespace.  
   → [Configure Azure Firewall diagnostics](https://learn.microsoft.com/azure/firewall/firewall-diagnostics)

2. **Event Hub** buffers the events (default retention: 1 day) so az-firewall-watch can consume them live.  
   → [Azure Event Hubs overview](https://learn.microsoft.com/azure/event-hubs/event-hubs-about)

### 💰 Cost considerations

An Event Hub for firewall logs is typically inexpensive:

| Tier | ~Rough monthly cost |
| --- | --- |
| **Basic** (1 TU) | ~$10 + ~$0.028 per million events |
| **Standard** (1 TU) | ~$22 + ~$0.028 per million events — required for multiple consumer groups |

Firewall log volume depends on traffic intensity — most environments stay comfortably within a single Throughput Unit.  
→ [Event Hubs pricing](https://azure.microsoft.com/pricing/details/event-hubs/)

> **Tip:** The built-in setup wizard can deploy a new Event Hub and configure diagnostic settings automatically in ~2–3 minutes.

---

## 🚀 Getting started

### Option 1 — Download a prebuilt binary *(easiest, no Python needed)*

Download the binary for your platform from the [latest release](../../releases/latest):

| Platform            | File                             |
| ------------------- | -------------------------------- |
| Linux x86_64        | `az-firewall-watch-linux.tar.gz` |
| macOS Apple Silicon | `az-firewall-watch-macos.tar.gz` |
| Windows             | `az-firewall-watch.exe`          |

**macOS / Linux:**

```bash
# 1. Download (example for macOS)
curl -L -O \
  https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch-macos.tar.gz

# 2. Extract (preserves execute permission)
tar -xzf az-firewall-watch-macos.tar.gz

# 3. macOS only: remove Gatekeeper quarantine flag
xattr -d com.apple.quarantine az-firewall-watch

# 4. Run — the setup wizard launches automatically on first start
./az-firewall-watch
```

**Windows:**

Double-click `az-firewall-watch.exe` or run from PowerShell:

```powershell
.\az-firewall-watch.exe
```

> **Windows SmartScreen** may warn on first launch — click **More info → Run anyway**.  
> This is expected for unsigned binaries.

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

On first launch the wizard asks how you want to connect and then writes `.env` automatically. Three options are available:

| Option | Description | Azure CLI required |
| --- | --- | :---: |
| **1 — Pick existing** | Choose an existing Event Hub from your subscriptions | ✅ |
| **2 — Deploy new** | Discover your firewall and deploy a new Event Hub incl. diagnostic settings (~2–3 min) | ✅ |
| **3 — Paste string** | Paste a connection string directly — no Azure CLI needed | — |

Run with `--reconfigure` to redo setup at any time:

```bash
./az-firewall-watch --reconfigure
```

---

## ⌨️ Key bindings

| Key | Action |
| --- | --- |
| `q` or `Ctrl` + `q` | Quit |
| `Ctrl` + `p` | Pause / resume streaming |
| `Enter` | Open detail view for the selected row |
| `c` | Clear all rows from the table |
| `Escape` | Clear all filter inputs |
| `f` | Jump focus to the filters |
| `Tab` | Move between filter inputs |

---

## 🔍 Filters

All filters are **case-insensitive substring matches** applied instantly as you type.

| Filter | Matches against |
| --- | --- |
| Source IP | `sourceip` field |
| Dest / FQDN | `targetip` / FQDN field |
| Action | `allow`, `deny`, `dnat`, `alert` |
| Category | `NetworkRule`, `AppRule`, `DnsQuery`, `NATRule`, `IDPS`, `ThreatIntel`, … |
| Protocol | `TCP`, `UDP`, `HTTPS`, `HTTP`, … |
| Port | Destination port (e.g. `443`, `80`, `53`) |

Press `Escape` to clear all filters at once, or `f` to jump directly into the filter bar.

---

## ⚙️ Configuration

### Manual setup (skip the wizard)

If you already have an Event Hub connection string, create `.env` next to the binary (or in the repo root):

```ini
EVENT_HUB_CONNECTION_STRING=Endpoint=sb://your-ns.servicebus.windows.net/;SharedAccessKeyName=...;EntityPath=firewall-logs
EVENT_HUB_CONSUMER_GROUP=$Default
EVENT_HUB_START_POSITION=latest   # or: earliest
```

### Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `EVENT_HUB_CONNECTION_STRING` | Primary connection string with `EntityPath=firewall-logs` | *(required)* |
| `EVENT_HUB_CONSUMER_GROUP` | Consumer group | `$Default` |
| `EVENT_HUB_START_POSITION` | `latest` (live only) or `earliest` (read full retention) | `latest` |

> **Tip:** If you deploy the Event Hub manually, configure [Diagnostic Settings](https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings) on your Azure Firewall to forward logs to the `firewall-logs` Event Hub.

---

## 📋 Supported log categories

Both legacy and structured log formats are parsed:

| Category shown | Raw Azure category |
| --- | --- |
| NetworkRule | `AZFWNetworkRule` / `AzureFirewallNetworkRule` |
| AppRule | `AZFWApplicationRule` / `AzureFirewallApplicationRule` |
| NATRule | `AZFWNatRule` / `AzureFirewallNatRuleLog` |
| DnsQuery | `AZFWDnsQuery` |
| DnsProxy | `AzureFirewallDnsProxy` |
| IDPS | `AZFWIdpsSignature` |
| ThreatIntel | `AZFWThreatIntel` |

---

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
  --add-data "setup_wizard.py:." \
  main.py

# Binary is at dist/az-firewall-watch  (or dist/az-firewall-watch.exe on Windows)
```

---

## 📄 License

MIT
