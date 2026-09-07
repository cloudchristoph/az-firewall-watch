# Getting started

Two ways to run Azure Firewall Watch: a self-contained binary (recommended) or
from source with Python 3.10+. Either way the setup wizard takes over on first
launch and writes your `.env`.

## Option 1: Download the binary *(recommended)*

Download the binary for your platform from the
[latest release](https://github.com/cloudchristoph/az-firewall-watch/releases/latest):

<!-- markdownlint-disable MD060 -->
| Platform            | File                                                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Windows             | [`az-firewall-watch.exe`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch.exe)                           |
| macOS Apple Silicon | [`az-firewall-watch-macos.tar.gz`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch-macos.tar.gz)         |
| Linux x86_64        | [`az-firewall-watch-linux.tar.gz`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch-linux.tar.gz)         |
<!-- markdownlint-enable MD060 -->

### Windows

Double-click `az-firewall-watch.exe` or run it from PowerShell:

```powershell
.\az-firewall-watch.exe
```

> [!NOTE]
> **Windows SmartScreen** may warn on first launch. Click **More info → Run anyway**.
> This is expected for unsigned binaries.

### macOS

```bash
# 1. Extract (preserves execute permission)
tar -xzf az-firewall-watch-macos.tar.gz

# 2. Remove the Gatekeeper quarantine flag (required for unsigned binaries)
xattr -d com.apple.quarantine az-firewall-watch

# 3. Run (the setup wizard launches automatically on first start)
./az-firewall-watch
```

### Linux

```bash
# 1. Extract (preserves execute permission)
tar -xzf az-firewall-watch-linux.tar.gz

# 2. Run (the setup wizard launches automatically on first start)
./az-firewall-watch
```

## Option 2: Run from source *(Python 3.10+)*

```bash
git clone https://github.com/cloudchristoph/az-firewall-watch.git
cd az-firewall-watch

# Linux / macOS
./start.sh

# Windows
start.bat
```

The scripts create a virtual environment, install dependencies and launch the
app. The setup wizard runs automatically if `.env` is not yet configured.

## 🧙 The setup wizard

The wizard runs the first time you launch the app, or whenever `.env` is missing.
It is a full TUI: pick with the arrow keys, **Next →** moves on, and every screen
has a **Back** button. `Ctrl` + `Q` quits; on the confirmation dialogs `Escape` or
`q` dismisses. Re-run the wizard any time with:

```bash
./az-firewall-watch --reconfigure
```

The wizard has three steps: pick an Event Hub, choose how to authenticate against
it, and decide whether the viewer may read policy context from Azure.

### Step 1: Pick an Event Hub

The first screen is a single list of four options, grouped into hubs that already
exist and one the wizard builds for you:

<!-- markdownlint-disable MD060 -->
| Option                                            | What it does                                                                                            | Azure CLI |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------- |
| **Discover Event Hub automatically**              | Lists your subscriptions, namespaces and hubs so you can pick one from a menu                             | yes       |
| **Enter existing Event Hub data**                 | Type namespace and hub name yourself, handy when your identity can read the hub but not list resources    | no        |
| **Paste SAS connection string**                   | Paste a full `Endpoint=sb://…;EntityPath=…` string, written verbatim to `.env`                            | no        |
| **Deploy new Event Hub and Diagnostics settings** | Creates a Basic-tier namespace with a `firewall-logs` hub and points your firewall's Diagnostic Settings at it, using exactly the categories the viewer displays | yes       |
<!-- markdownlint-enable MD060 -->

The deploy option is the only one that changes anything in Azure. It needs rights
to create the namespace and to update Diagnostic Settings on the firewall (see
[required Azure permissions](configuration.md#required-azure-permissions)), and
once it finishes it can take 10 to 15 minutes before the first events arrive in
the hub.

> [!NOTE]
> If your environment uses Azure Policy to enforce naming conventions, settings or
> resource tags (as it should 😉), that deployment may fail: it creates the
> namespace with default settings in the firewall's own subscription. Build the
> Event Hub manually or via IaC to match your policies instead, then come back and
> connect it with *Discover* or *Enter existing*.

### Step 2: Authentication method

After picking a hub (Discover, Enter existing, or Deploy new), a follow-up screen
asks **how** to authenticate against it:

- **Entra ID** *(recommended)*: passwordless auth via your Azure CLI login,
  managed identity, environment credentials, and so on. Nothing secret is written
  to `.env`. Requires the **Azure Event Hubs Data Receiver** role on the namespace
  or hub; the wizard verifies your assignment up front.
- **SAS auth rule**: looks for a reusable Listen-only authorization rule on the
  hub; if none exists you are asked to confirm the creation of a new one before
  the connection string is written to `.env`.

The *Paste connection string* path skips this screen, since SAS is already implied.

> [!CAUTION]
> SAS keys are powerful secrets that grant access to your Event Hub. If you choose
> the SAS auth method, protect the generated connection string and the `.env` file,
> and rotate keys regularly.
>
> Never commit your `.env` file to source control or share it with unauthorized
> parties.

### Step 3: Policy context

Right before `.env` is written, every wizard path asks whether the viewer may read
the firewall, its policy and IP groups via Azure Resource Manager. It is **on by
default** and saved as `POLICY_CONTEXT=on|off`.

Choose *Disable* if the viewer must not touch anything beyond the Event Hub. You
then get the Logs tab only, no ARM requests, no Azure CLI token and no cache file.

→ [What policy context gives you](policy-context.md), and how to change the
decision later.

## Next steps

- [Using the viewer](using-the-viewer.md): filters, key bindings, row details.
- [Configuration](configuration.md) for when you would rather write `.env` yourself.
