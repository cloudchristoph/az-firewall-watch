# Getting started

Three ways to run Azure Firewall Watch: a package manager (winget on Windows,
Homebrew on macOS and Linux), a self-contained binary, or from source with
Python 3.10+. Either way the setup wizard takes over on first launch and writes
your `.env`.

## Before you start

- **Azure access.** You need the firewall whose logs you want to see, and access
  to the Event Hub that receives them. The exact rights are listed under
  [required Azure permissions](configuration.md#required-azure-permissions).
- **Azure CLI.** Needed for *Discover* and *Deploy* in the wizard, and for Entra ID
  if you sign in with your own account. Install it and run `az login` once.
- **Python 3.10+.** Only needed for Option 3 below. The binaries need nothing installed.

## Option 1: Package manager *(recommended)*

### Windows: winget

```powershell
winget install cloudchristoph.az-firewall-watch
```

winget adds the command to your `PATH`, so open a new terminal and run:

```powershell
az-firewall-watch
```

Update with `winget upgrade cloudchristoph.az-firewall-watch`; the update notice
in the app shows that command too.

A winget install keeps `.env` in `%LOCALAPPDATA%\az-firewall-watch\` instead of
next to the binary, because winget owns its install folder. `winget uninstall`
leaves that folder in place; delete it to remove the configuration.

### macOS and Linux: Homebrew

*(macOS Apple Silicon, Linux x86_64 and arm64)*

```bash
brew install --cask cloudchristoph/tap/az-firewall-watch
az-firewall-watch
```

The cask installs the same binary as the release download and removes the
Gatekeeper quarantine flag for you. Update with
`brew upgrade --cask az-firewall-watch`; the update notice in the app shows that
command too.

A Homebrew install keeps `.env` in your config directory instead of next to the
binary, because `brew upgrade` replaces the versioned install folder:
`~/Library/Application Support/az-firewall-watch/` on macOS,
`~/.config/az-firewall-watch/` on Linux. `brew uninstall --zap` deletes it and moves
the cache to the trash.

## Option 2: Download the binary

Download the binary for your platform from the
[latest release](https://github.com/cloudchristoph/az-firewall-watch/releases/latest):

<!-- markdownlint-disable MD060 -->
| Platform            | File                                                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Windows             | [`az-firewall-watch.exe`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch.exe)                           |
| macOS Apple Silicon | [`az-firewall-watch-macos.tar.gz`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch-macos.tar.gz)         |
| Linux x86_64        | [`az-firewall-watch-linux.tar.gz`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch-linux.tar.gz)         |
| Linux arm64         | [`az-firewall-watch-linux-arm64.tar.gz`](https://github.com/cloudchristoph/az-firewall-watch/releases/latest/download/az-firewall-watch-linux-arm64.tar.gz) |
<!-- markdownlint-enable MD060 -->

### Windows

I recommend **Windows Terminal**, the default terminal on Windows 11 since 22H2.
In the classic console (conhost), button borders may show as boxes; use Windows
Terminal instead.

Run it from Windows Terminal:

```powershell
.\az-firewall-watch.exe
```

Double-clicking the `.exe` also works when Windows Terminal is your default
terminal app (*Settings › Privacy & security › For developers › Terminal* on Windows 11,
the *Default terminal application* setting in Windows Terminal on Windows 10). With the
Windows 10 default it opens in conhost.

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

The Linux binaries need glibc 2.38 or newer, for example Ubuntu 24.04, Debian 13 or
Fedora 39. On older distributions, [run from source](#option-3-run-from-source-python-310).

Pick the archive for your architecture (`uname -m` shows `x86_64` or `aarch64`).

x86_64:

```bash
# 1. Extract (preserves execute permission)
tar -xzf az-firewall-watch-linux.tar.gz

# 2. Run (the setup wizard launches automatically on first start)
./az-firewall-watch
```

arm64:

```bash
# 1. Extract (preserves execute permission)
tar -xzf az-firewall-watch-linux-arm64.tar.gz

# 2. Run (the setup wizard launches automatically on first start)
./az-firewall-watch
```

## Option 3: Run from source *(Python 3.10+)*

```bash
git clone https://github.com/cloudchristoph/az-firewall-watch.git
cd az-firewall-watch

# Windows
start.bat

# macOS / Linux
./start.sh
```

The scripts create a virtual environment, install dependencies and launch the
app. The setup wizard runs automatically while no Event Hub credentials are configured,
neither in `.env` nor in the environment.

## Blocked by your organisation's security policy?

The binaries are not code-signed yet, and every release has a new file hash
that Microsoft's reputation service has not seen often. Hardened Windows
machines may therefore refuse to start `az-firewall-watch.exe`, whether it came
from winget or from the release page. Typical messages are *"Your IT
administrator has blocked this app"*, *"An Application Control policy has
blocked this file"* or *"Access is denied"*.

The usual causes, which only an administrator can change:

| Policy | How to recognise it |
| --- | --- |
| Microsoft Defender attack surface reduction rule *Block executable files from running unless they meet a prevalence, age, or trusted list criterion* (`01443614-cd74-433a-b99e-2ecdc07bfc25`) | Event ID 1121 (blocked) or 1122 (audited) in *Applications and Services Logs › Microsoft › Windows › Windows Defender › Operational* |
| App Control for Business (WDAC) or AppLocker allow lists | Events in *Microsoft › Windows › CodeIntegrity › Operational* or *AppLocker* |
| Smart App Control (Windows 11) | A Smart App Control notification on launch |

**For administrators:** allow the file by its SHA-256 hash, for example as an
*Allow* file indicator in Microsoft Defender for Endpoint, an ASR exclusion or a
hash rule. Each release lists the hash of `az-firewall-watch.exe` in its notes and
all hashes in `SHA256SUMS.txt`. To check a downloaded file:

```powershell
Get-FileHash .\az-firewall-watch.exe -Algorithm SHA256
```

A winget install keeps the binary under
`%LOCALAPPDATA%\Microsoft\WinGet\Packages\cloudchristoph.az-firewall-watch_*\`.
The hash changes with every release, so the allowance has to be renewed on
update.

**Without an administrator:** [run from source](#option-3-run-from-source-python-310).
Python itself is signed, so these rules usually leave it alone.

## 🧙 The setup wizard

The wizard runs whenever no Event Hub credentials are configured, neither in `.env`
nor in the environment, which is the case on first launch.
It is a full TUI: pick with the arrow keys, **Next →** moves on, and every screen
has a **Back** button. `Ctrl` + `Q` quits; on the confirmation dialogs `Escape` or
`q` dismisses. Re-run the wizard any time with `--reconfigure`.

macOS and Linux:

```bash
./az-firewall-watch --reconfigure
```

Windows:

```powershell
.\az-firewall-watch.exe --reconfigure
```

The wizard asks up to three questions, one per step: which Event Hub to use, how
to authenticate against it, and whether the viewer may read policy context from
Azure. The authentication step is skipped where the path already implies it.

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

After picking a hub with Discover or Deploy new, a follow-up screen asks **how**
to authenticate against it:

- **Entra ID** *(recommended)*: passwordless auth via your Azure CLI login
  (`az login`), managed identity, environment credentials, and so on. Nothing secret is written
  to `.env`. Requires the **Azure Event Hubs Data Receiver** role on the namespace
  or hub; the wizard verifies your assignment up front.
- **SAS auth rule**: looks for a reusable Listen-only authorization rule on the
  hub; if none exists you are asked to confirm the creation of a new one before
  the connection string is written to `.env`.

The *Enter existing* path skips this screen and always uses Entra ID; the *Paste
connection string* path skips it too, since SAS is already implied.

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

## When the wizard is done

Once `.env` is written, the viewer starts in the same run, so you do not launch it
again. From then on, start the app as before. The wizard only runs again when
no Event Hub credentials are found (in `.env` or the environment) or you pass
`--reconfigure`.

Events show up as soon as the firewall sends them. Quit the viewer with `q` or
`Ctrl` + `Q`.

## Next steps

- [Using the viewer](using-the-viewer.md): filters, key bindings, row details.
- [Configuration](configuration.md) for when you would rather write `.env` yourself.
