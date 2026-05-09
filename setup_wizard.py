#!/usr/bin/env python3
"""
Cross-platform setup wizard for fw-log-tui.

Checks for Azure CLI, verifies login, and writes the Event Hub connection
string to .env.  Works on Linux, macOS, and Windows.

Usage (standalone):
    python setup_wizard.py [--reconfigure]

Called automatically by main.py when EVENT_HUB_CONNECTION_STRING is not set.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ── platform helpers ───────────────────────────────────────────────────────────
_IS_WIN = platform.system() == "Windows"

# On Windows, `az` is a batch wrapper (az.cmd); shutil.which respects PATHEXT.
def _find_az() -> Optional[str]:
    return shutil.which("az") or shutil.which("az.cmd")


def _run_az(*args: str, capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    az = _find_az()
    if not az:
        raise FileNotFoundError("Azure CLI not found")
    return subprocess.run(
        [az, *args],
        capture_output=capture,
        text=True,
        check=check,
    )


# ── colour helpers ─────────────────────────────────────────────────────────────
def _c(code: str, text: str) -> str:
    # Windows terminals support ANSI since Windows 10 1903 (with ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    # sys.stdout.isatty() guard avoids garbled output when piped
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def ok(msg: str)   -> None: print(f"  {_c('32', '✓')}  {msg}")
def fail(msg: str) -> None: print(f"  {_c('31', '✗')}  {msg}", file=sys.stderr)
def info(msg: str) -> None: print(f"  {_c('36', 'i')}  {msg}")
def warn(msg: str) -> None: print(f"  {_c('33', '!')}  {msg}")
def bold(text: str) -> str: return _c("1", text)


def print_header() -> None:
    print()
    print(_c("1;36", "╔═══════════════════════════════════════════════════════════════╗"))
    print(_c("1;36", "║             Azure Firewall Watch  —  Setup Wizard             ║"))
    print(_c("1;36", "╚═══════════════════════════════════════════════════════════════╝"))
    print()


def show_menu() -> None:
    print(bold("How do you want to connect to Azure Event Hub?"))
    print()
    print("    1)  Choose from existing Event Hubs in my subscriptions")
    print("    2)  Discover firewall, deploy Event Hub + configure diagnostics  (~2–3 min)")
    print("    q)  Quit")
    print()


# ── Azure CLI checks ───────────────────────────────────────────────────────────
def check_az_cli() -> None:
    if not _find_az():
        fail("Azure CLI is not installed.")
        print()
        print("  Install it with one of the following commands:")
        print("    macOS   :  brew install azure-cli")
        print("    Ubuntu  :  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
        print("    Windows :  winget install Microsoft.AzureCLI")
        print("    All OS  :  https://learn.microsoft.com/cli/azure/install-azure-cli")
        print()
        sys.exit(1)

    result = _run_az("version", "--query", '"azure-cli"', "-o", "tsv")
    version = result.stdout.strip() if result.returncode == 0 else "unknown"
    ok(f"Azure CLI found ({version})")


def check_login() -> None:
    result = _run_az("account", "show", "--query", "user.name", "-o", "tsv")
    if result.returncode != 0:
        warn("Not logged in — starting interactive login…")
        az = _find_az()
        assert az
        subprocess.run([az, "login"], check=True, capture_output=False)
        result = _run_az("account", "show", "--query", "user.name", "-o", "tsv")

    user = result.stdout.strip()
    tenant_result = _run_az("account", "show", "--query", "tenantDisplayName", "-o", "tsv")
    tenant = tenant_result.stdout.strip() if tenant_result.returncode == 0 else "unknown tenant"
    ok(f"Logged in as {bold(user)}  (tenant: {tenant})")


# ── .env helpers ───────────────────────────────────────────────────────────────
def get_existing_conn_str(env_file: Path) -> Optional[str]:
    if not env_file.exists():
        return None
    for line in env_file.read_text().splitlines():
        if line.startswith("EVENT_HUB_CONNECTION_STRING="):
            value = line[len("EVENT_HUB_CONNECTION_STRING="):].strip()
            return value if value else None
    return None


def write_env(env_file: Path, conn_str: str) -> None:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_file.write_text(
        f"# Written by setup_wizard.py — {ts}\n"
        "# Do NOT commit this file — it contains a shared access key.\n"
        f"EVENT_HUB_CONNECTION_STRING={conn_str}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n"
    )
    ok(f".env written to {env_file}")


# ── location abbreviation (CAF style) ─────────────────────────────────────────
_LOC_SHORT: dict[str, str] = {
    "germanywestcentral": "gwc", "germanynorth": "gn",
    "westeurope": "we",          "northeurope": "ne",
    "eastus": "eus",             "eastus2": "eus2",
    "westus": "wus",             "westus2": "wus2",
    "centralus": "cus",          "uksouth": "uks",
    "ukwest": "ukw",             "francecentral": "frc",
    "swedencentral": "swc",      "switzerlandnorth": "swn",
    "australiaeast": "ae",       "southeastasia": "sea",
    "eastasia": "ea",            "japaneast": "jpe",
}


def location_short(loc: str) -> str:
    return _LOC_SHORT.get(loc.lower(), loc[:6])


# ── 3a. Pick an existing Event Hub ────────────────────────────────────────────
def pick_existing_eventhub(env_file: Path) -> bool:
    info("Scanning your subscriptions for Event Hubs…")
    print()

    # Fetch all enabled subscriptions
    subs_result = _run_az(
        "account", "list",
        "--query", "[?state=='Enabled'].{id:id, name:name}",
        "-o", "json",
    )
    subs = json.loads(subs_result.stdout) if subs_result.returncode == 0 else []

    items: list[tuple[str, str, str, str, str]] = []  # (sub_id, sub_name, rg, ns, eh)

    for sub in subs:
        sub_id, sub_name = sub["id"], sub["name"]
        ns_result = _run_az(
            "eventhubs", "namespace", "list",
            "--subscription", sub_id,
            "--query", "[].{name:name, rg:resourceGroup}",
            "-o", "json",
        )
        if ns_result.returncode != 0:
            continue
        namespaces = json.loads(ns_result.stdout) or []

        for ns_info in namespaces:
            ns, rg = ns_info["name"], ns_info["rg"]
            eh_result = _run_az(
                "eventhubs", "eventhub", "list",
                "--namespace-name", ns,
                "--resource-group", rg,
                "--subscription", sub_id,
                "--query", "[].name",
                "-o", "json",
            )
            if eh_result.returncode != 0:
                continue
            for eh in (json.loads(eh_result.stdout) or []):
                items.append((sub_id, sub_name, rg, ns, eh))

    if not items:
        warn("No Event Hubs found in your accessible subscriptions.")
        return False

    print(f"  {bold('Available Event Hubs:')}")
    print()
    for i, (sid, sname, rg, ns, eh) in enumerate(items, 1):
        print(f"    {bold(str(i))}  {bold(eh)}  (namespace: {ns}, rg: {rg}, sub: {sname})")
    print()

    while True:
        raw = input(f"  Select Event Hub [1-{len(items)}] or q to go back: ").strip()
        if raw.lower() == "q":
            return False
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            choice = int(raw)
            break
        warn(f"Please enter a number between 1 and {len(items)}.")

    sub_id, _sub_name, rg, ns, eh = items[choice - 1]
    rule_name = "firewall-mon-listen"

    info(f"Looking up authorization rule '{rule_name}' on Event Hub '{eh}'…")
    keys_result = _run_az(
        "eventhubs", "eventhub", "authorization-rule", "keys", "list",
        "--subscription", sub_id,
        "--resource-group", rg,
        "--namespace-name", ns,
        "--eventhub-name", eh,
        "--name", rule_name,
        "--query", "primaryConnectionString",
        "-o", "tsv",
    )

    if keys_result.returncode == 0 and keys_result.stdout.strip():
        conn_str = keys_result.stdout.strip()
        ok(f"Found authorization rule '{rule_name}'")
    else:
        warn(f"Authorization rule '{rule_name}' not found — creating it now…")
        _run_az(
            "eventhubs", "eventhub", "authorization-rule", "create",
            "--subscription", sub_id,
            "--resource-group", rg,
            "--namespace-name", ns,
            "--eventhub-name", eh,
            "--name", rule_name,
            "--rights", "Listen",
            "--output", "none",
            check=True,
        )
        keys_result = _run_az(
            "eventhubs", "eventhub", "authorization-rule", "keys", "list",
            "--subscription", sub_id,
            "--resource-group", rg,
            "--namespace-name", ns,
            "--eventhub-name", eh,
            "--name", rule_name,
            "--query", "primaryConnectionString",
            "-o", "tsv",
            check=True,
        )
        conn_str = keys_result.stdout.strip()
        ok("Authorization rule created")

    write_env(env_file, conn_str)
    return True


# ── 3b. Deploy a new Event Hub and configure diagnostics ─────────────────────
def deploy_new_eventhub(env_file: Path) -> bool:
    print()
    print(f"  {bold('Deploy a new Event Hub + configure diagnostic settings')}")
    print(f"  {_c('36', 'Discovers your Azure Firewall, creates an Event Hub (Basic SKU),')}")
    print(f"  {_c('36', 'and wires diagnostic settings so logs stream in real time.')}")
    print()

    # ── subscription ──────────────────────────────────────────────────────────
    subs_result = _run_az(
        "account", "list",
        "--query", "[?state=='Enabled'].{id:id, name:name}",
        "-o", "json",
    )
    subs = json.loads(subs_result.stdout) if subs_result.returncode == 0 else []
    if not subs:
        fail("No enabled subscriptions found.")
        return False

    print(f"  {bold('Available subscriptions:')}")
    print()
    for i, s in enumerate(subs, 1):
        print(f"    {bold(str(i))}  {s['name']}  ({s['id']})")
    print()

    while True:
        raw = input(f"  Select subscription [1-{len(subs)}] or q to go back: ").strip()
        if raw.lower() == "q":
            return False
        if raw.isdigit() and 1 <= int(raw) <= len(subs):
            break
        warn(f"Please enter a number between 1 and {len(subs)}.")

    target_sub      = subs[int(raw) - 1]["id"]
    target_sub_name = subs[int(raw) - 1]["name"]
    ok(f"Using subscription: {target_sub_name}")
    print()

    # ── discover Azure Firewalls ──────────────────────────────────────────────
    info("Scanning for Azure Firewalls in this subscription…")
    fw_result = _run_az(
        "network", "firewall", "list",
        "--subscription", target_sub,
        "--query", "[].{name:name, rg:resourceGroup, location:location, id:id}",
        "-o", "json",
    )
    firewalls = json.loads(fw_result.stdout) if fw_result.returncode == 0 else []

    selected_fw: Optional[dict] = None
    location: str

    if not firewalls:
        warn("No Azure Firewalls found — Event Hub will be created without diagnostic settings.")
        print()
        loc_input = input("  Location [westeurope]: ").strip()
        location = loc_input or "westeurope"
    else:
        print()
        print(f"  {bold('Azure Firewalls found:')}")
        print()
        skip_idx = len(firewalls) + 1
        for i, fw in enumerate(firewalls, 1):
            print(f"    {bold(str(i))}  {bold(fw['name'])}  "
                  f"(rg: {fw['rg']}, location: {fw['location']})")
        print(f"    {bold(str(skip_idx))}  "
              f"Skip — deploy Event Hub only, configure diagnostics later")
        print()

        while True:
            raw_fw = input(f"  Select firewall [1-{skip_idx}] or q to go back: ").strip()
            if raw_fw.lower() == "q":
                return False
            if raw_fw.isdigit() and 1 <= int(raw_fw) <= skip_idx:
                break
            warn(f"Please enter a number between 1 and {skip_idx}.")

        if int(raw_fw) < skip_idx:
            selected_fw = firewalls[int(raw_fw) - 1]
            assert selected_fw is not None
            location = selected_fw["location"]
            ok(f"Selected firewall: {selected_fw['name']}  (location: {location})")
        else:
            loc_input = input("  Location [westeurope]: ").strip()
            location = loc_input or "westeurope"
        print()

    loc_abbr = location_short(location)

    # ── naming ────────────────────────────────────────────────────────────────
    env_tag = input("  Environment (dev/staging/prod) [dev]: ").strip() or "dev"

    # Default resource group: prefer the firewall's RG so everything is co-located
    rg_default = selected_fw["rg"] if selected_fw else f"rg-fwlogs-{env_tag}-{loc_abbr}-001"
    rg = input(f"  Resource group [{rg_default}]: ").strip() or rg_default

    ns_default = f"ehns-fwlogs-{env_tag}-{loc_abbr}-001"
    ns = input(f"  Event Hub namespace name [{ns_default}]: ").strip() or ns_default

    eh_name     = "firewall-logs"
    listen_rule = "firewall-mon-listen"
    send_rule   = "fw-diag-send"
    diag_name   = "fw-logs-to-eventhub"

    # ── summary ───────────────────────────────────────────────────────────────
    print()
    print(f"  {bold('Summary:')}")
    rows: list[tuple[str, str]] = [
        ("Subscription :",   target_sub_name),
        ("Location :",       location),
        ("Resource group :", rg),
        ("EH Namespace :",   ns),
        ("Event Hub :",      eh_name),
        ("Listen rule :",    f"{listen_rule}  (Listen — for this app)"),
    ]
    if selected_fw:
        rows.insert(2, ("Firewall :", f"{selected_fw['name']}  → diagnostic settings will be configured"))
        rows.append(("Send rule :",    f"{send_rule}  (Send — for Azure Monitor)"))
        rows.append(("Diag setting :", diag_name))
    for label, val in rows:
        print(f"    {label:<22} {val}")
    print()

    confirm = input("  Proceed? [Y/n]: ").strip().lower()
    if confirm == "n":
        return False

    print()
    tags = [f"environment={env_tag}", "project=az-firewall-watch", "managed-by=az-cli"]

    # ── resource group ────────────────────────────────────────────────────────
    using_existing_rg = selected_fw and rg == selected_fw["rg"]
    if using_existing_rg:
        info(f"Using existing resource group '{rg}'…")
        ok("Resource group ready")
    else:
        info(f"Creating resource group '{rg}'…")
        _run_az(
            "group", "create",
            "--subscription", target_sub,
            "--name", rg,
            "--location", location,
            "--tags", *tags,
            "--output", "none",
            check=True,
        )
        ok("Resource group ready")

    # ── Event Hub namespace — Basic SKU (smallest / cheapest) ─────────────────
    info(f"Creating Event Hub namespace '{ns}' (Basic SKU)…")
    _run_az(
        "eventhubs", "namespace", "create",
        "--subscription", target_sub,
        "--name", ns,
        "--resource-group", rg,
        "--location", location,
        "--sku", "Basic",
        "--minimum-tls-version", "1.2",
        "--tags", *tags,
        "--output", "none",
        check=True,
    )
    ok("Namespace ready")

    # ── Event Hub ─────────────────────────────────────────────────────────────
    info(f"Creating Event Hub '{eh_name}'…")
    _run_az(
        "eventhubs", "eventhub", "create",
        "--subscription", target_sub,
        "--name", eh_name,
        "--namespace-name", ns,
        "--resource-group", rg,
        "--partition-count", "1",
        "--output", "none",
        check=True,
    )
    ok("Event Hub ready")

    # ── Listen auth rule (used by this app to receive logs) ───────────────────
    info(f"Creating Listen authorization rule '{listen_rule}'…")
    _run_az(
        "eventhubs", "eventhub", "authorization-rule", "create",
        "--subscription", target_sub,
        "--resource-group", rg,
        "--namespace-name", ns,
        "--eventhub-name", eh_name,
        "--name", listen_rule,
        "--rights", "Listen",
        "--output", "none",
        check=True,
    )
    ok("Listen authorization rule created")

    # Retrieve connection string for the app
    keys_result = _run_az(
        "eventhubs", "eventhub", "authorization-rule", "keys", "list",
        "--subscription", target_sub,
        "--resource-group", rg,
        "--namespace-name", ns,
        "--eventhub-name", eh_name,
        "--name", listen_rule,
        "--query", "primaryConnectionString",
        "-o", "tsv",
        check=True,
    )
    conn_str = keys_result.stdout.strip()

    # ── Send auth rule + diagnostic settings (if a firewall was selected) ─────
    if selected_fw:
        # Namespace-level Send rule for Azure Monitor to authenticate
        info(f"Creating Send authorization rule '{send_rule}' for Azure Monitor…")
        _run_az(
            "eventhubs", "namespace", "authorization-rule", "create",
            "--subscription", target_sub,
            "--resource-group", rg,
            "--namespace-name", ns,
            "--name", send_rule,
            "--rights", "Send",
            "--output", "none",
            check=True,
        )
        ok("Send authorization rule created")

        send_rule_result = _run_az(
            "eventhubs", "namespace", "authorization-rule", "show",
            "--subscription", target_sub,
            "--resource-group", rg,
            "--namespace-name", ns,
            "--name", send_rule,
            "--query", "id",
            "-o", "tsv",
            check=True,
        )
        send_rule_id = send_rule_result.stdout.strip()

        # Discover which diagnostic log categories the firewall supports,
        # then filter to AZFW* only — these are the resource-specific log format
        # (structured logs). Legacy AzureFirewall* categories are excluded.
        info("Discovering available diagnostic log categories on the firewall…")
        cats_result = _run_az(
            "monitor", "diagnostic-settings", "categories", "list",
            "--resource", selected_fw["id"],
            "--query", "value[?categoryType=='Logs'].name",
            "-o", "json",
        )
        available_cats = []
        if cats_result.returncode == 0 and cats_result.stdout.strip():
            all_cats = json.loads(cats_result.stdout) or []
            # Keep only resource-specific structured log categories (AZFW prefix)
            available_cats = [c for c in all_cats if c.startswith("AZFW")]
        if not available_cats:
            # Fallback if query failed or returned no AZFW categories
            available_cats = [
                "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule",
                "AZFWThreatIntel", "AZFWIdpsSignature", "AZFWDnsQuery", "AZFWDnsProxy",
            ]
        diag_logs = json.dumps([{"category": c, "enabled": True} for c in available_cats])

        info(f"Configuring diagnostic settings '{diag_name}' on '{selected_fw['name']}'…")
        diag_result = _run_az(
            "monitor", "diagnostic-settings", "create",
            "--name", diag_name,
            "--resource", selected_fw["id"],
            "--event-hub", eh_name,
            "--event-hub-rule", send_rule_id,
            "--logs", diag_logs,
            "--output", "none",
        )
        if diag_result.returncode == 0:
            ok(f"Diagnostic settings '{diag_name}' configured — logs will start flowing shortly")
        else:
            warn("Could not configure diagnostic settings automatically.")
            warn(f"  Reason: {diag_result.stderr.strip()[:200]}")
            warn("  Please configure manually in the Azure Portal:")
            warn(f"    Firewall '{selected_fw['name']}' → Diagnostic settings → Add")
            warn(f"    → Stream to Event Hub → namespace: {ns}, hub: {eh_name}")

    write_env(env_file, conn_str)
    return True


# ── main entry point ──────────────────────────────────────────────────────────
def run_wizard(base_dir: Path, reconfigure: bool = False) -> None:
    """Run the setup wizard. Returns when .env is ready."""
    env_file = base_dir / ".env"

    # Skip if already configured
    if not reconfigure and get_existing_conn_str(env_file):
        return

    print_header()
    check_az_cli()
    check_login()

    while True:
        print()
        show_menu()
        choice = input("  Choice [1/2/q]: ").strip().lower()
        print()
        if choice == "1":
            if pick_existing_eventhub(env_file):
                break
        elif choice == "2":
            if deploy_new_eventhub(env_file):
                break
        elif choice == "q":
            print("  Bye.")
            sys.exit(0)
        else:
            warn("Please enter 1, 2, or q.")

    print()
    ok("Setup complete — launching the TUI…")
    print()


if __name__ == "__main__":
    reconfigure = "--reconfigure" in sys.argv
    run_wizard(Path(__file__).parent, reconfigure=reconfigure)
