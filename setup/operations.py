"""Azure CLI orchestration helpers for the setup wizard.

All functions are pure-async (no Textual imports) and accept a ``log``
callback so the TUI can stream progress messages in real-time.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
from collections.abc import Awaitable, Callable
from typing import Any

from .utils import az_async, find_az

# (sub_id, sub_name, resource_group, namespace, event_hub)
HubItem = tuple[str, str, str, str, str]
Log = Callable[[Any], Any]


# ---------------------------------------------------------------------------
# Login / subscription helpers
# ---------------------------------------------------------------------------

async def cli_ensure_login(
    log: Log,
    suspend: Callable[[], Any],
) -> tuple[str, str]:
    """Verify the Azure CLI is installed and the user is logged in.

    Performs ``az login`` (suspending the TUI) if necessary.

    Returns ``(username, object_id)``.  *object_id* may be an empty string
    if the signed-in-user lookup fails.

    Raises :class:`RuntimeError` if the CLI is not found.
    Raises :class:`subprocess.CalledProcessError` if ``az login`` fails.
    """
    az = find_az()
    if not az:
        raise RuntimeError(
            "Azure CLI not found.\n"
            "  macOS:   brew install azure-cli\n"
            "  Ubuntu:  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash\n"
            "  Windows: winget install Microsoft.AzureCLI"
        )

    result = await az_async("version", "--query", '"azure-cli"', "-o", "tsv")
    version = result.stdout.strip() if result.returncode == 0 else "unknown"
    log(f"[green]✓[/] Azure CLI {version}")

    acc = await az_async("account", "show", "--query", "user.name", "-o", "tsv")
    if acc.returncode != 0:
        log("[yellow]![/] Not logged in — starting az login…")
        with suspend():
            subprocess.run([az, "login"], check=True)
        acc = await az_async("account", "show", "--query", "user.name", "-o", "tsv")

    username = acc.stdout.strip()
    log(f"[green]✓[/] Logged in as [bold]{username}[/]")

    oid_result = await az_async(
        "ad", "signed-in-user", "show", "--query", "id", "-o", "tsv"
    )
    user_id = (
        oid_result.stdout.strip()
        if oid_result.returncode == 0 and oid_result.stdout.strip()
        else ""
    )
    return username, user_id


async def list_subscriptions(log: Log) -> list[dict]:
    """Return all enabled subscriptions as ``[{id, name}, …]``."""
    result = await az_async(
        "account", "list",
        "--query", "[?state=='Enabled'].{id:id, name:name}",
        "-o", "json",
    )
    subs: list[dict] = json.loads(result.stdout) if result.returncode == 0 else []
    log(f"[cyan]i[/] Found {len(subs)} subscription(s)")
    return subs


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

async def scan_event_hubs(
    subs: list[dict],
    log: Log,
) -> list[HubItem]:
    """Scan *subs* for all accessible Event Hubs.

    Returns a list of ``(sub_id, sub_name, rg, namespace, event_hub)`` tuples.
    """
    items: list[HubItem] = []
    for sub in subs:
        sub_id, sub_name = sub["id"], sub["name"]
        log(f"[cyan]i[/] Scanning {sub_name}…")
        ns_result = await az_async(
            "eventhubs", "namespace", "list",
            "--subscription", sub_id,
            "--query", "[].{name:name, rg:resourceGroup}",
            "-o", "json",
        )
        if ns_result.returncode != 0:
            continue
        for ns_info in (json.loads(ns_result.stdout) or []):
            ns, rg = ns_info["name"], ns_info["rg"]
            eh_result = await az_async(
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
                log(f"[green]✓[/] {eh}  (ns: {ns}, rg: {rg})")
    return items


async def scan_firewalls(
    sub_id: str,
    sub_name: str,
    log: Log,
) -> list[dict]:
    """List Azure Firewalls in *sub_id*.

    Returns a list of ``{name, rg, location, id}`` dicts.
    """
    log(f"[cyan]i[/] Scanning for firewalls in {sub_name}…")
    result = await az_async(
        "network", "firewall", "list",
        "--subscription", sub_id,
        "--query", "[].{name:name, rg:resourceGroup, location:location, id:id}",
        "-o", "json",
    )
    return json.loads(result.stdout) if result.returncode == 0 else []


# ---------------------------------------------------------------------------
# SAS connection-string resolution
# ---------------------------------------------------------------------------

def _has_listen_rights(rule: dict) -> bool:
    rights = rule.get("rights") or []
    if isinstance(rights, str):
        rights = [rights]
    return "Listen" in rights or "Manage" in rights


def _with_entity_path(raw: str, eh: str) -> str:
    if "EntityPath=" in raw:
        return raw
    sep = "" if raw.endswith(";") else ";"
    return f"{raw}{sep}EntityPath={eh}"


async def resolve_sas_conn_str(
    sub_id: str,
    rg: str,
    ns: str,
    eh: str,
    rule_name: str,
    log: Log,
    confirm_create: Callable[[], Awaitable[bool]],
) -> str:
    """Resolve a SAS connection string for *eh* using a three-step strategy:

    1. Reuse an existing entity-level rule that has Listen/Manage rights.
    2. Fall back to an existing namespace-level rule (excluding
       ``RootManageSharedAccessKey``).
    3. Offer to create a new entity-level rule (calls *confirm_create* first).

    Returns the connection string, or ``""`` if the user cancels creation.
    Raises on unrecoverable CLI errors (``check=True`` paths).
    """
    log(f"[cyan]i[/] Looking up auth rule '{rule_name}'…")
    conn_str = ""

    # 1) Entity-level rules
    entity_result = await az_async(
        "eventhubs", "eventhub", "authorization-rule", "list",
        "--subscription", sub_id, "--resource-group", rg,
        "--namespace-name", ns, "--eventhub-name", eh,
        "-o", "json",
    )
    entity_rules: list[dict] = (
        json.loads(entity_result.stdout)
        if entity_result.returncode == 0 and entity_result.stdout.strip()
        else []
    )
    preferred = next(
        (r for r in entity_rules if r.get("name") == rule_name and _has_listen_rights(r)),
        None,
    )
    chosen = preferred or next((r for r in entity_rules if _has_listen_rights(r)), None)
    if chosen:
        name = chosen["name"]
        log(f"[green]✓[/] Using existing Event Hub rule '{name}'")
        keys = await az_async(
            "eventhubs", "eventhub", "authorization-rule", "keys", "list",
            "--subscription", sub_id, "--resource-group", rg,
            "--namespace-name", ns, "--eventhub-name", eh,
            "--name", name, "--query", "primaryConnectionString", "-o", "tsv",
        )
        if keys.returncode == 0 and keys.stdout.strip():
            conn_str = _with_entity_path(keys.stdout.strip(), eh)

    # 2) Namespace-level rules
    if not conn_str:
        ns_result = await az_async(
            "eventhubs", "namespace", "authorization-rule", "list",
            "--subscription", sub_id, "--resource-group", rg,
            "--namespace-name", ns,
            "-o", "json",
        )
        ns_rules: list[dict] = (
            json.loads(ns_result.stdout)
            if ns_result.returncode == 0 and ns_result.stdout.strip()
            else []
        )
        preferred_ns = next(
            (r for r in ns_rules if r.get("name") == rule_name and _has_listen_rights(r)),
            None,
        )
        chosen_ns = preferred_ns or next(
            (
                r for r in ns_rules
                if r.get("name") != "RootManageSharedAccessKey" and _has_listen_rights(r)
            ),
            None,
        )
        if chosen_ns:
            name = chosen_ns["name"]
            log(f"[green]✓[/] Using existing namespace rule '{name}'")
            keys = await az_async(
                "eventhubs", "namespace", "authorization-rule", "keys", "list",
                "--subscription", sub_id, "--resource-group", rg,
                "--namespace-name", ns,
                "--name", name, "--query", "primaryConnectionString", "-o", "tsv",
            )
            if keys.returncode == 0 and keys.stdout.strip():
                conn_str = _with_entity_path(keys.stdout.strip(), eh)

    # 3) Create a new entity-level rule (with confirmation)
    if not conn_str:
        if not await confirm_create():
            log("[yellow]![/] Rule creation canceled by user")
            return ""
        log(f"[yellow]![/] No reusable Listen rule found — creating '{rule_name}'…")
        await az_async(
            "eventhubs", "eventhub", "authorization-rule", "create",
            "--subscription", sub_id, "--resource-group", rg,
            "--namespace-name", ns, "--eventhub-name", eh,
            "--name", rule_name, "--rights", "Listen", "--output", "none",
            check=True,
        )
        keys = await az_async(
            "eventhubs", "eventhub", "authorization-rule", "keys", "list",
            "--subscription", sub_id, "--resource-group", rg,
            "--namespace-name", ns, "--eventhub-name", eh,
            "--name", rule_name, "--query", "primaryConnectionString", "-o", "tsv",
            check=True,
        )
        conn_str = _with_entity_path(keys.stdout.strip(), eh)
        log("[green]✓[/] Auth rule created")

    return conn_str


# ---------------------------------------------------------------------------
# Full deployment
# ---------------------------------------------------------------------------

async def deploy_new_hub(
    sub_id: str,
    rg: str,
    ns: str,
    location: str,
    eh_name: str,
    listen_rule: str,
    send_rule: str,
    diag_name: str,
    fw: dict,
    auth_method: str,
    current_user_id: str,
    using_existing_rg: bool,
    log: Log,
) -> str:
    """Deploy an Event Hub namespace + hub, configure diagnostics, and (for
    Entra ID) assign the Data Receiver RBAC role.

    Returns the SAS primary connection string for ``auth_method='sas'``,
    or ``""`` for ``auth_method='entra'``.

    Raises on Azure CLI errors (``check=True`` paths).
    """
    tags = ["project=az-firewall-watch", "managed-by=az-cli"]

    # Resource group
    if using_existing_rg:
        log(f"[cyan]i[/] Using existing resource group '{rg}'")
    else:
        log(f"[cyan]i[/] Creating resource group '{rg}'…")
        await az_async(
            "group", "create",
            "--subscription", sub_id,
            "--name", rg, "--location", location,
            "--tags", *tags, "--output", "none",
            check=True,
        )
    log("[green]✓[/] Resource group ready")

    # Namespace
    log(f"[cyan]i[/] Creating namespace '{ns}' (Basic SKU)…")
    await az_async(
        "eventhubs", "namespace", "create",
        "--subscription", sub_id,
        "--name", ns, "--resource-group", rg, "--location", location,
        "--sku", "Basic", "--minimum-tls-version", "1.2",
        "--tags", *tags, "--output", "none",
        check=True,
    )
    log("[green]✓[/] Namespace ready")

    # Event Hub
    log(f"[cyan]i[/] Creating Event Hub '{eh_name}'…")
    await az_async(
        "eventhubs", "eventhub", "create",
        "--subscription", sub_id,
        "--name", eh_name, "--namespace-name", ns,
        "--resource-group", rg, "--partition-count", "1",
        "--output", "none",
        check=True,
    )
    log("[green]✓[/] Event Hub ready")

    # SAS: Listen rule + connection string
    conn_str = ""
    if auth_method == "sas":
        log(f"[cyan]i[/] Creating Listen rule '{listen_rule}'…")
        await az_async(
            "eventhubs", "eventhub", "authorization-rule", "create",
            "--subscription", sub_id,
            "--resource-group", rg, "--namespace-name", ns,
            "--eventhub-name", eh_name, "--name", listen_rule,
            "--rights", "Listen", "--output", "none",
            check=True,
        )
        log("[green]✓[/] Listen rule created")
        keys = await az_async(
            "eventhubs", "eventhub", "authorization-rule", "keys", "list",
            "--subscription", sub_id,
            "--resource-group", rg, "--namespace-name", ns,
            "--eventhub-name", eh_name, "--name", listen_rule,
            "--query", "primaryConnectionString", "-o", "tsv",
            check=True,
        )
        conn_str = keys.stdout.strip()

    # Send rule (used by diagnostics)
    log(f"[cyan]i[/] Creating Send rule '{send_rule}'…")
    await az_async(
        "eventhubs", "namespace", "authorization-rule", "create",
        "--subscription", sub_id,
        "--resource-group", rg, "--namespace-name", ns,
        "--name", send_rule, "--rights", "Send",
        "--output", "none",
        check=True,
    )
    log("[green]✓[/] Send rule created")

    send_rule_result = await az_async(
        "eventhubs", "namespace", "authorization-rule", "show",
        "--subscription", sub_id,
        "--resource-group", rg, "--namespace-name", ns,
        "--name", send_rule, "--query", "id", "-o", "tsv",
        check=True,
    )
    send_rule_id = send_rule_result.stdout.strip()

    # Diagnostics
    log("[cyan]i[/] Discovering diagnostic log categories…")
    cats_result = await az_async(
        "monitor", "diagnostic-settings", "categories", "list",
        "--resource", fw["id"],
        "--query", "value[?categoryType=='Logs'].name",
        "-o", "json",
    )
    available_cats: list[str] = []
    if cats_result.returncode == 0 and cats_result.stdout.strip():
        all_cats: list[str] = json.loads(cats_result.stdout) or []
        available_cats = [c for c in all_cats if c.startswith("AZFW")]
    if not available_cats:
        available_cats = [
            "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule",
            "AZFWThreatIntel", "AZFWIdpsSignature", "AZFWDnsQuery", "AZFWDnsProxy",
        ]
    diag_logs = json.dumps([{"category": c, "enabled": True} for c in available_cats])

    log(f"[cyan]i[/] Configuring diagnostic settings '{diag_name}'…")
    diag_result = await az_async(
        "monitor", "diagnostic-settings", "create",
        "--name", diag_name,
        "--resource", fw["id"],
        "--event-hub", eh_name,
        "--event-hub-rule", send_rule_id,
        "--logs", diag_logs,
        "--output", "none",
    )
    if diag_result.returncode == 0:
        log("[green]✓[/] Diagnostic settings configured — logs will start flowing shortly")
    else:
        log(
            f"[yellow]![/] Could not configure diagnostics automatically.\n"
            f"    Configure manually in Azure Portal:\n"
            f"    Firewall '{fw['name']}' → Diagnostic settings → Add\n"
            f"    → Stream to Event Hub → ns: {ns}, hub: {eh_name}"
        )

    # Entra ID: assign Data Receiver role + propagation countdown
    if auth_method == "entra":
        eh_scope = (
            f"/subscriptions/{sub_id}/resourceGroups/{rg}"
            f"/providers/Microsoft.EventHub/namespaces/{ns}/eventhubs/{eh_name}"
        )
        log("[cyan]i[/] Assigning 'Azure Event Hubs Data Receiver' role…")
        if current_user_id:
            rbac_result = await az_async(
                "role", "assignment", "create",
                "--assignee-object-id", current_user_id,
                "--assignee-principal-type", "User",
                "--role", "a638d3c7-ab3a-418d-83e6-5f17a39d4fde",
                "--scope", eh_scope,
                "--output", "none",
            )
            if rbac_result.returncode == 0:
                log("[green]✓[/] Data Receiver role assigned")
                for remaining in range(30, 0, -1):
                    log(f"[cyan]i[/] Waiting for permissions to propagate… {remaining}s")
                    await asyncio.sleep(1)
            else:
                log(
                    "[yellow]![/] Could not assign role automatically — assign manually:\n"
                    "    Role: 'Azure Event Hubs Data Receiver'\n"
                    f"    Scope: {eh_scope}"
                )
        else:
            log(
                "[yellow]![/] Could not determine current user — assign manually:\n"
                "    Role: 'Azure Event Hubs Data Receiver'\n"
                f"    Scope: {eh_scope}"
            )

    return conn_str
