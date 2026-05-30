from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING, cast

from textual import work
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    ContentSwitcher,
    Input,
    Label,
    ListItem,
    ListView,
    LoadingIndicator,
    RadioButton,
    RadioSet,
    RichLog,
    Static,
)

from .services import write_env, write_env_entra
from .utils import az_async, find_az, location_short

if TYPE_CHECKING:
    from .app import WizardApp


class _WizardScreen(Screen):
    """Base screen that exposes a typed accessor for :class:`WizardApp`."""

    @property
    def _wizard_app(self) -> "WizardApp":
        return cast("WizardApp", self.app)


class ConfirmCreateRuleScreen(ModalScreen[bool]):
    """Confirmation modal shown before creating a new auth rule."""

    def __init__(self, rule_name: str, namespace: str, event_hub: str) -> None:
        super().__init__()
        self._rule_name = rule_name
        self._namespace = namespace
        self._event_hub = event_hub

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Confirm environment change", classes="wiz-title")
            yield Static(
                "No reusable Listen auth rule was found.\n\n"
                "A new Event Hub authorization rule will be created:\n"
                f"  Rule: {self._rule_name}\n"
                f"  Namespace: {self._namespace}\n"
                f"  Event Hub: {self._event_hub}\n\n"
                "Do you want to continue?",
                classes="wiz-info",
            )
            with Horizontal(classes="wiz-buttons"):
                yield Button("Cancel", id="btn-cancel", variant="default")
                yield Button("Create Rule", id="btn-confirm", variant="warning")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-confirm":
            self.dismiss(True)
            return
        self.dismiss(False)

    def on_key(self, event) -> None:  # type: ignore[override]
        if event.key in ("escape", "q"):
            self.dismiss(False)


class WelcomeScreen(Screen):
    """Main wizard menu."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static(
                "Azure Firewall Watch — Setup Wizard",
                classes="wiz-title",
            )
            yield Static(
                "How do you want to connect to Azure Event Hub?",
                classes="wiz-info",
            )
            with RadioSet(id="welcome-radio"):
                yield RadioButton(
                    "Choose from existing Event Hubs in my subscriptions",
                    id="opt-pick",
                    value=True,
                )
                yield RadioButton(
                    "Discover firewall & deploy new Event Hub  (~2–3 min)",
                    id="opt-deploy",
                )
                yield RadioButton(
                    "Paste a connection string directly",
                    id="opt-paste",
                )
                yield RadioButton(
                    "Use Entra ID (passwordless) — enter namespace + hub name",
                    id="opt-entra",
                )
            with Horizontal(classes="wiz-buttons"):
                yield Button("Quit", id="btn-quit", variant="error")
                yield Button("Next →", id="btn-next", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-quit":
            self.app.exit()
            return
        if event.button.id == "btn-next":
            radio = self.query_one("#welcome-radio", RadioSet)
            if radio.pressed_button is None:
                return
            match radio.pressed_button.id:
                case "opt-pick":
                    self.app.push_screen(PickExistingScreen())
                case "opt-deploy":
                    self.app.push_screen(DeployNewScreen())
                case "opt-paste":
                    self.app.push_screen(PasteConnectionScreen())
                case "opt-entra":
                    self.app.push_screen(EntraIdScreen())


class PasteConnectionScreen(_WizardScreen):
    """Option 3 — paste a SAS connection string."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Paste Connection String", classes="wiz-title")
            yield Static(
                "Expected format:\n"
                "  Endpoint=sb://<namespace>.servicebus.windows.net/;"
                "SharedAccessKeyName=<rule>;SharedAccessKey=<key>;EntityPath=<hub>",
                classes="wiz-info",
            )
            yield Input(
                placeholder="Endpoint=sb://...",
                id="inp-conn",
            )
            yield Label("", id="lbl-error", classes="wiz-error")
            with Horizontal(classes="wiz-buttons"):
                yield Button("Back", id="btn-back", variant="default")
                yield Button("Save & Continue", id="btn-save", variant="success")

    def on_mount(self) -> None:
        self.query_one("#lbl-error", Label).display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return
        if event.button.id == "btn-save":
            self._validate_and_save()

    def _validate_and_save(self) -> None:
        raw = self.query_one("#inp-conn", Input).value.strip()
        err_label = self.query_one("#lbl-error", Label)
        err_label.display = False

        if not raw:
            err_label.update("Connection string must not be empty.")
            err_label.display = True
            return
        if not raw.startswith("Endpoint=sb://"):
            err_label.update(
                "Does not look like an Event Hub connection string "
                "(must start with 'Endpoint=sb://')."
            )
            err_label.display = True
            return
        if "EntityPath=" not in raw:
            err_label.update(
                "Connection string must target a specific Event Hub "
                "(must contain 'EntityPath=')."
            )
            err_label.display = True
            return

        write_env(self._wizard_app.env_file, raw)
        self.app.exit()


class EntraIdScreen(_WizardScreen):
    """Option 4 — Entra ID (passwordless) setup."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Entra ID (Passwordless) Authentication", classes="wiz-title")
            yield Static(
                "No secrets stored — uses DefaultAzureCredential\n"
                "(Azure CLI login, managed identity, environment credentials, etc.)\n\n"
                "Prerequisite: Your identity must have the\n"
                "'Azure Event Hubs Data Receiver' role on the namespace or hub.",
                classes="wiz-info",
            )
            yield Input(
                placeholder="mynamespace.servicebus.windows.net",
                id="inp-ns",
            )
            yield Input(
                placeholder="Event Hub name",
                id="inp-hub",
            )
            yield Label("", id="lbl-error", classes="wiz-error")
            with Horizontal(classes="wiz-buttons"):
                yield Button("Back", id="btn-back", variant="default")
                yield Button("Save & Continue", id="btn-save", variant="success")

    def on_mount(self) -> None:
        self.query_one("#lbl-error", Label).display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return
        if event.button.id == "btn-save":
            self._validate_and_save()

    def _validate_and_save(self) -> None:
        ns = self.query_one("#inp-ns", Input).value.strip()
        hub = self.query_one("#inp-hub", Input).value.strip()
        err_label = self.query_one("#lbl-error", Label)
        err_label.display = False

        if not ns:
            err_label.update("Namespace must not be empty.")
            err_label.display = True
            return
        if not ns.endswith(".servicebus.windows.net"):
            err_label.update("Expected format: <name>.servicebus.windows.net")
            err_label.display = True
            return
        if not hub:
            err_label.update("Event Hub name must not be empty.")
            err_label.display = True
            return

        write_env_entra(self._wizard_app.env_file, ns, hub)
        self.app.exit()


class PickExistingScreen(_WizardScreen):
    """Option 1 — pick an existing Event Hub from subscriptions."""

    _items: list

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Pick Existing Event Hub", classes="wiz-title")
            with ContentSwitcher(initial="phase-loading"):
                with Vertical(id="phase-loading"):
                    yield Static(
                        "Scanning subscriptions for Event Hubs…",
                        classes="wiz-info",
                    )
                    yield RichLog(id="scan-log", highlight=True, markup=True)
                    yield LoadingIndicator(id="scan-spinner")
                    yield Label("", id="lbl-scan-error", classes="wiz-error")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-loading", variant="default")

                with Vertical(id="phase-select"):
                    yield Static("Available Event Hubs:", classes="wiz-info")
                    yield ListView(id="hub-list")
                    yield Label("", id="lbl-select-error", classes="wiz-error")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-select", variant="default")
                        yield Button("Select", id="btn-select", variant="success")

    def on_mount(self) -> None:
        self._items = []
        self.query_one("#lbl-scan-error", Label).display = False
        self.query_one("#lbl-select-error", Label).display = False
        self._run_scan()

    @work(exclusive=True)
    async def _run_scan(self) -> None:
        log = self.query_one("#scan-log", RichLog)

        az = find_az()
        if not az:
            self._show_error(
                "Azure CLI not found.\n"
                "  macOS:   brew install azure-cli\n"
                "  Ubuntu:  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash\n"
                "  Windows: winget install Microsoft.AzureCLI",
            )
            return
        result = await az_async("version", "--query", '"azure-cli"', "-o", "tsv")
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
        log.write(f"[green]✓[/] Azure CLI {version}")

        acc = await az_async("account", "show", "--query", "user.name", "-o", "tsv")
        if acc.returncode != 0:
            log.write("[yellow]![/] Not logged in — starting az login…")
            try:
                with self.app.suspend():
                    subprocess.run([az, "login"], check=True)
            except subprocess.CalledProcessError as exc:
                self._show_error(f"az login failed: {exc}")
                return
            acc = await az_async("account", "show", "--query", "user.name", "-o", "tsv")
        user = acc.stdout.strip()
        log.write(f"[green]✓[/] Logged in as [bold]{user}[/]")

        subs_result = await az_async(
            "account", "list",
            "--query", "[?state=='Enabled'].{id:id, name:name}",
            "-o", "json",
        )
        subs = json.loads(subs_result.stdout) if subs_result.returncode == 0 else []
        log.write(f"[cyan]i[/] Found {len(subs)} subscription(s)")

        items: list[tuple[str, str, str, str, str]] = []
        for sub in subs:
            sub_id, sub_name = sub["id"], sub["name"]
            log.write(f"[cyan]i[/] Scanning {sub_name}…")
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
                    log.write(f"[green]✓[/] {eh}  (ns: {ns}, rg: {rg})")

        if not items:
            self._show_error("No Event Hubs found in your accessible subscriptions.")
            return

        self._show_results(items)

    def _show_error(self, message: str) -> None:
        self.query_one("#scan-spinner", LoadingIndicator).display = False
        err = self.query_one("#lbl-scan-error", Label)
        err.update(message)
        err.display = True

    def _show_results(self, items: list) -> None:
        self._items = items
        lv = self.query_one("#hub-list", ListView)
        for _sid, sub_name, rg, ns, eh in items:
            lv.append(ListItem(Static(f"{eh}  (ns: {ns}, rg: {rg}, sub: {sub_name})")))
        self.query_one(ContentSwitcher).current = "phase-select"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "btn-back-loading" | "btn-back-select":
                self.app.pop_screen()
            case "btn-select":
                self._confirm_selection()

    def _confirm_selection(self) -> None:
        lv = self.query_one("#hub-list", ListView)
        if lv.index is None:
            err = self.query_one("#lbl-select-error", Label)
            err.update("Please select an Event Hub from the list.")
            err.display = True
            return
        self._run_confirm(lv.index)

    @work(exclusive=True)
    async def _run_confirm(self, idx: int) -> None:
        sub_id, _sub_name, rg, ns, eh = self._items[idx]
        rule_name = "az-firewall-watch-listen"

        log = self.query_one("#scan-log", RichLog)
        self.query_one(ContentSwitcher).current = "phase-loading"
        log.write(f"[cyan]i[/] Looking up auth rule '{rule_name}'…")

        conn_str = ""

        def _has_listen_rights(rule: dict) -> bool:
            rights = rule.get("rights") or []
            if isinstance(rights, str):
                rights = [rights]
            return "Listen" in rights or "Manage" in rights

        def _with_entity_path(raw_conn_str: str) -> str:
            if "EntityPath=" in raw_conn_str:
                return raw_conn_str
            sep = "" if raw_conn_str.endswith(";") else ";"
            return f"{raw_conn_str}{sep}EntityPath={eh}"

        try:
            # 1) Prefer existing entity-level rule with Listen (or Manage).
            entity_rules_result = await az_async(
                "eventhubs", "eventhub", "authorization-rule", "list",
                "--subscription", sub_id, "--resource-group", rg,
                "--namespace-name", ns, "--eventhub-name", eh,
                "-o", "json",
            )
            entity_rules = (
                json.loads(entity_rules_result.stdout)
                if entity_rules_result.returncode == 0 and entity_rules_result.stdout.strip()
                else []
            )

            preferred_entity = next(
                (
                    rule for rule in entity_rules
                    if rule.get("name") == rule_name and _has_listen_rights(rule)
                ),
                None,
            )
            chosen_entity = preferred_entity or next(
                (rule for rule in entity_rules if _has_listen_rights(rule)),
                None,
            )

            if chosen_entity:
                chosen_rule_name = chosen_entity.get("name", "")
                log.write(
                    f"[green]✓[/] Using existing Event Hub rule '{chosen_rule_name}'"
                )
                keys_result = await az_async(
                    "eventhubs", "eventhub", "authorization-rule", "keys", "list",
                    "--subscription", sub_id, "--resource-group", rg,
                    "--namespace-name", ns, "--eventhub-name", eh,
                    "--name", chosen_rule_name,
                    "--query", "primaryConnectionString", "-o", "tsv",
                )
                if keys_result.returncode == 0 and keys_result.stdout.strip():
                    conn_str = _with_entity_path(keys_result.stdout.strip())

            # 2) Fall back to existing namespace-level rule with Listen (or Manage),
            # excluding RootManageSharedAccessKey.
            if not conn_str:
                namespace_rules_result = await az_async(
                    "eventhubs", "namespace", "authorization-rule", "list",
                    "--subscription", sub_id, "--resource-group", rg,
                    "--namespace-name", ns,
                    "-o", "json",
                )
                namespace_rules = (
                    json.loads(namespace_rules_result.stdout)
                    if namespace_rules_result.returncode == 0 and namespace_rules_result.stdout.strip()
                    else []
                )

                preferred_namespace = next(
                    (
                        rule for rule in namespace_rules
                        if rule.get("name") == rule_name and _has_listen_rights(rule)
                    ),
                    None,
                )
                chosen_namespace = preferred_namespace or next(
                    (
                        rule
                        for rule in namespace_rules
                        if rule.get("name") != "RootManageSharedAccessKey"
                        and _has_listen_rights(rule)
                    ),
                    None,
                )

                if chosen_namespace:
                    chosen_rule_name = chosen_namespace.get("name", "")
                    log.write(
                        f"[green]✓[/] Using existing namespace rule '{chosen_rule_name}'"
                    )
                    keys_result = await az_async(
                        "eventhubs", "namespace", "authorization-rule", "keys", "list",
                        "--subscription", sub_id, "--resource-group", rg,
                        "--namespace-name", ns,
                        "--name", chosen_rule_name,
                        "--query", "primaryConnectionString", "-o", "tsv",
                    )
                    if keys_result.returncode == 0 and keys_result.stdout.strip():
                        conn_str = _with_entity_path(keys_result.stdout.strip())

            # 3) Create dedicated entity-level Listen rule only if nothing reusable exists.
            if not conn_str:
                confirmed = await self.app.push_screen_wait(
                    ConfirmCreateRuleScreen(rule_name=rule_name, namespace=ns, event_hub=eh)
                )
                if not confirmed:
                    log.write("[yellow]![/] Rule creation canceled by user")
                    self.query_one(ContentSwitcher).current = "phase-select"
                    return

                log.write(f"[yellow]![/] No reusable Listen rule found — creating '{rule_name}'…")
                await az_async(
                    "eventhubs", "eventhub", "authorization-rule", "create",
                    "--subscription", sub_id, "--resource-group", rg,
                    "--namespace-name", ns, "--eventhub-name", eh,
                    "--name", rule_name, "--rights", "Listen", "--output", "none",
                    check=True,
                )
                keys_result = await az_async(
                    "eventhubs", "eventhub", "authorization-rule", "keys", "list",
                    "--subscription", sub_id, "--resource-group", rg,
                    "--namespace-name", ns, "--eventhub-name", eh,
                    "--name", rule_name, "--query", "primaryConnectionString", "-o", "tsv",
                    check=True,
                )
                conn_str = _with_entity_path(keys_result.stdout.strip())
                log.write("[green]✓[/] Auth rule created")

            if not conn_str:
                self._show_error("Could not retrieve a connection string for the auth rule.")
                return

            log.write("[green]✓[/] Writing .env…")
            write_env(self._wizard_app.env_file, conn_str)
            log.write("[green]✓[/] Done!")
            self.app.exit()

        except subprocess.CalledProcessError as exc:
            self._show_error(f"Failed to create authorization rule: {exc}")
        except Exception as exc:
            self._show_error(f"Failed to configure auth rule: {exc}")


class DeployNewScreen(_WizardScreen):
    """Option 2 — discover firewall, deploy new Event Hub + diagnostics."""

    _subs: list
    _target_sub: str
    _target_sub_name: str
    _firewalls: list
    _selected_fw: dict
    _location: str
    _rg: str
    _ns: str
    _eh_name: str
    _listen_rule: str
    _send_rule: str
    _diag_name: str

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Deploy New Event Hub", classes="wiz-title")
            with ContentSwitcher(initial="step-loading"):
                with Vertical(id="step-loading"):
                    yield Static("Checking Azure CLI…", classes="wiz-info")
                    yield RichLog(id="deploy-log", highlight=True, markup=True)
                    yield LoadingIndicator(id="deploy-spinner")
                    yield Label("", id="lbl-deploy-error", classes="wiz-error")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-loading", variant="default")

                with Vertical(id="step-subscription"):
                    yield Static("Select a subscription:", classes="wiz-info")
                    yield ListView(id="sub-list")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-sub", variant="default")
                        yield Button("Next →", id="btn-next-sub", variant="primary")

                with Vertical(id="step-firewall"):
                    yield Static("Select a firewall:", classes="wiz-info")
                    yield RichLog(id="fw-scan-log", highlight=True, markup=True)
                    yield LoadingIndicator(id="fw-spinner")
                    yield ListView(id="fw-list")
                    yield Label("", id="lbl-fw-error", classes="wiz-error")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-fw", variant="default")
                        yield Button("Next →", id="btn-next-fw", variant="primary")

                with Vertical(id="step-naming"):
                    yield Static("Resource naming:", classes="wiz-info")
                    yield Label("Resource group name:")
                    yield Input(id="inp-rg")
                    yield Label("Event Hub namespace name:")
                    yield Input(id="inp-ns-deploy")
                    yield Label("Event Hub name:")
                    yield Input(value="firewall-logs", id="inp-eh-name")
                    yield Label("Listen auth rule name:")
                    yield Input(value="az-firewall-watch-listen", id="inp-listen-rule")
                    yield Label("Send auth rule name:")
                    yield Input(value="az-firewall-watch-send", id="inp-send-rule")
                    yield Label("Diagnostic setting name:")
                    yield Input(value="az-firewall-watch-diag", id="inp-diag-name")
                    yield Label("", id="lbl-naming-error", classes="wiz-error")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-naming", variant="default")
                        yield Button("Next →", id="btn-next-naming", variant="primary")

                with Vertical(id="step-summary"):
                    yield Static("Deployment Summary:", classes="wiz-info")
                    yield Static("", id="summary-text")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-summary", variant="default")
                        yield Button("Deploy", id="btn-deploy", variant="success")

                with Vertical(id="step-progress"):
                    yield Static("Deploying…", classes="wiz-info")
                    yield RichLog(id="progress-log", highlight=True, markup=True)
                    yield LoadingIndicator(id="progress-spinner")
                    with Horizontal(classes="wiz-buttons"):
                        yield Button("Back", id="btn-back-progress", variant="default")

    def on_mount(self) -> None:
        self._subs = []
        self._firewalls = []
        self.query_one("#lbl-deploy-error", Label).display = False
        self.query_one("#lbl-fw-error", Label).display = False
        self.query_one("#lbl-naming-error", Label).display = False
        self.query_one("#fw-list", ListView).display = False
        self._run_loading()

    @work(exclusive=True)
    async def _run_loading(self) -> None:
        log = self.query_one("#deploy-log", RichLog)
        az = find_az()
        if not az:
            self._deploy_error(
                "Azure CLI not found.\n"
                "  macOS:   brew install azure-cli\n"
                "  Windows: winget install Microsoft.AzureCLI",
            )
            return
        result = await az_async("version", "--query", '"azure-cli"', "-o", "tsv")
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
        log.write(f"[green]✓[/] Azure CLI {version}")

        acc = await az_async("account", "show", "--query", "user.name", "-o", "tsv")
        if acc.returncode != 0:
            log.write("[yellow]![/] Not logged in — starting az login…")
            try:
                with self.app.suspend():
                    subprocess.run([az, "login"], check=True)
            except subprocess.CalledProcessError as exc:
                self._deploy_error(f"az login failed: {exc}")
                return
            acc = await az_async("account", "show", "--query", "user.name", "-o", "tsv")
        user = acc.stdout.strip()
        log.write(f"[green]✓[/] Logged in as [bold]{user}[/]")

        subs_result = await az_async(
            "account", "list",
            "--query", "[?state=='Enabled'].{id:id, name:name}",
            "-o", "json",
        )
        subs = json.loads(subs_result.stdout) if subs_result.returncode == 0 else []
        if not subs:
            self._deploy_error("No enabled subscriptions found.")
            return
        self._subs = subs
        self._advance_to_subscription()

    def _deploy_error(self, message: str) -> None:
        self.query_one("#deploy-spinner", LoadingIndicator).display = False
        err = self.query_one("#lbl-deploy-error", Label)
        err.update(message)
        err.display = True

    def _advance_to_subscription(self) -> None:
        lv = self.query_one("#sub-list", ListView)
        for s in self._subs:
            lv.append(ListItem(Static(f"{s['name']}  ({s['id']})")))
        self.query_one(ContentSwitcher).current = "step-subscription"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "btn-back-loading":
                self.app.pop_screen()
            case "btn-back-sub":
                self.query_one(ContentSwitcher).current = "step-loading"
            case "btn-next-sub":
                self._go_subscription()
            case "btn-back-fw":
                self.query_one(ContentSwitcher).current = "step-subscription"
            case "btn-next-fw":
                self._go_firewall()
            case "btn-back-naming":
                self.query_one(ContentSwitcher).current = "step-firewall"
            case "btn-next-naming":
                self._go_naming()
            case "btn-back-summary":
                self.query_one(ContentSwitcher).current = "step-naming"
            case "btn-deploy":
                self._start_deploy()
            case "btn-back-progress":
                self.query_one(ContentSwitcher).current = "step-summary"

    def _go_subscription(self) -> None:
        lv = self.query_one("#sub-list", ListView)
        if lv.index is None:
            return
        idx = lv.index
        self._target_sub = self._subs[idx]["id"]
        self._target_sub_name = self._subs[idx]["name"]
        self.query_one(ContentSwitcher).current = "step-firewall"
        self._scan_firewalls()

    @work(exclusive=True)
    async def _scan_firewalls(self) -> None:
        log = self.query_one("#fw-scan-log", RichLog)
        log.write(f"[cyan]i[/] Scanning for firewalls in {self._target_sub_name}…")
        fw_result = await az_async(
            "network", "firewall", "list",
            "--subscription", self._target_sub,
            "--query", "[].{name:name, rg:resourceGroup, location:location, id:id}",
            "-o", "json",
        )
        fws = json.loads(fw_result.stdout) if fw_result.returncode == 0 else []
        if not fws:
            err = self.query_one("#lbl-fw-error", Label)
            err.update(
                "No Azure Firewalls found in this subscription.\n"
                "Deployment requires an existing firewall to determine the region."
            )
            err.display = True
            self.query_one("#fw-spinner", LoadingIndicator).display = False
            return
        self._firewalls = fws
        self._populate_firewall_list(fws)

    def _populate_firewall_list(self, fws: list) -> None:
        lv = self.query_one("#fw-list", ListView)
        self.query_one("#fw-spinner", LoadingIndicator).display = False
        for fw in fws:
            lv.append(ListItem(Static(
                f"{fw['name']}  (rg: {fw['rg']}, location: {fw['location']})"
            )))
        lv.display = True

    def _go_firewall(self) -> None:
        lv = self.query_one("#fw-list", ListView)
        if lv.index is None:
            return
        idx = lv.index
        self._selected_fw = self._firewalls[idx]
        self._location = self._selected_fw["location"]

        loc_abbr = location_short(self._location)
        rg_default = self._selected_fw["rg"]
        ns_default = f"ehns-fwlogs-{loc_abbr}-001"

        self.query_one("#inp-rg", Input).value = rg_default
        self.query_one("#inp-ns-deploy", Input).value = ns_default
        self.query_one(ContentSwitcher).current = "step-naming"

    def _go_naming(self) -> None:
        rg = self.query_one("#inp-rg", Input).value.strip()
        ns = self.query_one("#inp-ns-deploy", Input).value.strip()
        eh_name = self.query_one("#inp-eh-name", Input).value.strip()
        listen_rule = self.query_one("#inp-listen-rule", Input).value.strip()
        send_rule = self.query_one("#inp-send-rule", Input).value.strip()
        diag_name = self.query_one("#inp-diag-name", Input).value.strip()
        err = self.query_one("#lbl-naming-error", Label)
        err.display = False

        if not rg or not ns or not eh_name or not listen_rule or not send_rule or not diag_name:
            err.update("All fields are required.")
            err.display = True
            return

        self._rg = rg
        self._ns = ns
        self._eh_name = eh_name
        self._listen_rule = listen_rule
        self._send_rule = send_rule
        self._diag_name = diag_name

        rows = [
            f"Subscription  : {self._target_sub_name}",
            f"Firewall      : {self._selected_fw['name']} → diagnostics will be configured",
            f"Location      : {self._location}",
            f"Resource group: {rg}" + (" → using existing" if self._selected_fw and rg == self._selected_fw["rg"] else ""),
            f"EH Namespace  : {ns}",
            f"Event Hub     : {eh_name}",
            f"Listen rule   : {listen_rule}",
            f"Send rule     : {send_rule}",
            f"Diag setting  : {diag_name}",
        ]
        self.query_one("#summary-text", Static).update("\n".join(rows))
        self.query_one(ContentSwitcher).current = "step-summary"

    def _start_deploy(self) -> None:
        self.query_one(ContentSwitcher).current = "step-progress"
        self.query_one("#btn-back-progress", Button).disabled = True
        self._run_deploy()

    @work(exclusive=True)
    async def _run_deploy(self) -> None:
        log = self.query_one("#progress-log", RichLog)
        sub_id = self._target_sub
        rg = self._rg
        ns = self._ns
        location = self._location
        eh_name = self._eh_name
        listen_rule = self._listen_rule
        send_rule = self._send_rule
        diag_name = self._diag_name
        tags = ["project=az-firewall-watch", "managed-by=az-cli"]

        try:
            using_existing = self._selected_fw and rg == self._selected_fw["rg"]
            if using_existing:
                log.write(f"[cyan]i[/] Using existing resource group '{rg}'")
            else:
                log.write(f"[cyan]i[/] Creating resource group '{rg}'…")
                await az_async(
                    "group", "create",
                    "--subscription", sub_id,
                    "--name", rg, "--location", location,
                    "--tags", *tags, "--output", "none",
                    check=True,
                )
            log.write("[green]✓[/] Resource group ready")

            log.write(f"[cyan]i[/] Creating namespace '{ns}' (Basic SKU)…")
            await az_async(
                "eventhubs", "namespace", "create",
                "--subscription", sub_id,
                "--name", ns, "--resource-group", rg, "--location", location,
                "--sku", "Basic", "--minimum-tls-version", "1.2",
                "--tags", *tags, "--output", "none",
                check=True,
            )
            log.write("[green]✓[/] Namespace ready")

            log.write(f"[cyan]i[/] Creating Event Hub '{eh_name}'…")
            await az_async(
                "eventhubs", "eventhub", "create",
                "--subscription", sub_id,
                "--name", eh_name, "--namespace-name", ns,
                "--resource-group", rg, "--partition-count", "1",
                "--output", "none",
                check=True,
            )
            log.write("[green]✓[/] Event Hub ready")

            log.write(f"[cyan]i[/] Creating Listen rule '{listen_rule}'…")
            await az_async(
                "eventhubs", "eventhub", "authorization-rule", "create",
                "--subscription", sub_id,
                "--resource-group", rg, "--namespace-name", ns,
                "--eventhub-name", eh_name, "--name", listen_rule,
                "--rights", "Listen", "--output", "none",
                check=True,
            )
            log.write("[green]✓[/] Listen rule created")

            keys_result = await az_async(
                "eventhubs", "eventhub", "authorization-rule", "keys", "list",
                "--subscription", sub_id,
                "--resource-group", rg, "--namespace-name", ns,
                "--eventhub-name", eh_name, "--name", listen_rule,
                "--query", "primaryConnectionString", "-o", "tsv",
                check=True,
            )
            conn_str = keys_result.stdout.strip()

            log.write(f"[cyan]i[/] Creating Send rule '{send_rule}'…")
            await az_async(
                "eventhubs", "namespace", "authorization-rule", "create",
                "--subscription", sub_id,
                "--resource-group", rg, "--namespace-name", ns,
                "--name", send_rule, "--rights", "Send",
                "--output", "none",
                check=True,
            )
            log.write("[green]✓[/] Send rule created")

            send_rule_result = await az_async(
                "eventhubs", "namespace", "authorization-rule", "show",
                "--subscription", sub_id,
                "--resource-group", rg, "--namespace-name", ns,
                "--name", send_rule, "--query", "id", "-o", "tsv",
                check=True,
            )
            send_rule_id = send_rule_result.stdout.strip()

            log.write("[cyan]i[/] Discovering diagnostic log categories…")
            cats_result = await az_async(
                "monitor", "diagnostic-settings", "categories", "list",
                "--resource", self._selected_fw["id"],
                "--query", "value[?categoryType=='Logs'].name",
                "-o", "json",
            )
            available_cats: list[str] = []
            if cats_result.returncode == 0 and cats_result.stdout.strip():
                all_cats = json.loads(cats_result.stdout) or []
                available_cats = [c for c in all_cats if c.startswith("AZFW")]
            if not available_cats:
                available_cats = [
                    "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule",
                    "AZFWThreatIntel", "AZFWIdpsSignature", "AZFWDnsQuery", "AZFWDnsProxy",
                ]
            diag_logs = json.dumps(
                [{"category": c, "enabled": True} for c in available_cats]
            )

            log.write(f"[cyan]i[/] Configuring diagnostic settings '{diag_name}'…")
            diag_result = await az_async(
                "monitor", "diagnostic-settings", "create",
                "--name", diag_name,
                "--resource", self._selected_fw["id"],
                "--event-hub", eh_name,
                "--event-hub-rule", send_rule_id,
                "--logs", diag_logs,
                "--output", "none",
            )
            if diag_result.returncode == 0:
                log.write(
                    "[green]✓[/] Diagnostic settings configured — logs will start flowing shortly"
                )
            else:
                log.write(
                    f"[yellow]![/] Could not configure diagnostics automatically.\n"
                    f"    Configure manually in Azure Portal:\n"
                    f"    Firewall '{self._selected_fw['name']}' → Diagnostic settings → Add\n"
                    f"    → Stream to Event Hub → ns: {ns}, hub: {eh_name}",
                )

            write_env(self._wizard_app.env_file, conn_str)
            log.write("[green]✓[/] .env written — setup complete!")
            self.app.exit()

        except Exception as exc:
            log.write(f"[red]✗[/] Deployment failed: {exc}")
            self.query_one("#progress-spinner", LoadingIndicator).display = False
            self.query_one("#btn-back-progress", Button).disabled = False
