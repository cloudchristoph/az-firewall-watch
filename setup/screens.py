from __future__ import annotations

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

from .operations import (
    cli_ensure_login,
    deploy_new_hub,
    list_subscriptions,
    resolve_sas_conn_str,
    scan_event_hubs,
    scan_firewalls,
)
from .services import write_env, write_env_entra
from .utils import location_short

if TYPE_CHECKING:
    from .app import WizardApp


class _WizardScreen(Screen):
    """Base screen that exposes a typed accessor for :class:`WizardApp`."""

    @property
    def _wizard_app(self) -> "WizardApp":
        return cast("WizardApp", self.app)


class _SafeRadioSet(RadioSet):
    """RadioSet that silently skips non-RadioButton children (e.g. section headers)."""

    def action_toggle_button(self) -> None:
        try:
            super().action_toggle_button()
        except AssertionError:
            pass


class WelcomeScreen(Screen):
    """Main wizard menu."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static(
                "Azure Firewall Watch — Setup Wizard",
                classes="wiz-title",
            )
            yield Static(
                "How do you want to connect to the Azure Event Hub?",
                classes="wiz-info",
            )
            with _SafeRadioSet(id="welcome-radio"):
                yield Static("Existing Event Hub", classes="wiz-section")
                yield RadioButton(
                    "Discover Event Hub automatically",
                    id="opt-discover",
                    value=True,
                )
                yield RadioButton("Enter existing Event Hub data", id="opt-enter")
                yield RadioButton("Paste SAS connection string", id="opt-paste")
                yield Static("New Event Hub", classes="wiz-section")
                yield RadioButton(
                    "Deploy new Event Hub and Diagnostics settings",
                    id="opt-deploy",
                )
            with Horizontal(classes="wiz-buttons"):
                yield Button("Quit", id="btn-quit", variant="error")
                yield Button("Next →", id="btn-next", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-quit":
            self.app.exit()
            return
        if event.button.id == "btn-next":
            radio = self.query_one("#welcome-radio", _SafeRadioSet)
            if radio.pressed_button is None:
                return
            match radio.pressed_button.id:
                case "opt-discover":
                    self.app.push_screen(PickExistingScreen())
                case "opt-deploy":
                    self.app.push_screen(DeployNewScreen())
                case "opt-enter":
                    self.app.push_screen(EnterExistingHubScreen())
                case "opt-paste":
                    self.app.push_screen(PasteConnectionScreen())


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


class AuthMethodScreen(ModalScreen[str | None]):
    """Sub-choice modal: Entra ID or SAS connection string."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("How do you want to connect?", classes="wiz-title")
            yield Static(
                "Entra ID - no secrets stored.\n"
                "  Uses existing Azure CLI login, managed identity,\n"
                "  environment credentials, etc.\n"
                "  Prerequisite: Your identity must have the\n"
                "  'Azure Event Hubs Data Receiver' role on the namespace or hub.\n\n"
                "SAS auth rule - a connection string is stored in .env",
                classes="wiz-info",
            )
            with RadioSet(id="auth-radio"):
                yield RadioButton(
                    "Entra ID (recommended)",
                    id="opt-entra",
                    value=True,
                )
                yield RadioButton(
                    "SAS auth rule",
                    id="opt-sas",
                )
            with Horizontal(classes="wiz-buttons"):
                yield Button("Back", id="btn-back", variant="default")
                yield Button("Next →", id="btn-next", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.dismiss(None)
            return
        if event.button.id == "btn-next":
            radio = self.query_one("#auth-radio", RadioSet)
            if radio.pressed_button is None:
                return
            match radio.pressed_button.id:
                case "opt-entra":
                    self.dismiss("entra")
                case "opt-sas":
                    self.dismiss("sas")

    def on_key(self, event) -> None:  # type: ignore[override]
        if event.key in ("escape", "q"):
            self.dismiss(None)


class PasteConnectionScreen(_WizardScreen):
    """Option 3 — paste a SAS connection string."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Paste Connection String", classes="wiz-title")
            yield Static(
                "Expected format:\n"
                "  Endpoint=sb://<namespace>.servicebus.windows.net/;"
                "  SharedAccessKeyName=<rule>;SharedAccessKey=<key>;EntityPath=<hub>",
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


class EnterExistingHubScreen(_WizardScreen):
    """Option 3 — enter existing Event Hub name, connect with Entra ID."""

    def compose(self):
        with Vertical(classes="wiz-box"):
            yield Static("Enter Existing Event Hub", classes="wiz-title")
            yield Static(
                "Uses Entra ID — no secrets stored.\n"
                "Authentication via existing Azure CLI login,\n"
                "managed identity, environment credentials, etc.)\n\n"
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
        try:
            await cli_ensure_login(log.write, self.app.suspend)
            subs = await list_subscriptions(log.write)
            items = await scan_event_hubs(subs, log.write)
            if not items:
                self._show_error("No Event Hubs found in your accessible subscriptions.")
                return
            self._show_results(items)
        except Exception as exc:
            self._show_error(str(exc))

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

        auth_method = await self.app.push_screen_wait(AuthMethodScreen())
        if auth_method is None:
            return

        if auth_method == "entra":
            write_env_entra(self._wizard_app.env_file, f"{ns}.servicebus.windows.net", eh)
            self.app.exit()
            return

        rule_name = "az-firewall-watch-listen"
        log = self.query_one("#scan-log", RichLog)
        self.query_one(ContentSwitcher).current = "phase-loading"

        async def _confirm_create() -> bool:
            return await self.app.push_screen_wait(
                ConfirmCreateRuleScreen(rule_name=rule_name, namespace=ns, event_hub=eh)
            )

        try:
            conn_str = await resolve_sas_conn_str(
                sub_id, rg, ns, eh, rule_name, log.write, _confirm_create
            )
            if not conn_str:
                self.query_one(ContentSwitcher).current = "phase-select"
                return
            log.write("[green]✓[/] Writing .env…")
            write_env(self._wizard_app.env_file, conn_str)
            log.write("[green]✓[/] Done!")
            self.app.exit()
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
    _auth_method: str
    _current_user_id: str

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
        self._auth_method = "sas"
        self._current_user_id = ""
        self.query_one("#lbl-deploy-error", Label).display = False
        self.query_one("#lbl-fw-error", Label).display = False
        self.query_one("#lbl-naming-error", Label).display = False
        self.query_one("#fw-list", ListView).display = False
        self._run_loading()

    @work(exclusive=True)
    async def _run_loading(self) -> None:
        log = self.query_one("#deploy-log", RichLog)
        try:
            _, user_id = await cli_ensure_login(log.write, self.app.suspend)
            self._current_user_id = user_id
            subs = await list_subscriptions(log.write)
            if not subs:
                self._deploy_error("No enabled subscriptions found.")
                return
            self._subs = subs
            self._advance_to_subscription()
        except Exception as exc:
            self._deploy_error(str(exc))

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
        try:
            fws = await scan_firewalls(self._target_sub, self._target_sub_name, log.write)
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
        except Exception as exc:
            err = self.query_one("#lbl-fw-error", Label)
            err.update(str(exc))
            err.display = True
            self.query_one("#fw-spinner", LoadingIndicator).display = False

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

        self._pick_auth_and_advance()

    @work(exclusive=True)
    async def _pick_auth_and_advance(self) -> None:
        auth_method = await self.app.push_screen_wait(AuthMethodScreen())
        if auth_method is None:
            return
        self._auth_method = auth_method
        auth_label = (
            "Entra ID" if auth_method == "entra" else "SAS connection string"
        )
        rows = [
            f"Subscription  : {self._target_sub_name}",
            f"Firewall      : {self._selected_fw['name']} → diagnostics will be configured",
            f"Location      : {self._location}",
            f"Resource group: {self._rg}"
            + (" → using existing" if self._selected_fw and self._rg == self._selected_fw["rg"] else ""),
            f"EH Namespace  : {self._ns}",
            f"Event Hub     : {self._eh_name}",
            f"Auth method   : {auth_label}",
        ]
        if auth_method == "sas":
            rows.append(f"Listen rule   : {self._listen_rule}")
        rows += [
            f"Send rule     : {self._send_rule}",
            f"Diag setting  : {self._diag_name}",
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
        try:
            conn_str = await deploy_new_hub(
                sub_id=self._target_sub,
                rg=self._rg,
                ns=self._ns,
                location=self._location,
                eh_name=self._eh_name,
                listen_rule=self._listen_rule,
                send_rule=self._send_rule,
                diag_name=self._diag_name,
                fw=self._selected_fw,
                auth_method=self._auth_method,
                current_user_id=self._current_user_id,
                using_existing_rg=bool(
                    self._selected_fw and self._rg == self._selected_fw["rg"]
                ),
                log=log.write,
            )
            if self._auth_method == "entra":
                write_env_entra(
                    self._wizard_app.env_file,
                    f"{self._ns}.servicebus.windows.net",
                    self._eh_name,
                )
            else:
                write_env(self._wizard_app.env_file, conn_str)
            log.write("[green]✓[/] .env written — setup complete!")
            self.app.exit()
        except Exception as exc:
            log.write(f"[red]✗[/] Deployment failed: {exc}")
            self.query_one("#progress-spinner", LoadingIndicator).display = False
            self.query_one("#btn-back-progress", Button).disabled = False
