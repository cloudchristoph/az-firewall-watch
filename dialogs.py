from __future__ import annotations

from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, LoadingIndicator, Static



class ConnectingDialog(ModalScreen[None]):
    """Splash shown while the initial connection probe is in progress."""

    DEFAULT_CSS = """
    ConnectingDialog {
        align: center middle;
    }
    ConnectingDialog > #dialog {
        width: 60;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    ConnectingDialog > #dialog > #title {
        text-style: bold;
        margin-bottom: 1;
    }
    ConnectingDialog > #dialog > #title.success {
        color: $success;
    }
    ConnectingDialog > #dialog > #info {
        color: $text-muted;
        margin-bottom: 1;
    }
    ConnectingDialog > #dialog > LoadingIndicator {
        height: 1;
        margin-bottom: 1;
    }
    ConnectingDialog > #dialog > Button {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, namespace: str, hub: str) -> None:
        super().__init__()
        self._namespace = namespace
        self._hub = hub

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Static("Connecting to Event Hub…", id="title")
            yield Static(
                f"Namespace:  {self._namespace}\nHub:        {self._hub}",
                id="info",
            )
            yield LoadingIndicator()
            yield Button("Cancel  (q)", variant="default", id="btn-cancel")

    def show_waiting(self) -> None:
        """Switch to 'connected, waiting for first event' state — keeps spinner."""
        title = self.query_one("#title", Static)
        title.update("✓  Connected — waiting for first event…")
        title.add_class("success")
        self.query_one(Button).display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.exit()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("q", "escape"):
            event.stop()
            self.app.exit()


class ErrorDialog(ModalScreen[None]):
    """Modal shown after repeated connection failures."""

    DEFAULT_CSS = """
    ErrorDialog {
        align: center middle;
    }
    ErrorDialog > #dialog {
        width: 70;
        height: auto;
        background: $surface;
        border: thick $error;
        padding: 1 2;
    }
    ErrorDialog > #dialog > #title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
    }
    ErrorDialog > #dialog > #hint {
        margin-bottom: 1;
        color: $text-muted;
    }
    ErrorDialog > #dialog > Button {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, error: str, hint: str) -> None:
        super().__init__()
        self._error = error
        self._hint = hint

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Static(" Connection failed", id="title")
            yield Static(self._error)
            yield Static(self._hint, id="hint")
            yield Button("Quit  (q)", variant="error", id="btn-quit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.exit()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("q", "escape"):
            event.stop()
            self.app.exit()


class PolicyContextNoticeDialog(ModalScreen[bool]):
    """One-time notice: policy context is on and reaches beyond the Event Hub.

    Dismisses with ``True`` to keep it enabled, ``False`` to switch it off.
    """

    DEFAULT_CSS = """
    PolicyContextNoticeDialog {
        align: center middle;
    }
    PolicyContextNoticeDialog > #dialog {
        width: 84;
        max-width: 96%;
        height: auto;
        background: $surface;
        border: thick $warning;
        padding: 1 2;
    }
    PolicyContextNoticeDialog > #dialog > #enr-title {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
    }
    PolicyContextNoticeDialog > #dialog > #enr-body {
        margin-bottom: 1;
    }
    PolicyContextNoticeDialog > #dialog > #enr-hint {
        color: $text-muted;
        margin-bottom: 1;
    }
    PolicyContextNoticeDialog > #dialog > .btn-row {
        height: 3;
    }
    PolicyContextNoticeDialog > #dialog > .btn-row > Button {
        width: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Static("Policy context is ON", id="enr-title")
            yield Static(
                "Beyond reading the Event Hub, this viewer will:\n"
                "• read the firewall, its policy and IP groups via Azure Resource Manager (Reader role)\n"
                "• use a token from the Azure CLI as fallback (az account get-access-token)\n"
                "• cache that metadata for one hour in ~/.az-firewall-watch/cache.json\n"
                "\n"
                "Nothing is written to Azure. In return you get the Firewall, Policy and "
                "IP Groups tabs, enriched rows and the evaluation trace (t).",
                id="enr-body",
            )
            yield Static("Saved to .env as POLICY_CONTEXT=on|off — change it there or run with --no-policy-context.", id="enr-hint")
            with Horizontal(classes="btn-row"):
                yield Button("Keep enabled  (Enter)", variant="success", id="btn-keep")
                yield Button("Disable", variant="default", id="btn-disable")

    def recreate(self) -> "PolicyContextNoticeDialog":
        """Fresh copy for re-pushing after the connecting splash is removed."""
        return PolicyContextNoticeDialog()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn-keep")

    def on_key(self, event: events.Key) -> None:
        if event.key in ("escape", "q"):
            event.stop()
            self.dismiss(True)  # closing means "leave it as it is"


class StatusBar(Static):
    """Single-line status bar at the bottom."""

    status: reactive[str] = reactive("Starting…")
    total: reactive[int] = reactive(0)
    visible_count: reactive[int] = reactive(-1)  # -1 = no filter active
    skipped: reactive[int] = reactive(0)
    paused: reactive[bool] = reactive(False)
    meta: reactive[str] = reactive("")  # management-plane metadata summary

    def render(self) -> str:  # type: ignore[override]
        icon = "⏸ PAUSED" if self.paused else "▶ LIVE"
        skipped_part = f"   Skipped: {self.skipped}" if self.skipped else ""
        if self.visible_count >= 0:
            events_part = f"Events (filtered): {self.visible_count}/{self.total}"
        else:
            events_part = f"Events: {self.total}"
        meta_part = f"   │   {self.meta}" if self.meta else ""
        return (
            f" {icon}   {self.status}   │   "
            f"{events_part}{skipped_part}{meta_part} "
        )

    def watch_paused(self, paused: bool) -> None:
        self.set_class(paused, "paused")

    def on_click(self) -> None:
        self.app.action_toggle_pause()  # type: ignore[attr-defined]


class UpdateDialog(ModalScreen[None]):
    """Shown on startup when a newer GitHub release is available."""

    DEFAULT_CSS = """
    UpdateDialog {
        align: center middle;
    }
    UpdateDialog > #dialog {
        width: 66;
        height: auto;
        background: $surface;
        border: thick $success;
        padding: 1 2;
    }
    UpdateDialog > #dialog > #upd-title {
        text-style: bold;
        color: $success;
        margin-bottom: 1;
    }
    UpdateDialog > #dialog > #upd-url {
        margin-bottom: 1;
    }
    UpdateDialog > #dialog > .btn-row {
        height: 3;
    }
    UpdateDialog > #dialog > .btn-row > Button {
        width: 1fr;
    }
    """

    def __init__(self, latest: str, url: str) -> None:
        super().__init__()
        self._latest = latest
        self._url = url

    def recreate(self) -> "UpdateDialog":
        """Fresh copy for re-pushing after the connecting splash is removed."""
        return UpdateDialog(self._latest, self._url)

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Static("\u2b06  Update available", id="upd-title")
            yield Static(
                f"Version [bold]{self._latest}[/bold] is now available on GitHub.",
                markup=True,
            )
            yield Static(f"[dim]{self._url}[/dim]", markup=True, id="upd-url")
            with Horizontal(classes="btn-row"):
                yield Button("Open in browser", variant="success", id="btn-open")
                yield Button("Dismiss  (Esc)", variant="default", id="btn-dismiss")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-open":
            import webbrowser

            try:
                webbrowser.open(self._url)
            except Exception:
                pass
        self.dismiss()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("escape", "q"):
            event.stop()
            self.dismiss()
