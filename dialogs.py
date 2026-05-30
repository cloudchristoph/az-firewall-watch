from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, LoadingIndicator, Static

from fw_parser import FirewallDataRow
from helpers import _to_local


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

    def on_key(self, event) -> None:  # type: ignore[override]
        if event.key in ("q", "escape"):
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

    def on_key(self, event) -> None:  # type: ignore[override]
        if event.key in ("q", "escape"):
            self.app.exit()


class DetailDialog(ModalScreen[None]):
    """Full details for a single log row, opened with Enter or double-click."""

    DEFAULT_CSS = """
    DetailDialog {
        align: center middle;
    }
    DetailDialog > #dialog {
        width: 84;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    DetailDialog > #dialog > #title {
        text-style: bold;
        margin-bottom: 1;
    }
    DetailDialog > #dialog > .detail-row {
        height: auto;
    }
    DetailDialog > #dialog > Button {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, row: FirewallDataRow) -> None:
        super().__init__()
        self._row = row

    @staticmethod
    def _field(label: str, value: str) -> Static:
        safe = value.replace("[", "\\[")
        return Static(f"[dim]{label}[/]  {safe}", markup=True, classes="detail-row")

    def compose(self) -> ComposeResult:
        row = self._row
        with Static(id="dialog"):
            yield Static(f"Log Entry — {row.category}", id="title")

            yield self._field("Time (UTC)   ", row.time)
            yield self._field("Time (Local) ", _to_local(row.time))
            yield self._field("Category     ", row.category)
            yield self._field("Protocol     ", row.protocol)
            yield self._field("Source       ", f"{row.sourceip}:{row.srcport}")
            yield self._field("Destination  ", f"{row.targetip}:{row.targetport}")
            yield self._field("Action       ", row.action)

            if row.fw_policy:
                yield self._field("Policy       ", row.fw_policy)
            if row.rule_collection_group:
                yield self._field("RCG          ", row.rule_collection_group)
            if row.rule_collection:
                yield self._field("Rule Coll.   ", row.rule_collection)
            if row.rule_name:
                yield self._field("Rule         ", row.rule_name)
            if not any([row.fw_policy, row.rule_collection_group, row.rule_collection, row.rule_name]) and row.policy:
                yield self._field("Policy / Info", row.policy)
            if row.moreinfo:
                yield self._field("More Info    ", row.moreinfo)

            yield Button("Close  (Esc)", variant="primary", id="btn-close")

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss()

    def on_key(self, event) -> None:  # type: ignore[override]
        if event.key in ("q", "escape"):
            self.dismiss()


class StatusBar(Static):
    """Single-line status bar at the bottom."""

    status: reactive[str] = reactive("Starting…")
    total: reactive[int] = reactive(0)
    visible_count: reactive[int] = reactive(-1)  # -1 = no filter active
    skipped: reactive[int] = reactive(0)
    paused: reactive[bool] = reactive(False)

    def render(self) -> str:  # type: ignore[override]
        icon = "⏸ PAUSED" if self.paused else "▶ LIVE"
        skipped_part = f"   Skipped: {self.skipped}" if self.skipped else ""
        if self.visible_count >= 0:
            events_part = f"Events (filtered): {self.visible_count}/{self.total}"
        else:
            events_part = f"Events: {self.total}"
        return (
            f" {icon}   {self.status}   │   "
            f"{events_part}{skipped_part} "
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

    def on_key(self, event) -> None:
        if event.key in ("escape", "q"):
            self.dismiss()
