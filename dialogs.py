from __future__ import annotations

import time
from collections.abc import Callable

from rich.text import Text
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

    AUTO_FOCUS = "#btn-keep"  # so 'Enter' really means 'Keep enabled'
    # Result callback to re-attach when the connecting splash re-pushes this
    # dialog (see streaming._repush_dialogs). Set by whoever pushes the dialog.
    repush_callback: Callable[[bool | None], None] | None = None

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
                "• cache that context for one hour in your user cache directory\n"
                "  (Library/Caches on macOS, .cache on Linux, %LOCALAPPDATA% on Windows)\n"
                "\n"
                "Nothing is written to Azure. In return you get the Firewall, Policy and "
                "IP Groups tabs, enriched rows and the evaluation trace.",
                id="enr-body",
            )
            yield Static("Saved to .env as POLICY_CONTEXT=on|off — change it there or run with --no-policy-context.", id="enr-hint")
            with Horizontal(classes="btn-row"):
                yield Button("Keep enabled  (Enter)", variant="success", id="btn-keep")
                yield Button("Disable", variant="default", id="btn-disable")

    def recreate(self) -> PolicyContextNoticeDialog:
        """Fresh copy for re-pushing after the connecting splash is removed."""
        return PolicyContextNoticeDialog()


    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn-keep")

    def on_key(self, event: events.Key) -> None:
        if event.key in ("escape", "q"):
            event.stop()
            self.dismiss(True)  # closing means "leave it as it is"


def _ago(seconds: float) -> str:
    """Compact relative age: ``4s ago``, ``12m ago``, ``3h ago``."""
    s = int(max(0.0, seconds))
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    return f"{s // 3600}h ago"


# One glyph per kind of state, single-width everywhere (emoji are not).
_GLYPHS: dict[str, tuple[str, str]] = {
    "ok": ("●", "green"),      # working as intended
    "busy": ("◐", "yellow"),   # something is in progress
    "off": ("○", "dim"),       # off, idle or not available; no error
    "error": ("✖", "red"),     # needs the operator
}


class StatusBar(Static):
    """Single-line status bar: pause state, then one segment per data source.

    ``EH`` is the Event Hub connection, ``Events`` whether records are arriving,
    ``Context`` the optional ARM-backed policy context. Every segment is a glyph,
    a label, a state word and, if there is room, a detail. The bar shows *state*
    only: one-off hints and error texts go through ``App.notify`` so nothing can
    stick here, and the last Event Hub error is the bar's tooltip.
    """

    # Event Hub connection
    eh_state: reactive[str] = reactive("connecting")
    # connecting | verifying | connected | retrying | reconnecting | failed | stopped | unconfigured
    eh_detail: reactive[str] = reactive("")  # short, e.g. "attempt 2 in 9s"
    eh_error: reactive[str] = reactive("")   # last error text: tooltip only, never in the line

    # Events
    total: reactive[int] = reactive(0)
    visible_count: reactive[int] = reactive(-1)  # -1 = no filter active
    skipped: reactive[int] = reactive(0)
    paused: reactive[bool] = reactive(False)
    last_event_at: reactive[float | None] = reactive(None)  # time.monotonic() of the last record

    # Policy context
    ctx_state: reactive[str] = reactive("off")
    # off | pending | loading | loaded | refreshing | unavailable
    ctx_detail: reactive[str] = reactive("")  # "new rule x", "refresh failed"
    ctx_error: reactive[str] = reactive("")   # last ARM error text: tooltip only, the Firewall tab shows it whole
    ctx_fetched_at: reactive[float | None] = reactive(None)  # time.time() the snapshot was fetched

    IDLE_AFTER = 60.0  # seconds without a record before "receiving" turns into "idle"

    def on_mount(self) -> None:
        self.set_interval(1.0, self.refresh)  # the "ago" parts tick on their own

    # ── segments ───────────────────────────────────────────────────────────────
    def _eh(self) -> tuple[str, str, list[str]]:
        st = self.eh_state
        detail = [self.eh_detail] if self.eh_detail else []
        if st == "connected":
            return "ok", "connected", []
        if st in ("connecting", "retrying", "reconnecting"):
            return "busy", st, detail
        if st == "verifying":
            return "busy", "verifying access", detail
        if st == "failed":
            return "error", "failed", detail
        if st == "unconfigured":
            return "error", "not configured", detail
        return "off", st, detail  # stopped

    def _events(self) -> tuple[str, str, list[str]]:
        counts = f"{self.visible_count}/{self.total} shown" if self.visible_count >= 0 else str(self.total)
        extra = [f"{self.skipped} skipped"] if self.skipped else []
        if self.paused:
            return "off", f"paused · {counts}", extra
        if self.eh_state != "connected":
            return "off", counts, extra
        if self.last_event_at is None:
            return "busy", f"waiting · {counts}", extra
        age = time.monotonic() - self.last_event_at
        last = f"last {_ago(age)}"
        if age <= self.IDLE_AFTER:
            return "ok", f"receiving · {counts}", [last, *extra]
        return "off", f"idle · {counts}", [last, *extra]

    def _ctx(self) -> tuple[str, str, list[str]]:
        st = self.ctx_state
        detail = [self.ctx_detail] if self.ctx_detail else []
        if st == "loaded":
            age = time.time() - (self.ctx_fetched_at or time.time())
            word = "loaded just now" if age < 60 else f"loaded {_ago(age)}"
            return "ok", word, detail
        if st in ("loading", "refreshing"):
            return "busy", st, detail
        if st == "unavailable":
            return "off", st, detail or ["no ARM access"]
        return "off", st, detail  # off, pending

    @staticmethod
    def _segment(label: str, kind: str, word: str, extra: list[str], level: int) -> Text:
        glyph, style = _GLYPHS[kind]
        t = Text.assemble((glyph, style), " ")
        if level < 2:
            t.append(label + " ", style="bold")
        t.append(word)
        if level < 1:
            for e in extra:
                t.append(" · " + e, style="dim")
        return t

    def _compose_line(self, level: int) -> Text:
        icon = " ⏸ PAUSED" if self.paused else " ▶ LIVE"
        parts = [
            Text(icon, style="bold"),
            self._segment("EH", *self._eh(), level),
            self._segment("Events", *self._events(), level),
            self._segment("Context", *self._ctx(), level),
        ]
        line = Text(" │ ").join(parts)
        line.append(" ")
        return line

    def render(self) -> Text:
        """Full line when it fits; otherwise drop details, then labels."""
        width = self.size.width
        line = self._compose_line(0)
        for level in (1, 2):
            if not width or line.cell_len <= width:
                break
            line = self._compose_line(level)
        return line

    # ── reactions ──────────────────────────────────────────────────────────────
    def watch_paused(self, paused: bool) -> None:
        self.set_class(paused, "paused")

    def watch_eh_error(self, error: str) -> None:
        self._update_tooltip()

    def watch_ctx_error(self, error: str) -> None:
        self._update_tooltip()

    def _update_tooltip(self) -> None:
        errors = [(label, text) for label, text in (("Event Hub", self.eh_error), ("Context", self.ctx_error)) if text]
        if len(errors) > 1:
            self.tooltip = "\n".join(f"{label}: {text}" for label, text in errors)   # both: say which is which
        else:
            self.tooltip = errors[0][1] if errors else None

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

    repush_callback = None  # pushed without a result callback; kept for the splash re-push protocol

    def recreate(self) -> UpdateDialog:
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
