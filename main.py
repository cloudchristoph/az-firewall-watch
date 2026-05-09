#!/usr/bin/env python3
"""
fw-log-tui  —  Azure Firewall log stream in your terminal.

Connects to an Azure Event Hub and displays incoming firewall logs in a
filterable TUI table. Connection string is read from .env in this folder.

Key bindings
  q        Quit
  p        Pause / resume streaming
  c        Clear all rows
  Escape   Clear all filter inputs
  f        Focus the Source-IP filter
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, LoadingIndicator, Static

# ── base directory (works both from source and as a PyInstaller binary) ───────
if getattr(sys, "frozen", False):
    # Running as a compiled binary — place .env next to the executable
    _BASE_DIR = Path(sys.executable).parent
else:
    _BASE_DIR = Path(__file__).parent

# ── local ─────────────────────────────────────────────────────────────────────
sys.path.insert(0, str(_BASE_DIR))
from fw_parser import FirewallDataRow, parse_record  # noqa: E402

# ── config ────────────────────────────────────────────────────────────────────
load_dotenv(_BASE_DIR / ".env")

# Run the setup wizard automatically if no connection string is configured.
# Pass --reconfigure to redo setup even when .env already exists.
if not os.environ.get("EVENT_HUB_CONNECTION_STRING") or "--reconfigure" in sys.argv:
    from setup_wizard import run_wizard  # noqa: E402
    run_wizard(_BASE_DIR, reconfigure="--reconfigure" in sys.argv)
    load_dotenv(_BASE_DIR / ".env", override=True)

MAX_ROWS = 5000  # maximum rows kept in memory


# ── helpers ───────────────────────────────────────────────────────────────────

def _to_local(ts: str) -> str:
    """Convert a UTC ISO-8601 timestamp to the local system timezone."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return ts[:19]


def _highlight(text: str, term: str) -> Text:
    """Return a Rich Text with *term* highlighted (case-insensitive)."""
    t = Text(text)
    if term:
        t.highlight_regex(f"(?i){re.escape(term)}", style="bold reverse")
    return t


def _parse_eventhub_endpoint(conn_str: str) -> tuple[str, str]:
    """Extract (namespace, hub_name) from a connection string — key is never returned."""
    namespace = hub = ""
    for part in conn_str.split(";"):
        low = part.lower()
        if low.startswith("endpoint=sb://"):
            namespace = part[len("Endpoint=sb://"):].rstrip("/")
        elif low.startswith("entitypath="):
            hub = part[part.index("=") + 1:]
    return namespace or "unknown", hub or "unknown"


# ── widgets ───────────────────────────────────────────────────────────────────

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

    def show_success(self) -> None:
        """Switch the dialog to a success state (called before auto-dismiss)."""
        title = self.query_one("#title", Static)
        title.update("✓  Connected to Event Hub!")
        title.add_class("success")
        self.query_one(LoadingIndicator).display = False
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


class StatusBar(Static):
    """Single-line status bar at the bottom."""

    status: reactive[str] = reactive("Starting…")
    total: reactive[int] = reactive(0)
    skipped: reactive[int] = reactive(0)
    paused: reactive[bool] = reactive(False)

    def render(self) -> str:  # type: ignore[override]
        icon = "⏸ PAUSED" if self.paused else "▶ LIVE"
        return (
            f" {icon}   {self.status}   │   "
            f"Events: {self.total}   Skipped: {self.skipped} "
        )


# ── main app ──────────────────────────────────────────────────────────────────

class FirewallLogApp(App[None]):
    """Azure Firewall Log streaming TUI."""

    TITLE = "Azure Firewall Watch"
    SUB_TITLE = "Live Log Monitor  |  connecting..."

    CSS = """
    Screen {
        layout: vertical;
    }

    #filter-bar {
        height: 3;
        background: $surface;
        padding: 0 1;
    }
    #filter-bar Label {
        height: 3;
        content-align: center middle;
        width: auto;
        padding: 0 1 0 0;
        color: $text-muted;
    }
    #filter-bar Input {
        width: 18;
        margin-right: 1;
    }

    DataTable {
        height: 1fr;
    }

    StatusBar {
        height: 1;
        background: $primary-darken-3;
        color: $text;
        padding: 0 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "toggle_pause", "Pause/Resume"),
        Binding("c", "clear_logs", "Clear"),
        Binding("escape", "clear_filters", "Clear Filters", priority=True),
        Binding("f", "focus_filter", "Filter"),
    ]

    # ── state ──────────────────────────────────────────────────────────────────
    def __init__(self) -> None:
        super().__init__()
        self._all_rows: list[FirewallDataRow] = []
        self._pending: list[FirewallDataRow] = []
        self._skip_pending: int = 0
        self._paused: bool = False
        self._fw_name_set: bool = False

    # ── layout ─────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="filter-bar"):
            yield Label("Filter:")
            yield Input(placeholder="Source IP",    id="f-src",    classes="filter-input")
            yield Input(placeholder="Dest / FQDN",  id="f-dst",    classes="filter-input")
            yield Input(placeholder="Action",       id="f-action", classes="filter-input")
            yield Input(placeholder="Category",     id="f-cat",    classes="filter-input")
            yield Input(placeholder="Protocol",     id="f-proto",  classes="filter-input")
        yield DataTable(zebra_stripes=True, cursor_type="row", id="log-table")
        yield StatusBar(id="status")
        yield Footer()

    def on_mount(self) -> None:
        tbl = self.query_one("#log-table", DataTable)
        tbl.add_columns(
            "Time (UTC)", "Category", "Proto",
            "Source", "Dest / FQDN", "Port",
            "Action", "Policy / Info",
        )
        self._start_stream()
        self.set_interval(1.0, self._flush)

    # ── Event Hub worker ────────────────────────────────────────────────────────
    @work(exclusive=True)
    async def _start_stream(self) -> None:
        """Connect to Event Hub and stream events; reconnects automatically on error."""
        from azure.eventhub.aio import EventHubConsumerClient  # type: ignore[import]

        conn_str = os.environ.get("EVENT_HUB_CONNECTION_STRING", "")
        consumer_group = os.environ.get("EVENT_HUB_CONSUMER_GROUP", "$Default")
        start_pos = os.environ.get("EVENT_HUB_START_POSITION", "latest")
        position = "@latest" if start_pos == "latest" else "@earliest"

        status = self.query_one("#status", StatusBar)

        if not conn_str:
            status.status = (
                "ERROR: EVENT_HUB_CONNECTION_STRING not set — "
                "copy .env.sample to .env and fill in the value"
            )
            return

        namespace, hub = _parse_eventhub_endpoint(conn_str)

        # Keywords that indicate a configuration error rather than a transient fault.
        _AUTH_KEYWORDS = (
            "unauthorized", "authentication", "forbidden",
            "401", "403", "invalid signature", "saskey",
        )
        # Exponential backoff delays in seconds between the three attempts.
        _BACKOFF = [2, 5, 10]
        _MAX_ATTEMPTS = 3
        attempt = 0
        last_exc: Exception | None = None

        # Show the connecting splash and keep a flag so we know when to dismiss it.
        _dialog = ConnectingDialog(namespace, hub)
        await self.push_screen(_dialog)
        _splash_shown = True

        while attempt < _MAX_ATTEMPTS:
            self.sub_title = "Live Log Monitor  |  connecting..."
            status.status = "Connecting to Event Hub…"

            try:
                async with EventHubConsumerClient.from_connection_string(
                    conn_str,
                    consumer_group=consumer_group,
                    load_balancing_interval=1,  # claim partitions after 1s instead of default ~30s
                    retry_total=0,              # no SDK-internal retries — our loop handles that
                ) as client:
                    # Probe the connection before starting the long-running receive().
                    # get_partition_ids() is a one-shot call without an internal reconnect
                    # loop, so it fails fast and visibly when the string is wrong or the
                    # namespace is unreachable.
                    try:
                        await asyncio.wait_for(client.get_partition_ids(), timeout=15)
                    except asyncio.TimeoutError:
                        raise TimeoutError(
                            "Event Hub did not respond within 15 s — "
                            "check connection string and network"
                        )

                    attempt = 0  # reset backoff counter after a successful connect
                    if _splash_shown:
                        _dialog.show_success()
                        await asyncio.sleep(2)
                        self.pop_screen()
                        _splash_shown = False
                    status.status = "Connected — waiting for events"
                    self.sub_title = "Live Log Monitor  |  waiting for events"

                    async def on_event(partition_ctx, event) -> None:  # type: ignore[misc]
                        if event is None or self._paused:
                            return
                        try:
                            body = json.loads(event.body_as_str())
                        except (ValueError, TypeError):
                            return
                        for rec in body.get("records", []):
                            if not self._fw_name_set:
                                rid: str = rec.get("resourceId", "")
                                if "/AZUREFIREWALLS/" in rid.upper():
                                    self.sub_title = rid.split("/")[-1]
                                    self._fw_name_set = True
                            row = parse_record(rec)
                            if row is None:
                                continue
                            if "SKIP:" in row.category:
                                self._skip_pending += 1
                            else:
                                self._pending.append(row)

                    await client.receive(on_event=on_event, starting_position=position)

            except asyncio.CancelledError:
                if _splash_shown:
                    self.pop_screen()
                status.status = "Streaming stopped"
                return

            except Exception as exc:
                last_exc = exc
                self._fw_name_set = False  # allow subtitle refresh on next connect
                attempt += 1

                if attempt >= _MAX_ATTEMPTS:
                    break

                delay = _BACKOFF[attempt - 1]
                for remaining in range(delay, 0, -1):
                    status.status = (
                        f"Connection error: {exc}"
                        f"  — attempt {attempt}/{_MAX_ATTEMPTS},"
                        f" retrying in {remaining}s…"
                    )
                    await asyncio.sleep(1)

        # ── all attempts exhausted ────────────────────────────────────────────
        if last_exc is not None:
            err_lower = str(last_exc).lower()
            is_cfg_error = any(kw in err_lower for kw in _AUTH_KEYWORDS)
            if is_cfg_error:
                hint = (
                    "The credentials in your connection string were rejected.\n"
                    "Restart the app with  --reconfigure  to update the settings."
                )
            else:
                hint = (
                    "The Event Hub namespace could not be reached.\n"
                    "Check your network connection and the connection string,\n"
                    "then restart the app (optionally with  --reconfigure)."
                )
            status.status = f"Failed after {_MAX_ATTEMPTS} attempts — see dialog"
            if _splash_shown:
                self.pop_screen()
            await self.push_screen(ErrorDialog(str(last_exc), hint))

    # ── periodic flush ──────────────────────────────────────────────────────────
    async def _flush(self) -> None:
        """Drain pending rows into _all_rows and refresh the table (every 1 s)."""
        has_new = bool(self._pending) or self._skip_pending > 0
        if not has_new:
            return

        batch, self._pending = self._pending[:], []
        skips, self._skip_pending = self._skip_pending, 0

        if batch:
            self._all_rows = (batch + self._all_rows)[:MAX_ROWS]

        status = self.query_one("#status", StatusBar)
        status.total += len(batch)
        status.skipped += skips

        if batch:
            self._refresh_table()

    # ── table rendering ─────────────────────────────────────────────────────────
    def _refresh_table(self) -> None:
        f = self._get_filters()
        visible = [r for r in self._all_rows if self._matches(r, f)]

        tbl = self.query_one("#log-table", DataTable)
        tbl.clear()
        for row in visible:
            src_str = f"{row.sourceip}:{row.srcport}"
            action_text = self._action_text(row.action)
            if f["action"]:
                action_text.highlight_regex(
                    f"(?i){re.escape(f['action'])}", style="bold reverse"
                )
            tbl.add_row(
                _to_local(row.time),
                _highlight(row.category, f["cat"]),
                _highlight(row.protocol, f["proto"]),
                _highlight(src_str, f["src"]),
                _highlight(row.targetip, f["dst"]),
                row.targetport,
                action_text,
                (row.policy or row.moreinfo)[:60],
                key=row.rowid,
            )

    @staticmethod
    def _action_text(action: str) -> Text:
        a = action.lower()
        if a in ("deny", "denywiththreat"):
            return Text(action, style="bold red")
        if a == "allow":
            return Text(action, style="bold green")
        if a == "dnat":
            return Text(action, style="bold yellow")
        if a in ("alert",):
            return Text(action, style="bold magenta")
        # DNS response codes
        if a == "noerror":
            return Text(action, style="green")
        if a == "nxdomain":
            return Text(action, style="bold yellow")
        if a in ("servfail", "refused"):
            return Text(action, style="bold red")
        return Text(action)

    # ── filtering ───────────────────────────────────────────────────────────────
    def _get_filters(self) -> dict[str, str]:
        return {
            "src":    self.query_one("#f-src",    Input).value.lower(),
            "dst":    self.query_one("#f-dst",    Input).value.lower(),
            "action": self.query_one("#f-action", Input).value.lower(),
            "cat":    self.query_one("#f-cat",    Input).value.lower(),
            "proto":  self.query_one("#f-proto",  Input).value.lower(),
        }

    @staticmethod
    def _matches(row: FirewallDataRow, f: dict[str, str]) -> bool:
        if f["src"]    and f["src"]    not in row.sourceip.lower():             return False
        if f["dst"]    and f["dst"]    not in (row.targetip or "").lower():     return False
        if f["action"] and f["action"] not in row.action.lower():               return False
        if f["cat"]    and f["cat"]    not in row.category.lower():             return False
        if f["proto"]  and f["proto"]  not in row.protocol.lower():             return False
        return True

    @on(Input.Changed, ".filter-input")
    def on_filter_changed(self, _event: Input.Changed) -> None:
        self._refresh_table()

    # ── actions (key bindings) ──────────────────────────────────────────────────
    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.query_one("#status", StatusBar).paused = self._paused

    def action_clear_logs(self) -> None:
        self._all_rows = []
        self._pending = []
        self.query_one("#log-table", DataTable).clear()
        status = self.query_one("#status", StatusBar)
        status.total = 0
        status.skipped = 0

    def action_clear_filters(self) -> None:
        for fid in ("#f-src", "#f-dst", "#f-action", "#f-cat", "#f-proto"):
            self.query_one(fid, Input).value = ""
        self._refresh_table()

    def action_focus_filter(self) -> None:
        self.query_one("#f-src", Input).focus()


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    FirewallLogApp().run()
