#!/usr/bin/env python3
"""
fw-log-tui  —  Azure Firewall log stream in your terminal.

Connects to an Azure Event Hub and displays incoming firewall logs in a
filterable TUI table. Connection string is read from .env in this folder.

Key bindings
  q        Quit
  ctrl+p   Pause / resume streaming  (or click the status bar)
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
from pathlib import Path

from dotenv import load_dotenv
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Input, Label

# ── base directory (works both from source and as a PyInstaller binary) ───────
if getattr(sys, "frozen", False):
    # Running as a compiled binary — place .env next to the executable
    _BASE_DIR = Path(sys.executable).parent
    _SRC_DIR = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    _BASE_DIR = Path(__file__).parent
    _SRC_DIR = _BASE_DIR

# ── version ───────────────────────────────────────────────────────────────────
try:
    VERSION = (_SRC_DIR / "version.txt").read_text(encoding="utf-8").strip()
except Exception:
    VERSION = "unknown"

# ── local ─────────────────────────────────────────────────────────────────────
sys.path.insert(0, str(_BASE_DIR))
from fw_parser import FirewallDataRow, parse_record  # noqa: E402
from helpers import _category_text, _highlight, _parse_eventhub_endpoint, _to_local  # noqa: E402
from dialogs import ConnectingDialog, DetailDialog, ErrorDialog, StatusBar, UpdateDialog  # noqa: E402

# ── config ────────────────────────────────────────────────────────────────────
def _load_env(path: Path, override: bool = False) -> None:
    """Load a .env file, falling back to latin-1 if the file is not valid UTF-8."""
    try:
        load_dotenv(path, encoding="utf-8", override=override)
    except UnicodeDecodeError:
        load_dotenv(path, encoding="latin-1", override=override)


_load_env(_BASE_DIR / ".env")

# Run the setup wizard automatically if no connection string is configured.
# Pass --reconfigure to redo setup even when .env already exists.
if not os.environ.get("EVENT_HUB_CONNECTION_STRING") or "--reconfigure" in sys.argv:
    from setup_wizard import run_wizard  # noqa: E402
    run_wizard(_BASE_DIR, reconfigure="--reconfigure" in sys.argv)
    _load_env(_BASE_DIR / ".env", override=True)

MAX_ROWS = 5000  # maximum rows kept in memory


# ── main app ──────────────────────────────────────────────────────────────────

class FirewallLogApp(App[None]):
    """Azure Firewall Log streaming TUI."""

    TITLE = f"Azure Firewall Watch v{VERSION}"
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
    StatusBar.paused {
        background: $warning-darken-2;
        color: $text;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+p", "toggle_pause", "Pause/Resume", priority=True, show=True),
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
        self._connecting_active: bool = False
        self._pending_update: tuple[str, str] | None = None

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
            yield Input(placeholder="Port",          id="f-port",   classes="filter-input")
        yield DataTable(zebra_stripes=True, cursor_type="row", id="log-table")
        yield StatusBar(id="status")
        yield Footer()

    def on_mount(self) -> None:
        tbl = self.query_one("#log-table", DataTable)
        tbl.add_columns(
            "Time (Local)", "Category", "Proto",
            "Source", "Dest / FQDN", "Port",
            "Action", "Policy / Info",
        )
        self._start_stream()
        self.set_interval(1.0, self._flush_rows)
        self._check_update()

    # ── Update check ────────────────────────────────────────────────────────────
    @work(exclusive=False)
    async def _check_update(self) -> None:
        """Silently fetch the latest GitHub release and show UpdateDialog if newer."""
        import urllib.request
        import urllib.error
        import json as _json

        url = "https://api.github.com/repos/cloudchristoph/az-firewall-watch/releases/latest"
        try:
            def _fetch() -> dict:
                req = urllib.request.Request(
                    url, headers={"User-Agent": f"az-firewall-watch/{VERSION}"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                    return _json.loads(resp.read())

            data: dict = await asyncio.get_event_loop().run_in_executor(None, _fetch)
            tag = data.get("tag_name", "").lstrip("v")
            release_url: str = data.get(
                "html_url",
                "https://github.com/cloudchristoph/az-firewall-watch/releases",
            )
        except Exception:
            return  # no network / API error — fail silently

        def _ver(v: str) -> tuple:
            try:
                return tuple(int(x) for x in v.split("."))
            except ValueError:
                return (0,)

        if _ver(tag) > _ver(VERSION):
            # Always push immediately — even over ConnectingDialog.
            # The first-event handler will surgically remove ConnectingDialog
            # from beneath it without touching UpdateDialog.
            self._pending_update = (tag, release_url)
            await self.push_screen(UpdateDialog(tag, release_url))

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
        self._connecting_active = True
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
                        _dialog.show_waiting()
                    status.status = "Connected"
                    self.sub_title = "Live Log Monitor  |  connected"

                    async def on_event(partition_ctx, event) -> None:  # type: ignore[misc]
                        nonlocal _splash_shown
                        if event is None or self._paused:
                            return
                        try:
                            body = json.loads(event.body_as_str())
                        except (ValueError, TypeError):
                            return
                        has_real = False
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
                                has_real = True
                        if has_real and _splash_shown:
                            _splash_shown = False
                            self._connecting_active = False
                            if isinstance(self.screen, UpdateDialog):
                                # UpdateDialog is on top of ConnectingDialog.
                                # Save its state, pop both, re-push UpdateDialog.
                                upd_tag = self.screen._latest
                                upd_url = self.screen._url
                                self._pending_update = None
                                self.pop_screen()   # remove UpdateDialog
                                self.pop_screen()   # remove ConnectingDialog
                                await self.push_screen(UpdateDialog(upd_tag, upd_url))
                            else:
                                self.pop_screen()   # remove ConnectingDialog

                    await client.receive(on_event=on_event, starting_position=position)

            except asyncio.CancelledError:
                if _splash_shown:
                    self._connecting_active = False
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
                self._connecting_active = False
                self.pop_screen()
            await self.push_screen(ErrorDialog(str(last_exc), hint))

    # ── periodic flush ──────────────────────────────────────────────────────────
    async def _flush_rows(self) -> None:
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
                _category_text(row.category, f["cat"]),
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
            "port":   self.query_one("#f-port",   Input).value.lower(),
        }

    @staticmethod
    def _matches(row: FirewallDataRow, f: dict[str, str]) -> bool:
        if f["src"]    and f["src"]    not in row.sourceip.lower():             return False
        if f["dst"]    and f["dst"]    not in (row.targetip or "").lower():     return False
        if f["action"] and f["action"] not in row.action.lower():               return False
        if f["cat"]    and f["cat"]    not in row.category.lower():             return False
        if f["proto"]  and f["proto"]  not in row.protocol.lower():             return False
        if f["port"]   and f["port"]   not in row.targetport.lower():           return False
        return True

    @on(Input.Changed, ".filter-input")
    def on_filter_changed(self, _event: Input.Changed) -> None:
        self._refresh_table()

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        rowid = event.row_key.value
        if rowid is None:
            return
        for row in self._all_rows:
            if row.rowid == rowid:
                self.push_screen(DetailDialog(row))
                return

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
        for fid in ("#f-src", "#f-dst", "#f-action", "#f-cat", "#f-proto", "#f-port"):
            self.query_one(fid, Input).value = ""
        self._refresh_table()

    def action_focus_filter(self) -> None:
        self.query_one("#f-src", Input).focus()


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    FirewallLogApp().run()
