"""Top-level Textual app for az-firewall-watch."""
from __future__ import annotations

import re

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Select

from dialogs import DetailDialog, StatusBar
from fw_parser import FirewallDataRow
from helpers import _category_text, _highlight, _to_local

from .config import CATEGORY_OPTIONS, MAX_ROWS, VERSION
from .streaming import run_stream
from .updates import check_for_update


class FirewallLogApp(App[None]):
    """Azure Firewall Log streaming TUI."""

    TITLE = f"Azure Firewall Watch v{VERSION}"
    SUB_TITLE = "Live Log Monitor  |  connecting..."

    CSS = """
    Screen {
        layout: vertical;
        overflow: hidden;
    }

    #filter-bar {
        height: 3;
        background: $surface;
        padding: 0 1;
        overflow: hidden;
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
    #filter-bar #f-cat {
        width: 24;
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
        Binding("q", "quit", "Quit", show=False),
        Binding("ctrl+q", "quit", "Quit", priority=True, show=True),
        Binding("ctrl+p", "toggle_pause", "Pause/Resume", priority=True, show=True),
        Binding("c", "clear_logs", "Clear"),
        Binding("escape", "clear_filters", "Clear Filters", priority=True),
        Binding("f", "focus_filter", "Filter"),
    ]

    # ── state ──────────────────────────────────────────────────────────────────
    def __init__(self) -> None:
        super().__init__()
        self.theme = "flexoki"
        self._all_rows: list[FirewallDataRow] = []
        self._pending: list[FirewallDataRow] = []
        self._skip_pending: int = 0
        self._paused: bool = False
        self._fw_name_set: bool = False
        self._seen_policies: set[str] = set()
        self._selected_rowid: str | None = None

    # ── layout ─────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="filter-bar"):
            yield Label("Filter:")
            yield Input(placeholder="Source IP",    id="f-src",    classes="filter-input")
            yield Input(placeholder="Dest / FQDN",  id="f-dst",    classes="filter-input")
            yield Input(placeholder="Action",       id="f-action", classes="filter-input")
            yield Select(
                [(label, value) for label, value in CATEGORY_OPTIONS],
                prompt="All",
                id="f-cat",
                allow_blank=True,
            )
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
            "Action", "Rule Info",
        )
        self._start_stream()
        self.set_interval(1.0, self._flush_rows)
        self._check_update()

    # ── workers ────────────────────────────────────────────────────────────────
    @work(exclusive=True)
    async def _start_stream(self) -> None:
        await run_stream(self)

    @work(exclusive=False)
    async def _check_update(self) -> None:
        await check_for_update(self, VERSION)

    # ── periodic flush ─────────────────────────────────────────────────────────
    async def _flush_rows(self) -> None:
        """Drain pending rows into _all_rows and refresh the table (every 1 s)."""
        has_new = bool(self._pending) or self._skip_pending > 0
        if not has_new:
            return

        batch, self._pending = self._pending[:], []
        skips, self._skip_pending = self._skip_pending, 0

        if batch:
            for r in batch:
                if r.fw_policy:
                    self._seen_policies.add(r.fw_policy)
            batch.sort(key=lambda r: r.time, reverse=True)
            self._all_rows = (batch + self._all_rows)[:MAX_ROWS]

        status = self.query_one("#status", StatusBar)
        status.total += len(batch)
        status.skipped += skips

        if batch:
            self._refresh_table()

    # ── table rendering ────────────────────────────────────────────────────────
    def _refresh_table(self) -> None:
        f = self._get_filters()
        visible = [r for r in self._all_rows if self._matches(r, f)]

        tbl = self.query_one("#log-table", DataTable)
        prev_scroll_y = tbl.scroll_y
        prev_rowid = self._selected_rowid
        single_policy = len(self._seen_policies) <= 1

        with tbl.prevent(DataTable.RowHighlighted):
            tbl.clear()
            for row in visible:
                action_text = self._action_text(row.action)
                if f["action"]:
                    action_text.highlight_regex(
                        f"(?i){re.escape(f['action'])}", style="bold reverse"
                    )
                info = row.policy or row.moreinfo
                if single_policy and row.fw_policy and info.startswith(row.fw_policy + "»"):
                    info = info[len(row.fw_policy) + 1:]
                tbl.add_row(
                    _to_local(row.time),
                    _category_text(row.category),
                    _highlight(row.protocol, f["proto"]),
                    self._source_text(row.sourceip, row.srcport, f["src"]),
                    _highlight(row.targetip, f["dst"]),
                    row.targetport,
                    action_text,
                    info[:60],
                    key=row.rowid,
                )

            if prev_rowid is not None:
                try:
                    idx = tbl.get_row_index(prev_rowid)
                    tbl.move_cursor(row=idx, animate=False, scroll=False)
                    tbl.scroll_to(y=prev_scroll_y, animate=False)
                except Exception:
                    pass
            else:
                # No active selection — keep the view pinned to the newest row.
                tbl.scroll_home(animate=False)

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
            return Text(action, style="dim")
        if a == "nxdomain":
            return Text(action, style="bold yellow")
        if a in ("servfail", "refused"):
            return Text(action, style="bold red")
        return Text(action)

    @staticmethod
    def _source_text(sourceip: str, srcport: str, term: str) -> Text:
        """Render 'ip:port' with the port portion dimmed."""
        t = Text()
        t.append(sourceip)
        t.append(":", style="dim")
        t.append(srcport, style="dim")
        if term:
            t.highlight_regex(f"(?i){re.escape(term)}", style="bold reverse")
        return t

    # ── filtering ──────────────────────────────────────────────────────────────
    def _get_filters(self) -> dict[str, str]:
        cat_val = self.query_one("#f-cat", Select).value
        cat = cat_val.lower() if isinstance(cat_val, str) else ""
        return {
            "src":    self.query_one("#f-src",    Input).value.lower(),
            "dst":    self.query_one("#f-dst",    Input).value.lower(),
            "action": self.query_one("#f-action", Input).value.lower(),
            "cat":    cat,
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

    # ── events ─────────────────────────────────────────────────────────────────
    @on(Input.Changed, ".filter-input")
    def on_filter_changed(self, _event: Input.Changed) -> None:
        self._refresh_table()

    @on(Select.Changed, "#f-cat")
    def on_category_changed(self, _event: Select.Changed) -> None:
        self._refresh_table()

    @on(DataTable.RowHighlighted)
    def on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = event.row_key.value if event.row_key else None
        if key is not None:
            self._selected_rowid = key

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        rowid = event.row_key.value
        if rowid is None:
            return
        for row in self._all_rows:
            if row.rowid == rowid:
                self.push_screen(DetailDialog(row))
                return

    # ── actions (key bindings) ─────────────────────────────────────────────────
    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.query_one("#status", StatusBar).paused = self._paused

    def action_clear_logs(self) -> None:
        self._all_rows = []
        self._pending = []
        self._selected_rowid = None
        self._seen_policies.clear()
        self.query_one("#log-table", DataTable).clear()
        status = self.query_one("#status", StatusBar)
        status.total = 0
        status.skipped = 0

    def action_clear_filters(self) -> None:
        for fid in ("#f-src", "#f-dst", "#f-action", "#f-proto", "#f-port"):
            self.query_one(fid, Input).value = ""
        self.query_one("#f-cat", Select).clear()
        # Deselect any pinned row so the view returns to auto-scrolling.
        self._selected_rowid = None
        self._refresh_table()

    def action_focus_filter(self) -> None:
        self.query_one("#f-src", Input).focus()

    def get_system_commands(self, screen: Screen):  # type: ignore[override]
        for cmd in super().get_system_commands(screen):
            if cmd.title in ("Maximize", "Minimize"):
                continue
            yield cmd
