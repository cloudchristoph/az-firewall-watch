"""Top-level Textual app for az-firewall-watch."""
from __future__ import annotations

import heapq
import re

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Select, Switch

from dialogs import DetailDialog, StatusBar
from fw_parser import FirewallDataRow
from helpers import _category_text, _highlight, _to_local

from .config import CATEGORY_OPTIONS, MAX_ROWS, TABLE_TRIM_SLACK, VERSION
from .streaming import run_stream
from .updates import check_for_update


class TimeCell(Text):
    """Time column cell: renders local time but remembers the ISO timestamp.

    DataTable.sort() only sees cell values, so the full-precision timestamp
    travels with the cell to keep newest-first ordering exact within a second.
    """

    __slots__ = ("iso",)

    def __init__(self, iso: str) -> None:
        super().__init__(_to_local(iso))
        self.iso = iso


def _row_time(row: FirewallDataRow) -> str:
    return row.time


def _time_cell_key(cells: tuple) -> str:
    first = cells[0]
    return first.iso if isinstance(first, TimeCell) else str(first)


class FirewallLogApp(App[None]):
    """Azure Firewall Log streaming TUI."""

    TITLE = f"Azure Firewall Watch v{VERSION}"
    SUB_TITLE = "Live Log Monitor  |  connecting..."
    COMMAND_PALETTE_BINDING = ""  # disable palette so ctrl+p is free for pause

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
    #filter-bar #f-hide-dns {
        margin: 0 1;
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
        Binding("ctrl+p", "toggle_pause", "Pause/Resume", show=True),
        Binding("c", "clear_logs", "Clear"),
        # Deliberately NOT a priority binding: priority bindings are resolved
        # from the App downwards and ignore modal screens, which would swallow
        # Escape before any dialog (Detail, Update, Error, Connecting) sees it.
        # The regular chain (focused widget → screen → app) stops at a modal and
        # still reaches this binding from the filter inputs on the main screen.
        Binding("escape", "clear_filters", "Clear Filters"),
        Binding("f", "focus_filter", "Filter"),
        Binding("ctrl+s", "screenshot", "Screenshot", show=True),
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
        # rowid → row for every row currently in the table (detail dialog lookup)
        self._row_index: dict[str, FirewallDataRow] = {}

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
            yield Label("Hide DNS")
            yield Switch(value=True, id="f-hide-dns")
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
        """Drain pending rows into _all_rows and update the table (every 1 s)."""
        has_new = bool(self._pending) or self._skip_pending > 0
        if not has_new:
            return

        batch, self._pending = self._pending[:], []
        skips, self._skip_pending = self._skip_pending, 0

        status = self.query_one("#status", StatusBar)
        status.total += len(batch)
        status.skipped += skips
        if not batch:
            return

        policies_before = len(self._seen_policies)
        for r in batch:
            if r.fw_policy:
                self._seen_policies.add(r.fw_policy)

        # _all_rows is kept sorted newest-first; merge the (small) sorted batch
        # in O(n) instead of re-sorting the whole buffer every second.
        batch.sort(key=_row_time, reverse=True)
        merged = list(heapq.merge(batch, self._all_rows, key=_row_time, reverse=True))
        self._all_rows = merged[:MAX_ROWS]

        tbl = self.query_one("#log-table", DataTable)
        needs_full_rebuild = (
            # The single-policy display rule changed → existing rows render differently.
            (policies_before <= 1 < len(self._seen_policies))
            # Table would grow past the buffer over MAX_ROWS → rebuild to trim.
            or tbl.row_count + len(batch) > MAX_ROWS + TABLE_TRIM_SLACK
        )
        if needs_full_rebuild:
            self._refresh_table()
        else:
            self._append_rows(batch)

    # ── table rendering ────────────────────────────────────────────────────────
    def _render_cells(self, row: FirewallDataRow, f: dict, single_policy: bool) -> tuple:
        """Build the cell renderables for one table row."""
        action_text = self._action_text(row.action)
        if f["action"]:
            action_text.highlight_regex(f"(?i){re.escape(f['action'])}", style="bold reverse")
        info = row.policy or row.moreinfo
        if single_policy and row.fw_policy and info.startswith(row.fw_policy + "»"):
            info = info[len(row.fw_policy) + 1:]
        return (
            TimeCell(row.time),
            _category_text(row.category),
            _highlight(row.protocol, f["proto"]),
            self._source_text(row.sourceip, row.srcport, f["src"]),
            _highlight(row.targetip, f["dst"]),
            row.targetport,
            action_text,
            self._info_text(info),
        )

    def _update_visible_count(self, f: dict, tbl: DataTable) -> None:
        status = self.query_one("#status", StatusBar)
        status.visible_count = tbl.row_count if any(f.values()) else -1

    def _append_rows(self, batch: list[FirewallDataRow]) -> None:
        """Incrementally add new rows and re-sort the table (steady-state path).

        Only the rows that pass the current filters are added; the table is
        then re-ordered newest-first via DataTable.sort, which re-indexes rows
        without re-creating them. Far cheaper than clear() + add_row() × N.
        """
        f = self._get_filters()
        tbl = self.query_one("#log-table", DataTable)
        single_policy = len(self._seen_policies) <= 1
        prev_rowid = self._selected_rowid
        prev_scroll_y = tbl.scroll_y
        prev_idx = None
        if prev_rowid is not None:
            try:
                prev_idx = tbl.get_row_index(prev_rowid)
            except Exception:
                prev_rowid = None

        added = 0
        with tbl.prevent(DataTable.RowHighlighted):
            for row in batch:
                if self._matches(row, f):
                    tbl.add_row(*self._render_cells(row, f, single_policy), key=row.rowid)
                    # Index only what is in the table (rows may linger there
                    # beyond _all_rows until the next trim); the index is
                    # rebuilt from _all_rows on every full refresh, so it
                    # stays bounded by max(MAX_ROWS, table size).
                    self._row_index[row.rowid] = row
                    added += 1
            if added:
                tbl.sort(key=_time_cell_key, reverse=True)
                if prev_rowid is not None and prev_idx is not None:
                    idx = tbl.get_row_index(prev_rowid)
                    tbl.move_cursor(row=idx, animate=False, scroll=False)
                    # keep the selected row where it was on screen
                    tbl.scroll_to(y=prev_scroll_y + (idx - prev_idx), animate=False)
                else:
                    tbl.scroll_home(animate=False)
        self._update_visible_count(f, tbl)

    def _refresh_table(self) -> None:
        """Full rebuild of the table from _all_rows (filter changes, trimming)."""
        f = self._get_filters()
        visible = [r for r in self._all_rows if self._matches(r, f)]
        self._row_index = {r.rowid: r for r in self._all_rows}
        tbl = self.query_one("#log-table", DataTable)
        prev_scroll_y = tbl.scroll_y
        prev_rowid = self._selected_rowid
        single_policy = len(self._seen_policies) <= 1

        with tbl.prevent(DataTable.RowHighlighted):
            tbl.clear()
            for row in visible:
                tbl.add_row(*self._render_cells(row, f, single_policy), key=row.rowid)

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
        self._update_visible_count(f, tbl)

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
        if a == "resolvefail":
            return Text(action, style="bold dark_orange3")
        # Flow-trace flags
        if a == "invalid":
            return Text(action, style="bold red")
        if a == "rst":
            return Text(action, style="bold yellow")
        if a in ("fin", "fin-ack", "syn-ack", "syn"):
            return Text(action, style="dim")
        # Fat-flow bandwidth
        if a.endswith(" mbps"):
            return Text(action, style="bold cyan")
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

    # group → collection → rule: progressively more prominent
    _INFO_SEGMENT_STYLES = ("dim", "default", "bold")

    @staticmethod
    def _info_text(info: str) -> Text:
        """Render rule-info with dimmed separators and per-segment colors."""
        t = Text()
        parts = info.split("»")
        styles = FirewallLogApp._INFO_SEGMENT_STYLES
        for i, part in enumerate(parts):
            if i > 0:
                t.append(" » ", style="dim")
            label = part[:40] + "…" if len(part) > 40 else part
            t.append(label, style=styles[min(i, len(styles) - 1)])
        return t

    # ── filtering ──────────────────────────────────────────────────────────────
    def _get_filters(self) -> dict:
        cat_val = self.query_one("#f-cat", Select).value
        cat = cat_val.lower() if isinstance(cat_val, str) else ""
        return {
            "src":      self.query_one("#f-src",    Input).value.lower(),
            "dst":      self.query_one("#f-dst",    Input).value.lower(),
            "action":   self.query_one("#f-action", Input).value.lower(),
            "cat":      cat,
            "proto":    self.query_one("#f-proto",  Input).value.lower(),
            "port":     self.query_one("#f-port",   Input).value.lower(),
            "hide_dns": self.query_one("#f-hide-dns", Switch).value,
        }

    @staticmethod
    def _matches(row: FirewallDataRow, f: dict) -> bool:
        if f["hide_dns"] and row.category.lower() == "dnsquery":               return False
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
    def on_category_changed(self, event: Select.Changed) -> None:
        # If the user explicitly picks DnsQuery, disable the hide-DNS toggle so
        # they actually see those rows.
        if isinstance(event.value, str) and event.value == "dnsquery":
            self.query_one("#f-hide-dns", Switch).value = False
        self._refresh_table()

    @on(Switch.Changed, "#f-hide-dns")
    def on_hide_dns_changed(self, _event: Switch.Changed) -> None:
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
        row = self._row_index.get(rowid)
        if row is not None:
            self.push_screen(DetailDialog(row))

    # ── actions (key bindings) ─────────────────────────────────────────────────
    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.query_one("#status", StatusBar).paused = self._paused

    def action_clear_logs(self) -> None:
        self._all_rows = []
        self._pending = []
        self._selected_rowid = None
        self._seen_policies.clear()
        self._row_index.clear()
        self.query_one("#log-table", DataTable).clear()
        status = self.query_one("#status", StatusBar)
        status.total = 0
        status.skipped = 0
        status.visible_count = -1

    def action_clear_filters(self) -> None:
        for fid in ("#f-src", "#f-dst", "#f-action", "#f-proto", "#f-port"):
            self.query_one(fid, Input).value = ""
        self.query_one("#f-cat", Select).clear()
        self.query_one("#f-hide-dns", Switch).value = True
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
