"""Top-level Textual app for az-firewall-watch."""
from __future__ import annotations

import heapq
import ipaddress
import re
import time
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Switch,
    TabbedContent,
    TabPane,
)

from dialogs import PolicyContextNoticeDialog, StatusBar
from fw_parser import FirewallDataRow
from helpers import _category_text, _highlight, _is_ipv6, _to_local

from .azure_resources import FirewallInfo, FirewallPolicyInfo, IpGroupInfo
from .cache import CachedSnapshot
from .config import CATEGORY_GROUPS, CATEGORY_OPTIONS, MAX_ROWS, TABLE_TRIM_SLACK, VERSION
from .enrichment import find_matching_ip_groups, resolve_fw_instance
from .management import load_management_data
from .streaming import run_stream
from .trace import Flow, LoggedMatch, build_trace, find_logged_rule
from .updates import check_for_update
from .views import FirewallView, IpGroupsView, PolicyView
from .views.detail_screen import DetailDialog


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

    TabbedContent {
        height: 1fr;
    }
    TabPane {
        height: 1fr;
        padding: 0;
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
        Binding("ctrl+q", "quit", "Quit", priority=True, show=False),  # works inside inputs too
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
        Binding("ctrl+r", "refresh_metadata", "Refresh metadata", show=True),
    ]

    # ── state ──────────────────────────────────────────────────────────────────
    def __init__(self, *, policy_context: bool = True, policy_context_notice: bool = False,
                 env_file: Path | None = None) -> None:
        super().__init__()
        self.theme = "flexoki"
        # Policy context (ARM reads, CLI token fallback, cache).
        # Off → Logs tab only, no ARM access at all.
        self._policy_context = policy_context
        self._policy_context_notice = policy_context and policy_context_notice
        # While the first-run notice is open nothing may reach ARM: the first
        # firewall id seen is parked here and loaded only after "Keep enabled".
        self._awaiting_context_answer = self._policy_context_notice
        self._deferred_firewall_id: str | None = None
        self._env_file = env_file
        self._all_rows: list[FirewallDataRow] = []
        self._pending: list[FirewallDataRow] = []
        self._skip_pending: int = 0
        self._paused: bool = False
        self._fw_name_set: bool = False
        self._seen_policies: set[str] = set()
        self._selected_rowid: str | None = None
        # rowid → row for every row currently in the table (detail dialog lookup)
        self._row_index: dict[str, FirewallDataRow] = {}
        # Policy context state (firewall, policy, IP groups from ARM)
        self._firewall_id: str | None = None
        self._fw_info: FirewallInfo | None = None
        self._policy_info: FirewallPolicyInfo | None = None
        self._ip_groups: dict[str, IpGroupInfo] = {}
        self._subnet_cidrs: list[str] = []
        self._mgmt_loaded: bool = False
        self._snapshot: CachedSnapshot | None = None
        self._known_rules: set[tuple[str, str, str]] = set()  # (rcg, rc, rule) of the loaded policy chain
        self._last_auto_refresh: float | None = None  # monotonic time of the last automatic re-fetch

    # ── layout ─────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header()
        if self._policy_context:
            with TabbedContent(id="main-tabs", initial="tab-logs"):
                with TabPane("Logs", id="tab-logs"):
                    # The filter bar belongs to the Logs tab: above the tab strip it
                    # would show and hide with the tab and make the strip jump.
                    yield from self._compose_filter_bar()
                    yield DataTable(zebra_stripes=True, cursor_type="row", id="log-table")
                with TabPane("Firewall", id="tab-firewall"):
                    yield FirewallView(id="firewall-view")
                with TabPane("Policy", id="tab-policy"):
                    yield PolicyView(id="policy-view")
                with TabPane("IP Groups", id="tab-ipgroups"):
                    yield IpGroupsView(id="ipgroups-view")
        else:
            yield from self._compose_filter_bar()
            yield DataTable(zebra_stripes=True, cursor_type="row", id="log-table")
        yield StatusBar(id="status")

    @staticmethod
    def _compose_filter_bar() -> ComposeResult:
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
        yield Footer()

    def on_mount(self) -> None:
        tbl = self.query_one("#log-table", DataTable)
        tbl.add_columns(
            "Time (Local)", "Category", "Proto",
            "Source", "Dest / FQDN", "Port",
            "Action", "Rule Info",
        )
        # Initial state: Logs tab is active, filters must be visible, and the
        # table has focus so single-key bindings (f, c, arrows) work at once.
        tbl.focus()
        self._refresh_metadata_views()
        self._start_stream()
        self.set_interval(1.0, self._flush_rows)
        self.set_interval(60.0, self._check_cache_age)
        self._check_update()
        if self._policy_context_notice:
            notice = PolicyContextNoticeDialog()
            notice.repush_callback = self._on_policy_context_notice  # keeps working if the splash lifts it
            self.push_screen(notice, callback=self._on_policy_context_notice)

    # ── enrichment switch ──────────────────────────────────────────────────────
    def _on_policy_context_notice(self, keep: bool | None) -> None:
        keep = True if keep is None else keep
        self._awaiting_context_answer = False
        self._persist_policy_context(keep)
        if not keep:
            self._disable_policy_context()
            return
        if self._deferred_firewall_id is not None:
            fid, self._deferred_firewall_id = self._deferred_firewall_id, None
            self.request_mgmt_load(fid)  # the consent is in; now the metadata may load

    def _persist_policy_context(self, enabled: bool) -> None:
        """Remember the decision in .env (only when a .env exists next to us)."""
        if self._env_file is None or not self._env_file.exists():
            return
        try:
            from setup.services import set_env_value
            set_env_value(self._env_file, "POLICY_CONTEXT", "on" if enabled else "off")
        except OSError:
            pass

    def _disable_policy_context(self) -> None:
        """Switch policy context off at runtime: drop the metadata tabs, stop ARM use."""
        self._policy_context = False
        self._firewall_id = None
        self._deferred_firewall_id = None
        self._mgmt_loaded = False
        self._snapshot = None
        self._known_rules = set()
        self._fw_info = self._policy_info = None
        self._ip_groups = {}
        self._subnet_cidrs = []
        self.workers.cancel_group(self, "mgmt")
        status = self.query_one("#status", StatusBar)
        status.meta = "policy context off"
        try:
            tabs = self.query_one("#main-tabs", TabbedContent)
            for pane in ("tab-firewall", "tab-policy", "tab-ipgroups"):
                tabs.remove_pane(pane)
            tabs.active = "tab-logs"
        except Exception:
            pass
        self._refresh_table()

    # ── workers ────────────────────────────────────────────────────────────────
    @work(exclusive=True)
    async def _start_stream(self) -> None:
        await run_stream(self)

    @work(exclusive=False)
    async def _check_update(self) -> None:
        await check_for_update(self, VERSION)

    @work(exclusive=True, group="mgmt")
    async def _load_mgmt(self, firewall_id: str, *, force: bool = False) -> None:
        """Background fetch of firewall / policy / IP-groups metadata."""
        status = self.query_one("#status", StatusBar)
        snap = await load_management_data(firewall_id, force=force)
        if snap is None:
            # Keep whatever was loaded before (still valid policy data) but say
            # so; only report "unavailable" when there is nothing to show.
            status.meta = (
                "refresh failed · showing previous metadata"
                if self._mgmt_loaded else "metadata unavailable (no ARM access)"
            )
            return
        self._fw_info = snap.firewall
        self._policy_info = snap.policy
        self._ip_groups = snap.ip_groups
        self._subnet_cidrs = snap.subnet_cidrs
        self._mgmt_loaded = True
        self._snapshot = snap
        self._known_rules = {
            (g.name, rc.name, r.name)
            for _, g in (snap.policy.all_groups() if snap.policy else [])
            for rc in g.rule_collections for r in rc.rules
        }
        if snap.firewall.name:
            # ARM knows the real (case-preserved) name; the diagnostics
            # resourceId only gave us an upper-cased one.
            self.sub_title = snap.firewall.name
            self._fw_name_set = True
        status.meta = self._meta_text(snap)
        self._refresh_metadata_views()
        self._refresh_table()

    @staticmethod
    def _meta_text(snap: CachedSnapshot) -> str:
        policy_txt = f"Policy: {snap.policy.sku_tier or 'unknown tier'}" if snap.policy else "Policy: none"
        age_min = int(snap.age_seconds() // 60)
        age = "fresh" if age_min < 1 else f"cache {age_min}m"
        return f"{policy_txt} · {len(snap.ip_groups)} IP groups · {age}"

    # ── keeping the policy context current ────────────────────────────────────
    _AUTO_REFRESH_INTERVAL = 300.0  # seconds between automatic re-fetches

    def _refresh_policy_context(self, reason: str) -> bool:
        """Force a metadata re-fetch for *reason*, at most once per interval."""
        if not self._policy_context or self._firewall_id is None or not self._mgmt_loaded:
            return False
        now = time.monotonic()
        # None, not 0.0: monotonic time counts from boot, and a fresh machine
        # (CI runners, VMs) may be younger than the interval.
        if self._last_auto_refresh is not None and now - self._last_auto_refresh < self._AUTO_REFRESH_INTERVAL:
            return False
        self._last_auto_refresh = now
        self.query_one("#status", StatusBar).meta = f"refreshing metadata ({reason})…"
        self._load_mgmt(self._firewall_id, force=True)
        return True

    def _check_cache_age(self) -> None:
        """Every minute: keep the age in the status bar honest; re-fetch once the TTL is over."""
        snap = self._snapshot
        if snap is None or not self._policy_context:
            return
        if not snap.is_fresh():
            if self._refresh_policy_context("cache expired"):
                return
        status = self.query_one("#status", StatusBar)
        if status.meta.startswith("Policy: "):
            status.meta = self._meta_text(snap)

    def _note_unknown_rules(self, batch: list[FirewallDataRow]) -> None:
        """A logged rule the loaded policy does not know means the cache is stale."""
        if not self._known_rules:
            return
        for r in batch:
            if r.rule_name and r.rule_collection_group and \
                    (r.rule_collection_group, r.rule_collection, r.rule_name) not in self._known_rules:
                self._refresh_policy_context(f"new rule {r.rule_name}")
                return

    def _refresh_metadata_views(self) -> None:
        """Refresh Firewall / Policy / IP Groups tabs from current state."""
        if not self._policy_context:
            return
        snap = self._snapshot
        self.query_one("#firewall-view", FirewallView).render_data(
            self._fw_info, self._policy_info, self._subnet_cidrs,
            snap.diagnostics if snap else [],
            subnets=snap.subnets if snap else [],
            nat_gateways=snap.nat_gateways if snap else [],
            maintenance=snap.maintenance if snap else [],
            maintenance_readable=snap.maintenance_readable if snap else True,
        )
        self.query_one("#policy-view", PolicyView).render_data(self._policy_info, self._ip_groups)
        self.query_one("#ipgroups-view", IpGroupsView).render_data(
            self._ip_groups,
            self._ip_group_usage_counts(),
            self._policy_info,
        )

    def _ip_group_usage_counts(self) -> dict[str, int]:
        if self._policy_info is None:
            return {}
        out: dict[str, int] = {}
        for _policy_name, g in self._policy_info.all_groups():  # parent chain included
            for rc in g.rule_collections:
                for r in rc.rules:
                    for gid in r.source_ip_groups + r.destination_ip_groups:
                        out[gid] = out.get(gid, 0) + 1
        return out

    def request_mgmt_load(self, firewall_id: str) -> None:
        """Called from streaming.on_event when we first see a resourceId."""
        if not self._policy_context:
            return
        if self._awaiting_context_answer:
            # Consent pending: remember the firewall, touch nothing yet.
            if self._deferred_firewall_id is None:
                self._deferred_firewall_id = firewall_id
            return
        if self._firewall_id is None:
            self._firewall_id = firewall_id
            self._load_mgmt(firewall_id)

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

        self._note_unknown_rules(batch)
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
            self._source_text(self._format_ip(row.sourceip), row.srcport, f["src"]),
            _highlight(self._format_ip(row.targetip), f["dst"]),
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
                    # beyond _all_rows until the next trim); every full refresh
                    # rebuilds the index from the visible rows, so it stays
                    # bounded by the table size.
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
        self._row_index = {r.rowid: r for r in visible}  # exactly the rows in the table
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
        """Render 'ip:port' with the port portion dimmed; IPv6 addresses get bracketed.

        ``sourceip`` may already be the ``AzFw.<n>`` label ``_format_ip`` resolved it
        to — that never parses as an address, so ``_is_ipv6`` only ever fires on a
        real, unresolved IP. The bracket decision therefore lands on the raw address
        exactly as if it were checked before ``_format_ip`` ran. ``format_endpoint``
        is not used here: it would hand back one joined string, and the port needs
        to stay a separate, dimmed ``Text`` span.
        """
        t = Text()
        t.append(f"[{sourceip}]" if _is_ipv6(sourceip) else sourceip)
        t.append(":", style="dim")
        t.append(srcport, style="dim")
        if term:
            t.highlight_regex(f"(?i){re.escape(term)}", style="bold reverse")
        return t

    def _format_ip(self, ip: str) -> str:
        """Return ``AzFw.N`` for IPs inside the firewall subnet, else the IP."""
        if not self._subnet_cidrs or not ip or ip == "-":
            return ip
        label = resolve_fw_instance(ip, self._subnet_cidrs)
        return label or ip

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

    def _is_logs_tab_active(self) -> bool:
        if not self._policy_context:
            return True
        tabs = self.query_one("#main-tabs", TabbedContent)
        return tabs.active == "tab-logs"

    @staticmethod
    def _category_matches(selected: str, category: str) -> bool:
        """``group:<name>`` presets match a set of categories, plain values a substring."""
        cat = category.lower()
        if selected.startswith("group:"):
            return cat in CATEGORY_GROUPS.get(selected[6:], frozenset())
        return selected in cat

    @staticmethod
    def _matches(row: FirewallDataRow, f: dict) -> bool:
        if f["hide_dns"] and row.category.lower() == "dnsquery":               return False
        if f["src"]    and f["src"]    not in row.sourceip.lower():             return False
        if f["dst"]    and f["dst"]    not in (row.targetip or "").lower():     return False
        if f["action"] and f["action"] not in row.action.lower():               return False
        if f["cat"] and not FirewallLogApp._category_matches(f["cat"], row.category):    return False
        if f["proto"]  and f["proto"]  not in row.protocol.lower():             return False
        if f["port"]   and f["port"]   not in row.targetport.lower():           return False
        return True

    # ── events ─────────────────────────────────────────────────────────────────
    @on(Input.Changed, ".filter-input")
    def on_filter_changed(self, _event: Input.Changed) -> None:
        if not self._is_logs_tab_active():
            return
        self._refresh_table()

    @on(Select.Changed, "#f-cat")
    def on_category_changed(self, event: Select.Changed) -> None:
        if not self._is_logs_tab_active():
            return
        # If the user explicitly asks for DNS rows, disable the hide-DNS toggle so
        # they actually see them.
        if isinstance(event.value, str) and event.value in ("dnsquery", "group:dns"):
            self.query_one("#f-hide-dns", Switch).value = False
        self._refresh_table()

    @on(Switch.Changed, "#f-hide-dns")
    def on_hide_dns_changed(self, _event: Switch.Changed) -> None:
        if not self._is_logs_tab_active():
            return
        self._refresh_table()

    @on(TabbedContent.TabActivated, "#main-tabs")
    def on_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        logs_active = self._is_logs_tab_active()
        if logs_active:
            self._refresh_table()
        else:
            self.query_one("#status", StatusBar).visible_count = -1

    @on(IpGroupsView.JumpToPolicyRule)
    def on_ipgroup_jump_to_policy(self, event: IpGroupsView.JumpToPolicyRule) -> None:
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-policy"
        self.query_one("#policy-view", PolicyView).focus_rule(event.rule_ref)

    @on(DataTable.RowHighlighted)
    def on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "log-table" or not self._is_logs_tab_active():
            return
        key = event.row_key.value if event.row_key else None
        if key is not None:
            self._selected_rowid = key

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "log-table" or not self._is_logs_tab_active():
            return
        rowid = event.row_key.value
        if rowid is None:
            return
        row = self._row_index.get(rowid)
        if row is not None:
            self._open_detail(row)

    # Only rows that *are* a policy decision get an evaluation trace. Flow traces,
    # fat flows, DNS proxy rows and IDPS hits are observations, not rule matches.
    _TRACEABLE = frozenset({"networkrule", "apprule", "natrule", "threatintel"})

    def _is_traceable(self, row: FirewallDataRow) -> bool:
        return row.category.lower() in self._TRACEABLE

    # Why an observation row has no trace: what the category records instead of
    # a rule decision. The wording must not read as "the firewall skipped the
    # policy": it did not, the log simply does not carry its decision here.
    _NO_DECISION = {
        "flowtrace": "FlowTrace records the handshake and flags of a connection, not a rule decision.",
        "fatflow": "FatFlow records the top flows by rate, not a rule decision.",
        "dnsquery": "DNS proxy rows record the query and its answer, not a rule decision.",
        "dnsfailure": "DNS proxy rows record a failed resolution, not a rule decision.",
        "idps": "IDPS rows record a signature hit; the rule decision for the flow is a separate row.",
    }

    def _trace_note(self, row: FirewallDataRow) -> str:
        """Title and reason for a missing trace, empty when a trace can be built."""
        cat = row.category.lower()
        if cat not in self._TRACEABLE:
            why = self._NO_DECISION.get(cat, f"{row.category} rows record observations, not a rule decision.")
            return f"No rule decision in this log\n{why} There is no policy trace to show."
        if not self._mgmt_loaded or self._policy_info is None:
            return "Policy trace not available\nIt needs the firewall metadata, which is not loaded yet."
        return ""

    def _open_detail(self, row: FirewallDataRow) -> None:
        """Open the row detail dialog; the evaluation trace sits beside it when possible.

        When policy context is on but no trace can be built, the dialog itself
        says why. The status bar keeps the policy and cache state: a property
        of one row must not overwrite the state of the application.
        """
        trace = None
        note = ""
        if self._policy_context:
            note = self._trace_note(row)
            if not note and self._policy_info is not None:
                trace = build_trace(self._flow_from_row(row), self._policy_info, self._ip_groups,
                                    self._logged_from_row(row))
        self.push_screen(
            DetailDialog(row, enrichment=self._compute_enrichment(row), trace=trace, trace_note=note),
            callback=self._on_trace_result,
        )

    @staticmethod
    def _flow_from_row(row: FirewallDataRow) -> Flow:
        target, port = row.targetip or "", row.targetport
        if row.category.lower() == "natrule" and row.nat_dst_ip:
            # The DNAT log carries the translated target; the rule matched the public one.
            target, port = row.nat_dst_ip, row.nat_dst_port
        try:
            ipaddress.ip_address(target)
            is_fqdn = False
        except ValueError:
            is_fqdn = bool(target) and target != "-"  # AppRule, DNS and FQDN-based ThreatIntel rows
        return Flow(
            category=row.category,
            protocol=row.protocol if row.protocol != "-" else "",
            src_ip=row.sourceip,
            dst_ip="" if is_fqdn else target,
            dst_fqdn=target if is_fqdn else "",
            dst_port="" if port == "-" else port,
            action=row.action if row.action != "-" else "",
            explicit_proxy=row.explicit_proxy == "yes",
            tls_inspected=row.tls_inspected == "yes",
        )

    @staticmethod
    def _logged_from_row(row: FirewallDataRow) -> LoggedMatch | None:
        if not (row.rule_collection_group and row.rule_collection and row.rule_name):
            return None
        return LoggedMatch(policy=row.fw_policy, group=row.rule_collection_group,
                           collection=row.rule_collection, rule=row.rule_name, action=row.action)

    def _compute_enrichment(self, row: FirewallDataRow) -> dict:
        """Build the optional enrichment payload for DetailDialog."""
        if not self._mgmt_loaded:
            return {}
        out: dict = {}
        if self._subnet_cidrs:
            src_lbl = resolve_fw_instance(row.sourceip, self._subnet_cidrs)
            dst_lbl = resolve_fw_instance(row.targetip, self._subnet_cidrs)
            if src_lbl:
                out["source_fw_instance"] = src_lbl
            if dst_lbl:
                out["dest_fw_instance"] = dst_lbl
        if self._ip_groups:
            src_groups = find_matching_ip_groups(row.sourceip, self._ip_groups)
            dst_groups = find_matching_ip_groups(row.targetip, self._ip_groups)
            if src_groups:
                out["source_ip_groups"] = src_groups
            if dst_groups:
                out["dest_ip_groups"] = dst_groups
        if self._policy_info is not None:
            # Exact lookup of the rule the firewall reported — no guessing.
            logged = self._logged_from_row(row)
            found = find_logged_rule(self._policy_info, logged)
            if found is not None:
                policy_name, grp, rc, rule = found
                out["rule_priority"] = f"RCG:{grp.priority} \u00bb RC:{rc.priority}"
                out["rule_action"] = rc.action
                out["rule_definition"] = self._rule_definition(rule)
                if policy_name and policy_name != self._policy_info.name:
                    out["rule_policy"] = f"{policy_name} (inherited)"
            elif logged is not None:
                out["rule_definition"] = "logged rule not in loaded policy (Ctrl+R to refresh)"
        return out

    def _rule_definition(self, rule) -> str:
        """One-line summary of a rule's definition with IP groups resolved to names."""
        def names(ids: list[str]) -> list[str]:
            return [self._ip_groups[g].name if g in self._ip_groups else g.rsplit("/", 1)[-1] for g in ids]
        src = rule.source_addresses + names(rule.source_ip_groups)
        dst = (rule.destination_addresses + names(rule.destination_ip_groups)
               + rule.destination_fqdns + rule.fqdn_tags + rule.target_urls)
        dst_txt = ", ".join(dst) or "any"
        if rule.translated_address or rule.translated_fqdn:
            target = rule.translated_address or rule.translated_fqdn
            dst_txt += f" → {target}:{rule.translated_port}" if rule.translated_port else f" → {target}"
        parts = [
            ", ".join(rule.protocols) or "any",
            ", ".join(rule.destination_ports) or "any port",
            "from " + (", ".join(src) or "any"),
            "to " + dst_txt,
        ]
        if rule.http_headers:
            count = len(rule.http_headers)
            noun = "HTTP header" if count == 1 else "HTTP headers"
            header_names = ", ".join(h.name for h in rule.http_headers)
            parts.append(f"inserts {count} {noun} ({header_names})")
        return "  ".join(parts)

    # ── actions (key bindings) ─────────────────────────────────────────────────
    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.query_one("#status", StatusBar).paused = self._paused

    def action_clear_logs(self) -> None:
        self._ensure_logs_tab()
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
        self._ensure_logs_tab()
        for fid in ("#f-src", "#f-dst", "#f-action", "#f-proto", "#f-port"):
            self.query_one(fid, Input).value = ""
        self.query_one("#f-cat", Select).clear()
        self.query_one("#f-hide-dns", Switch).value = True
        # Deselect any pinned row so the view returns to auto-scrolling.
        self._selected_rowid = None
        self._refresh_table()

    def action_focus_filter(self) -> None:
        self._ensure_logs_tab()
        self.query_one("#f-src", Input).focus()

    def _ensure_logs_tab(self) -> None:
        if not self._policy_context:
            return  # Logs-only layout: there are no tabs to switch
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "tab-logs":
            tabs.active = "tab-logs"

    def _on_trace_result(self, rule_ref: str | None) -> None:
        if not rule_ref:
            return
        self.query_one("#main-tabs", TabbedContent).active = "tab-policy"
        self.query_one("#policy-view", PolicyView).focus_rule(rule_ref)

    def action_refresh_metadata(self) -> None:
        """Force-refresh the firewall / policy / IP-group cache."""
        status = self.query_one("#status", StatusBar)
        if not self._policy_context:
            status.meta = "policy context off (POLICY_CONTEXT=on or --policy-context to enable)"
            return
        if self._firewall_id is None:
            status.meta = "refresh skipped: no firewall seen yet"
            return
        status.meta = "refreshing metadata…"
        self._load_mgmt(self._firewall_id, force=True)

    def get_system_commands(self, screen: Screen):
        for cmd in super().get_system_commands(screen):
            if cmd.title in ("Maximize", "Minimize"):
                continue
            yield cmd
