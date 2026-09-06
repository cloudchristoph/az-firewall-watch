"""Top-level Textual app for az-firewall-watch."""
from __future__ import annotations

import re

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

from dialogs import DetailDialog, StatusBar
from fw_parser import FirewallDataRow
from helpers import _category_text, _highlight, _to_local

from .azure_resources import FirewallInfo, FirewallPolicyInfo, IpGroupInfo
from .config import CATEGORY_OPTIONS, MAX_ROWS, VERSION
from .management import load_management_data
from .streaming import run_stream
from .updates import check_for_update
from .views import FirewallView, IpGroupsView, PolicyView


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
        Binding("escape", "clear_filters", "Clear Filters", priority=True),
        Binding("f", "focus_filter", "Filter"),
        Binding("ctrl+s", "screenshot", "Screenshot", show=True),
        Binding("ctrl+r", "refresh_metadata", "Refresh metadata", show=True),
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
        # Management-plane enrichment state
        self._firewall_id: str | None = None
        self._fw_info: FirewallInfo | None = None
        self._policy_info: FirewallPolicyInfo | None = None
        self._ip_groups: dict[str, IpGroupInfo] = {}
        self._subnet_cidrs: list[str] = []
        self._mgmt_loaded: bool = False

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
        with TabbedContent(id="main-tabs", initial="tab-logs"):
            with TabPane("Logs", id="tab-logs"):
                yield DataTable(zebra_stripes=True, cursor_type="row", id="log-table")
            with TabPane("Firewall", id="tab-firewall"):
                yield FirewallView(id="firewall-view")
            with TabPane("Policy", id="tab-policy"):
                yield PolicyView(id="policy-view")
            with TabPane("IP Groups", id="tab-ipgroups"):
                yield IpGroupsView(id="ipgroups-view")
        yield StatusBar(id="status")
        yield Footer()

    def on_mount(self) -> None:
        tbl = self.query_one("#log-table", DataTable)
        tbl.add_columns(
            "Time (Local)", "Category", "Proto",
            "Source", "Dest / FQDN", "Port",
            "Action", "Rule Info",
        )
        # Initial state: Logs tab is active, filters must be visible.
        self.query_one("#filter-bar", Horizontal).display = True
        self._refresh_metadata_views()
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

    @work(exclusive=True, group="mgmt")
    async def _load_mgmt(self, firewall_id: str, *, force: bool = False) -> None:
        """Background fetch of firewall / policy / IP-groups metadata."""
        snap = await load_management_data(firewall_id, force=force)
        if snap is None:
            self.query_one("#status", StatusBar).status = (
                "Live  (metadata unavailable \u2014 check ARM access)"
            )
            return
        self._fw_info = snap.firewall
        self._policy_info = snap.policy
        self._ip_groups = snap.ip_groups
        self._subnet_cidrs = snap.subnet_cidrs
        self._mgmt_loaded = True
        self._apply_mgmt_data()
        age_min = int(snap.age_seconds() // 60)
        tier = snap.policy.sku_tier if snap.policy else "?"
        self.query_one("#status", StatusBar).status = (
            f"Live  (policy {tier}, {len(snap.ip_groups)} IP groups, "
            f"cache age {age_min}m)"
        )
        self._refresh_metadata_views()
        self._refresh_table()

    def _apply_mgmt_data(self) -> None:
        """React to newly loaded management data: SKU-gated category dropdown."""
        if self._policy_info is None:
            return
        tier = (self._policy_info.sku_tier or "").lower()
        if tier in ("standard", "basic"):
            hidden = {"threatintel", "idps"}
            opts = [(label, value) for label, value in CATEGORY_OPTIONS
                    if value not in hidden]
        else:
            opts = list(CATEGORY_OPTIONS)
        select = self.query_one("#f-cat", Select)
        current = select.value
        try:
            select.set_options(opts)
            if isinstance(current, str) and any(v == current for _, v in opts):
                select.value = current
        except Exception:
            pass

    def _refresh_metadata_views(self) -> None:
        """Refresh Firewall / Policy / IP Groups tabs from current state."""
        self.query_one("#firewall-view", FirewallView).render_data(
            self._fw_info, self._policy_info, self._subnet_cidrs
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
        for g in self._policy_info.rule_collection_groups:
            for rc in g.rule_collections:
                for r in rc.rules:
                    for gid in r.source_ip_groups + r.destination_ip_groups:
                        out[gid] = out.get(gid, 0) + 1
        return out

    def request_mgmt_load(self, firewall_id: str) -> None:
        """Called from streaming.on_event when we first see a resourceId."""
        if self._firewall_id is None:
            self._firewall_id = firewall_id
            self._load_mgmt(firewall_id)

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
            merged = batch + self._all_rows
            merged.sort(key=lambda r: r.time, reverse=True)
            self._all_rows = merged[:MAX_ROWS]

        status = self.query_one("#status", StatusBar)
        status.total += len(batch)
        status.skipped += skips

        if batch:
            self._refresh_table()

    # ── table rendering ────────────────────────────────────────────────────────
    def _refresh_table(self) -> None:
        f = self._get_filters()
        visible = [r for r in self._all_rows if self._matches(r, f)]
        status = self.query_one("#status", StatusBar)
        filtered = any(f.values())
        status.visible_count = len(visible) if filtered else -1

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
                info_text = self._info_text(info)
                src_display = self._format_ip(row.sourceip)
                dst_display = self._format_ip(row.targetip)
                tbl.add_row(
                    _to_local(row.time),
                    _category_text(row.category),
                    _highlight(row.protocol, f["proto"]),
                    self._source_text(src_display, row.srcport, f["src"]),
                    _highlight(dst_display, f["dst"]),
                    row.targetport,
                    action_text,
                    info_text,
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

    def _format_ip(self, ip: str) -> str:
        """Return ``AzFw.N`` for IPs inside the firewall subnet, else the IP."""
        if not self._subnet_cidrs or not ip or ip == "-":
            return ip
        from .enrichment import resolve_fw_instance
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
        tabs = self.query_one("#main-tabs", TabbedContent)
        return tabs.active == "tab-logs"

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
        if not self._is_logs_tab_active():
            return
        self._refresh_table()

    @on(Select.Changed, "#f-cat")
    def on_category_changed(self, event: Select.Changed) -> None:
        if not self._is_logs_tab_active():
            return
        # If the user explicitly picks DnsQuery, disable the hide-DNS toggle so
        # they actually see those rows.
        if isinstance(event.value, str) and event.value == "dnsquery":
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
        self.query_one("#filter-bar", Horizontal).display = logs_active
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
        for row in self._all_rows:
            if row.rowid == rowid:
                enrichment = self._compute_enrichment(row)
                self.push_screen(DetailDialog(row, enrichment=enrichment))
                return

    def _compute_enrichment(self, row: FirewallDataRow) -> dict:
        """Build the optional enrichment payload for DetailDialog."""
        if not self._mgmt_loaded:
            return {}
        from .enrichment import find_matching_ip_groups, find_rule, resolve_fw_instance
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
            out["policy_sku_tier"] = self._policy_info.sku_tier
            match = find_rule(
                row.category, row.sourceip, row.targetip,
                row.moreinfo if row.category.lower() == "apprule" else "",
                row.targetport, self._policy_info, self._ip_groups,
            )
            if match is not None:
                rule, grp, rc = match
                out["rule_priority"] = f"RCG:{grp.priority} \u00bb RC:{rc.priority}"
                out["rule_action"] = rc.action
        return out

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
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "tab-logs":
            tabs.active = "tab-logs"

    def action_refresh_metadata(self) -> None:
        """Force-refresh the firewall / policy / IP-group cache."""
        if self._firewall_id is None:
            self.query_one("#status", StatusBar).status = (
                "Refresh skipped \u2014 no firewall resource ID seen yet"
            )
            return
        self.query_one("#status", StatusBar).status = "Refreshing metadata\u2026"
        self._load_mgmt(self._firewall_id, force=True)

    def get_system_commands(self, screen: Screen):  # type: ignore[override]
        for cmd in super().get_system_commands(screen):
            if cmd.title in ("Maximize", "Minimize"):
                continue
            yield cmd
