#!/usr/bin/env python3
"""
az-firewall-watch — Azure Firewall log stream in your terminal.

Connects to an Azure Event Hub and displays incoming firewall logs in a
filterable TUI table. Connection parameters are read from .env in this folder.

Key bindings
  q / ctrl+q  Quit
  ctrl+p      Pause / resume streaming  (or click the status bar)
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
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Select

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


CATEGORY_OPTIONS: list[tuple[str, str]] = [
    ("NetworkRule", "networkrule"),
    ("AppRule", "apprule"),
    ("NATRule", "natrule"),
    ("DnsQuery", "dnsquery"),
    ("DnsProxy", "dnsproxy"),
    ("IDPS", "idps"),
    ("ThreatIntel", "threatintel"),
]

# ── config ────────────────────────────────────────────────────────────────────
def _load_env(path: Path, override: bool = False) -> None:
    """Load a .env file, falling back to latin-1 if the file is not valid UTF-8."""
    try:
        load_dotenv(path, encoding="utf-8", override=override)
    except UnicodeDecodeError:
        load_dotenv(path, encoding="latin-1", override=override)


_load_env(_BASE_DIR / ".env")

# Run the setup wizard automatically if no Event Hub credentials are configured.
# Pass --reconfigure to redo setup even when .env already exists.
_has_conn_str = bool(os.environ.get("EVENT_HUB_CONNECTION_STRING"))
_has_entra = bool(os.environ.get("EVENT_HUB_NAMESPACE") and os.environ.get("EVENT_HUB_NAME"))
if (not _has_conn_str and not _has_entra) or "--reconfigure" in sys.argv:
    from setup.app import run_wizard  # noqa: E402
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
        self._all_rows: list[FirewallDataRow] = []
        self._pending: list[FirewallDataRow] = []
        self._skip_pending: int = 0
        self._paused: bool = False
        self._fw_name_set: bool = False
        self._connecting_active: bool = False
        self._pending_update: tuple[str, str] | None = None
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
        eh_namespace = os.environ.get("EVENT_HUB_NAMESPACE", "")  # fully qualified, e.g. mynamespace.servicebus.windows.net
        eh_name = os.environ.get("EVENT_HUB_NAME", "")
        consumer_group = os.environ.get("EVENT_HUB_CONSUMER_GROUP", "$Default")
        start_pos = os.environ.get("EVENT_HUB_START_POSITION", "latest")
        position = "@latest" if start_pos == "latest" else "@earliest"
        use_entra = bool(eh_namespace and eh_name)

        status = self.query_one("#status", StatusBar)

        if not conn_str and not use_entra:
            status.status = (
                "ERROR: No Event Hub credentials configured — set either "
                "EVENT_HUB_NAMESPACE + EVENT_HUB_NAME (for Entra ID) or "
                "EVENT_HUB_CONNECTION_STRING (for SAS key) in .env"
            )
            return

        # Resolve display values for the connecting dialog.
        if use_entra:
            namespace = eh_namespace
            hub = eh_name
        else:
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
        _credential = None  # track credential for cleanup on error

        while attempt < _MAX_ATTEMPTS:
            self.sub_title = "Live Log Monitor  |  connecting..."
            status.status = "Connecting to Event Hub…"

            try:
                # Build the client — prefer Entra ID when namespace+hub are set.
                if use_entra:
                    from azure.core.pipeline.transport import AsyncioRequestsTransport  # noqa: E402
                    from azure.identity.aio import DefaultAzureCredential  # type: ignore[import]
                    _credential = DefaultAzureCredential(transport=AsyncioRequestsTransport())
                    client = EventHubConsumerClient(
                        fully_qualified_namespace=eh_namespace,
                        eventhub_name=eh_name,
                        consumer_group=consumer_group,
                        credential=_credential,
                        load_balancing_interval=1,
                        retry_total=0,
                    )
                else:
                    _credential = None
                    client = EventHubConsumerClient.from_connection_string(
                        conn_str,
                        consumer_group=consumer_group,
                        load_balancing_interval=1,
                        retry_total=0,
                    )
                try:
                    async with client:
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

                        # Azure Event Hubs silently accepts AMQP receiver links regardless
                        # of permissions (authorization is enforced at message delivery,
                        # not link attach), so an SDK probe cannot detect a missing
                        # Data Receiver role.
                        # Instead we call the ARM Permissions API with the same credential
                        # to check effective data-plane permissions — no Azure CLI needed.
                        if use_entra:
                            status.status = "Verifying data-plane access…"
                            try:
                                import json as _json  # noqa: PLC0415
                                import urllib.request as _urllib_req  # noqa: PLC0415

                                assert _credential is not None
                                _arm_token = (
                                    await _credential.get_token(
                                        "https://management.azure.com/.default"
                                    )
                                ).token
                                _arm_auth = {"Authorization": f"Bearer {_arm_token}"}

                                # 1. Resolve namespace resource ID via Azure Resource Graph.
                                _ns_short = eh_namespace.split(".")[0]
                                _rg_req = _urllib_req.Request(
                                    "https://management.azure.com/providers/"
                                    "Microsoft.ResourceGraph/resources"
                                    "?api-version=2021-03-01",
                                    data=_json.dumps({
                                        "query": (
                                            "Resources"
                                            " | where type =~ 'microsoft.eventhub/namespaces'"
                                            f" | where name =~ '{_ns_short}'"
                                            " | project id | limit 1"
                                        )
                                    }).encode(),
                                    headers={**_arm_auth, "Content-Type": "application/json"},
                                    method="POST",
                                )
                                _loop = asyncio.get_event_loop()
                                _rg_resp = _json.loads(
                                    await _loop.run_in_executor(
                                        None,
                                        lambda: _urllib_req.urlopen(_rg_req, timeout=10).read(),
                                    )
                                )
                                # Resource Graph returns data as a list of objects
                                # (not the legacy {columns, rows} format).
                                _rg_rows = _rg_resp.get("data") or []

                                if _rg_rows:
                                    _ns_id: str = (
                                        _rg_rows[0]["id"]
                                        if isinstance(_rg_rows[0], dict)
                                        else _rg_rows[0][0]
                                    )
                                    # 2. Check effective data-plane permissions.
                                    _perm_req = _urllib_req.Request(
                                        f"https://management.azure.com{_ns_id}"
                                        "/providers/Microsoft.Authorization/permissions"
                                        "?api-version=2022-04-01",
                                        headers=_arm_auth,
                                        method="GET",
                                    )
                                    _data_actions: list[str] = []
                                    for _entry in _json.loads(
                                        await _loop.run_in_executor(
                                            None,
                                            lambda: _urllib_req.urlopen(_perm_req, timeout=10).read(),
                                        )
                                    ).get("value", []):
                                        _data_actions.extend(_entry.get("dataActions", []))
                                    if not any(
                                        # RG/subscription-inherited assignments use
                                        # wildcard form: "Microsoft.EventHub/*/receive/action"
                                        ("eventhub" in _a.lower() and "receive" in _a.lower())
                                        or _a.lower() in ("*", "microsoft.eventhub/*")
                                        for _a in _data_actions
                                    ):
                                        raise PermissionError(
                                            f"Missing 'Azure Event Hubs Data Receiver' "
                                            f"(or 'Data Owner') role on namespace '{_ns_short}'."
                                        )

                            except PermissionError:
                                raise  # propagate → fast-fail to error dialog
                            except Exception:
                                pass  # ARM check unavailable — proceed optimistically

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
                finally:
                    if _credential:
                        await _credential.close()
                        _credential = None

            except asyncio.CancelledError:
                if _splash_shown:
                    self._connecting_active = False
                    self.pop_screen()
                status.status = "Streaming stopped"
                return

            except Exception as exc:
                last_exc = exc
                self._fw_name_set = False  # allow subtitle refresh on next connect

                # Auth / configuration errors will not fix themselves — skip retries.
                if isinstance(exc, PermissionError) or any(
                    kw in str(exc).lower() for kw in _AUTH_KEYWORDS
                ):
                    attempt = _MAX_ATTEMPTS
                    break

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
            is_cfg_error = isinstance(last_exc, PermissionError) or any(
                kw in err_lower for kw in _AUTH_KEYWORDS
            )
            if is_cfg_error:
                if isinstance(last_exc, PermissionError):
                    hint = (
                        "Assign the role in the Azure portal (namespace → Access control (IAM))\n"
                        "or via Azure CLI:\n"
                        "  az role assignment create "
                        "--assignee <your-id> "
                        "--role 'Azure Event Hubs Data Receiver' "
                        "--scope <namespace-resource-id>"
                    )
                elif use_entra:
                    hint = (
                        "Entra ID authentication was rejected.\n"
                        "Ensure your identity has the 'Azure Event Hubs Data Receiver' role\n"
                        "on the Event Hub namespace or entity, then restart the app."
                    )
                else:
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

    # ── table rendering ─────────────────────────────────────────────────────────
    def _refresh_table(self) -> None:
        f = self._get_filters()
        visible = [r for r in self._all_rows if self._matches(r, f)]

        tbl = self.query_one("#log-table", DataTable)
        prev_scroll_y = tbl.scroll_y
        prev_rowid = self._selected_rowid
        single_policy = len(self._seen_policies) <= 1

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

    # ── filtering ───────────────────────────────────────────────────────────────
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

    # ── actions (key bindings) ──────────────────────────────────────────────────
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
        self.query_one("#f-cat", Select).value = Select.BLANK
        self._refresh_table()

    def action_focus_filter(self) -> None:
        self.query_one("#f-src", Input).focus()

    def get_system_commands(self, screen: Screen):  # type: ignore[override]
        for cmd in super().get_system_commands(screen):
            if cmd.title in ("Maximize", "Minimize"):
                continue
            yield cmd


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    FirewallLogApp().run()
