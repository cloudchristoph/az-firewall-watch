"""Row detail dialog: the log entry on the left, its evaluation trace on the right.

The trace column only exists when the app could build one (policy context on and
policy metadata loaded). Without it the dialog is the plain, narrow entry view: a
one-line header, the fields, the 0.6.0 note explaining why there is no trace, and
a footer with only ``Esc close``.
"""
from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Static, TabbedContent, TabPane

from fw_parser import FirewallDataRow, tcp_direction
from helpers import _to_local, _utc_short, format_endpoint

from ..trace import Trace
from .trace_screen import TracePanel

# Values longer than this go on their own line under the label instead of
# wrapping mid-word at the pane edge (long FQDNs, rule definitions). The pane
# is 52 columns beside the trace and 84 on its own, so the threshold follows
# the layout: a flow like ``10.2.0.5:9684 → 142.251.14.102:443`` fits inline
# in the wide dialog and only needs its own line next to the trace.
_INLINE_VALUE_MAX_WITH_TRACE = 34
_INLINE_VALUE_MAX_ALONE = 62

# The columns mean different things per category; the labels say what a row's
# value really is instead of the table's generic column names.
_ACTION_LABEL = {"flowtrace": "Flag", "fatflow": "Rate", "dnsquery": "Response", "dnsfailure": "Result"}
_INFO_LABEL = {"threatintel": "Threat", "dnsfailure": "Error"}
_PROTOCOL_LABEL = {"dnsquery": "Query type"}
_SOURCE_LABEL = {"dnsquery": "Client"}
_DEST_LABEL = {"dnsquery": "Query", "dnsfailure": "FQDN"}
_INFO_HIDDEN = {"flowtrace", "fatflow", "idps"}  # rendered in their own way below
_IDPS_FIELDS = ("Severity", "Signature", "Class", "Description")  # "Class": the Category row names the log category
# Categories whose Source/Destination equal the header's endpoints exactly —
# repeating them in the fields would say the same thing twice.
_DUP_HEADER_ENDPOINTS = {"apprule", "networkrule", "natrule", "threatintel", "idps"}
_FOOTER_WITH_TRACE = "Enter expand/collapse · p open in Policy tab · a all / focused · Shift+↑↓ detail · Esc close"
_FOOTER_ALONE = "Esc close"
# The tabbed layout sits on a terminal under 120 columns, where the full
# footer would wrap and cost the tree a row; same keys, fewer words.
_FOOTER_TABBED = "Enter fold · p Policy tab · a all · Tab fields/trace · Esc close"

# Below this many columns there is no room for the fields pane and the trace
# side by side; they become two tabs instead (see DetailDialog._classify).
_TABBED_BELOW_COLS = 120
# Below this many rows the tree needs the selection detail's space back
# (DetailDialog.-short, see the CSS below).
_SHORT_BELOW_ROWS = 40
# Below this many rows the dialog stops reserving a margin (height: 100%)
# and the selection detail under the tree shrinks to its name lines.
_TINY_BELOW_ROWS = 30
# The dialog's border and padding (see DEFAULT_CSS), taken off the terminal
# width to know how much of a header line fits.
_DIALOG_FRAME_COLS = 6


def _ports_join(address: str, port: str) -> str:
    """Bracketed IPv6, bare IPv4/FQDN — see ``helpers.format_endpoint``."""
    return format_endpoint(address, port)


def _ports(src: str, dst: str) -> str:
    """``47972 → 443`` — one line for both ports, so long FQDNs stay unbroken.

    Empty when the log has no ports (ICMP, DNS rows); a missing side shows as ``-``.
    """
    s = src if src and src != "-" else ""
    d = dst if dst and dst != "-" else ""
    if not s and not d:
        return ""
    return f"{s or '-'} → {d or '-'}"


def _flow_client_server(row: FirewallDataRow) -> tuple[str, str, str]:
    """The connection's client and server endpoints for a FlowTrace/FatFlow row.

    The log's source/destination are the packet's, which for a SYN-ACK (or any
    server-to-client packet) has the server as the source. Returns
    ``(client, server, direction)``; *direction* is empty when it cannot be told.
    """
    flag = row.action if row.category.lower() == "flowtrace" else ""  # FatFlow has a rate there
    direction = tcp_direction(flag, row.srcport, row.targetport)
    src = _ports_join(row.sourceip, row.srcport)
    dst = _ports_join(row.targetip, row.targetport)
    if direction == "server → client":
        return dst, src, direction
    return src, dst, direction


def _action_markup(action: str) -> str:
    """The action, coloured like the log table's Action column.

    Same weights as the trace tree's action tag (see trace_screen._action_tag):
    deny is what a reader must not miss, allow is the common case and stays
    quiet, dnat sits between the two. One row's logged action, not a verdict —
    so this stays independent of trace_screen._ICON.
    """
    if not action or action == "-":
        return ""
    safe = escape(action)
    a = action.lower()
    if a in ("deny", "denywiththreat"):
        return f"[bold red]{safe}[/]"
    if a == "allow":
        return f"[dim green]{safe}[/]"
    if a == "dnat":
        return f"[bold yellow]{safe}[/]"
    if a == "alert":
        return f"[magenta]{safe}[/]"
    return safe


def _header_endpoints(row: FirewallDataRow) -> tuple[str, str]:
    """The header's ``source → destination`` text for *row*'s category."""
    cat = row.category.lower()
    if cat in ("flowtrace", "fatflow"):
        src, dst, _ = _flow_client_server(row)
        return src, dst
    if cat == "natrule" and row.nat_dst_ip:
        # The client hit the public IP; that is what the header (and the rule
        # evaluation) cares about, not the translated target.
        return _ports_join(row.sourceip, row.srcport), _ports_join(row.nat_dst_ip, row.nat_dst_port)
    return _ports_join(row.sourceip, row.srcport), _ports_join(row.targetip, row.targetport)


def _header_line1(row: FirewallDataRow) -> str:
    src, dst = _header_endpoints(row)
    endpoint = f"[b]{escape(src)} → {escape(dst)}[/b]"
    protocol = escape(row.protocol) if row.protocol and row.protocol != "-" else ""
    action = _action_markup(row.action)
    tail = "   ".join(part for part in (protocol, action) if part)
    line = f"{endpoint}   {tail}" if tail else endpoint
    return f"{line}   [dim]{escape(row.category)}[/]"


def _compact_outcome(outcome: str) -> str:
    """The rule name alone, dropping the group and collection that ``outcome``
    otherwise spells out (``"Allow by rcg-net » rc-web » allow-web"`` becomes
    ``"Allow · allow-web"``). Outcomes with nothing to shorten (default deny,
    threat intel) come back unchanged."""
    action, sep, rest = outcome.partition(" by ")
    if not sep or "»" not in rest:
        return outcome
    rule_name = rest.rsplit("»", 1)[-1].strip()
    return f"{action} · {rule_name}"


def _header_line2(trace: Trace, cache_age: str, width: int | None = None) -> str:
    """The outcome line. With ``width`` the line is shortened until it fits
    on one row: first the group and collection go (the selection detail
    under the tree still names them), then the cache age."""
    if trace.matched_rule is not None:
        icon = "[green]✓[/]"
    elif trace.flow.threat_intel:
        icon = "[magenta]![/]"
    elif not trace.outcome.startswith("default action"):
        icon = "[yellow]?[/]"  # the firewall matched a rule we could not locate (stale cache)
    else:
        icon = "[red]✗[/]"
    age = f"   [dim]cached policy · {escape(cache_age)}[/]" if cache_age else ""
    candidates = [
        f"{icon} {escape(trace.outcome)}{age}",
        f"{icon} {escape(_compact_outcome(trace.outcome))}{age}",
        f"{icon} {escape(_compact_outcome(trace.outcome))}",
    ]
    if width is None:
        return candidates[0]
    for line in candidates:
        if Text.from_markup(line).cell_len <= width:
            return line
    return candidates[-1]


class DetailDialog(ModalScreen[str | None]):
    """Opened with Enter or double-click on a log row.

    Dismisses with a rule ref (``policy|rcg|rc|rule``, the key the Policy tab
    understands) when a rule is chosen in the trace, else ``None``.
    """

    DEFAULT_CSS = """
    DetailDialog {
        align: center middle;
    }
    DetailDialog > #dialog {
        width: 84;
        height: auto;
        max-height: 92%;
        background: $surface;
        border: round $panel;
        padding: 1 2;
    }
    DetailDialog.-with-trace > #dialog {
        width: 96%;
        height: 92%;
    }
    /* A terminal short on rows gets no 92% margin at all — see -tiny below,
       set from fewer than _TINY_BELOW_ROWS rows. Declared after -with-trace
       so it wins the height tie (same selector specificity, later wins). */
    DetailDialog.-tiny > #dialog {
        height: 100%;
    }
    DetailDialog > #dialog > #dialog-header {
        margin-bottom: 1;
    }
    DetailDialog > #dialog > #dialog-footer {
        margin-top: 1;
        color: $text-muted;
    }
    DetailDialog #dialog-body {
        width: 100%;
        height: auto;
    }
    DetailDialog.-with-trace #dialog-body {
        height: 1fr;
    }
    /* Every pane scrolls on its own: the fields pane never grows past the
       space it is given, in any layout (plain, side by side, or a Fields tab). */
    DetailDialog #detail-pane {
        width: 100%;
        height: auto;
        overflow-y: auto;
    }
    DetailDialog.-with-trace #detail-pane {
        width: 52;
        height: 100%;
        margin-right: 2;
        border-right: solid $panel;
        padding-right: 1;
    }
    /* Narrow with a trace: fields and trace are tabs, not columns — the
       fields pane takes the tab's full width instead of a fixed 52. */
    DetailDialog.-tabbed #detail-pane {
        width: 100%;
        margin-right: 0;
        border-right: none;
        padding-right: 0;
    }
    DetailDialog #dialog-body TracePanel {
        width: 1fr;
        height: 100%;
    }
    /* "1fr" only means something beside a sibling in a Horizontal; inside a
       tab pane TracePanel is the pane's only child and wants the full width. */
    DetailDialog.-tabbed #dialog-body TracePanel {
        width: 100%;
    }
    DetailDialog.-tabbed #dialog-body TabbedContent {
        width: 100%;
        height: 100%;
    }
    DetailDialog.-tabbed #dialog-body TabbedContent ContentSwitcher {
        height: 1fr;
    }
    DetailDialog.-tabbed #dialog-body TabPane {
        height: 100%;
        padding: 0;
    }
    /* Fewer than _SHORT_BELOW_ROWS rows: give the tree the room back from the
       selection detail below it. More specific than TracePanel's own
       "max-height: 12" (DetailDialog.-short + descendant beats a bare type
       selector), so this works without editing trace_screen.py. */
    DetailDialog.-short TracePanel > #trace-detail {
        max-height: 5;
    }
    /* Fewer than _TINY_BELOW_ROWS rows: the detail keeps its name lines and
       the first check; the rest is one scroll away, the tree gets the rows. */
    DetailDialog.-tiny TracePanel > #trace-detail {
        max-height: 3;
    }
    DetailDialog #trace-note {
        margin-top: 1;
    }
    DetailDialog .detail-row {
        height: auto;
    }
    DetailDialog .group-caption {
        margin-top: 1;
    }
    """

    def __init__(self, row: FirewallDataRow, *, enrichment: dict | None = None,
                 trace: Trace | None = None, trace_note: str = "", cache_age: str = "") -> None:
        super().__init__()
        self._row = row
        self._enrichment: dict = enrichment or {}
        self._trace = trace
        # Why there is no trace beside the fields; shown in the dialog itself,
        # because it is a property of this row, not of the application state.
        self._trace_note = trace_note
        self._cache_age = cache_age
        self._inline_max = _INLINE_VALUE_MAX_WITH_TRACE if trace is not None else _INLINE_VALUE_MAX_ALONE
        if trace is not None:
            self.add_class("-with-trace")
        # Set for real by _classify(), called from compose() once the
        # terminal size is known; the default here only matters before that.
        self._tabbed_mode = False

    @property
    def has_trace(self) -> bool:
        return self._trace is not None

    def _field(self, label: str, value: str) -> Static:
        safe = value.replace("[", "\\[")
        if len(value) > self._inline_max:
            return Static(f"[dim]{label.rstrip()}[/]\n  {safe}", markup=True, classes="detail-row")
        return Static(f"[dim]{label.ljust(13)}[/]  {safe}", markup=True, classes="detail-row")

    def _time_field(self, row: FirewallDataRow) -> Static:
        """Local time first, UTC dim beside it; the UTC date only when it differs
        from the local one, so the line fits the pane beside the trace."""
        local = _to_local(row.time)
        utc = _utc_short(row.time)                       # 2026-09-09T16:41:46Z
        utc_date, _, utc_clock = utc.partition("T")
        utc_short = utc_clock if local.startswith(utc_date) else utc
        text = f"[dim]{'Time'.ljust(13)}[/]  {escape(local)}   [dim]{escape(utc_short)} UTC[/]"
        return Static(text, markup=True, classes="detail-row")

    def _ip_groups_field(self, label: str, groups: list[str]) -> Static:
        indent = " " * (13 + 2)
        lines = [f"[dim]{label.ljust(13)}[/]  {escape(groups[0])}"]
        lines.extend(f"{indent}{escape(g)}" for g in groups[1:])
        return Static("\n".join(lines), markup=True, classes="detail-row")

    def _header_text(self) -> Text:
        lines = [_header_line1(self._row)]
        if self._trace is not None:
            width = self.app.size.width
            if self.has_class("-with-trace"):
                width = int(width * 0.96)
            lines.append(_header_line2(self._trace, self._cache_age, width - _DIALOG_FRAME_COLS))
        # Rich Text, not Textual markup — see TracePanel's tree labels: a Static
        # with markup=True takes colour names literally instead of the theme's.
        return Text.from_markup("\n".join(lines))

    def _footer_text(self) -> str:
        if self._trace is None:
            return _FOOTER_ALONE
        return _FOOTER_TABBED if self._tabbed_mode else _FOOTER_WITH_TRACE

    def _classify(self) -> bool:
        """Whether the terminal is too narrow for two columns. Also sets the
        size-dependent CSS classes (``-tabbed``, ``-short``, ``-tiny``);
        ``-with-trace`` is set once in ``__init__`` since it never depends
        on size.
        """
        size = self.app.size
        cols, rows = size.width, size.height
        tabbed = self._trace is not None and cols < _TABBED_BELOW_COLS
        self.set_class(tabbed, "-tabbed")
        self.set_class(rows < _SHORT_BELOW_ROWS, "-short")
        self.set_class(rows < _TINY_BELOW_ROWS, "-tiny")
        return tabbed

    def compose(self) -> ComposeResult:
        self._tabbed_mode = self._classify()
        with Vertical(id="dialog"):
            yield Static(self._header_text(), id="dialog-header")
            with Horizontal(id="dialog-body"):
                if self._tabbed_mode:
                    # Narrow, with a trace: one column, switched with Tab
                    # instead of two side by side — see on_key. _classify()
                    # only sets -tabbed when there is a trace to show.
                    trace = self._trace
                    assert trace is not None
                    with TabbedContent(initial="tab-trace"):
                        with TabPane("Fields", id="tab-fields"):
                            with Vertical(id="detail-pane"):
                                yield from self._entry_fields()
                        with TabPane("Policy trace", id="tab-trace"):
                            yield TracePanel(trace, id="trace-panel")
                else:
                    with Vertical(id="detail-pane"):
                        yield from self._entry_fields()
                        if self._trace is None and self._trace_note:
                            title, _, why = self._trace_note.partition("\n")
                            yield Static(f"[b]{escape(title)}[/b]\n[dim]{escape(why)}[/]", id="trace-note",
                                         classes="detail-row", markup=True)
                    if self._trace is not None:
                        yield TracePanel(self._trace, id="trace-panel")
            yield Static(f"[dim]{self._footer_text()}[/]", id="dialog-footer", markup=True)

    def _entry_fields(self) -> ComposeResult:
        """The row's own fields, grouped; whatever the header already shows
        (endpoints, protocol, action, category) is not repeated."""
        row = self._row
        with_trace = self._trace is not None
        cat = row.category.lower()

        yield Static("[dim]Connection[/]", classes="group-caption")
        yield self._time_field(row)
        if cat == "dnsquery" and row.protocol and row.protocol != "-":
            yield self._field(_PROTOCOL_LABEL[cat].ljust(13), row.protocol)

        if cat in ("flowtrace", "fatflow"):
            yield from self._flowtrace_fields(row)
        elif cat == "natrule" and row.nat_dst_ip:
            # The header already shows what the client hit and what it was
            # turned into is the interesting bit left to say here.
            ports = _ports(row.srcport, row.nat_dst_port)
            if ports:
                yield self._field("Ports        ", ports)
            yield self._field("Translated   ", _ports_join(row.targetip, row.targetport))
        else:
            if cat not in _DUP_HEADER_ENDPOINTS:
                yield self._field(_SOURCE_LABEL.get(cat, "Source").ljust(13), row.sourceip)
                yield self._field(_DEST_LABEL.get(cat, "Destination").ljust(13), row.targetip)
            ports = _ports(row.srcport, row.targetport)
            if ports:
                yield self._field("Ports        ", ports)

        if cat in _ACTION_LABEL:
            yield self._field(_ACTION_LABEL[cat].ljust(13), row.action)

        if row.moreinfo and cat not in _INFO_HIDDEN:
            yield self._field(_INFO_LABEL.get(cat, "More Info").ljust(13), row.moreinfo)
        if cat == "idps" and row.moreinfo:
            # parser joins "SEV:n · id · category · description"
            for label, value in zip(_IDPS_FIELDS, row.moreinfo.split(" · "), strict=False):
                yield self._field(label.ljust(13), value[4:] if label == "Severity" and value.startswith("SEV:") else value)
        if not any([row.fw_policy, row.rule_collection_group, row.rule_collection, row.rule_name]) and row.policy:
            yield self._field("Policy / Info", row.policy)

        inspection: list[Static] = []
        if cat == "apprule":
            if row.explicit_proxy:
                inspection.append(self._field("Expl. proxy  ", row.explicit_proxy))
            if row.tls_inspected:
                inspection.append(self._field("TLS inspected", row.tls_inspected))
        if inspection:
            yield Static("[dim]Inspection[/]", classes="group-caption")
            yield from inspection

        enr = self._enrichment
        groups: list[Static] = []
        if enr.get("source_fw_instance"):
            groups.append(self._field("Source (FW)  ", enr["source_fw_instance"]))
        if enr.get("dest_fw_instance"):
            groups.append(self._field("Dest (FW)    ", enr["dest_fw_instance"]))
        if enr.get("source_ip_groups"):
            groups.append(self._ip_groups_field("Src IP groups", enr["source_ip_groups"]))
        if enr.get("dest_ip_groups"):
            groups.append(self._ip_groups_field("Dst IP groups", enr["dest_ip_groups"]))
        if groups:
            yield Static("[dim]Groups[/]", classes="group-caption")
            yield from groups

        if not with_trace:
            rule: list[Static] = []
            if row.fw_policy:
                rule.append(self._field("Policy       ", row.fw_policy))
            if row.rule_collection_group:
                rule.append(self._field("RCG          ", row.rule_collection_group))
            if row.rule_collection:
                rule.append(self._field("Rule Coll.   ", row.rule_collection))
            if row.rule_name:
                rule.append(self._field("Rule         ", row.rule_name))
            if enr.get("rule_policy"):
                rule.append(self._field("Rule Policy  ", enr["rule_policy"]))
            if enr.get("rule_priority"):
                rule.append(self._field("Rule Priority", enr["rule_priority"]))
            if enr.get("rule_action"):
                rule.append(self._field("Rule Action  ", enr["rule_action"]))
            if rule:
                yield Static("[dim]Rule[/]", classes="group-caption")
                yield from rule

    def _flowtrace_fields(self, row: FirewallDataRow) -> ComposeResult:
        client, server, direction = _flow_client_server(row)
        yield self._field("Flow         ", f"{client} → {server}")
        if direction:
            yield self._field("Packet       ", f"{row.sourceip} → {row.targetip}  ({direction})")
        else:
            yield self._field("Packet       ", f"{row.sourceip} → {row.targetip}  (direction unknown)")

    def on_mount(self) -> None:
        if self._trace is None:
            pane = self.query_one("#detail-pane")
            pane.can_focus = True
            pane.focus()
        elif self._tabbed_mode:
            # Not focused on open — the trace tab (and its tree) is, so the
            # logged rule is the first thing seen — but Tab needs somewhere
            # to land the focus once the reader switches to Fields.
            self.query_one("#detail-pane").can_focus = True

    def on_resize(self, event: events.Resize) -> None:
        """Re-decide the layout as the terminal is resized.

        Toggling side-by-side vs. tabbed changes the DOM (a TabbedContent
        appears or disappears), so that case rebuilds the dialog; recompose()
        mounts a fresh TracePanel, which selects the logged rule again. The
        size-only cases (-short, -tiny, the header's length) are CSS and
        text updates and need no rebuild.
        """
        was_tabbed = self._tabbed_mode
        self._tabbed_mode = self._classify()
        if self._tabbed_mode != was_tabbed:
            self.call_after_refresh(self.recompose)
        elif self.is_mounted:
            try:
                self.query_one("#dialog-header", Static).update(self._header_text())
                self.query_one("#dialog-footer", Static).update(f"[dim]{self._footer_text()}[/]")
            except NoMatches:
                pass

    # ── interaction ─────────────────────────────────────────────────────────
    def on_trace_panel_rule_chosen(self, event: TracePanel.RuleChosen) -> None:
        event.stop()
        self.dismiss(event.rule_ref)

    def on_key(self, event: events.Key) -> None:
        if event.key in ("q", "escape"):
            # Stop the key here: once the modal is gone the event would bubble
            # on to the App and trigger its own q / escape bindings.
            event.stop()
            self.dismiss(None)
        elif self._tabbed_mode and event.key in ("tab", "shift+tab"):
            # Only two tabs, so either key just flips between them; Textual's
            # own Tab/Shift+Tab (focus_next/focus_previous, bound on Screen)
            # would otherwise move focus instead of the tab strip's selection.
            event.stop()
            self._toggle_tab()
        elif event.key == "a" and self._trace is not None:
            event.stop()
            self.query_one(TracePanel).toggle_expand_all()
        elif event.key == "p" and self._trace is not None:
            event.stop()
            self.query_one(TracePanel).open_selected_rule()
        elif event.key in ("shift+down", "shift+up") and self._trace is not None:
            # The selection detail under the tree is capped in height and
            # scrolls, but focus stays on the tree; these two keys scroll it
            # without moving the focus, for readers without a mouse wheel.
            event.stop()
            self.query_one(TracePanel).scroll_detail(1 if event.key == "shift+down" else -1)

    def _toggle_tab(self) -> None:
        tabs = self.query_one(TabbedContent)
        if tabs.active == "tab-trace":
            tabs.active = "tab-fields"
            self.query_one("#detail-pane").focus()
        else:
            tabs.active = "tab-trace"
            self.query_one(TracePanel).focus_tree()
