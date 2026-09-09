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
from textual.screen import ModalScreen
from textual.widgets import Static

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
_FOOTER_WITH_TRACE = "Enter expand/collapse · p open in Policy tab · a all / focused · Esc close"
_FOOTER_ALONE = "Esc close"


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
    """The action, coloured like the log table's Action column."""
    if not action or action == "-":
        return ""
    safe = escape(action)
    a = action.lower()
    if a in ("deny", "denywiththreat"):
        return f"[red]{safe}[/]"
    if a == "allow":
        return f"[green]{safe}[/]"
    if a == "dnat":
        return f"[yellow]{safe}[/]"
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


def _header_line2(trace: Trace, cache_age: str) -> str:
    if trace.matched_rule is not None:
        icon = "[green]✓[/]"
    elif trace.flow.threat_intel:
        icon = "[magenta]![/]"
    elif not trace.outcome.startswith("default action"):
        icon = "[yellow]?[/]"  # the firewall matched a rule we could not locate (stale cache)
    else:
        icon = "[red]✗[/]"
    line = f"{icon} {escape(trace.outcome)}"
    if cache_age:
        line += f"   [dim]cached policy · {escape(cache_age)}[/]"
    return line


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
    DetailDialog > #dialog > #dialog-header {
        margin-bottom: 1;
    }
    DetailDialog > #dialog > #dialog-footer {
        margin-top: 1;
        color: $text-muted;
    }
    DetailDialog > #dialog > #dialog-body {
        width: 100%;
        height: auto;
    }
    DetailDialog.-with-trace > #dialog > #dialog-body {
        height: 1fr;
    }
    DetailDialog > #dialog > #dialog-body > #detail-pane {
        width: 100%;
        height: auto;
    }
    DetailDialog.-with-trace > #dialog > #dialog-body > #detail-pane {
        width: 52;
        height: 100%;
        overflow-y: auto;
        margin-right: 2;
        border-right: solid $panel;
        padding-right: 1;
    }
    DetailDialog > #dialog > #dialog-body > TracePanel {
        width: 1fr;
        height: 100%;
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

    @property
    def has_trace(self) -> bool:
        return self._trace is not None

    def _field(self, label: str, value: str) -> Static:
        safe = value.replace("[", "\\[")
        if len(value) > self._inline_max:
            return Static(f"[dim]{label.rstrip()}[/]\n  {safe}", markup=True, classes="detail-row")
        return Static(f"[dim]{label.ljust(13)}[/]  {safe}", markup=True, classes="detail-row")

    def _time_field(self, row: FirewallDataRow) -> Static:
        local = escape(_to_local(row.time))
        utc = escape(_utc_short(row.time))
        text = f"[dim]{'Time'.ljust(13)}[/]  {local} local   [dim]{utc} UTC[/]"
        return Static(text, markup=True, classes="detail-row")

    def _ip_groups_field(self, label: str, groups: list[str]) -> Static:
        indent = " " * (13 + 2)
        lines = [f"[dim]{label.ljust(13)}[/]  {escape(groups[0])}"]
        lines.extend(f"{indent}{escape(g)}" for g in groups[1:])
        return Static("\n".join(lines), markup=True, classes="detail-row")

    def _header_text(self) -> Text:
        lines = [_header_line1(self._row)]
        if self._trace is not None:
            lines.append(_header_line2(self._trace, self._cache_age))
        # Rich Text, not Textual markup — see TracePanel's tree labels: a Static
        # with markup=True takes colour names literally instead of the theme's.
        return Text.from_markup("\n".join(lines))

    def _footer_text(self) -> str:
        return _FOOTER_WITH_TRACE if self._trace is not None else _FOOTER_ALONE

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(self._header_text(), id="dialog-header")
            with Horizontal(id="dialog-body"):
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
        elif event.key == "a" and self._trace is not None:
            event.stop()
            self.query_one(TracePanel).toggle_expand_all()
        elif event.key == "p" and self._trace is not None:
            event.stop()
            # open_selected_rule lands with the trace-screen focused-tree work
            # (same contract as toggle_expand_all above); not yet on this branch.
            self.query_one(TracePanel).open_selected_rule()  # type: ignore[attr-defined]
