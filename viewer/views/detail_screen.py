"""Row detail dialog: the log entry on the left, its evaluation trace on the right.

The trace column only exists when the app could build one (policy context on and
policy metadata loaded). Without it the dialog is the plain, narrow entry view.
"""
from __future__ import annotations

from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from fw_parser import FirewallDataRow
from helpers import _to_local

from ..trace import Trace
from .trace_screen import TracePanel


def _endpoint(address: str, port: str) -> str:
    """``ip:port`` — without the port when the log has none (ICMP, DNS rows)."""
    return address if not port or port == "-" else f"{address}:{port}"


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
        border: thick $primary;
        padding: 1 2;
    }
    DetailDialog.-with-trace > #dialog {
        width: 96%;
        height: 92%;
    }
    DetailDialog > #dialog > #detail-pane {
        width: 100%;
        height: auto;
    }
    DetailDialog.-with-trace > #dialog > #detail-pane {
        width: 52;
        height: 100%;
        overflow-y: auto;
        margin-right: 2;
        border-right: solid $panel;
        padding-right: 1;
    }
    DetailDialog > #dialog > TracePanel {
        width: 1fr;
        height: 100%;
    }
    DetailDialog #title {
        text-style: bold;
        margin-bottom: 1;
    }
    DetailDialog .detail-row {
        height: auto;
    }
    DetailDialog #detail-pane > Button {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, row: FirewallDataRow, *, enrichment: dict | None = None,
                 trace: Trace | None = None) -> None:
        super().__init__()
        self._row = row
        self._enrichment: dict = enrichment or {}
        self._trace = trace
        if trace is not None:
            self.add_class("-with-trace")

    @property
    def has_trace(self) -> bool:
        return self._trace is not None

    @staticmethod
    def _field(label: str, value: str) -> Static:
        safe = value.replace("[", "\\[")
        return Static(f"[dim]{label.ljust(13)}[/]  {safe}", markup=True, classes="detail-row")

    def compose(self) -> ComposeResult:
        with Horizontal(id="dialog"):
            with Vertical(id="detail-pane"):
                yield from self._entry_fields()
                yield Button("Close  (Esc)", variant="primary", id="btn-close")
            if self._trace is not None:
                yield TracePanel(self._trace, id="trace-panel")

    def _entry_fields(self) -> ComposeResult:
        """The row's own fields; with a trace beside them, whatever the trace
        already shows (policy path, priorities, action, SKU) is left out."""
        row = self._row
        with_trace = self._trace is not None
        yield Static(f"Log Entry — {row.category}", id="title")

        yield self._field("Time (UTC)   ", row.time)
        yield self._field("Time (Local) ", _to_local(row.time))
        yield self._field("Category     ", row.category)
        yield self._field("Protocol     ", row.protocol)
        yield self._field("Source       ", _endpoint(row.sourceip, row.srcport))
        yield self._field("Destination  ", _endpoint(row.targetip, row.targetport))
        yield self._field("Action       ", row.action)

        if row.fw_policy and not with_trace:
            yield self._field("Policy       ", row.fw_policy)
        if row.rule_collection_group and not with_trace:
            yield self._field("RCG          ", row.rule_collection_group)
        if row.rule_collection and not with_trace:
            yield self._field("Rule Coll.   ", row.rule_collection)
        if row.rule_name and not with_trace:
            yield self._field("Rule         ", row.rule_name)
        if not any([row.fw_policy, row.rule_collection_group, row.rule_collection, row.rule_name]) and row.policy:
            yield self._field("Policy / Info", row.policy)
        if row.moreinfo:
            yield self._field("More Info    ", row.moreinfo)

        enr = self._enrichment
        if enr:
            yield Static("")  # blank spacer
            if enr.get("source_fw_instance"):
                yield self._field("Source (FW)  ", enr["source_fw_instance"])
            if enr.get("dest_fw_instance"):
                yield self._field("Dest   (FW)  ", enr["dest_fw_instance"])
            if enr.get("source_ip_groups"):
                yield self._field("Src IP Groups", ", ".join(enr["source_ip_groups"]))
            if enr.get("dest_ip_groups"):
                yield self._field("Dst IP Groups", ", ".join(enr["dest_ip_groups"]))
            if enr.get("rule_policy") and not with_trace:
                yield self._field("Rule Policy  ", enr["rule_policy"])
            if enr.get("rule_priority") and not with_trace:
                yield self._field("Rule Priority", enr["rule_priority"])
            if enr.get("rule_action") and not with_trace:
                yield self._field("Rule Action  ", enr["rule_action"])
            if enr.get("rule_definition"):
                yield self._field("Rule Def.    ", enr["rule_definition"])  # the tree shows checks, not the whole rule
            if enr.get("policy_sku_tier") and not with_trace:
                yield self._field("Policy SKU   ", enr["policy_sku_tier"])

    def on_mount(self) -> None:
        if self._trace is None:
            self.query_one("#btn-close", Button).focus()

    # ── interaction ─────────────────────────────────────────────────────────
    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss(None)

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
