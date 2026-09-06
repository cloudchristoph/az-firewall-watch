"""IP Groups metadata tab view."""
from __future__ import annotations

from rich.markup import escape
from textual import events
from textual.containers import Horizontal
from textual.app import ComposeResult
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static

from ..azure_resources import FirewallPolicyInfo, IpGroupInfo


class IpGroupDetailDialog(ModalScreen[None]):
    """Shows all entries of one IP Group."""

    DEFAULT_CSS = """
    IpGroupDetailDialog {
        align: center middle;
    }
    IpGroupDetailDialog > #dialog {
        width: 90;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    IpGroupDetailDialog > #dialog > #items {
        max-height: 22;
        overflow-y: auto;
        margin-bottom: 1;
    }
    IpGroupDetailDialog > #dialog > Button {
        width: 100%;
    }
    """

    def __init__(self, group: IpGroupInfo) -> None:
        super().__init__()
        self._group = group

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Static(f"[b]{escape(self._group.name)}[/b] ({len(self._group.ip_addresses)} entries)", markup=True)
            items = "\n".join(self._group.ip_addresses) if self._group.ip_addresses else "(empty)"
            yield Static(escape(items), id="items", markup=True)
            yield Button("Close", variant="primary", id="btn-close")

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("escape", "q"):
            # Stop the key here, otherwise it bubbles on to the app's own
            # q / escape bindings once the modal is gone.
            event.stop()
            self.dismiss()


class IpGroupsView(Static):
    """Tabular overview of IP Groups and usage counts."""

    class JumpToPolicyRule(Message):
        """Request parent app to switch to Policy tab and focus one rule."""

        def __init__(self, rule_ref: str) -> None:
            super().__init__()
            self.rule_ref = rule_ref

    DEFAULT_CSS = """
    IpGroupsView {
        height: 1fr;
        padding: 1;
    }
    IpGroupsView > Horizontal {
        height: 1fr;
    }
    IpGroupsView #ipg-table {
        width: 1fr;
        min-width: 48;
    }
    IpGroupsView #ipg-right {
        width: 1fr;
        min-width: 60;
        border: round $panel;
        padding: 1;
    }
    IpGroupsView #ipg-details {
        height: auto;
        margin-bottom: 1;
        max-height: 11;
        overflow-y: auto;
    }
    IpGroupsView #ipg-rules {
        height: 1fr;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._groups: dict[str, IpGroupInfo] = {}
        self._policy: FirewallPolicyInfo | None = None
        self._rule_index: dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield DataTable(zebra_stripes=True, cursor_type="row", id="ipg-table")
            with Static(id="ipg-right"):
                yield Static("Select an IP Group to see details.", id="ipg-details", markup=True)
                yield DataTable(zebra_stripes=True, cursor_type="row", id="ipg-rules")

    def on_mount(self) -> None:
        t = self.query_one("#ipg-table", DataTable)
        t.add_columns("Name", "Location", "Entries", "Used by")
        r = self.query_one("#ipg-rules", DataTable)
        r.add_columns("RCG", "Collection", "Rule", "Dir")

    def render_data(
        self,
        groups: dict[str, IpGroupInfo],
        usage_by_id: dict[str, int],
        policy: FirewallPolicyInfo | None,
    ) -> None:
        self._groups = groups
        self._policy = policy
        self._rule_index.clear()
        t = self.query_one("#ipg-table", DataTable)
        rules = self.query_one("#ipg-rules", DataTable)
        details = self.query_one("#ipg-details", Static)
        t.clear()
        rules.clear()
        details.update("Select an IP Group to see details.")
        if not groups:
            t.add_row("No IP groups loaded", "-", "-", "-", key="__empty__")
            return
        for gid, g in sorted(groups.items(), key=lambda it: it[1].name.lower()):
            t.add_row(
                g.name,
                g.location or "-",
                str(len(g.ip_addresses)),
                str(usage_by_id.get(gid, 0)),
                key=gid,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "ipg-rules":
            key = event.row_key.value if event.row_key else None
            if isinstance(key, str) and key in self._rule_index:
                self.post_message(self.JumpToPolicyRule(rule_ref=key))
            return

        if event.data_table.id != "ipg-table":
            return

        key = event.row_key.value if event.row_key else None
        if not isinstance(key, str) or key == "__empty__":
            return
        group = self._groups.get(key)
        if group is None:
            return

        details = self.query_one("#ipg-details", Static)
        values = "\n".join(group.ip_addresses[:20]) if group.ip_addresses else "(empty)"
        if len(group.ip_addresses) > 20:
            values += "\n…"
        details.update("\n".join([
            f"[b]{escape(group.name)}[/b]",
            "",
            f"[dim]Location[/]    {escape(group.location) or '-'}",
            f"[dim]Entries[/]     {len(group.ip_addresses)}",
            "",
            "[dim]Values[/]",
            escape(values),
        ]))

        self._render_related_rules(group_id=key)

    def _render_related_rules(self, group_id: str) -> None:
        table = self.query_one("#ipg-rules", DataTable)
        table.clear()
        self._rule_index.clear()

        if self._policy is None:
            table.add_row("-", "-", "No policy loaded", "-", key="__empty_rules__")
            return

        # includes inherited (parent) policy groups, in evaluation order
        for _policy_name, g in self._policy.all_groups():
            for rc in sorted(g.rule_collections, key=lambda x: x.priority):
                for r in rc.rules:
                    directions: list[str] = []
                    if group_id in r.source_ip_groups:
                        directions.append("source")
                    if group_id in r.destination_ip_groups:
                        directions.append("target")
                    if not directions:
                        continue

                    rule_ref = f"{g.name}|{rc.name}|{r.name}"
                    self._rule_index[rule_ref] = {
                        "rcg": g.name,
                        "rc": rc.name,
                        "rule": r.name,
                    }
                    table.add_row(
                        g.name,
                        rc.name,
                        r.name,
                        "/".join(directions),
                        key=rule_ref,
                    )

        if not self._rule_index:
            table.add_row("-", "-", "No matching rules", "-", key="__empty_rules__")
