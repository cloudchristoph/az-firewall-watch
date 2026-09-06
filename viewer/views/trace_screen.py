"""Modal screen rendering an evaluation trace as a tree."""
from __future__ import annotations

from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static, Tree

from ..trace import MATCH, MISS, NA, UNKNOWN, CollectionTrace, RuleTrace, Trace

_ICON = {MATCH: "[green]✓[/]", MISS: "[red]✗[/]", UNKNOWN: "[yellow]?[/]", NA: "[dim]–[/]"}
_PASS_TITLE = {"dnat": "Pass 1 · DNAT rules", "network": "Pass 2 · Network rules", "application": "Pass 3 · Application rules"}


class TraceScreen(ModalScreen[str | None]):
    """Shows how the firewall evaluated one flow. Dismisses with a rule ref
    (``rcg|rc|rule``) when the user selects a rule node, else ``None``."""

    DEFAULT_CSS = """
    TraceScreen {
        align: center middle;
    }
    TraceScreen > #dialog {
        width: 90%;
        height: 90%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    TraceScreen > #dialog > #trace-title {
        text-style: bold;
        margin-bottom: 1;
    }
    TraceScreen > #dialog > #trace-warnings {
        color: $warning;
        margin-bottom: 1;
    }
    TraceScreen > #dialog > Tree {
        height: 1fr;
    }
    TraceScreen > #dialog > .btn-row {
        height: 3;
        margin-top: 1;
    }
    TraceScreen > #dialog > .btn-row > Button {
        width: 1fr;
    }
    """

    def __init__(self, trace: Trace, metadata_note: str = "") -> None:
        super().__init__()
        self._trace = trace
        self._metadata_note = metadata_note

    def compose(self) -> ComposeResult:
        t = self._trace
        f = t.flow
        with Static(id="dialog"):
            yield Static(
                f"Evaluation of {f.src_ip} → {f.dst_fqdn or f.dst_ip}:{f.dst_port} {f.protocol}"
                + (f"   [dim]{self._metadata_note}[/]" if self._metadata_note else ""),
                id="trace-title", markup=True,
            )
            if t.warnings:
                yield Static("\n".join(f"⚠ {w}" for w in t.warnings), id="trace-warnings", markup=True)
            yield Tree("Policy evaluation", id="trace-tree")
            with Horizontal(classes="btn-row"):
                yield Button("Open rule in Policy tab  (Enter)", variant="primary", id="btn-open-rule")
                yield Button("Close  (Esc)", variant="default", id="btn-close")

    def on_mount(self) -> None:
        tree = self.query_one("#trace-tree", Tree)
        t = self._trace
        root = tree.root
        root.set_label("Policy evaluation")
        root.add_leaf(f"Threat Intelligence   [dim]{t.threat_intel}[/]")
        for p in t.passes:
            label = _PASS_TITLE[p.kind]
            if not p.evaluated:
                node = root.add(f"[dim]{label}   {p.note}[/]", expand=False)
                continue
            if p.note and not p.collections:
                root.add_leaf(f"{label}   [dim]{p.note}[/]")
                continue
            node = root.add(label, expand=True)
            for c in p.collections:
                self._add_collection(node, c)
            if p.stopped_here:
                node.add_leaf("[green]evaluation stops here — rule matched[/]")
        if t.infrastructure:
            root.add_leaf(f"Infrastructure rule collection   [dim]{t.infrastructure}[/]")
        icon = "[green]✓[/]" if t.matched_rule else "[red]✗[/]"
        root.add_leaf(f"{icon} {t.outcome}")
        root.expand()
        tree.focus()
        matched = self._find_node(tree.root, lambda d: isinstance(d, dict) and d.get("logged"))
        if matched is not None:
            # Only move the cursor: select_node() would emit NodeSelected and
            # close the screen right away. The tree computes its line index
            # after the first refresh, so defer the cursor move until then.
            def _go(node=matched) -> None:
                tree.move_cursor(node)
                tree.scroll_to_node(node)

            self.call_after_refresh(_go)

    def _add_collection(self, parent, c: CollectionTrace) -> None:
        rc = c.collection
        head = f"[{c.group.priority}] {c.group.name} » [{rc.priority}] {rc.name} ({rc.action or rc.kind})"
        origin = f" [dim]· {c.policy_name}[/]" if c.policy_name else ""
        if not c.evaluated:
            parent.add_leaf(f"[dim]{head}   not evaluated[/]")
            return
        icon = _ICON.get(c.verdict, "")
        note = f"   [dim]{c.note}[/]" if c.note else ""
        node = parent.add(f"{icon} {head}{origin}{note}", expand=c.verdict != MISS or True)
        for r in c.rules:
            self._add_rule(node, c, r)

    def _add_rule(self, parent, c: CollectionTrace, r: RuleTrace) -> None:
        ref = c.rule_ref_prefix + r.rule.name
        summary = "  ".join(f"{_ICON[ch.result]} {ch.name}" for ch in r.checks)
        if r.logged:
            label = f"[green]✓[/] [b]{r.rule.name}[/b]   {summary}   [green]← logged match[/]"
        else:
            label = f"{_ICON.get(r.verdict, '')} {r.rule.name}   {summary}"
        node = parent.add(label, data={"rule_ref": ref, "logged": r.logged}, expand=r.logged)
        for ch in r.checks:
            node.add_leaf(f"{_ICON[ch.result]} {ch.name}: [dim]{ch.detail}[/]")

    @staticmethod
    def _find_node(node, pred):
        if pred(node.data):
            return node
        for child in node.children:
            found = TraceScreen._find_node(child, pred)
            if found is not None:
                return found
        return None

    def _selected_rule_ref(self) -> str | None:
        tree = self.query_one("#trace-tree", Tree)
        node = tree.cursor_node
        while node is not None:
            if isinstance(node.data, dict) and node.data.get("rule_ref"):
                return node.data["rule_ref"]
            node = node.parent
        return None

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if isinstance(data, dict) and data.get("rule_ref"):
            event.stop()
            self.dismiss(data["rule_ref"])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-open-rule":
            self.dismiss(self._selected_rule_ref())
        else:
            self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        if event.key in ("escape", "q", "t"):
            event.stop()
            self.dismiss(None)
