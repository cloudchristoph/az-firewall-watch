"""Modal screen rendering an evaluation trace as a compact tree.

Default is the *path view*: only the branch leading to the logged rule (or,
for "no rule matched", the nearest misses) is expanded; everything else is a
single collapsed line with a short reason. ``a`` expands everything.
"""
from __future__ import annotations

from rich.markup import escape
from textual import events
from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

from ..trace import (
    MATCH, MISS, NA, UNKNOWN,
    CollectionTrace, PassTrace, RuleTrace, Trace,
    first_problem, nearest_rules,
    nearest_miss,
)

_ICON = {MATCH: "[green]✓[/]", MISS: "[red]✗[/]", UNKNOWN: "[yellow]?[/]", NA: "[dim]–[/]"}
_PASS_TITLE = {"dnat": "Pass 1 · DNAT", "network": "Pass 2 · Network", "application": "Pass 3 · Application"}
LEGEND = "[green]✓[/] match   [red]✗[/] miss   [yellow]?[/] cannot evaluate   [dim]–[/] not in log      Enter open rule · a expand all · Esc/q/t close"


class TraceScreen(ModalScreen[str | None]):
    """Dismisses with a rule ref (``policy|rcg|rc|rule``, the same key the
    Policy tab uses) when a rule node is selected, else ``None``."""

    DEFAULT_CSS = """
    TraceScreen {
        align: center middle;
    }
    TraceScreen > #dialog {
        width: 110;
        max-width: 96%;
        height: 90%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    TraceScreen > #dialog > #trace-title {
        text-style: bold;
    }
    TraceScreen > #dialog > #trace-meta {
        color: $text-muted;
        margin-bottom: 1;
    }
    TraceScreen > #dialog > #trace-warnings {
        color: $warning;
        margin-bottom: 1;
    }
    TraceScreen > #dialog > Tree {
        height: 1fr;
    }
    TraceScreen > #dialog > #trace-legend {
        color: $text-muted;
        margin-top: 1;
    }
    """

    def __init__(self, trace: Trace, metadata_note: str = "") -> None:
        super().__init__()
        self._trace = trace
        self._metadata_note = metadata_note
        self._expand_all = False

    # ── layout ──────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        t = self._trace
        f = t.flow
        if t.matched_rule:
            icon = "[green]✓[/]"
        elif f.threat_intel:
            icon = "[magenta]![/]"
        else:
            icon = "[red]✗[/]"
        with Static(id="dialog"):
            # Everything dynamic (names, FQDNs, outcome) is escaped: labels are Rich markup.
            port = f":{f.dst_port}" if f.dst_port and f.dst_port != "-" else ""  # ICMP has none
            yield Static(
                escape(f"{f.src_ip} → {f.dst_fqdn or f.dst_ip}{port} {f.protocol}".rstrip())
                + f"    {icon} {escape(t.outcome)}",
                id="trace-title", markup=True,
            )
            yield Static(escape(self._metadata_note or ""), id="trace-meta", markup=True)
            if t.warnings:
                yield Static("\n".join(f"⚠ {escape(w)}" for w in t.warnings), id="trace-warnings", markup=True)
            yield Tree("Policy evaluation", id="trace-tree")
            yield Static(LEGEND, id="trace-legend", markup=True)

    def on_mount(self) -> None:
        self._build()

    # ── tree construction ───────────────────────────────────────────────────
    def _build(self) -> None:
        tree = self.query_one("#trace-tree", Tree)
        tree.clear()
        tree.show_root = False
        t = self._trace
        root = tree.root
        highlight = {id(r) for r in nearest_rules(t)} if t.matched_rule is None else set()
        show_origin = len({c.policy_name for p in t.passes for c in p.collections}) > 1

        root.add_leaf(f"Threat Intelligence   [dim]{escape(t.threat_intel)}[/]")
        for p in t.passes:
            self._add_pass(root, p, highlight, show_origin)
        if t.infrastructure:
            root.add_leaf(f"Infrastructure rule collection   [dim]{escape(t.infrastructure)}[/]")
        if t.matched_rule is not None:
            root.add_leaf("[green]✓[/] evaluation stopped at the logged rule")
        elif t.flow.threat_intel:
            root.add_leaf(f"[magenta]![/] {escape(t.outcome)}")
        else:
            root.add_leaf(f"[red]✗[/] {escape(t.outcome)}")
        root.expand()

        matched = self._find_node(root, lambda d: isinstance(d, dict) and d.get("logged"))
        if matched is not None:
            def _go(node=matched) -> None:
                tree.move_cursor(node)
                tree.scroll_to_node(node)
            self.call_after_refresh(_go)
        tree.focus()

    def _add_pass(self, root: TreeNode, p: PassTrace, highlight: set[int], show_origin: bool) -> None:
        title = _PASS_TITLE[p.kind]
        if not p.evaluated:
            root.add_leaf(f"[dim]{title}   {escape(p.note)}[/]")
            return
        if not p.collections:
            root.add_leaf(f"{title}   [dim]{escape(p.note or 'no collections')}[/]")
            return
        if p.stopped_here:
            summary = "[green]✓ matched[/]"
        elif any(c.verdict == UNKNOWN for c in p.collections if c.evaluated):
            summary = "[yellow]? no certain match[/]"
        elif any(c.verdict == MATCH for c in p.collections if c.evaluated):
            summary = "[green]✓ computed match[/]"
        else:
            summary = "[red]✗ no match[/]"
        contains_path = p.stopped_here or any(id(r) in highlight for c in p.collections for r in c.rules)
        pass_node = root.add(f"{title}   {summary}", expand=self._expand_all or contains_path)

        # group collections by their rule collection group (once per group)
        current_key = None
        group_node: TreeNode | None = None
        pending_skipped = 0
        for c in p.collections:
            key = (c.policy_name, c.group.name)
            if key != current_key:
                if pending_skipped and group_node is not None:
                    group_node.add_leaf(f"[dim]{pending_skipped} more collections not evaluated[/]")
                    pending_skipped = 0
                current_key = key
                origin = f"   [dim]· {escape(c.policy_name)}[/]" if show_origin and c.policy_name else ""
                group_node = pass_node.add(f"[{c.group.priority}] {escape(c.group.name)}{origin}", expand=True)
            if not c.evaluated:
                pending_skipped += 1
                continue
            self._add_collection(group_node, c, highlight)
        if pending_skipped and group_node is not None:
            group_node.add_leaf(f"[dim]{pending_skipped} more collections not evaluated[/]")

    def _add_collection(self, parent: TreeNode, c: CollectionTrace, highlight: set[int]) -> None:
        rc = c.collection
        head = escape(f"[{rc.priority}] {rc.name} ({rc.action or rc.kind})")
        n = len(c.rules)
        rules_txt = f"{n} rule" if n == 1 else f"{n} rules"
        if c.verdict == MATCH and any(r.logged for r in c.rules):
            label, expand = f"[green]✓[/] {head}", True
        elif c.verdict == MATCH:
            label, expand = f"[green]✓[/] {head}   [dim]{rules_txt} · {escape(c.note)}[/]", self._expand_all
        else:
            icon = _ICON.get(c.verdict, "")
            miss = nearest_miss(c)
            reason = c.note or (f"nearest miss: {miss.name}" if miss else "no rules")
            label = f"{icon} {head}   [dim]{rules_txt} · {escape(reason)}[/]"
            expand = self._expand_all or any(id(r) in highlight for r in c.rules)
        node = parent.add(label, expand=expand)
        for r in c.rules:
            self._add_rule(node, c, r, highlight)

    def _add_rule(self, parent: TreeNode, c: CollectionTrace, r: RuleTrace, highlight: set[int]) -> None:
        ref = c.rule_ref_prefix + r.rule.name
        name = escape(r.rule.name)
        if r.logged:
            summary = "  ".join(f"{_ICON[ch.result]} {ch.name}" for ch in r.checks)
            label = f"[green]✓[/] [b]{name}[/b]   {summary}   [green]← logged[/]"
        elif r.verdict == MATCH:
            label = f"[green]✓[/] {name}   [dim]would match[/]"
        else:
            problem = first_problem(r)
            detail = f"   [dim]{problem.name}: {escape(problem.detail)}[/]" if problem else ""
            star = " [yellow]★ nearest[/]" if id(r) in highlight else ""
            label = f"{_ICON.get(r.verdict, '')} {name}{detail}{star}"
        node = parent.add(label, data={"rule_ref": ref, "logged": r.logged}, expand=self._expand_all or r.logged)
        for ch in r.checks:
            node.add_leaf(f"{_ICON[ch.result]} {ch.name}: [dim]{escape(ch.detail)}[/]")

    @staticmethod
    def _find_node(node: TreeNode, pred):
        if pred(node.data):
            return node
        for child in node.children:
            found = TraceScreen._find_node(child, pred)
            if found is not None:
                return found
        return None

    # ── interaction ─────────────────────────────────────────────────────────
    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if isinstance(data, dict) and data.get("rule_ref"):
            event.stop()
            self.dismiss(data["rule_ref"])

    def on_key(self, event: events.Key) -> None:
        if event.key in ("escape", "q", "t"):
            event.stop()
            self.dismiss(None)
        elif event.key == "a":
            event.stop()
            self._expand_all = not self._expand_all
            self._build()
