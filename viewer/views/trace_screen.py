"""Evaluation trace rendered as a compact tree, embedded in the row detail dialog.

Default is the *path view*: only the branch leading to the logged rule (or,
for "no rule matched", the nearest misses) is expanded; everything else is a
single collapsed line with a short reason. ``a`` toggles between this path
view and a fully expanded tree.
"""
from __future__ import annotations

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

from ..trace import (
    MATCH,
    MISS,
    NA,
    UNKNOWN,
    CollectionTrace,
    PassTrace,
    RuleTrace,
    Trace,
    first_problem,
    nearest_miss,
    nearest_rules,
)

_ICON = {MATCH: "[green]✓[/]", MISS: "[red]✗[/]", UNKNOWN: "[yellow]?[/]", NA: "[dim]–[/]"}
# Azure Firewall's processing order top to bottom; the tree keeps it.
_PASS_TITLE = {"dnat": "DNAT rules", "network": "Network rules", "application": "Application rules"}
LEGEND = ("[green]✓[/] match   [red]✗[/] miss   [yellow]?[/] cannot evaluate   [dim]–[/] not in log      "
          "Enter: expand · Enter on an open rule: show in Policy tab · Space: fold · a: full tree · Esc/q: close")
# Leaves render without the ▶/▼ marker, so their text would sit two cells left of
# sibling nodes. Pad root-level leaves to keep one column.
_LEAF_PAD = "  "
_INLINE_DETAIL_MAX = 40  # collapsed rule lines stay short; the full text is on the child leaf


def _action_tag(action: str, kind: str) -> str:
    """The collection's action as a short coloured tag.

    ✓/✗ in front of a line say whether the flow matched; the tag says what a
    match means. Deny is what a reader must not miss, so it is loud; allow is
    the common case and stays quiet.
    """
    a = (action or "").lower()
    if a == "deny":
        return "[bold red]deny[/]"
    if a == "allow":
        return "[dim]allow[/]"
    if a == "dnat" or kind == "dnat":
        return "[bold yellow]dnat[/]"
    return f"[dim]{escape(a or kind or '')}[/]"


def _short(text: str, limit: int = _INLINE_DETAIL_MAX) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


class TracePanel(Vertical):
    """Header, tree and legend for one :class:`Trace`.

    Posts :class:`TracePanel.RuleChosen` when an expanded rule node is selected;
    the payload is the rule ref (``policy|rcg|rc|rule``) the Policy tab understands.
    """

    DEFAULT_CSS = """
    TracePanel > #trace-title {
        text-style: bold;
        margin-bottom: 1;
    }
    TracePanel > #trace-warnings {
        color: $warning;
        margin-bottom: 1;
    }
    TracePanel > Tree {
        height: 1fr;
    }
    TracePanel > #trace-legend {
        color: $text-muted;
        margin-top: 1;
    }
    """

    class RuleChosen(Message):
        def __init__(self, rule_ref: str) -> None:
            super().__init__()
            self.rule_ref = rule_ref

    def __init__(self, trace: Trace, **kwargs) -> None:
        super().__init__(**kwargs)
        self._trace = trace
        self._expand_all = False
        self._logged_node: TreeNode | None = None  # remembered while building, no tree search needed

    # ── layout ──────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        t = self._trace
        f = t.flow
        if t.matched_rule:
            icon = "[green]✓[/]"
        elif f.threat_intel:
            icon = "[magenta]![/]"
        elif not t.outcome.startswith("default action"):
            icon = "[yellow]?[/]"  # the firewall matched a rule we could not locate (stale cache)
        else:
            icon = "[red]✗[/]"
        # Everything dynamic (names, FQDNs, outcome) is escaped: labels are Rich markup.
        # Two lines, each starting with a symbol: the flow, then the verdict.
        port = f":{f.dst_port}" if f.dst_port and f.dst_port != "-" else ""  # ICMP has none
        flow_line = escape(f"{f.src_ip} → {f.dst_fqdn or f.dst_ip}{port} {f.protocol}".rstrip())
        yield Static(f"[b]▸ {flow_line}[/b]\n{icon} {escape(t.outcome)}", id="trace-title", markup=True)
        if t.warnings:
            yield Static("\n".join(f"⚠ {escape(w)}" for w in t.warnings), id="trace-warnings", markup=True)
        yield Tree("Policy evaluation", id="trace-tree")
        yield Static(LEGEND, id="trace-legend", markup=True)

    def on_mount(self) -> None:
        self._build()

    def toggle_expand_all(self) -> None:
        self._expand_all = not self._expand_all
        self._build()

    def focus_tree(self) -> None:
        self.query_one("#trace-tree", Tree).focus()

    # ── tree construction ───────────────────────────────────────────────────
    def _build(self) -> None:
        tree = self.query_one("#trace-tree", Tree)
        tree.clear()
        tree.show_root = False
        tree.auto_expand = False  # Enter is handled below: expand first, open the rule second
        self._logged_node = None
        t = self._trace
        root = tree.root
        highlight = {id(r) for r in nearest_rules(t)} if t.matched_rule is None else set()
        show_origin = len({c.policy_name for p in t.passes for c in p.collections}) > 1

        root.add_leaf(f"{_LEAF_PAD}Threat Intelligence   [dim]{escape(t.threat_intel)}[/]")
        if t.flow.threat_intel:
            # Decided before the rules: one line for all three passes, and no
            # repeated verdict — the header already carries it.
            root.add_leaf(f"{_LEAF_PAD}[dim]DNAT, Network and Application rules   "
                          "not evaluated — decided before rule processing[/]")
        else:
            for p in t.passes:
                self._add_pass(root, p, highlight, show_origin)
            if t.infrastructure:
                root.add_leaf(f"{_LEAF_PAD}Built-in infrastructure FQDNs   [dim]{escape(t.infrastructure)}[/]")
            if t.matched_rule is not None:
                root.add_leaf(f"{_LEAF_PAD}[green]✓[/] evaluation stopped at the logged rule")
            else:
                root.add_leaf(f"{_LEAF_PAD}[red]✗[/] {escape(t.outcome)}")
        root.expand()

        matched = self._logged_node
        if matched is not None:
            def _go(node=matched) -> None:
                tree.move_cursor(node)
                tree.scroll_to_node(node)
            self.call_after_refresh(_go)
        tree.focus()

    def _add_pass(self, root: TreeNode, p: PassTrace, highlight: set[int], show_origin: bool) -> None:
        title = _PASS_TITLE[p.kind]
        if not p.evaluated:
            root.add_leaf(f"{_LEAF_PAD}[dim]{title}   {escape(p.note)}[/]")
            return
        if not p.collections:
            root.add_leaf(f"{_LEAF_PAD}{title}   [dim]{escape(p.note or 'no collections')}[/]")
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
                group_node = pass_node.add(escape(f"[{c.group.priority}] {c.group.name}") + origin, expand=True)
            if not c.evaluated:
                pending_skipped += 1
                continue
            if group_node is not None:
                self._add_collection(group_node, c, highlight)
        if pending_skipped and group_node is not None:
            group_node.add_leaf(f"[dim]{pending_skipped} more collections not evaluated[/]")

    def _add_collection(self, parent: TreeNode, c: CollectionTrace, highlight: set[int]) -> None:
        rc = c.collection
        head = escape(f"[{rc.priority}] {rc.name}") + "  " + _action_tag(rc.action, rc.kind)
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
            # keep the collapsed line short; the child leaf carries the full detail
            detail = f"   [dim]{problem.name}: {escape(_short(problem.detail))}[/]" if problem else ""
            star = " [yellow]★ nearest[/]" if id(r) in highlight else ""
            label = f"{_ICON.get(r.verdict, '')} {name}{detail}{star}"
        node = parent.add(label, data={"rule_ref": ref, "logged": r.logged}, expand=self._expand_all or r.logged)
        if r.logged:
            self._logged_node = node
        for ch in r.checks:
            node.add_leaf(f"{_ICON[ch.result]} {ch.name}: [dim]{escape(ch.detail)}[/]")

    # ── interaction ─────────────────────────────────────────────────────────
    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Enter expands a collapsed node; on an already open rule it opens the rule."""
        event.stop()
        node = event.node
        data = node.data
        rule_ref = data.get("rule_ref") if isinstance(data, dict) else None
        if node.allow_expand and not node.is_expanded:
            node.expand()
        elif rule_ref:
            self.post_message(self.RuleChosen(rule_ref))
        elif node.allow_expand:
            node.collapse()
