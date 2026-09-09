"""Evaluation trace rendered as a compact tree, embedded in the row detail dialog.

Default is the *focused* view: only the branch leading to the logged rule (or,
for "no rule matched", the nearest misses) is expanded; everything else is a
single collapsed line with a short reason. ``a`` toggles between this focused
view and a fully expanded tree.

The tree itself carries only status, priority and name — no rule counts, no
inline check details, no "nearest miss" suffixes. All of that lives in the
selection detail below the tree (see ``_render_*_detail``), which follows the
tree's cursor. The dialog around this panel owns the flow/outcome header and
the footer; this panel only owns the tree, its legend and the detail Static.
"""
from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

from ..azure_resources import RuleCollectionGroup
from ..trace import (
    MATCH,
    MISS,
    NA,
    UNKNOWN,
    CollectionTrace,
    PassTrace,
    RuleTrace,
    Trace,
    nearest_miss,
    nearest_rules,
)

_ICON = {MATCH: "[green]✓[/]", MISS: "[red]✗[/]", UNKNOWN: "[yellow]?[/]", NA: "[dim]–[/]"}
# Azure Firewall's processing order top to bottom; the tree keeps it.
_PASS_TITLE = {"dnat": "DNAT rules", "network": "Network rules", "application": "Application rules"}
LEGEND = "[green]✓[/] match   [red]✗[/] miss   [yellow]?[/] cannot evaluate   [dim]–[/] not in log"
# Leaves render without the ▶/▼ marker, so their text would sit two cells left of
# sibling nodes. Pad root-level leaves to keep one column.
_LEAF_PAD = "  "
_NAME_MAX = 48  # tree lines cut long names with an ellipsis; the detail shows them whole
_VERDICT_WORD = {MATCH: "match", MISS: "miss", UNKNOWN: "cannot evaluate"}


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
        return "[dim green]allow[/]"   # quiet, but still readable as the good outcome
    if a == "dnat" or kind == "dnat":
        return "[bold yellow]dnat[/]"
    return f"[dim]{escape(a or kind or '')}[/]"


def _short(text: str, limit: int = _NAME_MAX) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ── selection detail: one render function per node kind ──────────────────────

def _render_pass_detail(p: PassTrace) -> str:
    title = _PASS_TITLE[p.kind]
    if not p.evaluated:
        return f"[b]{escape(title)}[/b]\n[dim]{escape(p.note)}[/]"
    matched = sum(1 for c in p.collections if c.verdict == MATCH)
    missed = sum(1 for c in p.collections if c.verdict == MISS)
    unknown = sum(1 for c in p.collections if c.verdict == UNKNOWN)
    skipped = sum(1 for c in p.collections if not c.evaluated)
    lines = [f"[b]{escape(title)}[/b]"]
    if p.note:
        lines.append(f"[dim]{escape(p.note)}[/]")
    lines.append(f"{matched} matched · {missed} miss · {unknown} cannot evaluate · {skipped} not evaluated")
    return "\n".join(lines)


def _render_group_detail(name: str, priority: int, collections: list[CollectionTrace]) -> str:
    n = len(collections)
    k = sum(1 for c in collections if c.verdict == UNKNOWN)
    return (f"[b]{escape(f'[{priority}] {name}')}[/b]\n"
            f"{n} collection{'s' if n != 1 else ''} · {k} with ?")


def _render_collection_detail(c: CollectionTrace) -> str:
    if not c.evaluated:
        return "[dim]not evaluated: a rule before it matched[/]"
    rc = c.collection
    lines = [
        f"[b]{escape(rc.name)}[/b]   {_action_tag(rc.action, rc.kind)}   "
        f"[dim]{escape(c.group.name)} · priority {rc.priority}[/]",
        f"{len(c.rules)} rule{'s' if len(c.rules) != 1 else ''}",
    ]
    icon = _ICON.get(c.verdict, "")
    body = escape(c.note) if c.note else _VERDICT_WORD.get(c.verdict, c.verdict)
    lines.append(f"{icon} {body}")
    if c.verdict in (MISS, UNKNOWN):
        miss = nearest_miss(c)
        if miss is not None:
            label = "nearest miss" if miss.result == MISS else "cannot decide"
            lines.append(f"{label}: {escape(miss.name)}: {escape(miss.detail)}")
    return "\n".join(lines)


def _render_rule_detail(r: RuleTrace, c: CollectionTrace) -> str:
    rule = r.rule
    lines = [f"[b]{escape(rule.name)}[/b]   {_action_tag(c.collection.action, c.collection.kind)}   "
             f"[dim]{escape(c.group.name)} » {escape(c.collection.name)}[/]"]
    for ch in r.checks:
        icon = _ICON.get(ch.result, "")
        lines.append(f"{icon} {ch.name:<12} {escape(ch.detail)}")
    if rule.http_headers:
        # What the rule does to the flow beyond allowing it. Names only:
        # the values can carry tokens, and the Policy tab reveals them on request.
        n = len(rule.http_headers)
        names = ", ".join(escape(h.name) for h in rule.http_headers)
        lines.append(f"✎ inserts {n} HTTP header{'s' if n != 1 else ''}: {names}")
    if r.logged:
        lines.append("[green]logged by the firewall[/]")
    return "\n".join(lines)


class TracePanel(Vertical):
    """Tree, selection detail and legend for one :class:`Trace`.

    The flow/outcome header lives in the dialog around this panel now, not
    here. Posts :class:`TracePanel.RuleChosen` — only from :meth:`open_selected_rule`,
    never from a plain tree interaction — with the rule ref
    (``policy|rcg|rc|rule``) the Policy tab understands.
    """

    DEFAULT_CSS = """
    TracePanel > #trace-warnings {
        color: $warning;
        margin-bottom: 1;
    }
    TracePanel > Tree {
        height: 1fr;
    }
    TracePanel > #trace-detail {
        height: auto;
        max-height: 12;
        overflow-y: auto;
        margin-top: 1;
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
        if t.warnings:
            yield Static("\n".join(f"⚠ {escape(w)}" for w in t.warnings), id="trace-warnings", markup=True)
        yield Tree("Policy evaluation", id="trace-tree")
        yield Static(id="trace-detail")
        yield Static(Text.from_markup(LEGEND), id="trace-legend")

    def on_mount(self) -> None:
        self._build()

    def toggle_expand_all(self) -> None:
        self._expand_all = not self._expand_all
        self._build()

    def focus_tree(self) -> None:
        self.query_one("#trace-tree", Tree).focus()

    def open_selected_rule(self) -> None:
        """Post :class:`RuleChosen` for the cursor node's rule, if it has one."""
        tree = self.query_one("#trace-tree", Tree)
        node = tree.cursor_node
        data = node.data if node is not None else None
        rule_ref = data.get("rule_ref") if isinstance(data, dict) else None
        if rule_ref:
            self.post_message(self.RuleChosen(rule_ref))

    # ── tree construction ───────────────────────────────────────────────────
    def _build(self) -> None:
        tree = self.query_one("#trace-tree", Tree)
        tree.clear()
        tree.show_root = False
        tree.auto_expand = False  # Enter only toggles; see on_tree_node_selected
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
                self._render_detail(node)
            self.call_after_refresh(_go)
        else:
            self._render_detail(tree.cursor_node)
        tree.focus()

    def _add_pass(self, root: TreeNode, p: PassTrace, highlight: set[int], show_origin: bool) -> None:
        title = _PASS_TITLE[p.kind]
        if not p.evaluated:
            root.add_leaf(f"{_LEAF_PAD}[dim]{title}   {escape(p.note)}[/]")
            return
        if not p.collections:
            root.add_leaf(f"{_LEAF_PAD}{title}   [dim]{escape(p.note or 'no collections')}[/]")
            return
        evaluated = [c for c in p.collections if c.evaluated]
        if p.stopped_here:
            summary = "[green]✓ matched[/]"
        elif any(c.verdict == UNKNOWN for c in evaluated):
            summary = "[yellow]? no certain match[/]"
        elif any(c.verdict == MATCH for c in evaluated):
            summary = "[green]✓ computed match[/]"
        else:
            summary = "[red]✗ no match[/]"
        has_star = any(id(r) in highlight for c in p.collections for r in c.rules)
        has_unknown = any(c.verdict == UNKNOWN for c in evaluated)
        pass_expand = self._expand_all or p.stopped_here or has_star or has_unknown
        pass_node = root.add(f"{title}   {summary}", data={"kind": "pass", "pass": p}, expand=pass_expand)

        # group collections by their rule collection group; contiguous, as
        # build_trace appends them group by group.
        groups: list[tuple[str, RuleCollectionGroup, list[CollectionTrace]]] = []
        for c in p.collections:
            if groups and groups[-1][0] == c.policy_name and groups[-1][1].name == c.group.name:
                groups[-1][2].append(c)
            else:
                groups.append((c.policy_name, c.group, [c]))

        for policy_name, group, cols in groups:
            origin = f"   [dim]· {escape(policy_name)}[/]" if show_origin and policy_name else ""
            label = escape(f"[{group.priority}] {group.name}") + origin
            logged_idx = next((i for i, c in enumerate(cols)
                               if c.evaluated and any(r.logged for r in c.rules)), None)
            g_has_unknown = any(c.verdict == UNKNOWN for c in cols if c.evaluated)
            g_has_star = any(id(r) in highlight for c in cols for r in c.rules)
            group_expand = self._expand_all or logged_idx is not None or g_has_unknown or g_has_star
            group_node = pass_node.add(
                label, data={"kind": "group", "name": group.name, "priority": group.priority, "collections": cols},
                expand=group_expand,
            )
            if logged_idx is not None:
                self._add_focused_group(group_node, cols, logged_idx, highlight)
            else:
                for c in cols:
                    if c.evaluated:
                        self._add_collection(group_node, c, highlight)
                    else:
                        self._add_notevaluated_leaf(group_node, c)

    def _add_focused_group(self, group_node: TreeNode, cols: list[CollectionTrace], logged_idx: int,
                           highlight: set[int]) -> None:
        """The group holding the logged collection: fold what came before and
        after it, so only the collection that actually matched stays open."""
        preceding = cols[:logged_idx]
        logged_col = cols[logged_idx]
        after = cols[logged_idx + 1:]

        if preceding:
            n = len(preceding)
            unknown_n = sum(1 for c in preceding if c.verdict == UNKNOWN)
            # An unknown must stay visible from the outside, so it goes in the summary text.
            summary = f"{unknown_n} with ?" if unknown_n else "all ✗"
            fold = group_node.add(
                f"{n} preceding collections   {summary}",
                data={"kind": "summary", "name": logged_col.group.name, "priority": logged_col.group.priority,
                      "collections": preceding},
                expand=self._expand_all,
            )
            for c in preceding:
                self._add_collection(fold, c, highlight)

        self._add_collection(group_node, logged_col, highlight)

        if after:
            n = len(after)
            fold = group_node.add(
                f"{n} not evaluated",
                data={"kind": "summary", "name": logged_col.group.name, "priority": logged_col.group.priority,
                      "collections": after},
                expand=self._expand_all,
            )
            for c in after:
                self._add_notevaluated_leaf(fold, c)

    def _add_collection(self, parent: TreeNode, c: CollectionTrace, highlight: set[int]) -> None:
        rc = c.collection
        icon = _ICON.get(c.verdict, "")
        head = escape(f"[{rc.priority}] {_short(rc.name)}") + "  " + _action_tag(rc.action, rc.kind)
        label = f"{icon} {head}"
        expand = (self._expand_all
                 or (c.verdict == MATCH and any(r.logged for r in c.rules))
                 or any(id(r) in highlight for r in c.rules))
        node = parent.add(label, data={"kind": "collection", "collection": c}, expand=expand)
        for r in c.rules:
            self._add_rule(node, c, r, highlight)

    def _add_notevaluated_leaf(self, parent: TreeNode, c: CollectionTrace) -> None:
        rc = c.collection
        head = escape(f"[{rc.priority}] {_short(rc.name)}") + "  " + _action_tag(rc.action, rc.kind)
        parent.add_leaf(f"{_ICON[NA]} {head}", data={"kind": "collection", "collection": c})

    def _add_rule(self, parent: TreeNode, c: CollectionTrace, r: RuleTrace, highlight: set[int]) -> None:
        ref = c.rule_ref_prefix + r.rule.name
        name = escape(_short(r.rule.name))
        if r.logged:
            label = f"{_ICON[MATCH]} [b]{name}[/b]   [green]LOGGED[/]"
        else:
            icon = _ICON.get(r.verdict, "")
            star = "   [yellow]★ nearest[/]" if id(r) in highlight else ""
            label = f"{icon} {name}{star}"
        node = parent.add_leaf(label, data={"kind": "rule", "rule": r, "collection": c, "rule_ref": ref})
        if r.logged:
            self._logged_node = node

    # ── interaction ─────────────────────────────────────────────────────────
    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Enter expands or collapses the node and nothing else — opening a
        rule in the Policy tab is a separate action (see open_selected_rule)."""
        event.stop()
        node = event.node
        if node.allow_expand:
            if node.is_expanded:
                node.collapse()
            else:
                node.expand()

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        self._render_detail(event.node)

    def _render_detail(self, node: TreeNode | None) -> None:
        detail = self.query_one("#trace-detail", Static)
        data = node.data if node is not None else None
        if not isinstance(data, dict):
            detail.update("")
            return
        kind = data.get("kind")
        text = ""
        if kind == "rule":
            text = _render_rule_detail(data["rule"], data["collection"])
        elif kind == "collection":
            text = _render_collection_detail(data["collection"])
        elif kind == "pass":
            text = _render_pass_detail(data["pass"])
        elif kind in ("group", "summary"):
            text = _render_group_detail(data["name"], data["priority"], data["collections"])
        detail.update(Text.from_markup(text) if text else "")
