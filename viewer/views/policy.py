"""Policy metadata tab view."""
from __future__ import annotations

from rich.markup import escape
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

from ..azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection

# Header values may carry auth tokens or tenant ids; hidden by default and
# never rendered as anything but a fixed number of bullets.
_HIDDEN_HEADER_VALUE = "•" * 6
# Visual width of the "[dim]<label>[/]" column before a value starts (see the
# existing rule-detail lines: "Source groups" (13) + 2 spaces, "Protocols" (9)
# + 6 spaces, etc. all land on column 15).
_VALUE_COLUMN = 15


def _rule_category(rule: Rule, collection: RuleCollection) -> str:
    t = (rule.rule_type or collection.rule_collection_type or "").lower()
    if "application" in t:
        return "apprule"
    if "nat" in t:
        return "natrule"
    return "networkrule"


class PolicyView(Static):
    """Tree view of Policy -> RCG -> RC -> Rule hierarchy."""

    BINDINGS = [
        Binding("v", "toggle_header_values", "Show/hide header values", show=False),
    ]

    DEFAULT_CSS = """
    PolicyView {
        height: 1fr;
        padding: 1;
    }
    PolicyView > Horizontal {
        height: 1fr;
    }
    PolicyView #policy-tree {
        width: 1fr;
        min-width: 50;
    }
    PolicyView #policy-details {
        width: 1fr;
        min-width: 50;
        height: 1fr;
        border: round $panel;
        padding: 1;
        overflow-y: auto;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._rule_ref_to_node: dict[str, TreeNode] = {}
        self._policy_sku_tier: str = ""
        self._reveal_header_values: bool = False
        self._last_payload: dict | None = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Tree("Policy data unavailable", id="policy-tree")
            yield Static("Select a policy node to see details.", id="policy-details", markup=True)

    def render_data(
        self,
        policy: FirewallPolicyInfo | None,
        ip_groups: dict[str, IpGroupInfo],
    ) -> None:
        tree = self.query_one("#policy-tree", Tree)
        details = self.query_one("#policy-details", Static)
        self._rule_ref_to_node.clear()
        # A refresh must not keep previously revealed header values on screen.
        self._reveal_header_values = False
        self._last_payload = None
        if policy is None:
            self._policy_sku_tier = ""
            tree.root.set_label("Policy data unavailable")
            tree.root.remove_children()
            tree.root.data = None  # no stale policy details on the root node
            tree.root.expand()
            details.update("Policy data unavailable")
            return

        self._policy_sku_tier = policy.sku_tier

        tree.root.set_label(escape(
            f"{policy.name}  (SKU: {policy.sku_tier or '-'}, ThreatIntel: {policy.threat_intel_mode or '-'})"
        ))
        tree.root.remove_children()
        tree.root.data = {
            "kind": "policy",
            "policy": policy,
        }

        # Inherited (parent) groups first, exactly as the firewall evaluates them.
        for policy_name, g in policy.all_groups():
            origin = f"  · {escape(policy_name)}" if policy.parent is not None and policy_name != policy.name else ""
            g_node = tree.root.add(
                escape(f"[{g.priority}] {g.name}") + origin,   # whole label escaped: it is Rich markup
                data={"kind": "rcg", "rcg": g},
            )
            for rc in sorted(g.rule_collections, key=lambda x: x.priority):
                action = f" ({rc.action})" if rc.action else ""
                rc_node = g_node.add(
                    escape(f"[{rc.priority}] {rc.name}{action}"),
                    data={"kind": "rc", "rcg": g, "rc": rc},
                )
                for r in rc.rules:
                    rule_ref = self._rule_ref(policy_name, g.name, rc.name, r.name)
                    node = rc_node.add_leaf(
                        escape(r.name),
                        data={"kind": "rule", "rcg": g, "rc": rc, "rule": r, "rule_ref": rule_ref},
                    )
                    self._rule_ref_to_node[rule_ref] = node
        # All nodes exist up front (focus_rule needs them addressable), but only
        # the groups start expanded so a large policy stays readable.
        tree.root.expand()
        for g_node in tree.root.children:
            g_node.expand()
        details.update(self._policy_summary(policy))

        # stash current ip-group map for detail rendering
        tree.root.data = {
            "kind": "policy",
            "policy": policy,
            "ip_groups": ip_groups,
        }

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        payload = event.node.data
        details = self.query_one("#policy-details", Static)
        if payload is not self._last_payload:
            # Values are revealed per rule and per request: moving to another
            # node hides them again.
            self._reveal_header_values = False
        self._last_payload = payload if isinstance(payload, dict) else None
        if not isinstance(payload, dict):
            details.update("No details available")
            return

        ip_groups = self._current_ip_groups()
        kind = payload.get("kind")
        if kind == "policy":
            pol = payload.get("policy")
            if isinstance(pol, FirewallPolicyInfo):
                details.update(self._policy_summary(pol))
            return
        if kind == "rcg":
            g = payload.get("rcg")
            details.update(self._rcg_summary(g))
            return
        if kind == "rc":
            rc = payload.get("rc")
            g = payload.get("rcg")
            details.update(self._rc_summary(g, rc))
            return
        if kind == "rule":
            r = payload.get("rule")
            g = payload.get("rcg")
            rc = payload.get("rc")
            if r is None or g is None or rc is None:
                details.update("No details available")
                return
            details.update(self._rule_summary(g, rc, r, ip_groups))

    def on_key(self, event: events.Key) -> None:
        # The Tree child holds focus and has no binding for "v", so the key
        # event bubbles here; handle it directly rather than relying on the
        # app-level BINDINGS chain to be reached (belt and braces — see the
        # BINDINGS entry above, which documents the same action).
        if event.key == "v":
            event.stop()
            self.action_toggle_header_values()

    def action_toggle_header_values(self) -> None:
        """Reveal or hide the header values of the selected rule.

        Only a rule that inserts headers reacts: a stray ``v`` on a group or
        on a rule without headers must not arm a reveal for the next rule.
        """
        rule = self._selected_rule_with_headers()
        if rule is None:
            return
        self._reveal_header_values = not self._reveal_header_values
        self._rerender_selected_rule()

    def _selected_rule_with_headers(self) -> Rule | None:
        payload = self._last_payload
        if not isinstance(payload, dict) or payload.get("kind") != "rule":
            return None
        rule = payload.get("rule")
        return rule if isinstance(rule, Rule) and rule.http_headers else None

    def _rerender_selected_rule(self) -> None:
        """Re-render the details pane for the currently selected rule."""
        payload = self._last_payload
        if not isinstance(payload, dict) or payload.get("kind") != "rule":
            return
        r = payload.get("rule")
        g = payload.get("rcg")
        rc = payload.get("rc")
        if r is None or g is None or rc is None:
            return
        details = self.query_one("#policy-details", Static)
        details.update(self._rule_summary(g, rc, r, self._current_ip_groups()))

    def focus_rule(self, rule_ref: str) -> bool:
        """Focus a rule node by its stable ref ``policy|rcg|rc|rule`` (see ``_rule_ref``)."""
        tree = self.query_one("#policy-tree", Tree)
        node = self._rule_ref_to_node.get(rule_ref)
        if node is None:
            return False
        try:
            # open the ancestors first — the tree is collapsed below group level
            ancestor = node.parent
            while ancestor is not None:
                ancestor.expand()
                ancestor = ancestor.parent

            # The tree rebuilds its line index after the next refresh; only then
            # can the cursor land on a node that was hidden a moment ago.
            def _go(target=node) -> None:
                tree.move_cursor(target)
                tree.select_node(target)
                tree.scroll_to_node(target)

            self.call_after_refresh(_go)
            return True
        except Exception:
            return False

    @staticmethod
    def _rule_ref(policy_name: str, rcg_name: str, rc_name: str, rule_name: str) -> str:
        """Stable key ``policy|rcg|rc|rule`` shared with the trace and IP-group views."""
        return f"{policy_name}|{rcg_name}|{rc_name}|{rule_name}"

    def _current_ip_groups(self) -> dict[str, IpGroupInfo]:
        root_data = self.query_one("#policy-tree", Tree).root.data
        if isinstance(root_data, dict) and isinstance(root_data.get("ip_groups"), dict):
            return root_data["ip_groups"]
        return {}

    @staticmethod
    def _policy_summary(policy: FirewallPolicyInfo) -> str:
        own = len(policy.rule_collection_groups)
        inherited = len(policy.all_groups()) - own
        rcg_count = f"{own}" if not inherited else f"{own} own + {inherited} inherited"
        base = escape(policy.parent.name) if policy.parent is not None else (escape(policy.base_policy_id) or "-")
        return "\n".join([
            f"[b]{escape(policy.name)}[/b]",
            "",
            f"[dim]SKU[/]            {escape(policy.sku_tier) or '-'}",
            f"[dim]ThreatIntel[/]    {escape(policy.threat_intel_mode) or '-'}",
            f"[dim]Base policy[/]    {base}",
            f"[dim]RCG count[/]      {rcg_count}",
        ])

    @staticmethod
    def _rcg_summary(rcg) -> str:
        if rcg is None:
            return "RCG details unavailable"
        return "\n".join([
            "[b]Rule Collection Group[/b]",
            "",
            f"[dim]Name[/]           {escape(rcg.name)}",
            f"[dim]Priority[/]       {rcg.priority}",
            f"[dim]Collections[/]    {len(rcg.rule_collections)}",
        ])

    @staticmethod
    def _rc_summary(rcg, rc) -> str:
        if rc is None:
            return "Rule collection details unavailable"
        return "\n".join([
            "[b]Rule Collection[/b]",
            "",
            f"[dim]RCG[/]            {escape(rcg.name) if rcg else '-'}",
            f"[dim]Name[/]           {escape(rc.name)}",
            f"[dim]Priority[/]       {rc.priority}",
            f"[dim]Action[/]         {escape(rc.action) or '-'}",
            f"[dim]Type[/]           {escape(rc.rule_collection_type) or '-'}",
            f"[dim]Rules[/]          {len(rc.rules)}",
        ])

    def _rule_summary(self, rcg, rc, rule: Rule, ip_groups: dict[str, IpGroupInfo]) -> str:
        if not isinstance(rule, Rule):
            return "Rule details unavailable"

        src_groups = self._render_group_values(rule.source_ip_groups, ip_groups)
        dst_groups = self._render_group_values(rule.destination_ip_groups, ip_groups)
        def j(values: list[str]) -> str:
            return escape(", ".join(values)) if values else "-"

        lines = [
            f"[b]Rule: {escape(rule.name)}[/b]",
            "",
            f"[dim]RCG[/]            {escape(rcg.name) if rcg else '-'}",
            f"[dim]Collection[/]     {escape(rc.name) if rc else '-'}",
            f"[dim]Category[/]       {_rule_category(rule, rc) if rc else '-'}",
            f"[dim]Protocols[/]      {j(rule.protocols)}",
            f"[dim]Dest ports[/]     {j(rule.destination_ports)}",
            "",
            f"[dim]Source addrs[/]   {j(rule.source_addresses)}",
            f"[dim]Target addrs[/]   {j(rule.destination_addresses)}",
            f"[dim]Target FQDNs[/]   {j(rule.destination_fqdns)}",
            "",
            f"[dim]Source groups[/]  {src_groups}",
            f"[dim]Target groups[/]  {dst_groups}",
        ]

        if rc is not None and _rule_category(rule, rc) == "apprule":
            lines.extend(self._app_rule_extra_lines(rule))

        return "\n".join(lines)

    def _app_rule_extra_lines(self, rule: Rule) -> list[str]:
        """TLS inspection and HTTP header insertion, application rules only."""
        lines: list[str] = [""]
        if rule.terminate_tls:
            lines.append("[dim]TLS inspection[/] on")
        if rule.http_headers:
            lines.extend(self._http_header_lines(rule))
        if len(lines) == 1:
            # nothing was appended after the blank separator — drop it too
            lines.pop()
        return lines

    def _http_header_lines(self, rule: Rule) -> list[str]:
        count = len(rule.http_headers)
        if self._reveal_header_values:
            status = "[dim]values shown, press v to hide[/]"
        else:
            status = "[dim]press v to show values[/]"
        lines = [f"[dim]HTTP headers[/]   {count} inserted   {status}"]
        pad = " " * _VALUE_COLUMN
        for h in rule.http_headers:
            value = escape(h.value) if self._reveal_header_values else _HIDDEN_HEADER_VALUE
            lines.append(f"{pad}{escape(h.name)}: {value}")
        lines.append(self._header_insertion_scope_line(rule))
        return lines

    def _header_insertion_scope_line(self, rule: Rule) -> str:
        """Which traffic actually gets the headers, given the protocols the
        rule can match, the policy SKU and whether this rule terminates TLS
        (Premium-only TLS inspection). Headers go into HTTP and into HTTPS
        the firewall decrypts; an HTTPS-only rule without inspection inserts
        nowhere, and saying "HTTP only" there would name traffic it never
        matches."""
        protocols = {p.lower() for p in rule.protocols}
        has_http, has_https = "http" in protocols, "https" in protocols
        if not has_https:
            return "[dim]inserted into HTTP[/]"
        tier = self._policy_sku_tier
        if not tier:
            # No SKU on the policy read: whether HTTPS gets the headers depends
            # on it, so say that it is not known rather than assume a tier.
            return "[yellow]policy SKU unknown: whether HTTPS gets the headers cannot be told from here[/]"
        if tier != "Premium":
            why = "HTTPS on Standard/Basic"
        elif not rule.terminate_tls:
            why = "HTTPS without TLS inspection on this rule"
        else:
            return ("[dim]inserted into HTTP and TLS-inspected HTTPS[/]" if has_http
                    else "[dim]inserted into TLS-inspected HTTPS[/]")
        if has_http:
            return f"[yellow]{why}: headers are inserted into HTTP only[/]"
        return f"[yellow]{why}: no traffic this rule matches gets the headers[/]"

    @staticmethod
    def _render_group_values(group_ids: list[str], ip_groups: dict[str, IpGroupInfo]) -> str:
        if not group_ids:
            return "-"
        out: list[str] = []
        for gid in group_ids:
            grp = ip_groups.get(gid)
            if grp is None:
                out.append(f"{escape(gid)} (unresolved)")
                continue
            preview = ", ".join(grp.ip_addresses[:5])
            if len(grp.ip_addresses) > 5:
                preview += ", …"
            # Parentheses, not brackets: this string is rendered as Rich markup.
            out.append(f"{escape(grp.name)}: ({escape(preview)})" if preview else escape(grp.name))
        return "\n                  ".join(out)
