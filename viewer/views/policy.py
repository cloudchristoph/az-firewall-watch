"""Policy metadata tab view."""
from __future__ import annotations

from textual.containers import Horizontal
from textual.app import ComposeResult
from textual.widgets import Static, Tree

from ..azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule, RuleCollection


def _rule_category(rule: Rule, collection: RuleCollection) -> str:
    t = (rule.rule_type or collection.rule_collection_type or "").lower()
    if "application" in t:
        return "apprule"
    if "nat" in t:
        return "natrule"
    return "networkrule"


class PolicyView(Static):
    """Tree view of Policy -> RCG -> RC -> Rule hierarchy."""

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
        self._rule_ref_to_node: dict[str, Tree.Node] = {}

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Tree("Policy data unavailable", id="policy-tree")
            yield Static("Select a policy node to see details.", id="policy-details")

    def render_data(
        self,
        policy: FirewallPolicyInfo | None,
        ip_groups: dict[str, IpGroupInfo],
    ) -> None:
        tree = self.query_one("#policy-tree", Tree)
        details = self.query_one("#policy-details", Static)
        self._rule_ref_to_node.clear()
        if policy is None:
            tree.root.set_label("Policy data unavailable")
            tree.root.remove_children()
            tree.root.expand()
            details.update("Policy data unavailable")
            return

        tree.root.set_label(
            f"{policy.name}  (SKU: {policy.sku_tier or '-'}, ThreatIntel: {policy.threat_intel_mode or '-'})"
        )
        tree.root.remove_children()
        tree.root.data = {
            "kind": "policy",
            "policy": policy,
        }

        for g in sorted(policy.rule_collection_groups, key=lambda x: x.priority):
            g_node = tree.root.add(
                f"[{g.priority}] {g.name}",
                data={"kind": "rcg", "rcg": g},
            )
            for rc in sorted(g.rule_collections, key=lambda x: x.priority):
                action = f" ({rc.action})" if rc.action else ""
                rc_node = g_node.add(
                    f"[{rc.priority}] {rc.name}{action}",
                    data={"kind": "rc", "rcg": g, "rc": rc},
                )
                for r in rc.rules:
                    rule_ref = self._rule_ref(g.name, rc.name, r.name)
                    node = rc_node.add_leaf(
                        r.name,
                        data={"kind": "rule", "rcg": g, "rc": rc, "rule": r, "rule_ref": rule_ref},
                    )
                    self._rule_ref_to_node[rule_ref] = node
        tree.root.expand_all()
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
            details.update(self._rule_summary(g, rc, r, ip_groups))

    def focus_rule(self, rule_ref: str) -> bool:
        """Focus a rule node by stable rule_ref (rcg|rc|rule)."""
        tree = self.query_one("#policy-tree", Tree)
        node = self._rule_ref_to_node.get(rule_ref)
        if node is None:
            return False
        try:
            tree.select_node(node)
            node.expand()
            return True
        except Exception:
            return False

    @staticmethod
    def _rule_ref(rcg_name: str, rc_name: str, rule_name: str) -> str:
        return f"{rcg_name}|{rc_name}|{rule_name}"

    def _current_ip_groups(self) -> dict[str, IpGroupInfo]:
        root_data = self.query_one("#policy-tree", Tree).root.data
        if isinstance(root_data, dict) and isinstance(root_data.get("ip_groups"), dict):
            return root_data["ip_groups"]
        return {}

    @staticmethod
    def _policy_summary(policy: FirewallPolicyInfo) -> str:
        return "\n".join([
            f"[b]{policy.name}[/b]",
            "",
            f"[dim]SKU[/]            {policy.sku_tier or '-'}",
            f"[dim]ThreatIntel[/]    {policy.threat_intel_mode or '-'}",
            f"[dim]Base policy[/]    {policy.base_policy_id or '-'}",
            f"[dim]RCG count[/]      {len(policy.rule_collection_groups)}",
        ])

    @staticmethod
    def _rcg_summary(rcg) -> str:
        if rcg is None:
            return "RCG details unavailable"
        return "\n".join([
            f"[b]Rule Collection Group[/b]",
            "",
            f"[dim]Name[/]           {rcg.name}",
            f"[dim]Priority[/]       {rcg.priority}",
            f"[dim]Collections[/]    {len(rcg.rule_collections)}",
        ])

    @staticmethod
    def _rc_summary(rcg, rc) -> str:
        if rc is None:
            return "Rule collection details unavailable"
        return "\n".join([
            f"[b]Rule Collection[/b]",
            "",
            f"[dim]RCG[/]            {rcg.name if rcg else '-'}",
            f"[dim]Name[/]           {rc.name}",
            f"[dim]Priority[/]       {rc.priority}",
            f"[dim]Action[/]         {rc.action or '-'}",
            f"[dim]Type[/]           {rc.rule_collection_type or '-'}",
            f"[dim]Rules[/]          {len(rc.rules)}",
        ])

    def _rule_summary(self, rcg, rc, rule: Rule, ip_groups: dict[str, IpGroupInfo]) -> str:
        if not isinstance(rule, Rule):
            return "Rule details unavailable"

        src_groups = self._render_group_values(rule.source_ip_groups, ip_groups)
        dst_groups = self._render_group_values(rule.destination_ip_groups, ip_groups)
        return "\n".join([
            f"[b]Rule: {rule.name}[/b]",
            "",
            f"[dim]RCG[/]            {rcg.name if rcg else '-'}",
            f"[dim]Collection[/]     {rc.name if rc else '-'}",
            f"[dim]Category[/]       {_rule_category(rule, rc) if rc else '-'}",
            f"[dim]Protocols[/]      {', '.join(rule.protocols) if rule.protocols else '-'}",
            f"[dim]Dest ports[/]     {', '.join(rule.destination_ports) if rule.destination_ports else '-'}",
            "",
            f"[dim]Source addrs[/]   {', '.join(rule.source_addresses) if rule.source_addresses else '-'}",
            f"[dim]Target addrs[/]   {', '.join(rule.destination_addresses) if rule.destination_addresses else '-'}",
            f"[dim]Target FQDNs[/]   {', '.join(rule.destination_fqdns) if rule.destination_fqdns else '-'}",
            "",
            f"[dim]Source groups[/]  {src_groups}",
            f"[dim]Target groups[/]  {dst_groups}",
        ])

    @staticmethod
    def _render_group_values(group_ids: list[str], ip_groups: dict[str, IpGroupInfo]) -> str:
        if not group_ids:
            return "-"
        out: list[str] = []
        for gid in group_ids:
            grp = ip_groups.get(gid)
            if grp is None:
                out.append(f"{gid} (unresolved)")
                continue
            preview = ", ".join(grp.ip_addresses[:5])
            if len(grp.ip_addresses) > 5:
                preview += ", …"
            out.append(f"{grp.name}: [{preview}]" if preview else grp.name)
        return "\n                  ".join(out)
