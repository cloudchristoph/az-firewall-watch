"""Firewall metadata tab view."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static

from ..azure_resources import FirewallInfo, FirewallPolicyInfo


class FirewallView(Static):
    """Renders firewall-level metadata in a compact text block."""

    DEFAULT_CSS = """
    FirewallView {
        height: 1fr;
        padding: 1 2;
        overflow-y: auto;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("Waiting for first firewall event…", id="fw-content", markup=True)

    def render_data(
        self,
        firewall: FirewallInfo | None,
        policy: FirewallPolicyInfo | None,
        subnet_cidrs: list[str],
    ) -> None:
        content = self.query_one("#fw-content", Static)
        if firewall is None:
            content.update("Waiting for first firewall event…")
            return

        lines = [
            f"[b]{firewall.name}[/b]",
            "",
            f"[dim]Resource group[/]  {firewall.resource_group or '-'}",
            f"[dim]Subscription  [/]  {firewall.subscription_id or '-'}",
            f"[dim]Location      [/]  {firewall.location or '-'}",
            f"[dim]SKU tier      [/]  {(policy.sku_tier if policy else firewall.sku_tier) or '-'}",
            f"[dim]Policy        [/]  {(policy.name if policy else firewall.policy_id) or '-'}",
            "",
            f"[dim]Private IPs   [/]  {', '.join(firewall.private_ips) if firewall.private_ips else '-'}",
            f"[dim]Subnet CIDRs  [/]  {', '.join(subnet_cidrs) if subnet_cidrs else '-'}",
            f"[dim]Subnet IDs    [/]  {', '.join(firewall.subnet_ids) if firewall.subnet_ids else '-'}",
        ]
        content.update("\n".join(lines))
