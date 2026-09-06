"""Firewall metadata tab view."""
from __future__ import annotations

from rich.markup import escape
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

        def v(value: str) -> str:
            return escape(value) if value else "-"

        lines = [
            f"[b]{escape(firewall.name)}[/b]",
            "",
            f"[dim]Resource group[/]  {v(firewall.resource_group)}",
            f"[dim]Subscription  [/]  {v(firewall.subscription_id)}",
            f"[dim]Location      [/]  {v(firewall.location)}",
            f"[dim]SKU tier      [/]  {v((policy.sku_tier if policy else firewall.sku_tier))}",
            f"[dim]Policy        [/]  {v((policy.name if policy else firewall.policy_id))}",
            "",
            f"[dim]Private IPs   [/]  {v(', '.join(firewall.private_ips))}",
            f"[dim]Subnet CIDRs  [/]  {v(', '.join(subnet_cidrs))}",
            f"[dim]Subnet IDs    [/]  {v(', '.join(firewall.subnet_ids))}",
        ]
        content.update("\n".join(lines))
