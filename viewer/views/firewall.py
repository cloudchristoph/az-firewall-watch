"""Firewall tab: everything ARM says about the instance, its policy and its logging."""
from __future__ import annotations

from rich.markup import escape
from textual.app import ComposeResult
from textual.widgets import Static

from ..azure_resources import DiagnosticSetting, FirewallInfo, FirewallPolicyInfo, IpConfig

# What this viewer can render; anything of these not forwarded to an Event Hub
# is worth a line, because it explains a category that never shows up.
VIEWER_CATEGORIES = [
    "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule", "AZFWThreatIntel", "AZFWIdpsSignature",
    "AZFWDnsQuery", "AZFWFqdnResolveFailure", "AZFWFlowTrace", "AZFWFatFlow",
]
_ADDITIONAL_PREFIX = "Network.AdditionalLogs."


def _v(value: str) -> str:
    return escape(value) if value else "-"


_LABEL_WIDTH = 18


def _row(label: str, value: str, width: int = _LABEL_WIDTH) -> str:
    return f"[dim]{label.ljust(width)}[/]  {value}"


def _head(title: str) -> str:
    return f"\n[b]{title}[/b]"


def _ip_config_line(cfg: IpConfig) -> str:
    parts = []
    if cfg.private_ip:
        parts.append(escape(cfg.private_ip))
    if cfg.public_ip_name:
        pip = escape(cfg.public_ip_name)
        if cfg.public_ip_address:
            pip += f" ({escape(cfg.public_ip_address)})"
        parts.append(pip)
    return "  →  ".join(parts) + f"   [dim]{escape(cfg.name)}[/]"


class FirewallView(Static):
    """Renders firewall-level metadata in four blocks: Instance, Networking, Policy, Logging."""

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
        diagnostics: list[DiagnosticSetting] | None = None,
    ) -> None:
        content = self.query_one("#fw-content", Static)
        if firewall is None:
            content.update("Waiting for first firewall event…")
            return
        lines = [f"[b]{escape(firewall.name)}[/b]"]
        lines += self._instance(firewall, policy)
        lines += self._networking(firewall, subnet_cidrs)
        lines += self._policy(policy, firewall)
        lines += self._logging(diagnostics or [])
        content.update("\n".join(lines))

    # ── blocks ──────────────────────────────────────────────────────────────
    @staticmethod
    def _instance(fw: FirewallInfo, policy: FirewallPolicyInfo | None) -> list[str]:
        tier = policy.sku_tier if policy and policy.sku_tier else fw.sku_tier
        sku = " · ".join(filter(None, [tier, fw.sku_name]))
        state = fw.provisioning_state
        if state and state != "Succeeded":
            state = f"[red]{escape(state)}[/]"
        tags = ", ".join(f"{escape(k)}={escape(v)}" for k, v in sorted(fw.tags.items()))
        return [
            _head("Instance"),
            _row("SKU", _v(sku)),
            _row("Zones", _v(", ".join(fw.zones)) if fw.zones else "none (regional)"),
            _row("Provisioning", state or "-"),
            _row("Resource group", _v(fw.resource_group)),
            _row("Subscription", _v(fw.subscription_id)),
            _row("Location", _v(fw.location)),
            _row("Tags", tags or "-"),
        ]

    @staticmethod
    def _networking(fw: FirewallInfo, subnet_cidrs: list[str]) -> list[str]:
        out = [_head("Networking")]
        if fw.ip_configs:
            for i, cfg in enumerate(fw.ip_configs):
                out.append(_row("IP config" if i == 0 else "", _ip_config_line(cfg)))
        else:
            out.append(_row("Private IPs", _v(", ".join(fw.private_ips))))
        if fw.management_ip is not None:
            out.append(_row("Management IP", _ip_config_line(fw.management_ip) + "   [dim](forced tunneling)[/]"))
        else:
            out.append(_row("Management IP", "none"))
        subnets = [s.rsplit("/", 1)[-1] for s in fw.subnet_ids]
        out.append(_row("Subnets", _v(", ".join(subnets))))
        out.append(_row("Subnet CIDRs", _v(", ".join(subnet_cidrs))))
        extras = {k[len(_ADDITIONAL_PREFIX):] if k.startswith(_ADDITIONAL_PREFIX) else k: v
                  for k, v in fw.additional_properties.items()}
        if extras:
            out.append(_row("Additional", ", ".join(f"{escape(k)}={escape(v)}" for k, v in sorted(extras.items()))))
        return out

    @staticmethod
    def _policy(policy: FirewallPolicyInfo | None, fw: FirewallInfo) -> list[str]:
        out = [_head("Policy")]
        if policy is None:
            out.append(_row("Policy", _v(fw.policy_id.rsplit("/", 1)[-1] if fw.policy_id else "")))
            out.append(_row("Threat intel", _v(fw.threat_intel_mode)))
            return out
        own = len(policy.rule_collection_groups)
        inherited = len(policy.parent.all_groups()) if policy.parent else 0
        groups = f"{own} rule collection groups" + (f" (+{inherited} inherited)" if inherited else "")
        state = policy.provisioning_state
        state = f"   [red]{escape(state)}[/]" if state and state != "Succeeded" else ""
        out.append(_row("Policy", f"{escape(policy.name)}   [dim]{escape(groups)}[/]{state}"))
        base = policy.parent.name if policy.parent else (policy.base_policy_id.rsplit("/", 1)[-1] if policy.base_policy_id else "")
        out.append(_row("Base policy", _v(base) if base else "none"))
        if policy.child_policy_count:
            out.append(_row("Child policies", str(policy.child_policy_count)))
        allow = []
        if policy.threat_intel_allow_fqdns:
            allow.append(f"{len(policy.threat_intel_allow_fqdns)} FQDNs")
        if policy.threat_intel_allow_ips:
            allow.append(f"{len(policy.threat_intel_allow_ips)} IPs")
        ti = _v(policy.threat_intel_mode) + ("   [dim]allowlist: " + ", ".join(allow) + "[/]" if allow else "   [dim]no allowlist[/]")
        out.append(_row("Threat intel", ti))
        if policy.dns_proxy:
            servers = ", ".join(escape(s) for s in policy.dns_servers) or "Azure DNS"
            out.append(_row("DNS proxy", f"on   [dim]servers: {servers}[/]"))
        else:
            out.append(_row("DNS proxy", "off"))
        if policy.idps_mode:
            out.append(_row("IDPS", f"{escape(policy.idps_mode)}   [dim]{policy.idps_bypass_count} bypass rules · "
                                    f"{policy.idps_override_count} signature overrides[/]"))
        else:
            out.append(_row("IDPS", "off"))
        out.append(_row("TLS inspection", f"on   [dim]CA: {escape(policy.tls_ca_name)}[/]" if policy.tls_ca_name else "off"))
        out.append(_row("SNAT ranges", _v(", ".join(policy.snat_private_ranges)) if policy.snat_private_ranges else "default (RFC 1918)"))
        out.append(_row("Explicit proxy", "on" if policy.explicit_proxy else "off"))
        return out

    @staticmethod
    def _logging(diagnostics: list[DiagnosticSetting]) -> list[str]:
        out = [_head("Logging")]
        if not diagnostics:
            out.append(_row("Diagnostics", "no diagnostic settings readable"))
            return out
        forwarded: set[str] = set()
        for d in diagnostics:
            targets = []
            if d.event_hub:
                targets.append(f"Event Hub {escape(d.event_hub)}")
            if d.workspace:
                targets.append(f"Log Analytics {escape(d.workspace)}")
            if d.storage:
                targets.append(f"Storage {escape(d.storage)}")
            cats = "all logs" if d.all_logs else ", ".join(escape(c) for c in d.categories) or "no categories"
            out.append(_row(d.name, f"{' + '.join(targets) or 'no target'}   [dim]{cats}[/]",
                            width=max(_LABEL_WIDTH, *(len(x.name) for x in diagnostics))))
            if d.event_hub:
                forwarded |= set(VIEWER_CATEGORIES) if d.all_logs else set(d.categories)
        missing = [c for c in VIEWER_CATEGORIES if c not in forwarded]
        if missing:
            out.append(_row("Not to Event Hub", "[yellow]" + escape(", ".join(missing)) + "[/]"))
        else:
            out.append(_row("Not to Event Hub", "none — every viewer category is forwarded"))
        return out
