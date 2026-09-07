"""Firewall tab: four panels — Instance, Networking, Policy, Logging — in a 2×2 grid."""
from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Grid, Vertical
from textual.widgets import DataTable, Static

from ..azure_resources import DiagnosticSetting, FirewallInfo, FirewallPolicyInfo, IpConfig

# What this viewer can render; anything of these not forwarded to an Event Hub
# is worth a line, because it explains a category that never shows up.
VIEWER_CATEGORIES = [
    "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule", "AZFWThreatIntel", "AZFWIdpsSignature",
    "AZFWDnsQuery", "AZFWFqdnResolveFailure", "AZFWFlowTrace", "AZFWFatFlow",
]
_ADDITIONAL_PREFIX = "Network.AdditionalLogs."
_LABEL_WIDTH = 18


def _v(value: str) -> str:
    return escape(value) if value else "-"


def _row(label: str, value: str) -> str:
    return f"[dim]{label.ljust(_LABEL_WIDTH)}[/]  {value}"


def _short(resource_id: str) -> str:
    return resource_id.rsplit("/", 1)[-1] if resource_id else ""


def _config_label(name: str) -> str:
    """``AzureFirewallIpConfiguration0`` → ``IpConfiguration0``: the prefix says nothing."""
    return name[len("AzureFirewall"):] if name.startswith("AzureFirewall") and len(name) > len("AzureFirewall") else name


class FirewallView(Vertical):
    """Everything ARM says about the instance, laid out so the eye can rest."""

    DEFAULT_CSS = """
    FirewallView {
        height: 1fr;
        padding: 0 1;
    }
    FirewallView > #fw-title {
        height: auto;
        padding: 1 1 1 1;
        text-style: bold;
    }
    FirewallView > #fw-grid {
        grid-size: 2 2;
        grid-gutter: 1 2;
        height: 1fr;
    }
    FirewallView .panel {
        border: round $primary;
        border-title-color: $text;
        border-title-style: bold;
        padding: 0 1;
        height: 1fr;
    }
    FirewallView .panel > Static {
        height: auto;
    }
    FirewallView .panel > DataTable {
        height: auto;
        max-height: 14;
    }
    FirewallView .panel > .panel-note {
        color: $text-muted;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("Waiting for first firewall event…", id="fw-title", markup=True)
        with Grid(id="fw-grid"):
            with Vertical(classes="panel", id="panel-instance"):
                yield Static("", id="fw-instance", markup=True)
            with Vertical(classes="panel", id="panel-network"):
                yield DataTable(id="fw-network", cursor_type="none", zebra_stripes=True)
                yield Static("", id="fw-network-note", classes="panel-note", markup=True)
            with Vertical(classes="panel", id="panel-policy"):
                yield Static("", id="fw-policy", markup=True)
            with Vertical(classes="panel", id="panel-logging"):
                yield DataTable(id="fw-logging", cursor_type="none", zebra_stripes=True)
                yield Static("", id="fw-logging-note", classes="panel-note", markup=True)

    def on_mount(self) -> None:
        for pid, title in (("#panel-instance", "Instance"), ("#panel-network", "Networking"),
                           ("#panel-policy", "Policy"), ("#panel-logging", "Logging")):
            self.query_one(pid, Vertical).border_title = title
        self.query_one("#fw-network", DataTable).add_columns("Configuration", "Private IP", "Public IP")
        self.query_one("#fw-logging", DataTable).add_columns("Setting", "Target")
        self.query_one("#fw-grid", Grid).display = False

    def render_data(
        self,
        firewall: FirewallInfo | None,
        policy: FirewallPolicyInfo | None,
        subnet_cidrs: list[str],
        diagnostics: list[DiagnosticSetting] | None = None,
    ) -> None:
        title = self.query_one("#fw-title", Static)
        grid = self.query_one("#fw-grid", Grid)
        if firewall is None:
            title.update("Waiting for first firewall event…")
            grid.display = False
            return
        tier = policy.sku_tier if policy and policy.sku_tier else firewall.sku_tier
        title.update(f"{escape(firewall.name)}   [dim]{escape(' · '.join(filter(None, [tier, firewall.sku_name, firewall.location])))}[/]")
        grid.display = True
        self.query_one("#fw-instance", Static).update("\n".join(self._instance(firewall)))
        self._fill_network(firewall, subnet_cidrs)
        self.query_one("#fw-policy", Static).update("\n".join(self._policy(policy, firewall)))
        self._fill_logging(diagnostics or [])

    # ── Instance ────────────────────────────────────────────────────────────
    @staticmethod
    def _instance(fw: FirewallInfo) -> list[str]:
        state = fw.provisioning_state or "-"
        if state not in ("Succeeded", "-"):
            state = f"[red]{escape(state)}[/]"
        tags = ", ".join(f"{escape(k)}={escape(v)}" for k, v in sorted(fw.tags.items()))
        extras = {k[len(_ADDITIONAL_PREFIX):] if k.startswith(_ADDITIONAL_PREFIX) else k: v
                  for k, v in fw.additional_properties.items()}
        return [
            _row("SKU", _v(" · ".join(filter(None, [fw.sku_tier, fw.sku_name])))),
            _row("Zones", _v(", ".join(fw.zones)) if fw.zones else "none (regional)"),
            _row("Provisioning", state),
            _row("Resource group", _v(fw.resource_group)),
            _row("Subscription", _v(fw.subscription_id)),
            _row("Location", _v(fw.location)),
            _row("Tags", tags or "-"),
            _row("Additional", ", ".join(f"{escape(k)}={escape(v)}" for k, v in sorted(extras.items())) or "-"),
        ]

    # ── Networking ──────────────────────────────────────────────────────────
    def _fill_network(self, fw: FirewallInfo, subnet_cidrs: list[str]) -> None:
        tbl = self.query_one("#fw-network", DataTable)
        tbl.clear()
        rows: list[tuple[str, IpConfig]] = [(_config_label(c.name), c) for c in fw.ip_configs]
        if fw.management_ip is not None:
            rows.append(("management", fw.management_ip))
        for label, cfg in rows:
            # name on the first line, address on the second: half a screen is narrow
            public = Text(cfg.public_ip_name or "-")
            if cfg.public_ip_name:
                public.append("\n" + (cfg.public_ip_address or "address not readable"),
                              style="" if cfg.public_ip_address else "dim")
            tbl.add_row(Text(label, style="dim"), cfg.private_ip or "-", public, height=2 if cfg.public_ip_name else 1)
        if not rows:
            tbl.add_row(Text("no IP configurations", style="dim"), ", ".join(fw.private_ips) or "-", "-")
        subnets = ", ".join(f"{_short(s)}" for s in fw.subnet_ids) or "-"
        note = self.query_one("#fw-network-note", Static)
        note.update("\n".join([
            _row("Subnets", escape(subnets)),
            _row("CIDRs", _v(", ".join(subnet_cidrs))),
            _row("Management", "forced tunneling (own subnet and public IP)" if fw.management_ip else "none"),
        ]))

    # ── Policy ──────────────────────────────────────────────────────────────
    @staticmethod
    def _policy(policy: FirewallPolicyInfo | None, fw: FirewallInfo) -> list[str]:
        if policy is None:
            return [
                _row("Policy", _v(_short(fw.policy_id)) if fw.policy_id else "none attached"),
                _row("Threat intel", _v(fw.threat_intel_mode)),
            ]
        own = len(policy.rule_collection_groups)
        inherited = len(policy.parent.all_groups()) if policy.parent else 0
        groups = f"{own} rule collection groups" + (f" (+{inherited} inherited)" if inherited else "")
        state = policy.provisioning_state
        state = f"   [red]{escape(state)}[/]" if state and state != "Succeeded" else ""
        base = policy.parent.name if policy.parent else _short(policy.base_policy_id)
        allow = []
        if policy.threat_intel_allow_fqdns:
            allow.append(f"{len(policy.threat_intel_allow_fqdns)} FQDNs")
        if policy.threat_intel_allow_ips:
            allow.append(f"{len(policy.threat_intel_allow_ips)} IPs")
        out = [
            _row("Policy", f"{escape(policy.name)}{state}"),
            _row("Groups", escape(groups)),
            _row("Base policy", _v(base) if base else "none"),
        ]
        if policy.child_policy_count:
            out.append(_row("Child policies", str(policy.child_policy_count)))
        out += [
            _row("Threat intel", _v(policy.threat_intel_mode)
                 + (f"   [dim]allowlist: {', '.join(allow)}[/]" if allow else "   [dim]no allowlist[/]")),
            _row("DNS proxy", (f"on   [dim]servers: {', '.join(escape(s) for s in policy.dns_servers) or 'Azure DNS'}[/]"
                               if policy.dns_proxy else "off")),
            _row("IDPS", (f"{escape(policy.idps_mode)}   [dim]{policy.idps_bypass_count} bypass rules · "
                          f"{policy.idps_override_count} signature overrides[/]" if policy.idps_mode else "off")),
            _row("TLS inspection", f"on   [dim]CA: {escape(policy.tls_ca_name)}[/]" if policy.tls_ca_name else "off"),
            _row("SNAT ranges", _v(", ".join(policy.snat_private_ranges)) if policy.snat_private_ranges else "default (RFC 1918)"),
            _row("Explicit proxy", "on" if policy.explicit_proxy else "off"),
        ]
        return out

    # ── Logging ─────────────────────────────────────────────────────────────
    def _fill_logging(self, diagnostics: list[DiagnosticSetting]) -> None:
        tbl = self.query_one("#fw-logging", DataTable)
        tbl.clear()
        note = self.query_one("#fw-logging-note", Static)
        if not diagnostics:
            tbl.add_row(Text("no diagnostic settings readable", style="dim"), "-")
            note.update("")
            return
        forwarded: set[str] = set()
        for d in diagnostics:
            targets = []
            if d.event_hub:
                targets.append(f"Event Hub {d.event_hub}")
            if d.workspace:
                targets.append(f"Log Analytics {d.workspace}")
            if d.storage:
                targets.append(f"Storage {d.storage}")
            if d.all_logs:
                cats = "all logs"
            else:
                viewer = sum(1 for c in d.categories if c in VIEWER_CATEGORIES)
                cats = f"{len(d.categories)} categories" + (f" · {viewer} of {len(VIEWER_CATEGORIES)} viewer" if viewer else "")
            target = Text(" + ".join(targets) or "no target")
            target.append("\n" + cats, style="dim")
            tbl.add_row(Text(d.name, style="dim"), target, height=2)
            if d.event_hub:
                forwarded |= set(VIEWER_CATEGORIES) if d.all_logs else set(d.categories)
        missing = [c for c in VIEWER_CATEGORIES if c not in forwarded]
        if missing:
            note.update(_row("Not to Event Hub", "[yellow]" + escape(", ".join(missing)) + "[/]"))
        else:
            note.update(_row("Not to Event Hub", "none — every viewer category is forwarded"))
