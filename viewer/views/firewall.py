"""Firewall tab: four panels — Instance, Networking, Policy, Logging — in a 2×2 grid."""
from __future__ import annotations

from datetime import date

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Grid, Vertical
from textual.widgets import DataTable, Static

from ..azure_resources import (
    ROUTE_SERVER_KEY,
    DiagnosticSetting,
    FirewallInfo,
    FirewallPolicyInfo,
    IpConfig,
    MaintenanceWindow,
    NatGatewayInfo,
    SubnetInfo,
)

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


def _note(text: str) -> str:
    """A continuation line under a row: indented to the value column, dimmed."""
    return f"{' ' * (_LABEL_WIDTH + 2)}[dim]{text}[/]"


def _short(resource_id: str) -> str:
    return resource_id.rsplit("/", 1)[-1] if resource_id else ""


# ── 0.6.0 rows: one function per fact the tab used to be silent about ─────────
# Each returns ready Rich-markup lines (via _row / _note). Everything dynamic
# must go through escape(); every uncertain statement stays a statement about
# what is *not* known, never a guess.

def _scaling_rows(fw: FirewallInfo) -> list[str]:
    """Instance panel: how the firewall scales (``autoscaleConfiguration``).

    Three states: no configuration (service default, autoscaling up to 20
    capacity units), min != max (prescaled, autoscaling within the range),
    min == max (fixed capacity, autoscaling off — the state one overlooks in
    the portal). Basic does not scale at all.
    """
    if fw.sku_tier == "Basic":
        return [_row("Scaling", "none   [dim]the Basic SKU does not scale[/]")]
    lo, hi = fw.autoscale_min, fw.autoscale_max
    if lo == 0 and hi == 0:
        return [_row("Scaling", "autoscaling, service default   [dim]up to 20 capacity units[/]")]
    if lo > 0 and hi > 0 and lo > hi:
        return [_row("Scaling", f"[yellow]min {lo} above max {hi}: configuration not understood[/]")]
    if lo > 0 and hi > 0 and lo == hi:
        return [_row("Scaling", f"[yellow]fixed at {lo} capacity units, autoscaling off[/]")]
    if lo > 0 and hi > 0 and lo < hi:
        return [_row("Scaling", f"autoscaling between {lo} and {hi} capacity units   [dim]prescaled[/]")]
    if lo > 0 and hi == 0:
        return [_row("Scaling", f"autoscaling from {lo} capacity units   [dim]no upper bound set[/]")]
    return [_row("Scaling", f"autoscaling up to {hi} capacity units")]


def _split_start(value: str) -> tuple[date | None, str]:
    """Split an Azure ``"YYYY-MM-DD hh:mm"`` timestamp into its date and the
    remainder. Returns ``(None, value)`` when it does not parse — the raw
    string is then shown as-is rather than guessed at."""
    if not value:
        return None, ""
    head, _, rest = value.partition(" ")
    try:
        d = date.fromisoformat(head)
    except ValueError:
        return None, value
    return d, rest or value


def _duration_human(duration: str) -> str:
    """``"05:00"`` → ``"5 h"``, ``"05:30"`` → ``"5 h 30 min"``; unparseable
    values (or a bare "hh") are shown verbatim rather than guessed at."""
    parts = duration.split(":")
    if len(parts) != 2:
        return duration
    try:
        hours, minutes = int(parts[0]), int(parts[1])
    except ValueError:
        return duration
    out = f"{hours} h"
    if minutes:
        out += f" {minutes} min"
    return out


_MAINTENANCE_SENTINEL_YEAR = 9999  # expirationDateTime "9999-12-31 23:59" means "no expiration"


def _maintenance_window_rows(w: MaintenanceWindow) -> list[str]:
    """The row (and, for a readable window, its note) for one assignment."""
    name = escape(w.configuration_name or w.assignment_name)
    if not w.readable:
        return [_row("Maintenance",
                     f"assigned: {name}   [dim]window not readable (no Reader on the maintenance configuration)[/]")]

    exp_date, _ = _split_start(w.expiration)
    exp_open = exp_date is not None and exp_date.year != _MAINTENANCE_SENTINEL_YEAR
    if exp_open and exp_date is not None and exp_date < date.today():
        return [_row("Maintenance", f"[yellow]expired {exp_date.isoformat()}[/]   [dim]{name}[/]")]

    start_date, start_time = _split_start(w.start)
    prefix = f"from {start_date.isoformat()}, " if start_date is not None and start_date > date.today() else ""
    recur = "daily" if w.recur_every == "Day" else (f"every {escape(w.recur_every)}" if w.recur_every else "")
    body = " ".join(filter(None, [recur, escape(start_time)]))
    value = f"{prefix}{body} for {_duration_human(w.duration)}, {escape(w.time_zone)}"
    if exp_open and exp_date is not None:
        value += f" until {exp_date.isoformat()}"
    if w.sub_scope and w.sub_scope != "NetworkSecurity":
        value += f"   [yellow]subscope {escape(w.sub_scope)}: not a firewall maintenance window[/]"
    return [
        _row("Maintenance", f"{value}   [dim]{name}[/]"),
        _note("covers guest OS and service updates; host updates and urgent security fixes can fall outside the window"),
    ]


def _maintenance_rows(fw: FirewallInfo, maintenance: list[MaintenanceWindow]) -> list[str]:
    """Instance panel: the customer-controlled maintenance window, if any.

    Says what the window covers (guest OS and service updates) and what it
    does not (host updates, urgent security fixes), so a RST burst outside
    the window is not read as proof of an incident.
    """
    if not maintenance:
        return [_row("Maintenance", "no customer-controlled window   [dim]Azure picks the time for updates[/]")]
    out: list[str] = []
    for w in maintenance:
        out.extend(_maintenance_window_rows(w))
    return out


def _nat_gateway_rows(fw: FirewallInfo, subnets: list[SubnetInfo], nat_gateways: list[NatGatewayInfo]) -> list[str]:
    """Networking panel: which public address outbound traffic really leaves with.

    With a NAT gateway on the firewall subnet, outbound SNAT uses the
    gateway's public IPs while DNAT and management traffic stay on the
    firewall's own. A Virtual WAN hub firewall (``AZFW_Hub``) cannot have one.
    """
    return []  # TODO(0.6.0 point 3): implement


def _explicit_proxy_rows(policy: FirewallPolicyInfo) -> list[str]:
    """Policy panel: explicit proxy with its ports and the PAC file."""
    return [_row("Explicit proxy", "on" if policy.explicit_proxy else "off")]  # TODO(0.6.0 point 1): implement


_LEARNED_NOTE = "learned ranges are not readable from here: listing them is a POST action, and this tool only reads"


def _snat_rows(policy: FirewallPolicyInfo, fw: FirewallInfo) -> list[str]:
    """Policy panel: SNAT private ranges plus auto-learn and its Route Server.

    Auto-learn on without a Route Server on the firewall means nothing is ever
    learned; auto-learn on with one means the effective list is learned by
    BGP every 30 minutes and is not readable from here (a POST action).
    """
    ranges = (escape(", ".join(policy.snat_private_ranges)) if policy.snat_private_ranges
              else "default (RFC 1918 and RFC 6598)")
    rows = [
        _row("SNAT ranges", ranges),
        _note("applies to network rules only; application rules are always SNATed"),
    ]
    if policy.snat_auto_learn != "Enabled":
        rows.append(_row("Auto-learn SNAT", "off"))
        return rows
    if fw.sku_name == "AZFW_Hub":
        rows.append(_row("Auto-learn SNAT", "on   [dim]via the hub's built-in Route Server[/]"))
        rows.append(_note(_LEARNED_NOTE))
    elif fw.route_server_id:
        rs_name = escape(_short(fw.route_server_id))
        rows.append(_row("Auto-learn SNAT", f"on   [dim]via Route Server {rs_name}[/]"))
        rows.append(_note(_LEARNED_NOTE))
    else:
        rows.append(_row("Auto-learn SNAT",
                          "[yellow]on, but no Route Server is associated with the firewall: "
                          "nothing is ever learned[/]"))
    return rows


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
        self.query_one("#fw-logging", DataTable).add_columns("Diagnostic setting → target")
        self.query_one("#fw-grid", Grid).display = False

    def render_data(
        self,
        firewall: FirewallInfo | None,
        policy: FirewallPolicyInfo | None,
        subnet_cidrs: list[str],
        diagnostics: list[DiagnosticSetting] | None = None,
        *,
        subnets: list[SubnetInfo] | None = None,
        nat_gateways: list[NatGatewayInfo] | None = None,
        maintenance: list[MaintenanceWindow] | None = None,
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
        self.query_one("#fw-instance", Static).update("\n".join(self._instance(firewall, maintenance or [])))
        self._fill_network(firewall, subnet_cidrs, subnets or [], nat_gateways or [])
        self.query_one("#fw-policy", Static).update("\n".join(self._policy(policy, firewall)))
        self._fill_logging(diagnostics or [])

    # ── Instance ────────────────────────────────────────────────────────────
    @staticmethod
    def _instance(fw: FirewallInfo, maintenance: list[MaintenanceWindow]) -> list[str]:
        state = fw.provisioning_state or "-"
        if state not in ("Succeeded", "-"):
            state = f"[red]{escape(state)}[/]"
        tags = ", ".join(f"{escape(k)}={escape(v)}" for k, v in sorted(fw.tags.items()))
        # The Route Server association has its own row (see _snat_rows).
        extras = {k[len(_ADDITIONAL_PREFIX):] if k.startswith(_ADDITIONAL_PREFIX) else k: v
                  for k, v in fw.additional_properties.items() if k != ROUTE_SERVER_KEY}
        return [
            _row("SKU", _v(" · ".join(filter(None, [fw.sku_tier, fw.sku_name])))),
            _row("Zones", _v(", ".join(fw.zones)) if fw.zones else "none (regional)"),
            _row("Provisioning", state),
            *_scaling_rows(fw),
            *_maintenance_rows(fw, maintenance),
            _row("Resource group", _v(fw.resource_group)),
            _row("Subscription", _v(fw.subscription_id)),
            _row("Location", _v(fw.location)),
            _row("Tags", tags or "-"),
            _row("Additional", ", ".join(f"{escape(k)}={escape(v)}" for k, v in sorted(extras.items())) or "-"),
        ]

    # ── Networking ──────────────────────────────────────────────────────────
    def _fill_network(self, fw: FirewallInfo, subnet_cidrs: list[str],
                      subnets: list[SubnetInfo], nat_gateways: list[NatGatewayInfo]) -> None:
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
        subnet_names = ", ".join(f"{_short(s)}" for s in fw.subnet_ids) or "-"
        note = self.query_one("#fw-network-note", Static)
        note.update("\n".join([
            _row("Subnets", escape(subnet_names)),
            _row("CIDRs", _v(", ".join(subnet_cidrs))),
            _row("Management", "forced tunneling (own subnet and public IP)" if fw.management_ip else "none"),
            *_nat_gateway_rows(fw, subnets, nat_gateways),
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
            *_snat_rows(policy, fw),
            *_explicit_proxy_rows(policy),
        ]
        return out

    # ── Logging ─────────────────────────────────────────────────────────────
    def _fill_logging(self, diagnostics: list[DiagnosticSetting]) -> None:
        tbl = self.query_one("#fw-logging", DataTable)
        tbl.clear()
        note = self.query_one("#fw-logging-note", Static)
        if not diagnostics:
            tbl.add_row(Text("no diagnostic settings readable", style="dim"))
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
            cell = Text(d.name)
            cell.append("\n  " + (" + ".join(targets) or "no target"))
            cell.append(" · " + cats, style="dim")
            tbl.add_row(cell, height=2)
            if d.event_hub:
                forwarded |= set(VIEWER_CATEGORIES) if d.all_logs else set(d.categories)
        missing = [c for c in VIEWER_CATEGORIES if c not in forwarded]
        if missing:
            note.update(_row("Not to Event Hub", "[yellow]" + escape(", ".join(missing)) + "[/]"))
        else:
            note.update(_row("Not to Event Hub", "none — every viewer category is forwarded"))
