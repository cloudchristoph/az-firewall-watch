"""Typed dataclasses and fetchers for Azure Firewall management-plane data.

All functions take an :class:`viewer.arm.ArmClient` and return plain dataclasses
that are JSON-serialisable via :func:`dataclasses.asdict`. The cache layer
relies on this.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from .arm import ArmClient, ArmError

# API versions — pinned for predictable shapes.
# 2024-03-01 is the first version that returns autoscaleConfiguration on the
# firewall; an older one silently drops it and a prescaled firewall would read
# as "service default". Policies and IP groups are unchanged between the two.
_API_FW = "2024-03-01"          # azureFirewalls, firewallPolicies, ipGroups
_API_NET = "2024-01-01"         # virtualNetworks / subnets / publicIPAddresses / natGateways
_API_DIAG = "2021-05-01-preview"  # Microsoft.Insights/diagnosticSettings
_API_MAINT = "2023-04-01"       # Microsoft.Maintenance configurationAssignments / maintenanceConfigurations

# The firewall's association with an Azure Route Server (needed for auto-learn
# SNAT) is not a field of its own but an entry in the free-form property bag.
ROUTE_SERVER_KEY = "Network.RouteServerInfo.RouteServerID"


@dataclass
class IpGroupInfo:
    id: str
    name: str
    location: str
    ip_addresses: list[str] = field(default_factory=list)


@dataclass
class HttpHeader:
    """One header an application rule inserts (``httpHeadersToInsert``).

    ARM names the fields ``headerName`` / ``headerValue``; the value may carry
    a token or a tenant id, so views show it only on request.
    """
    name: str
    value: str = ""


@dataclass
class Rule:
    name: str
    rule_type: str = ""                     # NetworkRule | ApplicationRule | NatRule
    source_addresses: list[str] = field(default_factory=list)
    source_ip_groups: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    destination_ip_groups: list[str] = field(default_factory=list)
    destination_fqdns: list[str] = field(default_factory=list)
    destination_ports: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    # application-rule extras the trace cannot evaluate locally (reported as "unknown")
    fqdn_tags: list[str] = field(default_factory=list)
    web_categories: list[str] = field(default_factory=list)
    target_urls: list[str] = field(default_factory=list)
    # DNAT extras
    translated_address: str = ""
    translated_fqdn: str = ""
    translated_port: str = ""
    # application-rule extras that change what the rule *does* to a flow
    http_headers: list[HttpHeader] = field(default_factory=list)   # httpHeadersToInsert
    terminate_tls: bool = False                                      # terminateTLS (TLS inspection on this rule)

    @property
    def kind(self) -> str:
        """``dnat`` | ``network`` | ``application`` derived from the ARM ruleType."""
        return _rule_kind(self.rule_type)


@dataclass
class RuleCollection:
    name: str
    priority: int = 0
    action: str = ""
    rule_collection_type: str = ""
    rules: list[Rule] = field(default_factory=list)

    @property
    def kind(self) -> str:
        """``dnat`` | ``network`` | ``application``.

        NAT collections have their own ARM type; filter collections are typed
        by their (homogeneous) rules.
        """
        if "nat" in (self.rule_collection_type or "").lower():
            return "dnat"
        for r in self.rules:
            if r.rule_type:
                return r.kind
        return "network"


def _rule_kind(rule_type: str) -> str:
    t = (rule_type or "").lower()
    if "nat" in t:
        return "dnat"
    if "application" in t:
        return "application"
    return "network"


@dataclass
class RuleCollectionGroup:
    id: str
    name: str
    priority: int = 0
    rule_collections: list[RuleCollection] = field(default_factory=list)


@dataclass
class FirewallPolicyInfo:
    id: str
    name: str
    sku_tier: str = ""           # Standard | Premium | Basic
    threat_intel_mode: str = ""
    base_policy_id: str = ""
    rule_collection_groups: list[RuleCollectionGroup] = field(default_factory=list)
    # policy-level settings shown on the Firewall tab
    provisioning_state: str = ""
    dns_proxy: bool = False
    dns_servers: list[str] = field(default_factory=list)
    threat_intel_allow_fqdns: list[str] = field(default_factory=list)
    threat_intel_allow_ips: list[str] = field(default_factory=list)
    idps_mode: str = ""
    idps_bypass_count: int = 0
    idps_override_count: int = 0
    tls_ca_name: str = ""
    snat_private_ranges: list[str] = field(default_factory=list)
    snat_auto_learn: str = ""    # snat.autoLearnPrivateRanges: "Enabled" | "Disabled" | "" when absent
    explicit_proxy: bool = False
    # explicitProxy.* — 0 / "" when absent. pac_file keeps the blob URL without
    # its query string: Azure stores it as a SAS URL and the token must never
    # reach the cache file or a screenshot.
    explicit_proxy_http_port: int = 0
    explicit_proxy_https_port: int = 0
    explicit_proxy_pac: bool = False
    explicit_proxy_pac_port: int = 0
    explicit_proxy_pac_file: str = ""
    child_policy_count: int = 0
    # Inherited (parent) policy, if any. Its groups are always evaluated
    # before this policy's groups, per rule type.
    parent: FirewallPolicyInfo | None = None

    def all_groups(self) -> list[tuple[str, RuleCollectionGroup]]:
        """Groups in firewall evaluation order within one rule-type pass:
        parent policy first (by priority), then this policy (by priority).
        Returns ``(policy_name, group)`` tuples."""
        out: list[tuple[str, RuleCollectionGroup]] = []
        if self.parent is not None:
            out.extend(self.parent.all_groups())
        out.extend((self.name, g) for g in sorted(self.rule_collection_groups, key=lambda g: g.priority))
        return out


@dataclass
class IpConfig:
    """One firewall IP configuration (data plane or management)."""
    name: str
    private_ip: str = ""
    public_ip_id: str = ""
    public_ip_name: str = ""
    public_ip_address: str = ""   # filled by fetch_public_ips (needs Reader on the PIP)
    subnet_id: str = ""


@dataclass
class DiagnosticSetting:
    """A diagnostic setting on the firewall: where which log categories go."""
    name: str
    event_hub: str = ""           # "namespace/hub" when the setting targets an Event Hub
    workspace: str = ""           # Log Analytics workspace name
    storage: str = ""             # storage account name
    categories: list[str] = field(default_factory=list)   # enabled categories
    all_logs: bool = False        # categoryGroup allLogs / audit covers everything


@dataclass
class SubnetInfo:
    """A firewall subnet: its prefixes and, if attached, the NAT gateway."""
    id: str
    name: str = ""
    cidrs: list[str] = field(default_factory=list)
    nat_gateway_id: str = ""      # properties.natGateway.id


@dataclass
class NatGatewayInfo:
    """A NAT gateway attached to a firewall subnet (outbound SNAT leaves through it)."""
    id: str
    name: str = ""
    subnet_name: str = ""         # the firewall subnet it is attached to
    readable: bool = False        # False: only the id from the subnet is known (no Reader on the gateway)
    public_ip_ids: list[str] = field(default_factory=list)
    public_ip_names: list[str] = field(default_factory=list)
    public_ip_addresses: list[str] = field(default_factory=list)   # resolved best effort
    public_ip_prefix_names: list[str] = field(default_factory=list)


@dataclass
class MaintenanceWindow:
    """A customer-controlled maintenance window assigned to the firewall.

    Built from a ``Microsoft.Maintenance/configurationAssignments`` entry under
    the firewall and, when readable, the maintenance configuration it points to.
    """
    assignment_name: str
    configuration_id: str = ""
    configuration_name: str = ""
    readable: bool = False        # the configuration itself could be read (Reader on its resource group)
    start: str = ""               # maintenanceWindow.startDateTime, "YYYY-MM-DD hh:mm" as Azure writes it
    duration: str = ""            # maintenanceWindow.duration, "hh:mm"
    time_zone: str = ""           # maintenanceWindow.timeZone, e.g. "W. Europe Standard Time"
    recur_every: str = ""         # maintenanceWindow.recurEvery, "Day" for firewalls
    expiration: str = ""          # maintenanceWindow.expirationDateTime
    scope: str = ""               # maintenanceScope, "Resource" for firewalls
    sub_scope: str = ""           # extensionProperties.maintenanceSubScope, "NetworkSecurity"


@dataclass
class FirewallInfo:
    id: str
    name: str
    subscription_id: str
    resource_group: str
    location: str
    sku_tier: str = ""
    private_ips: list[str] = field(default_factory=list)
    subnet_ids: list[str] = field(default_factory=list)
    subnet_cidrs: list[str] = field(default_factory=list)
    policy_id: str = ""
    # instance details (all from the same GET)
    sku_name: str = ""            # AZFW_VNet | AZFW_Hub
    zones: list[str] = field(default_factory=list)
    provisioning_state: str = ""
    threat_intel_mode: str = ""   # firewall-level (classic) mode; the policy's wins when a policy is attached
    ip_configs: list[IpConfig] = field(default_factory=list)
    management_ip: IpConfig | None = None
    additional_properties: dict[str, str] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    # autoscaleConfiguration.minCapacity / maxCapacity; 0 when the field is absent
    # (service default). Equal values mean a fixed capacity with autoscaling off.
    autoscale_min: int = 0
    autoscale_max: int = 0
    # additionalProperties[ROUTE_SERVER_KEY]: the Route Server auto-learn SNAT needs
    route_server_id: str = ""


def parse_resource_id(resource_id: str) -> dict[str, str]:
    """Extract sub/RG/name from any ARM resource ID. Case-insensitive."""
    out: dict[str, str] = {}
    m = re.search(r"/subscriptions/([^/]+)", resource_id, re.IGNORECASE)
    if m:
        out["subscription_id"] = m.group(1)
    m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
    if m:
        out["resource_group"] = m.group(1)
    m = re.search(r"/providers/[^/]+/[^/]+/([^/]+)$", resource_id, re.IGNORECASE)
    if m:
        out["name"] = m.group(1)
    return out


async def fetch_firewall(arm: ArmClient, firewall_id: str) -> FirewallInfo:
    raw = await arm.get(firewall_id, _API_FW)
    props = raw.get("properties") or {}
    # ARM returns the id with its real casing; the diagnostics resourceId is upper-cased
    ids = parse_resource_id(raw.get("id") or firewall_id)

    private_ips: list[str] = []
    subnet_ids: list[str] = []
    ip_configs: list[IpConfig] = []
    for cfg in props.get("ipConfigurations") or []:
        ipc = _parse_ip_config(cfg)
        ip_configs.append(ipc)
        if ipc.private_ip:
            private_ips.append(ipc.private_ip)
        if ipc.subnet_id and ipc.subnet_id not in subnet_ids:
            subnet_ids.append(ipc.subnet_id)
    mgmt = props.get("managementIpConfiguration") or {}
    management_ip: IpConfig | None = None
    if isinstance(mgmt, dict) and mgmt:
        management_ip = _parse_ip_config(mgmt)
        if management_ip.subnet_id and management_ip.subnet_id not in subnet_ids:
            subnet_ids.append(management_ip.subnet_id)

    # The REST API returns the firewall SKU under properties.sku; the Azure
    # CLI flattens it to the top level, so accept both.
    sku = raw.get("sku") or props.get("sku") or {}
    policy_id = ((props.get("firewallPolicy") or {}).get("id")) or ""
    extra = props.get("additionalProperties") or {}
    if not isinstance(extra, dict):
        extra = {}
    autoscale = props.get("autoscaleConfiguration") or {}
    if not isinstance(autoscale, dict):
        autoscale = {}

    return FirewallInfo(
        id=raw.get("id") or firewall_id,
        name=raw.get("name") or ids.get("name", ""),
        subscription_id=ids.get("subscription_id", ""),
        resource_group=ids.get("resource_group", ""),
        location=raw.get("location") or "",
        sku_tier=sku.get("tier") or "",
        private_ips=private_ips,
        subnet_ids=subnet_ids,
        policy_id=policy_id,
        sku_name=sku.get("name") or "",
        zones=sorted(str(z) for z in (raw.get("zones") or [])),
        provisioning_state=props.get("provisioningState") or "",
        threat_intel_mode=props.get("threatIntelMode") or "",
        ip_configs=ip_configs,
        management_ip=management_ip,
        additional_properties={str(k): str(v) for k, v in extra.items()},
        tags={str(k): str(v) for k, v in (raw.get("tags") or {}).items()},
        autoscale_min=_int(autoscale.get("minCapacity")),
        autoscale_max=_int(autoscale.get("maxCapacity")),
        route_server_id=str(extra.get(ROUTE_SERVER_KEY) or ""),
    )


def _int(value: object) -> int:
    """An ARM integer field, ``0`` when absent, null or unreadable."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _parse_ip_config(cfg: dict) -> IpConfig:
    cprops = cfg.get("properties") or {}
    pip_id = ((cprops.get("publicIPAddress") or {}).get("id")) or ""
    return IpConfig(
        name=cfg.get("name") or "",
        private_ip=cprops.get("privateIPAddress") or "",
        public_ip_id=pip_id,
        public_ip_name=pip_id.rsplit("/", 1)[-1] if pip_id else "",
        subnet_id=((cprops.get("subnet") or {}).get("id")) or "",
    )


async def fetch_public_ips(arm: ArmClient, pip_ids: list[str]) -> dict[str, str]:
    """Resolve public IP resource ids to addresses; unreadable ones are left out."""
    out: dict[str, str] = {}
    for pid in pip_ids:
        try:
            raw = await arm.get(pid, _API_NET)
        except ArmError:
            continue
        addr = (raw.get("properties") or {}).get("ipAddress")
        if addr:
            out[pid] = addr
    return out


def _segment_after(resource_id: str, key: str) -> str:
    parts = (resource_id or "").split("/")
    for i, p in enumerate(parts):
        if p.lower() == key.lower() and i + 1 < len(parts):
            return parts[i + 1]
    return ""


async def fetch_diagnostic_settings(arm: ArmClient, firewall_id: str) -> list[DiagnosticSetting]:
    """The firewall's diagnostic settings: which categories go where (Reader suffices)."""
    items = await arm.get_all(f"{firewall_id}/providers/Microsoft.Insights/diagnosticSettings", _API_DIAG)
    out: list[DiagnosticSetting] = []
    for item in items:
        props = item.get("properties") or {}
        rule_id = props.get("eventHubAuthorizationRuleId") or ""
        ns = _segment_after(rule_id, "namespaces")
        hub = props.get("eventHubName") or ""
        categories: list[str] = []
        all_logs = False
        for log in props.get("logs") or []:
            if not log.get("enabled"):
                continue
            if log.get("categoryGroup"):
                all_logs = True
            elif log.get("category"):
                categories.append(log["category"])
        out.append(DiagnosticSetting(
            name=item.get("name") or "",
            event_hub=f"{ns}/{hub}" if ns and hub else (ns or hub),
            workspace=(props.get("workspaceId") or "").rsplit("/", 1)[-1],
            storage=(props.get("storageAccountId") or "").rsplit("/", 1)[-1],
            categories=categories,
            all_logs=all_logs,
        ))
    return out


async def fetch_subnet(arm: ArmClient, subnet_id: str) -> SubnetInfo:
    """One firewall subnet: prefixes plus the NAT gateway attached to it, if any."""
    raw = await arm.get(subnet_id, _API_NET)
    props = raw.get("properties") or {}
    cidrs: list[str] = []
    prefix = props.get("addressPrefix")
    if prefix:
        cidrs.append(prefix)
    for p in props.get("addressPrefixes") or []:
        if p and p not in cidrs:
            cidrs.append(p)
    nat = props.get("natGateway") or {}
    return SubnetInfo(
        id=raw.get("id") or subnet_id,
        name=raw.get("name") or subnet_id.rsplit("/", 1)[-1],
        cidrs=cidrs,
        nat_gateway_id=(nat.get("id") if isinstance(nat, dict) else "") or "",
    )


async def fetch_subnets(arm: ArmClient, subnet_ids: list[str]) -> list[SubnetInfo]:
    """The readable firewall subnets, in the order given; unreadable ones are left out."""
    if not subnet_ids:
        return []
    results = await asyncio.gather(
        *(fetch_subnet(arm, sid) for sid in subnet_ids),
        return_exceptions=True,
    )
    return [r for r in results if isinstance(r, SubnetInfo)]


def subnet_cidrs(subnets: list[SubnetInfo]) -> list[str]:
    """Every distinct prefix of *subnets* (what the ``AzFw.<n>`` rendering needs)."""
    out: list[str] = []
    for s in subnets:
        for c in s.cidrs:
            if c not in out:
                out.append(c)
    return out


async def fetch_subnet_cidrs(arm: ArmClient, subnet_id: str) -> list[str]:
    return (await fetch_subnet(arm, subnet_id)).cidrs


async def fetch_all_subnet_cidrs(arm: ArmClient, subnet_ids: list[str]) -> list[str]:
    return subnet_cidrs(await fetch_subnets(arm, subnet_ids))


async def fetch_nat_gateway(arm: ArmClient, gateway_id: str, subnet_name: str = "") -> NatGatewayInfo:
    """The NAT gateway behind ``subnet.nat_gateway_id``.

    Never raises: without Reader on the gateway the result only carries the id
    (``readable=False``), which is still worth a line on the Firewall tab.
    Public IP addresses are resolved separately with :func:`fetch_public_ips`.
    """
    return NatGatewayInfo(id=gateway_id, subnet_name=subnet_name)  # TODO(0.6.0 point 3): implement


async def fetch_nat_gateways(arm: ArmClient, subnets: list[SubnetInfo]) -> list[NatGatewayInfo]:
    """One :class:`NatGatewayInfo` per subnet that has a gateway attached."""
    return []  # TODO(0.6.0 point 3): implement


async def fetch_maintenance(arm: ArmClient, firewall_id: str) -> list[MaintenanceWindow]:
    """Customer-controlled maintenance windows assigned to the firewall.

    Lists ``{firewall}/providers/Microsoft.Maintenance/configurationAssignments``
    and reads each configuration it points to. Never raises: an unregistered
    ``Microsoft.Maintenance`` provider or missing rights simply mean there is
    nothing to read, and a configuration that cannot be read is returned with
    ``readable=False`` so the tab can still name it.
    """
    return []  # TODO(0.6.0 point 5): implement


def _parse_rule(raw: dict) -> Rule:
    # Network rules: ipProtocols=["TCP"] + destinationPorts=["443"].
    # Application rules: protocols=[{"protocolType": "Https", "port": 443}] —
    # the port lives inside the protocol entry, so lift it into
    # destination_ports for uniform port matching.
    protocols: list[str] = []
    ports: list[str] = [str(p) for p in (raw.get("destinationPorts") or [])]
    for p in raw.get("ipProtocols") or raw.get("protocols") or []:
        if isinstance(p, dict):
            protocols.append(str(p.get("protocolType") or ""))
            port = p.get("port")
            if port is not None and str(port) not in ports:
                ports.append(str(port))
        else:
            protocols.append(str(p))
    return Rule(
        name=raw.get("name") or "",
        rule_type=raw.get("ruleType") or "",
        source_addresses=list(raw.get("sourceAddresses") or []),
        source_ip_groups=list(raw.get("sourceIpGroups") or []),
        destination_addresses=list(raw.get("destinationAddresses") or []),
        destination_ip_groups=list(raw.get("destinationIpGroups") or []),
        # network rules carry destinationFqdns, application rules targetFqdns
        destination_fqdns=list(raw.get("targetFqdns") or raw.get("destinationFqdns") or []),
        destination_ports=ports,
        protocols=protocols,
        fqdn_tags=list(raw.get("fqdnTags") or []),
        web_categories=list(raw.get("webCategories") or []),
        target_urls=list(raw.get("targetUrls") or []),
        translated_address=str(raw.get("translatedAddress") or ""),
        translated_fqdn=str(raw.get("translatedFqdn") or ""),
        translated_port=str(raw.get("translatedPort") or ""),
        http_headers=[HttpHeader(name=str(h.get("headerName") or ""), value=str(h.get("headerValue") or ""))
                      for h in (raw.get("httpHeadersToInsert") or []) if isinstance(h, dict)],
        terminate_tls=bool(raw.get("terminateTLS")),
    )


def _parse_rule_collection(raw: dict) -> RuleCollection:
    action = ""
    act = raw.get("action") or {}
    if isinstance(act, dict):
        action = act.get("type") or ""
    return RuleCollection(
        name=raw.get("name") or "",
        priority=int(raw.get("priority") or 0),
        action=action,
        rule_collection_type=raw.get("ruleCollectionType") or "",
        rules=[_parse_rule(r) for r in (raw.get("rules") or [])],
    )


async def fetch_policy(arm: ArmClient, policy_id: str) -> FirewallPolicyInfo:
    raw = await arm.get(policy_id, _API_FW)
    props = raw.get("properties") or {}
    sku_tier = ((raw.get("sku") or props.get("sku") or {}).get("tier")) or ""
    threat_intel_mode = props.get("threatIntelMode") or ""
    base_policy_id = ((props.get("basePolicy") or {}).get("id")) or ""
    dns = props.get("dnsSettings") or {}
    allow = props.get("threatIntelWhitelist") or {}
    idps = props.get("intrusionDetection") or {}
    idps_cfg = idps.get("configuration") or {}
    tls = ((props.get("transportSecurity") or {}).get("certificateAuthority") or {})
    snat = props.get("snat") or {}
    explicit = props.get("explicitProxy") or {}

    rcg_items = await arm.get_all(f"{policy_id}/ruleCollectionGroups", _API_FW)
    groups: list[RuleCollectionGroup] = []
    for item in rcg_items:
        gprops = item.get("properties") or {}
        groups.append(RuleCollectionGroup(
            id=item.get("id") or "",
            name=item.get("name") or "",
            priority=int(gprops.get("priority") or 0),
            rule_collections=[_parse_rule_collection(rc)
                              for rc in (gprops.get("ruleCollections") or [])],
        ))
    groups.sort(key=lambda g: g.priority)

    ids = parse_resource_id(policy_id)
    return FirewallPolicyInfo(
        id=raw.get("id") or policy_id,
        name=raw.get("name") or ids.get("name", ""),
        sku_tier=sku_tier,
        threat_intel_mode=threat_intel_mode,
        provisioning_state=props.get("provisioningState") or "",
        dns_proxy=bool(dns.get("enableProxy")),
        dns_servers=list(dns.get("servers") or []),
        threat_intel_allow_fqdns=list(allow.get("fqdns") or []),
        threat_intel_allow_ips=list(allow.get("ipAddresses") or []),
        idps_mode=idps.get("mode") or "",
        idps_bypass_count=len(idps_cfg.get("bypassTrafficSettings") or []),
        idps_override_count=len(idps_cfg.get("signatureOverrides") or []),
        tls_ca_name=tls.get("name") or "",
        snat_private_ranges=list(snat.get("privateRanges") or []),
        snat_auto_learn=str(snat.get("autoLearnPrivateRanges") or ""),
        explicit_proxy=bool(explicit.get("enableExplicitProxy")),
        explicit_proxy_http_port=_int(explicit.get("httpPort")),
        explicit_proxy_https_port=_int(explicit.get("httpsPort")),
        explicit_proxy_pac=bool(explicit.get("enablePacFile")),
        explicit_proxy_pac_port=_int(explicit.get("pacFilePort")),
        explicit_proxy_pac_file=_strip_query(str(explicit.get("pacFile") or "")),
        child_policy_count=len(props.get("childPolicies") or []),
        base_policy_id=base_policy_id,
        rule_collection_groups=groups,
    )


def _strip_query(url: str) -> str:
    """A URL without its query string: a PAC file URL is a SAS URL, and the
    token in its query must not be cached or shown."""
    return url.split("?", 1)[0]


def collect_ip_group_ids(policy: FirewallPolicyInfo) -> list[str]:
    """All IP-group IDs referenced by *policy* and its parent chain."""
    seen: set[str] = set()
    for _policy_name, g in policy.all_groups():
        for rc in g.rule_collections:
            for r in rc.rules:
                seen.update(r.source_ip_groups)
                seen.update(r.destination_ip_groups)
    return sorted(seen)


async def fetch_policy_chain(arm: ArmClient, policy_id: str, max_depth: int = 4) -> FirewallPolicyInfo:
    """Fetch a policy and, best effort, its parent chain (``basePolicy``).

    A parent that cannot be read (RBAC, deleted) is left as ``None``; the
    child is still returned so the viewer degrades gracefully.
    """
    policy = await fetch_policy(arm, policy_id)
    current = policy
    depth = 0
    while current.base_policy_id and depth < max_depth:
        try:
            parent = await fetch_policy(arm, current.base_policy_id)
        except ArmError:
            break
        current.parent = parent
        current = parent
        depth += 1
    return policy


async def fetch_ip_group(arm: ArmClient, ip_group_id: str) -> IpGroupInfo:
    raw = await arm.get(ip_group_id, _API_FW)
    props = raw.get("properties") or {}
    ids = parse_resource_id(ip_group_id)
    return IpGroupInfo(
        id=raw.get("id") or ip_group_id,
        name=raw.get("name") or ids.get("name", ""),
        location=raw.get("location") or "",
        ip_addresses=list(props.get("ipAddresses") or []),
    )


async def fetch_ip_groups(arm: ArmClient, ip_group_ids: list[str]) -> dict[str, IpGroupInfo]:
    if not ip_group_ids:
        return {}
    results = await asyncio.gather(
        *(fetch_ip_group(arm, gid) for gid in ip_group_ids),
        return_exceptions=True,
    )
    out: dict[str, IpGroupInfo] = {}
    for gid, r in zip(ip_group_ids, results, strict=True):
        if isinstance(r, IpGroupInfo):
            out[gid] = r
        # silently skip groups we couldn't read (likely RBAC)
    return out


__all__ = [
    "ArmError", "ROUTE_SERVER_KEY",
    "IpGroupInfo", "HttpHeader", "Rule", "RuleCollection", "RuleCollectionGroup",
    "FirewallPolicyInfo", "FirewallInfo", "IpConfig", "DiagnosticSetting",
    "SubnetInfo", "NatGatewayInfo", "MaintenanceWindow",
    "parse_resource_id",
    "fetch_firewall", "fetch_subnet", "fetch_subnets", "subnet_cidrs",
    "fetch_subnet_cidrs", "fetch_all_subnet_cidrs",
    "fetch_nat_gateway", "fetch_nat_gateways", "fetch_maintenance",
    "fetch_public_ips", "fetch_diagnostic_settings",
    "fetch_policy", "fetch_policy_chain", "fetch_ip_group", "fetch_ip_groups",
    "collect_ip_group_ids",
]
