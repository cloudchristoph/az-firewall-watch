"""Policy-context tools through the MCP protocol (in-memory client against the real server object)."""
from __future__ import annotations

import json
import time
from typing import Any

import pytest
from mcp.client.client import Client

from mcp_server.context import ContextHolder
from mcp_server.server import build_server
from mcp_server.state import AppState
from tests.test_mcp_tools_logs import call, call_error, make_state
from tests.test_trace import app, nat, net, policy, rc, rcg
from viewer.azure_resources import (
    DiagnosticSetting,
    FirewallInfo,
    HttpHeader,
    IpConfig,
    IpGroupInfo,
    MaintenanceWindow,
    NatGatewayInfo,
    SubnetInfo,
)
from viewer.cache import CachedSnapshot

POLICY_TOOLS = ("get_firewall", "get_policy", "list_rules", "get_rule", "list_ip_groups", "get_ip_group",
                "refresh_policy_context")

G_SPOKES = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipg-spokes"
G_DMZ = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/ipg-dmz"
G_GONE = "/subscriptions/s/resourceGroups/other/providers/Microsoft.Network/ipGroups/ipg-hidden"
HEADER_SECRET = "tenant-0000-SECRET-VALUE"
PAC_SAS = "sv=2024&sig=PACSECRET"

IP_GROUPS = {
    G_SPOKES: IpGroupInfo(id=G_SPOKES, name="ipg-spokes", location="gwc", ip_addresses=["10.3.0.0/16", "10.4.0.0/16"]),
    G_DMZ: IpGroupInfo(id=G_DMZ, name="ipg-dmz", location="gwc",
                       ip_addresses=["10.2.0.0-10.2.0.31", "fd00::10-fd00::1f"]),
}


def build_policy():
    base = policy(rcg("rcg-base", 100, rc("base-deny", 100, "Deny",
                                         net("deny-bad", destination_addresses=["203.0.113.0/24"]))),
                  name="pol-base")
    hub = policy(
        rcg("rcg-app", 100,
            rc("app-web", 200, "Allow",
               app("allow-web", source_addresses=[], source_ip_groups=[G_SPOKES], destination_fqdns=["*.example.com"],
                   protocols=["Http", "Https"], destination_ports=["80", "443"], terminate_tls=True,
                   http_headers=[HttpHeader(name="X-Tenant", value=HEADER_SECRET)]),
               app("allow-urls", source_addresses=["10.5.0.0/24"], target_urls=["www.contoso.com/path/*"],
                   protocols=["Https"], destination_ports=["443"],
                   http_headers=[HttpHeader(name="X-Plain", value=HEADER_SECRET)]),
               app("allow-tags", fqdn_tags=["WindowsUpdate"], web_categories=["News"]))),
        rcg("rcg-net", 2000,
            rc("net-allow", 200, "Allow",
               net("allow-dns", source_addresses=["10.0.0.0/8"], destination_addresses=["168.63.129.16"],
                   destination_ports=["53"], protocols=["UDP"]),
               net("allow-range", source_addresses=[], source_ip_groups=[G_DMZ], destination_addresses=["AzureMonitor"],
                   destination_ports=["8000-8100"], protocols=["TCP"]),
               net("allow-hidden", destination_addresses=[], destination_ip_groups=[G_GONE], destination_ports=["22"],
                   protocols=["TCP"]))),
        rcg("rcg-dnat", 300,
            rc("dnat-rdp", 100, "Dnat", nat("rdp", source_ip_groups=[G_SPOKES]),
               rc_type="FirewallPolicyNatRuleCollection")),
        name="pol-hub", parent=base)
    hub.dns_proxy = True
    hub.dns_servers = ["168.63.129.16"]
    hub.idps_mode = "Alert"
    hub.idps_bypass_count = 2
    hub.snat_private_ranges = ["IANAPrivateRanges"]
    hub.snat_auto_learn = "Enabled"
    hub.explicit_proxy = True
    hub.explicit_proxy_http_port = 8080
    hub.explicit_proxy_pac = True
    hub.explicit_proxy_pac_port = 8082
    hub.explicit_proxy_pac_file = f"https://st.blob.core.windows.net/pac/proxy.pac?{PAC_SAS}"
    hub.base_policy_id = base.id
    return hub


def build_snapshot(*, with_policy: bool = True, sku_tier: str = "Premium", autoscale: tuple[int, int] = (2, 10),
                   fetched_at: float | None = None) -> CachedSnapshot:
    fw = FirewallInfo(
        id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-hub", name="fw-hub",
        subscription_id="s", resource_group="rg", location="germanywestcentral", sku_tier=sku_tier,
        sku_name="AZFW_VNet", zones=["1", "2"], provisioning_state="Succeeded", private_ips=["10.1.0.4"],
        subnet_ids=["/sub/AzureFirewallSubnet"], policy_id="/pol-hub",
        ip_configs=[IpConfig(name="ipconfig1", private_ip="10.1.0.4", public_ip_name="pip-fw",
                             public_ip_address="20.1.1.1", public_ip_id="/pip/pip-fw",
                             subnet_id="/sub/AzureFirewallSubnet")],
        management_ip=IpConfig(name="mgmt", public_ip_name="pip-mgmt", public_ip_address="20.1.1.2"),
        additional_properties={"Network.SNAT.PrivateRanges": "IANAPrivateRanges"},
        tags={"env": "lab"}, autoscale_min=autoscale[0], autoscale_max=autoscale[1],
        route_server_id="/rs/route-server")
    return CachedSnapshot(
        firewall=fw, policy=build_policy() if with_policy else None, ip_groups=dict(IP_GROUPS),
        subnet_cidrs=["10.1.0.0/26"], fetched_at=time.time() - 30 if fetched_at is None else fetched_at,
        diagnostics=[DiagnosticSetting(name="to-hub", event_hub="ns/firewall-logs",
                                       categories=["AZFWNetworkRule", "AZFWApplicationRule"]),
                     DiagnosticSetting(name="to-law", workspace="law-hub", all_logs=True)],
        subnets=[SubnetInfo(id="/sub/AzureFirewallSubnet", name="AzureFirewallSubnet", cidrs=["10.1.0.0/26"],
                            nat_gateway_id="/ng/ngw-hub")],
        nat_gateways=[NatGatewayInfo(id="/ng/ngw-hub", name="ngw-hub", subnet_name="AzureFirewallSubnet",
                                     readable=True, public_ip_names=["pip-ngw"], public_ip_addresses=["20.1.1.3"])],
        maintenance=[MaintenanceWindow(assignment_name="nightly", configuration_name="mc-nightly", readable=True,
                                       start="2020-01-01 22:00", duration="05:00",
                                       time_zone="W. Europe Standard Time", recur_every="Day")],
    )


def loaded_state(snap: CachedSnapshot | None = None) -> AppState:
    holder = ContextHolder(enabled=True, firewall_id="/fw")
    holder.snapshot = snap or build_snapshot()
    return make_state(context=holder)


@pytest.fixture
def state() -> AppState:
    return loaded_state()


async def rules(state: AppState, **args: Any) -> list[str]:
    out = await call(state, "list_rules", args)
    return [r["ref"] for r in out["rules"]]


# ── tool list and the unavailable answer ─────────────────────────────────────

async def test_policy_tools_are_listed_with_annotations(state):
    async with Client(build_server(state.config, state=state)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(POLICY_TOOLS) <= set(tools)
    for name in POLICY_TOOLS[:-1]:
        ann = tools[name].annotations
        assert ann is not None and ann.read_only_hint is True and ann.destructive_hint is False
        assert tools[name].description
    refresh = tools["refresh_policy_context"].annotations
    assert refresh is not None and refresh.idempotent_hint is True and refresh.destructive_hint is False
    props = tools["list_rules"].input_schema["properties"]
    assert {"kind", "group", "collection", "action", "name", "address", "fqdn", "port", "ip_group", "limit",
            "offset"} <= set(props)
    assert "overlaps" in props["address"]["description"]
    assert "ctx" not in props


TOOL_ARGS: dict[str, dict[str, Any]] = {
    "get_firewall": {}, "get_policy": {}, "list_rules": {}, "get_rule": {"ref": "a » b » c"},
    "list_ip_groups": {}, "get_ip_group": {"name": "ipg-spokes"}, "refresh_policy_context": {},
}


@pytest.mark.parametrize("tool", POLICY_TOOLS)
@pytest.mark.parametrize("holder, expected_state", [
    (ContextHolder(enabled=False), "off"),
    (ContextHolder(enabled=True), "waiting_for_firewall_id"),
], ids=["off", "waiting"])
async def test_every_tool_answers_unavailable_without_context(tool, holder, expected_state):
    state = make_state(context=holder)
    out = await call(state, tool, TOOL_ARGS[tool])
    assert out["available"] is False and out["state"] == expected_state
    assert out["reason"] and out["hint"]


@pytest.mark.parametrize("tool", POLICY_TOOLS[:-1])
async def test_every_tool_answers_unavailable_while_loading_or_failed(tool):
    loading = make_state(context=ContextHolder(enabled=True, firewall_id="/fw"))
    out = await call(loading, tool, TOOL_ARGS[tool])
    assert (out["available"], out["state"]) == (False, "loading")
    failed_holder = ContextHolder(enabled=True, firewall_id="/fw")
    failed_holder.last_attempt_at = time.time()
    failed_holder.reason = "AuthorizationFailed on the firewall"
    out = await call(make_state(context=failed_holder), tool, TOOL_ARGS[tool])
    assert (out["available"], out["state"]) == (False, "unavailable")
    assert "AuthorizationFailed" in out["reason"]


@pytest.mark.parametrize("tool", ["get_policy", "list_rules", "get_rule"])
async def test_policy_tools_say_so_when_the_snapshot_has_no_policy(tool):
    state = loaded_state(build_snapshot(with_policy=False))
    out = await call(state, tool, TOOL_ARGS[tool])
    assert out["available"] is False and out["state"] == "loaded" and "carries no policy" in out["reason"]
    assert (await call(state, "get_firewall"))["name"] == "fw-hub"


# ── get_firewall ─────────────────────────────────────────────────────────────

async def test_get_firewall_shape(state):
    fw = await call(state, "get_firewall")
    assert (fw["name"], fw["sku_tier"], fw["sku_name"], fw["zones"]) == ("fw-hub", "Premium", "AZFW_VNet", ["1", "2"])
    assert 29 <= fw["cache_age_s"] < 60 and fw["fetched_at"].endswith("Z")
    assert fw["subnets"] == [{"id": "/sub/AzureFirewallSubnet", "name": "AzureFirewallSubnet",
                              "cidrs": ["10.1.0.0/26"], "nat_gateway_id": "/ng/ngw-hub"}]
    assert fw["subnet_cidrs"] == ["10.1.0.0/26"]
    gw = fw["nat_gateways"][0]
    assert (gw["name"], gw["readable"], gw["public_ip_addresses"], gw["subnet"]) == (
        "ngw-hub", True, ["20.1.1.3"], "AzureFirewallSubnet")
    assert fw["ip_configs"][0]["public_ip_address"] == "20.1.1.1"
    assert fw["management_ip"]["public_ip_address"] == "20.1.1.2" and fw["management_ip"]["private_ip"] is None
    assert fw["maintenance_readable"] is True
    window = fw["maintenance_windows"][0]
    assert (window["configuration_name"], window["start"], window["duration"], window["expiration"]) == (
        "mc-nightly", "2020-01-01 22:00", "05:00", None)
    assert fw["diagnostic_settings"] == [
        {"name": "to-hub", "targets": {"event_hub": "ns/firewall-logs", "workspace": None, "storage": None},
         "categories": ["AZFWNetworkRule", "AZFWApplicationRule"], "all_logs": False},
        {"name": "to-law", "targets": {"event_hub": None, "workspace": "law-hub", "storage": None},
         "categories": [], "all_logs": True},
    ]
    assert fw["autoscale"] == {"min": 2, "max": 10, "mode": "range"}
    assert fw["route_server_id"] == "/rs/route-server"
    assert fw["additional_properties"] == {"Network.SNAT.PrivateRanges": "IANAPrivateRanges"}
    assert fw["tags"] == {"env": "lab"}


@pytest.mark.parametrize("tier, bounds, expected", [
    ("Standard", (0, 0), {"min": None, "max": None, "mode": "service_default"}),
    ("Standard", (4, 4), {"min": 4, "max": 4, "mode": "fixed"}),
    ("Premium", (2, 10), {"min": 2, "max": 10, "mode": "range"}),
    ("Basic", (0, 0), {"min": None, "max": None, "mode": "not_supported"}),
    ("Standard", (5, 0), {"min": 5, "max": 0, "mode": "not_understood"}),
])
async def test_get_firewall_autoscale_modes(tier, bounds, expected):
    fw = await call(loaded_state(build_snapshot(sku_tier=tier, autoscale=bounds)), "get_firewall")
    assert fw["autoscale"] == expected


async def test_get_firewall_unreadable_maintenance_is_unknown_not_none():
    snap = build_snapshot()
    snap.maintenance, snap.maintenance_readable = [], False
    fw = await call(loaded_state(snap), "get_firewall")
    assert fw["maintenance_readable"] is False and fw["maintenance_windows"] == []


# ── get_policy ───────────────────────────────────────────────────────────────

async def test_get_policy_summary(state):
    pol = await call(state, "get_policy")
    assert (pol["name"], pol["sku_tier"]) == ("pol-hub", "Premium")
    assert pol["threat_intel"]["mode"] == "Alert"
    assert pol["dns"] == {"proxy": True, "servers": ["168.63.129.16"]}
    assert pol["idps"]["mode"] == "Alert" and pol["idps"]["bypass_count"] == 2
    assert pol["snat"] == {"private_ranges": ["IANAPrivateRanges"], "auto_learn": "Enabled"}
    proxy = pol["explicit_proxy"]
    assert (proxy["http_port"], proxy["https_port"], proxy["pac_port"]) == (8080, None, 8082)
    assert proxy["pac_file"] == "https://st.blob.core.windows.net/pac/proxy.pac"
    assert PAC_SAS not in json.dumps(pol)
    assert pol["parent"]["name"] == "pol-base" and pol["parent"]["parent"] is None
    assert "groups" not in pol["parent"]
    assert [(g["policy"], g["name"], g["inherited"]) for g in pol["groups"]] == [
        ("pol-base", "rcg-base", True), ("pol-hub", "rcg-app", False), ("pol-hub", "rcg-dnat", False),
        ("pol-hub", "rcg-net", False)]
    app_group = pol["groups"][1]
    assert (app_group["priority"], app_group["collection_count"], app_group["rule_count"]) == (100, 1, 3)
    assert app_group["collections"] == [{"name": "app-web", "priority": 200, "action": "Allow",
                                         "kind": "application", "rule_count": 3}]
    assert pol["groups"][2]["collections"][0]["kind"] == "dnat"
    assert pol["rule_count"] == 8 and pol["group_count"] == 4
    assert "rules" not in app_group["collections"][0]


async def test_get_policy_with_rules_hides_header_values(state):
    pol = await call(state, "get_policy", {"include_rules": True})
    web = pol["groups"][1]["collections"][0]["rules"][0]
    assert web["ref"] == "pol-hub » rcg-app » app-web » allow-web"
    assert web["http_headers"] == ["X-Tenant"]
    assert web["source_ip_groups"][0]["name"] == "ipg-spokes"
    assert HEADER_SECRET not in json.dumps(pol)


# ── list_rules ───────────────────────────────────────────────────────────────

async def test_list_rules_in_evaluation_order(state):
    out = await call(state, "list_rules")
    assert [r["ref"] for r in out["rules"]] == [
        "pol-hub » rcg-dnat » dnat-rdp » rdp",
        "pol-base » rcg-base » base-deny » deny-bad",
        "pol-hub » rcg-net » net-allow » allow-dns",
        "pol-hub » rcg-net » net-allow » allow-range",
        "pol-hub » rcg-net » net-allow » allow-hidden",
        "pol-hub » rcg-app » app-web » allow-web",
        "pol-hub » rcg-app » app-web » allow-urls",
        "pol-hub » rcg-app » app-web » allow-tags",
    ]
    assert (out["total"], out["returned"], out["offset"], out["has_more"], out["next_offset"]) == (8, 8, 0, False, None)
    first = out["rules"][0]
    assert (first["position"], first["kind"], first["action"], first["group_priority"],
            first["collection_priority"]) == (1, "dnat", "Dnat", 300, 100)
    assert first["translated"] == {"address": "10.3.5.4", "fqdn": None, "port": "3389"}
    assert first["source_ip_groups"] == ["ipg-spokes"]
    assert out["rules"][1]["inherited"] is True and out["rules"][1]["policy"] == "pol-base"
    hidden = out["rules"][4]
    assert hidden["destination_ip_groups"] == [G_GONE]
    web = out["rules"][5]
    assert web["terminate_tls"] is True and web["http_header_count"] == 1
    assert HEADER_SECRET not in json.dumps(out)


@pytest.mark.parametrize("args, expected", [
    ({"kind": "network"}, ["deny-bad", "allow-dns", "allow-range", "allow-hidden"]),
    ({"kind": "APP"}, ["allow-web", "allow-urls", "allow-tags"]),
    ({"kind": "dnat"}, ["rdp"]),
    ({"group": "RCG-NET"}, ["allow-dns", "allow-range", "allow-hidden"]),
    ({"collection": "base-deny"}, ["deny-bad"]),
    ({"action": "deny"}, ["deny-bad"]),
    ({"action": "DNAT"}, ["rdp"]),
    ({"name": "ALLOW-"}, ["allow-dns", "allow-range", "allow-hidden", "allow-web", "allow-urls", "allow-tags"]),
    ({"address": "10.3.5.4"}, ["rdp", "deny-bad", "allow-dns", "allow-hidden", "allow-web", "allow-tags"]),
    ({"address": "10.2.0.7", "kind": "network"}, ["deny-bad", "allow-dns", "allow-range", "allow-hidden"]),
    ({"address": "fd00::12", "group": "rcg-net"}, ["allow-range", "allow-hidden"]),
    ({"address": "203.0.113.9", "action": "deny"}, ["deny-bad"]),
    ({"fqdn": "www.example.com"}, ["allow-web"]),
    ({"fqdn": "contoso"}, ["allow-urls"]),
    ({"fqdn": "www.contoso.com", "name": "urls"}, ["allow-urls"]),
    ({"port": 8050}, ["deny-bad", "allow-range"]),
    ({"port": "53", "kind": "network", "group": "rcg-net"}, ["allow-dns"]),
    ({"port": 3389, "kind": "dnat"}, ["rdp"]),
    ({"ip_group": "ipg-spokes"}, ["rdp", "allow-web"]),
    ({"ip_group": G_DMZ.upper()}, ["allow-range"]),
    ({"ip_group": "ipg-hidden"}, ["allow-hidden"]),
])
async def test_list_rules_filters(state, args, expected):
    names = [ref.rsplit(" » ", 1)[-1] for ref in await rules(state, **args)]
    assert names == expected


async def test_list_rules_address_match_says_how(state):
    out = await call(state, "list_rules", {"address": "10.3.0.0/24", "kind": "application"})
    web = next(r for r in out["rules"] if r["name"] == "allow-web")
    assert web["address_match"] == {"source": {"entry": "10.3.0.0/16", "ip_group": "ipg-spokes",
                                               "relation": "contains"}}
    tags = next(r for r in out["rules"] if r["name"] == "allow-tags")
    assert tags["address_match"]["source"] == {"entry": "*", "ip_group": None, "relation": "wildcard"}
    # A wide CIDR is only partly inside the group's /16 entries: that is an overlap.
    wide = await call(state, "list_rules", {"address": "10.0.0.0/12", "name": "allow-web"})
    assert wide["rules"][0]["address_match"]["source"]["relation"] == "overlaps"
    # The direct /8 entry contains the /12 entirely.
    dns = await call(state, "list_rules", {"address": "10.0.0.0/12", "name": "allow-dns"})
    assert dns["rules"][0]["address_match"]["source"] == {"entry": "10.0.0.0/8", "ip_group": None,
                                                           "relation": "contains"}
    assert "address_match" not in (await call(state, "list_rules", {"name": "allow-dns"}))["rules"][0]


async def test_list_rules_paging(state):
    page1 = await call(state, "list_rules", {"limit": 3})
    assert (page1["returned"], page1["total"], page1["has_more"], page1["next_offset"]) == (3, 8, True, 3)
    page2 = await call(state, "list_rules", {"limit": 3, "offset": page1["next_offset"]})
    page3 = await call(state, "list_rules", {"limit": 3, "offset": page2["next_offset"]})
    assert (page3["returned"], page3["has_more"], page3["next_offset"]) == (2, False, None)
    refs = [r["ref"] for p in (page1, page2, page3) for r in p["rules"]]
    assert refs == [r["ref"] for r in (await call(state, "list_rules"))["rules"]]
    assert [r["position"] for r in page2["rules"]] == [4, 5, 6]
    assert (await call(state, "list_rules", {"limit": 0}))["returned"] == 1        # clamped up
    assert (await call(state, "list_rules", {"limit": 5000}))["returned"] == 8     # clamped down
    beyond = await call(state, "list_rules", {"offset": 50})
    assert (beyond["rules"], beyond["total"], beyond["has_more"]) == ([], 8, False)
    assert (await call(state, "list_rules", {"offset": -4}))["offset"] == 0


@pytest.mark.parametrize("args, message", [
    ({"kind": "firewall"}, "kind must be one of dnat, network, application"),
    ({"address": "10.0.0.300"}, "address must be an IP address or a CIDR"),
    ({"port": "https"}, "port must be a single port number"),
    ({"port": 70000}, "port must be a single port number"),
    ({"group": "rcg-nte"}, "Nearest: rcg-net"),
    ({"collection": "net-alow"}, "Nearest: net-allow"),
    ({"ip_group": "ipg-spoke"}, "Nearest IP groups: ipg-spokes"),
])
async def test_list_rules_rejects_bad_arguments_readably(state, args, message):
    assert message in await call_error(state, "list_rules", args)


# ── get_rule ─────────────────────────────────────────────────────────────────

async def test_get_rule_by_ref_resolves_ip_groups_and_hides_header_values(state):
    out = await call(state, "get_rule", {"ref": "pol-hub » rcg-app » app-web » allow-web"})
    assert (out["name"], out["kind"], out["action"], out["position"], out["inherited"]) == (
        "allow-web", "application", "Allow", 6, False)
    assert out["source_ip_groups"] == [{"id": G_SPOKES, "name": "ipg-spokes", "readable": True, "address_count": 2}]
    assert out["destination_fqdns"] == ["*.example.com"] and out["destination_ports"] == ["80", "443"]
    assert out["terminate_tls"] is True
    assert out["http_headers"] == ["X-Tenant"]
    assert out["inserted_headers_land_in"] == "inserted into HTTP and TLS-inspected HTTPS"
    assert HEADER_SECRET not in json.dumps(out)
    assert out["cache_age_s"] >= 0


async def test_get_rule_by_parts_and_short_ref(state):
    by_parts = await call(state, "get_rule", {"group": "rcg-net", "collection": "net-allow", "rule": "ALLOW-HIDDEN"})
    assert by_parts["ref"] == "pol-hub » rcg-net » net-allow » allow-hidden"
    assert by_parts["destination_ip_groups"] == [{"id": G_GONE, "name": None, "readable": False,
                                                  "address_count": None}]
    short = await call(state, "get_rule", {"ref": "rcg-base»base-deny»deny-bad"})
    assert short["inherited"] is True and short["policy"] == "pol-base"
    tui = await call(state, "get_rule", {"ref": "pol-hub|rcg-dnat|dnat-rdp|rdp"})
    assert tui["translated"] == {"address": "10.3.5.4", "fqdn": None, "port": "3389"}
    assert tui["inserted_headers_land_in"] is None and tui["http_headers"] == []


async def test_get_rule_headers_sentence_without_inspection(state):
    out = await call(state, "get_rule", {"ref": "rcg-app » app-web » allow-urls"})
    assert out["http_headers"] == ["X-Plain"] and out["terminate_tls"] is False
    assert out["inserted_headers_land_in"] == ("HTTPS without TLS inspection on this rule: no traffic this rule "
                                               "matches gets the headers")
    assert out["target_urls"] == ["www.contoso.com/path/*"]
    assert HEADER_SECRET not in json.dumps(out)


@pytest.mark.parametrize("args, message", [
    ({"ref": "pol-hub » rcg-app » app-web » allow-wbe"}, "No rule 'allow-wbe' in rcg-app » app-web. Nearest rules: "
                                                         "allow-web"),
    ({"ref": "rcg-ap » app-web » allow-web"}, "No rule collection group 'rcg-ap'. Nearest groups: rcg-app"),
    ({"group": "rcg-net", "collection": "net-deny", "rule": "x"}, "Nearest collections: net-allow"),
    ({"ref": "pol-other » rcg-app » app-web » allow-web"}, "No policy 'pol-other' in the loaded chain. Policies: "
                                                           "pol-base, pol-hub"),
    ({"ref": "just-a-name"}, "ref must look like 'policy » group » collection » rule'"),
    ({"group": "rcg-net"}, "by group, collection and rule together"),
    ({}, "by group, collection and rule together"),
])
async def test_get_rule_unknown_names_the_nearest(state, args, message):
    assert message in await call_error(state, "get_rule", args)


# ── IP groups ────────────────────────────────────────────────────────────────

async def test_list_ip_groups(state):
    out = await call(state, "list_ip_groups")
    assert out["total"] == 3
    by_name = {(g["name"] or g["id"]): g for g in out["ip_groups"]}
    assert by_name["ipg-spokes"] == {"id": G_SPOKES, "name": "ipg-spokes", "location": "gwc", "readable": True,
                                     "address_count": 2, "used_by": 2}
    assert by_name["ipg-dmz"]["used_by"] == 1
    hidden = by_name[G_GONE]
    assert hidden["readable"] is False and hidden["used_by"] == 1 and "Reader" in hidden["reason"]
    assert [g["name"] for g in (await call(state, "list_ip_groups", {"name": "DMZ"}))["ip_groups"]] == ["ipg-dmz"]
    assert (await call(state, "list_ip_groups", {"name": "hidden"}))["ip_groups"][0]["id"] == G_GONE


async def test_get_ip_group_by_name_and_id(state):
    out = await call(state, "get_ip_group", {"name": "IPG-SPOKES"})
    assert out["addresses"] == ["10.3.0.0/16", "10.4.0.0/16"] and out["address_count"] == 2
    assert out["used_by"] == [
        {"ref": "pol-hub » rcg-dnat » dnat-rdp » rdp", "kind": "dnat", "action": "Dnat", "sides": ["source"]},
        {"ref": "pol-hub » rcg-app » app-web » allow-web", "kind": "application", "action": "Allow",
         "sides": ["source"]},
    ]
    by_id = await call(state, "get_ip_group", {"id": G_DMZ})
    assert by_id["name"] == "ipg-dmz" and by_id["addresses"] == ["10.2.0.0-10.2.0.31", "fd00::10-fd00::1f"]


async def test_get_ip_group_unreadable_and_unknown(state):
    hidden = await call(state, "get_ip_group", {"name": "ipg-hidden"})
    assert (hidden["readable"], hidden["addresses"], hidden["id"]) == (False, None, G_GONE)
    assert hidden["used_by"][0]["sides"] == ["destination"]
    assert "Nearest IP groups: ipg-dmz" in await call_error(state, "get_ip_group", {"name": "ipg-dmzz"})
    assert "Pass the IP group's name or id" in await call_error(state, "get_ip_group", {})


# ── refresh_policy_context ───────────────────────────────────────────────────

async def test_refresh_forces_a_load_and_reports_fetched_at():
    calls: list[tuple[str, bool]] = []
    fresh = build_snapshot(fetched_at=time.time())

    async def loader(firewall_id: str, *, force: bool, errors: list[str]) -> CachedSnapshot:
        calls.append((firewall_id, force))
        return fresh

    holder = ContextHolder(enabled=True, firewall_id="/fw", loader=loader)
    state = make_state(context=holder)
    out = await call(state, "refresh_policy_context")
    assert calls == [("/fw", True)]
    assert (out["state"], out["available"], out["reason"]) == ("loaded", True, None)
    assert out["fetched_at"].endswith("Z") and out["age_s"] < 5
    assert (await call(state, "get_firewall"))["name"] == "fw-hub"


async def test_refresh_failure_keeps_the_previous_snapshot():
    async def loader(firewall_id: str, *, force: bool, errors: list[str]) -> None:
        errors.append("AuthorizationFailed")
        return None

    holder = ContextHolder(enabled=True, firewall_id="/fw", loader=loader)
    holder.snapshot = build_snapshot()
    out = await call(make_state(context=holder), "refresh_policy_context")
    assert (out["state"], out["available"]) == ("loaded", True)
    assert "previous snapshot stays in use: AuthorizationFailed" in out["reason"]

    empty = ContextHolder(enabled=True, firewall_id="/fw", loader=loader)
    out = await call(make_state(context=empty), "refresh_policy_context")
    assert (out["state"], out["available"], out["reason"]) == ("unavailable", False, "AuthorizationFailed")
