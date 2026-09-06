"""ARM resource parsing (viewer/azure_resources.py) against canned payloads."""
from __future__ import annotations

import pytest

from viewer.arm import ArmError
from viewer.azure_resources import (
    collect_ip_group_ids,
    fetch_all_subnet_cidrs,
    fetch_firewall,
    fetch_ip_group,
    fetch_ip_groups,
    fetch_policy,
    fetch_subnet_cidrs,
    parse_resource_id,
)

SUB = "/subscriptions/25ca1d83-3de5-46c7-9941-fb98c2ea026e"
FW_ID = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/azureFirewalls/fw-hub-gwc"
POLICY_ID = f"{SUB}/resourceGroups/rg-hub-firewallpolicy-gwc/providers/Microsoft.Network/firewallPolicies/fwp-hub-premium-gwc"
VNET = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/virtualNetworks/vnet-hub-gwc"
SUBNET = f"{VNET}/subnets/AzureFirewallSubnet"
MGMT_SUBNET = f"{VNET}/subnets/AzureFirewallManagementSubnet"
G_SPOKES = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/ipGroups/ipgroup-all-spokes"
G_ONPREM = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/ipGroups/ipgroup-onpremises"


class FakeArm:
    """Stand-in for ArmClient: answers GETs from a path → payload map."""

    def __init__(self, routes: dict) -> None:
        self.routes = routes
        self.calls: list[str] = []

    async def get(self, path: str, api_version: str, *, params=None) -> dict:
        self.calls.append(path)
        if path not in self.routes:
            raise ArmError(404, "ResourceNotFound", f"no route for {path}")
        payload = self.routes[path]
        if isinstance(payload, Exception):
            raise payload
        return payload

    async def get_all(self, path: str, api_version: str, *, params=None) -> list:
        self.calls.append(path)
        payload = self.routes.get(path, {"value": []})
        if isinstance(payload, Exception):
            raise payload
        return list(payload.get("value", []))


FIREWALL_JSON = {
    "id": FW_ID, "name": "fw-hub-gwc", "location": "germanywestcentral",
    "sku": {"name": "AZFW_VNet", "tier": "Premium"},
    "properties": {
        "ipConfigurations": [
            {"name": "ipconfig", "properties": {"privateIPAddress": "10.2.0.4", "subnet": {"id": SUBNET}}},
            {"name": "ipconfig2", "properties": {"privateIPAddress": "10.2.0.4", "subnet": {"id": SUBNET}}},
        ],
        "managementIpConfiguration": {"properties": {"subnet": {"id": MGMT_SUBNET}}},
        "firewallPolicy": {"id": POLICY_ID},
    },
}

POLICY_JSON = {
    "id": POLICY_ID, "name": "fwp-hub-premium-gwc",
    "properties": {"sku": {"tier": "Premium"}, "threatIntelMode": "Alert", "basePolicy": {"id": f"{SUB}/base"}},
}

RCG_JSON = {"value": [
    {"id": f"{POLICY_ID}/ruleCollectionGroups/net", "name": "cclab-network-rule-collection-group",
     "properties": {"priority": 2000, "ruleCollections": [
         {"name": "azure-monitor-access", "priority": 100, "action": {"type": "Allow"},
          "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
          "rules": [{"name": "allow-azure-monitor", "ruleType": "NetworkRule",
                     "sourceIpGroups": [G_SPOKES], "destinationAddresses": ["AzureMonitor"],
                     "destinationPorts": ["443"], "ipProtocols": ["TCP"]}]},
     ]}},
    {"id": f"{POLICY_ID}/ruleCollectionGroups/app", "name": "cclab-application-rule-collection-group",
     "properties": {"priority": 100, "ruleCollections": [
         {"name": "outbound-access-demo-app-rules", "priority": 200, "action": {"type": "Allow"},
          "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
          "rules": [{"name": "allow-outbound-web-traffic", "ruleType": "ApplicationRule",
                     "sourceIpGroups": [G_SPOKES, G_ONPREM], "destinationFqdns": ["*.duckduckgo.com"],
                     "protocols": [{"protocolType": "Https", "port": 443}, {"protocolType": "Http", "port": 80}]}]},
     ]}},
]}


def _routes(**extra):
    routes = {
        FW_ID: FIREWALL_JSON,
        POLICY_ID: POLICY_JSON,
        f"{POLICY_ID}/ruleCollectionGroups": RCG_JSON,
        SUBNET: {"properties": {"addressPrefix": "10.2.0.0/26"}},
        MGMT_SUBNET: {"properties": {"addressPrefixes": ["10.2.0.64/26", "10.2.0.0/26"]}},
        G_SPOKES: {"id": G_SPOKES, "name": "ipgroup-all-spokes", "location": "germanywestcentral",
                   "properties": {"ipAddresses": ["10.3.0.0/16", "10.4.0.0/16"]}},
        G_ONPREM: {"id": G_ONPREM, "name": "ipgroup-onpremises", "location": "germanywestcentral",
                   "properties": {"ipAddresses": ["192.168.0.0/16"]}},
    }
    routes.update(extra)
    return routes


# ── parse_resource_id ────────────────────────────────────────────────────────

def test_parse_resource_id():
    assert parse_resource_id(FW_ID) == {
        "subscription_id": "25ca1d83-3de5-46c7-9941-fb98c2ea026e",
        "resource_group": "rg-hub-network-gwc",
        "name": "fw-hub-gwc",
    }


def test_parse_resource_id_is_case_insensitive_and_partial():
    assert parse_resource_id(FW_ID.upper())["name"] == "FW-HUB-GWC"
    assert parse_resource_id("nonsense") == {}


# ── firewall ─────────────────────────────────────────────────────────────────

async def test_fetch_firewall():
    fw = await fetch_firewall(FakeArm(_routes()), FW_ID)
    assert fw.name == "fw-hub-gwc"
    assert fw.subscription_id == "25ca1d83-3de5-46c7-9941-fb98c2ea026e"
    assert fw.resource_group == "rg-hub-network-gwc"
    assert fw.location == "germanywestcentral"
    assert fw.sku_tier == "Premium"
    assert fw.private_ips == ["10.2.0.4", "10.2.0.4"]
    assert fw.subnet_ids == [SUBNET, MGMT_SUBNET]  # de-duplicated, management subnet appended
    assert fw.policy_id == POLICY_ID


async def test_fetch_firewall_minimal_payload_falls_back_to_id_parts():
    fw = await fetch_firewall(FakeArm({FW_ID: {}}), FW_ID)
    assert fw.id == FW_ID
    assert fw.name == "fw-hub-gwc"
    assert fw.subnet_ids == [] and fw.private_ips == [] and fw.policy_id == ""


async def test_fetch_firewall_propagates_arm_error():
    with pytest.raises(ArmError):
        await fetch_firewall(FakeArm({}), FW_ID)


# ── subnets ──────────────────────────────────────────────────────────────────

async def test_fetch_subnet_cidrs_prefix_and_prefixes():
    arm = FakeArm(_routes())
    assert await fetch_subnet_cidrs(arm, SUBNET) == ["10.2.0.0/26"]
    assert await fetch_subnet_cidrs(arm, MGMT_SUBNET) == ["10.2.0.64/26", "10.2.0.0/26"]


async def test_fetch_all_subnet_cidrs_dedupes_and_tolerates_failures():
    arm = FakeArm(_routes())
    cidrs = await fetch_all_subnet_cidrs(arm, [SUBNET, MGMT_SUBNET, f"{VNET}/subnets/missing"])
    assert cidrs == ["10.2.0.0/26", "10.2.0.64/26"]
    assert await fetch_all_subnet_cidrs(arm, []) == []


# ── policy ───────────────────────────────────────────────────────────────────

async def test_fetch_policy_parses_groups_collections_rules():
    pol = await fetch_policy(FakeArm(_routes()), POLICY_ID)
    assert pol.name == "fwp-hub-premium-gwc"
    assert pol.sku_tier == "Premium"
    assert pol.threat_intel_mode == "Alert"
    assert pol.base_policy_id == f"{SUB}/base"
    # sorted by priority: app (100) before net (2000)
    assert [g.name for g in pol.rule_collection_groups] == [
        "cclab-application-rule-collection-group", "cclab-network-rule-collection-group",
    ]
    app_rc = pol.rule_collection_groups[0].rule_collections[0]
    assert (app_rc.name, app_rc.priority, app_rc.action) == ("outbound-access-demo-app-rules", 200, "Allow")
    app_rule = app_rc.rules[0]
    assert app_rule.rule_type == "ApplicationRule"
    assert app_rule.source_ip_groups == [G_SPOKES, G_ONPREM]
    assert app_rule.destination_fqdns == ["*.duckduckgo.com"]
    assert app_rule.protocols == ["Https", "Http"]  # dict protocols reduced to their type
    net_rule = pol.rule_collection_groups[1].rule_collections[0].rules[0]
    assert net_rule.protocols == ["TCP"]
    assert net_rule.destination_ports == ["443"]


async def test_fetch_policy_sku_at_top_level():
    routes = _routes()
    routes[POLICY_ID] = {"id": POLICY_ID, "name": "p", "sku": {"tier": "Standard"}, "properties": {}}
    pol = await fetch_policy(FakeArm(routes), POLICY_ID)
    assert pol.sku_tier == "Standard"
    assert pol.rule_collection_groups[0].name  # groups still fetched


def test_collect_ip_group_ids_is_sorted_and_unique():
    pol = FIREWALL_JSON and None  # placeholder to keep flake-free
    from viewer.azure_resources import FirewallPolicyInfo, Rule, RuleCollection, RuleCollectionGroup
    policy = FirewallPolicyInfo(id="/p", name="p", rule_collection_groups=[
        RuleCollectionGroup(id="/g", name="g", rule_collections=[
            RuleCollection(name="rc", rules=[
                Rule(name="a", source_ip_groups=["/z", "/a"], destination_ip_groups=["/a"]),
                Rule(name="b", destination_ip_groups=["/m"]),
            ]),
        ]),
    ])
    assert collect_ip_group_ids(policy) == ["/a", "/m", "/z"]


# ── IP groups ────────────────────────────────────────────────────────────────

async def test_fetch_ip_group():
    grp = await fetch_ip_group(FakeArm(_routes()), G_SPOKES)
    assert grp.name == "ipgroup-all-spokes"
    assert grp.ip_addresses == ["10.3.0.0/16", "10.4.0.0/16"]
    assert grp.location == "germanywestcentral"


async def test_fetch_ip_groups_skips_unreadable_groups():
    groups = await fetch_ip_groups(FakeArm(_routes()), [G_SPOKES, f"{SUB}/ipGroups/forbidden", G_ONPREM])
    assert set(groups) == {G_SPOKES, G_ONPREM}
    assert groups[G_ONPREM].ip_addresses == ["192.168.0.0/16"]
    assert await fetch_ip_groups(FakeArm(_routes()), []) == {}
