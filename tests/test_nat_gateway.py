"""NAT gateway on the firewall subnet: fetch, orchestration, cache, rendering."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

import viewer.cache as cache
import viewer.management as mgmt
from viewer.arm import ArmError
from viewer.azure_resources import (
    FirewallInfo,
    NatGatewayInfo,
    SubnetInfo,
    fetch_nat_gateway,
    fetch_nat_gateways,
    fetch_subnet,
)
from viewer.cache import CachedSnapshot
from viewer.views.firewall import _nat_gateway_rows, _note, _row

from .test_azure_resources import SUB, VNET, FakeArm

SUBNET = f"{VNET}/subnets/AzureFirewallSubnet"
NATGW = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/natGateways/natgw-hub"
PIP1 = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/publicIPAddresses/pip-natgw-1"
PIP2 = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/publicIPAddresses/pip-natgw-2"
PREFIX = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/publicIPPrefixes/pfx-natgw"


# ── fetch_subnet: properties.natGateway ─────────────────────────────────────

async def test_fetch_subnet_reads_nat_gateway_id_when_present():
    arm = FakeArm({SUBNET: {"properties": {"addressPrefix": "10.2.0.0/26", "natGateway": {"id": NATGW}}}})
    subnet = await fetch_subnet(arm, SUBNET)
    assert subnet.nat_gateway_id == NATGW


async def test_fetch_subnet_nat_gateway_absent():
    arm = FakeArm({SUBNET: {"properties": {"addressPrefix": "10.2.0.0/26"}}})
    subnet = await fetch_subnet(arm, SUBNET)
    assert subnet.nat_gateway_id == ""


async def test_fetch_subnet_nat_gateway_null():
    arm = FakeArm({SUBNET: {"properties": {"addressPrefix": "10.2.0.0/26", "natGateway": None}}})
    subnet = await fetch_subnet(arm, SUBNET)
    assert subnet.nat_gateway_id == ""


# ── fetch_nat_gateway ────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip_key,prefix_key", [
    ("publicIpAddresses", "publicIpPrefixes"),   # the documented NatGatewayPropertiesFormat keys
    ("publicIPAddresses", "publicIPPrefixes"),   # the resource-type spelling, tolerated
])
async def test_fetch_nat_gateway_readable(ip_key, prefix_key):
    arm = FakeArm({NATGW: {
        "id": NATGW, "name": "natgw-hub",
        "properties": {
            ip_key: [{"id": PIP1}, {"id": PIP2}],
            prefix_key: [{"id": PREFIX}],
        },
    }})
    gw = await fetch_nat_gateway(arm, NATGW, subnet_name="AzureFirewallSubnet")
    assert gw.readable is True
    assert gw.id == NATGW and gw.name == "natgw-hub" and gw.subnet_name == "AzureFirewallSubnet"
    assert gw.public_ip_ids == [PIP1, PIP2]
    assert gw.public_ip_names == ["pip-natgw-1", "pip-natgw-2"]
    assert gw.public_ip_prefix_names == ["pfx-natgw"]
    assert gw.public_ip_addresses == []  # resolved separately


async def test_fetch_nat_gateway_no_public_ips_or_prefixes():
    arm = FakeArm({NATGW: {"id": NATGW, "name": "natgw-hub", "properties": {}}})
    gw = await fetch_nat_gateway(arm, NATGW, subnet_name="AzureFirewallSubnet")
    assert gw.readable is True
    assert gw.public_ip_ids == [] and gw.public_ip_prefix_names == []


@pytest.mark.parametrize("properties", ["not a dict", None, {"publicIpAddresses": "not a list"}])
async def test_fetch_nat_gateway_tolerates_odd_payload_shapes(properties):
    arm = FakeArm({NATGW: {"id": NATGW, "name": "natgw-hub", "properties": properties}})
    gw = await fetch_nat_gateway(arm, NATGW, subnet_name="AzureFirewallSubnet")
    assert gw.readable is True and gw.public_ip_ids == [] and gw.public_ip_prefix_names == []


async def test_fetch_nat_gateways_survives_an_unexpected_error(monkeypatch):
    """An optional detail must not abort the whole metadata fetch."""
    import viewer.azure_resources as res

    async def boom(arm, gateway_id, subnet_name=""):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(res, "fetch_nat_gateway", boom)
    subnets = [SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)]
    gws = await fetch_nat_gateways(FakeArm({}), subnets)
    assert len(gws) == 1
    assert gws[0].readable is False and gws[0].name == "natgw-hub" and gws[0].subnet_name == "AzureFirewallSubnet"


async def test_fetch_nat_gateway_unreadable_never_raises():
    arm = FakeArm({NATGW: ArmError(403, "AuthorizationFailed", "denied")})
    gw = await fetch_nat_gateway(arm, NATGW, subnet_name="AzureFirewallSubnet")
    assert gw.readable is False
    assert gw.id == NATGW
    assert gw.name == "natgw-hub"  # derived from the id, not from ARM
    assert gw.subnet_name == "AzureFirewallSubnet"
    assert gw.public_ip_ids == [] and gw.public_ip_names == [] and gw.public_ip_prefix_names == []


# ── fetch_nat_gateways ───────────────────────────────────────────────────────

async def test_fetch_nat_gateways_only_for_subnets_with_a_gateway_and_keeps_order():
    other_natgw = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/natGateways/natgw-other"
    subnets = [
        SubnetInfo(id="/sn1", name="sn1", nat_gateway_id=""),
        SubnetInfo(id="/sn2", name="sn2", nat_gateway_id=other_natgw),
        SubnetInfo(id="/sn3", name="sn3", nat_gateway_id=NATGW),
    ]
    arm = FakeArm({
        other_natgw: {"id": other_natgw, "name": "natgw-other", "properties": {}},
        NATGW: {"id": NATGW, "name": "natgw-hub", "properties": {}},
    })
    gateways = await fetch_nat_gateways(arm, subnets)
    assert [(g.name, g.subnet_name) for g in gateways] == [("natgw-other", "sn2"), ("natgw-hub", "sn3")]


async def test_fetch_nat_gateways_empty_when_no_subnet_has_a_gateway():
    subnets = [SubnetInfo(id="/sn1", name="sn1"), SubnetInfo(id="/sn2", name="sn2")]
    assert await fetch_nat_gateways(FakeArm({}), subnets) == []
    assert await fetch_nat_gateways(FakeArm({}), []) == []


# ── management orchestration ────────────────────────────────────────────────

FW_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"
FW = FirewallInfo(id=FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc",
                  subnet_ids=["/sn1"], policy_id="")


class FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class FakeCredential:
    instances: list = []

    def __init__(self, **_kw):
        self.closed = False
        FakeCredential.instances.append(self)

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def world(monkeypatch):
    state: dict = {
        "cached": None, "saved": [], "invalidated": [], "calls": [],
        "firewall": FW, "policy": None, "groups": {}, "cidrs": ["10.2.0.0/26"],
        "nat_gateways": [], "pips": {}, "monkeypatch": monkeypatch,
    }
    FakeCredential.instances = []

    def load(fw_id):
        return state["cached"]

    def save(fw_id, snap):
        state["saved"].append((fw_id, snap))

    def invalidate(fw_id):
        state["invalidated"].append(fw_id)

    async def fetch_firewall(arm, fw_id):
        state["calls"].append(("firewall", fw_id))
        return state["firewall"]

    async def fetch_subnets(arm, ids):
        state["calls"].append(("subnets", ids))
        return state.get("subnets") or []

    async def fetch_nat_gateways(arm, subnets):
        state["calls"].append(("natgw", [s.id for s in subnets]))
        return state["nat_gateways"]

    async def fetch_public_ips(arm, ids):
        state["calls"].append(("pips", list(ids)))
        return {pid: addr for pid, addr in state["pips"].items() if pid in ids}

    async def fetch_diagnostic_settings(arm, fw_id):
        return []

    async def fetch_maintenance(arm, fw_id):
        return []

    async def fetch_ip_groups(arm, ids):
        return {}

    for name, fn in (
        ("load", load), ("save", save), ("invalidate", invalidate),
        ("fetch_firewall", fetch_firewall), ("fetch_subnets", fetch_subnets),
        ("fetch_nat_gateways", fetch_nat_gateways), ("fetch_public_ips", fetch_public_ips),
        ("fetch_diagnostic_settings", fetch_diagnostic_settings), ("fetch_maintenance", fetch_maintenance),
        ("fetch_ip_groups", fetch_ip_groups),
    ):
        monkeypatch.setattr(mgmt, name, fn)
    monkeypatch.setattr(mgmt, "collect_ip_group_ids", lambda policy: [])
    monkeypatch.setattr(mgmt.aiohttp, "ClientSession", FakeSession)
    import azure.identity.aio as ident
    monkeypatch.setattr(ident, "DefaultAzureCredential", FakeCredential)
    return state


async def test_management_resolves_nat_gateway_public_ips(world):
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_ids=[PIP1, PIP2], public_ip_names=["pip-natgw-1", "pip-natgw-2"])
    world["subnets"] = [subnet]
    world["nat_gateways"] = [gw]
    world["pips"] = {PIP1: "20.1.2.3", PIP2: "20.1.2.4"}

    snap = await mgmt.load_management_data(FW_ID)

    assert snap is not None
    assert snap.subnets == [subnet]
    assert snap.nat_gateways == [gw]
    assert gw.public_ip_addresses == ["20.1.2.3", "20.1.2.4"]
    pip_calls = [c[1] for c in world["calls"] if c[0] == "pips"]
    assert any(PIP1 in call and PIP2 in call for call in pip_calls)


async def test_gateway_pip_failure_keeps_the_firewall_addresses(world):
    """The NAT gateway lookup is optional; when it raises, the firewall's own
    public IP addresses, already read, must stay on the tab."""
    from viewer.azure_resources import IpConfig
    fw = FirewallInfo(id=FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      subnet_ids=["/sn1"],  # no policy: this fixture fakes no policy fetch
                      ip_configs=[IpConfig(name="c0", public_ip_id="/fwpip", public_ip_name="pip-fw")])
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_ids=[PIP1], public_ip_names=["pip-natgw-1"])
    world["firewall"] = fw
    world["subnets"] = [subnet]
    world["nat_gateways"] = [gw]
    calls = {"n": 0}

    async def fetch_public_ips(arm, ids):
        calls["n"] += 1
        if PIP1 in ids:
            raise ArmError(403, "AuthorizationFailed", "no Reader on the gateway's public IP")
        return {"/fwpip": "72.144.131.50"}

    monkeypatch_fetch = world["monkeypatch"]
    monkeypatch_fetch.setattr(mgmt, "fetch_public_ips", fetch_public_ips)

    snap = await mgmt.load_management_data(FW_ID)

    assert snap is not None and calls["n"] == 2
    assert fw.ip_configs[0].public_ip_address == "72.144.131.50"
    assert gw.public_ip_addresses == [""]


async def test_management_keeps_a_slot_for_every_gateway_pip(world):
    """An unreadable public IP stays as "" in its position: a partly resolved
    list must never look like the complete one."""
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_ids=[PIP1, PIP2], public_ip_names=["pip-natgw-1", "pip-natgw-2"])
    world["subnets"] = [subnet]
    world["nat_gateways"] = [gw]
    world["pips"] = {PIP2: "20.1.2.4"}  # only the second one is readable

    snap = await mgmt.load_management_data(FW_ID)

    assert snap is not None
    assert gw.public_ip_addresses == ["", "20.1.2.4"]
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert "outbound traffic leaves with pip-natgw-1 (address not readable), 20.1.2.4;" in rows[1]


async def test_management_asks_for_each_gateway_pip_once(world):
    """Duplicate ids across gateways, and ids the firewall lookup already covers, cost no extra GET."""
    from viewer.azure_resources import IpConfig
    fw = FirewallInfo(id=FW_ID, name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      subnet_ids=["/sn1", "/sn2"],
                      ip_configs=[IpConfig(name="c0", public_ip_id=PIP1, public_ip_name="pip-natgw-1")])
    subnets = [SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW),
               SubnetInfo(id="/sn2", name="AzureFirewallManagementSubnet", nat_gateway_id=NATGW)]
    gws = [NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name=s.name, readable=True,
                          public_ip_ids=[PIP1, PIP2], public_ip_names=["pip-natgw-1", "pip-natgw-2"]) for s in subnets]
    world["firewall"] = fw
    world["subnets"] = subnets
    world["nat_gateways"] = gws
    world["pips"] = {PIP1: "20.1.2.3", PIP2: "20.1.2.4"}

    snap = await mgmt.load_management_data(FW_ID)

    assert snap is not None
    pip_calls = [ids for name, ids in world["calls"] if name == "pips"]
    assert pip_calls == [[PIP1], [PIP2]]  # the firewall's own PIP once, the gateway's extra PIP once
    assert all(gw.public_ip_addresses == ["20.1.2.3", "20.1.2.4"] for gw in gws)


# ── cache round trip (same cache_file fixture pattern as tests/test_cache.py) ─

@pytest.fixture
def cache_file(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "cache.json"
    monkeypatch.setattr(cache, "cache_path", lambda: path)
    return path


def test_cache_round_trip_subnets_and_nat_gateways(cache_file):
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", cidrs=["10.2.0.0/26"], nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_ids=[PIP1], public_ip_names=["pip-natgw-1"],
                        public_ip_addresses=["20.1.2.3"], public_ip_prefix_names=["pfx-natgw"])
    snap = CachedSnapshot(firewall=FW, policy=None, subnets=[subnet], nat_gateways=[gw], fetched_at=time.time())
    cache.save(FW_ID, snap)
    loaded = cache.load(FW_ID)
    assert loaded is not None
    assert loaded.subnets == [subnet]
    assert loaded.nat_gateways == [gw]


def test_cache_round_trip_unreadable_nat_gateway(cache_file):
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=False)
    snap = CachedSnapshot(firewall=FW, policy=None, nat_gateways=[gw], fetched_at=time.time())
    cache.save(FW_ID, snap)
    loaded = cache.load(FW_ID)
    assert loaded is not None
    assert loaded.nat_gateways == [gw]


# ── _nat_gateway_rows rendering ──────────────────────────────────────────────

HUB_FW = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_name="AZFW_Hub")
VNET_FW = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                       sku_name="AZFW_VNet", subnet_ids=["/sn1"])
VNET_FW_NO_SUBNET_IDS = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                                     sku_name="AZFW_VNet")


def test_nat_gateway_rows_hub_firewall():
    rows = _nat_gateway_rows(HUB_FW, [], [])
    assert len(rows) == 1
    assert "not supported on a Virtual WAN hub firewall" in rows[0]


def test_nat_gateway_rows_subnet_not_readable():
    rows = _nat_gateway_rows(VNET_FW, [], [])
    assert len(rows) == 1
    assert "unknown" in rows[0] and "firewall subnet not readable" in rows[0]


def test_nat_gateway_rows_no_subnet_ids_treated_as_no_gateway():
    rows = _nat_gateway_rows(VNET_FW_NO_SUBNET_IDS, [], [])
    assert len(rows) == 1
    assert "none" in rows[0]
    assert "outbound traffic leaves with the firewall's public IPs" in rows[0]


def test_nat_gateway_rows_subnets_readable_no_gateway():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet")
    rows = _nat_gateway_rows(VNET_FW, [subnet], [])
    assert len(rows) == 1
    assert "none" in rows[0]
    assert "outbound traffic leaves with the firewall's public IPs" in rows[0]


TWO_SUBNET_FW = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                             sku_name="AZFW_VNet", subnet_ids=["/sn1", "/sn2"])


def test_nat_gateway_rows_partial_subnet_read_never_claims_none():
    """A gateway could sit on the subnet that was not readable."""
    readable = [SubnetInfo(id="/sn1", name="AzureFirewallSubnet")]
    rows = _nat_gateway_rows(TWO_SUBNET_FW, readable, [])
    assert rows == [_row("NAT gateway", "none on the readable subnets   [dim]1 of 2 firewall subnets not readable, "
                         "so a gateway there would not show[/]")]


def test_nat_gateway_rows_partial_subnet_read_marks_the_list_as_possibly_incomplete():
    readable = [SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)]
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_addresses=["20.1.2.3"])
    rows = _nat_gateway_rows(TWO_SUBNET_FW, readable, [gw])
    assert rows[0] == _note("1 of 2 firewall subnets not readable; the list below may be incomplete")
    assert rows[1] == _row("NAT gateway", "natgw-hub on AzureFirewallSubnet")


def test_nat_gateway_rows_readable_with_resolved_addresses():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_ids=[PIP1, PIP2], public_ip_names=["pip-natgw-1", "pip-natgw-2"],
                        public_ip_addresses=["20.1.2.3", "20.1.2.4"])
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert len(rows) == 2
    assert "natgw-hub on AzureFirewallSubnet" in rows[0]
    assert ("outbound traffic leaves with 20.1.2.3, 20.1.2.4; DNAT and management traffic "
            "stay on the firewall's public IPs") in rows[1]


def test_nat_gateway_rows_readable_unresolved_addresses_use_names():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_ids=[PIP1], public_ip_names=["pip-natgw-1"])
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert "outbound traffic leaves with pip-natgw-1 (address not readable);" in rows[1]


def test_nat_gateway_rows_readable_with_prefix():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_addresses=["20.1.2.3"], public_ip_prefix_names=["pfx-natgw"])
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert "outbound traffic leaves with 20.1.2.3, prefix pfx-natgw;" in rows[1]


def test_nat_gateway_rows_readable_no_ip_and_no_prefix():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True)
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert "an unknown address (the gateway lists no public IP)" in rows[1]


def test_nat_gateway_rows_not_readable():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=False)
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert len(rows) == 2
    assert "natgw-hub on AzureFirewallSubnet" in rows[0]
    assert "gateway not readable: its public IPs are unknown" in rows[0]
    assert "DNAT and management traffic stay on the firewall's public IPs" in rows[1]


def test_nat_gateway_rows_several_gateways_one_row_each():
    subnet1 = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    subnet2 = SubnetInfo(id="/sn2", name="AzureFirewallSubnet2", nat_gateway_id=NATGW + "2")
    gw1 = NatGatewayInfo(id=NATGW, name="natgw-hub", subnet_name="AzureFirewallSubnet", readable=True,
                         public_ip_addresses=["20.1.2.3"])
    gw2 = NatGatewayInfo(id=NATGW + "2", name="natgw-hub2", subnet_name="AzureFirewallSubnet2", readable=False)
    rows = _nat_gateway_rows(VNET_FW, [subnet1, subnet2], [gw1, gw2])
    assert len(rows) == 4
    assert "natgw-hub on AzureFirewallSubnet" in rows[0]
    assert "natgw-hub2 on AzureFirewallSubnet2" in rows[2]
    assert "gateway not readable" in rows[2]


def test_nat_gateway_rows_names_are_escaped():
    subnet = SubnetInfo(id="/sn1", name="AzureFirewallSubnet", nat_gateway_id=NATGW)
    gw = NatGatewayInfo(id=NATGW, name="natgw[hub]", subnet_name="AzureFirewallSubnet", readable=True,
                        public_ip_names=["pip[red]"])
    rows = _nat_gateway_rows(VNET_FW, [subnet], [gw])
    assert "natgw\\[hub] on AzureFirewallSubnet" in rows[0]
    assert "pip\\[red] (address not readable)" in rows[1]
