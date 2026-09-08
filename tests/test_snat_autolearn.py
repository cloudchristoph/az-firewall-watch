"""0.6.0 point 2: auto-learn SNAT and its Route Server.

Covers parsing (FirewallPolicyInfo.snat_auto_learn, FirewallInfo.route_server_id)
and every rendered variant of the Firewall tab's Policy panel SNAT rows.
"""
from __future__ import annotations

from viewer.arm import ArmError
from viewer.azure_resources import (
    ROUTE_SERVER_KEY,
    FirewallInfo,
    FirewallPolicyInfo,
    fetch_firewall,
    fetch_policy,
)
from viewer.views.firewall import FirewallView, _snat_rows

SUB = "/subscriptions/25ca1d83-3de5-46c7-9941-fb98c2ea026e"
FW_ID = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/azureFirewalls/fw-hub-gwc"
POLICY_ID = f"{SUB}/resourceGroups/rg-hub-firewallpolicy-gwc/providers/Microsoft.Network/firewallPolicies/fwp-hub-premium-gwc"
RS_ID = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/virtualHubs/hub-gwc/ipConfigurations/rs-hub"
RS_STANDALONE_ID = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/routeServers/rs-hub"


class FakeArm:
    """Stand-in for ArmClient: answers GETs from a path → payload map."""

    def __init__(self, routes: dict) -> None:
        self.routes = routes

    async def get(self, path: str, api_version: str, *, params=None) -> dict:
        if path not in self.routes:
            raise ArmError(404, "ResourceNotFound", f"no route for {path}")
        payload = self.routes[path]
        if isinstance(payload, Exception):
            raise payload
        return payload

    async def get_all(self, path: str, api_version: str, *, params=None) -> list:
        payload = self.routes.get(path, {"value": []})
        if isinstance(payload, Exception):
            raise payload
        return list(payload.get("value", []))


# ── parsing: FirewallPolicyInfo.snat_auto_learn ───────────────────────────────

async def test_fetch_policy_snat_auto_learn_enabled():
    payload = {"id": POLICY_ID, "name": "p", "properties": {"snat": {"autoLearnPrivateRanges": "Enabled"}}}
    pol = await fetch_policy(FakeArm({POLICY_ID: payload}), POLICY_ID)
    assert pol.snat_auto_learn == "Enabled"


async def test_fetch_policy_snat_auto_learn_disabled():
    payload = {"id": POLICY_ID, "name": "p", "properties": {"snat": {"autoLearnPrivateRanges": "Disabled"}}}
    pol = await fetch_policy(FakeArm({POLICY_ID: payload}), POLICY_ID)
    assert pol.snat_auto_learn == "Disabled"


async def test_fetch_policy_snat_auto_learn_absent():
    """Neither the ``snat`` block nor the ``autoLearnPrivateRanges`` key present."""
    payload = {"id": POLICY_ID, "name": "p", "properties": {}}
    pol = await fetch_policy(FakeArm({POLICY_ID: payload}), POLICY_ID)
    assert pol.snat_auto_learn == "" and pol.snat_private_ranges == []


# ── parsing: FirewallInfo.route_server_id ─────────────────────────────────────

async def test_fetch_firewall_route_server_id_present():
    payload = {
        "id": FW_ID, "name": "fw", "location": "x",
        "properties": {"additionalProperties": {
            ROUTE_SERVER_KEY: RS_STANDALONE_ID,
            "Network.AdditionalLogs.EnableFatFlowLogging": "true",
        }},
    }
    fw = await fetch_firewall(FakeArm({FW_ID: payload}), FW_ID)
    assert fw.route_server_id == RS_STANDALONE_ID
    # the other additionalProperties key survives untouched
    assert fw.additional_properties["Network.AdditionalLogs.EnableFatFlowLogging"] == "true"


async def test_fetch_firewall_route_server_id_absent_key():
    """additionalProperties present but without the Route Server key."""
    payload = {
        "id": FW_ID, "name": "fw", "location": "x",
        "properties": {"additionalProperties": {"Network.AdditionalLogs.EnableFatFlowLogging": "true"}},
    }
    fw = await fetch_firewall(FakeArm({FW_ID: payload}), FW_ID)
    assert fw.route_server_id == ""


async def test_fetch_firewall_route_server_id_no_additional_properties():
    payload = {"id": FW_ID, "name": "fw", "location": "x", "properties": {}}
    fw = await fetch_firewall(FakeArm({FW_ID: payload}), FW_ID)
    assert fw.route_server_id == ""


# ── rendering: _snat_rows ──────────────────────────────────────────────────────

def _fw(sku_name: str = "AZFW_VNet", route_server_id: str = "") -> FirewallInfo:
    return FirewallInfo(id=FW_ID, name="fw-hub-gwc", subscription_id="s", resource_group="rg",
                        location="germanywestcentral", sku_name=sku_name, route_server_id=route_server_id)


def test_snat_rows_default_ranges_when_none_configured():
    rows = _snat_rows(FirewallPolicyInfo(id=POLICY_ID, name="p"), _fw())
    assert rows[0] == "[dim]SNAT ranges       [/]  default (RFC 1918 and RFC 6598)"
    assert rows[1] == "                    [dim]applies to network rules only; application rules are always SNATed[/]"


def test_snat_rows_configured_ranges_are_escaped_and_joined():
    pol = FirewallPolicyInfo(id=POLICY_ID, name="p", snat_private_ranges=["IANAPrivateRanges", "100.64.0.0/10"])
    rows = _snat_rows(pol, _fw())
    assert rows[0] == "[dim]SNAT ranges       [/]  IANAPrivateRanges, 100.64.0.0/10"


def test_snat_rows_auto_learn_off_when_disabled():
    pol = FirewallPolicyInfo(id=POLICY_ID, name="p", snat_auto_learn="Disabled")
    rows = _snat_rows(pol, _fw())
    assert rows[-1] == "[dim]Auto-learn SNAT   [/]  off"
    assert len(rows) == 3  # no learned-ranges note when auto-learn is off


def test_snat_rows_auto_learn_off_when_absent():
    pol = FirewallPolicyInfo(id=POLICY_ID, name="p", snat_auto_learn="")
    rows = _snat_rows(pol, _fw())
    assert rows[-1] == "[dim]Auto-learn SNAT   [/]  off"


def test_snat_rows_auto_learn_on_via_hub_builtin_route_server():
    pol = FirewallPolicyInfo(id=POLICY_ID, name="p", snat_auto_learn="Enabled")
    rows = _snat_rows(pol, _fw(sku_name="AZFW_Hub"))
    assert rows[2] == "[dim]Auto-learn SNAT   [/]  on   [dim]via the hub's built-in Route Server[/]"
    assert rows[3] == ("                    [dim]learned ranges are not readable from here: listing them is a "
                        "POST action, and this tool only reads[/]")
    assert len(rows) == 4


def test_snat_rows_auto_learn_on_via_vnet_route_server():
    pol = FirewallPolicyInfo(id=POLICY_ID, name="p", snat_auto_learn="Enabled")
    rows = _snat_rows(pol, _fw(sku_name="AZFW_VNet", route_server_id=RS_STANDALONE_ID))
    assert rows[2] == "[dim]Auto-learn SNAT   [/]  on   [dim]via Route Server rs-hub[/]"
    assert rows[3] == ("                    [dim]learned ranges are not readable from here: listing them is a "
                        "POST action, and this tool only reads[/]")
    assert len(rows) == 4


def test_snat_rows_auto_learn_on_without_route_server_is_flagged():
    """The misconfiguration this tab exists to name: ranges look complete but nothing is learned."""
    pol = FirewallPolicyInfo(id=POLICY_ID, name="p", snat_auto_learn="Enabled")
    rows = _snat_rows(pol, _fw(sku_name="AZFW_VNet", route_server_id=""))
    assert rows[2] == ("[dim]Auto-learn SNAT   [/]  [yellow]on, but no Route Server is associated with the "
                        "firewall: nothing is ever learned[/]")
    assert len(rows) == 3  # no learned-ranges note in this branch


# ── rendering: through FirewallView._policy ────────────────────────────────────

def test_policy_panel_includes_snat_rows():
    fw = _fw(sku_name="AZFW_VNet", route_server_id=RS_STANDALONE_ID)
    pol = FirewallPolicyInfo(id=POLICY_ID, name="fwp-hub-premium-gwc", snat_auto_learn="Enabled",
                             snat_private_ranges=["100.64.0.0/10"])
    out = FirewallView._policy(pol, fw)
    assert "[dim]SNAT ranges       [/]  100.64.0.0/10" in out
    assert "[dim]Auto-learn SNAT   [/]  on   [dim]via Route Server rs-hub[/]" in out


# ── rendering: Instance panel excludes the Route Server key ───────────────────

def test_instance_panel_hides_route_server_key_but_shows_other_additional_properties():
    fw = FirewallInfo(id=FW_ID, name="fw-hub-gwc", subscription_id="s", resource_group="rg",
                      location="germanywestcentral",
                      additional_properties={
                          ROUTE_SERVER_KEY: RS_STANDALONE_ID,
                          "Network.AdditionalLogs.EnableFatFlowLogging": "true",
                      })
    out = "\n".join(FirewallView._instance(fw, []))
    assert ROUTE_SERVER_KEY not in out and "rs-hub" not in out and RS_STANDALONE_ID not in out
    assert "EnableFatFlowLogging=true" in out
