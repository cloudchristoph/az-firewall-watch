"""A deallocated virtual network firewall (issue #60).

Azure: removing all IP configurations deallocates the firewall, and
``Deallocate()`` removes them. ARM keeps ``provisioningState`` ``Succeeded``,
so the empty list is the only sign. How a deallocated *hub* firewall reads in
ARM is not documented, so it is never reported as stopped.
"""
from __future__ import annotations

import asyncio

from viewer.azure_resources import FirewallInfo, IpConfig, fetch_firewall
from viewer.views.firewall import FirewallView, _nat_gateway_rows

from .test_azure_resources import FW_ID, FakeArm


def _fw(**kw) -> FirewallInfo:
    base = dict(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                sku_tier="Standard", sku_name="AZFW_VNet", provisioning_state="Succeeded")
    base.update(kw)
    return FirewallInfo(**base)


_IPC = IpConfig(name="ipconfig", private_ip="10.0.0.4", public_ip_id="/pip", subnet_id="/sn")


def test_a_vnet_firewall_without_ip_configurations_is_stopped():
    assert _fw().stopped


def test_it_is_not_stopped_with_a_data_plane_or_a_management_configuration():
    assert not _fw(ip_configs=[_IPC]).stopped
    assert not _fw(management_ip=IpConfig(name="mgmt", subnet_id="/m")).stopped


def test_hub_firewalls_and_unfinished_provisioning_are_never_called_stopped():
    assert not _fw(sku_name="AZFW_Hub").stopped
    assert not _fw(sku_name="").stopped                       # unknown SKU: no claim
    assert not _fw(provisioning_state="Creating").stopped
    assert not _fw(provisioning_state="Failed").stopped
    assert not _fw(provisioning_state="").stopped


def test_the_instance_block_names_the_state_only_when_stopped():
    stopped = "\n".join(FirewallView._instance(_fw(), []))
    assert "stopped" in stopped and "deallocated" in stopped and "no new log rows" in stopped
    running = "\n".join(FirewallView._instance(_fw(ip_configs=[_IPC]), []))
    assert "stopped" not in running and "deallocated" not in running


def test_the_nat_gateway_row_does_not_blame_the_routes_for_a_stopped_firewall():
    rows = "\n".join(_nat_gateway_rows(_fw(), [], []))
    assert "deallocated" in rows and "egress depends on your routes" not in rows
    live = "\n".join(_nat_gateway_rows(_fw(ip_configs=[IpConfig(name="c", private_ip="10.0.0.4", subnet_id="/sn")]),
                                       [], []))
    assert "egress depends on your routes" in live            # unchanged for a running forced-tunnel design


def test_fetch_firewall_reads_a_deallocated_firewall_as_stopped():
    raw = {"id": FW_ID, "name": "fw-example", "location": "germanywestcentral",
           "properties": {"provisioningState": "Succeeded", "sku": {"name": "AZFW_VNet", "tier": "Standard"},
                          "ipConfigurations": []}}
    fw = asyncio.run(fetch_firewall(FakeArm({FW_ID: raw}), FW_ID))
    assert fw.sku_name == "AZFW_VNet" and fw.ip_configs == [] and fw.stopped
