"""autoscaleConfiguration: parsing (viewer/azure_resources.py) and rendering
(viewer/views/firewall.py _scaling_rows) for the Firewall tab's Scaling row.

Three documented states plus the Basic SKU (no scaling) and a defensive
min > max case that Azure should reject but this viewer must not trust.
"""
from __future__ import annotations

import pytest

from viewer.arm import ArmError
from viewer.azure_resources import FirewallInfo, fetch_firewall
from viewer.views.firewall import FirewallView, _row, _scaling_rows

SUB = "/subscriptions/25ca1d83-3de5-46c7-9941-fb98c2ea026e"
FW_ID = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/azureFirewalls/fw-hub-gwc"


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
        return list(payload.get("value", []))


def _fw_payload(autoscale) -> dict:
    props: dict = {"ipConfigurations": []}
    if autoscale is not None:
        props["autoscaleConfiguration"] = autoscale
    return {"id": FW_ID, "name": "fw-hub-gwc", "location": "germanywestcentral", "properties": props}


# ── parsing (fetch_firewall) ────────────────────────────────────────────────

async def test_autoscale_both_present():
    fw = await fetch_firewall(FakeArm({FW_ID: _fw_payload({"minCapacity": 5, "maxCapacity": 10})}), FW_ID)
    assert (fw.autoscale_min, fw.autoscale_max) == (5, 10)


async def test_autoscale_field_absent():
    fw = await fetch_firewall(FakeArm({FW_ID: _fw_payload(None)}), FW_ID)
    assert (fw.autoscale_min, fw.autoscale_max) == (0, 0)


async def test_autoscale_null_values():
    fw = await fetch_firewall(FakeArm({FW_ID: _fw_payload({"minCapacity": None, "maxCapacity": None})}), FW_ID)
    assert (fw.autoscale_min, fw.autoscale_max) == (0, 0)


async def test_autoscale_numeric_strings():
    fw = await fetch_firewall(FakeArm({FW_ID: _fw_payload({"minCapacity": "5", "maxCapacity": "10"})}), FW_ID)
    assert (fw.autoscale_min, fw.autoscale_max) == (5, 10)


async def test_autoscale_non_dict_value():
    fw = await fetch_firewall(FakeArm({FW_ID: _fw_payload("not-a-dict")}), FW_ID)
    assert (fw.autoscale_min, fw.autoscale_max) == (0, 0)


# ── rendering (_scaling_rows) ───────────────────────────────────────────────

def _fw(sku_tier: str = "Premium", autoscale_min: int = 0, autoscale_max: int = 0) -> FirewallInfo:
    return FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="loc",
                        sku_tier=sku_tier, autoscale_min=autoscale_min, autoscale_max=autoscale_max)


def test_scaling_basic_sku_does_not_scale():
    assert _scaling_rows(_fw(sku_tier="Basic", autoscale_min=5, autoscale_max=5)) == [
        _row("Scaling", "none   [dim]the Basic SKU does not scale[/]")
    ]


def test_scaling_absent_is_service_default():
    assert _scaling_rows(_fw(autoscale_min=0, autoscale_max=0)) == [
        _row("Scaling", "autoscaling, service default   [dim]up to 20 capacity units[/]")
    ]


def test_scaling_fixed_capacity_min_equals_max():
    assert _scaling_rows(_fw(autoscale_min=5, autoscale_max=5)) == [
        _row("Scaling", "[yellow]fixed at 5 capacity units, autoscaling off[/]")
    ]


def test_scaling_prescaled_range():
    assert _scaling_rows(_fw(autoscale_min=5, autoscale_max=10)) == [
        _row("Scaling", "autoscaling between 5 and 10 capacity units   [dim]prescaled[/]")
    ]


@pytest.mark.parametrize("lo,hi", [(5, 0), (0, 10)])
def test_scaling_with_one_bound_only_shows_the_raw_pair_and_claims_nothing(lo, hi):
    """0 is also what an absent field parses to: a single bound must not turn
    into "no upper bound" or "from zero"."""
    assert _scaling_rows(_fw(autoscale_min=lo, autoscale_max=hi)) == [
        _row("Scaling", f"[yellow]autoscaleConfiguration with min {lo} and max {hi}: not understood, "
             "shape not documented[/]")
    ]


def test_scaling_min_above_max_is_flagged_not_trusted():
    assert _scaling_rows(_fw(autoscale_min=10, autoscale_max=5)) == [
        _row("Scaling", "[yellow]min 10 above max 5: configuration not understood[/]")
    ]


# ── through FirewallView._instance: the row sits between Provisioning and
#    Resource group ─────────────────────────────────────────────────────────

def test_scaling_row_sits_between_provisioning_and_maintenance():
    fw = _fw(autoscale_min=5, autoscale_max=10)
    fw.provisioning_state = "Succeeded"
    rows = FirewallView._instance(fw, [])
    labels = [r.split("[/]", 1)[0].replace("[dim]", "").strip() for r in rows]
    assert labels.index("Scaling") == labels.index("Provisioning") + 1
    assert labels.index("Scaling") == labels.index("Maintenance") - 1
    assert labels.index("Maintenance") < labels.index("Resource group")
    assert any("autoscaling between 5 and 10 capacity units" in r for r in rows)
