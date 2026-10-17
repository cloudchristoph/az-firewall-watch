"""is_firewall_resource_id (viewer/arm.py): the gate for ids from Event Hub records."""
from __future__ import annotations

import pytest

from viewer.arm import is_firewall_resource_id

from .conftest import FIREWALL_ID

SUB = "00000000-0000-0000-0000-000000000000"
FW = f"/subscriptions/{SUB}/resourceGroups/rg-hub/providers/Microsoft.Network/azureFirewalls/fw-hub"


@pytest.mark.parametrize("value", [
    FW,
    FW.upper(),
    FW.lower(),
    FIREWALL_ID,  # as diagnostics deliver it
    f"/subscriptions/{SUB.replace('0', 'A')}/resourceGroups/rg.with(parens)_x/providers/"
    "Microsoft.Network/azureFirewalls/fw.1",
])
def test_accepts_firewall_ids_in_any_case(value):
    assert is_firewall_resource_id(value)


@pytest.mark.parametrize("value", [
    None,
    42,
    ["/subscriptions/..."],
    "",
    "https://attacker.example/x/AZUREFIREWALLS/y",
    "https://management.azure.com" + FW,
    "//attacker.example" + FW,
    FW + "/",
    FW + "/extra",
    FW + "?x=1",
    FW + "#x",
    FW + "\n",
    " " + FW,
    FW.replace(SUB, "s"),                                   # not a GUID
    FW.replace(SUB, SUB + "0"),
    FW.replace("rg-hub", ".."),
    FW.replace("rg-hub", "."),
    FW.replace("fw-hub", ".."),
    FW.replace("fw-hub", ""),
    FW.replace("fw-hub", "fw hub"),
    FW.replace("fw-hub", "fw\x00hub"),
    FW.replace("fw-hub", "fw\\hub"),
    FW.replace("rg-hub", "rg/x"),
    FW.replace("azureFirewalls", "virtualNetworks"),
    FW.replace("Microsoft.Network", "MicrosoftXNetwork"),
])
def test_rejects_everything_else(value):
    assert not is_firewall_resource_id(value)
