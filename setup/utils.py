from __future__ import annotations

import asyncio
import shutil
import subprocess
from typing import Optional


def find_az() -> Optional[str]:
    """Return the Azure CLI executable path if installed."""
    return shutil.which("az") or shutil.which("az.cmd")


def run_az(*args: str, capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    """Run an Azure CLI command synchronously."""
    az = find_az()
    if not az:
        raise FileNotFoundError("Azure CLI not found")
    return subprocess.run(
        [az, *args],
        capture_output=capture,
        text=True,
        check=check,
    )


async def az_async(*args: str, capture: bool = True, check: bool = False):
    """Run Azure CLI in a thread pool so the TUI stays responsive."""
    return await asyncio.to_thread(run_az, *args, capture=capture, check=check)


_LOC_SHORT: dict[str, str] = {
    "germanywestcentral": "gwc", "germanynorth": "gn",
    "westeurope": "we",          "northeurope": "ne",
    "eastus": "eus",             "eastus2": "eus2",
    "westus": "wus",             "westus2": "wus2",
    "centralus": "cus",          "uksouth": "uks",
    "ukwest": "ukw",             "francecentral": "frc",
    "swedencentral": "swc",      "switzerlandnorth": "swn",
    "australiaeast": "ae",       "southeastasia": "sea",
    "eastasia": "ea",            "japaneast": "jpe",
}


def location_short(loc: str) -> str:
    """Return a short CAF-style abbreviation for an Azure location."""
    return _LOC_SHORT.get(loc.lower(), loc[:6])
