from __future__ import annotations

import asyncio
import shutil
import subprocess


def find_az() -> str | None:
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


def cli_error_text(exc: BaseException) -> str:
    """Describe a failed CLI call for the user.

    ``CalledProcessError`` only says which command returned which exit status;
    the reason is in its captured stderr, where the CLI writes an ``ERROR:``
    line and often repeats it as ``Code:`` / ``Message:``. Keep the first
    ``ERROR:`` line (or the whole stderr when there is none) so the wizard
    shows why, not just that, a step failed.
    """
    if not isinstance(exc, subprocess.CalledProcessError):
        return str(exc)
    stderr = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
    if not stderr:
        return str(exc)
    reason = next((line for line in stderr.splitlines() if line.startswith("ERROR:")), stderr)
    command = " ".join(str(part) for part in exc.cmd[1:4]) if isinstance(exc.cmd, (list, tuple)) else ""
    return f"az {command} failed: {reason.removeprefix('ERROR:').strip()}"


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
