"""GitHub release update check for the viewer TUI."""
from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import TYPE_CHECKING

from dialogs import UpdateDialog

if TYPE_CHECKING:
    from .app import FirewallLogApp


_RELEASES_URL = "https://api.github.com/repos/cloudchristoph/az-firewall-watch/releases/latest"


def _parse_version(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


async def check_for_update(app: "FirewallLogApp", current_version: str) -> None:
    """Silently fetch the latest GitHub release and show UpdateDialog if newer."""

    def _fetch() -> dict:
        req = urllib.request.Request(
            _RELEASES_URL,
            headers={"User-Agent": f"az-firewall-watch/{current_version}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return json.loads(resp.read())

    try:
        data: dict = await asyncio.get_event_loop().run_in_executor(None, _fetch)
        tag = data.get("tag_name", "").lstrip("v")
        release_url: str = data.get(
            "html_url",
            "https://github.com/cloudchristoph/az-firewall-watch/releases",
        )
    except Exception:
        return  # no network / API error — fail silently

    if _parse_version(tag) > _parse_version(current_version):
        # Always push immediately — even over ConnectingDialog.
        # The first-event handler in streaming will surgically remove
        # ConnectingDialog from beneath it without touching UpdateDialog.
        app._pending_update = (tag, release_url)
        await app.push_screen(UpdateDialog(tag, release_url))
