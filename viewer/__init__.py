"""Main TUI for az-firewall-watch.

``FirewallLogApp`` is imported lazily: the MCP server uses the TUI-free
modules of this package (``viewer.eventhub``, ``viewer.trace``,
``viewer.management`` and friends) and must not pull in Textual just because
Python runs this file first.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .app import FirewallLogApp


def __getattr__(name: str) -> Any:
    if name == "FirewallLogApp":
        from .app import FirewallLogApp
        return FirewallLogApp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["FirewallLogApp"]
