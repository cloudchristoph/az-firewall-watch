"""MCP server for az-firewall-watch.

Runs the log stream headless and lets an AI agent query the live firewall log,
the policy context and the evaluation trace through typed, read-only tools.
Nothing in this package may import Textual or ``dialogs``, and nothing may
write to stdout: with the stdio transport, stdout is the protocol channel.
"""
from __future__ import annotations

SERVER_NAME = "az-firewall-watch"

__all__ = ["SERVER_NAME"]
