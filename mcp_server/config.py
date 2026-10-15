"""Server configuration from the environment (``.env``) and the command line.

The Event Hub keys are the ones the setup wizard writes for the TUI, so an
existing installation needs no second configuration. Command-line options win
over environment variables, which win over the defaults.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from viewer.config import policy_context_setting
from viewer.eventhub import EventHubSettings

DEFAULT_BUFFER_SIZE = 20000
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
TRANSPORTS = ("stdio", "http")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Below this a buffer is too small to summarise anything; above it memory
# grows past what a laptop should spend on a log tail.
MIN_BUFFER_SIZE = 100
MAX_BUFFER_SIZE = 1_000_000


def build_arg_parser() -> argparse.ArgumentParser:
    """The command line of ``python -m mcp_server`` (and ``main.py --mcp``).

    Defaults are ``None`` on purpose: an option that was not given must not
    hide the environment variable behind it.
    """
    parser = argparse.ArgumentParser(
        prog="az-firewall-watch --mcp",
        description="Serve the Azure Firewall log stream and policy context to MCP clients (read-only).",
    )
    parser.add_argument("--transport", choices=TRANSPORTS, default=None,
                        help="stdio (default) or http (streamable HTTP on --host/--port, path /mcp, no authentication)")
    parser.add_argument("--host", default=None, help=f"HTTP transport only (default {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=None, help=f"HTTP transport only (default {DEFAULT_PORT})")
    parser.add_argument("--env-file", default=None, help="read settings from this file instead of .env next to the app")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--no-policy-context", action="store_true",
                       help="no ARM access: logs only, no firewall, policy or trace")
    group.add_argument("--policy-context", action="store_true", help="force the policy context on")
    parser.add_argument("--firewall-id", default=None,
                        help="load the policy context for this firewall at start instead of waiting for the first log")
    parser.add_argument("--buffer-size", type=int, default=None,
                        help=f"log rows kept in memory (default {DEFAULT_BUFFER_SIZE})")
    parser.add_argument("--log-level", type=str.upper, choices=LOG_LEVELS, default=None,
                        help="stderr log level (default INFO)")
    # The TUI's entry point passes its own switch through; accept it silently.
    parser.add_argument("--mcp", action="store_true", help=argparse.SUPPRESS)
    return parser


def _int_setting(name: str, raw: str | int | None, default: int) -> int:
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number, got {raw!r}.") from None


@dataclass(frozen=True)
class ServerConfig:
    """Everything the server needs to start; immutable once built."""

    eventhub: EventHubSettings = field(default_factory=EventHubSettings)
    policy_context: bool = True
    firewall_id: str | None = None
    buffer_size: int = DEFAULT_BUFFER_SIZE
    transport: str = "stdio"
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    log_level: str = "INFO"
    env_file: Path | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str], argv: Sequence[str] | None = None) -> ServerConfig:
        """Build the configuration; raises ``ValueError`` with a readable sentence on bad values."""
        args_list = list(argv or [])
        args = build_arg_parser().parse_args(args_list)
        enabled, _explicit = policy_context_setting(args_list, environ)

        transport = (args.transport or environ.get("AZFW_MCP_TRANSPORT") or "stdio").strip().lower()
        if transport not in TRANSPORTS:
            raise ValueError(f"AZFW_MCP_TRANSPORT must be one of {', '.join(TRANSPORTS)}, got {transport!r}.")
        log_level = (args.log_level or environ.get("AZFW_MCP_LOG_LEVEL") or "INFO").strip().upper()
        if log_level not in LOG_LEVELS:
            raise ValueError(f"AZFW_MCP_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, got {log_level!r}.")
        buffer_size = _int_setting("AZFW_MCP_BUFFER_SIZE",
                                   args.buffer_size if args.buffer_size is not None
                                   else environ.get("AZFW_MCP_BUFFER_SIZE"), DEFAULT_BUFFER_SIZE)
        if not MIN_BUFFER_SIZE <= buffer_size <= MAX_BUFFER_SIZE:
            raise ValueError(f"The buffer size must be between {MIN_BUFFER_SIZE} and {MAX_BUFFER_SIZE}, "
                             f"got {buffer_size}.")
        port = _int_setting("AZFW_MCP_PORT", args.port if args.port is not None else environ.get("AZFW_MCP_PORT"),
                            DEFAULT_PORT)
        if not 1 <= port <= 65535:
            raise ValueError(f"The HTTP port must be between 1 and 65535, got {port}.")
        host = (args.host or environ.get("AZFW_MCP_HOST") or DEFAULT_HOST).strip()
        firewall_id = (args.firewall_id or environ.get("AZFW_FIREWALL_ID") or "").strip() or None
        if firewall_id is not None and "/providers/microsoft.network/azurefirewalls/" not in firewall_id.lower():
            raise ValueError("AZFW_FIREWALL_ID must be an Azure Firewall resource id "
                             "(/subscriptions/…/providers/Microsoft.Network/azureFirewalls/<name>).")
        return cls(
            eventhub=EventHubSettings.from_env(environ),
            policy_context=enabled,
            firewall_id=firewall_id,
            buffer_size=buffer_size,
            transport=transport,
            host=host,
            port=port,
            log_level=log_level,
            env_file=Path(args.env_file) if args.env_file else None,
        )


__all__ = ["ServerConfig", "build_arg_parser", "DEFAULT_BUFFER_SIZE", "DEFAULT_HOST", "DEFAULT_PORT"]
