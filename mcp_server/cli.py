"""Command line of the MCP server: ``python -m mcp_server`` and ``main.py --mcp``.

The server never runs the setup wizard: it may be started by an MCP client
with no terminal attached, and with the stdio transport the terminal is the
protocol channel. Missing settings end the process with exit code 2 and a
message on stderr that names the wizard.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from viewer.config import BASE_DIR, load_env

from .config import ServerConfig, build_arg_parser

log = logging.getLogger("mcp_server")

WIZARD_HINT = (
    "az-firewall-watch MCP server: no Event Hub credentials configured.\n"
    "Run the setup wizard once in a terminal (./az-firewall-watch, or python main.py --reconfigure from source),\n"
    "or set EVENT_HUB_NAMESPACE + EVENT_HUB_NAME (Entra ID) or EVENT_HUB_CONNECTION_STRING (SAS) in .env\n"
    "or pass --env-file. The MCP server never runs the wizard itself."
)


def configure_logging(level: str) -> None:
    """Every log line goes to stderr; stdout belongs to the stdio transport.

    The Azure SDKs log every AMQP link and token refresh at INFO, which would
    drown the server's own lines, so they are held at WARNING unless DEBUG is asked for.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=level, handlers=[handler], force=True)
    quiet = logging.DEBUG if level == "DEBUG" else logging.WARNING
    for name in ("azure", "uamqp", "aiohttp", "urllib3", "httpx"):
        logging.getLogger(name).setLevel(quiet)


def main(argv: list[str] | None = None) -> int:
    """Run the server; returns the process exit code."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    args = build_arg_parser().parse_args(args_list)   # usage errors exit with 2 on stderr

    env_file = Path(args.env_file).expanduser() if args.env_file else BASE_DIR / ".env"
    if args.env_file and not env_file.is_file():
        print(f"az-firewall-watch MCP server: --env-file {env_file} does not exist.", file=sys.stderr)
        return 2
    if env_file.is_file():
        load_env(env_file)

    try:
        config = ServerConfig.from_env(os.environ, args_list)
    except ValueError as exc:
        print(f"az-firewall-watch MCP server: {exc}", file=sys.stderr)
        return 2
    if not config.eventhub.configured:
        print(WIZARD_HINT, file=sys.stderr)
        return 2

    configure_logging(config.log_level)
    namespace, hub = config.eventhub.display_endpoint
    log.info("Starting MCP server (%s transport) for Event Hub %s/%s, policy context %s",
             config.transport, namespace, hub, "on" if config.policy_context else "off")

    from .server import build_server  # the SDK import is the slow part; config errors answer first

    server = build_server(config)
    try:
        if config.transport == "http":
            server.run("streamable-http", host=config.host, port=config.port)
        else:
            server.run("stdio")
    except KeyboardInterrupt:
        pass
    return 0


__all__ = ["main", "configure_logging", "WIZARD_HINT"]
