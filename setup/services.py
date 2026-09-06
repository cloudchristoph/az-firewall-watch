from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _read_env_text(env_file: Path) -> str:
    """Read .env as UTF-8, falling back to latin-1 on decode errors."""
    try:
        return env_file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return env_file.read_text(encoding="latin-1")


def get_existing_conn_str(env_file: Path) -> Optional[str]:
    """Return a non-empty connection string from .env, or None."""
    if not env_file.exists():
        return None
    for line in _read_env_text(env_file).splitlines():
        if line.startswith("EVENT_HUB_CONNECTION_STRING="):
            value = line[len("EVENT_HUB_CONNECTION_STRING="):].strip()
            return value if value else None
    return None


def has_entra_config(env_file: Path) -> bool:
    """Return True if .env has EVENT_HUB_NAMESPACE and EVENT_HUB_NAME set."""
    if not env_file.exists():
        return False
    found_ns = found_name = False
    for line in _read_env_text(env_file).splitlines():
        if line.startswith("EVENT_HUB_NAMESPACE=") and line.split("=", 1)[1].strip():
            found_ns = True
        if line.startswith("EVENT_HUB_NAME=") and line.split("=", 1)[1].strip():
            found_name = True
    return found_ns and found_name


_ENRICHMENT_COMMENT = (
    "# ENRICHMENT=on reads the firewall, its policy and IP groups via Azure Resource Manager\n"
    "# (Reader role), may use an Azure CLI token, and caches the result in ~/.az-firewall-watch.\n"
)


def _enrichment_line(enrichment: bool) -> str:
    return f"ENRICHMENT={'on' if enrichment else 'off'}\n"


def write_env(env_file: Path, conn_str: str, enrichment: bool = True) -> None:
    """Write a connection-string-based .env file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_file.write_text(
        f"# Written by setup.app - {ts}\n"
        "# Do NOT commit this file - it contains a shared access key.\n"
        f"EVENT_HUB_CONNECTION_STRING={conn_str}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n"
        + _ENRICHMENT_COMMENT + _enrichment_line(enrichment),
        encoding="utf-8",
    )


def write_env_entra(env_file: Path, namespace: str, hub_name: str, enrichment: bool = True) -> None:
    """Write an Entra ID (passwordless) .env file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_file.write_text(
        f"# Written by setup.app - {ts}\n"
        "# Entra ID (passwordless) authentication — no secrets stored.\n"
        "# Your identity must have 'Azure Event Hubs Data Receiver' role.\n"
        f"EVENT_HUB_NAMESPACE={namespace}\n"
        f"EVENT_HUB_NAME={hub_name}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n"
        + _ENRICHMENT_COMMENT + _enrichment_line(enrichment),
        encoding="utf-8",
    )


def set_env_value(env_file: Path, key: str, value: str) -> None:
    """Set ``KEY=value`` in .env, replacing an existing line or appending one.

    Comments and other keys are preserved. Creates the file if it is missing.
    """
    lines = _read_env_text(env_file).splitlines() if env_file.exists() else []
    prefix = f"{key}="
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = f"{key}={value}"
            replaced = True
    if not replaced:
        if key == "ENRICHMENT":
            lines.extend(_ENRICHMENT_COMMENT.rstrip("\n").splitlines())
        lines.append(f"{key}={value}")
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
