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


def write_env(env_file: Path, conn_str: str) -> None:
    """Write a connection-string-based .env file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_file.write_text(
        f"# Written by setup.app - {ts}\n"
        "# Do NOT commit this file - it contains a shared access key.\n"
        f"EVENT_HUB_CONNECTION_STRING={conn_str}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n",
        encoding="utf-8",
    )


def write_env_entra(env_file: Path, namespace: str, hub_name: str) -> None:
    """Write an Entra ID (passwordless) .env file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_file.write_text(
        f"# Written by setup.app - {ts}\n"
        "# Entra ID (passwordless) authentication — no secrets stored.\n"
        "# Your identity must have 'Azure Event Hubs Data Receiver' role.\n"
        f"EVENT_HUB_NAMESPACE={namespace}\n"
        f"EVENT_HUB_NAME={hub_name}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n",
        encoding="utf-8",
    )
