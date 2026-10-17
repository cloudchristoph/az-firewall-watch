from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path


def _read_env_text(env_file: Path) -> str:
    """Read .env as UTF-8, falling back to latin-1 on decode errors."""
    try:
        return env_file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return env_file.read_text(encoding="latin-1")


def get_existing_conn_str(env_file: Path) -> str | None:
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


_POLICY_CONTEXT_COMMENT = (
    "# POLICY_CONTEXT=on reads the firewall, its policy and IP groups via Azure Resource Manager\n"
    "# (Reader role), may use an Azure CLI token, and caches the result in your user cache directory.\n"
)


def _policy_context_line(policy_context: bool) -> str:
    return f"POLICY_CONTEXT={'on' if policy_context else 'off'}\n"


def _write_private(env_file: Path, text: str) -> None:
    """Write .env readable by the user only (0600): it can carry a SAS key.
    On Windows the mode only sets the read-only flag; the user profile is
    private there already."""
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(env_file, 0o600)  # an existing file keeps its old mode through os.open
    except OSError:
        pass


def write_env(env_file: Path, conn_str: str, policy_context: bool = True) -> None:
    """Write a connection-string-based .env file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_private(
        env_file,
        f"# Written by setup.app - {ts}\n"
        "# Do NOT commit this file - it contains a shared access key.\n"
        f"EVENT_HUB_CONNECTION_STRING={conn_str}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n"
        + _POLICY_CONTEXT_COMMENT + _policy_context_line(policy_context),
    )


def write_env_entra(env_file: Path, namespace: str, hub_name: str, policy_context: bool = True) -> None:
    """Write an Entra ID (passwordless) .env file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_private(
        env_file,
        f"# Written by setup.app - {ts}\n"
        "# Entra ID (passwordless) authentication: no secrets stored.\n"
        "# Your identity must have 'Azure Event Hubs Data Receiver' role.\n"
        f"EVENT_HUB_NAMESPACE={namespace}\n"
        f"EVENT_HUB_NAME={hub_name}\n"
        "EVENT_HUB_CONSUMER_GROUP=$Default\n"
        "EVENT_HUB_START_POSITION=latest\n"
        + _POLICY_CONTEXT_COMMENT + _policy_context_line(policy_context),
    )


def set_env_value(env_file: Path, key: str, value: str) -> None:
    """Set ``KEY=value`` in .env, replacing an existing line or appending one.

    Comments and other keys are preserved. Creates the file if it is missing.
    """
    lines = _read_env_text(env_file).splitlines() if env_file.exists() else []
    prefix = f"{key}="
    replaced = False
    kept: list[str] = []
    for line in lines:
        if line.startswith(prefix):
            if replaced:
                continue  # drop duplicates (e.g. from manual edits) so the key is unambiguous
            kept.append(f"{key}={value}")
            replaced = True
        else:
            kept.append(line)
    lines = kept
    if not replaced:
        if key == "POLICY_CONTEXT":
            lines.extend(_POLICY_CONTEXT_COMMENT.rstrip("\n").splitlines())
        lines.append(f"{key}={value}")
    _write_private(env_file, "\n".join(lines) + "\n")
