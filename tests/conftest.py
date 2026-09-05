"""Shared fixtures for the az-firewall-watch test suite."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

import pytest

# Make the repo root importable (main.py, fw_parser.py, viewer/, setup/ …).
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIREWALL_ID = (
    "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000"
    "/RESOURCEGROUPS/rg-hub"
    "/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/fw-hub"
)


@pytest.fixture
def firewall_id() -> str:
    return FIREWALL_ID


@pytest.fixture
def structured_record() -> Callable[..., dict[str, Any]]:
    """Build a structured (AZFW*) diagnostic record."""

    def _build(category: str, time: str = "2026-09-05T08:00:00Z", **props: Any) -> dict[str, Any]:
        return {
            "resourceId": FIREWALL_ID,
            "category": category,
            "operationName": "AzureFirewall",
            "time": time,
            "properties": props,
        }

    return _build


@pytest.fixture
def legacy_record() -> Callable[..., dict[str, Any]]:
    """Build a legacy (properties.msg) diagnostic record."""

    def _build(category: str, op_name: str, msg: str, time: str = "2026-09-05T08:00:00Z") -> dict[str, Any]:
        return {
            "resourceId": FIREWALL_ID,
            "category": category,
            "operationName": op_name,
            "time": time,
            "properties": {"msg": msg},
        }

    return _build


@pytest.fixture
def no_eventhub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no Event Hub credentials leak into tests from the developer's shell."""
    for key in (
        "EVENT_HUB_CONNECTION_STRING",
        "EVENT_HUB_NAMESPACE",
        "EVENT_HUB_NAME",
        "EVENT_HUB_CONSUMER_GROUP",
        "EVENT_HUB_START_POSITION",
    ):
        monkeypatch.delenv(key, raising=False)
