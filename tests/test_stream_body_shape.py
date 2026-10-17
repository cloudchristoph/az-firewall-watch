"""Untrusted Event Hub bodies in streaming.on_event: shape checks and the firewall id gate.

Anyone who can send to the hub controls the body. A malformed event must not
raise out of the callback (that stops the partition receiver), and a
resourceId that is not a firewall id must never reach the policy context load,
which would send the ARM token to it.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest
from rich.text import Text

import viewer.app as app_module
from dialogs import StatusBar
from viewer.app import FirewallLogApp

pytestmark = pytest.mark.usefixtures("no_eventhub_env")

SAS_CONN = (
    "Endpoint=sb://lab-ns.servicebus.windows.net/;"
    "SharedAccessKeyName=listen;SharedAccessKey=SECRET;EntityPath=firewall-logs"
)
ATTACKER = "https://attacker.example/x/AZUREFIREWALLS/y"
# Passes the parser's own substring test, so it still becomes a log row.
ATTACKER_ROW = "https://attacker.example/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/y"


class Event:
    def __init__(self, body: Any) -> None:
        self._body = body if isinstance(body, str) else json.dumps(body)

    def body_as_str(self) -> str:
        return self._body


class Client:
    """Minimal EventHubConsumerClient: delivers the class' events once, then blocks."""

    events: list[Event] = []
    errors: list[BaseException] = []

    def __init__(self, **_kw: Any) -> None:
        pass

    @classmethod
    def from_connection_string(cls, _conn: str, **kw: Any) -> Client:
        return cls(**kw)

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def get_partition_ids(self) -> list[str]:
        return ["0"]

    async def receive(self, on_event: Callable, starting_position: str) -> None:
        for ev in Client.events:
            try:
                await on_event(None, ev)
            except BaseException as exc:  # what would abort the real receiver
                Client.errors.append(exc)
                raise
        await asyncio.Event().wait()


@pytest.fixture
def client(monkeypatch):
    Client.events, Client.errors = [], []
    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", Client)

    async def _noop(*_a: Any, **_kw: Any) -> None:
        return None

    monkeypatch.setattr(app_module, "check_for_update", _noop)
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    return Client


@pytest.fixture
def arm_loads(monkeypatch) -> list[str]:
    calls: list[str] = []

    async def _load(firewall_id: str, *_a: Any, **_kw: Any) -> None:
        calls.append(firewall_id)
        return None

    monkeypatch.setattr(app_module, "load_management_data", _load)
    return calls


def _record(resource_id: Any, i: int = 0) -> dict:
    return {
        "resourceId": resource_id, "category": "AZFWNetworkRule",
        "time": f"2026-09-05T08:00:0{i}Z",
        "properties": {"Protocol": "TCP", "SourceIp": f"10.0.0.{i}", "SourcePort": 1,
                       "DestinationIp": "10.1.0.1", "DestinationPort": 443, "Action": "Allow"},
    }


async def wait_until(pilot, cond: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await pilot.pause(0.05)


def _spy_mgmt_requests(monkeypatch, app: FirewallLogApp) -> list[str]:
    seen: list[str] = []
    original = app.request_mgmt_load

    def _spy(firewall_id: str) -> None:
        seen.append(firewall_id)
        original(firewall_id)

    monkeypatch.setattr(app, "request_mgmt_load", _spy)
    return seen


async def test_attacker_resource_id_never_reaches_arm(monkeypatch, client, arm_loads, firewall_id):
    client.events = [
        Event({"records": [_record(ATTACKER, 0), _record(ATTACKER_ROW, 1)]}),
        Event({"records": [_record(firewall_id, 2)]}),
    ]
    app = FirewallLogApp()
    requested = _spy_mgmt_requests(monkeypatch, app)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: arm_loads == [firewall_id])
        await wait_until(pilot, lambda: len(app._all_rows) == 2)
    # The upper-cased real id is the one and only id handed on.
    assert requested == [firewall_id]
    assert app._firewall_id == firewall_id
    # The attacker's records were still treated as log data, not dropped.
    assert {r.time for r in app._all_rows} == {"2026-09-05T08:00:01Z", "2026-09-05T08:00:02Z"}
    assert client.errors == []


async def test_request_mgmt_load_ignores_non_firewall_ids(client, arm_loads, firewall_id):
    client.events = []
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        for bad in (ATTACKER, ATTACKER_ROW, "https://management.azure.com" + firewall_id, ""):
            app.request_mgmt_load(bad)
        await pilot.pause(0.2)
        assert arm_loads == []
        assert app._firewall_id is None
        app.request_mgmt_load(firewall_id)
        await wait_until(pilot, lambda: arm_loads == [firewall_id])


async def test_rejected_id_never_becomes_the_subtitle(client, arm_loads, firewall_id):
    evil = ("/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/rg"
            "/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/fw\x1b]8;;https://evil\x07x")
    client.events = [Event({"records": [_record(evil, 0)]})]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 1)
        assert "\x1b" not in app.sub_title and "evil" not in app.sub_title
        assert not app._fw_name_set
        assert arm_loads == []


async def test_forged_port_is_not_rendered_as_markup(client, firewall_id):
    rec = _record(firewall_id, 0)
    rec["properties"]["DestinationPort"] = "[link=https://evil]443[/link]"
    client.events = [Event({"records": [rec]})]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 1)
        cells = app._render_cells(app._all_rows[0], app._get_filters(), True)
    port = cells[5]
    assert isinstance(port, Text)
    assert port.plain == "[link=https://evil]443[/link]"
    assert not port.spans


async def test_connection_error_toast_is_not_parsed_as_markup(monkeypatch, client):
    """Exception text is untrusted; with markup on, a '[' in it can crash or inject."""
    import viewer.streaming as streaming

    class Failing(Client):
        async def get_partition_ids(self) -> list[str]:
            raise OSError("broken [/] reply [link=https://evil]x[/link]")

    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", Failing)
    monkeypatch.setattr(streaming, "_BACKOFF", [0, 0, 0])
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: any("Connection error" in n.message for n in app._notifications))
        note = next(n for n in app._notifications if "Connection error" in n.message)
        assert note.markup is False
        assert "[link=https://evil]x[/link]" in note.message
        await pilot.pause()


@pytest.mark.parametrize("body", [
    [],
    {"records": 5},
    {"records": [1]},
    "str",
    {"records": "abc"},
    {"records": None},
    {"records": [None, "x", [1]]},
    {"records": [{"resourceId": 5, "category": []}]},
    {"records": [{"resourceId": ["x"], "category": "AZFWNetworkRule", "properties": 3}]},
    42,
    None,
])
async def test_malformed_body_does_not_stop_the_receiver(client, arm_loads, firewall_id, body):
    encoded = Event(json.dumps(body) if body == "str" else body)
    client.events = [
        encoded,
        # valid data in the same event as junk, and in a later event
        Event({"records": [1, _record(firewall_id, 0)]}),
        Event({"records": [_record(firewall_id, 1)]}),
    ]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 2)
        await wait_until(pilot, lambda: arm_loads == [firewall_id])
        status = app.query_one("#status", StatusBar)
        assert status.total == 2
    assert client.errors == []
