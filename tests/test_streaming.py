"""Streaming worker (viewer/streaming.py) with a fake Event Hub client.

The real ``EventHubConsumerClient`` is replaced by ``FakeClient`` so the
connect / probe / receive / retry / error paths run without Azure.
"""
from __future__ import annotations

import asyncio
import io
import json
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Static

import viewer.app as app_module
import viewer.streaming as streaming
from dialogs import ConnectingDialog, ErrorDialog, PolicyContextNoticeDialog, StatusBar, UpdateDialog
from viewer.app import FirewallLogApp

from .conftest import toasts

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check", "fast_backoff")

SAS_CONN = (
    "Endpoint=sb://lab-ns.servicebus.windows.net/;"
    "SharedAccessKeyName=listen;SharedAccessKey=SECRET;EntityPath=firewall-logs"
)


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def no_update_check(monkeypatch):
    async def _noop(*_a, **_kw):
        return None

    monkeypatch.setattr(app_module, "check_for_update", _noop)


@pytest.fixture
def fast_backoff(monkeypatch):
    monkeypatch.setattr(streaming, "_BACKOFF", [0, 0, 0])
    monkeypatch.setattr(streaming, "_RECONNECT_BACKOFF", [0])


class FakeEvent:
    def __init__(self, records: list[dict] | str) -> None:
        self._body = records if isinstance(records, str) else json.dumps({"records": records})

    def body_as_str(self) -> str:
        return self._body


class FakeClient:
    """Scriptable stand-in for EventHubConsumerClient (aio).

    ``script`` is a list of per-connection-attempt behaviours; each entry is a
    dict with optional keys:
      probe:   exception to raise from get_partition_ids()
      events:  list of FakeEvent (or None) to deliver via on_event
      receive: exception to raise from receive() after delivering events
    When events are delivered and no ``receive`` exception is set, receive()
    blocks until cancelled (like the real long-running receiver).
    """

    instances: list[FakeClient] = []
    script: list[dict] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.entered = False
        self.exited = False
        self.received_position: str | None = None
        FakeClient.instances.append(self)
        self._step = FakeClient.script.pop(0) if FakeClient.script else {}

    @classmethod
    def from_connection_string(cls, conn_str: str, **kwargs: Any) -> FakeClient:
        return cls(conn_str=conn_str, **kwargs)

    async def __aenter__(self) -> FakeClient:
        self.entered = True
        return self

    async def __aexit__(self, *_exc) -> bool:
        self.exited = True
        return False

    async def get_partition_ids(self) -> list[str]:
        exc = self._step.get("probe")
        if exc is not None:
            raise exc
        return ["0"]

    async def receive(self, on_event: Callable, starting_position: str) -> None:
        self.on_event = on_event  # exposed so tests can deliver events later
        self.received_position = starting_position
        for ev in self._step.get("events", []):
            await on_event(None, ev)
        exc = self._step.get("receive")
        if exc is not None:
            raise exc
        await asyncio.Event().wait()  # block until cancelled


@pytest.fixture
def fake_client(monkeypatch):
    FakeClient.instances = []
    FakeClient.script = []
    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", FakeClient)
    return FakeClient


class FakeCredential:
    instances: list[FakeCredential] = []

    def __init__(self, **kwargs: Any) -> None:
        self.closed = False
        FakeCredential.instances.append(self)

    async def get_token(self, *_scopes: str):
        class _T:
            token = "tok"
        return _T()

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_credential(monkeypatch):
    FakeCredential.instances = []
    monkeypatch.setattr(app_module, "create_credential", FakeCredential)
    return FakeCredential


async def wait_until(pilot, cond: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await pilot.pause(0.05)


def _connected(app: FirewallLogApp) -> bool:
    """True once the status bar exists and the EH segment says connected. On a slow runner the
    first poll can land before the main screen is mounted, and the query must
    not fail there."""
    bar = app.query("#status")
    return bool(bar) and bar.first(StatusBar).eh_state == "connected"


async def wait_for_dialog(pilot, app, cls, timeout: float = 5.0) -> None:
    """Wait until *cls* is the active screen and its widgets are composed."""
    await wait_until(pilot, lambda: isinstance(app.screen, cls), timeout)
    # The '#dialog' container is itself a Static with empty content and mounts
    # before its children; wait for a child with text (flaky on slow CI runners).
    await wait_until(pilot, lambda: any(str(s.content).strip() for s in app.screen.query(Static)), timeout)


def _records(firewall_id: str, n: int = 2) -> list[dict]:
    return [
        {
            "resourceId": firewall_id, "category": "AZFWNetworkRule",
            "time": f"2026-09-05T08:00:0{i}Z",
            "properties": {"Protocol": "TCP", "SourceIp": f"10.0.0.{i}", "SourcePort": 1,
                           "DestinationIp": "10.1.0.1", "DestinationPort": 443, "Action": "Allow"},
        }
        for i in range(n)
    ]


def _dialog_text(screen) -> str:
    return "\n".join(str(s.content) for s in screen.query(Static))


# ── no configuration ─────────────────────────────────────────────────────────

async def test_no_credentials_sets_error_status_without_dialog(fake_client):
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        status = app.query_one("#status", StatusBar)
        assert status.eh_state == "unconfigured"
        assert status.eh_detail == "no credentials in .env"
        assert "EH not configured · no credentials in .env" in str(status.render())
        assert status.eh_error.startswith("No Event Hub credentials configured")
        assert status.tooltip == status.eh_error  # the long text lives in the tooltip
        assert any(t.startswith("No Event Hub credentials configured") for t in toasts(app))
        assert not isinstance(app.screen, (ConnectingDialog, ErrorDialog))
        assert fake_client.instances == []


# ── SAS happy path ───────────────────────────────────────────────────────────

async def test_sas_connect_shows_splash_then_streams_rows(monkeypatch, fake_client, firewall_id):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": [FakeEvent(_records(firewall_id, 3))]}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 3)
        status = app.query_one("#status", StatusBar)
        assert status.eh_state == "connected"
        assert app.sub_title == "fw-hub"  # firewall name from the (upper-cased) resourceId, lower-cased
        assert not isinstance(app.screen, ConnectingDialog)  # popped on first real event
        client = fake_client.instances[0]
        assert client.kwargs["conn_str"] == SAS_CONN
        assert client.kwargs["consumer_group"] == "$Default"
        assert client.received_position == "@latest"


async def test_splash_shows_namespace_and_hub_but_never_the_key(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": []}]  # connected, but no events → splash stays
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ConnectingDialog)
        await wait_until(pilot, lambda: _connected(app))
        text = _dialog_text(app.screen)
        fields = {k.strip(): v.strip() for k, v in (line.split(":", 1) for line in text.splitlines() if ":" in line)}
        assert fields["Namespace"] == "lab-ns.servicebus.windows.net"
        assert fields["Hub"] == "firewall-logs"
        assert "SECRET" not in text
        assert "waiting for first event" in text


async def test_consumer_group_and_start_position_from_env(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    monkeypatch.setenv("EVENT_HUB_CONSUMER_GROUP", "watchers")
    monkeypatch.setenv("EVENT_HUB_START_POSITION", "earliest")
    fake_client.script = [{"events": []}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: bool(fake_client.instances) and fake_client.instances[0].received_position is not None)
        client = fake_client.instances[0]
        assert client.kwargs["consumer_group"] == "watchers"
        assert client.received_position == "-1"  # SDK value for "beginning of stream"


async def test_skipped_and_malformed_events_are_counted_not_displayed(monkeypatch, fake_client, firewall_id):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    other = {"resourceId": "/SUBSCRIPTIONS/x/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKS/v",
             "category": "AZFWNetworkRule", "time": "t", "properties": {}}
    fake_client.script = [{"events": [
        FakeEvent("this is not json"),
        None,
        FakeEvent([other, other]),
        FakeEvent(_records(firewall_id, 1)),
    ]}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 1)
        status = app.query_one("#status", StatusBar)
        assert status.total == 1
        assert status.skipped == 2


async def test_splash_stays_until_a_real_firewall_event(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    other = {"resourceId": "/SUBSCRIPTIONS/x/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKS/v",
             "category": "AZFWNetworkRule", "time": "t", "properties": {}}
    fake_client.script = [{"events": [FakeEvent([other])]}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: app.query_one("#status", StatusBar).skipped == 1)
        assert isinstance(app.screen, ConnectingDialog)


async def test_paused_app_drops_incoming_events(monkeypatch, fake_client, firewall_id):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": [FakeEvent(_records(firewall_id, 2))]}]
    app = FirewallLogApp()
    app._paused = True
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: fake_client.instances and fake_client.instances[0].received_position is not None)
        await pilot.pause(0.3)
        assert app._pending == []
        assert app._all_rows == []
        assert isinstance(app.screen, ConnectingDialog)


async def test_update_dialog_survives_first_event(monkeypatch, fake_client, firewall_id):
    """The Update dialog sits above the splash; the splash must go, the update must stay."""
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": []}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: _connected(app))
        await app.push_screen(UpdateDialog("9.9.9", "https://example.test/rel"))
        await pilot.pause()
        assert isinstance(app.screen, UpdateDialog)
        assert len(app.screen_stack) == 3  # main, connecting, update

        # Deliver the first real event through the same callback the client would use.
        client = fake_client.instances[0]
        await client.on_event(None, FakeEvent(_records(firewall_id, 1)))
        await pilot.pause(0.2)

        assert isinstance(app.screen, UpdateDialog)
        assert app.screen._latest == "9.9.9"
        assert not any(isinstance(s, ConnectingDialog) for s in app.screen_stack)
        assert len(app.screen_stack) == 2


async def test_policy_context_notice_survives_first_event(monkeypatch, fake_client, firewall_id, tmp_path):
    """The policy-context notice is pushed on top of the splash at start-up. The first
    event must remove the splash underneath it, keep the notice, and keep its
    callback wired so the answer still lands in .env."""
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": []}]
    env = tmp_path / ".env"
    env.write_text(f"EVENT_HUB_CONNECTION_STRING={SAS_CONN}\n", encoding="utf-8")
    app = FirewallLogApp(policy_context=True, policy_context_notice=True, env_file=env)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: _connected(app))
        # the splash is pushed *beneath* the notice, so the question is visible at once
        assert [type(s).__name__ for s in app.screen_stack] == ["Screen", "ConnectingDialog", "PolicyContextNoticeDialog"]

        client = fake_client.instances[0]
        await client.on_event(None, FakeEvent(_records(firewall_id, 1)))
        await pilot.pause(0.2)

        assert isinstance(app.screen, PolicyContextNoticeDialog)  # bug: used to be popped
        assert not any(isinstance(s, ConnectingDialog) for s in app.screen_stack)  # bug: used to linger
        assert len(app.screen_stack) == 2

        await pilot.click("#btn-disable")
        await wait_until(pilot, lambda: not isinstance(app.screen, PolicyContextNoticeDialog))
        await pilot.pause()
        assert [p.id for p in app.query("TabPane")] == ["tab-logs"]
    assert "POLICY_CONTEXT=off" in env.read_text(encoding="utf-8")


async def test_splash_lifting_the_notice_is_not_a_decline(monkeypatch, fake_client, firewall_id, tmp_path):
    """The splash pops and re-pushes the notice. ``app.pop_screen()`` drops the result
    callback without calling it, so the lift must leave consent pending and a later
    'Keep enabled' must keep policy context on."""
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": []}]
    env = tmp_path / ".env"
    env.write_text(f"EVENT_HUB_CONNECTION_STRING={SAS_CONN}\n", encoding="utf-8")
    app = FirewallLogApp(policy_context=True, policy_context_notice=True, env_file=env)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: _connected(app))
        client = fake_client.instances[0]
        await client.on_event(None, FakeEvent(_records(firewall_id, 1)))
        await pilot.pause(0.2)
        assert isinstance(app.screen, PolicyContextNoticeDialog)  # lifted and re-pushed twice by now
        assert app._policy_context
        assert app._awaiting_context_answer
        assert not app._context_decided.is_set()

        await pilot.click("#btn-keep")
        await wait_until(pilot, lambda: not isinstance(app.screen, PolicyContextNoticeDialog))
        await pilot.pause()
        assert app.arm_access_allowed()
        assert [p.id for p in app.query("TabPane")] == ["tab-logs", "tab-firewall", "tab-policy", "tab-ipgroups"]
    assert "POLICY_CONTEXT=on" in env.read_text(encoding="utf-8")


# ── retries and errors ───────────────────────────────────────────────────────

async def test_transient_errors_retry_three_times_then_error_dialog(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"probe": ConnectionError("name resolution failed")}] * 3
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert len(fake_client.instances) == 3
        assert all(c.exited for c in fake_client.instances)
        status = app.query_one("#status", StatusBar)
        assert status.eh_state == "failed"
        assert status.eh_detail == "after 3 attempts, see dialog"
        assert status.eh_error == "name resolution failed"
        assert "✖ EH failed · after 3 attempts, see dialog" in str(status.render())
        assert toasts(app).count("Connection error: name resolution failed") == 1
        text = _dialog_text(app.screen)
        assert "name resolution failed" in text
        assert "could not be reached" in text
        assert not any(isinstance(s, ConnectingDialog) for s in app.screen_stack)


async def test_probe_timeout_is_reported_as_timeout(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)

    class SlowClient(FakeClient):
        async def get_partition_ids(self):
            await asyncio.sleep(60)

    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", SlowClient)

    real_wait_for = asyncio.wait_for

    async def _short_wait_for(aw, timeout):
        return await real_wait_for(aw, timeout=0.05)

    monkeypatch.setattr(streaming.asyncio, "wait_for", _short_wait_for)

    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert "did not respond within 15 s" in _dialog_text(app.screen)


@pytest.mark.parametrize("message", ["Unauthorized access", "401 bad token", "Invalid signature", "SasKey rejected"])
async def test_auth_errors_do_not_retry_and_show_sas_hint(monkeypatch, fake_client, message):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"probe": RuntimeError(message)}] * 3
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert len(fake_client.instances) == 1
        text = _dialog_text(app.screen)
        assert message in text
        assert "--reconfigure" in text
        status = app.query_one("#status", StatusBar)
        assert status.eh_error == message                          # the tooltip carries the terminal error too
        assert status.eh_detail == "configuration error, see dialog"  # one try, not three


async def test_error_dialog_q_quits_app(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"probe": RuntimeError("Unauthorized")}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        await pilot.press("q")
        await pilot.pause(0.2)
        assert app._exit


async def test_connecting_dialog_escape_quits_app(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": []}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ConnectingDialog)
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert app._exit


async def test_receive_drop_after_connect_reconnects(monkeypatch, fake_client, firewall_id):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [
        {"events": [FakeEvent(_records(firewall_id, 1))], "receive": ConnectionResetError("link detached")},
        {"events": [FakeEvent(_records(firewall_id, 2))]},
    ]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 3)
        assert len(fake_client.instances) == 2
        assert app.query_one("#status", StatusBar).eh_state == "connected"
        assert not isinstance(app.screen, ErrorDialog)


async def test_established_connection_reconnects_beyond_three_failures(monkeypatch, fake_client, firewall_id):
    """After a successful connect, drops are retried indefinitely (no error dialog)."""
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = (
        [{"events": [FakeEvent(_records(firewall_id, 1))], "receive": ConnectionResetError("link detached")}]
        + [{"probe": ConnectionError("namespace unreachable")}] * 6
        + [{"events": [FakeEvent(_records(firewall_id, 2))]}]
    )
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 3)
        assert len(fake_client.instances) == 8
        assert not isinstance(app.screen, ErrorDialog)
        assert app.query_one("#status", StatusBar).eh_state == "connected"
        assert app.sub_title == "fw-hub"


async def test_reconnect_status_and_backoff_cap(monkeypatch, fake_client, firewall_id):
    monkeypatch.setattr(streaming, "_RECONNECT_BACKOFF", [1])
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [
        {"events": [FakeEvent(_records(firewall_id, 1))], "receive": ConnectionResetError("link detached")},
        {"probe": ConnectionError("still down")},
        {"events": []},
    ]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        status = app.query_one("#status", StatusBar)
        await wait_until(pilot, lambda: status.eh_state == "reconnecting" and status.eh_detail)
        assert status.eh_error == "link detached"  # the exception text is tooltip, not bar text
        assert status.eh_detail.startswith("attempt 1 in ")
        assert "◐ EH reconnecting · attempt 1 in " in str(status.render())
        assert app.sub_title == "Live Log Monitor  |  connection lost"
        await wait_until(pilot, lambda: status.eh_detail.startswith("attempt 2 in "))
        await wait_until(pilot, lambda: status.eh_state == "connected", timeout=8)
        assert status.eh_detail == "" and status.eh_error == ""
        assert toasts(app).count("Connection lost: link detached") == 1  # one toast per outage, not per attempt
        assert len(fake_client.instances) == 3


async def test_auth_error_after_connect_still_stops_with_dialog(monkeypatch, fake_client, firewall_id):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [
        {"events": [FakeEvent(_records(firewall_id, 1))], "receive": RuntimeError("401 Unauthorized: key rotated")},
        {"events": []},
    ]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert len(fake_client.instances) == 1
        assert "key rotated" in _dialog_text(app.screen)


async def test_worker_cancellation_pops_splash_and_stops(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    fake_client.script = [{"events": []}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: _connected(app))
        assert isinstance(app.screen, ConnectingDialog)
        app.workers.cancel_all()
        await wait_until(pilot, lambda: app.query_one("#status", StatusBar).eh_state == "stopped")
        assert not isinstance(app.screen, ConnectingDialog)
        assert app.is_running


# ── Entra ID path ────────────────────────────────────────────────────────────

async def test_entra_connect_uses_credential_and_verifies_access(monkeypatch, fake_client, fake_credential, firewall_id):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    verified: list[str] = []

    async def _verify(credential, ns, hub, **kwargs):
        verified.append(ns)

    monkeypatch.setattr(streaming, "_verify_data_plane_access", _verify)
    fake_client.script = [{"events": [FakeEvent(_records(firewall_id, 1))]}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 1)
        client = fake_client.instances[0]
        assert client.kwargs["fully_qualified_namespace"] == "lab-ns.servicebus.windows.net"
        assert client.kwargs["eventhub_name"] == "firewall-logs"
        assert isinstance(client.kwargs["credential"], FakeCredential)
        assert verified == ["lab-ns.servicebus.windows.net"]


async def test_entra_is_preferred_over_connection_string(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", SAS_CONN)
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")

    async def _verify(credential, ns, hub, **kwargs):
        return None

    monkeypatch.setattr(streaming, "_verify_data_plane_access", _verify)
    fake_client.script = [{"events": []}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: bool(fake_client.instances))
        assert "credential" in fake_client.instances[0].kwargs
        assert "conn_str" not in fake_client.instances[0].kwargs


async def test_entra_missing_role_shows_role_hint_without_retry(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")

    async def _verify(credential, ns, hub, **kwargs):
        raise PermissionError("Missing 'Azure Event Hubs Data Receiver' role on namespace 'lab-ns'.")

    monkeypatch.setattr(streaming, "_verify_data_plane_access", _verify)
    fake_client.script = [{"events": []}] * 3
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert len(fake_client.instances) == 1
        text = _dialog_text(app.screen)
        assert "Data Receiver" in text
        assert "az role assignment create" in text
        assert not fake_credential.instances[0].closed
    assert fake_credential.instances[0].closed


async def test_entra_arm_check_failure_is_ignored(monkeypatch, fake_client, fake_credential, firewall_id):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")

    async def _verify(credential, ns, hub, **kwargs):
        raise RuntimeError("ARM unreachable")

    monkeypatch.setattr(streaming, "_verify_data_plane_access", _verify)
    fake_client.script = [{"events": [FakeEvent(_records(firewall_id, 1))]}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 1)
        assert app.query_one("#status", StatusBar).eh_state == "connected"


async def test_entra_auth_error_shows_entra_hint_and_closes_credential_on_shutdown(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    fake_client.script = [{"probe": RuntimeError("403 Forbidden")}]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        text = _dialog_text(app.screen)
        assert "Entra ID authentication was rejected" in text
        assert not any(c.closed for c in fake_credential.instances)
    assert all(c.closed for c in fake_credential.instances)


async def test_one_credential_survives_transient_failures_until_shutdown(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    fake_client.script = [{"probe": ConnectionError("boom")}] * 3
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert len(fake_credential.instances) == 1
        assert all(client.kwargs["credential"] is fake_credential.instances[0] for client in fake_client.instances)
        assert not any(c.closed for c in fake_credential.instances)
    assert all(c.closed for c in fake_credential.instances)


# ── start position ───────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "value, expected",
    [
        ("latest", "@latest"),
        ("LATEST", "@latest"),
        ("", "@latest"),
        ("@latest", "@latest"),
        ("earliest", "-1"),
        ("Earliest ", "-1"),
        ("@earliest", "-1"),          # SDK-style spelling; previously matched nothing
        ("-1", "-1"),
        (None, "@latest"),
        ("12345", "12345"),           # raw offset passed through
        ("2026-09-05T08:00:00Z", "2026-09-05T08:00:00Z"),
    ],
)
def test_resolve_start_position(value, expected):
    assert streaming.resolve_start_position(value) == expected


# ── _error_hint ──────────────────────────────────────────────────────────────

def test_error_hint_variants():
    assert "az role assignment create" in streaming._error_hint(PermissionError("x"), use_entra=True)
    assert "Entra ID authentication was rejected" in streaming._error_hint(RuntimeError("401"), use_entra=True)
    assert "--reconfigure" in streaming._error_hint(RuntimeError("401"), use_entra=False)


# ── _verify_data_plane_access ────────────────────────────────────────────────

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _arm_urlopen(rg_payload: Any, perm_payload: Any):
    calls: list[str] = []

    def _urlopen(req, timeout=None):
        calls.append(req.full_url)
        if "Microsoft.ResourceGraph" in req.full_url:
            body = json.loads(req.data)
            assert "microsoft.eventhub/namespaces" in body["query"]
            assert "'lab-ns'" in body["query"]
            return _Resp(json.dumps(rg_payload).encode())
        # The permissions are read at the hub's scope, where a hub-only assignment is visible too.
        assert req.full_url.endswith(f"{NS_ID}/eventhubs/firewall-logs/providers/Microsoft.Authorization/permissions"
                                     "?api-version=2022-04-01"), req.full_url
        return _Resp(json.dumps(perm_payload).encode())

    _urlopen.calls = calls  # type: ignore[attr-defined]
    return _urlopen


NS_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/lab-ns"


@pytest.mark.parametrize(
    "data_actions",
    [
        ["Microsoft.EventHub/namespaces/messages/receive/action"],
        ["Microsoft.EventHub/*/receive/action"],
        ["*"],
        ["Microsoft.EventHub/*"],
        ["Microsoft.Storage/*", "Microsoft.EventHub/namespaces/messages/receive/action"],
    ],
)
async def test_verify_access_passes_with_receive_permission(monkeypatch, data_actions):
    fake = _arm_urlopen({"data": [{"id": NS_ID}]}, {"value": [{"dataActions": data_actions}]})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    await streaming._verify_data_plane_access(FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs")
    assert any(NS_ID in url for url in fake.calls)


async def test_verify_access_accepts_row_array_resource_graph_format(monkeypatch):
    fake = _arm_urlopen({"data": [[NS_ID]]}, {"value": [{"dataActions": ["*"]}]})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    await streaming._verify_data_plane_access(FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs")
    assert any(NS_ID in url for url in fake.calls)


@pytest.mark.parametrize(
    "data_actions",
    [
        [],
        ["Microsoft.EventHub/namespaces/messages/send/action"],
        ["Microsoft.Storage/*"],
    ],
)
async def test_verify_access_raises_without_receive_permission(monkeypatch, data_actions):
    fake = _arm_urlopen({"data": [{"id": NS_ID}]}, {"value": [{"dataActions": data_actions}]})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(PermissionError, match="Data Receiver"):
        await streaming._verify_data_plane_access(FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs")


async def test_verify_access_skips_when_namespace_not_resolvable(monkeypatch):
    fake = _arm_urlopen({"data": []}, {"value": []})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    await streaming._verify_data_plane_access(FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs")
    assert len(fake.calls) == 1  # permissions endpoint never called


async def test_receive_starts_while_access_check_is_pending(monkeypatch, fake_client, fake_credential, firewall_id):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    started, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def verify(credential, ns, hub, **kwargs):
        started.set()
        try:
            await release.wait()
        finally:
            assert not credential.closed
            finished.set()

    monkeypatch.setattr(streaming, "_verify_data_plane_access", verify)
    fake_client.script = [{"events": [FakeEvent(_records(firewall_id, 1))]}]
    app = FirewallLogApp(policy_context=True)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: started.is_set() and len(app._all_rows) == 1)
        assert _connected(app)
        assert not release.is_set()
    assert finished.is_set()
    assert fake_client.instances[0].exited
    assert fake_credential.instances[0].closed


async def test_late_missing_role_stops_active_receiver_without_retries(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    release = asyncio.Event()

    async def verify(*args, **kwargs):
        await release.wait()
        raise PermissionError("Missing Azure Event Hubs Data Receiver role")

    monkeypatch.setattr(streaming, "_verify_data_plane_access", verify)
    app = FirewallLogApp(policy_context=True)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: bool(fake_client.instances) and hasattr(fake_client.instances[0], "on_event"))
        assert _connected(app)
        release.set()
        await wait_for_dialog(pilot, app, ErrorDialog)
        assert "Data Receiver" in _dialog_text(app.screen)
        assert app.query_one("#status", StatusBar).eh_state == "failed"
        assert fake_client.instances[0].exited
        assert len(fake_client.instances) == 1


async def test_reconnect_drains_old_access_check_and_shares_identity_with_arm(
    monkeypatch, fake_client, fake_credential, firewall_id,
):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    checks: list[dict] = []
    arm_credentials = []

    async def verify(credential, *args, **kwargs):
        if checks:
            assert checks[-1]["finished"]
        entry = {"finished": False, "credential": credential}
        checks.append(entry)
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            assert not credential.closed
            entry["finished"] = True

    async def load(firewall_id, *, credential, **kwargs):
        arm_credentials.append(credential)
        return None

    monkeypatch.setattr(streaming, "_verify_data_plane_access", verify)
    monkeypatch.setattr(app_module, "load_management_data", load)
    fake_client.script = [
        {"receive": ConnectionResetError("link detached")},
        {"events": [FakeEvent(_records(firewall_id, 1))]},
    ]
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(checks) == 2 and bool(arm_credentials))
        credential = fake_credential.instances[0]
        assert len(fake_credential.instances) == 1
        assert all(client.kwargs["credential"] is credential for client in fake_client.instances)
        assert arm_credentials == [credential]
        assert checks[0]["finished"]
        assert not checks[1]["finished"]
        assert not credential.closed
    assert all(check["finished"] for check in checks)
    assert credential.closed


async def test_shutdown_drains_eh_and_arm_token_borrowers_before_closing(monkeypatch, fake_client, firewall_id):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")

    class GatedCredential:
        def __init__(self):
            self.borrowers = 0
            self.closed = 0

        async def get_token(self, *scopes):
            self.borrowers += 1
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0)
                assert self.closed == 0
                self.borrowers -= 1

        async def close(self):
            assert self.borrowers == 0
            self.closed += 1

    credential = GatedCredential()
    monkeypatch.setattr(app_module, "create_credential", lambda: credential)

    class TokenClient(FakeClient):
        async def get_partition_ids(self):
            await self.kwargs["credential"].get_token("https://eventhubs.azure.net/.default")

    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", TokenClient)

    async def load(firewall_id, *, credential, **kwargs):
        await credential.get_token("https://management.azure.com/.default")

    monkeypatch.setattr(app_module, "load_management_data", load)
    app = FirewallLogApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: credential.borrowers == 1)
        app.request_mgmt_load(firewall_id)
        await wait_until(pilot, lambda: credential.borrowers == 2)
    assert credential.closed == 1
    assert credential.borrowers == 0


@pytest.mark.parametrize("decision", ["keep", "disable", "escape", "q", "none", "off"])
async def test_entra_arm_token_and_http_wait_for_explicit_consent(
    monkeypatch, fake_client, firewall_id, decision,
):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    scopes: list[str] = []
    management = []
    credential = FakeCredential()

    async def token(*requested):
        scopes.extend(requested)
        return type("Token", (), {"token": "test-token"})()

    credential.get_token = token
    monkeypatch.setattr(app_module, "create_credential", lambda: credential)
    http = _arm_urlopen({"data": [{"id": NS_ID}]}, {"value": [{"dataActions": ["*"]}]})
    monkeypatch.setattr("urllib.request.urlopen", http)

    class TokenClient(FakeClient):
        async def get_partition_ids(self):
            await self.kwargs["credential"].get_token("https://eventhubs.azure.net/.default")
            return ["0"]

    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", TokenClient)

    async def load(firewall_id, *, credential, **kwargs):
        await credential.get_token("https://management.azure.com/.default")
        management.append(firewall_id)
        return None

    monkeypatch.setattr(app_module, "load_management_data", load)
    fake_client.script = [{"events": [FakeEvent(_records(firewall_id, 1))]}]
    app = FirewallLogApp(policy_context=decision != "off", policy_context_notice=True)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(app._all_rows) == 1)
        assert scopes == ["https://eventhubs.azure.net/.default"]
        assert http.calls == []
        assert management == []
        # Even a direct/racing worker call cannot bypass the pending decision.
        app._load_mgmt(firewall_id)
        await pilot.pause()
        assert scopes == ["https://eventhubs.azure.net/.default"]
        assert management == []
        if decision == "keep":
            await pilot.click("#btn-keep")
            await wait_until(pilot, lambda: len(http.calls) == 2 and management == [firewall_id])
            assert "https://management.azure.com/.default" in scopes
            assert len(fake_client.instances) == 1  # no reconnect needed after consent
        else:
            if decision == "disable":
                await pilot.click("#btn-disable")
            elif decision in ("escape", "q"):
                await pilot.press(decision)
            elif decision == "none":
                app.screen.dismiss(None)
            await pilot.pause()
            assert not app._policy_context
            assert scopes == ["https://eventhubs.azure.net/.default"]
            assert http.calls == []
            assert management == []
        assert _connected(app)
    assert credential.closed


async def test_pending_consent_wait_is_drained_on_reconnect_and_shutdown(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    waiters, finished, verifications = [], [], []

    class App(FirewallLogApp):
        async def wait_for_arm_permission(self):
            index = len(waiters)
            waiters.append(index)
            try:
                return await super().wait_for_arm_permission()
            finally:
                finished.append(index)

    async def verify(*args, **kwargs):
        verifications.append(True)

    monkeypatch.setattr(streaming, "_verify_data_plane_access", verify)
    fake_client.script = [{"receive": ConnectionResetError("link detached")}, {}]
    app = App(policy_context=True, policy_context_notice=True)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: len(waiters) == 2)
        assert finished == [0]
        assert verifications == []
    assert finished == [0, 1]
    assert verifications == []
    assert fake_credential.instances[0].closed


async def test_runtime_disable_cancels_role_check_but_keeps_receiver(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def verify(*args, **kwargs):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(streaming, "_verify_data_plane_access", verify)
    app = FirewallLogApp(policy_context=True)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, started.is_set)
        app._disable_policy_context()
        await wait_until(pilot, cancelled.is_set)
        assert _connected(app)
        assert not fake_client.instances[0].exited
        assert len(fake_client.instances) == 1


async def test_disable_before_queued_verifier_starts_never_requests_arm(monkeypatch, fake_client, fake_credential):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    verifications = []

    class App(FirewallLogApp):
        async def wait_for_arm_permission(self):
            allowed = await super().wait_for_arm_permission()
            if allowed:
                # Run disable after the initial permission result, before the
                # verifier task created by check_access gets its first turn.
                asyncio.get_running_loop().call_soon(self._disable_policy_context)
            return allowed

    async def verify(*args, **kwargs):
        verifications.append(True)

    monkeypatch.setattr(streaming, "_verify_data_plane_access", verify)
    app = App(policy_context=True)
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: not app._policy_context)
        await pilot.pause()
        assert verifications == []
        assert _connected(app)
        assert not fake_client.instances[0].exited


async def test_disable_while_arm_token_completes_prevents_followup_http(monkeypatch, fake_client):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "lab-ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    scopes, http = [], []
    app = FirewallLogApp(policy_context=True)

    class Credential(FakeCredential):
        async def get_token(self, *requested):
            scopes.extend(requested)
            app._disable_policy_context()
            return type("Token", (), {"token": "test-token"})()

    monkeypatch.setattr(app_module, "create_credential", Credential)
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: http.append(True))
    async with app.run_test(size=(140, 40)) as pilot:
        await wait_until(pilot, lambda: not app._policy_context)
        await pilot.pause()
        assert scopes == ["https://management.azure.com/.default"]
        assert http == []
        assert _connected(app)
        assert not fake_client.instances[0].exited


async def test_revoking_arm_access_after_namespace_lookup_skips_permissions_http(monkeypatch):
    permitted = True
    calls = []

    def urlopen(request, **kwargs):
        nonlocal permitted
        calls.append(request.full_url)
        permitted = False
        return _Resp(json.dumps({"data": [{"id": NS_ID}]}).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    await streaming._verify_data_plane_access(
        FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs", allowed=lambda: permitted,
    )
    assert len(calls) == 1
    assert "Microsoft.ResourceGraph" in calls[0]


async def test_queued_arm_http_rechecks_revocation_before_start(monkeypatch):
    permitted = True
    calls = []
    loop = asyncio.get_running_loop()

    def run_in_daemon_thread(function):
        nonlocal permitted
        permitted = False  # consent revoked before the thread got to run
        result = loop.create_future()
        result.set_result(function())
        return result

    monkeypatch.setattr(streaming, "_run_in_daemon_thread", run_in_daemon_thread)
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: calls.append(True))
    await streaming._verify_data_plane_access(
        FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs", allowed=lambda: permitted,
    )
    assert calls == []


def test_abandoned_arm_request_does_not_hold_up_quitting(monkeypatch):
    # Default-executor threads are joined by asyncio.run(), so a hanging
    # urlopen used to keep the process alive until its timeout after quit.
    started, release = threading.Event(), threading.Event()

    def urlopen(request, **kwargs):
        started.set()
        release.wait(30)
        return _Resp(b"{}")

    async def main():
        check = asyncio.create_task(streaming._verify_data_plane_access(
            FakeCredential(), "lab-ns.servicebus.windows.net", "firewall-logs"))
        while not started.is_set():
            await asyncio.sleep(0.01)
        check.cancel()
        with pytest.raises(asyncio.CancelledError):
            await check

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    begin = time.monotonic()
    try:
        asyncio.run(main())
        assert time.monotonic() - begin < 5
        assert not release.is_set()  # the request was still open at exit
    finally:
        release.set()


async def test_daemon_thread_delivers_result_and_error():
    assert await streaming._run_in_daemon_thread(lambda: 42) == 42
    with pytest.raises(ValueError, match="boom"):
        await streaming._run_in_daemon_thread(lambda: (_ for _ in ()).throw(ValueError("boom")))
