"""StreamWorker (mcp_server/stream.py) against a fake Event Hub client.

Same scripted ``FakeClient`` idea as ``test_streaming.py``: the SDK class is
replaced on ``azure.eventhub.aio`` so connect, probe, receive, retry and error
paths run without Azure. No test may see anything on stdout, because with the
stdio transport stdout is the protocol channel.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import pytest

import viewer.eventhub as eventhub
from mcp_server.buffer import LogBuffer
from mcp_server.stream import StreamWorker
from viewer.eventhub import EventHubSettings

SAS_CONN = (
    "Endpoint=sb://lab-ns.servicebus.windows.net/;"
    "SharedAccessKeyName=listen;SharedAccessKey=SECRET;EntityPath=firewall-logs"
)
SAS = EventHubSettings(connection_string=SAS_CONN, consumer_group="mcp", start_position_raw="earliest")
ENTRA = EventHubSettings(fq_namespace="lab-ns.servicebus.windows.net", hub_name="firewall-logs")


class FakeEvent:
    def __init__(self, records: list[dict] | str) -> None:
        self._body = records if isinstance(records, str) else json.dumps({"records": records})

    def body_as_str(self) -> str:
        return self._body


class FakeClient:
    """Per-connection script entries: ``probe`` (exception), ``events``, ``receive`` (exception)."""

    instances: list[FakeClient] = []
    script: list[dict] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.exited = False
        self.received_position: str | None = None
        FakeClient.instances.append(self)
        self._step = FakeClient.script.pop(0) if FakeClient.script else {}

    @classmethod
    def from_connection_string(cls, conn_str: str, **kwargs: Any) -> FakeClient:
        return cls(conn_str=conn_str, **kwargs)

    async def __aenter__(self) -> FakeClient:
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
        self.received_position = starting_position
        for ev in self._step.get("events", []):
            await on_event(None, ev)
        exc = self._step.get("receive")
        if exc is not None:
            raise exc
        await asyncio.Event().wait()


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
def fake_client(monkeypatch):
    FakeClient.instances = []
    FakeClient.script = []
    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", FakeClient)
    return FakeClient


@pytest.fixture
def fake_credential(monkeypatch):
    FakeCredential.instances = []
    import azure.identity.aio as ident
    monkeypatch.setattr(ident, "DefaultAzureCredential", FakeCredential)
    return FakeCredential


@pytest.fixture
def verified(monkeypatch) -> list[str]:
    calls: list[str] = []

    async def _verify(credential, ns, hub):
        calls.append(f"{ns}/{hub}")

    monkeypatch.setattr(eventhub, "verify_data_plane_access", _verify)
    return calls


@pytest.fixture(autouse=True)
def nothing_on_stdout(capsys):
    yield
    assert capsys.readouterr().out == ""


def make_worker(settings: EventHubSettings = SAS, **kw: Any) -> StreamWorker:
    kw.setdefault("backoff", [0, 0, 0])
    kw.setdefault("reconnect_backoff", [0])
    return StreamWorker(settings, LogBuffer(100), **kw)


def records(firewall_id: str, n: int = 2, action: str = "Allow") -> list[dict]:
    return [
        {"resourceId": firewall_id, "category": "AZFWNetworkRule", "time": f"2026-09-05T08:00:0{i}Z",
         "properties": {"Protocol": "TCP", "SourceIp": f"10.0.0.{i}", "SourcePort": 1,
                        "DestinationIp": "10.1.0.1", "DestinationPort": 443, "Action": action}}
        for i in range(n)
    ]


async def wait_until(cond: Callable[[], bool], timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.01)


# ── happy paths ──────────────────────────────────────────────────────────────

async def test_sas_connect_streams_rows_and_reports_firewall_once(fake_client, firewall_id):
    seen: list[str] = []
    batches: list[int] = []
    fake_client.script = [{"events": [FakeEvent(records(firewall_id, 2)), FakeEvent(records(firewall_id, 1))]}]
    worker = make_worker(on_firewall_id=seen.append, on_rows=lambda rows: batches.append(len(rows)))
    assert worker.state == "stopped"
    worker.start()
    await wait_until(lambda: worker.buffer.size == 3)
    assert worker.state == "connected"
    assert worker.connected_since is not None and worker.last_error is None
    client = fake_client.instances[0]
    assert client.kwargs["conn_str"] == SAS_CONN
    assert client.kwargs["consumer_group"] == "mcp"
    assert client.kwargs["retry_total"] == 0
    assert client.received_position == "-1"
    assert seen == [firewall_id] and worker.firewall_id == firewall_id
    assert batches == [2, 1]
    await worker.stop()
    assert worker.state == "stopped" and worker.connected_since is None
    assert client.exited


async def test_entra_connect_uses_credential_verifies_and_closes(fake_client, fake_credential, verified, firewall_id):
    fake_client.script = [{"events": [FakeEvent(records(firewall_id, 1))]}]
    worker = make_worker(ENTRA)
    worker.start()
    await wait_until(lambda: worker.buffer.size == 1)
    client = fake_client.instances[0]
    assert client.kwargs["fully_qualified_namespace"] == "lab-ns.servicebus.windows.net"
    assert client.kwargs["eventhub_name"] == "firewall-logs"
    assert client.kwargs["consumer_group"] == "$Default"
    assert isinstance(client.kwargs["credential"], FakeCredential)
    assert client.received_position == "@latest"
    assert verified == ["lab-ns.servicebus.windows.net/firewall-logs"]
    await worker.stop()
    assert fake_credential.instances[0].closed


async def test_entra_state_passes_through_verifying(fake_client, fake_credential, monkeypatch, firewall_id):
    states: list[str] = []
    worker = make_worker(ENTRA)

    async def _verify(credential, ns, hub):
        states.append(worker.state)

    monkeypatch.setattr(eventhub, "verify_data_plane_access", _verify)
    fake_client.script = [{"events": [FakeEvent(records(firewall_id, 1))]}]
    worker.start()
    await wait_until(lambda: worker.state == "connected")
    assert states == ["verifying"]
    await worker.stop()


async def test_arm_check_failure_is_ignored(fake_client, fake_credential, monkeypatch, firewall_id):
    async def _verify(credential, ns, hub):
        raise RuntimeError("ARM unreachable")

    monkeypatch.setattr(eventhub, "verify_data_plane_access", _verify)
    fake_client.script = [{"events": [FakeEvent(records(firewall_id, 1))]}]
    worker = make_worker(ENTRA)
    worker.start()
    await wait_until(lambda: worker.buffer.size == 1)
    assert worker.state == "connected"
    await worker.stop()


# ── what gets counted instead of kept ────────────────────────────────────────

async def test_skips_counted_by_reason(fake_client, firewall_id):
    other = dict(records(firewall_id, 1)[0], resourceId="/SUBSCRIPTIONS/X/PROVIDERS/MICROSOFT.SQL/SERVERS/DB")
    unknown = dict(records(firewall_id, 1)[0], category="AzureFirewallSomethingNew")
    fake_client.script = [{"events": [
        FakeEvent([other, unknown, *records(firewall_id, 1)]),
        FakeEvent("not json"),
        FakeEvent(json.dumps([1, 2])),
        FakeEvent(json.dumps({"records": ["oops"]})),
        None,   # the SDK delivers None on idle timeouts; ignored
    ]}]
    worker = make_worker()
    worker.start()
    await wait_until(lambda: worker.buffer.skipped["MalformedEvent"] == 3)
    assert worker.buffer.size == 1
    assert worker.buffer.skipped == {"ResourceType": 1, "Category:AzureFirewallSomethingNew": 1, "MalformedEvent": 3}
    await worker.stop()


def test_firewall_id_comes_from_the_first_firewall_record(firewall_id):
    seen: list[str] = []
    worker = make_worker(on_firewall_id=seen.append)
    not_fw = {"resourceId": "/SUBSCRIPTIONS/X/PROVIDERS/MICROSOFT.NETWORK/PUBLICIPADDRESSES/PIP",
              "category": "AZFWNetworkRule", "time": "2026-09-05T08:00:00Z", "properties": {}}
    worker.handle_body(json.dumps({"records": [not_fw]}))
    assert seen == [] and worker.firewall_id is None
    worker.handle_body(json.dumps({"records": records(firewall_id, 2)}))
    worker.handle_body(json.dumps({"records": records(firewall_id.replace("FW-HUB", "FW-OTHER"), 1)}))
    assert seen == [firewall_id]


# ── retry and reconnect ──────────────────────────────────────────────────────

async def test_three_transient_failures_before_first_connect_fail(fake_client):
    fake_client.script = [{"probe": ConnectionError("name resolution failed")}] * 3
    worker = make_worker()
    await asyncio.wait_for(worker.run(), 3)
    assert len(fake_client.instances) == 3
    assert all(c.exited for c in fake_client.instances)
    assert worker.state == "failed"
    assert worker.last_error == "name resolution failed"
    assert not worker.configuration_error


@pytest.mark.parametrize("message", ["Unauthorized access", "401 bad token", "Invalid signature", "SasKey rejected",
                                     "403 Forbidden"])
async def test_configuration_error_stops_without_retry(fake_client, message):
    fake_client.script = [{"probe": RuntimeError(message)}] * 3
    worker = make_worker()
    await asyncio.wait_for(worker.run(), 3)
    assert len(fake_client.instances) == 1
    assert (worker.state, worker.last_error, worker.configuration_error) == ("failed", message, True)


async def test_missing_role_stops_and_closes_credential(fake_client, fake_credential, monkeypatch):
    async def _verify(credential, ns, hub):
        raise PermissionError("Missing 'Azure Event Hubs Data Receiver' role on hub 'firewall-logs'.")

    monkeypatch.setattr(eventhub, "verify_data_plane_access", _verify)
    fake_client.script = [{"events": []}] * 3
    worker = make_worker(ENTRA)
    await asyncio.wait_for(worker.run(), 3)
    assert len(fake_client.instances) == 1
    assert worker.state == "failed" and "Data Receiver" in (worker.last_error or "")
    assert all(c.closed for c in fake_credential.instances)


async def test_credentials_closed_on_every_transient_failure(fake_client, fake_credential):
    fake_client.script = [{"probe": ConnectionError("boom")}] * 3
    worker = make_worker(ENTRA)
    await asyncio.wait_for(worker.run(), 3)
    assert len(fake_credential.instances) == 3
    assert all(c.closed for c in fake_credential.instances)


async def test_drop_after_connect_reconnects(fake_client, firewall_id):
    fake_client.script = [
        {"events": [FakeEvent(records(firewall_id, 1))], "receive": ConnectionError("link detached")},
        {"events": [FakeEvent(records(firewall_id, 2))]},
    ]
    worker = make_worker()
    worker.start()
    await wait_until(lambda: worker.buffer.size == 3)
    assert len(fake_client.instances) == 2
    assert worker.state == "connected" and worker.last_error is None
    await worker.stop()


async def test_established_connection_retries_beyond_three_failures(fake_client, firewall_id):
    fake_client.script = [
        {"events": [FakeEvent(records(firewall_id, 1))], "receive": ConnectionError("drop")},
        *[{"probe": ConnectionError("still down")}] * 5,
        {"events": [FakeEvent(records(firewall_id, 1))]},
    ]
    worker = make_worker()
    worker.start()
    await wait_until(lambda: worker.buffer.size == 2)
    assert len(fake_client.instances) == 7
    assert worker.state == "connected"
    await worker.stop()


async def test_reconnecting_state_and_capped_backoff(fake_client, firewall_id, monkeypatch):
    delays: list[float] = []
    real_sleep = asyncio.sleep

    async def _sleep(delay, *a, **kw):
        # The patch reaches every asyncio.sleep, wait_until's polls included;
        # only the worker sleeps whole seconds.
        if delay >= 1:
            delays.append(delay)
            delay = 0
        await real_sleep(delay)

    fake_client.script = [
        {"events": [FakeEvent(records(firewall_id, 1))], "receive": ConnectionError("drop")},
        *[{"probe": ConnectionError("down")}] * 4,
        {"events": []},
    ]
    worker = make_worker(reconnect_backoff=[1, 7])
    monkeypatch.setattr("mcp_server.stream.asyncio.sleep", _sleep)
    states: list[str] = []
    original = FakeClient.get_partition_ids

    async def _probe(self):
        states.append(worker.state)
        return await original(self)

    monkeypatch.setattr(FakeClient, "get_partition_ids", _probe)
    worker.start()
    await wait_until(lambda: len(fake_client.instances) == 6 and worker.state == "connected")
    assert delays == [1, 7, 7, 7, 7]
    assert states == ["connecting"] + ["reconnecting"] * 5
    await worker.stop()


async def test_auth_error_after_connect_still_stops(fake_client, firewall_id):
    fake_client.script = [
        {"events": [FakeEvent(records(firewall_id, 1))], "receive": RuntimeError("401 token expired")},
        {"events": []},
    ]
    worker = make_worker()
    await asyncio.wait_for(worker.run(), 3)
    assert len(fake_client.instances) == 1
    assert worker.state == "failed" and worker.configuration_error


async def test_probe_timeout_is_reported_as_timeout(fake_client, monkeypatch):
    class SlowClient(FakeClient):
        async def get_partition_ids(self):
            await asyncio.sleep(60)

    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", SlowClient)
    worker = make_worker(probe_timeout=0.02)
    await asyncio.wait_for(worker.run(), 3)
    assert worker.state == "failed"
    assert "did not respond within 0.02 s" in (worker.last_error or "")


async def test_unconfigured_settings_fail_at_once(fake_client):
    worker = make_worker(EventHubSettings())
    await worker.run()
    assert worker.state == "failed" and worker.configuration_error
    assert "No Event Hub credentials configured" in (worker.last_error or "")
    assert fake_client.instances == []


async def test_stop_while_connecting_sets_stopped(fake_client, monkeypatch):
    class SlowClient(FakeClient):
        async def get_partition_ids(self):
            await asyncio.sleep(60)

    import azure.eventhub.aio as eh_aio
    monkeypatch.setattr(eh_aio, "EventHubConsumerClient", SlowClient)
    worker = make_worker()
    worker.start()
    await wait_until(lambda: bool(SlowClient.instances))
    assert worker.state == "connecting"
    await worker.stop()
    assert worker.state == "stopped"


# ── warm-up: replaying the hub's retention ───────────────────────────────────

EARLIEST = SAS
LATEST = EventHubSettings(connection_string=SAS_CONN, consumer_group="mcp", start_position_raw="latest")


def old_records(firewall_id: str, n: int, time: str = "2026-09-05T08:00:00Z") -> list[dict]:
    """``n`` rows that all carry the same log time, so the lag is a known number."""
    return [dict(records(firewall_id, 1)[0], time=time) for _ in range(n)]


def connected_worker(settings: EventHubSettings, now: float, *, since: float) -> StreamWorker:
    """A worker as it looks after a successful connect, with a frozen clock."""
    worker = make_worker(settings)
    worker.clock = lambda: now
    worker.state = "connected"
    worker.connected_since = now - since
    return worker


def test_not_replaying_before_the_connect_or_after_a_failure(firewall_id):
    worker = make_worker(EARLIEST)
    assert worker.replaying is False and worker.newest_log_lag_s is None
    worker.state = "failed"
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 300)}))
    assert worker.replaying is False


def test_replaying_during_the_initial_burst_ends_with_the_rate_or_the_age(firewall_id):
    now = 1_800_000_000.0
    worker = connected_worker(LATEST, now, since=1)
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 150)}))
    assert worker.rows_in_last(2) == 150
    assert worker.replaying is False           # live traffic can look like this
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 100)}))
    assert worker.rows_in_last(2) == 250 and worker.replaying is True
    # The burst stops: nothing in the last two seconds, the connection is still young.
    worker.clock = lambda: now + 3
    assert worker.rows_in_last(2) == 0 and worker.replaying is False
    # Rows pour in again, but the connection is older than the warm-up: a busy
    # firewall at steady state, not a replay (start position latest, so no lag check).
    worker.clock = lambda: now + 31
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 500)}))
    assert worker.replaying is False


def test_replaying_by_lag_only_while_rows_arrive_and_only_with_an_old_start_position(firewall_id):
    now = 1_800_000_000.0
    worker = connected_worker(EARLIEST, now, since=40)
    # One old row a moment ago: the tail of the replay, well below the rate threshold.
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 1, time="2026-09-05T08:00:00Z")}))
    assert worker.newest_log_lag_s is not None and worker.newest_log_lag_s > 3600
    assert worker.replaying is True
    # A ten-second pause is how the hub switches partitions mid-replay; the flag holds.
    worker.clock = lambda: now + 10
    assert worker.replaying is True
    # Half a minute of silence: a quiet hub whose newest log happens to be old is not replaying.
    worker.clock = lambda: now + 30
    assert worker.replaying is False
    # A row from the last three minutes arrives: Azure's pipeline latency, not a replay.
    worker.clock = lambda: now + 31
    fresh = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 31 - 90))
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 1, time=fresh)}))
    assert worker.newest_log_lag_s == pytest.approx(90, abs=1)
    assert worker.replaying is False


def test_lag_is_ignored_with_start_position_latest(firewall_id):
    now = 1_800_000_000.0
    worker = connected_worker(LATEST, now, since=40)
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 1)}))
    assert worker.newest_log_lag_s is not None and worker.newest_log_lag_s > 3600
    assert worker.replaying is False


def test_arrival_window_is_pruned(firewall_id):
    now = 1_800_000_000.0
    worker = connected_worker(EARLIEST, now, since=1)
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 10)}))
    worker.clock = lambda: now + 25
    worker.handle_body(json.dumps({"records": old_records(firewall_id, 1)}))
    assert len(worker._arrivals) == 1 and worker.rows_in_last(60) == 1
