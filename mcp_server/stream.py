"""Event Hub → parser → buffer, headless.

Same connection behaviour as the TUI's ``viewer.streaming.run_stream``: three
initial attempts with a short backoff, then ``failed`` (a first-time failure is
most likely a configuration problem); once connected, a drop is transient and
reconnects forever with a capped backoff; an authentication or role error
stops at once because retrying cannot fix it. Instead of dialogs the worker
reports ``state`` and ``last_error`` for ``get_status``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Sequence
from typing import Any

from fw_parser import parse_record
from viewer import eventhub
from viewer.eventhub import EventHubSettings, build_consumer_client, is_configuration_error

from .buffer import MALFORMED_REASON, BufferedRow, LogBuffer

log = logging.getLogger(__name__)

STATES = ("connecting", "verifying", "connected", "reconnecting", "failed", "stopped")


class StreamWorker:
    """Runs the receive loop and keeps the connection state for the status tool.

    ``on_firewall_id`` is called once with the first Azure Firewall resource id
    seen in the stream (the policy context loads from it); ``on_rows`` gets every
    batch of accepted rows (the policy context checks it for unknown rules).
    """

    def __init__(self, settings: EventHubSettings, buffer: LogBuffer, *,
                 on_firewall_id: Callable[[str], None] | None = None,
                 on_rows: Callable[[list[BufferedRow]], object] | None = None,
                 backoff: Sequence[float] | None = None,
                 reconnect_backoff: Sequence[float] | None = None,
                 max_attempts: int | None = None,
                 probe_timeout: float | None = None) -> None:
        self.settings = settings
        self.buffer = buffer
        self.on_firewall_id = on_firewall_id
        self.on_rows = on_rows
        # Read the shared tables at construction, so a test can pass zeros.
        self.backoff = list(backoff if backoff is not None else eventhub.BACKOFF)
        self.reconnect_backoff = list(reconnect_backoff if reconnect_backoff is not None
                                      else eventhub.RECONNECT_BACKOFF)
        self.max_attempts = max_attempts if max_attempts is not None else eventhub.MAX_ATTEMPTS
        self.probe_timeout = probe_timeout if probe_timeout is not None else eventhub.PROBE_TIMEOUT_S
        self.state = "stopped"
        self.last_error: str | None = None
        self.connected_since: float | None = None
        self.attempt = 0
        self.firewall_id: str | None = None
        self.configuration_error = False
        self._task: asyncio.Task[None] | None = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> asyncio.Task[None]:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run(), name="azfw-event-hub-stream")
        return self._task

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.state = "stopped"
        self.connected_since = None

    async def run(self) -> None:
        """Connect, receive, reconnect. Returns when it gives up; cancel it to stop."""
        if not self.settings.configured:
            self.state, self.last_error, self.configuration_error = "failed", eventhub.NOT_CONFIGURED_MESSAGE, True
            log.error("%s", eventhub.NOT_CONFIGURED_MESSAGE)
            return
        attempt = 0
        connected_once = False   # switches to endless reconnects after the first success
        try:
            while connected_once or attempt < self.max_attempts:
                self.state = "reconnecting" if connected_once else "connecting"
                self.attempt = attempt + 1
                try:
                    await self._connect_and_receive()
                    # receive() only returns when the SDK closes the client; treat
                    # that like a drop so the loop decides what comes next.
                    raise ConnectionError("Event Hub receive loop ended")
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if self.state == "connected":
                        connected_once = True
                        attempt = 0
                    self.last_error = str(exc) or type(exc).__name__
                    self.connected_since = None
                    if is_configuration_error(exc):
                        self.configuration_error = True
                        log.error("Event Hub configuration error, not retrying: %s", self.last_error)
                        break
                    attempt += 1
                    if connected_once:
                        delay = self.reconnect_backoff[min(attempt, len(self.reconnect_backoff)) - 1]
                        self.state = "reconnecting"
                        log.warning("Event Hub connection lost (%s); reconnect %d in %ss",
                                    self.last_error, attempt, delay)
                        await asyncio.sleep(delay)
                        continue
                    if attempt >= self.max_attempts:
                        break
                    delay = self.backoff[attempt - 1]
                    log.warning("Event Hub connection error (%s); attempt %d/%d in %ss",
                                self.last_error, attempt + 1, self.max_attempts, delay)
                    await asyncio.sleep(delay)
            self.state = "failed"
            log.error("Event Hub stream stopped: %s", self.last_error)
        except asyncio.CancelledError:
            self.state = "stopped"
            self.connected_since = None
            raise

    async def _connect_and_receive(self) -> None:
        handle = build_consumer_client(self.settings)
        try:
            async with handle.client:
                # A one-shot call without the SDK's internal reconnect loop: it
                # fails fast when the namespace is wrong or unreachable.
                try:
                    await asyncio.wait_for(handle.client.get_partition_ids(), timeout=self.probe_timeout)
                except asyncio.TimeoutError:
                    raise TimeoutError(
                        f"Event Hub did not respond within {self.probe_timeout:g} s: "
                        "check the namespace, the hub name and the network"
                    ) from None
                # Event Hubs accepts receiver links regardless of permissions, so
                # only the ARM permissions API can tell a missing Data Receiver role.
                if handle.use_entra:
                    self.state = "verifying"
                    try:
                        await eventhub.verify_data_plane_access(handle.credential, handle.namespace, handle.hub)
                    except PermissionError:
                        raise
                    except Exception as exc:   # the ARM check is best-effort, as in the TUI
                        log.info("Data-plane role check skipped: %s", exc)
                self.state = "connected"
                self.connected_since = time.time()
                self.last_error = None
                self.attempt = 0
                log.info("Connected to Event Hub %s/%s (consumer group %s)",
                         handle.namespace, handle.hub, handle.consumer_group)
                await handle.client.receive(on_event=self._on_event, starting_position=handle.start_position)
        finally:
            if handle.credential is not None:
                try:
                    await handle.credential.close()
                except Exception:
                    pass

    # ── events ───────────────────────────────────────────────────────────────
    async def _on_event(self, _partition_context: Any, event: Any) -> None:
        if event is None:
            return
        self.handle_body(event.body_as_str())

    def handle_body(self, body_text: str) -> list[BufferedRow]:
        """Parse one Event Hub message body into the buffer; returns the rows accepted."""
        try:
            body = json.loads(body_text)
        except (ValueError, TypeError):
            self.buffer.count_skip(MALFORMED_REASON)
            return []
        records = body.get("records") if isinstance(body, dict) else None
        if not isinstance(records, list):
            self.buffer.count_skip(MALFORMED_REASON)
            return []
        accepted: list[BufferedRow] = []
        for rec in records:
            if not isinstance(rec, dict):
                self.buffer.count_skip(MALFORMED_REASON)
                continue
            if self.firewall_id is None:
                rid = rec.get("resourceId", "")
                if isinstance(rid, str) and "/AZUREFIREWALLS/" in rid.upper():
                    self.firewall_id = rid
                    if self.on_firewall_id is not None:
                        self.on_firewall_id(rid)
            row = parse_record(rec)
            if row is None:
                self.buffer.count_skip(MALFORMED_REASON)
                continue
            if row.category.startswith("SKIP:"):
                self.buffer.count_skip(row.category[len("SKIP:"):])
                continue
            accepted.append(self.buffer.append(row, rec))
        if accepted and self.on_rows is not None:
            self.on_rows(accepted)
        return accepted


__all__ = ["StreamWorker", "STATES"]
