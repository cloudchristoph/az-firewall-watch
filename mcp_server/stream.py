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
from collections import deque
from collections.abc import Callable, Sequence
from typing import Any

from fw_parser import parse_record
from viewer import eventhub
from viewer.arm import is_firewall_resource_id
from viewer.eventhub import EventHubSettings, build_consumer_client, is_configuration_error

from .buffer import MALFORMED_REASON, BufferedRow, LogBuffer

log = logging.getLogger(__name__)

STATES = ("connecting", "verifying", "connected", "reconnecting", "failed", "stopped")

# Warm-up detection. With EVENT_HUB_START_POSITION=earliest the hub replays up
# to its whole retention right after the connect (tens of thousands of rows in
# the first seconds on a busy firewall). A client that asks during that burst
# sees a partial buffer, so the worker reports ``replaying`` while either
# holds: the connection is young and rows pour in faster than live traffic
# ever does, or the newest log is still far behind the wall clock while rows
# keep arriving (the tail of the replay, where the rate has already dropped).
WARMUP_S = 30.0              # a connection younger than this may still be in the initial burst
RATE_WINDOW_S = 2.0          # rows are counted over this sliding window
RATE_THRESHOLD = 200         # more rows than this per window is a replay, not live traffic
# Azure's diagnostics pipeline delivers a row a minute or two after the event
# (measured on the lab hub: about 60 s), so a lag below three minutes is normal
# live operation and must not look like a replay.
LAG_THRESHOLD_S = 180.0
# The lag only counts while rows still arrive: a quiet hub whose newest log is
# old is not replaying. The window is generous because a replay pauses for up
# to ten seconds between partitions (seen live), and a short gap must not drop
# the flag with hours of retention still to come.
ARRIVAL_WINDOW_S = 20.0


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
        self._rejected_id_logged = False   # warn once, not once per record
        self.configuration_error = False
        self._task: asyncio.Task[None] | None = None
        # The clock is an attribute so a test can freeze it; it feeds the
        # connection age and the receive-rate window.
        self.clock: Callable[[], float] = time.time
        # (wall clock, accepted rows) per handled body, pruned to the longest
        # window the warm-up check looks at.
        self._arrivals: deque[tuple[float, int]] = deque()

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
                self.connected_since = self.clock()
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
                # The id goes to ARM as a path with the caller's bearer token, so a
                # record from the hub only counts when it is exactly a firewall id.
                # Anything else (a URL, a traversal, another resource type) is
                # parsed as a row but never named as the firewall.
                rid = rec.get("resourceId", "")
                if is_firewall_resource_id(rid):
                    self.firewall_id = rid
                    if self.on_firewall_id is not None:
                        self.on_firewall_id(rid)
                elif isinstance(rid, str) and "/AZUREFIREWALLS/" in rid.upper() and not self._rejected_id_logged:
                    self._rejected_id_logged = True
                    log.warning("Ignoring a record whose resourceId is not a well-formed Azure Firewall id: %r",
                                rid[:200])
            row = parse_record(rec)
            if row is None:
                self.buffer.count_skip(MALFORMED_REASON)
                continue
            if row.category.startswith("SKIP:"):
                self.buffer.count_skip(row.category[len("SKIP:"):])
                continue
            accepted.append(self.buffer.append(row, rec))
        self._note_arrival(len(accepted))
        if accepted and self.on_rows is not None:
            self.on_rows(accepted)
        return accepted

    # ── warm-up (retention replay) ───────────────────────────────────────────
    def _note_arrival(self, rows: int) -> None:
        now = self.clock()
        self._arrivals.append((now, rows))
        horizon = now - max(RATE_WINDOW_S, ARRIVAL_WINDOW_S)
        while self._arrivals and self._arrivals[0][0] < horizon:
            self._arrivals.popleft()

    def rows_in_last(self, seconds: float, now: float | None = None) -> int:
        """Accepted rows handled in the last ``seconds`` (at most the pruning horizon)."""
        now = self.clock() if now is None else now
        cutoff = now - seconds
        return sum(n for t, n in self._arrivals if t >= cutoff)

    @property
    def newest_log_lag_s(self) -> float | None:
        """How far the newest buffered log time is behind the wall clock, ``None`` before the first row."""
        newest = self.buffer.last_log_time
        if newest is None:
            return None
        return max(0.0, self.clock() - newest)

    @property
    def replaying(self) -> bool:
        """Whether the stream is still catching up on the hub's retention (see the module constants).

        Only a connected stream replays: a worker that is still connecting has
        nothing in the buffer yet, and a failed one will not fill it any further.
        """
        if self.state != "connected" or self.connected_since is None:
            return False
        now = self.clock()
        if now - self.connected_since < WARMUP_S and self.rows_in_last(RATE_WINDOW_S, now) > RATE_THRESHOLD:
            return True
        if self.settings.start_position == "@latest":
            return False
        lag = self.newest_log_lag_s
        return lag is not None and lag > LAG_THRESHOLD_S and self.rows_in_last(ARRIVAL_WINDOW_S, now) > 0


__all__ = ["StreamWorker", "STATES"]
