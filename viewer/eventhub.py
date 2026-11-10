"""Event Hub connection plumbing without any user interface.

The MCP server needs the same connection logic as the TUI: the same
environment keys, the same start-position spelling, the same data-plane role
check and the same idea of which errors are configuration errors. This module
holds that logic free of Textual so a headless process can import it.

``viewer/streaming.py`` still carries its own originals of
``resolve_start_position``, ``_verify_data_plane_access``, ``_AUTH_KEYWORDS``
and the backoff tables. They are copies on purpose for now: an open change
(PR #35) rewrites ``streaming.py``, and touching it here would conflict. Once
that change lands, ``streaming.py`` imports these names and the duplicates go.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from helpers import _parse_eventhub_endpoint

# Keywords that indicate a configuration error rather than a transient fault.
AUTH_KEYWORDS = (
    "unauthorized", "authentication", "forbidden",
    "401", "403", "invalid signature", "saskey",
)
# Initial connection: three attempts with these delays, then give up (a
# first-time failure is most likely a configuration problem).
BACKOFF = [2, 5, 10]
MAX_ATTEMPTS = 3
# After a connection has been established once, a drop is treated as
# transient: reconnect indefinitely, backing off up to the last delay.
RECONNECT_BACKOFF = [2, 5, 10, 30, 60]
# The probe that makes a wrong namespace or a blocked network fail fast.
PROBE_TIMEOUT_S = 15

NOT_CONFIGURED_MESSAGE = (
    "No Event Hub credentials configured. Set either "
    "EVENT_HUB_NAMESPACE + EVENT_HUB_NAME (for Entra ID) or "
    "EVENT_HUB_CONNECTION_STRING (for SAS key) in .env"
)


class EventHubNotConfigured(ValueError):
    """Neither Entra ID settings nor a connection string are present."""


def resolve_start_position(value: str | None) -> str:
    """Map EVENT_HUB_START_POSITION to the SDK's starting_position.

    ``latest`` → ``"@latest"`` (only new events), ``earliest`` → ``"-1"``
    (beginning of retention), both case-insensitive and also accepted in the
    SDK spellings ``@latest`` / ``@earliest``; anything else is passed through
    unchanged so a raw offset or sequence number can be used. An empty or
    missing value means ``latest``.
    """
    raw = (value or "").strip()
    normalised = raw.lower()
    if normalised in ("", "latest", "@latest"):
        return "@latest"
    if normalised in ("earliest", "@earliest", "-1"):
        return "-1"
    return raw


def is_configuration_error(exc: BaseException) -> bool:
    """True when retrying cannot help: a missing role or rejected credentials."""
    if isinstance(exc, PermissionError):
        return True
    text = str(exc).lower()
    return any(kw in text for kw in AUTH_KEYWORDS)


async def verify_data_plane_access(credential: Any, eh_namespace: str, eh_name: str) -> None:
    """Probe ARM Permissions API to check the identity can receive from this hub.

    The check runs at the hub's own scope, not the namespace's: permissions
    granted higher up (namespace, resource group, subscription) are inherited
    and show up there too, while a role assigned on the hub alone, which is
    what the setup wizard does and what least privilege asks for, is invisible
    one level up and used to be reported as missing.

    Raises :class:`PermissionError` when the role is missing.  Silently
    returns when the namespace cannot be resolved (best-effort); other
    failures of the ARM calls propagate and the caller decides.
    """
    import urllib.request as _urllib_req

    _arm_token = (
        await credential.get_token("https://management.azure.com/.default")
    ).token
    _arm_auth = {"Authorization": f"Bearer {_arm_token}"}

    # 1. Resolve namespace resource ID via Azure Resource Graph.
    _ns_short = eh_namespace.split(".")[0]
    _rg_req = _urllib_req.Request(
        "https://management.azure.com/providers/"
        "Microsoft.ResourceGraph/resources"
        "?api-version=2021-03-01",
        data=json.dumps({
            "query": (
                "Resources"
                " | where type =~ 'microsoft.eventhub/namespaces'"
                f" | where name =~ '{_ns_short}'"
                " | project id | limit 1"
            )
        }).encode(),
        headers={**_arm_auth, "Content-Type": "application/json"},
        method="POST",
    )
    _loop = asyncio.get_running_loop()
    _rg_resp = json.loads(
        await _loop.run_in_executor(
            None,
            lambda: _urllib_req.urlopen(_rg_req, timeout=10).read(),
        )
    )
    _rg_rows = _rg_resp.get("data") or []
    if not _rg_rows:
        return  # could not resolve, so skip the check

    _ns_id: str = (
        _rg_rows[0]["id"] if isinstance(_rg_rows[0], dict) else _rg_rows[0][0]
    )

    # 2. Check effective data-plane permissions at the hub's scope.
    _perm_req = _urllib_req.Request(
        f"https://management.azure.com{_ns_id}/eventhubs/{eh_name}"
        "/providers/Microsoft.Authorization/permissions"
        "?api-version=2022-04-01",
        headers=_arm_auth,
        method="GET",
    )
    _data_actions: list[str] = []
    for _entry in json.loads(
        await _loop.run_in_executor(
            None,
            lambda: _urllib_req.urlopen(_perm_req, timeout=10).read(),
        )
    ).get("value", []):
        _data_actions.extend(_entry.get("dataActions", []))
    if not any(
        # RG/subscription-inherited assignments use wildcard form like
        # "Microsoft.EventHub/*/receive/action"
        ("eventhub" in _a.lower() and "receive" in _a.lower())
        or _a.lower() in ("*", "microsoft.eventhub/*")
        for _a in _data_actions
    ):
        raise PermissionError(
            f"Missing 'Azure Event Hubs Data Receiver' "
            f"(or 'Data Owner') role on hub '{eh_name}' or namespace '{_ns_short}'."
        )


@dataclass(frozen=True)
class EventHubSettings:
    """The Event Hub keys of ``.env``, resolved the way the TUI resolves them.

    The connection string is kept out of ``repr`` so that logging a settings
    object can never leak the SAS key.
    """

    connection_string: str = field(default="", repr=False)
    fq_namespace: str = ""          # EVENT_HUB_NAMESPACE, fully qualified
    hub_name: str = ""              # EVENT_HUB_NAME
    consumer_group: str = "$Default"
    start_position_raw: str = "latest"

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> EventHubSettings:
        return cls(
            connection_string=environ.get("EVENT_HUB_CONNECTION_STRING", "") or "",
            fq_namespace=environ.get("EVENT_HUB_NAMESPACE", "") or "",
            hub_name=environ.get("EVENT_HUB_NAME", "") or "",
            consumer_group=environ.get("EVENT_HUB_CONSUMER_GROUP", "") or "$Default",
            start_position_raw=environ.get("EVENT_HUB_START_POSITION", "") or "latest",
        )

    @property
    def use_entra(self) -> bool:
        """Entra ID wins over a connection string whenever namespace and hub are set."""
        return bool(self.fq_namespace and self.hub_name)

    @property
    def configured(self) -> bool:
        return self.use_entra or bool(self.connection_string)

    @property
    def start_position(self) -> str:
        return resolve_start_position(self.start_position_raw)

    @property
    def display_endpoint(self) -> tuple[str, str]:
        """``(namespace, hub)`` for display; never derived in a way that returns the key."""
        if self.use_entra:
            return self.fq_namespace, self.hub_name
        if self.connection_string:
            return _parse_eventhub_endpoint(self.connection_string)
        return "", ""


@dataclass
class ConsumerHandle:
    """One connection attempt's client plus what is needed to describe it.

    ``credential`` is the Entra ID credential the client uses, ``None`` for
    SAS. The caller closes it after the client, as the TUI does.
    """

    client: Any
    credential: Any | None
    namespace: str
    hub: str
    use_entra: bool
    consumer_group: str
    start_position: str


def build_consumer_client(environ: Mapping[str, str] | EventHubSettings) -> ConsumerHandle:
    """Build an ``EventHubConsumerClient`` exactly as the TUI does.

    ``retry_total=0`` keeps the SDK from retrying on its own, so the caller's
    backoff decides; ``load_balancing_interval=1`` claims partitions quickly.
    Raises :class:`EventHubNotConfigured` when nothing is configured.
    """
    from azure.eventhub.aio import EventHubConsumerClient

    settings = environ if isinstance(environ, EventHubSettings) else EventHubSettings.from_env(environ)
    if not settings.configured:
        raise EventHubNotConfigured(NOT_CONFIGURED_MESSAGE)
    namespace, hub = settings.display_endpoint
    credential: Any | None = None
    if settings.use_entra:
        from azure.core.pipeline.transport import AsyncioRequestsTransport
        from azure.identity.aio import DefaultAzureCredential
        credential = DefaultAzureCredential(transport=AsyncioRequestsTransport())
        client = EventHubConsumerClient(
            fully_qualified_namespace=settings.fq_namespace,
            eventhub_name=settings.hub_name,
            consumer_group=settings.consumer_group,
            credential=credential,
            load_balancing_interval=1,
            retry_total=0,
        )
    else:
        client = EventHubConsumerClient.from_connection_string(
            settings.connection_string,
            consumer_group=settings.consumer_group,
            load_balancing_interval=1,
            retry_total=0,
        )
    return ConsumerHandle(
        client=client,
        credential=credential,
        namespace=namespace,
        hub=hub,
        use_entra=settings.use_entra,
        consumer_group=settings.consumer_group,
        start_position=settings.start_position,
    )


__all__ = [
    "AUTH_KEYWORDS", "BACKOFF", "MAX_ATTEMPTS", "RECONNECT_BACKOFF", "PROBE_TIMEOUT_S", "NOT_CONFIGURED_MESSAGE",
    "EventHubNotConfigured", "EventHubSettings", "ConsumerHandle", "build_consumer_client",
    "resolve_start_position", "is_configuration_error", "verify_data_plane_access",
]
