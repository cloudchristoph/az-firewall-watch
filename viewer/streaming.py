"""Azure Event Hub streaming worker for the viewer TUI.

The :func:`run_stream` coroutine connects to the configured Event Hub
(SAS or Entra ID), verifies data-plane permissions via the ARM
Permissions API when using Entra ID, then dispatches parsed records
back into the app's pending queue.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING

from dialogs import ConnectingDialog, ErrorDialog, StatusBar, UpdateDialog
from fw_parser import parse_record
from helpers import _parse_eventhub_endpoint

if TYPE_CHECKING:
    from .app import FirewallLogApp


# Keywords that indicate a configuration error rather than a transient fault.
_AUTH_KEYWORDS = (
    "unauthorized", "authentication", "forbidden",
    "401", "403", "invalid signature", "saskey",
)
# Exponential backoff delays in seconds between the three attempts.
_BACKOFF = [2, 5, 10]
_MAX_ATTEMPTS = 3


async def _verify_data_plane_access(credential, eh_namespace: str) -> None:
    """Probe ARM Permissions API to check the identity can receive from this namespace.

    Raises :class:`PermissionError` when the role is missing.  Silently
    returns when the ARM check itself fails (best-effort).
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
    _loop = asyncio.get_event_loop()
    _rg_resp = json.loads(
        await _loop.run_in_executor(
            None,
            lambda: _urllib_req.urlopen(_rg_req, timeout=10).read(),
        )
    )
    _rg_rows = _rg_resp.get("data") or []
    if not _rg_rows:
        return  # could not resolve — skip the check

    _ns_id: str = (
        _rg_rows[0]["id"] if isinstance(_rg_rows[0], dict) else _rg_rows[0][0]
    )

    # 2. Check effective data-plane permissions.
    _perm_req = _urllib_req.Request(
        f"https://management.azure.com{_ns_id}"
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
            f"(or 'Data Owner') role on namespace '{_ns_short}'."
        )


def _error_hint(exc: Exception, use_entra: bool) -> str:
    if isinstance(exc, PermissionError):
        return (
            "Assign the role in the Azure portal (namespace → Access control (IAM))\n"
            "or via Azure CLI:\n"
            "  az role assignment create "
            "--assignee <your-id> "
            "--role 'Azure Event Hubs Data Receiver' "
            "--scope <namespace-resource-id>"
        )
    if use_entra:
        return (
            "Entra ID authentication was rejected.\n"
            "Ensure your identity has the 'Azure Event Hubs Data Receiver' role\n"
            "on the Event Hub namespace or entity, then restart the app."
        )
    return (
        "The credentials in your connection string were rejected.\n"
        "Restart the app with  --reconfigure  to update the settings."
    )


async def run_stream(app: "FirewallLogApp") -> None:
    """Connect to Event Hub and stream events; reconnects automatically on error."""
    from azure.eventhub.aio import EventHubConsumerClient  # type: ignore[import]

    conn_str = os.environ.get("EVENT_HUB_CONNECTION_STRING", "")
    eh_namespace = os.environ.get("EVENT_HUB_NAMESPACE", "")  # fully qualified, e.g. mynamespace.servicebus.windows.net
    eh_name = os.environ.get("EVENT_HUB_NAME", "")
    consumer_group = os.environ.get("EVENT_HUB_CONSUMER_GROUP", "$Default")
    start_pos = os.environ.get("EVENT_HUB_START_POSITION", "latest")
    position = "@latest" if start_pos == "latest" else "@earliest"
    use_entra = bool(eh_namespace and eh_name)

    status = app.query_one("#status", StatusBar)

    if not conn_str and not use_entra:
        status.status = (
            "ERROR: No Event Hub credentials configured — set either "
            "EVENT_HUB_NAMESPACE + EVENT_HUB_NAME (for Entra ID) or "
            "EVENT_HUB_CONNECTION_STRING (for SAS key) in .env"
        )
        return

    # Resolve display values for the connecting dialog.
    if use_entra:
        namespace = eh_namespace
        hub = eh_name
    else:
        namespace, hub = _parse_eventhub_endpoint(conn_str)

    attempt = 0
    last_exc: Exception | None = None

    # Show the connecting splash and keep a flag so we know when to dismiss it.
    _dialog = ConnectingDialog(namespace, hub)
    await app.push_screen(_dialog)
    _splash_shown = True
    _credential = None  # track credential for cleanup on error

    while attempt < _MAX_ATTEMPTS:
        app.sub_title = "Live Log Monitor  |  connecting..."
        status.status = "Connecting to Event Hub…"

        try:
            # Build the client — prefer Entra ID when namespace+hub are set.
            if use_entra:
                from azure.core.pipeline.transport import AsyncioRequestsTransport
                from azure.identity.aio import DefaultAzureCredential  # type: ignore[import]
                _credential = DefaultAzureCredential(transport=AsyncioRequestsTransport())
                client = EventHubConsumerClient(
                    fully_qualified_namespace=eh_namespace,
                    eventhub_name=eh_name,
                    consumer_group=consumer_group,
                    credential=_credential,
                    load_balancing_interval=1,
                    retry_total=0,
                )
            else:
                _credential = None
                client = EventHubConsumerClient.from_connection_string(
                    conn_str,
                    consumer_group=consumer_group,
                    load_balancing_interval=1,
                    retry_total=0,
                )
            try:
                async with client:
                    # Probe the connection before starting the long-running receive().
                    # get_partition_ids() is a one-shot call without an internal reconnect
                    # loop, so it fails fast and visibly when the string is wrong or the
                    # namespace is unreachable.
                    try:
                        await asyncio.wait_for(client.get_partition_ids(), timeout=15)
                    except asyncio.TimeoutError:
                        raise TimeoutError(
                            "Event Hub did not respond within 15 s — "
                            "check connection string and network"
                        )

                    # Azure Event Hubs silently accepts AMQP receiver links regardless
                    # of permissions (authorization is enforced at message delivery,
                    # not link attach), so an SDK probe cannot detect a missing
                    # Data Receiver role.  Use ARM Permissions API instead.
                    if use_entra:
                        status.status = "Verifying data-plane access…"
                        try:
                            assert _credential is not None
                            await _verify_data_plane_access(_credential, eh_namespace)
                        except PermissionError:
                            raise
                        except Exception:
                            pass  # ARM check unavailable — proceed optimistically

                    attempt = 0  # reset backoff counter after a successful connect
                    if _splash_shown:
                        _dialog.show_waiting()
                    status.status = "Connected"
                    app.sub_title = "Live Log Monitor  |  connected"

                    async def on_event(_partition_ctx, event) -> None:  # type: ignore[misc]
                        nonlocal _splash_shown
                        if event is None or app._paused:
                            return
                        try:
                            body = json.loads(event.body_as_str())
                        except (ValueError, TypeError):
                            return
                        has_real = False
                        for rec in body.get("records", []):
                            if not app._fw_name_set:
                                rid: str = rec.get("resourceId", "")
                                if "/AZUREFIREWALLS/" in rid.upper():
                                    app.sub_title = rid.split("/")[-1]
                                    app._fw_name_set = True
                            row = parse_record(rec)
                            if row is None:
                                continue
                            if "SKIP:" in row.category:
                                app._skip_pending += 1
                            else:
                                app._pending.append(row)
                                has_real = True
                        if has_real and _splash_shown:
                            _splash_shown = False
                            if isinstance(app.screen, UpdateDialog):
                                # UpdateDialog is on top of ConnectingDialog.
                                # Save its state, pop both, re-push UpdateDialog.
                                upd_tag = app.screen._latest
                                upd_url = app.screen._url
                                app.pop_screen()   # remove UpdateDialog
                                app.pop_screen()   # remove ConnectingDialog
                                await app.push_screen(UpdateDialog(upd_tag, upd_url))
                            else:
                                app.pop_screen()   # remove ConnectingDialog

                    await client.receive(on_event=on_event, starting_position=position)
            finally:
                if _credential:
                    await _credential.close()
                    _credential = None

        except asyncio.CancelledError:
            if _splash_shown:
                if isinstance(app.screen, UpdateDialog):
                    app.pop_screen()   # remove UpdateDialog
                app.pop_screen()       # remove ConnectingDialog
            status.status = "Streaming stopped"
            return

        except Exception as exc:
            last_exc = exc
            app._fw_name_set = False  # allow subtitle refresh on next connect

            # Auth / configuration errors will not fix themselves — skip retries.
            if isinstance(exc, PermissionError) or any(
                kw in str(exc).lower() for kw in _AUTH_KEYWORDS
            ):
                attempt = _MAX_ATTEMPTS
                break

            attempt += 1
            if attempt >= _MAX_ATTEMPTS:
                break

            delay = _BACKOFF[attempt - 1]
            for remaining in range(delay, 0, -1):
                status.status = (
                    f"Connection error: {exc}"
                    f"  — attempt {attempt}/{_MAX_ATTEMPTS},"
                    f" retrying in {remaining}s…"
                )
                await asyncio.sleep(1)

    # ── all attempts exhausted ────────────────────────────────────────────
    if last_exc is not None:
        err_lower = str(last_exc).lower()
        is_cfg_error = isinstance(last_exc, PermissionError) or any(
            kw in err_lower for kw in _AUTH_KEYWORDS
        )
        if is_cfg_error:
            hint = _error_hint(last_exc, use_entra)
        else:
            hint = (
                "The Event Hub namespace could not be reached.\n"
                "Check your network connection and the connection string,\n"
                "then restart the app (optionally with  --reconfigure)."
            )
        status.status = f"Failed after {_MAX_ATTEMPTS} attempts — see dialog"
        if _splash_shown:
            if isinstance(app.screen, UpdateDialog):
                app.pop_screen()   # remove UpdateDialog
            app.pop_screen()       # remove ConnectingDialog
        await app.push_screen(ErrorDialog(str(last_exc), hint))
