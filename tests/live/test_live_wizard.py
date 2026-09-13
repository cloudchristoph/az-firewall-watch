"""Optional live end-to-end runs of the setup wizard against a real Azure environment.

Every path the Welcome screen offers is driven through the real screens with
the real Azure CLI behind them, and after each path the viewer is started
headless on the ``.env`` the wizard wrote until it reports the Event Hub as
connected. Skipped unless the environment variables below are set, so the
default ``pytest`` run and CI never touch Azure::

    AZFW_LIVE_EVENTHUB_NAMESPACE=<ns>.servicebus.windows.net   # an existing hub with logs
    AZFW_LIVE_EVENTHUB_NAME=firewall-logs
    AZFW_LIVE_WIZARD_SUBSCRIPTION="<subscription name>"        # where that hub and the firewall live
    AZFW_LIVE_WIZARD_FIREWALL=<firewall name>
    AZFW_LIVE_WIZARD_DEPLOY=1                                   # opt in to the deploy path
    pytest tests/live/test_live_wizard.py -m live

The paste, enter and discover paths only read (the SAS variants read keys of
an existing Listen rule). The deploy path, opted into separately, creates a
resource group, a Basic namespace, a hub, auth rules, a diagnostic setting on
the firewall and, for Entra ID, a role assignment, then deletes all of it
again in a ``finally`` block. It needs one free diagnostic-setting slot on the
firewall (Azure allows five) and a *user* login (not a service principal):
the wizard assigns the role with ``--assignee-principal-type User`` to the
signed-in user, and the test resolves that user the same way.

Requirements for the read-only paths: an Azure CLI login with Reader on the
subscription and *Azure Event Hubs Data Receiver* on the existing hub.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from textual.widgets import Button, ContentSwitcher, Input, ListView, RichLog, Static

import setup.operations as ops
from helpers import load_env
from setup.app import WizardApp
from setup.screens import (
    AuthMethodScreen,
    ConfirmCreateRuleScreen,
    DeployNewScreen,
    EnterExistingHubScreen,
    PasteConnectionScreen,
    PickExistingScreen,
    PolicyContextScreen,
)
from setup.services import get_existing_conn_str, has_entra_config
from setup.utils import run_az
from viewer import FirewallLogApp

pytestmark = pytest.mark.live

EH_NAMESPACE = os.environ.get("AZFW_LIVE_EVENTHUB_NAMESPACE", "")  # fully qualified
EH_NAME = os.environ.get("AZFW_LIVE_EVENTHUB_NAME", "")
SUBSCRIPTION = os.environ.get("AZFW_LIVE_WIZARD_SUBSCRIPTION", "")
FIREWALL = os.environ.get("AZFW_LIVE_WIZARD_FIREWALL", "")
DEPLOY = os.environ.get("AZFW_LIVE_WIZARD_DEPLOY", "") == "1"
NS_SHORT = EH_NAMESPACE.split(".", 1)[0]

needs_hub = pytest.mark.skipif(
    not (EH_NAMESPACE and EH_NAME), reason="set AZFW_LIVE_EVENTHUB_NAMESPACE and AZFW_LIVE_EVENTHUB_NAME to run",
)
needs_subscription = pytest.mark.skipif(not SUBSCRIPTION, reason="set AZFW_LIVE_WIZARD_SUBSCRIPTION to run")
needs_deploy = pytest.mark.skipif(
    not (DEPLOY and SUBSCRIPTION and FIREWALL),
    reason="set AZFW_LIVE_WIZARD_DEPLOY=1, AZFW_LIVE_WIZARD_SUBSCRIPTION and AZFW_LIVE_WIZARD_FIREWALL to run",
)

# Names of what the deploy path creates. The resource group is new on purpose:
# that exercises the "create resource group" branch and makes the teardown a
# single group delete. Namespace names are global and stay reserved for a
# while after deletion, so every run gets a fresh one.
E2E_RG = "rg-azfw-watch-e2e"
E2E_HUB = "firewall-logs"
E2E_DIAG = "azfw-e2e-diag"
E2E_LISTEN = "az-firewall-watch-listen"
E2E_SEND = "az-firewall-watch-send"

SCAN_TIMEOUT = 600.0     # discovery walks every subscription the login can see
DEPLOY_TIMEOUT = 900.0   # namespace creation plus the wizard's 30 s propagation wait
RBAC_TIMEOUT = 600.0     # a fresh role assignment can take minutes to reach the data plane
FIRST_RECORD_TIMEOUT = 1800.0  # a fresh diagnostic setting delivers its first batch after 5 to 20+ minutes

_ENV_KEYS = (
    "EVENT_HUB_CONNECTION_STRING", "EVENT_HUB_NAMESPACE", "EVENT_HUB_NAME",
    "EVENT_HUB_CONSUMER_GROUP", "EVENT_HUB_START_POSITION", "POLICY_CONTEXT",
)


# ── helpers ──────────────────────────────────────────────────────────────────

async def wait_until(pilot, cond: Callable[[], bool], timeout: float, what: str = "condition") -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError(f"{what} not met within {timeout:.0f} s")
        await pilot.pause(0.2)


def _log_text(screen, log_id: str) -> str:
    log = screen.query_one(log_id, RichLog)
    return "\n".join("".join(seg.text for seg in strip) for strip in log.lines)


def _az_json(*args: str):
    result = run_az(*args, "-o", "json", check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    return tmp_path / ".env"


@pytest.fixture
def clean_process_env(monkeypatch):
    """The viewer reads its credentials from the process environment; start every
    check from nothing so a previous path's values cannot leak into the next."""
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)  # records the real originals for undo()
    yield
    for key in _ENV_KEYS:
        os.environ.pop(key, None)  # not delenv: that would record the wizard's values as originals and restore them


async def _pass_policy_context(app, pilot) -> None:
    await wait_until(pilot, lambda: isinstance(app.screen, PolicyContextScreen), 60, "policy context dialog")
    await pilot.pause()
    await pilot.click("#btn-next")


async def _choose_auth(app, pilot, method: str) -> None:
    await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen), 60, "auth method dialog")
    await pilot.pause()
    if method == "sas":
        app.screen.query_one("#opt-sas").value = True
        await pilot.pause()
    await pilot.click("#btn-next")


async def viewer_connects(env_file: Path, timeout: float = 120.0) -> tuple[str, str]:
    """Start the viewer on the wizard's .env; return the Event Hub state it settles on."""
    for key in _ENV_KEYS:
        os.environ.pop(key, None)
    load_env(env_file, override=True)
    app = FirewallLogApp(policy_context=False, env_file=env_file)
    async with app.run_test(size=(140, 40)) as pilot:
        status = app.query_one("#status")
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while status.eh_state not in ("connected", "failed", "unconfigured") and loop.time() < deadline:
            await pilot.pause(0.5)
        return status.eh_state, status.eh_error


async def viewer_connects_eventually(env_file: Path, timeout: float) -> None:
    """Like viewer_connects, but tolerant of a role assignment that is still propagating."""
    started = time.time()
    deadline = started + timeout
    last = ("", "")
    while time.time() < deadline:
        last = await viewer_connects(env_file, timeout=90)
        if last[0] == "connected":
            print(f"\n    viewer connected after {time.time() - started:.0f} s")
            return
        await asyncio.sleep(15)
    raise AssertionError(f"viewer never connected: {last}")


async def first_record_arrives(namespace: str, hub: str, timeout: float) -> dict:
    """Receive from the hub's beginning until the first firewall record shows up."""
    from azure.core.pipeline.transport import AsyncioRequestsTransport
    from azure.eventhub.aio import EventHubConsumerClient
    from azure.identity.aio import DefaultAzureCredential

    from viewer.streaming import resolve_start_position

    seen: list[dict] = []
    started = time.time()
    deadline = started + timeout
    last_error = "no receive attempt failed; the hub was reachable but empty"
    credential = DefaultAzureCredential(transport=AsyncioRequestsTransport())
    try:
        while time.time() < deadline and not seen:
            client = EventHubConsumerClient(
                fully_qualified_namespace=namespace, eventhub_name=hub, consumer_group="$Default",
                credential=credential, retry_total=0,
            )

            async def on_event(_ctx, event):
                if event is not None:
                    seen.extend(json.loads(event.body_as_str()).get("records", []))

            try:
                async with client:
                    task = asyncio.ensure_future(
                        client.receive(on_event=on_event, starting_position=resolve_start_position("earliest"))
                    )
                    until = time.time() + 60
                    while time.time() < until and not seen:
                        await asyncio.sleep(1)
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass
            except Exception as exc:  # RBAC still propagating, or the hub not ready yet
                last_error = f"{type(exc).__name__}: {exc}"
                await asyncio.sleep(15)
    finally:
        await credential.close()
    assert seen, f"no record reached {namespace}/{hub} within {timeout:.0f} s; last receive error: {last_error}"
    print(f"\n    first record after {time.time() - started:.0f} s, category {seen[0].get('category')}")
    return seen[0]


async def _resolve_lab_sas() -> str:
    """A SAS string for the existing hub, read from a Listen rule that already exists."""
    subs = _az_json("account", "list", "--query", "[?state=='Enabled'].{id:id, name:name}")
    for sub in subs:
        hubs = await ops.scan_event_hubs([sub], lambda _m: None)
        for sub_id, _name, rg, ns, eh in hubs:
            if ns == NS_SHORT and eh == EH_NAME:
                async def _decline() -> bool:
                    return False
                return await ops.resolve_sas_conn_str(sub_id, rg, ns, eh, E2E_LISTEN, lambda _m: None, _decline)
    return ""


# ── paste ────────────────────────────────────────────────────────────────────

@needs_hub
async def test_paste_sas_string_then_viewer_connects(env_file, clean_process_env):
    conn = await _resolve_lab_sas()
    if not conn:
        pytest.skip(f"{EH_NAMESPACE}/{EH_NAME} has no reusable Listen rule to read a SAS string from")

    app = WizardApp(env_file)
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        await app.push_screen(PasteConnectionScreen())
        await pilot.pause()
        app.screen.query_one("#inp-conn", Input).value = conn
        await pilot.click("#btn-save")
        await _pass_policy_context(app, pilot)
        await wait_until(pilot, lambda: app._exit, 30, "wizard exit")

    assert get_existing_conn_str(env_file) == conn
    assert "POLICY_CONTEXT=on" in env_file.read_text(encoding="utf-8")
    assert await viewer_connects(env_file) == ("connected", "")


# ── enter existing (Entra ID) ────────────────────────────────────────────────

@needs_hub
async def test_enter_existing_hub_entra_then_viewer_connects(env_file, clean_process_env):
    app = WizardApp(env_file)
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        await app.push_screen(EnterExistingHubScreen())
        await pilot.pause()
        app.screen.query_one("#inp-ns", Input).value = EH_NAMESPACE
        app.screen.query_one("#inp-hub", Input).value = EH_NAME
        await pilot.click("#btn-save")
        await _pass_policy_context(app, pilot)
        await wait_until(pilot, lambda: app._exit, 30, "wizard exit")

    assert has_entra_config(env_file)
    text = env_file.read_text(encoding="utf-8")
    assert f"EVENT_HUB_NAMESPACE={EH_NAMESPACE}" in text and f"EVENT_HUB_NAME={EH_NAME}" in text
    assert await viewer_connects(env_file) == ("connected", "")


# ── discover ─────────────────────────────────────────────────────────────────

async def _discover_and_select(app, pilot, ns_short: str, hub: str) -> tuple:
    """Run the real scan, pick the hub, and return its (sub_id, sub_name, rg, ns, eh)."""
    await pilot.pause()
    await app.push_screen(PickExistingScreen())
    await wait_until(
        pilot,
        lambda: app.screen.query_one(ContentSwitcher).current == "phase-select"
        or bool(str(app.screen.query_one("#lbl-scan-error").content)),
        SCAN_TIMEOUT, "event hub scan",
    )
    await pilot.pause()
    screen = app.screen
    assert screen.query_one(ContentSwitcher).current == "phase-select", _log_text(screen, "#scan-log")
    items = screen._items
    matches = [i for i, (_s, _n, _rg, ns, eh) in enumerate(items) if ns == ns_short and eh == hub]
    assert matches, f"{ns_short}/{hub} not among the discovered hubs: {[(i[3], i[4]) for i in items]}"
    screen.query_one("#hub-list", ListView).index = matches[0]
    await pilot.pause()
    await pilot.click("#btn-select")
    return items[matches[0]]


@needs_hub
async def test_discover_then_entra_then_viewer_connects(env_file, clean_process_env):
    app = WizardApp(env_file)
    async with app.run_test(size=(120, 50)) as pilot:
        await _discover_and_select(app, pilot, NS_SHORT, EH_NAME)
        await _choose_auth(app, pilot, "entra")
        await _pass_policy_context(app, pilot)
        await wait_until(pilot, lambda: app._exit, 30, "wizard exit")

    assert has_entra_config(env_file)
    assert f"EVENT_HUB_NAMESPACE={EH_NAMESPACE}" in env_file.read_text(encoding="utf-8")
    assert await viewer_connects(env_file) == ("connected", "")


@needs_hub
async def test_discover_then_sas_reuses_existing_rule_then_viewer_connects(env_file, clean_process_env):
    app = WizardApp(env_file)
    async with app.run_test(size=(120, 50)) as pilot:
        await _discover_and_select(app, pilot, NS_SHORT, EH_NAME)
        await _choose_auth(app, pilot, "sas")
        await _pass_policy_context(app, pilot)
        await wait_until(
            pilot, lambda: app._exit or isinstance(app.screen, ConfirmCreateRuleScreen), 120, "SAS resolution",
        )
        if isinstance(app.screen, ConfirmCreateRuleScreen):
            await pilot.click("#btn-cancel")  # this path is meant to reuse, never to create
            pytest.skip(f"{EH_NAMESPACE}/{EH_NAME} has no reusable Listen rule")
        log = _log_text(app.screen, "#scan-log")

    assert "Using existing" in log, log
    conn = get_existing_conn_str(env_file)
    assert conn and conn.startswith("Endpoint=sb://") and f"EntityPath={EH_NAME}" in conn
    assert await viewer_connects(env_file) == ("connected", "")


# ── deploy new ───────────────────────────────────────────────────────────────

class _Deployment:
    """Names and cleanup of one deploy-path run."""

    def __init__(self) -> None:
        self.ns = f"ehns-azfw-e2e-{secrets.token_hex(4)}"
        self.fqdn = f"{self.ns}.servicebus.windows.net"
        self.sub_id = ""
        self.fw_id = ""
        self.hub_scope = ""

    def teardown(self, user_id: str) -> list[str]:
        """Delete everything the wizard created and verify it is gone.

        Returns what is still there afterwards (empty on success). The delete
        of the group is retried once, because a create the wizard started can
        still be in flight when the test gave up on it.
        """
        if self.fw_id:
            run_az("monitor", "diagnostic-settings", "delete", "--name", E2E_DIAG, "--resource", self.fw_id)
        if self.hub_scope and user_id:
            run_az(
                "role", "assignment", "delete", "--assignee", user_id, "--scope", self.hub_scope,
                "--role", "a638d3c7-ab3a-418d-83e6-5f17a39d4fde",
            )
        leftovers: list[str] = []
        if self.sub_id:
            for _attempt in range(2):
                run_az("group", "delete", "--subscription", self.sub_id, "--name", E2E_RG, "--yes")
                if run_az("group", "exists", "--subscription", self.sub_id, "-n", E2E_RG).stdout.strip() == "false":
                    break
                time.sleep(30)
            else:
                leftovers.append(f"resource group {E2E_RG} still exists")
        if self.fw_id and _az_json(
            "monitor", "diagnostic-settings", "list", "--resource", self.fw_id, "--query", f"[?name=='{E2E_DIAG}']",
        ):
            leftovers.append(f"diagnostic setting {E2E_DIAG} still on the firewall")
        if self.hub_scope and user_id:
            # The scope is gone with the group, and the CLI then errors instead of
            # answering "none"; only an answer that lists assignments is a leftover.
            listed = run_az("role", "assignment", "list", "--assignee", user_id, "--scope", self.hub_scope, "-o", "json")
            if listed.returncode == 0 and listed.stdout.strip() and json.loads(listed.stdout):
                leftovers.append(f"role assignment still on {self.hub_scope}")
        return leftovers


async def _deploy_through_wizard(app, pilot, dep: _Deployment, auth: str) -> str:
    """Drive DeployNewScreen with real Azure behind it; return the progress log."""
    await pilot.pause()
    await app.push_screen(DeployNewScreen())
    screen = app.screen
    sw = lambda: screen.query_one(ContentSwitcher).current  # noqa: E731
    await wait_until(
        pilot, lambda: sw() == "step-subscription" or bool(str(screen.query_one("#lbl-deploy-error").content)),
        120, "login and subscription list",
    )
    assert sw() == "step-subscription", str(screen.query_one("#lbl-deploy-error").content)
    subs = screen._subs
    idx = [i for i, s in enumerate(subs) if SUBSCRIPTION in (s["name"], s["id"])]
    assert idx, f"subscription {SUBSCRIPTION!r} not in {[s['name'] for s in subs]}"
    dep.sub_id = subs[idx[0]]["id"]
    screen.query_one("#sub-list", ListView).index = idx[0]
    await pilot.pause()
    await pilot.click("#btn-next-sub")

    await wait_until(
        pilot, lambda: screen.query_one("#fw-list", ListView).display
        or bool(str(screen.query_one("#lbl-fw-error").content)),
        120, "firewall scan",
    )
    fws = screen._firewalls
    fidx = [i for i, fw in enumerate(fws) if fw["name"] == FIREWALL]
    assert fidx, f"firewall {FIREWALL!r} not in {[fw['name'] for fw in fws]}"
    dep.fw_id = fws[fidx[0]]["id"]
    screen.query_one("#fw-list", ListView).index = fidx[0]
    await pilot.pause()
    await pilot.click("#btn-next-fw")
    await wait_until(pilot, lambda: sw() == "step-naming", 30, "naming step")
    await pilot.pause()

    screen.query_one("#inp-rg", Input).value = E2E_RG
    screen.query_one("#inp-ns-deploy", Input).value = dep.ns
    screen.query_one("#inp-eh-name", Input).value = E2E_HUB
    screen.query_one("#inp-diag-name", Input).value = E2E_DIAG
    await pilot.click("#btn-next-naming")
    await _choose_auth(app, pilot, auth)
    await _pass_policy_context(app, pilot)
    await wait_until(pilot, lambda: isinstance(app.screen, DeployNewScreen) and sw() == "step-summary", 30, "summary")
    await pilot.pause()
    summary = str(screen.query_one("#summary-text", Static).content)
    assert dep.ns in summary and E2E_RG in summary and "using existing" not in summary
    assert ("Entra ID" if auth == "entra" else "SAS connection string") in summary

    dep.hub_scope = (
        f"/subscriptions/{dep.sub_id}/resourceGroups/{E2E_RG}"
        f"/providers/Microsoft.EventHub/namespaces/{dep.ns}/eventhubs/{E2E_HUB}"
    )
    await pilot.click("#btn-deploy")
    await wait_until(
        pilot, lambda: app._exit or not screen.query_one("#btn-back-progress", Button).disabled,
        DEPLOY_TIMEOUT, "deployment",
    )
    log = _log_text(screen, "#progress-log")
    assert app._exit, f"deployment failed:\n{log}"
    return log


def _assert_deployed(dep: _Deployment, auth: str, user_id: str) -> None:
    ns = _az_json("eventhubs", "namespace", "show", "--subscription", dep.sub_id, "-g", E2E_RG, "-n", dep.ns)
    assert ns["sku"]["name"] == "Basic" and ns["tags"].get("project") == "az-firewall-watch"
    hub = _az_json("eventhubs", "eventhub", "show", "--subscription", dep.sub_id, "-g", E2E_RG,
                   "--namespace-name", dep.ns, "-n", E2E_HUB)
    assert hub["partitionCount"] == 1
    ns_rules = {r["name"]: r["rights"] for r in _az_json(
        "eventhubs", "namespace", "authorization-rule", "list", "--subscription", dep.sub_id,
        "-g", E2E_RG, "--namespace-name", dep.ns,
    )}
    assert ns_rules.get(E2E_SEND) == ["Send"]
    hub_rules = {r["name"]: r["rights"] for r in _az_json(
        "eventhubs", "eventhub", "authorization-rule", "list", "--subscription", dep.sub_id,
        "-g", E2E_RG, "--namespace-name", dep.ns, "--eventhub-name", E2E_HUB,
    )}
    if auth == "sas":
        assert hub_rules.get(E2E_LISTEN) == ["Listen"]
    else:
        assert E2E_LISTEN not in hub_rules
        roles = _az_json("role", "assignment", "list", "--assignee", user_id, "--scope", dep.hub_scope)
        assert any(r["roleDefinitionName"] == "Azure Event Hubs Data Receiver" for r in roles), roles

    diag = _az_json("monitor", "diagnostic-settings", "show", "--name", E2E_DIAG, "--resource", dep.fw_id)
    assert diag["eventHubName"] == E2E_HUB
    assert diag["eventHubAuthorizationRuleId"].lower().endswith(f"/authorizationrules/{E2E_SEND}".lower())
    enabled = {entry["category"] for entry in diag["logs"] if entry["enabled"]}
    assert enabled and enabled <= set(ops.VIEWER_CATEGORIES), enabled
    assert "AZFWNetworkRule" in enabled and "AZFWApplicationRule" in enabled


@needs_deploy
async def test_deploy_new_hub_entra_then_discover_sas_creates_rule(env_file, tmp_path, clean_process_env):
    """The deploy path with Entra ID, verified down to the first record in the new
    hub. Then the discover path on that hub with SAS: it has no Listen rule, so the
    wizard asks before creating one. Everything is removed at the end."""
    user_id = run_az("ad", "signed-in-user", "show", "--query", "id", "-o", "tsv", check=True).stdout.strip()
    dep = _Deployment()
    try:
        app = WizardApp(env_file)
        async with app.run_test(size=(120, 60)) as pilot:
            log = await _deploy_through_wizard(app, pilot, dep, "entra")
        assert "Data Receiver role assigned" in log, log
        assert "logs will start flowing shortly" in log, log
        assert "Creating resource group" in log, log

        assert has_entra_config(env_file)
        text = env_file.read_text(encoding="utf-8")
        assert f"EVENT_HUB_NAMESPACE={dep.fqdn}" in text and f"EVENT_HUB_NAME={E2E_HUB}" in text
        assert "POLICY_CONTEXT=on" in text
        _assert_deployed(dep, "entra", user_id)

        await viewer_connects_eventually(env_file, RBAC_TIMEOUT)
        record = await first_record_arrives(dep.fqdn, E2E_HUB, FIRST_RECORD_TIMEOUT)
        assert record.get("category", "").startswith("AZFW"), record
        assert record.get("resourceId", "").lower() == dep.fw_id.lower()

        # Discover the new hub and ask for SAS: no reusable Listen rule exists, so the
        # wizard must ask, create the rule after confirmation, and write the string.
        sas_env = tmp_path / "sas.env"
        app = WizardApp(sas_env)
        async with app.run_test(size=(120, 50)) as pilot:
            await _discover_and_select(app, pilot, dep.ns, E2E_HUB)
            await _choose_auth(app, pilot, "sas")
            await _pass_policy_context(app, pilot)
            await wait_until(pilot, lambda: isinstance(app.screen, ConfirmCreateRuleScreen), 120, "create prompt")
            await pilot.pause()
            prompt = " ".join(str(s.content) for s in app.screen.query(Static))
            assert E2E_LISTEN in prompt and dep.ns in prompt
            await pilot.click("#btn-confirm")
            await wait_until(pilot, lambda: app._exit, 120, "rule creation")
        conn = get_existing_conn_str(sas_env)
        assert conn and f"SharedAccessKeyName={E2E_LISTEN}" in conn and f"EntityPath={E2E_HUB}" in conn
        hub_rules = {r["name"]: r["rights"] for r in _az_json(
            "eventhubs", "eventhub", "authorization-rule", "list", "--subscription", dep.sub_id,
            "-g", E2E_RG, "--namespace-name", dep.ns, "--eventhub-name", E2E_HUB,
        )}
        assert hub_rules.get(E2E_LISTEN) == ["Listen"]
        assert await viewer_connects(sas_env) == ("connected", "")
    finally:
        leftovers = dep.teardown(user_id)
        print("\nteardown:", "clean" if not leftovers else "LEFTOVERS " + "; ".join(leftovers))
        assert not leftovers, leftovers


@needs_deploy
async def test_deploy_new_hub_sas(env_file, clean_process_env):
    """The deploy path with a SAS Listen rule: the wizard creates the rule itself
    and writes the connection string. Torn down at the end."""
    user_id = run_az("ad", "signed-in-user", "show", "--query", "id", "-o", "tsv", check=True).stdout.strip()
    dep = _Deployment()
    try:
        app = WizardApp(env_file)
        async with app.run_test(size=(120, 60)) as pilot:
            log = await _deploy_through_wizard(app, pilot, dep, "sas")
        assert "Listen rule created" in log, log
        assert "Data Receiver" not in log, log

        conn = get_existing_conn_str(env_file)
        assert conn and conn.startswith("Endpoint=sb://") and f"SharedAccessKeyName={E2E_LISTEN}" in conn
        assert f"EntityPath={E2E_HUB}" in conn
        _assert_deployed(dep, "sas", user_id)
        assert await viewer_connects(env_file) == ("connected", "")
    finally:
        leftovers = dep.teardown("")  # no role assignment in the SAS variant
        print("\nteardown:", "clean" if not leftovers else "LEFTOVERS " + "; ".join(leftovers))
        assert not leftovers, leftovers
