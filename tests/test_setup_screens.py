"""Headless runs of the setup wizard screens (setup/screens.py).

Azure CLI orchestration functions are replaced at the ``setup.screens``
import site so the wizard can be driven end-to-end without Azure.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import pytest
from textual.widgets import Button, ContentSwitcher, Input, Label, ListView, RadioSet, Static

import setup.screens as screens
from setup.app import WizardApp
from setup.screens import (
    AuthMethodScreen,
    EnrichmentScreen,
    ConfirmCreateRuleScreen,
    DeployNewScreen,
    EnterExistingHubScreen,
    PasteConnectionScreen,
    PickExistingScreen,
    WelcomeScreen,
)
from setup.services import get_existing_conn_str, has_entra_config

CONN = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=l;SharedAccessKey=K;EntityPath=h"
FW = {
    "name": "fw-hub", "rg": "rg-hub", "location": "germanywestcentral",
    "id": "/subscriptions/s1/resourceGroups/rg-hub/providers/Microsoft.Network/azureFirewalls/fw-hub",
}


# ── helpers ──────────────────────────────────────────────────────────────────

async def wait_until(pilot, cond: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await pilot.pause(0.05)


def _env_values(env_file: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )


def _visible_error(screen, label_id: str) -> str:
    lbl = screen.query_one(label_id, Label)
    return str(lbl.content) if lbl.display else ""


async def _pick_radio(pilot, screen, button_id: str) -> None:
    screen.query_one(button_id).value = True
    await pilot.pause()


async def _pass_enrichment(app, pilot, enable: bool = True) -> None:
    """Every flow asks about metadata enrichment right before .env is written."""
    await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentScreen))
    await pilot.pause()
    if not enable:
        await _pick_radio(pilot, app.screen, "#opt-enrich-off")
    await pilot.click("#btn-next")


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    return tmp_path / ".env"


@pytest.fixture
def fake_ops(monkeypatch):
    """Replace every Azure-CLI-backed operation used by the screens."""
    state: dict[str, Any] = {
        "user": ("me@example.com", "oid-123"),
        "subs": [{"id": "s1", "name": "Sub One"}],
        "hubs": [("s1", "Sub One", "rg-a", "ns-a", "firewall-logs")],
        "firewalls": [FW],
        "sas_conn": CONN,
        "deploy_conn": CONN,
        "calls": [],
    }

    async def cli_ensure_login(log, suspend):
        state["calls"].append("login")
        log("[green]✓[/] Logged in")
        if isinstance(state["user"], Exception):
            raise state["user"]
        return state["user"]

    async def list_subscriptions(log):
        state["calls"].append("subs")
        return state["subs"]

    async def scan_event_hubs(subs, log):
        state["calls"].append("hubs")
        return state["hubs"]

    async def scan_firewalls(sub_id, sub_name, log):
        state["calls"].append(("firewalls", sub_id))
        return state["firewalls"]

    async def resolve_sas_conn_str(sub_id, rg, ns, eh, rule_name, log, confirm_create):
        state["calls"].append(("resolve_sas", sub_id, rg, ns, eh, rule_name))
        if state.get("sas_needs_confirm"):
            if not await confirm_create():
                return ""
        if isinstance(state["sas_conn"], Exception):
            raise state["sas_conn"]
        return state["sas_conn"]

    async def deploy_new_hub(**kwargs):
        state["calls"].append(("deploy", kwargs))
        if isinstance(state["deploy_conn"], Exception):
            raise state["deploy_conn"]
        return state["deploy_conn"]

    for name, fn in (
        ("cli_ensure_login", cli_ensure_login),
        ("list_subscriptions", list_subscriptions),
        ("scan_event_hubs", scan_event_hubs),
        ("scan_firewalls", scan_firewalls),
        ("resolve_sas_conn_str", resolve_sas_conn_str),
        ("deploy_new_hub", deploy_new_hub),
    ):
        monkeypatch.setattr(screens, name, fn)
    return state


# ── Welcome ──────────────────────────────────────────────────────────────────

async def test_welcome_defaults_to_discover(env_file):
    app = WizardApp(env_file)
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, WelcomeScreen)
        radio = app.screen.query_one("#welcome-radio", RadioSet)
        assert radio.pressed_button is not None
        assert radio.pressed_button.id == "opt-discover"


@pytest.mark.parametrize(
    "option, target",
    [
        ("opt-discover", PickExistingScreen),
        ("opt-enter", EnterExistingHubScreen),
        ("opt-paste", PasteConnectionScreen),
        ("opt-deploy", DeployNewScreen),
    ],
)
async def test_welcome_next_opens_selected_screen(env_file, fake_ops, option, target):
    app = WizardApp(env_file)
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        await _pick_radio(pilot, app.screen, f"#{option}")
        await pilot.click("#btn-next")
        await pilot.pause()
        assert isinstance(app.screen, target)


async def test_welcome_quit_exits_without_env(env_file):
    app = WizardApp(env_file)
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        await pilot.click("#btn-quit")
        await pilot.pause()
        assert app._exit
    assert not env_file.exists()


# ── Paste connection string ──────────────────────────────────────────────────

class TestPasteConnection:
    async def _open(self, app, pilot):
        await pilot.pause()
        await app.push_screen(PasteConnectionScreen())
        await pilot.pause()

    @pytest.mark.parametrize(
        "value, fragment",
        [
            ("", "must not be empty"),
            ("Endpoint=https://nope", "Endpoint=sb://"),
            ("Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKey=K", "EntityPath="),
        ],
    )
    async def test_validation_errors(self, env_file, value, fragment):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            app.screen.query_one("#inp-conn", Input).value = value
            await pilot.click("#btn-save")
            await pilot.pause()
            assert fragment in _visible_error(app.screen, "#lbl-error")
            assert not app._exit
        assert not env_file.exists()

    async def test_valid_string_is_written_verbatim(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            app.screen.query_one("#inp-conn", Input).value = f"  {CONN}  "
            await pilot.click("#btn-save")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: app._exit)
        assert get_existing_conn_str(env_file) == CONN
        assert _env_values(env_file)["ENRICHMENT"] == "on"

    async def test_enrichment_can_be_disabled(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            app.screen.query_one("#inp-conn", Input).value = CONN
            await pilot.click("#btn-save")
            await _pass_enrichment(app, pilot, enable=False)
            await wait_until(pilot, lambda: app._exit)
        assert _env_values(env_file)["ENRICHMENT"] == "off"

    async def test_enrichment_back_keeps_wizard_open(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            app.screen.query_one("#inp-conn", Input).value = CONN
            await pilot.click("#btn-save")
            await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentScreen))
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, PasteConnectionScreen)
            assert not app._exit
        assert not env_file.exists()

    async def test_back_returns_to_welcome(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            await pilot.click("#btn-back")
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)


# ── Enter existing hub (Entra) ───────────────────────────────────────────────

class TestEnterExistingHub:
    async def _open(self, app, pilot):
        await pilot.pause()
        await app.push_screen(EnterExistingHubScreen())
        await pilot.pause()

    @pytest.mark.parametrize(
        "ns, hub, fragment",
        [
            ("", "h", "Namespace must not be empty"),
            ("ns", "h", "servicebus.windows.net"),
            ("ns.servicebus.windows.net", "", "Event Hub name must not be empty"),
        ],
    )
    async def test_validation_errors(self, env_file, ns, hub, fragment):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            app.screen.query_one("#inp-ns", Input).value = ns
            app.screen.query_one("#inp-hub", Input).value = hub
            await pilot.click("#btn-save")
            await pilot.pause()
            assert fragment in _visible_error(app.screen, "#lbl-error")
        assert not env_file.exists()

    async def test_valid_input_writes_entra_env(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open(app, pilot)
            app.screen.query_one("#inp-ns", Input).value = "lab.servicebus.windows.net"
            app.screen.query_one("#inp-hub", Input).value = "firewall-logs"
            await pilot.click("#btn-save")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: app._exit)
        assert has_entra_config(env_file)
        assert _env_values(env_file)["ENRICHMENT"] == "on"
        text = env_file.read_text(encoding="utf-8")
        assert "EVENT_HUB_NAMESPACE=lab.servicebus.windows.net" in text
        assert "EVENT_HUB_NAME=firewall-logs" in text


# ── Auth method modal ────────────────────────────────────────────────────────

class TestAuthMethodScreen:
    async def _ask(self, app, pilot, action: Callable[[], Any]):
        result: list = []
        app.push_screen(AuthMethodScreen(), callback=result.append)
        await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
        await pilot.pause()
        await action()
        await wait_until(pilot, lambda: bool(result))
        return result[0]

    async def test_default_is_entra(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            assert await self._ask(app, pilot, lambda: pilot.click("#btn-next")) == "entra"

    async def test_sas_choice(self, env_file):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()

            async def _choose():
                await _pick_radio(pilot, app.screen, "#opt-sas")
                await pilot.click("#btn-next")

            assert await self._ask(app, pilot, _choose) == "sas"

    @pytest.mark.parametrize("how", ["button", "escape"])
    async def test_back_returns_none(self, env_file, how):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()

            async def _back():
                if how == "button":
                    await pilot.click("#btn-back")
                else:
                    await pilot.press("escape")

            assert await self._ask(app, pilot, _back) is None


# ── Pick existing hub (discover) ─────────────────────────────────────────────

class TestPickExisting:
    async def _open_and_scan(self, app, pilot):
        await pilot.pause()
        await app.push_screen(PickExistingScreen())
        await wait_until(pilot, lambda: app.screen.query_one(ContentSwitcher).current == "phase-select")
        await pilot.pause()

    async def test_scan_lists_hubs(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            lv = app.screen.query_one("#hub-list", ListView)
            assert len(lv.children) == 1
            assert fake_ops["calls"] == ["login", "subs", "hubs"]

    async def test_scan_without_hubs_shows_error(self, env_file, fake_ops):
        fake_ops["hubs"] = []
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            await app.push_screen(PickExistingScreen())
            await wait_until(pilot, lambda: bool(_visible_error(app.screen, "#lbl-scan-error")))
            assert "No Event Hubs found" in _visible_error(app.screen, "#lbl-scan-error")

    async def test_cli_missing_shows_error(self, env_file, fake_ops):
        fake_ops["user"] = RuntimeError("Azure CLI not found.\n  macOS: brew install azure-cli")
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            await app.push_screen(PickExistingScreen())
            await wait_until(pilot, lambda: bool(_visible_error(app.screen, "#lbl-scan-error")))
            assert "Azure CLI not found" in _visible_error(app.screen, "#lbl-scan-error")

    async def test_select_without_choice_shows_hint(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = None
            await pilot.click("#btn-select")
            await pilot.pause()
            assert "select an Event Hub" in _visible_error(app.screen, "#lbl-select-error")

    async def test_select_with_entra_writes_env(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = 0
            await pilot.click("#btn-select")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await pilot.click("#btn-next")  # Entra is the default
            await _pass_enrichment(app, pilot, enable=False)
            await wait_until(pilot, lambda: app._exit)
        text = env_file.read_text(encoding="utf-8")
        assert "EVENT_HUB_NAMESPACE=ns-a.servicebus.windows.net" in text
        assert "ENRICHMENT=off" in text
        assert "EVENT_HUB_NAME=firewall-logs" in text
        assert "resolve_sas" not in [c[0] if isinstance(c, tuple) else c for c in fake_ops["calls"]]

    async def test_select_with_sas_resolves_and_writes_env(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = 0
            await pilot.click("#btn-select")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await _pick_radio(pilot, app.screen, "#opt-sas")
            await pilot.click("#btn-next")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: app._exit)
        assert get_existing_conn_str(env_file) == CONN
        assert _env_values(env_file)["ENRICHMENT"] == "on"
        resolve = [c for c in fake_ops["calls"] if isinstance(c, tuple) and c[0] == "resolve_sas"][0]
        assert resolve[1:] == ("s1", "rg-a", "ns-a", "firewall-logs", "az-firewall-watch-listen")

    async def test_sas_rule_creation_prompt_can_be_declined(self, env_file, fake_ops):
        fake_ops["sas_needs_confirm"] = True
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = 0
            await pilot.click("#btn-select")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await _pick_radio(pilot, app.screen, "#opt-sas")
            await pilot.click("#btn-next")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: isinstance(app.screen, ConfirmCreateRuleScreen))
            await pilot.pause()
            text = " ".join(str(s.content) for s in app.screen.query(Static))
            assert "az-firewall-watch-listen" in text and "ns-a" in text
            await pilot.click("#btn-cancel")
            await wait_until(pilot, lambda: isinstance(app.screen, PickExistingScreen))
            await pilot.pause()
            assert app.screen.query_one(ContentSwitcher).current == "phase-select"
            assert not app._exit
        assert not env_file.exists()

    async def test_sas_rule_creation_prompt_confirmed(self, env_file, fake_ops):
        fake_ops["sas_needs_confirm"] = True
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = 0
            await pilot.click("#btn-select")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await _pick_radio(pilot, app.screen, "#opt-sas")
            await pilot.click("#btn-next")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: isinstance(app.screen, ConfirmCreateRuleScreen))
            await pilot.pause()
            await pilot.click("#btn-confirm")
            await wait_until(pilot, lambda: app._exit)
        assert get_existing_conn_str(env_file) == CONN

    async def test_sas_failure_shows_error(self, env_file, fake_ops):
        fake_ops["sas_conn"] = RuntimeError("keys list failed")
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = 0
            await pilot.click("#btn-select")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await _pick_radio(pilot, app.screen, "#opt-sas")
            await pilot.click("#btn-next")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: bool(_visible_error(app.screen, "#lbl-scan-error")))
            assert "keys list failed" in _visible_error(app.screen, "#lbl-scan-error")
        assert not env_file.exists()

    async def test_auth_back_returns_to_list(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 40)) as pilot:
            await self._open_and_scan(app, pilot)
            app.screen.query_one("#hub-list", ListView).index = 0
            await pilot.click("#btn-select")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await pilot.click("#btn-back")
            await wait_until(pilot, lambda: isinstance(app.screen, PickExistingScreen))
            assert not app._exit


# ── Deploy new hub ───────────────────────────────────────────────────────────

class TestDeployNew:
    async def _to_naming(self, app, pilot):
        await pilot.pause()
        await app.push_screen(DeployNewScreen())
        sw = lambda: app.screen.query_one(ContentSwitcher).current  # noqa: E731
        await wait_until(pilot, lambda: sw() == "step-subscription")
        await pilot.pause()
        app.screen.query_one("#sub-list", ListView).index = 0
        await pilot.click("#btn-next-sub")
        await wait_until(pilot, lambda: sw() == "step-firewall")
        await wait_until(pilot, lambda: app.screen.query_one("#fw-list", ListView).display)
        await pilot.pause()
        app.screen.query_one("#fw-list", ListView).index = 0
        await pilot.click("#btn-next-fw")
        await wait_until(pilot, lambda: sw() == "step-naming")
        await pilot.pause()

    async def test_naming_defaults_derive_from_firewall(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._to_naming(app, pilot)
            s = app.screen
            assert s.query_one("#inp-rg", Input).value == "rg-hub"
            assert s.query_one("#inp-ns-deploy", Input).value == "ehns-fwlogs-gwc-001"
            assert s.query_one("#inp-eh-name", Input).value == "firewall-logs"
            assert s.query_one("#inp-listen-rule", Input).value == "az-firewall-watch-listen"
            assert s.query_one("#inp-send-rule", Input).value == "az-firewall-watch-send"
            assert s.query_one("#inp-diag-name", Input).value == "az-firewall-watch-diag"
            assert fake_ops["calls"][-1] == ("firewalls", "s1")

    async def test_naming_requires_all_fields(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._to_naming(app, pilot)
            app.screen.query_one("#inp-eh-name", Input).value = ""
            await pilot.click("#btn-next-naming")
            await pilot.pause()
            assert "All fields are required" in _visible_error(app.screen, "#lbl-naming-error")

    async def test_no_firewalls_shows_error(self, env_file, fake_ops):
        fake_ops["firewalls"] = []
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await pilot.pause()
            await app.push_screen(DeployNewScreen())
            await wait_until(pilot, lambda: app.screen.query_one(ContentSwitcher).current == "step-subscription")
            await pilot.pause()
            app.screen.query_one("#sub-list", ListView).index = 0
            await pilot.click("#btn-next-sub")
            await wait_until(pilot, lambda: bool(_visible_error(app.screen, "#lbl-fw-error")))
            assert "No Azure Firewalls found" in _visible_error(app.screen, "#lbl-fw-error")

    async def test_no_subscriptions_shows_error(self, env_file, fake_ops):
        fake_ops["subs"] = []
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await pilot.pause()
            await app.push_screen(DeployNewScreen())
            await wait_until(pilot, lambda: bool(_visible_error(app.screen, "#lbl-deploy-error")))
            assert "No enabled subscriptions" in _visible_error(app.screen, "#lbl-deploy-error")

    async def _through_summary(self, app, pilot, auth: str):
        await self._to_naming(app, pilot)
        await pilot.click("#btn-next-naming")
        await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
        await pilot.pause()
        if auth == "sas":
            await _pick_radio(pilot, app.screen, "#opt-sas")
        await pilot.click("#btn-next")
        await _pass_enrichment(app, pilot, enable=(auth != "entra"))
        await wait_until(pilot, lambda: isinstance(app.screen, DeployNewScreen)
                         and app.screen.query_one(ContentSwitcher).current == "step-summary")
        await pilot.pause()

    async def test_summary_reflects_choices(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._through_summary(app, pilot, "sas")
            summary = str(app.screen.query_one("#summary-text", Static).content)
            assert "Sub One" in summary
            assert "fw-hub" in summary
            assert "using existing" in summary
            assert "SAS connection string" in summary
            assert "az-firewall-watch-listen" in summary
            assert "Enrichment    : on" in summary

    async def test_summary_entra_hides_listen_rule(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._through_summary(app, pilot, "entra")
            summary = str(app.screen.query_one("#summary-text", Static).content)
            assert "Entra ID" in summary
            assert "Listen rule" not in summary
            assert "Enrichment    : off" in summary  # _through_summary disables it for entra

    async def test_deploy_sas_writes_env_and_exits(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._through_summary(app, pilot, "sas")
            await pilot.click("#btn-deploy")
            await wait_until(pilot, lambda: app._exit)
        assert get_existing_conn_str(env_file) == CONN
        deploy = [c for c in fake_ops["calls"] if isinstance(c, tuple) and c[0] == "deploy"][0][1]
        assert deploy["auth_method"] == "sas"
        assert deploy["current_user_id"] == "oid-123"
        assert deploy["using_existing_rg"] is True
        assert deploy["fw"] == FW
        assert deploy["ns"] == "ehns-fwlogs-gwc-001"

    async def test_deploy_entra_writes_env_and_exits(self, env_file, fake_ops):
        fake_ops["deploy_conn"] = ""
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._through_summary(app, pilot, "entra")
            await pilot.click("#btn-deploy")
            await wait_until(pilot, lambda: app._exit)
        assert has_entra_config(env_file)
        assert _env_values(env_file)["EVENT_HUB_NAMESPACE"] == "ehns-fwlogs-gwc-001.servicebus.windows.net"
        assert _env_values(env_file)["ENRICHMENT"] == "off"

    async def test_deploy_with_new_rg_flag(self, env_file, fake_ops):
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._to_naming(app, pilot)
            app.screen.query_one("#inp-rg", Input).value = "rg-brand-new"
            await pilot.click("#btn-next-naming")
            await wait_until(pilot, lambda: isinstance(app.screen, AuthMethodScreen))
            await pilot.pause()
            await pilot.click("#btn-next")
            await _pass_enrichment(app, pilot)
            await wait_until(pilot, lambda: isinstance(app.screen, DeployNewScreen)
                             and app.screen.query_one(ContentSwitcher).current == "step-summary")
            await pilot.pause()
            assert "using existing" not in str(app.screen.query_one("#summary-text", Static).content)
            await pilot.click("#btn-deploy")
            await wait_until(pilot, lambda: app._exit)
        deploy = [c for c in fake_ops["calls"] if isinstance(c, tuple) and c[0] == "deploy"][0][1]
        assert deploy["using_existing_rg"] is False
        assert deploy["rg"] == "rg-brand-new"

    async def test_deploy_failure_keeps_wizard_open(self, env_file, fake_ops):
        fake_ops["deploy_conn"] = RuntimeError("quota exceeded")
        app = WizardApp(env_file)
        async with app.run_test(size=(100, 50)) as pilot:
            await self._through_summary(app, pilot, "sas")
            await pilot.click("#btn-deploy")
            await wait_until(pilot, lambda: not app.screen.query_one("#btn-back-progress", Button).disabled)
            assert not app._exit
            assert app.screen.query_one(ContentSwitcher).current == "step-progress"
        assert not env_file.exists()
