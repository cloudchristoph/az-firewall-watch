"""The ENRICHMENT feature flag: config resolution, .env persistence, viewer behaviour."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from textual.widgets import DataTable, TabbedContent

import viewer.app as app_module
from dialogs import EnrichmentNoticeDialog, StatusBar
from setup.services import set_env_value, write_env, write_env_entra
from viewer.app import FirewallLogApp
from viewer.config import enrichment_setting

from .test_views import no_update_check, wait_until  # noqa: F401

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")

CONN = "Endpoint=sb://x.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=s;EntityPath=h"


# ── config resolution ────────────────────────────────────────────────────────

@pytest.mark.parametrize("value, enabled", [
    ("on", True), ("ON", True), ("true", True), ("1", True), ("yes", True),
    ("off", False), ("false", False), ("0", False), ("no", False), ("anything", False),
])
def test_env_value_is_explicit(value, enabled):
    assert enrichment_setting([], {"ENRICHMENT": value}) == (enabled, True)


@pytest.mark.parametrize("environ", [{}, {"ENRICHMENT": ""}, {"ENRICHMENT": "   "}])
def test_missing_value_defaults_on_but_not_explicit(environ):
    assert enrichment_setting([], environ) == (True, False)


def test_cli_flags_override_environment():
    assert enrichment_setting(["main.py", "--no-enrichment"], {"ENRICHMENT": "on"}) == (False, True)
    assert enrichment_setting(["main.py", "--enrichment"], {"ENRICHMENT": "off"}) == (True, True)
    assert enrichment_setting(["main.py", "--enrichment"], {}) == (True, True)


# ── .env persistence ─────────────────────────────────────────────────────────

def _values(env: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in env.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )


def test_write_env_records_enrichment(tmp_path: Path):
    env = tmp_path / ".env"
    write_env(env, CONN)
    assert _values(env)["ENRICHMENT"] == "on"
    write_env(env, CONN, enrichment=False)
    assert _values(env)["ENRICHMENT"] == "off"
    write_env_entra(env, "ns.servicebus.windows.net", "h", enrichment=False)
    assert _values(env)["ENRICHMENT"] == "off"
    assert "Resource Manager" in env.read_text(encoding="utf-8")  # explained inline


def test_set_env_value_replaces_in_place(tmp_path: Path):
    env = tmp_path / ".env"
    write_env(env, CONN)
    before = env.read_text(encoding="utf-8")
    set_env_value(env, "ENRICHMENT", "off")
    after = env.read_text(encoding="utf-8")
    assert _values(env)["ENRICHMENT"] == "off"
    assert _values(env)["EVENT_HUB_CONNECTION_STRING"] == CONN
    assert sum(l.startswith("ENRICHMENT=") for l in after.splitlines()) == 1
    assert "Do NOT commit" in after and len(after.splitlines()) == len(before.splitlines())


def test_set_env_value_appends_to_pre_flag_env(tmp_path: Path):
    """A 0.4.x .env has no ENRICHMENT line; the decision is appended with its comment."""
    env = tmp_path / ".env"
    env.write_text(f"EVENT_HUB_CONNECTION_STRING={CONN}\nEVENT_HUB_START_POSITION=latest\n", encoding="utf-8")
    set_env_value(env, "ENRICHMENT", "on")
    text = env.read_text(encoding="utf-8")
    assert text.startswith(f"EVENT_HUB_CONNECTION_STRING={CONN}\n")
    assert text.endswith("ENRICHMENT=on\n")
    assert "# ENRICHMENT=on reads" in text


def test_set_env_value_collapses_duplicates(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("A=1\nENRICHMENT=on\nB=2\nENRICHMENT=off\n", encoding="utf-8")
    set_env_value(env, "ENRICHMENT", "off")
    assert env.read_text(encoding="utf-8") == "A=1\nENRICHMENT=off\nB=2\n"


def test_set_env_value_creates_missing_file(tmp_path: Path):
    env = tmp_path / ".env"
    set_env_value(env, "FOO", "bar")
    assert env.read_text(encoding="utf-8") == "FOO=bar\n"


# ── viewer with enrichment off ───────────────────────────────────────────────

@pytest.fixture
def arm_calls(monkeypatch):
    calls: list[str] = []

    async def _load(firewall_id, *, force=False):
        calls.append(firewall_id)
        return None

    monkeypatch.setattr(app_module, "load_management_data", _load)
    return calls


async def test_off_means_logs_only_and_no_arm(arm_calls):
    app = FirewallLogApp(enrichment=False)
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        assert not app.query(TabbedContent)
        assert app.query_one("#log-table", DataTable).has_focus
        app.request_mgmt_load("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw")
        await pilot.pause()
        await pilot.pause()
        assert arm_calls == []
        status = app.query_one("#status", StatusBar)
        assert status.meta == ""
        await pilot.press("t")
        assert "needs enrichment" in status.meta
        await pilot.press("ctrl+r")
        assert "enrichment off" in status.meta
        assert app._is_logs_tab_active()  # filters keep working without tabs
        # keys that normally switch back to the Logs tab must not crash without tabs
        for key in ("c", "escape", "f"):
            await pilot.press(key)
            await pilot.pause()
        assert app.query_one("#f-src").has_focus


async def test_off_notice_then_disable_keys_still_work(tmp_path: Path, arm_calls):
    app, env = await _open_notice(tmp_path, arm_calls)
    async with app.run_test(size=(160, 45)) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentNoticeDialog))
        await pilot.pause()
        await pilot.click("#btn-disable")
        await wait_until(pilot, lambda: not isinstance(app.screen, EnrichmentNoticeDialog))
        for key in ("c", "escape", "f"):
            await pilot.press(key)
            await pilot.pause()
        assert app.query_one("#f-src").has_focus


async def test_off_shows_no_notice(arm_calls):
    app = FirewallLogApp(enrichment=False, enrichment_notice=True)
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        assert not isinstance(app.screen, EnrichmentNoticeDialog)


async def test_on_without_notice_is_silent(arm_calls):
    app = FirewallLogApp(enrichment=True, enrichment_notice=False)
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        assert not isinstance(app.screen, EnrichmentNoticeDialog)
        assert app.query_one(TabbedContent)


# ── first-run notice ─────────────────────────────────────────────────────────

async def _open_notice(tmp_path: Path, arm_calls) -> tuple[FirewallLogApp, Path]:
    env = tmp_path / ".env"
    env.write_text(f"EVENT_HUB_CONNECTION_STRING={CONN}\n", encoding="utf-8")
    app = FirewallLogApp(enrichment=True, enrichment_notice=True, env_file=env)
    return app, env


async def test_notice_keep_persists_on(tmp_path: Path, arm_calls):
    app, env = await _open_notice(tmp_path, arm_calls)
    async with app.run_test(size=(160, 45)) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentNoticeDialog))
        await pilot.pause()
        await pilot.click("#btn-keep")
        await wait_until(pilot, lambda: not isinstance(app.screen, EnrichmentNoticeDialog))
        assert app.query_one(TabbedContent)
        app.request_mgmt_load("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw")
        await wait_until(pilot, lambda: len(arm_calls) == 1)
    assert _values(env)["ENRICHMENT"] == "on"
    assert _values(env)["EVENT_HUB_CONNECTION_STRING"] == CONN


@pytest.mark.parametrize("key", ["escape", "q"])
async def test_notice_close_keys_keep_enabled(tmp_path: Path, arm_calls, key):
    app, env = await _open_notice(tmp_path, arm_calls)
    async with app.run_test(size=(160, 45)) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentNoticeDialog))
        await pilot.pause()
        await pilot.press(key)
        await wait_until(pilot, lambda: not isinstance(app.screen, EnrichmentNoticeDialog))
        assert app.query_one(TabbedContent)
        assert not app._exit  # 'q' must not quit the viewer through the dialog
    assert _values(env)["ENRICHMENT"] == "on"


async def test_notice_disable_removes_tabs_and_persists_off(tmp_path: Path, arm_calls):
    app, env = await _open_notice(tmp_path, arm_calls)
    async with app.run_test(size=(160, 45)) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentNoticeDialog))
        await pilot.pause()
        await pilot.click("#btn-disable")
        await wait_until(pilot, lambda: not isinstance(app.screen, EnrichmentNoticeDialog))
        await pilot.pause()
        tabs = app.query_one(TabbedContent)
        assert [p.id for p in tabs.query("TabPane")] == ["tab-logs"]
        assert app.query_one("#status", StatusBar).meta == "enrichment off"
        app.request_mgmt_load("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw")
        await pilot.pause()
        await pilot.pause()
        assert arm_calls == []
        assert app._is_logs_tab_active()
    assert _values(env)["ENRICHMENT"] == "off"


async def test_notice_without_env_file_does_not_write(tmp_path: Path, arm_calls):
    app = FirewallLogApp(enrichment=True, enrichment_notice=True, env_file=tmp_path / "missing.env")
    async with app.run_test(size=(160, 45)) as pilot:
        await wait_until(pilot, lambda: isinstance(app.screen, EnrichmentNoticeDialog))
        await pilot.pause()
        await pilot.click("#btn-disable")
        await wait_until(pilot, lambda: not isinstance(app.screen, EnrichmentNoticeDialog))
    assert not (tmp_path / "missing.env").exists()
    assert not os.path.exists(tmp_path / ".env")
