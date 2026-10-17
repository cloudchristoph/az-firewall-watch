"""UPDATE_CHECK / --no-update-check: the start-up request to api.github.com can be turned off."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from textual.widgets import Static

from setup.app import WizardApp
from setup.screens import WelcomeScreen
from setup.services import write_env, write_env_entra
from viewer.app import FirewallLogApp
from viewer.config import update_check_enabled

# The host named as a word in user-facing text (not a URL check).
_GITHUB_HOST = re.compile(r"(?<![\w.])api\.github\.com(?![\w.])")


@pytest.mark.parametrize("argv, environ, expected", [
    ([], {}, True),                                      # default: on
    ([], {"UPDATE_CHECK": "off"}, False),
    ([], {"UPDATE_CHECK": " OFF "}, False),
    ([], {"UPDATE_CHECK": "false"}, False),
    ([], {"UPDATE_CHECK": "on"}, True),
    ([], {"UPDATE_CHECK": "yes"}, True),
    ([], {"UPDATE_CHECK": ""}, True),
    (["--no-update-check"], {}, False),
    (["--no-update-check"], {"UPDATE_CHECK": "on"}, False),  # the flag wins
])
def test_update_check_enabled(argv, environ, expected):
    assert update_check_enabled(argv, environ) is expected


@pytest.mark.usefixtures("no_eventhub_env")
@pytest.mark.parametrize("update_check, expected_calls", [(True, 1), (False, 0)])
async def test_app_asks_github_only_when_enabled(monkeypatch, update_check, expected_calls):
    calls: list[str] = []

    def _urlopen(req, timeout=None, context=None):
        calls.append(req.full_url)
        raise OSError("offline in tests")

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    app = FirewallLogApp(update_check=update_check)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.5)
    github = [url for url in calls if urlsplit(url).hostname == "api.github.com"]
    assert len(github) == expected_calls


@pytest.mark.parametrize("writer, args", [
    (write_env, ("Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=x;EntityPath=h",)),
    (write_env_entra, ("ns.servicebus.windows.net", "hub")),
])
def test_wizard_env_documents_the_switch(tmp_path: Path, writer, args):
    env = tmp_path / ".env"
    writer(env, *args)
    text = env.read_text(encoding="utf-8")
    assert _GITHUB_HOST.search(text)
    assert "# UPDATE_CHECK=off\n" in text           # offered, commented out
    assert "\nUPDATE_CHECK=" not in text            # not set: the default stays on


async def test_wizard_welcome_mentions_the_update_check(tmp_path: Path):
    app = WizardApp(tmp_path / ".env")
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, WelcomeScreen)
        note = str(app.screen.query_one("#welcome-update-note", Static).content)
        assert _GITHUB_HOST.search(note) and "UPDATE_CHECK=off" in note


@pytest.mark.parametrize("value", ["off", "on"])
@pytest.mark.parametrize("writer, args", [
    (write_env, ("Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=x;EntityPath=h",)),
    (write_env_entra, ("ns.servicebus.windows.net", "hub")),
])
def test_reconfigure_keeps_an_update_check_choice(tmp_path: Path, writer, args, value):
    """--reconfigure rewrites .env; a set UPDATE_CHECK must survive it."""
    env = tmp_path / ".env"
    writer(env, *args)
    text = env.read_text(encoding="utf-8").replace("# UPDATE_CHECK=off\n", f"UPDATE_CHECK={value}\n")
    env.write_text(text, encoding="utf-8")  # the user uncommented the switch

    writer(env, *args)  # the wizard runs again
    rewritten = env.read_text(encoding="utf-8")
    assert f"\nUPDATE_CHECK={value}\n" in rewritten
    assert "# UPDATE_CHECK=off\n" not in rewritten
    assert update_check_enabled([], {"UPDATE_CHECK": value}) is (value == "on")
