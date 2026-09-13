"""main._maybe_run_wizard: when the viewer hands over to the setup wizard.

The decision is made on the process environment (after .env was loaded), and
whatever the wizard wrote has to be visible to the viewer afterwards.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import main
import setup.app as setup_app

CONN = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=l;SharedAccessKey=K;EntityPath=h"
_ENV_KEYS = ("EVENT_HUB_CONNECTION_STRING", "EVENT_HUB_NAMESPACE", "EVENT_HUB_NAME")


@pytest.fixture
def wizard(monkeypatch, tmp_path: Path):
    """A wizard stand-in that records its call and writes a SAS .env."""
    calls: list[dict] = []

    def _run_wizard(base_dir: Path, reconfigure: bool = False) -> None:
        calls.append({"base_dir": base_dir, "reconfigure": reconfigure})
        (base_dir / ".env").write_text(f"EVENT_HUB_CONNECTION_STRING={CONN}\n", encoding="utf-8")

    monkeypatch.setattr(setup_app, "run_wizard", _run_wizard)
    monkeypatch.setattr(main, "BASE_DIR", tmp_path)
    monkeypatch.setattr(main.sys, "argv", ["main.py"])
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    return calls


def test_without_credentials_the_wizard_runs_and_its_env_is_loaded(wizard, tmp_path: Path, monkeypatch):
    main._maybe_run_wizard()
    assert wizard == [{"base_dir": tmp_path, "reconfigure": False}]
    assert main.os.environ["EVENT_HUB_CONNECTION_STRING"] == CONN


def test_wizard_result_overrides_a_stale_value(wizard, monkeypatch):
    """Empty string counts as missing (the .env template ships one), and the
    wizard's value must win over it, hence override=True on the reload."""
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", "")
    main._maybe_run_wizard()
    assert len(wizard) == 1
    assert main.os.environ["EVENT_HUB_CONNECTION_STRING"] == CONN


def test_connection_string_skips_the_wizard(wizard, monkeypatch):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", CONN)
    main._maybe_run_wizard()
    assert wizard == []


def test_entra_pair_skips_the_wizard(wizard, monkeypatch):
    monkeypatch.setenv("EVENT_HUB_NAMESPACE", "ns.servicebus.windows.net")
    monkeypatch.setenv("EVENT_HUB_NAME", "firewall-logs")
    main._maybe_run_wizard()
    assert wizard == []


@pytest.mark.parametrize("present", ["EVENT_HUB_NAMESPACE", "EVENT_HUB_NAME"])
def test_half_an_entra_config_runs_the_wizard(wizard, monkeypatch, present):
    monkeypatch.setenv(present, "something")
    main._maybe_run_wizard()
    assert len(wizard) == 1


def test_reconfigure_runs_the_wizard_despite_credentials(wizard, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EVENT_HUB_CONNECTION_STRING", "Endpoint=sb://old/;EntityPath=old")
    monkeypatch.setattr(main.sys, "argv", ["main.py", "--reconfigure"])
    main._maybe_run_wizard()
    assert wizard == [{"base_dir": tmp_path, "reconfigure": True}]
    assert main.os.environ["EVENT_HUB_CONNECTION_STRING"] == CONN  # the new value replaced the old
