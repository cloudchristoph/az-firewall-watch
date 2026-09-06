"""setup/services.py, setup/utils.py and the run_wizard() entry decision."""
from __future__ import annotations

from pathlib import Path

import pytest

import setup.app as wizard_app
from setup.services import get_existing_conn_str, has_entra_config, write_env, write_env_entra
from setup.utils import find_az, location_short

CONN = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=l;SharedAccessKey=K;EntityPath=h"


# ── write / read .env ────────────────────────────────────────────────────────

def test_write_env_sas(tmp_path: Path):
    env = tmp_path / ".env"
    write_env(env, CONN)
    text = env.read_text(encoding="utf-8")
    assert f"EVENT_HUB_CONNECTION_STRING={CONN}\n" in text
    assert "EVENT_HUB_CONSUMER_GROUP=$Default\n" in text
    assert "EVENT_HUB_START_POSITION=latest\n" in text
    assert "Do NOT commit" in text
    assert get_existing_conn_str(env) == CONN
    assert has_entra_config(env) is False


def test_write_env_entra(tmp_path: Path):
    env = tmp_path / ".env"
    write_env_entra(env, "ns.servicebus.windows.net", "firewall-logs")
    text = env.read_text(encoding="utf-8")
    assert "EVENT_HUB_NAMESPACE=ns.servicebus.windows.net\n" in text
    assert "EVENT_HUB_NAME=firewall-logs\n" in text
    assert "EVENT_HUB_CONNECTION_STRING" not in text
    assert has_entra_config(env) is True
    assert get_existing_conn_str(env) is None


def test_write_env_overwrites_previous_mode(tmp_path: Path):
    env = tmp_path / ".env"
    write_env(env, CONN)
    write_env_entra(env, "ns.servicebus.windows.net", "h")
    assert get_existing_conn_str(env) is None
    assert has_entra_config(env)


def test_missing_env_file(tmp_path: Path):
    env = tmp_path / ".env"
    assert get_existing_conn_str(env) is None
    assert has_entra_config(env) is False


def test_empty_values_do_not_count(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("EVENT_HUB_CONNECTION_STRING=\nEVENT_HUB_NAMESPACE=ns\nEVENT_HUB_NAME=   \n", encoding="utf-8")
    assert get_existing_conn_str(env) is None
    assert has_entra_config(env) is False


def test_entra_requires_both_namespace_and_name(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("EVENT_HUB_NAMESPACE=ns.servicebus.windows.net\n", encoding="utf-8")
    assert has_entra_config(env) is False


def test_env_with_cp1252_encoding_is_readable(tmp_path: Path):
    """Regression for the Windows crash on non-UTF-8 .env files (0.2.1)."""
    env = tmp_path / ".env"
    env.write_bytes(("# Überschrift\n" f"EVENT_HUB_CONNECTION_STRING={CONN}\n").encode("cp1252"))
    assert get_existing_conn_str(env) == CONN


# ── utils ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "location, short",
    [
        ("germanywestcentral", "gwc"),
        ("WestEurope", "we"),
        ("eastus2", "eus2"),
        ("brazilsouth", "brazil"),  # unknown → first six chars
        ("uk", "uk"),
    ],
)
def test_location_short(location, short):
    assert location_short(location) == short


def test_find_az_uses_which(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/az" if name == "az" else None)
    assert find_az() == "/usr/bin/az"


def test_find_az_falls_back_to_windows_shim(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: r"C:\az.cmd" if name == "az.cmd" else None)
    assert find_az() == r"C:\az.cmd"


def test_find_az_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert find_az() is None


# ── run_wizard entry decision ────────────────────────────────────────────────

@pytest.fixture
def fake_wizard(monkeypatch):
    runs: list[Path] = []

    class _FakeApp:
        def __init__(self, env_file: Path) -> None:
            self.env_file = env_file

        def run(self) -> None:
            runs.append(self.env_file)

    monkeypatch.setattr(wizard_app, "WizardApp", _FakeApp)
    return runs


def test_run_wizard_skips_when_sas_configured(tmp_path: Path, fake_wizard):
    write_env(tmp_path / ".env", CONN)
    wizard_app.run_wizard(tmp_path)
    assert fake_wizard == []


def test_run_wizard_skips_when_entra_configured(tmp_path: Path, fake_wizard):
    write_env_entra(tmp_path / ".env", "ns.servicebus.windows.net", "h")
    wizard_app.run_wizard(tmp_path)
    assert fake_wizard == []


def test_run_wizard_runs_when_env_missing(tmp_path: Path, fake_wizard):
    wizard_app.run_wizard(tmp_path)
    assert fake_wizard == [tmp_path / ".env"]


def test_run_wizard_runs_on_reconfigure_even_if_configured(tmp_path: Path, fake_wizard):
    write_env(tmp_path / ".env", CONN)
    wizard_app.run_wizard(tmp_path, reconfigure=True)
    assert fake_wizard == [tmp_path / ".env"]
