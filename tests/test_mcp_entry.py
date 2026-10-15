"""Entry point of the MCP server: command line, configuration, exit codes, import hygiene."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import mcp_server.cli as cli
import mcp_server.server as server_module
from mcp_server.config import DEFAULT_BUFFER_SIZE, ServerConfig

ROOT = Path(__file__).resolve().parent.parent
ENTRA_ENV = {"EVENT_HUB_NAMESPACE": "lab-ns.servicebus.windows.net", "EVENT_HUB_NAME": "firewall-logs"}

pytestmark = pytest.mark.usefixtures("no_eventhub_env")


@pytest.fixture
def empty_env_file(tmp_path: Path) -> Path:
    path = tmp_path / "empty.env"
    path.write_text("# nothing configured\n", encoding="utf-8")
    return path


@pytest.fixture
def fake_run(monkeypatch) -> dict[str, Any]:
    """Replace the server with a recorder; the real one would block on stdin."""
    seen: dict[str, Any] = {}

    class _Server:
        def run(self, transport: str, **kwargs: Any) -> None:
            seen["transport"], seen["kwargs"] = transport, kwargs

    def _build(config: ServerConfig, **_kw: Any) -> _Server:
        seen["config"] = config
        return _Server()

    monkeypatch.setattr(server_module, "build_server", _build)
    monkeypatch.setattr(cli, "configure_logging", lambda level: seen.setdefault("log_level", level))
    for key in ("POLICY_CONTEXT", "AZFW_FIREWALL_ID", "AZFW_MCP_BUFFER_SIZE", "AZFW_MCP_TRANSPORT", "AZFW_MCP_HOST",
                "AZFW_MCP_PORT", "AZFW_MCP_LOG_LEVEL"):
        monkeypatch.delenv(key, raising=False)
    return seen


# ── exit codes ───────────────────────────────────────────────────────────────

def test_missing_credentials_exit_2_with_wizard_hint(empty_env_file, capsys):
    assert cli.main(["--env-file", str(empty_env_file)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no Event Hub credentials configured" in captured.err
    assert "./az-firewall-watch" in captured.err and "--reconfigure" in captured.err


def test_default_env_file_is_next_to_the_app(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "BASE_DIR", tmp_path)   # no .env there
    assert cli.main([]) == 2
    assert "no Event Hub credentials" in capsys.readouterr().err


def test_missing_env_file_exit_2(tmp_path, capsys):
    assert cli.main(["--env-file", str(tmp_path / "nope.env")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_bad_setting_exit_2(empty_env_file, monkeypatch, capsys):
    monkeypatch.setenv("AZFW_MCP_BUFFER_SIZE", "lots")
    assert cli.main(["--env-file", str(empty_env_file)]) == 2
    assert "AZFW_MCP_BUFFER_SIZE must be a whole number" in capsys.readouterr().err


def test_env_file_is_loaded_and_server_runs_stdio(tmp_path, fake_run, monkeypatch, capsys):
    env_file = tmp_path / "custom.env"
    env_file.write_text("EVENT_HUB_NAMESPACE=lab-ns.servicebus.windows.net\nEVENT_HUB_NAME=firewall-logs\n",
                        encoding="utf-8")
    for key in ENTRA_ENV:
        # load_env writes into os.environ behind monkeypatch's back; registering the
        # keys first makes monkeypatch remove them again after the test.
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)
    assert cli.main(["--env-file", str(env_file)]) == 0
    assert fake_run["transport"] == "stdio" and fake_run["kwargs"] == {}
    config = fake_run["config"]
    assert config.eventhub.use_entra and config.eventhub.hub_name == "firewall-logs"
    assert config.env_file == env_file
    assert capsys.readouterr().out == ""


def test_no_policy_context_flag(empty_env_file, fake_run, monkeypatch):
    for key, value in ENTRA_ENV.items():
        monkeypatch.setenv(key, value)
    assert cli.main(["--env-file", str(empty_env_file), "--no-policy-context"]) == 0
    assert fake_run["config"].policy_context is False


def test_http_transport(empty_env_file, fake_run, monkeypatch):
    for key, value in ENTRA_ENV.items():
        monkeypatch.setenv(key, value)
    assert cli.main(["--env-file", str(empty_env_file), "--transport", "http", "--port", "9000",
                     "--log-level", "debug"]) == 0
    assert fake_run["transport"] == "streamable-http"
    assert fake_run["kwargs"] == {"host": "127.0.0.1", "port": 9000}
    assert fake_run["log_level"] == "DEBUG"


def test_main_py_switch_is_accepted(empty_env_file, fake_run, monkeypatch):
    for key, value in ENTRA_ENV.items():
        monkeypatch.setenv(key, value)
    assert cli.main(["--mcp", "--env-file", str(empty_env_file)]) == 0


# ── ServerConfig ─────────────────────────────────────────────────────────────

def test_config_defaults():
    config = ServerConfig.from_env(ENTRA_ENV, [])
    assert (config.policy_context, config.firewall_id, config.buffer_size, config.transport, config.host,
            config.port, config.log_level) == (True, None, DEFAULT_BUFFER_SIZE, "stdio", "127.0.0.1", 8765, "INFO")
    assert config.eventhub.consumer_group == "$Default"


def test_config_from_environment(firewall_id):
    env = {**ENTRA_ENV, "POLICY_CONTEXT": "off", "AZFW_FIREWALL_ID": firewall_id, "AZFW_MCP_BUFFER_SIZE": "500",
           "AZFW_MCP_TRANSPORT": "HTTP", "AZFW_MCP_HOST": "localhost", "AZFW_MCP_PORT": "9999",
           "AZFW_MCP_LOG_LEVEL": "warning", "EVENT_HUB_CONSUMER_GROUP": "mcp"}
    config = ServerConfig.from_env(env, [])
    assert (config.policy_context, config.firewall_id, config.buffer_size, config.transport, config.host,
            config.port, config.log_level) == (False, firewall_id, 500, "http", "localhost", 9999, "WARNING")
    assert config.eventhub.consumer_group == "mcp"


def test_command_line_wins_over_environment(firewall_id):
    env = {**ENTRA_ENV, "POLICY_CONTEXT": "off", "AZFW_MCP_BUFFER_SIZE": "500", "AZFW_MCP_TRANSPORT": "http"}
    config = ServerConfig.from_env(env, ["--policy-context", "--buffer-size", "1000", "--transport", "stdio",
                                         "--firewall-id", firewall_id])
    assert (config.policy_context, config.buffer_size, config.transport, config.firewall_id) == \
        (True, 1000, "stdio", firewall_id)


@pytest.mark.parametrize("env, argv, message", [
    ({"AZFW_MCP_TRANSPORT": "carrier-pigeon"}, [], "AZFW_MCP_TRANSPORT must be one of"),
    ({"AZFW_MCP_LOG_LEVEL": "chatty"}, [], "AZFW_MCP_LOG_LEVEL must be one of"),
    ({}, ["--buffer-size", "5"], "between 100 and"),
    ({"AZFW_MCP_PORT": "70000"}, [], "between 1 and 65535"),
    ({"AZFW_FIREWALL_ID": "/subscriptions/x/virtualMachines/vm"}, [], "Azure Firewall resource id"),
])
def test_config_rejects_bad_values(env, argv, message):
    with pytest.raises(ValueError, match=message):
        ServerConfig.from_env({**ENTRA_ENV, **env}, argv)


def test_config_repr_never_shows_the_sas_key():
    config = ServerConfig.from_env({"EVENT_HUB_CONNECTION_STRING": "Endpoint=sb://x/;SharedAccessKey=TOPSECRET"}, [])
    assert config.eventhub.configured and not config.eventhub.use_entra
    assert "TOPSECRET" not in repr(config)


# ── import hygiene and the real process ──────────────────────────────────────

def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("EVENT_HUB_", "AZFW_", "POLICY_CONTEXT"))}
    env["PYTHONPATH"] = str(ROOT)
    return env


def test_package_imports_without_textual():
    code = ("import sys\n"
            "import mcp_server, mcp_server.cli, mcp_server.server, mcp_server.tools_logs, mcp_server.state\n"
            "from mcp_server.server import build_server\n"
            "from mcp_server.config import ServerConfig\n"
            "build_server(ServerConfig())\n"
            "bad = sorted(m for m in sys.modules if m == 'textual' or m.startswith('textual.') or m == 'dialogs')\n"
            "assert not bad, bad\n")
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=_clean_env(), capture_output=True,
                            text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_module_entry_point_exits_2_without_credentials(empty_env_file):
    result = subprocess.run([sys.executable, "-m", "mcp_server", "--env-file", str(empty_env_file)], cwd=ROOT,
                            env=_clean_env(), capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "setup wizard" in result.stderr
