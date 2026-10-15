"""main.py --mcp: the MCP server runs instead of the viewer, and every other option goes to it."""
from __future__ import annotations

from typing import Any

import pytest

import main
import mcp_server.cli as cli

RETURN_CODE = 3  # distinct from 0 (ok) and 2 (usage or configuration error)


@pytest.fixture
def started(monkeypatch) -> dict[str, Any]:
    """Replace the server, the viewer, the wizard and the .env loader with recorders."""
    seen: dict[str, Any] = {"mcp_argv": [], "started": []}

    def _fake_mcp_main(argv: Any = None) -> int:
        seen["mcp_argv"].append(None if argv is None else list(argv))
        return RETURN_CODE

    class _FakeViewer:
        def __init__(self, **kwargs: Any) -> None:
            seen["started"].append("viewer")
            seen["viewer_kwargs"] = kwargs

        def run(self) -> None:
            seen["started"].append("viewer.run")

    monkeypatch.setattr(cli, "main", _fake_mcp_main)
    monkeypatch.setattr(main, "FirewallLogApp", _FakeViewer)
    monkeypatch.setattr(main, "_maybe_run_wizard", lambda: seen["started"].append("wizard"))
    monkeypatch.setattr(main, "load_env", lambda *_a, **_k: seen["started"].append("load_env"))
    return seen


def _run_main(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr(main.sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        main.main()
    return exc.value.code


def test_mcp_switch_starts_the_server_with_no_further_options(monkeypatch, started):
    assert _run_main(monkeypatch, ["main.py", "--mcp"]) == RETURN_CODE
    assert started["mcp_argv"] == [[]]


def test_mcp_switch_starts_neither_the_viewer_nor_the_wizard(monkeypatch, started):
    _run_main(monkeypatch, ["main.py", "--mcp"])
    assert started["started"] == []  # no load_env, no wizard, no FirewallLogApp


def test_other_options_pass_through_to_the_server(monkeypatch, started):
    code = _run_main(monkeypatch, ["main.py", "--mcp", "--no-policy-context", "--transport", "http"])
    assert code == RETURN_CODE
    assert started["mcp_argv"] == [["--no-policy-context", "--transport", "http"]]
    assert started["started"] == []


def test_switch_position_does_not_matter(monkeypatch, started):
    _run_main(monkeypatch, ["main.py", "--env-file", "lab.env", "--mcp", "--port", "9000"])
    assert started["mcp_argv"] == [["--env-file", "lab.env", "--port", "9000"]]


def test_without_the_switch_the_viewer_starts(monkeypatch, started):
    """Regression guard: the new branch must not change the TUI path."""
    monkeypatch.setattr(main, "load_env", lambda *_a, **_k: started["started"].append("load_env"))
    monkeypatch.setattr(main.sys, "argv", ["main.py", "--no-policy-context"])
    main.main()
    assert started["mcp_argv"] == []
    assert "viewer.run" in started["started"]
    assert started["viewer_kwargs"]["policy_context"] is False
