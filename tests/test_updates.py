"""Update check against GitHub releases (viewer/updates.py + UpdateDialog)."""
from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest
from textual.widgets import Static

import viewer.app as app_module
from dialogs import UpdateDialog
from viewer.app import FirewallLogApp
from viewer.updates import _parse_version, check_for_update


# ── helpers ──────────────────────────────────────────────────────────────────

class _FakeResponse(io.BytesIO):
    """Minimal stand-in for the object returned by urllib.request.urlopen."""

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def _fake_urlopen(payload: Any, *, raise_exc: Exception | None = None):
    """Return a urlopen replacement that yields *payload* (or raises)."""
    calls: list[dict] = []

    def _urlopen(req, timeout=None):
        calls.append({"url": req.full_url, "headers": dict(req.header_items()), "timeout": timeout})
        if raise_exc is not None:
            raise raise_exc
        body = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()
        return _FakeResponse(body)

    _urlopen.calls = calls  # type: ignore[attr-defined]
    return _urlopen


class _RecordingApp:
    """Duck-typed app that records pushed screens."""

    def __init__(self) -> None:
        self.pushed: list[Any] = []

    async def push_screen(self, screen: Any) -> None:
        self.pushed.append(screen)


def _release(tag: str, url: str = "https://github.com/cloudchristoph/az-firewall-watch/releases/tag/x") -> dict:
    return {"tag_name": tag, "html_url": url}


# ── _parse_version ───────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("0.3.0", (0, 3, 0)),
        ("1.10.2", (1, 10, 2)),
        ("2", (2,)),
        ("unknown", (0,)),
        ("", (0,)),
        ("0.3.0-rc1", (0,)),
    ],
)
def test_parse_version(raw, expected):
    assert _parse_version(raw) == expected


def test_parse_version_orders_numerically_not_lexically():
    assert _parse_version("0.10.0") > _parse_version("0.9.9")
    assert _parse_version("1.0.0") > _parse_version("0.99.99")


def test_unknown_version_is_older_than_everything():
    # A binary without version.txt reports "unknown" → every real release counts as newer.
    assert _parse_version("0.1.0") > _parse_version("unknown")


# ── check_for_update (unit) ──────────────────────────────────────────────────

async def test_newer_release_pushes_update_dialog(monkeypatch):
    fake = _fake_urlopen(_release("v0.4.0", "https://example.test/rel"))
    monkeypatch.setattr("urllib.request.urlopen", fake)
    app = _RecordingApp()

    await check_for_update(app, "0.3.0")

    assert len(app.pushed) == 1
    dialog = app.pushed[0]
    assert isinstance(dialog, UpdateDialog)
    assert dialog._latest == "0.4.0"  # "v" prefix stripped
    assert dialog._url == "https://example.test/rel"


async def test_request_targets_latest_release_with_user_agent(monkeypatch):
    fake = _fake_urlopen(_release("v0.3.0"))
    monkeypatch.setattr("urllib.request.urlopen", fake)

    await check_for_update(_RecordingApp(), "0.3.0")

    call = fake.calls[0]
    assert call["url"] == "https://api.github.com/repos/cloudchristoph/az-firewall-watch/releases/latest"
    assert call["headers"].get("User-agent") == "az-firewall-watch/0.3.0"
    assert call["timeout"] == 5


@pytest.mark.parametrize("tag", ["v0.3.0", "0.3.0", "v0.2.9", "v0.1.0"])
async def test_same_or_older_release_shows_nothing(monkeypatch, tag):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(_release(tag)))
    app = _RecordingApp()

    await check_for_update(app, "0.3.0")

    assert app.pushed == []


async def test_unknown_current_version_still_sees_release_as_newer(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(_release("v0.3.0")))
    app = _RecordingApp()

    await check_for_update(app, "unknown")

    assert len(app.pushed) == 1


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError("no network"),
        urllib.error.HTTPError("u", 403, "rate limited", {}, None),  # type: ignore[arg-type]
        TimeoutError("timed out"),
    ],
)
async def test_network_errors_fail_silently(monkeypatch, exc):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(None, raise_exc=exc))
    app = _RecordingApp()

    await check_for_update(app, "0.3.0")

    assert app.pushed == []


async def test_malformed_payload_fails_silently(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(b"<html>not json</html>"))
    app = _RecordingApp()

    await check_for_update(app, "0.3.0")

    assert app.pushed == []


async def test_payload_without_tag_shows_nothing(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen({"message": "Not Found"}))
    app = _RecordingApp()

    await check_for_update(app, "0.3.0")

    assert app.pushed == []


async def test_missing_html_url_falls_back_to_releases_page(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen({"tag_name": "v9.0.0"}))
    app = _RecordingApp()

    await check_for_update(app, "0.3.0")

    assert app.pushed[0]._url == "https://github.com/cloudchristoph/az-firewall-watch/releases"


# ── UpdateDialog behaviour (headless app) ────────────────────────────────────

@pytest.mark.usefixtures("no_eventhub_env")
class TestUpdateDialogInApp:
    @pytest.fixture(autouse=True)
    def _newer_release(self, monkeypatch):
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(_release("v99.0.0", "https://example.test/rel")))

    async def test_dialog_appears_on_startup_and_escape_dismisses(self):
        app = FirewallLogApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            assert isinstance(app.screen, UpdateDialog)
            rendered = " ".join(str(s.content) for s in app.screen.query(Static))
            assert "99.0.0" in rendered
            assert "https://example.test/rel" in rendered
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, UpdateDialog)

    async def test_open_button_launches_browser_and_dismisses(self, monkeypatch):
        opened: list[str] = []
        monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
        app = FirewallLogApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            assert isinstance(app.screen, UpdateDialog)
            await pilot.click("#btn-open")
            await pilot.pause()
            assert opened == ["https://example.test/rel"]
            assert not isinstance(app.screen, UpdateDialog)

    async def test_dismiss_button_does_not_open_browser(self, monkeypatch):
        opened: list[str] = []
        monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
        app = FirewallLogApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn-dismiss")
            await pilot.pause()
            assert opened == []
            assert not isinstance(app.screen, UpdateDialog)

    async def test_browser_failure_still_dismisses(self, monkeypatch):
        def _boom(_url):
            raise RuntimeError("no browser")

        monkeypatch.setattr("webbrowser.open", _boom)
        app = FirewallLogApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn-open")
            await pilot.pause()
            assert not isinstance(app.screen, UpdateDialog)


@pytest.mark.usefixtures("no_eventhub_env")
async def test_no_dialog_when_up_to_date(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(_release(f"v{app_module.VERSION}")))
    app = FirewallLogApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        assert not isinstance(app.screen, UpdateDialog)
