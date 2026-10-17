"""Homebrew cask install: config location and the upgrade hint."""
from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import Static

import viewer.updates as updates_module
from dialogs import UpdateDialog
from viewer.config import frozen_base_dir, is_homebrew_install
from viewer.updates import check_for_update


def _cask_binary(tmp_path: Path) -> tuple[Path, Path]:
    """A binary in a versioned Caskroom folder and its symlink in ``bin``,
    laid out the way ``brew install --cask`` does it."""
    real = tmp_path / "homebrew" / "Caskroom" / "az-firewall-watch" / "0.7.0" / "az-firewall-watch"
    real.parent.mkdir(parents=True)
    real.write_text("")
    link = tmp_path / "homebrew" / "bin" / "az-firewall-watch"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    return real, link


def test_caskroom_binary_is_a_homebrew_install(tmp_path):
    real, link = _cask_binary(tmp_path)
    assert is_homebrew_install(real)
    assert is_homebrew_install(link)  # resolved through the bin symlink


def test_downloaded_binary_is_not_a_homebrew_install(tmp_path):
    exe = tmp_path / "Downloads" / "az-firewall-watch"
    exe.parent.mkdir()
    exe.write_text("")
    assert not is_homebrew_install(exe)
    assert frozen_base_dir(exe) == exe.parent  # .env next to the binary, as before


def test_homebrew_install_keeps_env_outside_the_caskroom(tmp_path, monkeypatch):
    _, link = _cask_binary(tmp_path)
    monkeypatch.setattr("platformdirs.user_config_dir", lambda name, appauthor=None: str(tmp_path / "config" / name))
    base = frozen_base_dir(link)
    assert base == tmp_path / "config" / "az-firewall-watch"
    assert "Caskroom" not in base.parts  # survives brew upgrade, which replaces the versioned folder


class _RecordingApp:
    def __init__(self) -> None:
        self.pushed: list = []

    async def push_screen(self, screen) -> None:
        self.pushed.append(screen)


@pytest.mark.parametrize("homebrew", [True, False])
async def test_update_dialog_carries_install_kind(monkeypatch, homebrew):
    import io
    import json

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    payload = json.dumps({"tag_name": "v99.0.0", "html_url": "https://example.test/rel"}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resp(payload))
    monkeypatch.setattr(updates_module, "HOMEBREW", homebrew)
    app = _RecordingApp()
    await check_for_update(app, "0.1.0")
    assert app.pushed[0]._homebrew is homebrew
    assert app.pushed[0].recreate()._homebrew is homebrew  # kept across the splash re-push


class _DialogHost(App):
    def __init__(self, dialog: UpdateDialog) -> None:
        super().__init__()
        self._dialog = dialog

    async def on_mount(self) -> None:
        await self.push_screen(self._dialog)


@pytest.mark.parametrize("homebrew, shown", [(True, True), (False, False)])
async def test_brew_upgrade_hint_only_for_homebrew(homebrew, shown):
    app = _DialogHost(UpdateDialog("99.0.0", "https://example.test/rel", homebrew=homebrew))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        rendered = " ".join(str(s.content) for s in app.screen.query(Static))
        assert ("brew upgrade --cask az-firewall-watch" in rendered) is shown
