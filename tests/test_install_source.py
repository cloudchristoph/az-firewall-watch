"""Package-manager installs (Homebrew cask, winget portable): config location and the upgrade hint."""
from __future__ import annotations

import io
import json
from pathlib import Path, PureWindowsPath

import pytest
from textual.app import App
from textual.widgets import Static

import viewer.updates as updates_module
from dialogs import UpdateDialog
from viewer.config import UPGRADE_COMMANDS, frozen_base_dir, install_source, install_source_of, prepare_base_dir
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
    assert install_source(real) == "homebrew"
    assert install_source(link) == "homebrew"  # resolved through the bin symlink


@pytest.mark.parametrize("path", [
    r"C:\Users\me\AppData\Local\Microsoft\WinGet\Packages\cloudchristoph.az-firewall-watch_Microsoft.Winget.Source_8wekyb3d8bbwe\az-firewall-watch.exe",
    r"C:\Users\me\AppData\Local\Microsoft\WinGet\Links\az-firewall-watch.exe",
    r"C:\Program Files\WinGet\Packages\cloudchristoph.az-firewall-watch_Microsoft.Winget.Source_8wekyb3d8bbwe\az-firewall-watch.exe",
    r"c:\users\me\appdata\local\microsoft\winget\links\az-firewall-watch.exe",  # case-insensitive, as Windows is
])
def test_winget_portable_paths(path):
    assert install_source_of(PureWindowsPath(path).parts) == "winget"


@pytest.mark.parametrize("path", [
    r"C:\Users\me\Downloads\az-firewall-watch.exe",
    r"C:\Tools\winget\az-firewall-watch.exe",  # a folder named winget alone is not winget's
])
def test_other_windows_paths_are_not_package_installs(path):
    assert install_source_of(PureWindowsPath(path).parts) is None


def test_downloaded_binary_is_not_a_package_install(tmp_path):
    exe = tmp_path / "Downloads" / "az-firewall-watch"
    exe.parent.mkdir()
    exe.write_text("")
    assert install_source(exe) is None
    assert frozen_base_dir(exe) == exe.parent  # .env next to the binary, as before


def test_package_install_keeps_env_in_the_config_dir(tmp_path, monkeypatch):
    _, link = _cask_binary(tmp_path)
    monkeypatch.setattr("platformdirs.user_config_dir", lambda name, appauthor=None: str(tmp_path / "config" / name))
    base = frozen_base_dir(link)
    assert base == tmp_path / "config" / "az-firewall-watch"
    assert "Caskroom" not in base.parts  # survives brew upgrade, which replaces the versioned folder


@pytest.mark.skipif(not hasattr(__import__("os"), "geteuid"), reason="POSIX permissions")
def test_package_config_dir_is_private(tmp_path):
    base = tmp_path / "config" / "az-firewall-watch"
    prepare_base_dir(base, private=True)
    assert base.is_dir()
    assert base.stat().st_mode & 0o777 == 0o700  # the .env inside may carry a SAS key


@pytest.mark.skipif(not hasattr(__import__("os"), "geteuid"), reason="POSIX permissions")
def test_folder_next_to_a_download_keeps_its_permissions(tmp_path):
    folder = tmp_path / "Downloads"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    prepare_base_dir(folder, private=False)
    assert folder.stat().st_mode & 0o777 == 0o755  # the user's folder, not ours to lock down


def test_prepare_base_dir_creates_missing_parents(tmp_path):
    base = tmp_path / "a" / "b" / "az-firewall-watch"
    prepare_base_dir(base, private=True)
    assert base.is_dir()


class _RecordingApp:
    def __init__(self) -> None:
        self.pushed: list = []

    async def push_screen(self, screen) -> None:
        self.pushed.append(screen)


@pytest.mark.parametrize("source", ["homebrew", "winget", None])
async def test_update_dialog_carries_upgrade_command(monkeypatch, source):
    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    payload = json.dumps({"tag_name": "v99.0.0", "html_url": "https://example.test/rel"}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resp(payload))
    monkeypatch.setattr(updates_module, "INSTALL_SOURCE", source)
    app = _RecordingApp()
    await check_for_update(app, "0.1.0")
    expected = UPGRADE_COMMANDS.get(source) if source else None
    assert app.pushed[0]._upgrade_command == expected
    assert app.pushed[0].recreate()._upgrade_command == expected  # kept across the splash re-push


class _DialogHost(App):
    def __init__(self, dialog: UpdateDialog) -> None:
        super().__init__()
        self._dialog = dialog

    async def on_mount(self) -> None:
        await self.push_screen(self._dialog)


@pytest.mark.parametrize("command", [
    "brew upgrade --cask az-firewall-watch",
    "winget upgrade cloudchristoph.az-firewall-watch",
    None,
])
async def test_upgrade_hint_only_for_package_installs(command):
    app = _DialogHost(UpdateDialog("99.0.0", "https://example.test/rel", command))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        rendered = " ".join(str(s.content) for s in app.screen.query(Static))
        if command:
            assert command in rendered
        else:
            assert "upgrade" not in rendered


# ── .env file mode ────────────────────────────────────────────────────────────

_POSIX = pytest.mark.skipif(not hasattr(__import__("os"), "geteuid"), reason="POSIX permissions")
_CONN = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=secret;EntityPath=h"


@_POSIX
@pytest.mark.parametrize("write", [
    lambda env: __import__("setup.services", fromlist=["write_env"]).write_env(env, _CONN),
    lambda env: __import__("setup.services", fromlist=["write_env_entra"]).write_env_entra(env, "ns.servicebus.windows.net", "h"),
])
def test_wizard_writes_env_for_the_user_only(tmp_path, write):
    env = tmp_path / ".env"
    write(env)
    assert env.stat().st_mode & 0o777 == 0o600  # may carry a SAS key


@_POSIX
def test_set_env_value_tightens_an_existing_env(tmp_path):
    from setup.services import set_env_value

    env = tmp_path / ".env"
    env.write_text(f"EVENT_HUB_CONNECTION_STRING={_CONN}\n", encoding="utf-8")
    env.chmod(0o644)  # written by an older version or by hand
    set_env_value(env, "POLICY_CONTEXT", "off")
    assert env.stat().st_mode & 0o777 == 0o600
    assert env.read_text(encoding="utf-8").startswith(f"EVENT_HUB_CONNECTION_STRING={_CONN}\n")
