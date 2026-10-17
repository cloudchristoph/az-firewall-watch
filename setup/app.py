from __future__ import annotations

import sys
from pathlib import Path

from textual.app import App
from textual.binding import Binding

from helpers import load_env

from .screens import WelcomeScreen
from .services import get_existing_conn_str, has_entra_config


class WizardApp(App[bool]):
    """Top-level Textual app for the setup wizard."""

    TITLE = "Azure Firewall Watch — Setup Wizard"

    CSS = """
    Screen {
        align: center middle;
    }
    .wiz-box {
        width: 72;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    .wiz-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
        text-align: center;
    }
    .wiz-info {
        color: $text-muted;
        margin-bottom: 1;
    }
    .wiz-error {
        color: $error;
        margin-bottom: 1;
    }
    .wiz-ok {
        color: $success;
    }
    .wiz-warn {
        color: $warning;
    }
    .wiz-section {
        text-style: bold;
        color: $text;
        margin-top: 1;
    }
    .wiz-buttons {
        height: auto;
        margin-top: 1;
        align: right middle;
    }
    .wiz-buttons Button {
        margin-left: 1;
    }
    ContentSwitcher {
        height: auto;
    }
    ContentSwitcher > Vertical {
        height: auto;
    }
    RichLog {
        height: 8;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }
    #scan-log {
        height: 5;
    }
    LoadingIndicator {
        height: 1;
        margin-bottom: 1;
    }
    ListView {
        height: 7;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }
    """

    BINDINGS = [Binding("ctrl+q", "quit", "Quit", priority=True)]

    def __init__(self, env_file: Path) -> None:
        super().__init__()
        self.theme = "flexoki"
        self.env_file = env_file

    async def action_quit(self) -> None:
        self.exit(False)

    def on_mount(self) -> None:
        self.push_screen(WelcomeScreen())


def run_wizard(base_dir: Path, reconfigure: bool = False) -> bool:
    """Return True when configuration is ready, False when setup is cancelled."""
    env_file = base_dir / ".env"

    if not reconfigure and (get_existing_conn_str(env_file) or has_entra_config(env_file)):
        return True

    load_env(env_file)
    return WizardApp(env_file).run() is True


if __name__ == "__main__":
    reconfigure = "--reconfigure" in sys.argv
    run_wizard(Path(__file__).parent.parent, reconfigure=reconfigure)
