#!/usr/bin/env python3
"""
az-firewall-watch — Azure Firewall log stream in your terminal.

Connects to an Azure Event Hub and displays incoming firewall logs in a
filterable TUI table. Connection parameters are read from .env in this folder.

Key bindings
  q / ctrl+q  Quit
  ctrl+p      Pause / resume streaming  (or click the status bar)
  c        Clear all rows
  Escape   Clear all filter inputs
  f        Focus the Source-IP filter
"""
from __future__ import annotations

import os
import sys

from viewer import FirewallLogApp
from viewer.config import BASE_DIR, load_env


def _maybe_run_wizard() -> None:
    """Launch the setup wizard when Event Hub credentials are missing or on --reconfigure."""
    has_conn_str = bool(os.environ.get("EVENT_HUB_CONNECTION_STRING"))
    has_entra = bool(
        os.environ.get("EVENT_HUB_NAMESPACE") and os.environ.get("EVENT_HUB_NAME")
    )
    if (not has_conn_str and not has_entra) or "--reconfigure" in sys.argv:
        from setup.app import run_wizard
        run_wizard(BASE_DIR, reconfigure="--reconfigure" in sys.argv)
        load_env(BASE_DIR / ".env", override=True)


def main() -> None:
    load_env(BASE_DIR / ".env")
    _maybe_run_wizard()
    FirewallLogApp().run()


if __name__ == "__main__":
    main()
