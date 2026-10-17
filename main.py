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

Options
  --reconfigure     redo the setup wizard
  --policy-context      force policy context on for this run
  --no-policy-context   force it off (no ARM access, no cache, Logs tab only)
"""
from __future__ import annotations

import os
import sys

from viewer import FirewallLogApp
from viewer.config import BASE_DIR, load_env, policy_context_setting, update_check_enabled


def _maybe_run_wizard() -> bool:
    """Return whether to start the viewer, running setup when needed."""
    has_conn_str = bool(os.environ.get("EVENT_HUB_CONNECTION_STRING"))
    has_entra = bool(
        os.environ.get("EVENT_HUB_NAMESPACE") and os.environ.get("EVENT_HUB_NAME")
    )
    if (not has_conn_str and not has_entra) or "--reconfigure" in sys.argv:
        from setup.app import run_wizard
        if not run_wizard(BASE_DIR, reconfigure="--reconfigure" in sys.argv):
            return False
        load_env(BASE_DIR / ".env", override=True)

    return True


def main() -> None:
    load_env(BASE_DIR / ".env")
    if not _maybe_run_wizard():
        return
    enabled, explicit = policy_context_setting(sys.argv, os.environ)
    FirewallLogApp(
        policy_context=enabled,
        policy_context_notice=enabled and not explicit,  # nobody decided yet → say what is on
        env_file=BASE_DIR / ".env",
        update_check=update_check_enabled(sys.argv, os.environ),
    ).run()


if __name__ == "__main__":
    main()
