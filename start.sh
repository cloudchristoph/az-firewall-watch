#!/usr/bin/env bash
# start.sh  —  run az-firewall-watch from source (Linux / macOS)
#
# Usage:
#   ./start.sh               normal start (setup wizard runs if .env is missing)
#   ./start.sh --reconfigure redo the Event Hub setup
set -e
cd "$(dirname "$0")"

# Python 3.11 or newer is required; say so before building a venv that cannot run it
if [ ! -f ".venv/bin/python" ]; then
  python3 -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>/dev/null || {
    echo "  Python 3.11 or newer is required (found: $(python3 --version 2>&1))." >&2
    exit 1
  }
  echo "  Creating Python virtual environment…"
  python3 -m venv .venv
fi
.venv/bin/python -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>/dev/null || {
  echo "  The virtual environment uses $(.venv/bin/python --version 2>&1); Python 3.11 or newer is required." >&2
  echo "  Delete the .venv folder and run this script again." >&2
  exit 1
}

.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

exec .venv/bin/python main.py "$@"
