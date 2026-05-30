#!/usr/bin/env bash
# start.sh  —  run az-firewall-watch from source (Linux / macOS)
#
# Usage:
#   ./start.sh               normal start (setup wizard runs if .env is missing)
#   ./start.sh --reconfigure redo the Event Hub setup
set -e
cd "$(dirname "$0")"

# Create / update the virtual environment if needed
if [ ! -f ".venv/bin/python" ]; then
  echo "  Creating Python virtual environment…"
  python3 -m venv .venv
fi

.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

exec .venv/bin/python main.py "$@"
