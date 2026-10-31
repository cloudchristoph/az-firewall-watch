#!/usr/bin/env python3
"""Collect raw Azure Firewall log records that contain IPv6 addresses from the two Event Hubs.

Azure Monitor writes one Event Hub event per batch; each event body is a JSON document with a
``records`` array. Every record is written verbatim (``json.dumps`` of the parsed object with
``separators=(",", ":")``, key order preserved) to ``<out>/<structured|legacy>/<category>.jsonl``
when its serialised form contains an IPv6 literal. Nothing is anonymised.

Environment:
  EH_STRUCTURED_CONN   Listen connection string for hub "firewall-logs" (structured AZFW* categories)
  EH_LEGACY_CONN       Listen connection string for hub "firewall-logs-legacy" (namespace root key is fine)

Examples:
  python3 collect_ipv6_samples.py --minutes 120 --out .          # everything from the last 2 h
  python3 collect_ipv6_samples.py --from-latest --duration 900    # live, 15 minutes
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    from azure.eventhub import EventHubConsumerClient
except ImportError:  # pragma: no cover
    sys.exit("pip install azure-eventhub")

# Anything with at least two "::"-style groups; deliberately loose, the filter only decides which
# raw records are kept. Excludes the obvious IPv4-only records cheaply.
IPV6_RE = re.compile(r"(?<![0-9a-zA-Z:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-zA-Z])")

HUBS = {
    "structured": ("EH_STRUCTURED_CONN", "firewall-logs"),
    "legacy": ("EH_LEGACY_CONN", "firewall-logs-legacy"),
}


def _conn(env_name: str) -> str | None:
    value = os.environ.get(env_name)
    return value.strip() if value else None


def _has_ipv6(record: dict) -> bool:
    blob = json.dumps(record, separators=(",", ":"))
    for m in IPV6_RE.finditer(blob):
        token = m.group(0)
        # ignore pure timestamps like 12:34:56 and things without a second colon-group of hex
        if token.count(":") >= 2 and any(c in "abcdefABCDEF" for c in token) or "::" in token:
            return True
    return False


def collect(kind: str, conn: str, hub: str, out: Path, starting: dt.datetime | str,
            duration: float, idle_timeout: float) -> dict[str, int]:
    counts: dict[str, int] = {}
    files: dict[str, object] = {}
    target = out / kind
    target.mkdir(parents=True, exist_ok=True)
    last_event = time.monotonic()
    deadline = time.monotonic() + duration

    def on_event(partition_context, event):
        nonlocal last_event
        if event is None:
            if time.monotonic() - last_event > idle_timeout or time.monotonic() > deadline:
                client.close()
            return
        last_event = time.monotonic()
        try:
            body = json.loads(event.body_as_str(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        for record in body.get("records", []):
            if not isinstance(record, dict) or not _has_ipv6(record):
                continue
            category = str(record.get("category", "unknown"))
            counts[category] = counts.get(category, 0) + 1
            fh = files.get(category)
            if fh is None:
                fh = (target / f"{category}.jsonl").open("a", encoding="utf-8")
                files[category] = fh
            fh.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
            fh.flush()
        if time.monotonic() > deadline:
            client.close()

    client = EventHubConsumerClient.from_connection_string(conn, consumer_group="$Default", eventhub_name=hub)
    print(f"[{kind}] reading {hub} from {starting} for up to {duration:.0f}s ...", flush=True)
    with client:
        client.receive(on_event=on_event, starting_position=starting, max_wait_time=5)
    for fh in files.values():
        fh.close()
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=".", help="output directory (default: current)")
    ap.add_argument("--minutes", type=float, default=60, help="read events enqueued within the last N minutes (default 60)")
    ap.add_argument("--from-latest", action="store_true", help="ignore history, read only new events")
    ap.add_argument("--duration", type=float, default=300, help="max seconds to read per hub (default 300)")
    ap.add_argument("--idle-timeout", type=float, default=30, help="stop a hub after N seconds without events (default 30)")
    ap.add_argument("--only", choices=list(HUBS), help="read only this hub")
    args = ap.parse_args()

    out = Path(args.out)
    starting: dt.datetime | str = "@latest" if args.from_latest else (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=args.minutes))

    total: dict[str, dict[str, int]] = {}
    for kind, (env_name, hub) in HUBS.items():
        if args.only and args.only != kind:
            continue
        conn = _conn(env_name)
        if not conn:
            print(f"[{kind}] {env_name} not set — skipping {hub}", file=sys.stderr)
            continue
        total[kind] = collect(kind, conn, hub, out, starting, args.duration, args.idle_timeout)

    print("\nIPv6 records written:")
    for kind, counts in total.items():
        if not counts:
            print(f"  {kind}: none")
        for category, n in sorted(counts.items()):
            print(f"  {kind}/{category}.jsonl: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
