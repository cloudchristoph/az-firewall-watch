#!/usr/bin/env python3
"""Summarise the captured IPv6 samples: record counts per category and, for the legacy
categories, the exact endpoint spelling inside ``properties.msg`` (bracketed or not).

  python3 summarize_samples.py [samples-dir]
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
BRACKET = re.compile(r"\[[0-9a-fA-F:]+\]:\d+")
BARE = re.compile(r"(?<![\[0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}:\d{1,5}(?![0-9a-fA-F:])")

for kind in ("structured", "legacy"):
    d = root / kind
    if not d.is_dir():
        continue
    print(f"\n== {kind}")
    for f in sorted(d.glob("*.jsonl")):
        records = [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
        print(f"{f.name}: {len(records)} records")
        if kind == "structured":
            actions = Counter((r.get("properties", {}).get("Action"), r.get("properties", {}).get("Rule")) for r in records)
            for (action, rule), n in actions.most_common(8):
                if action:
                    print(f"    {n:4d}  Action={action} Rule={rule}")
            qt = Counter(r.get("properties", {}).get("QueryType") for r in records if r.get("properties", {}).get("QueryType"))
            if qt:
                print(f"    QueryType: {dict(qt)}")
        else:
            msgs = [r.get("properties", {}).get("msg", "") for r in records]
            bracketed = sum(1 for m in msgs if BRACKET.search(m))
            bare = sum(1 for m in msgs if BARE.search(m))
            print(f"    endpoints written as [addr]:port -> {bracketed}, as addr:port -> {bare}")
            for m in msgs[:3]:
                print(f"    e.g. {m[:200]}")
