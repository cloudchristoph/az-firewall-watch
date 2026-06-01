"""Standalone smoke test for viewer.arm / azure_resources / cache / enrichment.

Resolves the firewall named 'fw-hub-gwc' in the 'cclab-connectivity'
subscription, fetches its policy + IP groups, and prints a summary.
Uses DefaultAzureCredential with az-CLI fallback.

Run from repo root:  .venv/bin/python _arm_sample.py
"""
from __future__ import annotations

import asyncio
import sys
from pprint import pprint

import aiohttp

from viewer.arm import ArmClient
from viewer.azure_resources import (
    collect_ip_group_ids,
    fetch_all_subnet_cidrs,
    fetch_firewall,
    fetch_ip_groups,
    fetch_policy,
)
from viewer.cache import CachedSnapshot, cache_path, invalidate, load, save
from viewer.enrichment import find_matching_ip_groups, resolve_fw_instance


SUB = "25ca1d83-3de5-46c7-9941-fb98c2ea026e"
FW = "fw-hub-gwc"
TEST_IP = "10.0.0.4"   # likely inside firewall subnet
PROBE_IP = "10.2.0.6"  # probably matches an IP group


async def _resolve_firewall_id() -> str:
    import shutil, subprocess, json
    if shutil.which("az") is None:
        raise SystemExit("az CLI not available")
    out = subprocess.run(
        ["az", "network", "firewall", "show",
         "--subscription", SUB, "--resource-group", "rg-hub-gwc",
         "--name", FW, "--query", "id", "-o", "tsv"],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        # fall back to discovery via list
        out = subprocess.run(
            ["az", "graph", "query", "--subscriptions", SUB, "-q",
             f"Resources | where type =~ 'microsoft.network/azurefirewalls' and name =~ '{FW}' | project id"],
            capture_output=True, text=True, check=False,
        )
        if out.returncode != 0:
            raise SystemExit(f"failed to resolve firewall: {out.stderr}")
        data = json.loads(out.stdout)
        rows = data.get("data") or []
        if not rows:
            raise SystemExit("firewall not found")
        return rows[0]["id"]
    return out.stdout.strip()


async def main() -> None:
    try:
        from azure.identity.aio import DefaultAzureCredential
        cred = DefaultAzureCredential()
    except Exception:
        cred = None

    fw_id = await _resolve_firewall_id()
    print(f"Firewall ID: {fw_id}")

    invalidate(fw_id)

    async with aiohttp.ClientSession() as session:
        arm = ArmClient(cred, session)
        print("\n-- fetch_firewall --")
        fw = await fetch_firewall(arm, fw_id)
        pprint(fw)

        print("\n-- fetch_all_subnet_cidrs --")
        cidrs = await fetch_all_subnet_cidrs(arm, fw.subnet_ids)
        print(cidrs)

        policy = None
        ip_groups = {}
        if fw.policy_id:
            print(f"\n-- fetch_policy ({fw.policy_id.split('/')[-1]}) --")
            policy = await fetch_policy(arm, fw.policy_id)
            print(f"  sku_tier={policy.sku_tier!r}")
            print(f"  threat_intel_mode={policy.threat_intel_mode!r}")
            print(f"  RCG count={len(policy.rule_collection_groups)}")
            for g in policy.rule_collection_groups[:3]:
                print(f"    [{g.priority}] {g.name}  ({len(g.rule_collections)} collections)")

            ip_group_ids = collect_ip_group_ids(policy)
            print(f"\n-- fetch_ip_groups (n={len(ip_group_ids)}) --")
            ip_groups = await fetch_ip_groups(arm, ip_group_ids)
            for gid, grp in list(ip_groups.items())[:5]:
                print(f"  {grp.name}: {len(grp.ip_addresses)} entries")

    if cred is not None:
        await cred.close()

    snap = CachedSnapshot(firewall=fw, policy=policy, ip_groups=ip_groups,
                          subnet_cidrs=cidrs, fetched_at=__import__("time").time())
    save(fw_id, snap)
    print(f"\nCache written to: {cache_path()}")
    loaded = load(fw_id)
    assert loaded is not None
    assert loaded.firewall.name == fw.name
    print(f"Cache round-trip OK; age={loaded.age_seconds():.2f}s; fresh={loaded.is_fresh()}")

    print("\n-- enrichment --")
    print(f"resolve_fw_instance({TEST_IP!r}) = {resolve_fw_instance(TEST_IP, cidrs)!r}")
    print(f"find_matching_ip_groups({PROBE_IP!r}) = {find_matching_ip_groups(PROBE_IP, ip_groups)!r}")


if __name__ == "__main__":
    asyncio.run(main())
