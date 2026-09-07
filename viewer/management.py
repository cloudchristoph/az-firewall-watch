"""Orchestrates management-plane fetch: cache lookup, ARM fetch, cache write.

Kept separate from :mod:`viewer.app` so the worker logic is testable and the
app stays focused on UI.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import aiohttp

from .arm import ArmClient, ArmError
from .azure_resources import (
    collect_ip_group_ids,
    fetch_all_subnet_cidrs,
    fetch_diagnostic_settings,
    fetch_firewall,
    fetch_ip_groups,
    fetch_public_ips,
)
from .azure_resources import (
    fetch_policy_chain as fetch_policy,  # policy plus inherited parent chain
)
from .cache import CachedSnapshot, invalidate, load, save


async def load_management_data(firewall_id: str, *, force: bool = False) -> CachedSnapshot | None:
    """Return a cached or freshly-fetched snapshot for ``firewall_id``.

    Returns ``None`` if no credential is available or ARM is unreachable.
    On cache hit (and not ``force``), returns immediately without ARM calls.
    """
    if not force:
        cached = load(firewall_id)
        if cached is not None and cached.is_fresh():
            return cached

    if force:
        invalidate(firewall_id)

    # Try to acquire a credential; fall through to None (ArmClient handles
    # `az` CLI fallback transparently).
    credential: Any | None = None
    try:
        from azure.core.pipeline.transport import AsyncioRequestsTransport
        from azure.identity.aio import DefaultAzureCredential
        credential = DefaultAzureCredential(transport=AsyncioRequestsTransport())
    except Exception:
        credential = None

    try:
        async with aiohttp.ClientSession() as session:
            arm = ArmClient(credential, session)
            try:
                firewall = await fetch_firewall(arm, firewall_id)
            except ArmError:
                return None

            subnet_task = asyncio.create_task(
                fetch_all_subnet_cidrs(arm, firewall.subnet_ids)
            )
            pip_ids = [c.public_ip_id for c in firewall.ip_configs if c.public_ip_id]
            if firewall.management_ip and firewall.management_ip.public_ip_id:
                pip_ids.append(firewall.management_ip.public_ip_id)
            pip_task = asyncio.create_task(fetch_public_ips(arm, pip_ids))
            diag_task = asyncio.create_task(fetch_diagnostic_settings(arm, firewall_id))
            policy = None
            if firewall.policy_id:
                try:
                    policy = await fetch_policy(arm, firewall.policy_id)
                except ArmError:
                    policy = None

            subnet_cidrs = await subnet_task
            try:
                addresses = await pip_task
            except ArmError:
                addresses = {}
            for cfg in firewall.ip_configs + ([firewall.management_ip] if firewall.management_ip else []):
                cfg.public_ip_address = addresses.get(cfg.public_ip_id, "")
            try:
                diagnostics = await diag_task
            except ArmError:
                diagnostics = []

            ip_groups: dict = {}
            if policy is not None:
                gids = collect_ip_group_ids(policy)
                try:
                    ip_groups = await fetch_ip_groups(arm, gids)
                except ArmError:
                    ip_groups = {}

            snap = CachedSnapshot(
                firewall=firewall,
                policy=policy,
                ip_groups=ip_groups,
                subnet_cidrs=subnet_cidrs,
                fetched_at=time.time(),
                diagnostics=diagnostics,
            )
            try:
                save(firewall_id, snap)
            except OSError:
                pass
            return snap
    finally:
        if credential is not None:
            try:
                await credential.close()
            except Exception:
                pass
