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
    fetch_diagnostic_settings,
    fetch_firewall,
    fetch_ip_groups,
    fetch_maintenance,
    fetch_nat_gateways,
    fetch_public_ips,
    fetch_subnets,
    subnet_cidrs,
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

            subnet_task = asyncio.create_task(fetch_subnets(arm, firewall.subnet_ids))
            pip_ids = [c.public_ip_id for c in firewall.ip_configs if c.public_ip_id]
            if firewall.management_ip and firewall.management_ip.public_ip_id:
                pip_ids.append(firewall.management_ip.public_ip_id)
            pip_task = asyncio.create_task(fetch_public_ips(arm, pip_ids))
            diag_task = asyncio.create_task(fetch_diagnostic_settings(arm, firewall_id))
            maint_task = asyncio.create_task(fetch_maintenance(arm, firewall_id))
            policy = None
            if firewall.policy_id:
                try:
                    policy = await fetch_policy(arm, firewall.policy_id)
                except ArmError:
                    policy = None

            subnets = await subnet_task
            # A NAT gateway on a firewall subnet changes which public address
            # outbound traffic leaves with; its public IPs are resolved like
            # the firewall's own (one optional GET each).
            nat_gateways = await fetch_nat_gateways(arm, subnets)
            nat_pip_ids = [pid for gw in nat_gateways for pid in gw.public_ip_ids]
            try:
                addresses = await pip_task
                if nat_pip_ids:
                    addresses.update(await fetch_public_ips(arm, nat_pip_ids))
            except ArmError:
                addresses = {}
            for cfg in firewall.ip_configs + ([firewall.management_ip] if firewall.management_ip else []):
                cfg.public_ip_address = addresses.get(cfg.public_ip_id, "")
            for gw in nat_gateways:
                # One entry per public IP, in id order; an unreadable one stays ""
                # so the view can name it as unresolved instead of the list
                # silently looking complete with the readable ones only.
                gw.public_ip_addresses = [addresses.get(pid, "") for pid in gw.public_ip_ids]
            try:
                diagnostics = await diag_task
            except ArmError:
                diagnostics = []
            try:
                maintenance = await maint_task
            except ArmError:
                maintenance = []

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
                subnet_cidrs=subnet_cidrs(subnets),
                fetched_at=time.time(),
                diagnostics=diagnostics,
                subnets=subnets,
                nat_gateways=nat_gateways,
                maintenance=maintenance,
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
