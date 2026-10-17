"""Shared, in-memory token reuse for the viewer's asynchronous Azure clients."""
from __future__ import annotations

import asyncio
import time
from typing import Any


class CachedCredential:
    """Reuse tokens for identical requests, refreshing before expiry."""

    def __init__(self, credential: Any) -> None:
        self._credential = credential
        self._tokens: dict[tuple, Any] = {}
        self._pending: dict[tuple, asyncio.Task] = {}
        # Callers still waiting on each shared acquisition.
        self._waiters: dict[asyncio.Task, int] = {}
        self._closed = False
        self._close_task: asyncio.Task | None = None

    async def __aenter__(self) -> CachedCredential:
        if self._closed:
            raise RuntimeError("Credential is closed")
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def get_token(self, *scopes: str, **kwargs: Any) -> Any:
        if self._closed:
            raise RuntimeError("Credential is closed")
        # Include every option, even ones introduced by future SDK versions.
        # Unknown unhashable options cannot safely form a cache key.
        key: tuple = (scopes, tuple(sorted((name, type(value), value) for name, value in kwargs.items())))
        cacheable = True
        try:
            hash(key)
        except TypeError:
            key = (object(),)
            cacheable = False
        token = self._tokens.get(key)
        if token is not None and token.expires_on > time.time() + 60:
            return token
        self._tokens.pop(key, None)
        task = self._pending.get(key)
        if task is None:
            task = asyncio.create_task(self._acquire(key, scopes, kwargs, cacheable))
            self._pending[key] = task
            # Retrieve failures even if every waiting caller was cancelled.
            task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        self._waiters[task] = self._waiters.get(task, 0) + 1
        try:
            return await asyncio.shield(task)
        finally:
            remaining = self._waiters.pop(task) - 1
            if remaining:
                self._waiters[task] = remaining
            elif not task.done():
                # Every caller gave up (revoked ARM access, cancelled worker):
                # stop the acquisition instead of finishing and caching it.
                # A later caller starts a fresh one rather than joining this.
                if self._pending.get(key) is task:
                    del self._pending[key]
                task.cancel()

    async def _acquire(self, key: tuple, scopes: tuple[str, ...], kwargs: dict[str, Any], cacheable: bool) -> Any:
        try:
            token = await self._credential.get_token(*scopes, **kwargs)
            if cacheable and not self._closed and token.expires_on > time.time() + 60:
                self._tokens[key] = token
            return token
        finally:
            if self._pending.get(key) is asyncio.current_task():
                del self._pending[key]

    async def close(self) -> None:
        """Stop pending acquisitions and close the underlying credential once."""
        if self._close_task is None:
            self._closed = True
            self._close_task = asyncio.create_task(self._close())
            self._close_task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._close_task)

    async def _close(self) -> None:
        self._tokens.clear()
        pending = list(self._pending.values())
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await self._credential.close()


def create_credential() -> CachedCredential:
    """Build the full Azure credential chain only when Entra access is needed."""
    from azure.core.pipeline.transport import AsyncioRequestsTransport
    from azure.identity.aio import DefaultAzureCredential

    return CachedCredential(DefaultAzureCredential(transport=AsyncioRequestsTransport()))
