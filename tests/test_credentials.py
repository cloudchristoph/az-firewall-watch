"""Token reuse and cancellation without network access or Azure accounts."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

import viewer.credentials as credentials
from viewer.credentials import CachedCredential


class FakeCredential:
    def __init__(self):
        self.calls = []
        self.closed = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()
        self.failure = None

    async def get_token(self, *scopes, **kwargs):
        self.calls.append((scopes, kwargs))
        self.started.set()
        await self.release.wait()
        if self.failure:
            raise self.failure
        return SimpleNamespace(token=f"token-{len(self.calls)}", expires_on=1000)

    async def close(self):
        self.closed += 1


@pytest.fixture
def credential(monkeypatch):
    monkeypatch.setattr(credentials.time, "time", lambda: 100)
    return FakeCredential()


async def test_reuses_token_and_renews_at_expiry_margin(credential, monkeypatch):
    cached = CachedCredential(credential)
    first = await cached.get_token("scope")
    assert await cached.get_token("scope") is first
    monkeypatch.setattr(credentials.time, "time", lambda: 940)
    renewed = await cached.get_token("scope")
    assert renewed is not first
    assert len(credential.calls) == 2
    # A token already within the refresh margin is never cached.
    assert await cached.get_token("scope") is not renewed
    await cached.close()


@pytest.mark.parametrize("option", ["claims", "tenant_id", "enable_cae", "future_option"])
async def test_cache_isolates_every_request_option(credential, option):
    cached = CachedCredential(credential)
    first = await cached.get_token("scope", **{option: "a"})
    second = await cached.get_token("scope", **{option: "b"})
    assert first is not second
    assert await cached.get_token("scope", **{option: "a"}) is first
    assert credential.calls == [(("scope",), {option: "a"}), (("scope",), {option: "b"})]
    await cached.close()


async def test_scopes_and_option_order(credential):
    cached = CachedCredential(credential)
    first = await cached.get_token("arm", tenant_id="tenant", claims="claims")
    assert await cached.get_token("arm", claims="claims", tenant_id="tenant") is first
    assert await cached.get_token("eventhub", tenant_id="tenant", claims="claims") is not first
    assert await cached.get_token("arm", "extra", tenant_id="tenant", claims="claims") is not first
    await cached.close()


async def test_concurrent_requests_share_acquisition(credential):
    credential.release.clear()
    cached = CachedCredential(credential)
    first = asyncio.create_task(cached.get_token("scope"))
    await credential.started.wait()
    second = asyncio.create_task(cached.get_token("scope"))
    await asyncio.sleep(0)
    assert len(credential.calls) == 1
    credential.release.set()
    assert await first is await second
    await cached.close()


async def test_failure_is_shared_but_not_cached(credential):
    credential.release.clear()
    credential.failure = ValueError("authentication failed")
    cached = CachedCredential(credential)
    first = asyncio.create_task(cached.get_token("scope"))
    await credential.started.wait()
    second = asyncio.create_task(cached.get_token("scope"))
    await asyncio.sleep(0)
    credential.release.set()
    results = await asyncio.gather(first, second, return_exceptions=True)
    assert all(isinstance(result, ValueError) for result in results)
    assert len(credential.calls) == 1
    credential.failure = None
    assert (await cached.get_token("scope")).token == "token-2"
    await cached.close()


async def test_cancelled_waiter_does_not_cancel_shared_acquisition(credential):
    credential.release.clear()
    cached = CachedCredential(credential)
    first = asyncio.create_task(cached.get_token("scope"))
    await credential.started.wait()
    second = asyncio.create_task(cached.get_token("scope"))
    await asyncio.sleep(0)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    credential.release.set()
    token = await second
    assert await cached.get_token("scope") is token
    assert len(credential.calls) == 1
    await cached.close()


async def test_last_cancelled_waiter_stops_acquisition(credential):
    credential.release.clear()
    cached = CachedCredential(credential)
    request = asyncio.create_task(cached.get_token("scope"))
    await credential.started.wait()
    acquisition = cached._pending[(("scope",), ())]
    request.cancel()
    # A caller arriving in the same turn must not join the abandoned acquisition.
    fresh = asyncio.create_task(cached.get_token("scope"))
    with pytest.raises(asyncio.CancelledError):
        await request
    await asyncio.gather(acquisition, return_exceptions=True)
    assert acquisition.cancelled()
    credential.release.set()
    assert (await fresh).token == "token-2"
    assert len(credential.calls) == 2
    assert cached._waiters == {}
    await cached.close()


async def test_close_waits_for_an_abandoned_acquisition_to_unwind():
    """A cancelled acquisition that is still unwinding must finish before the
    underlying credential is closed."""
    events: list[str] = []
    started = asyncio.Event()

    class SlowUnwind:
        async def get_token(self, *scopes, **kwargs):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)  # cleanup that takes a moment
                events.append("unwound")
                raise

        async def close(self):
            events.append("closed")

    cached = CachedCredential(SlowUnwind())
    request = asyncio.create_task(cached.get_token("scope"))
    await started.wait()
    request.cancel()  # the only waiter gives up: the acquisition is cancelled
    with pytest.raises(asyncio.CancelledError):
        await request
    assert cached._pending == {}
    await cached.close()
    assert events == ["unwound", "closed"]
    assert cached._abandoned == set()


async def test_close_cancels_acquisition_and_is_idempotent(credential):
    credential.release.clear()
    cached = CachedCredential(credential)
    request = asyncio.create_task(cached.get_token("scope"))
    await credential.started.wait()
    await asyncio.gather(cached.close(), cached.close())
    with pytest.raises(asyncio.CancelledError):
        await request
    assert credential.closed == 1
    with pytest.raises(RuntimeError, match="closed"):
        await cached.get_token("scope")


async def test_unhashable_options_are_forwarded_without_caching(credential):
    cached = CachedCredential(credential)
    options = {"future_option": ["value"]}
    first = await cached.get_token("scope", **options)
    assert await cached.get_token("scope", **options) is not first
    assert credential.calls == [(("scope",), options), (("scope",), options)]
    await cached.close()


async def test_context_manager_closes_credential(credential):
    async with CachedCredential(credential) as cached:
        assert (await cached.get_token("scope")).token == "token-1"
    assert credential.closed == 1


async def test_cancelled_close_waiter_does_not_interrupt_cleanup(credential, monkeypatch):
    closing = asyncio.Event()
    release = asyncio.Event()

    async def close():
        closing.set()
        await release.wait()
        credential.closed += 1

    monkeypatch.setattr(credential, "close", close)
    cached = CachedCredential(credential)
    task = asyncio.create_task(cached.close())
    await closing.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await cached.close()
    assert credential.closed == 1


async def test_factory_wraps_full_default_chain_with_requests_transport(monkeypatch):
    import azure.core.pipeline.transport as transport
    import azure.identity.aio as identity

    sentinel = object()
    underlying = FakeCredential()
    monkeypatch.setattr(transport, "AsyncioRequestsTransport", lambda: sentinel)

    def build(**kwargs):
        assert kwargs == {"transport": sentinel}
        return underlying

    monkeypatch.setattr(identity, "DefaultAzureCredential", build)
    cached = credentials.create_credential()
    assert isinstance(cached, CachedCredential)
    await cached.close()
    assert underlying.closed == 1
