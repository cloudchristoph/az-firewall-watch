"""Minimal ARM client (viewer/arm.py) with a fake aiohttp session."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

import aiohttp
import pytest

import viewer.arm as arm_mod
from viewer.arm import ArmClient, ArmError, _extract_error, _token_from_az_cli


class FakeResponse:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False


class FakeSession:
    """Routes: url (without query) → (status, body) or an exception to raise."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kw: Any):
        self.calls.append({"method": method, "url": url, **kw})
        target = self.routes.get(url)
        if isinstance(target, Exception):
            raise target
        if target is None:
            return FakeResponse(404, json.dumps({"error": {"code": "NotFound", "message": f"no route {url}"}}))
        status, body = target
        return FakeResponse(status, body if isinstance(body, str) else json.dumps(body))


class FakeCredential:
    def __init__(self, token: str = "tok", ttl: float = 3600, fail: bool = False) -> None:
        self.token, self.ttl, self.fail = token, ttl, fail
        self.calls = 0

    async def get_token(self, *_scopes: str):
        self.calls += 1
        if self.fail:
            raise RuntimeError("no identity")

        class _T:
            token = self.token
            expires_on = time.time() + self.ttl
        return _T()


ARM = "https://management.azure.com"
FW = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw"


# ── URL building / errors ────────────────────────────────────────────────────

def test_url_forms():
    assert ArmClient._url(FW) == ARM + FW
    assert ArmClient._url(FW.lstrip("/")) == ARM + FW
    assert ArmClient._url("https://management.azure.com/next?x=1") == "https://management.azure.com/next?x=1"


def test_extract_error_variants():
    assert _extract_error(json.dumps({"error": {"code": "AuthorizationFailed", "message": "nope"}})) == ("AuthorizationFailed", "nope")
    assert _extract_error(json.dumps({"code": "X", "message": "flat"})) == ("X", "flat")
    assert _extract_error("<html>gateway</html>") == ("Unknown", "<html>gateway</html>")
    # valid JSON that is not dict-shaped (gateways, proxies) must not raise
    assert _extract_error("[]") == ("Unknown", "[]")
    assert _extract_error("42") == ("Unknown", "42")
    assert _extract_error(json.dumps({"error": "string, not an object"})) == ("Unknown", '{"error": "string, not an object"}')
    assert _extract_error(json.dumps({})) == ("Unknown", "{}")


def test_arm_error_str():
    err = ArmError(403, "AuthorizationFailed", "denied")
    assert str(err) == "ARM 403 AuthorizationFailed: denied"
    assert (err.status, err.code, err.message) == (403, "AuthorizationFailed", "denied")


# ── GET / pagination ─────────────────────────────────────────────────────────

async def test_get_sends_bearer_and_api_version():
    session = FakeSession({ARM + FW: (200, {"name": "fw"})})
    cred = FakeCredential()
    client = ArmClient(cred, session)
    assert await client.get(FW, "2024-01-01", params={"$expand": "x"}) == {"name": "fw"}
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["headers"]["Authorization"] == "Bearer tok"
    assert call["params"] == {"api-version": "2024-01-01", "$expand": "x"}


async def test_get_all_follows_next_link():
    session = FakeSession({
        ARM + "/list": (200, {"value": [1, 2], "nextLink": ARM + "/list?page=2"}),
        ARM + "/list?page=2": (200, {"value": [3]}),
    })
    client = ArmClient(FakeCredential(), session)
    assert await client.get_all("/list", "2024-01-01") == [1, 2, 3]
    assert session.calls[1]["url"] == ARM + "/list?page=2"
    assert session.calls[1]["params"] is None  # next links carry their own query string


async def test_get_all_without_value():
    client = ArmClient(FakeCredential(), FakeSession({ARM + "/x": (200, {})}))
    assert await client.get_all("/x", "v") == []


async def test_empty_body_is_empty_dict():
    client = ArmClient(FakeCredential(), FakeSession({ARM + "/x": (204, "")}))
    assert await client.get("/x", "v") == {}


async def test_http_error_raises_arm_error():
    session = FakeSession({ARM + FW: (403, {"error": {"code": "AuthorizationFailed", "message": "denied"}})})
    with pytest.raises(ArmError) as exc:
        await ArmClient(FakeCredential(), session).get(FW, "v")
    assert exc.value.status == 403 and exc.value.code == "AuthorizationFailed"


async def test_non_json_success_body_raises_arm_error():
    """A gateway may answer 200 with HTML; that must not leak a JSONDecodeError."""
    session = FakeSession({ARM + FW: (200, "<html>maintenance</html>")})
    with pytest.raises(ArmError) as exc:
        await ArmClient(FakeCredential(), session).get(FW, "v")
    assert exc.value.status == 200 and exc.value.code == "InvalidResponse"
    assert "maintenance" in exc.value.message


async def test_transport_error_raises_arm_error():
    session = FakeSession({ARM + FW: aiohttp.ClientConnectionError("dns")})
    with pytest.raises(ArmError) as exc:
        await ArmClient(FakeCredential(), session).get(FW, "v")
    assert exc.value.status == 0 and exc.value.code == "Transport"


# ── tokens ───────────────────────────────────────────────────────────────────

async def test_token_is_cached_until_close_to_expiry():
    session = FakeSession({ARM + "/x": (200, {})})
    cred = FakeCredential(ttl=3600)
    client = ArmClient(cred, session)
    await client.get("/x", "v")
    await client.get("/x", "v")
    assert cred.calls == 1


async def test_token_refreshes_within_60s_of_expiry():
    session = FakeSession({ARM + "/x": (200, {})})
    cred = FakeCredential(ttl=30)
    client = ArmClient(cred, session)
    await client.get("/x", "v")
    await client.get("/x", "v")
    assert cred.calls == 2


async def test_falls_back_to_az_cli_when_credential_fails(monkeypatch):
    monkeypatch.setattr(arm_mod, "_token_from_az_cli", _fake_cli_token("cli-tok"))
    session = FakeSession({ARM + "/x": (200, {})})
    client = ArmClient(FakeCredential(fail=True), session)
    await client.get("/x", "v")
    assert session.calls[0]["headers"]["Authorization"] == "Bearer cli-tok"


async def test_no_credential_at_all_raises(monkeypatch):
    async def _none():
        return None

    monkeypatch.setattr(arm_mod, "_token_from_az_cli", _none)
    client = ArmClient(None, FakeSession({}))
    with pytest.raises(ArmError) as exc:
        await client.get("/x", "v")
    assert exc.value.status == 401 and exc.value.code == "NoCredential"


def _fake_cli_token(value: str):
    async def _tok():
        return arm_mod._Token(value=value, expires_at=time.time() + 600)
    return _tok


# ── az CLI token acquisition ─────────────────────────────────────────────────

async def test_cli_token_without_az_installed(monkeypatch):
    monkeypatch.setattr(arm_mod.shutil, "which", lambda _n: None)
    assert await _token_from_az_cli() is None


async def test_cli_token_parses_output(monkeypatch):
    monkeypatch.setattr(arm_mod.shutil, "which", lambda _n: "/usr/bin/az")
    monkeypatch.setattr(arm_mod.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 0, stdout=json.dumps({"accessToken": "abc", "expires_on": 1_900_000_000}), stderr=""))
    tok = await _token_from_az_cli()
    assert tok is not None and tok.value == "abc" and tok.expires_at == 1_900_000_000


@pytest.mark.parametrize(
    "result",
    [
        subprocess.CompletedProcess(["az"], 1, stdout="", stderr="not logged in"),
        subprocess.CompletedProcess(["az"], 0, stdout="not json", stderr=""),
        subprocess.CompletedProcess(["az"], 0, stdout=json.dumps({"accessToken": ""}), stderr=""),
    ],
)
async def test_cli_token_failure_modes(monkeypatch, result):
    monkeypatch.setattr(arm_mod.shutil, "which", lambda _n: "/usr/bin/az")
    monkeypatch.setattr(arm_mod.subprocess, "run", lambda *a, **k: result)
    assert await _token_from_az_cli() is None


async def test_cli_token_timeout(monkeypatch):
    monkeypatch.setattr(arm_mod.shutil, "which", lambda _n: "/usr/bin/az")

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(a[0], 15)

    monkeypatch.setattr(arm_mod.subprocess, "run", _boom)
    assert await _token_from_az_cli() is None


async def test_cli_token_without_expiry_defaults_to_five_minutes(monkeypatch):
    monkeypatch.setattr(arm_mod.shutil, "which", lambda _n: "/usr/bin/az")
    monkeypatch.setattr(arm_mod.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 0, stdout=json.dumps({"accessToken": "abc"}), stderr=""))
    tok = await _token_from_az_cli()
    assert tok is not None and 250 < tok.expires_at - time.time() <= 300
