"""Minimal async ARM (Azure Resource Manager) REST client.

Uses :class:`azure.identity.aio.DefaultAzureCredential` when available, and
falls back to ``az account get-access-token`` (subprocess) when the SDK
credential cannot acquire a token. This keeps enrichment working for users
who configured the app with a SAS connection string but have the Azure CLI
logged in locally.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any

import aiohttp


_ARM_BASE = "https://management.azure.com"
_ARM_SCOPE = "https://management.azure.com/.default"
_ARM_RESOURCE = "https://management.azure.com"


class ArmError(Exception):
    """ARM call failed with a non-2xx response or transport error."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"ARM {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class _Token:
    value: str
    expires_at: float  # epoch seconds


async def _token_from_az_cli() -> _Token | None:
    """Acquire an ARM token via ``az account get-access-token``.

    Returns ``None`` when the Azure CLI is not installed or not logged in.
    """
    if shutil.which("az") is None:
        return None

    def _run() -> _Token | None:
        try:
            out = subprocess.run(
                ["az", "account", "get-access-token", "--resource", _ARM_RESOURCE, "--output", "json"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if out.returncode != 0 or not out.stdout.strip():
            return None
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            return None
        token = data.get("accessToken")
        if not token:
            return None
        # `expires_on` (epoch) is more reliable than `expiresOn` (local string)
        exp = data.get("expires_on")
        try:
            expires_at = float(exp) if exp is not None else time.time() + 300
        except (TypeError, ValueError):
            expires_at = time.time() + 300
        return _Token(value=token, expires_at=expires_at)

    return await asyncio.to_thread(_run)


class ArmClient:
    """Async ARM REST client with credential fallback to the Azure CLI."""

    def __init__(self, credential: Any | None, session: aiohttp.ClientSession) -> None:
        self._credential = credential
        self._session = session
        self._token: _Token | None = None
        self._lock = asyncio.Lock()

    async def _get_token(self) -> str:
        async with self._lock:
            now = time.time()
            if self._token and self._token.expires_at - 60 > now:
                return self._token.value

            # Try the supplied credential first
            if self._credential is not None:
                try:
                    res = await self._credential.get_token(_ARM_SCOPE)
                    self._token = _Token(value=res.token, expires_at=float(res.expires_on))
                    return self._token.value
                except Exception:
                    pass  # fall through to CLI

            cli_tok = await _token_from_az_cli()
            if cli_tok is None:
                raise ArmError(401, "NoCredential",
                               "No ARM credential available "
                               "(DefaultAzureCredential failed and `az` CLI not logged in).")
            self._token = cli_tok
            return cli_tok.value

    async def _request(self, method: str, url: str, *,
                       params: dict[str, str] | None = None,
                       json_body: dict | None = None) -> dict:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with self._session.request(
                method, url, headers=headers, params=params, json=json_body,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    code, message = _extract_error(text)
                    raise ArmError(resp.status, code, message)
                if not text:
                    return {}
                return json.loads(text)
        except aiohttp.ClientError as exc:
            raise ArmError(0, "Transport", str(exc)) from exc

    async def get(self, resource_id_or_path: str, api_version: str,
                  *, params: dict[str, str] | None = None) -> dict:
        """GET an ARM resource by resource ID (or absolute path starting with '/')."""
        url = self._url(resource_id_or_path)
        merged: dict[str, str] = {"api-version": api_version}
        if params:
            merged.update(params)
        return await self._request("GET", url, params=merged)

    async def get_all(self, resource_id_or_path: str, api_version: str,
                      *, params: dict[str, str] | None = None) -> list[dict]:
        """Paginated GET returning the concatenated ``value`` arrays."""
        first = await self.get(resource_id_or_path, api_version, params=params)
        items: list[dict] = list(first.get("value") or [])
        next_link: str | None = first.get("nextLink")
        while next_link:
            page = await self._request("GET", next_link)
            items.extend(page.get("value") or [])
            next_link = page.get("nextLink")
        return items

    @staticmethod
    def _url(resource_id_or_path: str) -> str:
        if resource_id_or_path.startswith("http://") or resource_id_or_path.startswith("https://"):
            return resource_id_or_path
        if not resource_id_or_path.startswith("/"):
            resource_id_or_path = "/" + resource_id_or_path
        return _ARM_BASE + resource_id_or_path


def _extract_error(body: str) -> tuple[str, str]:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return "Unknown", body[:200]
    err = data.get("error") or data
    code = str(err.get("code") or "Unknown")
    message = str(err.get("message") or body[:200])
    return code, message
