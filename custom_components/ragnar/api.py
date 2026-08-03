"""Thin async HTTP client for a Ragnar unit.

Ragnar authenticates with a Flask *session cookie*, not an API token, so this
client keeps its own aiohttp cookie jar: it logs in once (only if the unit has
auth configured) and reuses the cookie for every poll, re-logging in on a 401.
Every endpoint used here is a read-only GET; the only write is the login POST.
"""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
from aiohttp import ClientError, ClientTimeout

from .const import (
    API_AUTH_LOGIN,
    API_AUTH_STATUS,
    API_INCIDENTS,
    API_RUSENSE_PRESENCE,
    API_RUSENSE_VITALS,
    API_SENSING_STATUS,
    API_STATUS,
    API_WATCHTOWER,
)

_LOGGER = logging.getLogger(__name__)

_TIMEOUT = ClientTimeout(total=15)


class RagnarAuthError(Exception):
    """Raised when login credentials are rejected."""


class RagnarConnectionError(Exception):
    """Raised when the unit is unreachable or returns a bad response."""


class RagnarApiClient:
    """Talk to one Ragnar unit's web API."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        use_ssl: bool,
        verify_ssl: bool,
    ) -> None:
        scheme = "https" if use_ssl else "http"
        self._base = f"{scheme}://{host}:{port}"
        self._username = username or ""
        self._password = password or ""
        self._verify_ssl = verify_ssl
        # Private cookie jar so we don't leak/inherit cookies from other
        # integrations sharing HA's default session.
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True), timeout=_TIMEOUT
        )
        self._auth_required: bool | None = None

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        await self._session.close()

    async def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    async def async_auth_required(self) -> bool:
        """Return True if this unit has authentication configured."""
        if self._auth_required is not None:
            return self._auth_required
        data = await self._get_json(API_AUTH_STATUS, _retry_login=False)
        # get_auth_status returns {"configured": bool, "authenticated": bool, ...}
        self._auth_required = bool(data.get("configured", False))
        return self._auth_required

    async def async_login(self) -> None:
        """POST credentials and store the session cookie."""
        if not await self.async_auth_required():
            return  # open unit, nothing to do
        try:
            resp = await self._session.post(
                await self._url(API_AUTH_LOGIN),
                json={"username": self._username, "password": self._password},
                ssl=self._verify_ssl,
            )
        except ClientError as err:
            raise RagnarConnectionError(str(err)) from err
        if resp.status in (401, 403):
            raise RagnarAuthError("Invalid username or password")
        if resp.status >= 400:
            raise RagnarConnectionError(f"Login failed: HTTP {resp.status}")
        body = await resp.json(content_type=None)
        if not body.get("success"):
            raise RagnarAuthError(body.get("error", "Login rejected"))

    async def _get_json(
        self, path: str, _retry_login: bool = True
    ) -> dict[str, Any]:
        try:
            resp = await self._session.get(
                await self._url(path), ssl=self._verify_ssl
            )
        except ClientError as err:
            raise RagnarConnectionError(str(err)) from err
        if resp.status == 401 and _retry_login:
            # Cookie expired or never set — log in once and retry.
            await self.async_login()
            return await self._get_json(path, _retry_login=False)
        if resp.status == 401:
            raise RagnarAuthError("Unauthorized")
        if resp.status >= 400:
            raise RagnarConnectionError(f"HTTP {resp.status} for {path}")
        return await resp.json(content_type=None)

    # -- Feature reads ---------------------------------------------------

    async def async_presence(self) -> dict[str, Any]:
        return await self._get_json(API_RUSENSE_PRESENCE)

    async def async_vitals(self) -> dict[str, Any]:
        return await self._get_json(API_RUSENSE_VITALS)

    async def async_sensing_status(self) -> dict[str, Any]:
        return await self._get_json(API_SENSING_STATUS)

    async def async_watchtower(self) -> dict[str, Any]:
        return await self._get_json(API_WATCHTOWER)

    async def async_incidents(self) -> dict[str, Any]:
        return await self._get_json(API_INCIDENTS)

    async def async_status(self) -> dict[str, Any]:
        return await self._get_json(API_STATUS)
