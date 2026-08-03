"""DataUpdateCoordinator: one poll cycle fans out to the Ragnar endpoints."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import RagnarApiClient, RagnarAuthError, RagnarConnectionError
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class RagnarCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Poll a Ragnar unit and expose a merged data dict to all entities."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: RagnarApiClient,
        scan_interval: int,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.client = client

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            # Fan out; a single slow/failed feature shouldn't drop the rest.
            presence, vitals, sensing, watchtower, incidents, status = (
                await asyncio.gather(
                    self.client.async_presence(),
                    self.client.async_vitals(),
                    self.client.async_sensing_status(),
                    self.client.async_watchtower(),
                    self.client.async_incidents(),
                    self.client.async_status(),
                    return_exceptions=True,
                )
            )
        except RagnarAuthError as err:
            raise UpdateFailed(f"Authentication failed: {err}") from err
        except RagnarConnectionError as err:
            raise UpdateFailed(f"Cannot reach Ragnar: {err}") from err

        def ok(result: Any) -> dict[str, Any]:
            return result if isinstance(result, dict) else {}

        return {
            "presence": ok(presence),
            "vitals": ok(vitals),
            "sensing": ok(sensing),
            "watchtower": ok(watchtower),
            "incidents": ok(incidents),
            "status": ok(status),
        }
