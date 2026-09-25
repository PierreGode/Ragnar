"""Shared entity base — ties every entity to one Ragnar device."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import RagnarCoordinator


class RagnarEntity(CoordinatorEntity[RagnarCoordinator]):
    """Base class registering all entities under the same Ragnar hub device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: RagnarCoordinator, entry_id: str) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry_id)},
            name="Ragnar",
            manufacturer="Ragnar",
            model="Ragnar Security Node",
            configuration_url=coordinator.client._base,  # noqa: SLF001
        )
