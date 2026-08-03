"""Sensors: people count, heart rate, breathing rate, alert/incident counts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import RagnarConfigEntry
from .entity import RagnarEntity


def _latest_vital(data: dict[str, Any], key: str) -> float | None:
    """Newest vitals bucket that carries `key` (hr/br); None if none do."""
    buckets = (data.get("vitals") or {}).get("buckets") or []
    for bucket in reversed(buckets):
        if bucket.get(key) is not None:
            return bucket[key]
    return None


def _mesh_reachable(data: dict[str, Any]) -> int | None:
    """Reachable Ragnar-node count, or None when the mesh is off/unavailable."""
    mesh = data.get("mesh") or {}
    if not mesh.get("enabled"):
        return None
    return ((mesh.get("summary") or {}).get("health") or {}).get("reachable")


@dataclass(frozen=True, kw_only=True)
class RagnarSensorDescription(SensorEntityDescription):
    """Sensor description with a value extractor over the coordinator data."""

    value_fn: Callable[[dict[str, Any]], Any]
    available_fn: Callable[[dict[str, Any]], bool] | None = None


SENSORS: tuple[RagnarSensorDescription, ...] = (
    RagnarSensorDescription(
        key="people",
        translation_key="people",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: (d.get("presence") or {}).get("people"),
    ),
    RagnarSensorDescription(
        key="heart_rate",
        translation_key="heart_rate",
        native_unit_of_measurement="bpm",
        icon="mdi:heart-pulse",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _latest_vital(d, "hr"),
    ),
    RagnarSensorDescription(
        key="breathing_rate",
        translation_key="breathing_rate",
        native_unit_of_measurement="bpm",
        icon="mdi:lungs",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _latest_vital(d, "br"),
    ),
    RagnarSensorDescription(
        key="alert_count",
        translation_key="alert_count",
        icon="mdi:shield-alert",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: len((d.get("watchtower") or {}).get("alerts") or []),
    ),
    RagnarSensorDescription(
        key="incident_count",
        translation_key="incident_count",
        icon="mdi:shield-alert-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: len((d.get("incidents") or {}).get("incidents") or []),
    ),
    RagnarSensorDescription(
        key="vulnerability_count",
        translation_key="vulnerability_count",
        icon="mdi:bug",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: (d.get("status") or {}).get("vulnerability_count"),
    ),
    RagnarSensorDescription(
        key="ssid",
        translation_key="ssid",
        icon="mdi:wifi",
        value_fn=lambda d: (d.get("status") or {}).get("current_ssid") or None,
    ),
    RagnarSensorDescription(
        key="mesh_reachable",
        translation_key="mesh_reachable",
        icon="mdi:server-network",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_mesh_reachable,
        available_fn=lambda d: bool((d.get("mesh") or {}).get("enabled")),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RagnarConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Ragnar sensors."""
    coordinator = entry.runtime_data
    async_add_entities(
        RagnarSensor(coordinator, entry.entry_id, desc) for desc in SENSORS
    )


class RagnarSensor(RagnarEntity, SensorEntity):
    """A single value pulled from the merged coordinator data."""

    entity_description: RagnarSensorDescription

    def __init__(self, coordinator, entry_id, description: RagnarSensorDescription):
        super().__init__(coordinator, entry_id)
        self.entity_description = description
        self._attr_unique_id = f"{entry_id}_{description.key}"

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def available(self) -> bool:
        if not super().available:
            return False
        avail_fn = self.entity_description.available_fn
        return avail_fn(self.coordinator.data) if avail_fn else True
