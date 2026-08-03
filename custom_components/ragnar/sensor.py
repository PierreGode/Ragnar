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


@dataclass(frozen=True, kw_only=True)
class RagnarSensorDescription(SensorEntityDescription):
    """Sensor description with a value extractor over the coordinator data."""

    value_fn: Callable[[dict[str, Any]], Any]


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
