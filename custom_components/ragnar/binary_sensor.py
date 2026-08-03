"""Binary sensors: RuSense presence and an active-security-alert flag."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import RagnarConfigEntry
from .entity import RagnarEntity

# Severities that count as "security alert active".
_ACTIVE_SEVERITIES = {"high", "critical"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RagnarConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Ragnar binary sensors."""
    coordinator = entry.runtime_data
    async_add_entities(
        [
            RagnarPresenceBinarySensor(coordinator, entry.entry_id),
            RagnarSecurityAlertBinarySensor(coordinator, entry.entry_id),
            RagnarSensingHealthBinarySensor(coordinator, entry.entry_id),
            RagnarWifiConnectivityBinarySensor(coordinator, entry.entry_id),
            RagnarEthernetConnectivityBinarySensor(coordinator, entry.entry_id),
            RagnarMeshAttentionBinarySensor(coordinator, entry.entry_id),
        ]
    )


class RagnarPresenceBinarySensor(RagnarEntity, BinarySensorEntity):
    """RuSense occupancy — the backend's authoritative presence decision."""

    _attr_translation_key = "presence"
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_presence"

    @property
    def is_on(self) -> bool | None:
        pres = self.coordinator.data.get("presence") or {}
        if not pres.get("success"):
            return None
        return bool(pres.get("present"))

    @property
    def extra_state_attributes(self) -> dict:
        pres = self.coordinator.data.get("presence") or {}
        return {
            "people": pres.get("people"),
            "motion_level": pres.get("motion_level"),
            "confidence": pres.get("confidence"),
            "model_active": pres.get("model_active"),
            "age_s": pres.get("age_s"),
        }


class RagnarSecurityAlertBinarySensor(RagnarEntity, BinarySensorEntity):
    """On when Watchtower has a high/critical alert in its recent window."""

    _attr_translation_key = "security_alert"
    _attr_device_class = BinarySensorDeviceClass.SAFETY

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_security_alert"

    @property
    def is_on(self) -> bool:
        wt = self.coordinator.data.get("watchtower") or {}
        alerts = wt.get("alerts") or []
        return any(
            (a.get("severity") or "").lower() in _ACTIVE_SEVERITIES for a in alerts
        )

    @property
    def extra_state_attributes(self) -> dict:
        wt = self.coordinator.data.get("watchtower") or {}
        inc = self.coordinator.data.get("incidents") or {}
        return {
            "alert_count": len(wt.get("alerts") or []),
            "incident_count": len(inc.get("incidents") or []),
            "watchtower_enabled": wt.get("enabled"),
        }


class RagnarSensingHealthBinarySensor(RagnarEntity, BinarySensorEntity):
    """Problem sensor: on when the sensing backend is installed but not running."""

    _attr_translation_key = "sensing_health"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_sensing_health"

    @property
    def is_on(self) -> bool | None:
        s = self.coordinator.data.get("sensing") or {}
        if not s.get("success"):
            return None
        return bool(s.get("installed")) and not bool(s.get("active"))


class RagnarWifiConnectivityBinarySensor(RagnarEntity, BinarySensorEntity):
    """On when the unit's Wi-Fi is connected (from /api/status)."""

    _attr_translation_key = "wifi_connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_connected"

    @property
    def is_on(self) -> bool:
        return bool((self.coordinator.data.get("status") or {}).get("wifi_connected"))

    @property
    def extra_state_attributes(self) -> dict:
        st = self.coordinator.data.get("status") or {}
        return {"ssid": st.get("current_ssid")}


class RagnarEthernetConnectivityBinarySensor(RagnarEntity, BinarySensorEntity):
    """On when the unit's Ethernet is connected (from /api/status)."""

    _attr_translation_key = "ethernet_connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_ethernet_connected"

    @property
    def is_on(self) -> bool:
        return bool(
            (self.coordinator.data.get("status") or {}).get("ethernet_connected")
        )

    @property
    def extra_state_attributes(self) -> dict:
        st = self.coordinator.data.get("status") or {}
        return {
            "interface": st.get("ethernet_interface"),
            "ip": st.get("ethernet_ip"),
        }


def _mesh_health(data: dict) -> dict:
    """The mesh summary.health roll, or {} when mesh is off/unavailable."""
    mesh = data.get("mesh") or {}
    if not mesh.get("enabled"):
        return {}
    return (mesh.get("summary") or {}).get("health") or {}


class RagnarMeshAttentionBinarySensor(RagnarEntity, BinarySensorEntity):
    """On when any unit in the Ragnar mesh needs attention.

    A node needs attention if it is unreachable, its node key is warning/expired,
    it reports undervoltage, or it carries a high/critical finding (the backend
    computes this roll in summary.health.attention). Only available when the mesh
    is enabled on this unit.
    """

    _attr_translation_key = "mesh_attention"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_mesh_attention"

    @property
    def available(self) -> bool:
        return super().available and bool(
            (self.coordinator.data.get("mesh") or {}).get("enabled")
        )

    @property
    def is_on(self) -> bool:
        return int(_mesh_health(self.coordinator.data).get("attention") or 0) > 0

    @property
    def extra_state_attributes(self) -> dict:
        h = _mesh_health(self.coordinator.data)
        return {
            "attention": h.get("attention"),
            "reachable": h.get("reachable"),
            "unreachable": h.get("unreachable"),
            "total": h.get("total"),
            "worst_severity": h.get("worst"),
        }
