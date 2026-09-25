"""Event entity: fires once per new Watchtower security alert.

An `event` entity is the right HA primitive for a stream of discrete security
alerts (vs. a sensor that holds a level). Automations trigger on the event and
read the alert's severity/source/title from the event attributes.
"""

from __future__ import annotations

from homeassistant.components.event import EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import RagnarConfigEntry
from .entity import RagnarEntity

# One generic event type; the severity/source ride along as attributes so a
# single trigger can cover everything and filter in the automation.
_EVENT_TYPE = "security_alert"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RagnarConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Ragnar security-alert event entity."""
    async_add_entities([RagnarSecurityAlertEvent(entry.runtime_data, entry.entry_id)])


class RagnarSecurityAlertEvent(RagnarEntity, EventEntity):
    """Fire an HA event for each newly-seen Watchtower alert."""

    _attr_translation_key = "security_alert"
    _attr_event_types = [_EVENT_TYPE]
    _attr_icon = "mdi:shield-alert"

    def __init__(self, coordinator, entry_id: str) -> None:
        super().__init__(coordinator, entry_id)
        self._attr_unique_id = f"{entry_id}_security_alert_event"
        # Highest alert ts already emitted; suppresses replays of the rolling
        # window on every poll. 0.0 means "emit nothing on first refresh" is
        # handled by seeding from the first batch (see _handle_coordinator_update).
        self._last_ts: float | None = None

    @callback
    def _handle_coordinator_update(self) -> None:
        wt = self.coordinator.data.get("watchtower") or {}
        alerts = wt.get("alerts") or []
        if not alerts:
            self.async_write_ha_state()
            return

        # Newest-first list; work with epoch ts from watchtower.normalize().
        max_ts = max((a.get("ts") or 0.0) for a in alerts)

        if self._last_ts is None:
            # First poll after (re)start: seed the watermark, don't replay
            # history as a flood of "new" alerts.
            self._last_ts = max_ts
            self.async_write_ha_state()
            return

        fresh = [a for a in alerts if (a.get("ts") or 0.0) > self._last_ts]
        for alert in sorted(fresh, key=lambda a: a.get("ts") or 0.0):
            self._trigger_event(
                _EVENT_TYPE,
                {
                    "severity": alert.get("severity"),
                    "source": alert.get("source"),
                    "title": alert.get("title"),
                    "key": alert.get("key"),
                    "ts": alert.get("ts"),
                },
            )
        if fresh:
            self._last_ts = max_ts
        self.async_write_ha_state()
