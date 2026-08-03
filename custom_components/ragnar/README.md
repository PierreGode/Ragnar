# Ragnar — Home Assistant integration

Bring a Ragnar unit's **RuSense presence/vitals** and **security alerts** into
Home Assistant as native entities, so you can automate on them (turn on lights
when presence is detected, push a notification on an evil-twin alert, etc.).

Home Assistant never runs Ragnar code — this integration is a thin **local
polling** client that talks to the Ragnar web API you already run (default
`http://<unit>:8000`).

## Entities

| Entity | Type | Source endpoint |
|--------|------|-----------------|
| Presence | `binary_sensor` (occupancy) | `/api/rusense/presence` |
| People | `sensor` | `/api/rusense/presence` |
| Heart rate | `sensor` (bpm) | `/api/rusense/vitals-history` |
| Breathing rate | `sensor` (bpm) | `/api/rusense/vitals-history` |
| Security alert | `binary_sensor` (safety) | `/api/net/watchtower` |
| Active alerts | `sensor` | `/api/net/watchtower` |
| Active incidents | `sensor` | `/api/net/incidents` |
| Vulnerabilities | `sensor` | `/api/status` |
| Sensing backend problem | `binary_sensor` (problem) | `/api/sensing/status` |
| Security alert | `event` | `/api/net/watchtower` |

## Install (HACS — recommended)

1. HACS → three-dot menu → **Custom repositories**.
2. Add `https://github.com/PierreGode/Ragnar` with category **Integration**.
3. Install **Ragnar**, then restart Home Assistant.
4. **Settings → Devices & Services → Add Integration → Ragnar**.
5. Enter the unit's host/IP and port. If your Ragnar has a login configured,
   enter its username/password; otherwise leave them blank.

## Install (manual)

Copy `custom_components/ragnar/` into your Home Assistant `config/custom_components/`
folder and restart, then add the integration from the UI as above.

## Authentication

Ragnar uses a Flask **session cookie** (there is no API token). The integration
logs in once with your credentials and reuses the cookie, re-authenticating
automatically if it expires. Units with no auth configured need no credentials.

## Example automation

```yaml
automation:
  - alias: Notify on Ragnar critical security alert
    trigger:
      - platform: event
        event_type: ragnar_security_alert
    condition:
      - condition: template
        value_template: "{{ trigger.event.data.severity in ['high','critical'] }}"
    action:
      - service: notify.mobile_app
        data:
          title: "Ragnar: {{ trigger.event.data.severity | upper }}"
          message: "{{ trigger.event.data.source }}: {{ trigger.event.data.title }}"
```

> **Status:** initial scaffold (v0.1.0). Not yet validated against a live Home
> Assistant instance.
