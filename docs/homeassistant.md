# Home Assistant integration

Bring a Ragnar unit's **RuSense presence / vitals** and **security alerts** into
[Home Assistant](https://www.home-assistant.io/) as native entities, so the
sensing and threat data Ragnar already produces can drive HA automations — turn
on the hallway light when RuSense sees someone, push a phone notification the
moment Watchtower raises an evil-twin alert, put occupancy on a dashboard, or
log heart-rate trends alongside the rest of your home telemetry.

Home Assistant never runs Ragnar code. The integration is a thin **local-polling**
client that talks to the same web API the Ragnar UI already serves (default
`http://<unit>:8000`). It lives in this repo under
[`custom_components/ragnar/`](../custom_components/ragnar/), which doubles as a
[HACS](https://hacs.xyz/) custom repository via the top-level `hacs.json`.

## What you get

One HA **device** ("Ragnar") with ten entities:

| Entity | Type | Ragnar endpoint | Meaning |
|--------|------|-----------------|---------|
| `binary_sensor.ragnar_presence` | occupancy | `/api/rusense/presence` | RuSense's authoritative, smoothed presence decision (the same one that gates alerts/sightings). Attributes carry `people`, `motion_level`, `confidence`, `model_active`, `age_s`. |
| `sensor.ragnar_people` | measurement | `/api/rusense/presence` | Estimated people count. |
| `sensor.ragnar_heart_rate` | bpm | `/api/rusense/vitals-history` | Newest vitals bucket carrying a heart rate. `unknown` while nobody is in range. |
| `sensor.ragnar_breathing_rate` | bpm | `/api/rusense/vitals-history` | Newest vitals bucket carrying a breathing rate. |
| `binary_sensor.ragnar_security_alert` | safety | `/api/net/watchtower` | On when Watchtower has a **high/critical** alert in its recent window. Attributes carry alert/incident counts. |
| `sensor.ragnar_active_alerts` | measurement | `/api/net/watchtower` | Count of alerts in the Watchtower feed. |
| `sensor.ragnar_active_incidents` | measurement | `/api/net/incidents` | Count of correlated attack-chain [incidents](incident-correlation.md). |
| `sensor.ragnar_vulnerabilities` | measurement | `/api/status` | Open vulnerability count from the dashboard status. |
| `binary_sensor.ragnar_sensing_backend_problem` | problem | `/api/sensing/status` | On when the bundled sensing backend is **installed but not running** (a silent-failure tell). |
| `event.ragnar_security_alert` | event | `/api/net/watchtower` | Fires once per **new** Watchtower alert. Event data: `severity`, `source`, `title`, `key`, `ts`. |

> **Note on vitals cadence.** Heart rate and breathing rate come from RuSense's
> 5-minute vitals-history buckets, so those two sensors update on that cadence
> and read `unknown` when the room is empty (there is no vital to report). The
> presence, people and alert entities update every poll.

## Install (HACS — recommended)

1. In Home Assistant, open **HACS → ⋮ (top right) → Custom repositories**.
2. Add `https://github.com/PierreGode/Ragnar` with category **Integration**.
3. Install **Ragnar**, then **restart Home Assistant**.
4. Go to **Settings → Devices & Services → Add Integration** and search for
   **Ragnar**.
5. Fill in the unit's **host/IP** and **port** (default `8000`). If your Ragnar
   has a [login configured](SECURITY.md), enter its **username/password**;
   otherwise leave them blank.

## Install (manual)

Copy the integration folder into your Home Assistant config directory and
restart, then add it from the UI as in steps 4–5 above:

```
config/custom_components/ragnar/   ←  copy of custom_components/ragnar/ from this repo
```

## Authentication

Ragnar authenticates the web API with a **Flask session cookie** — there is no
API token. The integration therefore keeps its own cookie jar: on setup it
`POST`s your credentials to `/api/auth/login`, stores the cookie, and reuses it
for every poll, transparently re-logging in if the cookie expires (HTTP 401).
A unit with **no** authentication configured needs no credentials at all — the
integration checks `/api/auth/status` and skips login when the unit is open.

Every other request the integration makes is a read-only `GET`.

## Reaching the unit from a containerised Home Assistant

If Home Assistant runs in Docker and Ragnar runs on the **same host**, use the
Docker bridge gateway address (commonly `172.17.0.1`) as the host, not
`localhost` — inside the container `localhost` is the container itself. On a
separate box, just use the Ragnar unit's LAN IP or its
[Ragnar Mesh](mesh.md)/Tailscale address.

## Example automation

Notify a phone on any high/critical Ragnar security alert:

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
      - service: notify.mobile_app_myphone
        data:
          title: "Ragnar: {{ trigger.event.data.severity | upper }}"
          message: "{{ trigger.event.data.source }}: {{ trigger.event.data.title }}"
```

Presence-driven lighting:

```yaml
automation:
  - alias: Hallway light on RuSense presence
    trigger:
      - platform: state
        entity_id: binary_sensor.ragnar_presence
        to: "on"
    action:
      - service: light.turn_on
        target:
          entity_id: light.hallway
```

## Options

After setup, **Configure** on the integration lets you change the **poll
interval** (default 30 s, range 5–3600 s).

## Troubleshooting

- **"Failed to connect"** — check the host/port and that the Ragnar web UI is
  reachable from the HA machine (from a containerised HA, see the bridge-address
  note above). Confirm with `curl http://<host>:<port>/api/status`.
- **"Invalid authentication"** — the unit has a login configured and the
  username/password were wrong. Blank credentials only work on an open unit.
- **Heart rate / breathing rate show `unknown`** — expected while no one is in
  RuSense range; they populate once a person is detected at display-grade
  confidence.
- **Sensing-backend-problem is on** — the bundled sensing service is installed
  but not `active`; check it from the Ragnar UI's Nodes tab or with
  `systemctl status ragnar-sensing`.

## Related

- [RuSense / sensing](../README.md) — the WiFi-CSI sensing backend the presence
  and vitals data comes from.
- [Watchtower](watchtower.md) — the unified alert feed behind the security
  entities.
- [Incident correlation](incident-correlation.md) — the attack-chain incidents
  counted by `sensor.ragnar_active_incidents`.
