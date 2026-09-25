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

One HA **device** ("Ragnar") with fifteen entities:

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
| `binary_sensor.ragnar_wifi_connected` | connectivity | `/api/status` | On when the unit's Wi-Fi is connected. Attribute `ssid`. |
| `binary_sensor.ragnar_ethernet_connected` | connectivity | `/api/status` | On when the unit's Ethernet is connected. Attributes `interface`, `ip`. |
| `sensor.ragnar_connected_ssid` | — | `/api/status` | The Wi-Fi SSID the unit is joined to. |
| `binary_sensor.ragnar_mesh_needs_attention` | problem | `/api/mesh/status` | On when any [Ragnar Mesh](mesh.md) node needs attention (unreachable, node-key warning/expired, undervoltage, or high/critical finding). Attributes carry the reachable/unreachable/total roll and worst severity. **Unavailable** unless the mesh is enabled. |
| `sensor.ragnar_mesh_nodes_reachable` | measurement | `/api/mesh/status` | Count of reachable mesh nodes. **Unavailable** unless the mesh is enabled. |
| `event.ragnar_security_alert` | event | `/api/net/watchtower` | Fires once per **new** Watchtower alert. Event data: `severity`, `source`, `title`, `key`, `ts`. |

> **Wireless-attack alerts** (deauth floods, evil twins, KARMA) are **not** a
> separate entity: when a monitor-mode adapter is running the WiFi Defense /
> `wifiwatch` monitor, those detections flow into Watchtower and therefore
> already surface through `binary_sensor.ragnar_security_alert` and the
> `event.ragnar_security_alert` event above.

> **Note on vitals cadence.** Heart rate and breathing rate come from RuSense's
> 5-minute vitals-history buckets, so those two sensors update on that cadence
> and read `unknown` when the room is empty (there is no vital to report). The
> presence, people and alert entities update every poll.

## Where the entities show up

All entities are plain sensors/controls, so **every one of them appears on the
Ragnar device page** (**Settings → Devices & Services → Ragnar**) and is
available to dashboards and automations — nothing is tucked into a hidden
"Diagnostic" section.

> Earlier versions tagged the connectivity / mesh / health entities as
> `diagnostic`, which tidied the device page but made Home Assistant **hide them
> from dashboards**. That was reverted — organise them with the dashboard card
> below instead, which keeps everything visible.

## A tidy dashboard card

For a Lovelace dashboard, this **Entities** card lays the same entities out under
labelled sections. Paste it via **Edit dashboard → Add card → Manual**:

```yaml
type: entities
title: Ragnar
show_header_toggle: false
state_color: true
entities:
  - type: section
    label: RuSense
  - entity: binary_sensor.ragnar_presence
  - entity: sensor.ragnar_people
  - entity: sensor.ragnar_heart_rate
  - entity: sensor.ragnar_breathing_rate
  - type: section
    label: Security
  - entity: binary_sensor.ragnar_security_alert
  - entity: sensor.ragnar_active_alerts
  - entity: sensor.ragnar_active_incidents
  - entity: sensor.ragnar_vulnerabilities
  - type: section
    label: Connectivity
  - entity: binary_sensor.ragnar_wi_fi_connected
  - entity: sensor.ragnar_connected_ssid
  - entity: binary_sensor.ragnar_ethernet_connected
  - type: section
    label: Mesh & health
  - entity: binary_sensor.ragnar_mesh_needs_attention
  - entity: sensor.ragnar_mesh_nodes_reachable
  - entity: binary_sensor.ragnar_sensing_backend_problem
```

> Entity IDs above assume the default `ragnar_` prefix; adjust if you renamed the
> device or entities. The mesh rows show as *unavailable* unless the unit has the
> [Ragnar Mesh](mesh.md) enabled — drop them on a single-unit setup.

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

> **`event.ragnar_security_alert` is an event *entity*, not a bus event.** The
> integration updates the entity's state (a timestamp) and carries the alert's
> `severity` / `source` / `title` / `key` as **attributes** — it does **not**
> fire a `ragnar_security_alert` event on the HA event bus. So automations must
> use a **state trigger** on the entity and read `trigger.to_state.attributes`,
> as below. (A `platform: event, event_type: ragnar_security_alert` trigger will
> never fire.)

```yaml
automation:
  - alias: Notify on Ragnar critical security alert
    trigger:
      - platform: state
        entity_id: event.ragnar_security_alert
    condition:
      - condition: template
        value_template: "{{ trigger.to_state.attributes.severity in ['high','critical'] }}"
    action:
      - service: notify.mobile_app_myphone
        data:
          title: "Ragnar: {{ trigger.to_state.attributes.severity | upper }}"
          message: >
            {{ trigger.to_state.attributes.source }}:
            {{ trigger.to_state.attributes.title }}
```

Warn when a mesh node drops or needs attention:

```yaml
automation:
  - alias: Notify when a Ragnar mesh node needs attention
    trigger:
      - platform: state
        entity_id: binary_sensor.ragnar_mesh_needs_attention
        to: "on"
        for: "00:02:00"
    action:
      - service: notify.mobile_app_myphone
        data:
          title: Ragnar mesh
          message: >
            A node needs attention —
            {{ state_attr('binary_sensor.ragnar_mesh_needs_attention', 'unreachable') }}
            of {{ state_attr('binary_sensor.ragnar_mesh_needs_attention', 'total') }} unreachable.
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

Turn an LED strip **red** when a captive-portal / evil-twin attack is detected.
HaleHound's GARMR fingerprint and WiFi Defense's evil-twin / attack-tool
detections both flow into Watchtower and surface on the
`event.ragnar_security_alert` entity — the `condition` below keeps the strip
reacting to portal-class alerts specifically (drop the `is search(...)` clause to
react to **any** medium-or-worse alert). Replace `light.led_strip` with your
strip's entity.

> **Severity note.** A freshly-started captive portal often scores **`medium`**
> ("possible") from HaleHound, not `high`/`critical` — it only escalates once the
> GARMR portal is confirmed across multiple signals. So this example triggers on
> `medium` and above; the keyword filter keeps ordinary `medium` noise (asset /
> IP-change alerts) from setting it off.

```yaml
automation:
  - alias: LED strip red on Ragnar captive-portal attack
    mode: restart
    trigger:
      - platform: state
        entity_id: event.ragnar_security_alert
    condition:
      - condition: template
        value_template: >
          {% set a = trigger.to_state.attributes %}
          {% set t = ((a.title | default('')) ~ ' ' ~ (a.source | default(''))) | lower %}
          {{ (a.severity | default('')) in ['medium','high','critical']
             and (t is search('portal|captive|garmr|evil.?twin|halehound|marauder|ghost.?esp|rogue|multitool|attack.?tool')) }}
    action:
      # Snapshot the strip so we can restore it afterward.
      - service: scene.create
        data:
          scene_id: ragnar_led_restore
          snapshot_entities:
            - light.led_strip
      # Flash red.
      - repeat:
          count: 6
          sequence:
            - service: light.turn_on
              target:
                entity_id: light.led_strip
              data:
                rgb_color: [255, 0, 0]
                brightness_pct: 100
            - delay: "00:00:00.6"
            - service: light.turn_off
              target:
                entity_id: light.led_strip
            - delay: "00:00:00.4"
      # Hold solid red for a minute, then restore the previous state.
      - service: light.turn_on
        target:
          entity_id: light.led_strip
        data:
          rgb_color: [255, 0, 0]
          brightness_pct: 100
      - delay: "00:01:00"
      - service: scene.turn_on
        target:
          entity_id: scene.ragnar_led_restore
```

> Prefer to react to **any** high/critical alert instead?
> `binary_sensor.ragnar_security_alert` turns `on` for those — trigger on it going
> `on` — but it can't single out the captive-portal case (and, being high/critical
> only, it misses the `medium` "possible portal" verdict the example above catches),
> so the event-entity route is the better fit here.

## Worked example: flash Philips Hue strips red on a captive-portal attack

A complete, end-to-end setup — this is the exact recipe used to make two Hue
light strips flash red the moment Ragnar sees a captive portal. Adapt the entity
names to your own lights.

**1. Get your strips into Home Assistant.** A Hue strip is controlled through the
**Hue Bridge**, so add the bridge, not the strip: **Settings → Devices &
Services → Add Integration → Philips Hue**. HA auto-discovers the bridge on the
LAN; press the round **link button** on top of the bridge when prompted. Every
light paired to the bridge then appears as a `light.<name>` entity. Two things to
check for each strip you want to flash:

- It must be **color-capable** — in **Developer Tools → States**, its
  `supported_color_modes` should include `xy`, `hs`, `rgb`, or `rgbw`. A
  white/tunable-white strip can't go red.
- Note its exact **entity_id** (e.g. `light.undersangen`,
  `light.hue_lightstrip_sangram`) — you'll paste it into the automation.

**2. Understand what fires.** When Ragnar/HaleHound sees an evil-twin captive
portal, it raises a Watchtower alert (`source: halehound`) that the integration
delivers on the **`event.ragnar_security_alert` entity**. A just-started portal
usually scores **`medium`** ("possible, ~45%") and only escalates to
`high`/`critical` once the GARMR portal is confirmed — so the automation must
trigger at `medium` and above, and (crucially) use a **state trigger** on the
event entity, because that entity does not fire a `ragnar_security_alert` bus
event (see the note under [Example automation](#example-automation)).

**3. The automation.** Snapshots the strips, flashes them red six times, holds
solid red for a minute, then restores whatever they were doing before. Replace
the two `light.*` entities with yours (there are four references — the snapshot,
the two flash calls, and the hold):

```yaml
automation:
  - alias: LED strips red on Ragnar captive-portal attack
    mode: restart
    trigger:
      - platform: state
        entity_id: event.ragnar_security_alert
    condition:
      - condition: template
        value_template: >
          {% set a = trigger.to_state.attributes %}
          {% set t = ((a.title | default('')) ~ ' ' ~ (a.source | default(''))) | lower %}
          {{ (a.severity | default('')) in ['medium','high','critical']
             and (t is search('portal|captive|garmr|evil.?twin|halehound|marauder|ghost.?esp|rogue|multitool|attack.?tool')) }}
    action:
      # Remember the strips' current state so we can restore them afterward.
      - service: scene.create
        data:
          scene_id: ragnar_led_restore
          snapshot_entities:
            - light.undersangen
            - light.hue_lightstrip_sangram
      # Flash red six times.
      - repeat:
          count: 6
          sequence:
            - service: light.turn_on
              target:
                entity_id:
                  - light.undersangen
                  - light.hue_lightstrip_sangram
              data:
                rgb_color: [255, 0, 0]
                brightness_pct: 100
            - delay: "00:00:00.6"
            - service: light.turn_off
              target:
                entity_id:
                  - light.undersangen
                  - light.hue_lightstrip_sangram
            - delay: "00:00:00.4"
      # Hold solid red for a minute, then restore the previous state.
      - service: light.turn_on
        target:
          entity_id:
            - light.undersangen
            - light.hue_lightstrip_sangram
        data:
          rgb_color: [255, 0, 0]
          brightness_pct: 100
      - delay: "00:01:00"
      - service: scene.turn_on
        target:
          entity_id: scene.ragnar_led_restore
```

**4. Test it.** Two levels:

- **Light actions only** — on the automation, use **⋮ → Run** (or Developer Tools
  → Actions → *Automation: Trigger* with *skip conditions* on). This skips the
  trigger/condition and runs the flash-and-restore actions, confirming the strips
  react and restore.
- **The whole chain** — start a captive portal on a test ESP32 and watch the
  strips. Within one poll interval (default 30 s) of Ragnar raising the alert
  they flash red. Check **Settings → Automations → (this one) → Traces** if it
  doesn't fire: the trace shows the event entity's attributes and exactly which
  condition line passed or failed.

> **Why medium, not high/critical?** HaleHound's captive-portal verdict is
> confidence-scored. A portal you just switched on typically reads
> `medium` / "possible"; it climbs to `high`/`critical` only when the GARMR
> DNS-hijack + redirect + credential-form signals all confirm. Gating at
> `medium`+ with the keyword filter catches the portal early while the keyword
> list keeps ordinary `medium` chatter (asset-inventory / IP-change alerts) from
> triggering the lights. Tighten the list to
> `portal|captive|garmr|evil.?twin` if you want captive-portal alerts *only*.

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
