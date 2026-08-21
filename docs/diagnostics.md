# Wardriving Diagnostics Panel

A deep, read-only diagnostics view for the wardriving stack. It answers the
field questions the plain status card cannot — *why is only one radio scanning?
what is each dongle drawing? is the Pi browning out? is the GPS actually alive
or just showing stale numbers?* — and draws a live **GPS sky view**.

- **UI:** bottom of the **Wardriving** tab, and of the phone-access AP page
  (`web/wardrive_mobile.html`). A native `<details>` element, collapsed by
  default.
- **Backend:** [`wardrive_diagnostics.py`](../wardrive_diagnostics.py)
- **Endpoint:** `GET /api/wardriving/diagnostics`

---

## Why a separate endpoint

The 3-second wardriving status poll stays cheap. This payload walks sysfs and
shells out to `iw` / `vcgencmd`, so it is fetched **only while the panel is
expanded** (at most every 8 s on the client; the backend caches the whole
payload for 5 s). Collapse the panel and the extra work stops.

Everything here is **best-effort and read-only**: a missing tool or sysfs node
degrades a single field, never the whole payload. Each top-level section is
wrapped so one failure (e.g. `power_error`) can't take the others down.

The panel is a `<details>` element on purpose — the toggle keeps working even
when a script errors, which is precisely when you reach for diagnostics. Its
summary always shows a live hint (`GPS fix` / `GPS searching` / `no GPS`, with
`· error` appended when the engine or GPS reports one), so a glance is often
enough without expanding.

---

## Groups

The **GPS**, **Session**, **Scanning**, **Coverage**, **Companions** and
**Device** groups come from the status object the panel already polls. The
**GPS constellations**, **GPS sky view**, **Radios**, **Power** and **Errors**
groups come from this endpoint.

| Group | Contents |
|-------|----------|
| **GPS** | fix + quality, satellites used/in-view, SNR max, HDOP, lat/lon/altitude, speed, course, source, port, age of last update and last NMEA sentence, time-to-first-fix (or how long it has been searching), error |
| **GPS constellations** | per-constellation satellites in view and peak SNR (GPS / GLONASS / Galileo / BeiDou / QZSS / NavIC) |
| **GPS sky view** | polar plot of every satellite by azimuth/elevation, coloured per constellation — North up, zenith at centre, horizon at the rim. Fill opacity tracks SNR (untracked satellites render hollow); hover a dot for PRN / elevation / azimuth / SNR. The graphical half of the same GSV data u-center draws. A **⛶ Fullscreen** button opens an immersive view with a real **starfield** behind the satellites (see below) |
| **Radios** | every wireless interface present, whether it is scanning, its driver / mode / link state, the USB adapter behind it — and **when it is not scanning, the reason** |
| **Power** | per-USB-device declared draw and which interface it backs, summed USB budget, `usb_max_current_enable`, supply throttle/under-voltage flags (now and since boot), core voltage, temperature, and Pi 5 PMIC board power |
| **Errors** | everything currently complaining — engine, GPS, radios, companions, supply and **stalled feeds** — gathered into one list |

---

## Radios — "why is only wlan0 scanning?"

`radios()` enumerates **every** wireless netdev from sysfs (the authority on
what exists), then for each one reports whether it is in the live scan set and,
if not, **why** — ordered by how decisive the cause is:

1. `monitor child interface (skipped by design)` — a `*mon` / `mon*` vif
2. `rfkill-blocked — run: sudo rfkill unblock all`
3. `held as the uplink / management radio`
4. `in AP mode (lent to the phone-access AP)`
5. `lent to the phone-access AP`
6. `not claimed — present but not in the scan set`

Each row also carries `mode` (managed/monitor/AP via `iw`), `operstate`,
`driver`, and the backing USB device (product / manufacturer / USB id /
declared mA) when the radio is a dongle.

> New BT/WiFi dongles come up **rfkill-blocked** system-wide until
> `sudo rfkill unblock all` — the Radios group names this explicitly so it isn't
> mistaken for a driver fault.

## Power — USB budget + supply health

> The main **Dashboard** carries a small always-on **[power badge](power.md)**
> that lights straight off the same throttle register when the board under-volts
> — you don't have to open this panel to catch a brownout. This section is the
> deeper per-radio view.

`power()` reports the per-USB-device **declared** draw (`bMaxPower` from the USB
descriptor — *declared, not measured*; no Pi meters per-port current), which
netdev each adapter backs, and the summed budget. Plus supply health from
`vcgencmd`:

- **`get_throttled` flags**, split into **now** (low nibble) and **since boot**
  (bits 16–19). The "occurred" bits are the ones that catch a brownout that
  already passed — exactly the case where a GPS cold start dies but everything
  looks healthy by the time you go looking.
- **Core voltage** and **temperature**.
- **`usb_max_current_enable`** and **Pi 5 PMIC rail power**, reported **only on
  a Pi 5** (the flag is meaningless on a Pi 4 / Zero 2 W, so the row is omitted
  there rather than shown as a false problem). On a Pi 5 total USB peripheral
  current is capped at 600 mA unless a 5 A PD supply is detected or this flag is
  set.

## Errors — one list, with feed-stall correlation

`errors()` gathers engine / GPS / companion / power complaints into one list,
and adds the two failure modes the summary numbers hide:

- **Stale GPS** — the receiver still reports `connected`, but no NMEA sentence
  has arrived for **> 30 s** (`GPS_STALE_S`). A stopped feed looks identical to
  a weak one in the numbers — the count and SNR just sit at their last value —
  so this is called out explicitly.
- **Stalled scan** — the engine reports `running`, but no scan completed for
  **> 60 s** (`SCAN_STALE_S`).
- **Tracking but no fix** — the receiver is **searching > 3 min** with **≥ 4
  satellites in view** and still no fix. Satellites "in view" only means carrier
  lock; a fix also needs the 50 bps navigation message demodulated, which fails
  when the signal is too weak. This is antenna placement / sky view (a GPS puck
  next to the Pi or a USB hub gets desensed) or a cold start on a receiver with
  no battery-backed almanac — **not a Ragnar fault**, so the panel says so
  instead of leaving a healthy-looking feed with N satellites looking like a bug.
- **Shared-USB correlation** — if **both** feeds go quiet within a minute of
  each other, that points at the shared USB bus (a hub dropping, a bus/power
  dip) rather than at reception or either device individually. The hint says so
  and points you at `dmesg` for USB resets/disconnects.

> **Reading a stale panel.** If you see `Last NMEA` tens of minutes old while
> `Satellites`/`SNR` still show non-zero values, those numbers are **frozen** —
> the feed died and the last sample is just being held. The **GPS sky view will
> be empty** (its per-satellite data is pruned after 30 s of staleness), even
> though the constellation counts may still show a stale figure.

---

## GPS sky view & the data behind it

The sky view is driven by NMEA **`GSV` ("satellites in view")** sentences,
which a receiver emits *while still searching* — so dots appear **before** a
position fix, as soon as the antenna is hearing satellites. See the **GPS**
section of the [Wardriving Guide](wardriving.md#gps) for the parsing details:
the multi-message GSV sweep is stitched into a per-satellite list (PRN,
elevation, azimuth, SNR) per constellation, exposed here as `gps.sky`.

Each dot needs **both** azimuth and elevation, which the receiver can only
compute once it has the satellite's almanac. On a full cold start there is a
window where the constellation counts show satellites (SNR only) but the sky
plot is still empty — the dots fill in once the almanac downloads, typically
still before the fix completes. u-blox 7 pucks lose their almanac every power
cycle, so this cold-start window is expected on that hardware, not a bug.

**gpsd vs direct NMEA.** When a `gpsd` instance owns the receiver, Ragnar reads
its JSON stream (`TPV`/`SKY`) instead of raw NMEA. gpsd `SKY` reports carry the
same per-satellite azimuth/elevation/SNR (and a `gnssid` per satellite) that
NMEA `GSV` does, so the counts, the **per-constellation breakdown** and the
**sky view** are all derived from `SKY` on this path — mapped by `gnssid` to the
same talker codes the GSV path uses. If gpsd reports a position but zero
satellites, it usually needs `GPSD_OPTIONS="-n"` (poll before a client
connects) or the receiver isn't feeding per-satellite detail to gpsd.

### Fullscreen sky view (stars behind the satellites)

The **⛶ Fullscreen** button on the sky view opens
[`web/scripts/skyview.js`](../web/scripts/skyview.js) — a full-window overlay
(Esc or ✕ to close) that draws a **real starfield** behind the live satellites,
so you can see the sky the receiver is looking at.

- **Stars** come from a bundled bright-star catalog
  ([`web/vendor/star_catalog.json`](../web/vendor/star_catalog.json) — 1,627
  stars to magnitude 5, RA/Dec J2000, colour-bucketed by B–V; derived from the
  d3-celestial / HYG–Hipparcos data, BSD-2-Clause). Each star's RA/Dec is
  projected to the observer's local **altitude/azimuth** from the GPS fix and
  the device clock using standard sidereal-time math, so stars and satellites
  share one true-north frame. Star size scales with brightness; the brightest
  named stars are labelled.
- **Stars need a position, and fall back to last-known.** A live fix is used
  when present; otherwise the server's **persisted last-known position** places
  the stars (with a "last-known — no live fix yet" note), so the starfield is
  roughly right the moment you open the view, even straight after a reboot
  before this boot's receiver has locked. The last-known fix is written to
  `data/last_gps.json` (throttled, atomic) and reloaded at startup — see
  [`GPSManager`](../gps_manager.py) (`_record_position` / `_load_last_known`,
  exposed as `gps.status.last_known`). Only with neither a fix nor any
  last-known does the overlay show satellites alone. (Satellites carry their own
  az/el and always render.)
- **Tap/click** a satellite for its constellation / PRN / elevation / azimuth /
  SNR, or a star for its name, constellation, magnitude and elevation/azimuth.
- It polls the lightweight, uncached `GET /api/wardriving/gps` (which now carries
  the `sky` list alongside the GPS status) at ~1 Hz — not the heavy, 5 s-cached
  `/diagnostics` endpoint — so satellites update live and the starfield drifts
  with sidereal time.

No external libraries or CDN — pure SVG + vanilla JS; the RA/Dec→alt/az
transform is self-tested against Polaris (altitude ≈ latitude, azimuth ≈ 0°).

### Ragnar Starview — the Observatory mode

The same overlay has an **enhanced "Ragnar Starview"** mode: an alt/az sky
**panorama** (rather than the polar disc) that turns the starfield into a small
pocket-planetarium *and* a live GNSS instrument. It opens when the code passes
`{ enhanced: true }` to `RagnarSkyView.open()` — the Wardriving dashboard wires
it to the **easter egg** (clicking the word *Wardriving* in the config/header),
distinct from the plain polar sky view above. Everything below is enhanced-mode
only; the polar view is unchanged.

**Astronomy layers**

- **Real IAU constellation figures.** Proper asterism stick-figures — not
  nearest-neighbour guesses — projected live from
  [`web/vendor/constellation_lines.json`](../web/vendor/constellation_lines.json)
  (88 constellations, `[RA,Dec]` J2000 vertices; d3-celestial, BSD-2-Clause).
  Toggle with the **✦ Constellations** chip.
- **Deep-sky (Messier) overlay.** All 110 Messier objects from
  [`web/vendor/deep_sky.json`](../web/vendor/deep_sky.json) (id, common name,
  type, magnitude; d3-celestial, BSD-2-Clause), drawn as dashed markers with a
  click-through card (type / magnitude / RA-Dec / airmass). Toggle with the
  **◇ Deep sky** chip.
- **Sun, twilight and Moon phase.** The Sun is drawn and its altitude drives a
  **Sky conditions** card — daylight / civil / nautical / astronomical twilight /
  night, a darkness %, and the *next* sunrise/sunset plus when astronomical dark
  begins (a forward 5-minute scan of solar altitude). The Moon is rendered with a
  **lit-fraction terminator** and its phase name / illumination % / age.
- **Planets** (Mercury–Neptune) and the **ecliptic + Milky Way** band, as before.
- **What's up now** — the brightest objects currently above 8°, sorted by
  magnitude, with altitude / cardinal azimuth / magnitude.

**GNSS instrument layers** (this is the part hobbyists/pros actually use)

- **Geometry (DOP).** Live **PDOP / HDOP / VDOP** computed from the tracked
  satellites' az/el geometry (a 4×4 normal-matrix inversion), with a plain-English
  verdict (excellent → poor geometry).
- **Obstruction / multipath sky survey.** The **▦ Sky survey** chip paints a
  per-cell heatmap (5°×5° az/el bins) of how often a satellite is *seen* in a
  direction versus how often it is actually *tracked* (has SNR). Directions
  frequently transited but rarely locked are obstructed — buildings, trees, an
  antenna mask. It yields an **open-sky score** and is **persisted to
  `localStorage`** so a survey builds up across visits; **⟲ Reset survey** clears
  it. This is a real GNSS site-survey tool built from data already streaming.
- **SNR-vs-elevation scatter** — the classic curve that exposes antenna/cable
  problems at a glance.
- **Integrity (experimental).** Heuristic **spoofing / jamming** indicators —
  uniform high SNR across many sats, improbable SNR, single-constellation lock,
  identical-SNR clusters, and position jumps between polls — surfaced as an
  OK / caution / suspect verdict with the reason.

**Controls**

- **Time scrubber** (bottom) — drag ±12 h to see the sky at any moment
  (planning); **● Live** returns to now. The header shows a `⏱ ±Hh Mm` flag when
  scrubbed. The stars, Sun, Moon and planets move from their ephemerides, and the
  **GNSS satellites move too** via an **approximate circular-orbit model**: each
  satellite's geocentric position is reconstructed from its az/el plus a
  per-constellation nominal orbit radius, its orbital plane is *learned from the
  motion seen between live polls*, then advanced at the Keplerian mean rate.
  Scrubbed (modeled) satellites draw **dashed**, and the header/card say
  `sats modeled`. It is deliberately approximate — it ignores eccentricity, J2
  drift and mixed-altitude constellations, and can only propagate satellites that
  are *visible now* (it cannot show ones that rise later), so the sat sky thins as
  you scrub hours out. At offset 0 it is an exact no-op (measured az/el verbatim).
- **One consistent satellite set.** The **panorama**, the **GNSS radar** minimap,
  and the **GNSS quality** card are all driven by the *same* satellite array, so
  their counts agree: the card shows `In view / tracked` and how many sats the
  PDOP solution used, and the radar caption echoes `N in view · M tracked`.
  Satellites everywhere use one visual language — a constellation-coloured marker,
  **filled/solid = SNR-locked**, **hollow/dim = visible-only**, **dashed =
  modeled**. On the radar the old green dots are now the **🛰 glyph** inside a
  constellation-coloured ring.
- **Zoom / pan**, click-through info cards, the **GNSS radar** minimap, and a
  **📷 snapshot** button (header) that rasterises the current sky to a PNG.

Still no external libraries or CDN — the astronomy math (Sun/Moon low-precision
ephemerides, DOP inversion) is plain JS, and the two new catalogs are bundled
locally alongside the existing star catalog.

---

## Payload shape

`collect()` returns (fields degrade to `null` / `[]` on error):

```json
{
  "generated_at": 1721557200.0,
  "power":  { "usb_devices": [...], "usb_count": 3, "usb_declared_ma": 1400,
              "throttled": {...}, "pmic": {...}, "core_volts": 5.05,
              "temp_c": 47.2, "model": "Raspberry Pi 5 ...",
              "usb_max_current_enabled": true },
  "radios": [ { "name": "wlan1", "scanning": true, "excluded_reason": null,
                "rfkill_blocked": false, "mode": "managed", "operstate": "up",
                "is_management": false, "driver": "mt7921u", "usb": {...} } ],
  "gps":    { "present": true, "status": {...},
              "constellations": [ { "talker": "GP", "constellation": "GPS",
                                    "in_view": 8, "snr_max": 42, "age_s": 0.4 } ],
              "sky": [ { "constellation": "GPS", "talker": "GP", "prn": 16,
                         "az": 208, "elev": 57, "snr": 39 } ],
              "port": "gpsd", "use_gpsd": true, "baudrate": null, "ttff_s": 31 },
  "errors": [ { "source": "gps", "message": "No NMEA sentence for 45s ...",
                "severity": "error" } ]
}
```
