# Sub-GHz SDR (RTL-SDR)

Ragnar's **SDR** tab turns a cheap **RTL-SDR** dongle into two receive-only
sub-GHz tools. It's the low-band counterpart to the HackRF
[True-RF Waterfall](wifi-analyzer.md#true-rf-waterfall-hackrf-sdr): the RTL-SDR
**cannot** see the 2.4/5/6 GHz Wi-Fi bands (it tops out ~1.7 GHz), but the range
it *can* reach — the 433 / 868 / 915 MHz ISM bands — is where most of the
non-Wi-Fi world lives.

Everything here is **receive-only** — nothing ever transmits.

## The two tools

| Tool | Backed by | What it does |
|---|---|---|
| **📡 ISM Devices** | `rtl_433 -F json` | A live table of every device it decodes — TPMS tyre-pressure sensors, weather stations, door/window & PIR contacts, remotes/keyfobs, utility meters, doorbells — with model, id, RSSI, hit count, last-seen, and the decoded fields. |
| **📈 Sub-GHz Waterfall** | `rtl_power` | A scrolling power-vs-frequency heatmap (same look as the HackRF Waterfall) over 433 / 868 / 915 MHz or a wide **300–960 MHz** sweep. Raw energy only — no decode — for spotting activity, carriers and jammers below 1.7 GHz. |

## One dongle, one claim

An RTL-SDR is a single USB device only one program can open at a time. So the
two tools are **mutually exclusive** — starting one stops the other — and the
tab reflects that automatically. The same rule is why a device probe
(`rtl_test`) is never run while a capture is streaming: opening the dongle a
second time would knock the capture offline (the lesson learned from the HackRF
view). While anything is running, `/status` reports availability from a cached
probe instead of touching the bus.

## Hardware

Any **RTL2832U**-based dongle (RTL-SDR Blog V3/V4, generic R820T2/R860). The
dongle draws real USB current — a **powered USB hub** is recommended on the Pi
(see the undervoltage note in the HackRF section). Leaving the tab, or switching
modes, stops the capture and frees the dongle.

**The tab's buttons stay greyed until Ragnar detects a dongle.** It polls
`/api/net/rtl/status` and un-greys once `rtl_test -t` answers.

Install the tools (done by `install_ragnar.sh`, ensured by `update_ragnar.sh`):

```bash
sudo apt install rtl-sdr rtl-433
```

If the dongle isn't found, blacklist the DVB-T kernel driver that otherwise
grabs it (`dvb_usb_rtl28xxu`), replug, and confirm with `rtl_test -t`.

## API

| Route | Purpose |
|---|---|
| `GET  /api/net/rtl/status` | Dongle detection (gates the tab) + capture state for both modes |
| `POST /api/net/rtl/ism/start` `{band}` | Start the ISM scanner (433/868/915) |
| `POST /api/net/rtl/ism/stop` | Stop the ISM scanner |
| `GET  /api/net/rtl/ism/devices` | The live decoded-device table |
| `POST /api/net/rtl/power/start` `{band}` | Start the sub-GHz sweep (433/868/915/subghz) |
| `POST /api/net/rtl/power/stop` | Stop the sweep |
| `GET  /api/net/rtl/power/frames?since=` | New waterfall frames + max-hold since a seq |
| `GET  /api/net/rtl/selftest` | Offline parser / frame-assembly self-test |

## CLI

`rtl_sdr.py` runs standalone for quick checks (no web server needed):

```bash
python3 rtl_sdr.py detect
python3 rtl_sdr.py ism   --band 433 --seconds 20
python3 rtl_sdr.py power --band subghz --seconds 20
python3 rtl_sdr.py selftest
```

## Legality

Listening is passive, but decoding third-party device telemetry (TPMS, meters,
sensors) can be regulated where you live. Use it on your own devices and within
local law.
