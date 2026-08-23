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

Any **RTL2832U**-based dongle works — Ragnar shells out to the standard
`rtl_power` / `rtl_433` / `rtl_test`, so it's brand-agnostic. Tested/supported
families, with what Ragnar shows for each:

| Dongle | Tuner | Ragnar shows | Notes |
|---|---|---|---|
| **RTL-SDR Blog V3** (RTL-SDR.com) | R820T2 | `RTL-SDR Blog V3` | TCXO, HF direct-sampling, software bias-tee. Works with the stock driver. |
| **RTL-SDR Blog V4** (RTL-SDR.com) | **R828D** | `RTL-SDR Blog V4` ⚠ | **Needs the RTL-SDR Blog librtlsdr fork** — the stock distro driver mis-tunes the R828D (see below). |
| **Nooelec NESDR** (SMArt / Nano / Mini 2+) | R820T2 | `Nooelec NESDR …` | TCXO models recommended. Works with the stock driver. |
| **Generic RTL2832U** (R820T / R820T2 / R860) | R820T/T2 | `RTL-SDR (R820T2)` | Any no-name stick. Works with the stock driver. |

Ragnar identifies the dongle from its USB product string and tuner chip
(`rtl_sdr.py` → `identify_model`). When a vendor flashed an EEPROM string
("Blog V4", "NESDR SMArt", …) that name is used verbatim; otherwise the tuner
chip decides (an **R828D** tuner is reported as a Blog V4).

The dongle draws real USB current — a **powered USB hub** is recommended on the
Pi (see the undervoltage note in the HackRF section). Leaving the tab, or
switching modes, stops the capture and frees the dongle.

**The tab's buttons stay greyed until Ragnar detects a dongle.** It polls
`/api/net/rtl/status` and un-greys once `rtl_test -t` answers.

Install the tools (done by `install_ragnar.sh`, ensured by `update_ragnar.sh`):

```bash
sudo apt install rtl-sdr rtl-433
```

The installer/updater also **blacklists the DVB-T kernel driver**
(`dvb_usb_rtl28xxu`, via `/etc/modprobe.d/blacklist-rtl-sdr.conf`) that would
otherwise grab the dongle before `rtl_*` can, and unloads it on the spot so a
plugged-in stick works without a reboot. If you set one up by hand: blacklist
that module, replug, and confirm with `rtl_test -t`.

### RTL-SDR Blog V4 (R828D) driver

The V4 swapped the R820T2 tuner for an **R828D**, which the *stock* Debian /
Raspberry Pi OS `librtlsdr` does not tune correctly — the sweep appears but lands
on the wrong frequencies. The V4 needs the **RTL-SDR Blog fork** of `librtlsdr`.
Ragnar detects the R828D tuner and flags it in the SDR tab ("⚠ needs Blog
driver"). To install the fork:

```bash
sudo apt purge -y ^librtlsdr        # remove the stock lib
sudo apt install -y libusb-1.0-0-dev git cmake pkg-config
git clone https://github.com/rtlsdrblog/rtl-sdr-blog
cd rtl-sdr-blog && mkdir build && cd build
cmake ../ -DINSTALL_UDEV_RULES=ON && make -j"$(nproc)"
sudo make install && sudo ldconfig
```

The V3, Nooelec and generic (R820T2) dongles need none of this — they work with
the stock driver as soon as the DVB blacklist is in place.

### Troubleshooting "not detected"

Detection runs a ladder (`rtl_sdr.py` → `detect`): `rtl_test -t` to open the
radio, then an `lsusb` VID:PID fallback (`0bda:2838`/`2832` and common rebadges)
so a plugged-in dongle is still reported when the tools are missing or the DVB
driver is holding it. That lets `/status` tell three cases apart:

- **`usb_id: null`, `device_present: false`** — the dongle is **not on the USB
  bus at all**. This is below Ragnar: check power and the cable/port. RTL-SDR
  dongles (NESDR SMArt especially, with its TCXO + LNA) draw ~300 mA; on a Pi
  that's browning out (`vcgencmd get_throttled` != `0x0`) the port may fail to
  enumerate it. Use a solid PSU + a **powered USB hub**, a *data* cable (not
  charge-only), and confirm with `lsusb` that a `Realtek ... RTL283x` line shows.
- **`device_present: true` but `available: false`** — the dongle *is* on the bus
  but `rtl_test` can't open it: either the rtl-sdr tools aren't installed, or the
  DVB-T driver still holds it (blacklist `dvb_usb_rtl28xxu`, replug).
- **`available: true`** — good; the SDR tab and RF Waterfall button light up.

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
