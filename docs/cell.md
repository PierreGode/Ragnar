# Supported Cellular Modems (Wardriving Cell-Tower Capture)

Ragnar's wardriving cell-tower capture is built entirely around **ModemManager
(`mmcli`)**. To log cell towers you need a modem that presents as a real
ModemManager modem in **QMI / MBIM / serial** mode — **not** a USB
tethering / RNDIS / HiLink network interface, and **not** a self-contained
hotspot (e.g. Orbic Speed) shared over USB.

Confirm any device with `mmcli -L` — if it lists the modem, cell capture works.

## Quectel
- EG25-G
- EC25 (EC25-E / EC25-A / EC25-AF)
- EC21
- EP06
- EM06
- EM12-G
- EM120K / EM160R-GL
- RM500Q-GL (5G)
- RM502Q-AE (5G)
- RM520N-GL (5G)

## SIMCom
- SIM7600 (G-H / E / A variants)
- SIM7100
- SIM7080G (NB-IoT / Cat-M)
- SIM8200EA-M2 (5G)
- SIM8202G-M2 (5G)

## Sierra Wireless
- MC7455
- MC7430 / MC7421
- EM7455
- EM7565
- EM7690 (5G)
- WP7607

## Telit
- LN940
- LM940
- FN980 (5G)
- FN990 (5G)

## Fibocom
- L850-GL
- L860-GL
- FM150-AE (5G)
- FM350-GL (5G)

## Huawei (must be in QMI/MBIM/stick mode, NOT HiLink)
- ME909s-120
- MS2131
- E3372 (only the "stick"/NCM-switchable variant, mode-switched off HiLink)

## u-blox
- LARA-R6
- TOBY-L2

## Notes
- This is the practically-tested set, not ModemManager's full list — the
  official compatibility list is very large and grows each release.
- Any modem must present as **QMI / MBIM / serial**, not RNDIS/HiLink tethering.
- A **SIM is required** — serving-cell data (cell-id / MCC / MNC / LAC /
  operator) only appears once the modem registers on a network.
- `--3gpp-scan` (neighbor towers) support varies by modem/firmware; without it
  you still get the *serving* cell. Some modems refuse the scan during an active
  data session.
- Most 5G modules are M.2 / mini-PCIe → use a USB adapter/enclosure on a Pi.
- **Won't work:** USB-tethered hotspots (Orbic Speed, MiFi units) and HiLink
  dongles — they expose a network interface, not a controllable modem.
