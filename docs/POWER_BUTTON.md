# Pi 5 power button → Ragnar ⟷ Pwnagotchi toggle

On an all-in-one box you often have no e-Paper HAT KEY1 and no PiSugar, but the
Raspberry Pi 5 has a **dedicated on-board power button**. This optional add-on
turns a short press of that button into a one-touch swap between Ragnar
(dashboard `:8000`) and the built-in Pwnagotchi mode (web UI `:8080`).

It complements the existing swap controls (Web UI, PiSugar, e-Paper KEY1) — see
[PWNAGOTCHI.md › Switching Modes](PWNAGOTCHI.md#-switching-modes). Unlike the
PiSugar/KEY1 listener (`ragnar-swap-button.service`, which only swaps
Pwnagotchi → Ragnar), this listener runs in **both** modes and toggles either
direction, because Ragnar and Pwnagotchi never run at the same time.

## Install

```bash
sudo bash scripts/install_power_button.sh
```

Then short-press the power button to flip modes. Watch it work:

```bash
journalctl -u ragnar-power-toggle -f
```

## ⚠️ Behaviour change

A short press **no longer powers the Pi off** — it toggles the mode. Replacements:

| Action | Result |
|--------|--------|
| **Short press** | Toggle Ragnar ⟷ Pwnagotchi |
| **Long-hold (~10 s)** | Firmware hard power-off (unchanged) |
| `sudo poweroff` / dashboard | Clean shutdown |

## How it works

1. **`/etc/systemd/logind.conf.d/ragnar-power-toggle.conf`** sets
   `HandlePowerKey=ignore`, so systemd-logind stops shutting the Pi down on the
   power key. The firmware long-hold hard-off is unaffected.
2. **`ragnar-power-toggle.service`** runs `scripts/ragnar_power_toggle.py` in
   both modes. It reads `KEY_POWER` events straight from the `pwr_button` evdev
   device (`/dev/input/by-path/platform-pwr_button-event`) using the Python
   standard library only — no `python3-evdev` dependency.
3. On a press it checks `systemctl is-active ragnar.service` and launches the
   opposite swap as a `systemd-run` transient unit (`ragnar-to-pwn-swap` /
   `pwn-to-ragnar-swap`), so the stop/start sequence survives the cgroup it
   tears down — the same approach as `ragnar_swap_button.py`.
4. A **20-second cooldown** debounces the button: rapidly toggling the Wi-Fi
   adapter between managed and monitor mode can wedge the driver, so presses
   inside the window are ignored.

## Note for SPI-TFT kiosk builds

The installer applies the logind change with `systemctl reload systemd-logind`,
**not** a restart. Restarting systemd-logind tears down PAM-login sessions,
which kills the SPI-TFT kiosk (`ragnar-tft.service` logs in on vt7 via
`PAMName=login`). Normal power-button swaps never touch logind, so the kiosk
rides through every mode flip. If you ever change the logind drop-in by hand,
reload (don't restart) logind, or just `systemctl restart ragnar-tft.service`
afterwards.

## Uninstall

```bash
sudo bash scripts/uninstall_power_button.sh
```

Restores the default power-button behaviour (short press = power off). A reboot
fully re-applies the logind default.

## Compatibility

Requires the Pi 5 on-board `pwr_button` input device (present in
`/proc/bus/input/devices`). On boards that don't expose the power button as a
`KEY_POWER` event to userspace the installer warns and stops unless run with
`--force`.
