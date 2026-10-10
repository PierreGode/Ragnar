# Ragnar OS — a prebuilt Raspberry Pi image

Ragnar OS is Raspberry Pi OS (64-bit) Lite with Ragnar already installed,
enabled and ready. Flash it, boot it, open the web UI — no install script, no
waiting for pip. It is meant for people who just want a Ragnar box without
running `install_ragnar.sh` by hand.

- [What you get](#what-you-get)
- [Flashing it](#flashing-it)
- [First boot](#first-boot)
- [Optional: ragnar.conf](#optional-ragnarconf)
- [Building the image yourself](#building-the-image-yourself)
- [How it is put together](#how-it-is-put-together)
- [Differences from a script install](#differences-from-a-script-install)

> For authorized penetration testing only. Unauthorized access to networks is
> illegal.

---

## What you get

- Raspberry Pi OS Lite (64-bit), so it runs on the Pi Zero 2 W, 3, 4, 5 and
  CM4/CM5 from one image.
- Ragnar preinstalled as a real `git` clone (so the in-app updater works) and
  enabled as a systemd service — the web UI comes up on first boot.
- Every display driver present, so you can attach a screen later without
  reinstalling. The image is **headless by default** (it never grabs a board's
  display pins unless you ask for a screen).
- Batteries included: the heavy scanners (Nuclei, Nikto, SQLMap, OWASP ZAP) are
  baked in by default, so everything Ragnar can do works offline on first boot.
  A board without the RAM to run them still boots fine — Ragnar's runtime RAM
  gate just keeps them idle. Want a smaller image instead? Build with
  `RAGNAR_INSTALL_ADVANCED=no ./os-image/build.sh` and those tools install on
  demand from the web UI later.
- Mesh- and attack-ready out of the box: the **Tailscale** client is baked in
  (binary only — it never joins a tailnet during imaging, so the web UI Mesh tab
  or a `/boot/firmware/ragnar-mesh.conf` can join with no download), and
  **AirSnitch** (the MacStealer / port-steal research tool) is cloned and built
  into `tools/airsnitch` so the Pentest tab's AirSnitch runs offline. Both are
  normally left as on-demand installs; the image bakes them in the stage script.

## Flashing it

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/):

1. **Choose OS → Use custom**, and select the downloaded
   `RagnarOS-*.img.xz` (from the project's GitHub Releases), **or** load the
   Ragnar custom OS list (`os-image/os-list.json`) so "Ragnar OS" appears in the
   list.
2. Click the gear / **Edit Settings** and set, at minimum, a **username and
   password** (Raspberry Pi OS no longer ships a default login) and your
   **Wi-Fi** if you want it to join your network straight away. These are
   standard Raspberry Pi OS settings and work normally on this image.
3. Write the card, put it in the Pi, power on.

You can also flash it with any tool that writes a `.img` — decompress first with
`xz -d RagnarOS-*.img.xz`.

## First boot

The first boot does a little per-device setup automatically (it generates unique
SSH host keys and a unique TLS certificate, then starts Ragnar). Give it a
minute or two.

Then reach the web UI:

- **On your network:** `http://<device-ip>:8000` (or `https://` on the same
  port). If you set a hostname in Imager, `http://<hostname>.local:8000` works
  too.
- **No network configured:** the device raises its own access point. Join Wi-Fi
  **`Ragnar`** (password **`ragnarconnect`**) and open
  **`http://192.168.4.1:8000`** to tell it which network to use. See
  [RagnarAP.md](RagnarAP.md).

## Optional: ragnar.conf

You usually do not need this. But if you want to set a hostname or turn on an
attached screen *without* touching the web UI, drop a file named `ragnar.conf`
onto the card's boot partition before first boot (it is a normal FAT partition —
edit it on any computer). A template is at `os-image/ragnar.conf.example`:

```ini
hostname=ragnar-01
display=epd2in13_V4
```

`display=` takes the same driver ids as **Config → Display** in the web UI
(e-Paper `epd*`, TFT/OLED `gc9a01` `ili9486` `ssd1306` `lcd1602` …, LED matrix
`max7219_*`). Setting it switches the service out of headless mode and lights up
the panel on that first boot. The file is read once and then ignored.

To join the Tailscale mesh unattended, drop a `ragnar-mesh.conf` instead (see
[mesh.md](mesh.md)).

## Building the image yourself

The image is built with [pi-gen](https://github.com/RPi-Distro/pi-gen) (the same
tool Raspberry Pi uses for Raspberry Pi OS). Everything lives under `os-image/`.

On a Raspberry Pi (or any arm64 Debian/Ubuntu host) with Docker:

```bash
sudo ./os-image/build.sh
```

On an x86 host or CI, the docker path handles the arm64 emulation for you. To
build natively instead (you supply pi-gen's build dependencies):

```bash
sudo PIGEN_NATIVE=1 ./os-image/build.sh
```

The finished image lands in `os-image/.pi-gen/deploy/` as `RagnarOS-*.img.xz`.
The build needs about 10 GB of free disk and an internet connection.

Useful overrides:

| Variable | Default | Purpose |
|---|---|---|
| `RAGNAR_REPO_BRANCH` | `main` | Ragnar branch baked into the image |
| `RAGNAR_REPO_URL` | upstream | Ragnar repo to clone |
| `PIGEN_REF` | `arm64` | pi-gen branch to pin |
| `PIGEN_NATIVE` | `0` | `1` = build without Docker |

CI builds it too: pushing a tag like `os-v1.0.0` runs
`.github/workflows/build-os-image.yml`, which builds the image and attaches
`RagnarOS-*.img.xz` (plus its `.sha256`) to the matching GitHub Release. A manual
run (workflow_dispatch) builds and uploads a workflow artifact without releasing.

## How it is put together

The build appends one pi-gen stage, `stage-ragnar`, on top of the stock Lite
rootfs (`stage0`→`stage2`). Inside the image chroot it:

1. clones Ragnar into `/home/ragnar/Ragnar` (a real `.git`, so updates work);
2. runs `install_ragnar.sh --image-build` with
   `RAGNAR_PROFILE=headless RAGNAR_INSTALL_ALL_DISPLAYS=1
   RAGNAR_INSTALL_ADVANCED=yes RAGNAR_FORCE_PI=1` (the advanced default is set
   by `build.sh` from `$RAGNAR_INSTALL_ADVANCED`). `--image-build` means the
   installer only *enables* units (never starts services, never reboots, never
   touches a live kernel), because there is no init in a chroot;
3. installs and enables `ragnar-firstboot.service`;
4. strips the baked SSH host keys, machine-id and any TLS cert so each device
   mints its own.

`--image-build` and `--unattended` are general-purpose: you can script a fresh
install on real hardware the same way (see `install_ragnar.sh --help`).

`scripts/ragnar-firstboot.sh` is the per-device finaliser. It runs once, ordered
before `ragnar.service`, regenerates anything that must be unique, applies
`ragnar.conf` if present, optionally joins the mesh, then disables itself.

## Differences from a script install

- Default profile is **headless** with all display drivers present — a script
  install asks you to pick one profile/display up front.
- Advanced scanners (Nuclei/Nikto/SQLMap/ZAP) are preinstalled by default
  (`RAGNAR_INSTALL_ADVANCED=yes`); a script install RAM-gates them. Build with
  `RAGNAR_INSTALL_ADVANCED=no` for a smaller image that installs them on demand.
- Everything else — the service, AP onboarding, the updater, sudoers, udev
  rules, system limits — is identical, because the image runs the very same
  installer.
