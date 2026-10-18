# Ragnar OS Ulfberht (offensive edition)

**Ragnar OS Ulfberht** is an offensive / red-team edition of [Ragnar OS](ragnar-os.md):
the same flash-and-go Ragnar appliance, but built on a **Kali Linux ARM base**
instead of Raspberry Pi OS Lite. It is for authorized security testing only.

> **Naming / trademark.** This image is *built from* Kali Linux but is **not**
> Kali, is not affiliated with or endorsed by OffSec, and deliberately does not
> carry the Kali name or branding. "Ulfberht" (a legendary Viking sword) is the
> Ragnar edition name. Kali™ is a trademark of OffSec.

## Why a Kali base

Two things the stock Raspberry Pi OS build can't give you:

- **Nexmon onboard Wi-Fi** — Kali's Raspberry Pi kernel ships Nexmon
  (`brcmfmac-nexmon-dkms` + `firmware-nexmon`), so the Pi's **built-in** Wi-Fi can
  do **monitor mode and frame injection with no USB adapter** (chipset-dependent;
  monitor/injection restored for the Pi 5 in Kali 2025.3). Ragnar's Wi-Fi
  analyzer, WIDS and wardriving can use the onboard radio directly.
- **The full offensive toolset in-repo** — nmap, aircrack-ng/wifite, hashcat,
  hydra, bettercap, responder, sqlmap, nikto, Metasploit, CrackMapExec/NetExec
  and friends are one `apt` away (and many are preinstalled), so Ragnar can
  surface them rather than re-bundle them.

Trade-offs: Kali is a **rolling** release (more churn than Debian stable), the
image is **larger**, and it leans harder on RAM — Ragnar's existing runtime RAM
gates (e.g. Nuclei/ZAP) still apply, more so on a 512 MB board.

## Supported Raspberry Pi models

Same arm64 range as the standard image:

| Board | Ulfberht |
|---|---|
| Pi 5, Pi 4 / 400, Pi 3 / 3+, CM4 / CM5 | ✅ arm64 |
| Pi Zero 2 W | ✅ arm64 |
| Pi 1 / original Pi Zero / Zero W | ❌ ARMv6 — Kali dropped ARMel |

## The "hidden switch" — edition detection

The extended capabilities belong to the **official Ulfberht image only**, not to
any Kali box. Detection (`ragnar_edition.py`, exposed at `GET /api/edition`) keys
off a **build-time marker** — `/etc/ragnar-edition` — that the image build writes
and that `install_ragnar.sh` never creates. So:

- On the official **Ulfberht image**, the **System** tab reveals an edition card:
  the **Ulfberht** badge + build info, **Nexmon status** (onboard monitor mode /
  injection), and the **offensive tools detected on `PATH`** as reference chips.
- On the standard Ragnar OS image — *and on anyone's own Kali box where they
  simply `git clone` Ragnar and run the installer* — there is no marker, so it
  reports `edition=standard` and nothing new appears. Being Kali-based is
  deliberately **not** enough; only this image carries the marker.

The switch is purely additive: a standard box never sees it.

## Coordinated workflows (Engagements)

Ulfberht's headline capability is the **Engagements** engine — marker-gated
playbooks that chain **discovery → diagnostics → assessment → reporting** over
one scope into one NIST SP 800-115-aligned report, rather than a loose pile of
tools. It appears as the **⚔️ Engagements** tab (and an **Arsenal** panel on the
Pentest tab) on the official image only. See
[Ulfberht Engagements](ulfberht-workflows.md).

## Flashing & first boot

1. Open the [Releases page](https://github.com/PierreGode/Ragnar/releases) (tag
   `os-ulfberht-vX.Y.Z`). The image is **~4.3 GB** — larger than GitHub's 2 GiB
   per-asset limit — so the release carries the `.sha256` and the release notes
   link to the single `RagnarOS-Ulfberht-arm64.img.xz` hosted on **Proton Drive**.
   Download the image from that link and verify it against the published
   `sha256` before flashing:
   ```bash
   sha256sum -c RagnarOS-Ulfberht-arm64.img.xz.sha256   # must print: OK
   ```
2. Write it with Raspberry Pi Imager (or `dd`) to an SD card / USB / NVMe.
3. Boot headless. The web UI is on **`:8000`**. No network yet? Join Wi-Fi
   **`Ragnar`** (pass `ragnarconnect`) and open `http://192.168.4.1:8000` to
   onboard. Per-device SSH host keys and the TLS cert are regenerated on first
   boot, same as the standard image.

The Kali base keeps its own console login (`kali` / `kali` by default — change
it); Ragnar itself runs as the `ragnar` service user, exactly as on the standard
image.

## How the image is built

The recipe lives in the **private** `PierreGode/RagnarOS` pipeline (the app stays
public). Unlike the standard image (pi-gen), Ulfberht is built by **customizing
the official Kali Raspberry Pi arm64 image** — the most reliable path, because it
reuses Kali's known-good kernel, Nexmon and bootloader:

1. Download + checksum-verify the current official Kali RPi arm64 image.
2. Expand the root filesystem, loop-mount it, and `chroot` in (native arm64 — no
   qemu on the Pi build runner).
3. Run `install_ragnar.sh --image-build` inside the chroot (unattended,
   build-safe, `RAGNAR_FORCE_PI=1`), exactly as the standard image does — the
   installer is Debian-family and recognizes the Kali base.
4. Bake the Ragnar extras (Tailscale client, AirSnitch), ensure the Nexmon
   packages are present, wire the per-device first-boot unit, strip baked
   identity, and repack to `RagnarOS-Ulfberht-arm64.img.xz`.

CI publishes a release on the public repo when an **`os-ulfberht-v*`** tag is
pushed to the private repo; `workflow_dispatch` builds a test artifact from any
Ragnar branch. Because the finished `.img.xz` is well over GitHub's 2 GiB
per-asset limit, the release ships the `.sha256` and links out to the image on
external storage (Proton Drive) rather than attaching the image itself.

See also: [Ragnar OS (standard image)](ragnar-os.md).
