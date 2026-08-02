# 🐝 Pwnagotchi Bridge — Setup, Switching & Troubleshooting

Ragnar includes a built-in bridge that lets you swap between Ragnar and [Pwnagotchi](https://github.com/PierreGode/pwnagotchiworking) on the same device. Both share the e-paper display and GPIO pins, so only one can run at a time. The swap is handled through systemd service orchestration.

---

## 📋 Requirements

| Component | Details |
|-----------|---------|
| **Board** | Raspberry Pi Zero 2 W (or any Pi with wireless) |
| **Display** | Waveshare 2.13" e-Paper HAT (V4 preferred, V2 supported) |
| **WiFi for monitor mode** | USB WiFi adapter on `wlan1` **or** onboard WiFi with nexmon (see below) |
| **Disk space** | ≥ 300 MB free |
| **Swap button (optional)** | PiSugar 3 (double-tap or long-press to swap modes) |

### WiFi & Monitor Mode

Pwnagotchi needs a wireless interface in **monitor mode** to capture WPA handshakes. There are two ways to provide this:

#### Option A — USB WiFi Adapter (recommended)

Plug in a USB adapter that supports monitor mode. The installer auto-detects the first `wlan*` interface that isn't `wlan0` and writes it into the config. Confirmed-working chipsets:

- Atheros AR9271 (Alfa AWUS036NHA)
- Ralink RT5370
- Realtek RTL8812AU (with `aircrack-ng` driver)

#### Option B — Onboard WiFi with Nexmon (advanced)

The Broadcom BCM43436s on the Pi Zero 2 W does **not** support monitor mode out of the box — `iw` will return `Operation not supported (-95)`. You can unlock it by building [nexmon](https://github.com/seemoo-lab/nexmon) firmware patches for your exact kernel version:

1. Build nexmon drivers and firmware from source for your running kernel.
2. Install the patched firmware blob and `nexutil`.
3. Edit `/usr/bin/monstart` and `/usr/bin/monstop` to use nexmon commands instead of standard `iw` monitor-mode creation (see [Customising monstart/monstop](#customising-monstartmonstop) below).
4. Set `iface = "wlan0"` in `/etc/pwnagotchi/config.toml` since there is no secondary adapter.

> **Note:** Nexmon patches are kernel-version-specific. A kernel update will break monitor mode until you rebuild.

---

## ⚡ Installation

```bash
cd /home/ragnar/Ragnar
sudo ./scripts/install_pwnagotchi.sh
```

The script:

1. Clones [pwnagotchiworking](https://github.com/PierreGode/pwnagotchiworking) into `/opt/pwnagotchi`
2. Installs Python dependencies (scapy, flask-cors, gpiozero, etc.)
3. Patches Pillow 10+ compatibility (`ImageFont.getsize` shim)
4. Detects the WiFi interface for monitor mode
5. Generates `/usr/bin/monstart` and `/usr/bin/monstop`
6. Writes `/etc/pwnagotchi/config.toml`
7. Creates RSA keys and log directories
8. Registers `pwnagotchi.service` (disabled by default)

Re-running is safe — already-installed packages are skipped.

### Installation Check & Repair (dashboard)

The **Pwnagotchi Bridge** settings section shows an **Installation Check** card that
validates each piece of a working install independently rather than treating it as
all-or-nothing:

| Component | Path / check |
| --- | --- |
| `/opt/pwnagotchi clone` | `/opt/pwnagotchi` directory present |
| git metadata | `/opt/pwnagotchi/.git` present (needed for in-app updates) |
| `pwnagotchi.service` unit | `/etc/systemd/system/pwnagotchi.service` present |
| service wired to launcher | unit's `ExecStart` points at `/usr/bin/pwnagotchi-launcher` (so MANU/AUTO flags work) |
| `config.toml` | `/etc/pwnagotchi/config.toml` present |
| launcher wrapper | `/usr/bin/pwnagotchi-launcher` present and executable |
| pwnagotchi executable | real `pwnagotchi` binary resolvable |
| pwnagotchi + pydrive2 import | `import pwnagotchi, pydrive2` succeeds in a clean interpreter (the launcher will start instead of exit-coding) |

Each row shows ✓ / ✗. The badge reflects three states:

- **Healthy** — everything present.
- **Needs Repair** (red) — a *critical* piece is missing: the clone, service unit,
  `config.toml`, launcher wrapper, the executable, or the **runtime import**.

> **Why the runtime-import row exists:** the pip steps in the installer all swallow
> their own errors so a flaky network never aborts an install. The cost was that a
> reinstall could report success while the `pwnagotchi` package or its crash-on-start
> dependency `pydrive2` never actually landed — the service is launched on demand, so
> the breakage only surfaced as an exit code (status=127 for a missing binary, status=1
> for a missing import) the moment you swapped. The installer now **verifies the runtime
> before claiming success** (and fails with the real cause otherwise), and this row keeps
> the dashboard honest so a half-installed box shows *Needs Repair* rather than a green
> badge that exit-codes on launch.
- **Degraded** (amber) — only recommended pieces are missing (git metadata, or the
  service `ExecStart` no longer points at the launcher). Pwnagotchi still runs, but
  updates or the MANU/AUTO flags may not work.

Whenever anything is missing a **Repair Installation** button appears — it re-runs
the idempotent installer to restore the missing pieces without touching your
captures or config.

A **Reinstall (clean)** button is **always** shown, even when Healthy. It runs the
installer with `--clean`, which stops the services, wipes `/opt/pwnagotchi`, and
regenerates `config.toml` fresh (the old one is copied to
`config.toml.bak.<timestamp>` first — it is **never** left deleted, so an
interrupted reinstall can't strand the box without a config), then rebuilds
everything from scratch. Handshakes/captures are left untouched.
(Manual equivalent: `sudo ./scripts/install_pwnagotchi.sh --clean`.)

> During a clean reinstall the clone is briefly absent while it re-downloads, so
> the Installation Check badge shows **Installing…** (not a red *Needs Repair*)
> until it finishes.

### Does Pwnagotchi's own updater conflict with Ragnar's?

It can. Pwnagotchi ships an `auto-update` plugin that pulls upstream releases on its
own. Left enabled it would fight Ragnar's git updater over `/opt/pwnagotchi` (dirtying
the clone) and can revert `pwnagotchi.service` `ExecStart` back to the raw binary —
breaking the flag-aware launcher wiring (MANU/AUTO). The Ragnar installer therefore
sets `main.plugins.auto-update.enabled = false`, making Ragnar the single update
authority. If an older install drifted, the **Installation Check** card flags it and
the `ragnar-pwn-migrate` boot unit + **Repair** both restore the launcher wiring.

The check is exposed via `GET /api/pwnagotchi/status` under `components`,
`missing_critical`, `missing_optional`, `healthy`, and `needs_repair`.

---

## 🔧 Configuration

### /etc/pwnagotchi/config.toml

Key settings generated by the installer:

```toml
[main]
name = "RagnarPwn"
iface = "wlan1"                    # station interface (change if needed)
mon_iface = "mon0"                 # monitor interface name
mon_start_cmd = "/usr/bin/monstart"
mon_stop_cmd = "/usr/bin/monstop"

[ui.display]
enabled = true
type = "waveshare_4"
rotation = 180

[ui.web]
enabled = true
address = "0.0.0.0"
port = 8080
username = "ragnar"
password = "ragnar"
```

**If the installer picked the wrong interface**, edit `iface` to match your actual wireless interface (run `ls /sys/class/net/` to check).

### Customising monstart/monstop

The default scripts use standard `iw` commands:

```bash
# /usr/bin/monstart (default)
iw dev $STA_IF interface add $MON_IF type monitor
ip link set $MON_IF up
```

For **nexmon** on the onboard Broadcom chip, replace with something like:

```bash
# /usr/bin/monstart (nexmon example)
ifconfig wlan0 down
nexutil -m2                        # enable monitor mode via nexmon
iw phy $(iw dev wlan0 info | grep wiphy | awk '{print "phy"$2}') \
    interface add mon0 type monitor
ifconfig mon0 up
```

```bash
# /usr/bin/monstop (nexmon example)
ifconfig mon0 down
iw mon0 del
nexutil -m0                        # back to managed mode
ifconfig wlan0 up
```

Adapt the exact commands to your nexmon version and kernel.

---

## 🔄 Switching Modes

### Ragnar → Pwnagotchi

**Via Web UI:** Open Ragnar dashboard → **Config** tab → **Pwnagotchi Bridge** → **Switch to Pwnagotchi**

**Via PiSugar button:** Double-tap or long-press

**What happens internally:**

1. Ragnar shows "Switching to Pwnagotchi..." on e-paper
2. A transient systemd unit (`ragnar-to-pwnagotchi-swap`) is created via `systemd-run` to survive Ragnar's cgroup teardown
3. The sequence runs:
   ```
   systemctl stop ragnar.service
   python3 -OO /home/ragnar/Ragnar/wipe_epd.py   # release GPIO/SPI
   systemctl start bettercap.service               # API on port 8081
   systemctl start pwnagotchi.service              # connects to bettercap
   systemctl start ragnar-swap-button.service       # listen for swap-back
   ```
4. Pwnagotchi web UI becomes available at `http://<ip>:8080`

### Pwnagotchi → Ragnar

**Via Web UI:** From the Pwnagotchi portal open `http://<ip>:8080/plugins/ragnar_return`
→ **Return to Ragnar**. The page triggers the swap and then **redirects your
browser to `http://<ip>:8000`** automatically once Ragnar is back — so the tab
doesn't get stuck on the dead :8080 portal. It also follows Ragnar back if you
trigger the swap with the hardware button while that page is open.

**Via PiSugar button:** Double-tap or long-press

**Via physical button:** Press KEY1 on the e-Paper HAT

> **Why a plugin?** The :8080 portal is served by Pwnagotchi, not Ragnar, so only
> a page served from :8080 can redirect that tab. The hardware button can move the
> *service* to :8000 but has no way to move your *browser* — that's what the
> `ragnar_return` web plugin adds. It's symlinked into
> `/etc/pwnagotchi/custom_plugins/` and enabled (`main.plugins.ragnar_return.enabled = true`)
> by the installer.

**What happens internally:**

1. The button press (`ragnar-swap-button.service`, 10-second cooldown) **or** a POST
   to `/plugins/ragnar_return/swap` from the web plugin triggers the swap
2. A transient systemd unit (`pwnagotchi-to-ragnar-swap`) runs:
   ```
   systemctl stop pwnagotchi.service
   systemctl stop bettercap.service
   systemctl stop ragnar-swap-button.service
   sleep 2
   systemctl start ragnar.service
   ```
3. Ragnar cleans up leftover state on startup (removes `mon0`, stops any lingering services)

### Manual (MANU) vs Auto mode

By default Pwnagotchi boots in **AUTO** mode and immediately starts hunting handshakes. To boot it **paused** in **MANU** mode instead, enable **Start in Manual mode** in the **Swap Control** card (Config tab → Pwnagotchi Bridge) *before* switching. The preference persists and applies to every subsequent Pwnagotchi launch (swap, button, or reboot) until you turn it off.

**How it works:** the Ragnar-managed launcher (`/usr/bin/pwnagotchi-launcher`, the `ExecStart` of `pwnagotchi.service`) checks for boot-mode flags before starting Pwnagotchi:

| Flag | Effect | Lifetime |
|------|--------|----------|
| `/root/.pwnagotchi-manual` | start with `--manual` | one-shot (deleted on read) |
| `/root/.pwnagotchi-auto` | force AUTO this boot | one-shot (deleted on read) |
| `/etc/pwnagotchi/.ragnar-manual-mode` | start with `--manual` | persistent (Ragnar toggle) |

The one-shot flags are what Pwnagotchi's own web UI MANU/AUTO buttons write, so those now stick across the restart they trigger. The persistent file is managed by the Ragnar toggle.

### Button Reference

| Button Action | While Ragnar is running | While Pwnagotchi is running |
|---------------|------------------------|---------------------------|
| Single tap    | Toggle manual mode      | —                          |
| Double tap    | Switch to Pwnagotchi    | Switch to Ragnar           |
| Long press    | Switch to Pwnagotchi    | Switch to Ragnar           |

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/pwnagotchi/status` | Install state, current mode, metadata |
| `POST` | `/api/pwnagotchi/install` | Start the installer |
| `GET`  | `/api/pwnagotchi/logs` | Stream installer/service logs |
| `POST` | `/api/pwnagotchi/swap` | Schedule mode switch (accepts `manual` boolean) |
| `GET`  | `/api/pwnagotchi/manual-mode` | Whether Pwnagotchi boots in MANU mode |
| `POST` | `/api/pwnagotchi/manual-mode` | Toggle MANU boot mode (`enabled` boolean) |

---

## 🔍 Troubleshooting

### E-ink goes blank but Pwnagotchi never loads on port 8080

This means the switch started but Pwnagotchi crashed during startup. Check logs:

```bash
sudo journalctl -u pwnagotchi -n 80 --no-pager
sudo journalctl -u bettercap -n 40 --no-pager
```

### `error 400: exit status 1` — monitor mode fails

Bettercap runs `/usr/bin/monstart` and it fails. Diagnose:

```bash
# Test monitor interface creation directly
sudo /usr/bin/monstart

# Or manually
sudo iw dev wlan1 interface add mon0 type monitor
```

**Common causes:**

| Error | Cause | Fix |
|-------|-------|-----|
| `Operation not supported (-95)` | Onboard Broadcom chip without nexmon | Install nexmon or use a USB adapter |
| `No such device` | Wrong interface name in config | Edit `/etc/pwnagotchi/config.toml` and `/usr/bin/monstart` |
| `Device or resource busy` | NetworkManager holds the interface | Add to unmanaged list (see below) |
| Command not found | `iw` not installed | `sudo apt install iw` |

### NetworkManager holds the WiFi interface

```bash
sudo bash -c 'cat > /etc/NetworkManager/conf.d/unmanaged.conf << EOF
[keyfile]
unmanaged-devices=interface-name:wlan1;interface-name:mon0
EOF'
sudo systemctl restart NetworkManager
```

### Wrong interface auto-detected

The installer picks the first `wlan*` interface that isn't `wlan0`. If it guessed wrong:

```bash
# Check actual interfaces
ls /sys/class/net/

# Fix config
sudo nano /etc/pwnagotchi/config.toml   # update iface = "..."
sudo nano /usr/bin/monstart              # update STA_IF = "..."
sudo nano /usr/bin/monstop              # update STA_IF = "..."
```

### Ragnar won't start after a bad swap

```bash
sudo /home/ragnar/Ragnar/scripts/fix_services.sh
```

Or manually clean up:

```bash
sudo ip link set mon0 down 2>/dev/null
sudo iw mon0 del 2>/dev/null
sudo systemctl stop pwnagotchi bettercap ragnar-swap-button
sudo systemctl start ragnar
```

### Static IP recommended

WiFi may briefly reconnect with a different DHCP IP during a mode switch. Set a static IP:

```bash
sudo nmcli con mod "YOUR_WIFI_SSID" ipv4.method manual \
  ipv4.addresses "192.168.1.211/24" \
  ipv4.gateway "192.168.1.1" \
  ipv4.dns "192.168.1.1"
sudo nmcli con up "YOUR_WIFI_SSID"
```

Or set a DHCP reservation on your router. This only affects `wlan0` — the monitor interface (`wlan1`/`mon0`) is unaffected.
