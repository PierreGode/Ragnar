# Running Ragnar in Docker

Ragnar can run as a container on any Linux host with Docker. The container runs
the **headless web UI** — the full dashboard, scanning engine, and network
watchers — without any Raspberry-Pi hardware (e-Paper display, buttons, UPS,
LED-matrix). Those are skipped automatically via `RAGNAR_HEADLESS=1`.

This is the easiest way to try Ragnar on an x86 server, a NAS, a VM, or a
Raspberry Pi you'd rather manage with Docker than the native installer.

---

## Quick start (Docker Compose)

```bash
git clone https://github.com/PierreGode/Ragnar.git
cd Ragnar
docker compose up -d --build
```

Then open **http://<host-ip>:8000**.

Follow logs with:

```bash
docker compose logs -f
```

Stop / start / update:

```bash
docker compose down                 # stop
docker compose up -d                # start
git pull && docker compose up -d --build   # update to latest
```

## Quick start (plain Docker)

```bash
docker build -t ragnar .

docker run -d --name ragnar \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD/data:/opt/ragnar/data" \
  -v "$PWD/config:/opt/ragnar/config" \
  -v "$PWD/certs:/opt/ragnar/certs" \
  ragnar
```

---

## Networking

Ragnar is a **LAN scanner**, so it needs to see your real network.

- **Host networking (recommended, default):** `--network host` puts the
  container directly on the host's network stack. ARP discovery, host
  inventory, and interface tooling all work against your physical LAN. The web
  UI is reachable on the host's own IP at port `8000`.
- **Bridge networking (fallback):** if you can't use host mode, comment out
  `network_mode: host` in `docker-compose.yml` and uncomment the `ports:` block
  (`8000:8000`). The UI still works, **but discovery is limited to Docker's
  bridge subnet** — you won't see your physical LAN.

`NET_ADMIN` and `NET_RAW` capabilities are granted so scapy, nmap, and tcpdump
can open raw sockets and (where supported) configure interfaces.

### Running alongside a native install (port conflict)

A native Ragnar install runs as the `ragnar` **systemd service** and already
binds port **8000**. A container in `network_mode: host` binds the host's 8000
directly, so the two collide — the container will fail to start with
`address already in use`. You have three options:

- **Use one or the other.** Docker is an alternative to the native install, not
  an addition. Stop the native service if you're switching:
  `sudo systemctl stop ragnar` (and `sudo systemctl disable ragnar` to keep it
  off across reboots).
- **Pick a different port (host mode).** Set `RAGNAR_WEB_PORT` — the app binds
  that port instead of 8000:
  ```bash
  RAGNAR_WEB_PORT=8010 docker compose up -d
  ```
- **Pick a different port (bridge mode).** Comment out `network_mode: host`,
  uncomment the `ports:` block, and map e.g. `8010:8000` — but remember bridge
  mode limits LAN discovery to Docker's subnet.

## Persistent data

Three directories hold all runtime state and are mounted as volumes:

| Path (host)  | Purpose                                             |
|--------------|-----------------------------------------------------|
| `./data`     | scan results, inventory, watcher state, databases   |
| `./config`   | `shared_config.json` and app configuration          |
| `./certs`    | TLS certificates (generated per host at runtime)    |

These survive `docker compose down` and image rebuilds. Files are written by the
container as **root**; if you edit them from the host you may need `sudo`.

## API keys / secrets (optional)

Features like the AI assistant or Pushover alerts read keys from the
environment. Create a `.env` file and enable it in `docker-compose.yml`:

```yaml
    env_file:
      - .env
```

Example `.env`:

```dotenv
OPENAI_API_KEY=sk-...
PUSHOVER_TOKEN=...
PUSHOVER_USER=...
```

`.env` is git-ignored and excluded from the image build context.

---

## What does NOT work in a container

The container is headless and hardware-agnostic. The following need physical
hardware and/or kernel access that a standard container doesn't have, so they
are unavailable (or need extra host wiring) under Docker:

- **e-Paper / LCD display, buttons, UPS, LED-matrix** — Pi-only, skipped.
- **Wi-Fi monitor mode / WiDS, wardriving, deauth defense** — need a monitor-mode
  capable adapter passed through to the container and host-level `rfkill`
  control. Use the native installer on a Pi for these.
- **GPS, SDR (HackRF/RTL-SDR), Zigbee/Meshtastic serial dongles, Bluetooth** —
  require USB device passthrough (`--device`) and are not wired up by default.
- **Host/Pi-only CLI tools** — `nmcli` (NetworkManager), `systemctl` (systemd),
  `vcgencmd`, `hostapd_cli`, `loginctl`. Features that call these degrade
  gracefully (logged, non-fatal); interface *viewing* and scanning still work.

For the full hardware experience (e-Paper HAT, radios, GPS), use the native
installer described in the main [README](../README.md).

## Updating

Two paths, and the durable one is a rebuild:

**Recommended — rebuild the image (durable):**

```bash
git pull                       # on the host, in your Ragnar clone
docker compose up -d --build   # rebuild + restart the container
```

**In-app Updates tab (works, but ephemeral):** `git` is installed in the image,
and the image ships without `.git` — which looks to Ragnar exactly like a
"tarball install". On the first update check the container self-reattaches to
upstream (`git init` + `fetch`, keeping the working tree) and the one-click
updater then works. **Caveat:** those updates land on the container's writable
layer, so they are lost the next time you rebuild or recreate the container
(they survive a plain `docker restart`). To make in-app updates persist, mount
the app directory as a volume; otherwise treat the rebuild flow as the real
update mechanism and the tab as a convenience.

## Troubleshooting

- **Can't reach the UI** — confirm the container is up (`docker compose ps`) and,
  if using bridge mode, that you uncommented the `ports:` block.
- **Empty host list** — you're almost certainly on bridge networking; switch to
  `network_mode: host`.
- **Permission errors on `./data`** — the container runs as root; `sudo chown`
  the directory back to your user if you need to edit it from the host.
- **`vulners.nse` missing** — a fully offline build skips it; nmap scans still
  run, just without CVE tagging. Rebuild with network access to fetch it.
