"""
Bluetooth PAN (NAP) — a direct Bluetooth link to the box.

Turns the box into a Bluetooth **network access point** so a phone can reach it
over Bluetooth when Tailscale or Wi-Fi can't (no internet, a locked-down
network, out in the field). The box runs a NAP server (`bt-network -s nap`)
bridged to a private ``pan0`` bridge on 192.168.44.0/24, with a scoped dnsmasq
handing the phone an address and a `bt-agent` accepting "just works" pairing.

On the phone (Android only — iOS does not support Bluetooth PAN to a device like
this): pair the box in the system Bluetooth settings, turn on tethering /
"Internet access" for it, then open the Ragnar Mobile app and connect to
``192.168.44.1:8000`` (its default Bluetooth address). The app itself speaks no
Bluetooth — the phone's OS provides the IP link and the app just talks HTTP.

Everything here is **opt-in** (``bt_pan_enabled``) and **fully reversible**:
:meth:`stop` removes the NAP server, the pairing agent, dnsmasq, and the bridge,
leaving networking exactly as it was. The link carries **no default route**, so
turning it on never hijacks the phone's own internet — the phone reaches only
the box on 192.168.44.0/24.

    ┌─────────┐  Bluetooth   ┌──────── box ────────┐
    │  phone  │  PAN/bnep    │  pan0 bridge         │
    │ .44.x   │─────────────▶│  192.168.44.1  :8000 │
    └─────────┘              │  dnsmasq (DHCP only) │
                             │  bt-network -s nap   │
                             └──────────────────────┘

This is receive-only from a networking standpoint (no forwarding/NAT), so it can
never bridge the phone's traffic onto the box's other networks.

NOTE: needs on-device validation with a real Android phone — the pairing +
tethering handshake is the one part that cannot be exercised without hardware.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

# --- Fixed, self-contained topology -----------------------------------------
BRIDGE = "pan0"
GATEWAY = "192.168.44.1"
CIDR = "192.168.44.1/24"
DHCP_LO = "192.168.44.10"
DHCP_HI = "192.168.44.50"
DNSMASQ_CONF = "/tmp/ragnar/btpan-dnsmasq.conf"
DNSMASQ_PID = "/tmp/ragnar/btpan-dnsmasq.pid"

# What the phone sees when it scans for the box. Set as the adapter Alias while
# the NAP is up; cleared (reverts to the hostname) when it comes down.
ADAPTER_ALIAS = "Ragnar"

# Class-of-Device advertised while the NAP is up: Networking service class +
# LAN Access Point major device class. Without this the box's audio stack
# (pipewire/wireplumber register A2DP) leaves the adapter flagged as an
# audio/rendering device, so a phone pairs it as "headphones" and never offers
# the Bluetooth-tethering ("Internet access") toggle that the PAN needs.
NAP_CLASS = "0x020300"

_CMD_TIMEOUT = 8.0
_DBUS_TIMEOUT = 5.0

# Which apt package provides each runtime tool the NAP needs. `ip` comes from
# iproute2, which is always present, so it is not part of the installable set.
_TOOL_PKG = {
    "bt-network": "bluez-tools",
    "bt-agent": "bluez-tools",
    "dnsmasq": "dnsmasq",
}
# bridge-utils is not strictly required (we bring the bridge up with `ip link`),
# but installing it alongside is harmless and matches what other setups expect.
_INSTALL_PACKAGES = ["bluez-tools", "dnsmasq", "bridge-utils"]


def _priv(cmd: list[str]) -> list[str]:
    """Prefix ``sudo -n`` unless we are already root (ragnar.service runs as
    root; a dev shell may not). Mirrors the rest of the codebase."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return cmd
    return ["sudo", "-n"] + cmd


def _run(cmd: list[str], timeout: float = _CMD_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(_priv(cmd), capture_output=True, text=True, timeout=timeout)


def _ok(cmd: list[str], timeout: float = _CMD_TIMEOUT) -> bool:
    try:
        return _run(cmd, timeout).returncode == 0
    except Exception as exc:  # noqa: BLE001 - never let a shell-out raise
        logger.debug("[btpan] %s failed: %s", cmd, exc)
        return False


def _tool(name: str) -> bool:
    from shutil import which
    return which(name) is not None


class BtPanServer:
    """Orchestrates the NAP server, pairing agent, dnsmasq and the bridge."""

    def __init__(self, hci: str = "hci0"):
        self.hci = hci
        self._lock = threading.Lock()
        self._procs: dict[str, subprocess.Popen] = {}
        self._error: str | None = None
        self._started_at: float | None = None
        self._trust_thread: threading.Thread | None = None
        self._trust_stop = threading.Event()

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> dict:
        with self._lock:
            missing = [t for t in ("bt-network", "bt-agent", "dnsmasq", "ip") if not _tool(t)]
            if missing:
                self._error = f"missing tools: {', '.join(missing)}"
                return self._status_locked()

            try:
                self._bring_up_adapter()
                self._bring_up_bridge()
                self._start_dnsmasq()
                self._start_agent()
                self._start_nap()
                self._configure_adapters(True)
                self._set_network_class()
                self._start_trust_loop()
                self._error = None
                self._started_at = time.time()
                logger.info("[btpan] NAP up on %s (%s)", BRIDGE, GATEWAY)
            except Exception as exc:  # noqa: BLE001
                self._error = str(exc)
                logger.error("[btpan] start failed: %s", exc)
                self._teardown_locked()
            return self._status_locked()

    def stop(self) -> dict:
        with self._lock:
            self._teardown_locked()
            self._started_at = None
            logger.info("[btpan] NAP down")
            return self._status_locked()

    # -- steps ---------------------------------------------------------------
    def _bring_up_adapter(self) -> None:
        # New BT dongles can boot rfkill-blocked; unblock before touching them.
        # Powering + naming + discoverability are done over D-Bus in
        # _configure_adapters (bluetoothctl hangs on a busy stack here).
        _ok(["rfkill", "unblock", "bluetooth"])

    def _bring_up_bridge(self) -> None:
        # Idempotent: leave an existing bridge in place, just ensure addr + up.
        exists = _ok(["ip", "link", "show", BRIDGE])
        if not exists and not _ok(["ip", "link", "add", "name", BRIDGE, "type", "bridge"]):
            raise RuntimeError(f"could not create bridge {BRIDGE}")
        # Adding an address that already exists returns non-zero; ignore that.
        _run(["ip", "addr", "add", CIDR, "dev", BRIDGE])
        if not _ok(["ip", "link", "set", BRIDGE, "up"]):
            raise RuntimeError(f"could not bring up {BRIDGE}")

    def _start_dnsmasq(self) -> None:
        os.makedirs("/tmp/ragnar", exist_ok=True)
        # A stale instance from a crash/restart would hold the pan0 address; kill
        # it by its pid file first (targets only OUR dnsmasq, never the AP one).
        self._kill_dnsmasq()
        # DHCP only (port=0 = no DNS), bound to pan0 alone so it can never touch
        # another network, and NO default route advertised (option 3 empty) so
        # the link never hijacks the phone's own internet.
        conf = (
            f"interface={BRIDGE}\n"
            "bind-interfaces\n"
            "except-interface=lo\n"
            "port=0\n"
            f"dhcp-range={DHCP_LO},{DHCP_HI},255.255.255.0,1h\n"
            "dhcp-option=3\n"
        )
        with open(DNSMASQ_CONF, "w") as fh:
            fh.write(conf)
        # Daemonised with its own pid file, so it is managed by pid (no fragile
        # pattern matching that could hit the AP-mode dnsmasq or a sudo wrapper).
        res = _run(["dnsmasq", "-C", DNSMASQ_CONF, f"--pid-file={DNSMASQ_PID}"])
        if res.returncode != 0:
            raise RuntimeError(f"dnsmasq failed: {res.stderr.strip() or res.returncode}")

    def _kill_dnsmasq(self) -> None:
        try:
            with open(DNSMASQ_PID) as fh:
                pid = int(fh.read().strip())
            _ok(["kill", str(pid)])
        except Exception:  # noqa: BLE001 - stale/missing pid file is fine
            pass
        try:
            os.remove(DNSMASQ_PID)
        except OSError:
            pass

    def _start_agent(self) -> None:
        # "Just works" pairing so a headless box needs no PIN entry.
        self._procs["agent"] = subprocess.Popen(
            _priv(["bt-agent", "-c", "NoInputNoOutput"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _start_nap(self) -> None:
        # bt-network registers the BlueZ NAP server and enslaves each incoming
        # bnep link to the bridge for us.
        self._procs["nap"] = subprocess.Popen(
            _priv(["bt-network", "-s", "nap", BRIDGE]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.4)
        if self._procs["nap"].poll() is not None:
            raise RuntimeError("bt-network exited immediately (NAP registration failed)")

    def _set_network_class(self) -> None:
        """Flag every controller as a network access point (see NAP_CLASS).

        Best-effort and reversible: the class resets when bluetoothd restarts,
        and a missing controller just returns non-zero. Note a phone caches the
        class at pair time, so a device paired while the box still looked like
        audio must be forgotten and re-paired to pick this up.
        """
        for hci in ("hci0", "hci1"):
            if _ok(["hciconfig", hci, "class", NAP_CLASS], timeout=5):
                logger.info("[btpan] %s Class-of-Device set to %s (network access point)", hci, NAP_CLASS)

    def _configure_adapters(self, on: bool) -> None:
        """Power, name and (un)advertise every BlueZ adapter — over D-Bus.

        bluetoothctl is unreliable on a busy stack (it can block indefinitely and
        silently no-op, which is exactly why the box never showed up), so drive
        the adapter properties directly with bounded calls. Setting ``on`` names
        the box "Ragnar", makes it discoverable with no timeout, and pairable;
        clearing it reverts the name to the hostname and hides the box again.
        Never raises — a missing dbus or a wedged bluetoothd degrades to a log
        line, not a failed start.
        """
        try:
            import dbus
        except Exception:
            logger.warning("[btpan] python3-dbus unavailable; cannot set discoverable/name")
            return
        try:
            bus = dbus.SystemBus()
            om = dbus.Interface(bus.get_object("org.bluez", "/"),
                                "org.freedesktop.DBus.ObjectManager")
            objs = om.GetManagedObjects(timeout=_DBUS_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[btpan] could not reach bluetoothd over D-Bus: %s", exc)
            return
        found = False
        for path, ifaces in objs.items():
            if "org.bluez.Adapter1" not in ifaces:
                continue
            found = True
            try:
                props = dbus.Interface(bus.get_object("org.bluez", path),
                                       "org.freedesktop.DBus.Properties")
                props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(True), timeout=_DBUS_TIMEOUT)
                props.Set("org.bluez.Adapter1", "Alias",
                          dbus.String(ADAPTER_ALIAS if on else ""), timeout=_DBUS_TIMEOUT)
                props.Set("org.bluez.Adapter1", "DiscoverableTimeout", dbus.UInt32(0), timeout=_DBUS_TIMEOUT)
                props.Set("org.bluez.Adapter1", "PairableTimeout", dbus.UInt32(0), timeout=_DBUS_TIMEOUT)
                props.Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(on), timeout=_DBUS_TIMEOUT)
                props.Set("org.bluez.Adapter1", "Discoverable", dbus.Boolean(on), timeout=_DBUS_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[btpan] adapter %s config failed: %s", path, exc)
        if on and not found:
            logger.warning("[btpan] bluetoothd exposes no adapters — is a controller present?")

    def _start_trust_loop(self) -> None:
        """Keep paired devices marked Trusted while the NAP is up.

        On a box whose Bluetooth stack is also running audio (pipewire /
        wireplumber register their own agent), an incoming PAN connection is sent
        to *that* agent for authorization and gets cancelled — the phone pairs
        but the tether never forms. A Trusted device is auto-authorized by
        bluetoothd with no agent prompt, so trusting paired devices (a phone can
        pair at any time, so poll rather than trust once) is what lets the PAN
        actually connect.
        """
        if self._trust_thread and self._trust_thread.is_alive():
            return
        self._trust_stop.clear()
        self._trust_thread = threading.Thread(target=self._trust_loop, daemon=True,
                                              name="btpan-trust")
        self._trust_thread.start()

    def _trust_loop(self) -> None:
        self._keepalive()  # immediately, then on a slow poll
        while not self._trust_stop.wait(8.0):
            self._keepalive()

    def _keepalive(self) -> None:
        """Re-assert the NAP-critical adapter state, and keep devices trusted.

        bluetoothd changes this out from under us: it drops **Discoverable**
        (notably when a device connects) and recomputes the **Class-of-Device**,
        which silently makes the box unpairable / look like the wrong kind of
        device again. Re-forcing discoverable / pairable / no-timeout / the
        network class on the poll keeps the box reachable the whole time the NAP
        is enabled, not just for the first few seconds after start.
        """
        self._configure_adapters(True)
        self._set_network_class()
        self._trust_paired()

    def _trust_paired(self) -> None:
        try:
            import dbus
            bus = dbus.SystemBus()
            om = dbus.Interface(bus.get_object("org.bluez", "/"),
                                "org.freedesktop.DBus.ObjectManager")
            objs = om.GetManagedObjects(timeout=_DBUS_TIMEOUT)
        except Exception:  # noqa: BLE001
            return
        for path, ifaces in objs.items():
            dev = ifaces.get("org.bluez.Device1")
            if not dev or not dev.get("Paired") or dev.get("Trusted"):
                continue
            try:
                props = dbus.Interface(bus.get_object("org.bluez", path),
                                       "org.freedesktop.DBus.Properties")
                props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True), timeout=_DBUS_TIMEOUT)
                logger.info("[btpan] trusted paired device %s", path)
            except Exception:  # noqa: BLE001
                pass

    def _teardown_locked(self) -> None:
        self._trust_stop.set()
        self._configure_adapters(False)
        for name in ("nap", "agent"):
            proc = self._procs.pop(name, None)
            if not proc:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                try:
                    proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        # Orphans from a previous crash/restart. Match the process NAME exactly
        # (-x), never an arg pattern with -f — under `sudo -n pkill -f "…"` the
        # pattern also matches the sudo wrapper's own command line. Only our own
        # bt-network / bt-agent run, so an exact-name kill is safe here.
        _ok(["pkill", "-x", "bt-network"], timeout=4)
        _ok(["pkill", "-x", "bt-agent"], timeout=4)
        self._kill_dnsmasq()
        # Remove the bridge so networking returns exactly to its prior state.
        _ok(["ip", "link", "set", BRIDGE, "down"])
        _ok(["ip", "link", "del", BRIDGE])

    # -- status --------------------------------------------------------------
    def _bridge_present(self) -> bool:
        return _ok(["ip", "link", "show", BRIDGE], timeout=4)

    def _connected_devices(self) -> int:
        """Count bnep links enslaved to the bridge — i.e. connected phones."""
        try:
            out = _run(["ip", "-o", "link", "show", "master", BRIDGE], timeout=4)
            if out.returncode != 0:
                return 0
            return sum(1 for line in out.stdout.splitlines() if "bnep" in line)
        except Exception:  # noqa: BLE001
            return 0

    def _running(self) -> bool:
        proc = self._procs.get("nap")
        if proc and proc.poll() is None:
            return True
        # Survive a webapp restart: detect an orphaned server too. Match the
        # process NAME exactly (-x), never the arg string with -f — under
        # `sudo -n pgrep -f "bt-network …"` the pattern also appears in the sudo
        # wrapper's own command line, so -f would always match itself.
        return _ok(["pgrep", "-x", "bt-network"], timeout=4)

    def _status_locked(self) -> dict:
        running = self._running()
        missing = missing_tools()
        return {
            "success": True,
            "running": running,
            # Available only when every runtime tool is present; the UI shows an
            # "Install dependencies" action from `missing_packages` otherwise.
            "available": not missing,
            "missing_tools": missing,
            "missing_packages": missing_packages(),
            "bridge": BRIDGE if self._bridge_present() else None,
            "address": GATEWAY if running else None,
            "port": 8000,
            "connected_devices": self._connected_devices() if running else 0,
            "discoverable": running,
            "uptime_s": (time.time() - self._started_at) if (running and self._started_at) else 0,
            "error": self._error,
            "platform_note": "Android only — iOS does not support Bluetooth PAN.",
        }

    def status(self) -> dict:
        with self._lock:
            return self._status_locked()


# --- module-level singleton the web routes drive ----------------------------
_server: BtPanServer | None = None


def _instance() -> BtPanServer:
    global _server
    if _server is None:
        _server = BtPanServer()
    return _server


def start() -> dict:
    return _instance().start()


def stop() -> dict:
    return _instance().stop()


def status() -> dict:
    return _instance().status()


# --- PAN client (reverse direction) -----------------------------------------
# Android will not run IP over a Bluetooth PAN where the box is the access point
# — it connects the profile but never DHCPs (confirmed on multiple devices, IPv4
# and IPv6 both silent). The direction Android *does* support is the reverse:
# the phone turns on **Bluetooth tethering** (becomes the NAP) and the box
# connects to it as a PAN user (PANU). Android's tether always serves
# 192.168.44.0/24 with the phone at 192.168.44.1, so the box takes a fixed
# 192.168.44.2 (no DHCP client needed — and dhcpcd is told to ignore bnep*
# anyway) and the app reaches the box's web UI at 192.168.44.2:8000 over
# Bluetooth.

NAP_UUID = "00001116-0000-1000-8000-00805f9b34fb"  # BNEP NAP service
CLIENT_IP = "192.168.44.2"
CLIENT_CIDR = "192.168.44.2/24"
PHONE_GATEWAY = "192.168.44.1"

# What the box last connected to, so status()/disconnect() can find it again.
_client_state: dict = {"iface": None, "device": None, "name": None}


def _power_on_adapter() -> None:
    _ok(["rfkill", "unblock", "bluetooth"])
    _ok(["bluetoothctl", "power", "on"])


def _managed_objects():
    """(bus, objects) from BlueZ, or (None, None) on any failure."""
    try:
        import dbus
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        return bus, om.GetManagedObjects(timeout=_DBUS_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[btpan] managed objects failed: %s", exc)
        return None, None


def _pick_phone(objs, address: str | None):
    """Choose the device to connect to: an explicit address if given, else the
    best paired candidate — preferring one that advertises the NAP service
    (a phone with Bluetooth tethering on) and/or is already connected."""
    want = (address or "").strip().upper()
    best = None  # (score, path, name, addr)
    for path, ifaces in objs.items():
        d = ifaces.get("org.bluez.Device1")
        if not d:
            continue
        addr = str(d.get("Address", "")).upper()
        name = str(d.get("Name") or d.get("Alias") or addr or "phone")
        if want:
            if addr == want:
                return path, name, addr
            continue
        if not (d.get("Paired") or d.get("Connected")):
            continue
        uuids = [str(u).lower() for u in (d.get("UUIDs") or [])]
        score = ((NAP_UUID.lower() in uuids) * 4
                 + bool(d.get("Connected")) * 2 + bool(d.get("Paired")))
        if best is None or score > best[0]:
            best = (score, path, name, addr)
    if want or best is None:
        return None, None, None
    return best[1], best[2], best[3]


def client_connect(address: str | None = None) -> dict:
    """Connect the box to a phone's Bluetooth tethering (NAP) as a PAN user.

    Turn on 'Bluetooth tethering' on the paired phone first. On success the box
    joins the phone's 192.168.44.0/24 at a fixed 192.168.44.2, so the mobile app
    reaches the box's web UI at 192.168.44.2:8000 over the Bluetooth link.
    """
    # One radio: the NAP server and the client cannot both hold it. Stop AP mode.
    try:
        _instance().stop()
    except Exception:  # noqa: BLE001
        pass
    _power_on_adapter()
    bus, objs = _managed_objects()
    if objs is None:
        return {"success": False, "error": "BlueZ unreachable (is bluetoothd running?)"}
    path, name, addr = _pick_phone(objs, address)
    if not path:
        if (address or "").strip():
            return {"success": False, "error": f"{address} is not paired — pair it first"}
        return {"success": False,
                "error": "no paired phone found — pair the box in the phone's Bluetooth settings first"}
    try:
        import dbus
        net = dbus.Interface(bus.get_object("org.bluez", path), "org.bluez.Network1")
        iface = str(net.Connect("nap", timeout=25))
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        low = msg.lower()
        if "not supported" in low or "notsupported" in low or "not available" in low or "notavailable" in low:
            msg = "the phone isn't sharing — turn on Bluetooth tethering on the phone, then retry"
        elif "in progress" in low:
            msg = "connection already in progress — retry in a moment"
        return {"success": False, "error": msg, "phone": name}
    # Static address on the bnep link (Android tether is always 192.168.44.1/24).
    _run(["ip", "addr", "flush", "dev", iface])
    _run(["ip", "addr", "add", CLIENT_CIDR, "dev", iface])
    _ok(["ip", "link", "set", iface, "up"])
    reachable = _ok(["ping", "-c", "1", "-W", "2", "-I", iface, PHONE_GATEWAY], timeout=6)
    _client_state.update({"iface": iface, "device": addr, "name": name})
    logger.info("[btpan] client connected to %s via %s (reachable=%s)", name, iface, reachable)
    return {
        "success": True,
        "interface": iface,
        "ip": CLIENT_IP,
        "gateway": PHONE_GATEWAY,
        "app_url": f"http://{CLIENT_IP}:8000",
        "phone": name,
        "reachable": reachable,
        "note": None if reachable else
                "link up, but the phone isn't answering yet — confirm Bluetooth tethering is on, then check status",
    }


def client_disconnect() -> dict:
    """Drop the PAN-client link to the phone and release the static address."""
    iface = _client_state.get("iface")
    addr = (_client_state.get("device") or "").upper()
    bus, objs = _managed_objects()
    if objs is not None:
        try:
            import dbus
            for p, ifaces in objs.items():
                d = ifaces.get("org.bluez.Device1")
                if d and (not addr or str(d.get("Address", "")).upper() == addr) \
                   and "org.bluez.Network1" in ifaces:
                    dbus.Interface(bus.get_object("org.bluez", p),
                                   "org.bluez.Network1").Disconnect(timeout=_DBUS_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[btpan] client disconnect: %s", exc)
    if iface:
        _run(["ip", "addr", "flush", "dev", iface])
    _client_state.update({"iface": None, "device": None, "name": None})
    return {"success": True}


def client_status() -> dict:
    """Whether the box is currently a PAN client of a phone's tethering."""
    connected = False
    iface = _client_state.get("iface")
    name = _client_state.get("name")
    _bus, objs = _managed_objects()
    if objs is not None:
        addr = (_client_state.get("device") or "").upper()
        for _p, ifaces in objs.items():
            net = ifaces.get("org.bluez.Network1")
            d = ifaces.get("org.bluez.Device1")
            if not net or not d:
                continue
            if addr and str(d.get("Address", "")).upper() != addr:
                continue
            if net.get("Connected"):
                connected = True
                iface = str(net.get("Interface") or iface or "")
                name = str(d.get("Name") or d.get("Alias") or name or "phone")
                _client_state.update({"iface": iface, "name": name,
                                      "device": str(d.get("Address", "")).upper()})
                break
    ip = None
    reachable = False
    if connected and iface:
        r = _run(["ip", "-4", "-o", "addr", "show", iface])
        ip = CLIENT_IP if (CLIENT_IP in (r.stdout or "")) else None
        if ip is None:  # link is up but lost its address (e.g. after a flap) — re-add
            _run(["ip", "addr", "add", CLIENT_CIDR, "dev", iface])
            ip = CLIENT_IP
        reachable = _ok(["ping", "-c", "1", "-W", "2", "-I", iface, PHONE_GATEWAY], timeout=6)
    return {
        "success": True,
        "connected": connected,
        "interface": iface if connected else None,
        "ip": ip,
        "gateway": PHONE_GATEWAY if connected else None,
        "app_url": f"http://{CLIENT_IP}:8000" if connected else None,
        "phone": name if connected else None,
        "reachable": reachable,
    }


# --- Paired / connected device management -----------------------------------
# The Config card lists the box's paired/connected Bluetooth devices so the
# operator can forget one — the common reason a phone can't re-pair is a stale
# bond left on the box after it forgot the device on its side.


def list_devices() -> dict:
    """Every paired or connected Bluetooth device, over D-Bus (bounded)."""
    try:
        import dbus
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        objs = om.GetManagedObjects(timeout=_DBUS_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "devices": []}
    devices = []
    for path, ifaces in objs.items():
        d = ifaces.get("org.bluez.Device1")
        if not d or not (d.get("Paired") or d.get("Connected")):
            continue
        addr = str(d.get("Address", ""))
        devices.append({
            "address": addr,
            "name": str(d.get("Name") or d.get("Alias") or addr or "device"),
            "connected": bool(d.get("Connected")),
            "paired": bool(d.get("Paired")),
            "trusted": bool(d.get("Trusted")),
            "icon": str(d.get("Icon", "")),
        })
    devices.sort(key=lambda x: (not x["connected"], x["name"].lower()))
    return {"success": True, "devices": devices}


def forget_device(address: str) -> dict:
    """Remove a device's bond from the box (BlueZ Adapter1.RemoveDevice)."""
    address = (address or "").strip().upper()
    if not address:
        return {"success": False, "error": "no address given"}
    try:
        import dbus
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        objs = om.GetManagedObjects(timeout=_DBUS_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}
    for path, ifaces in objs.items():
        d = ifaces.get("org.bluez.Device1")
        if not d or str(d.get("Address", "")).upper() != address:
            continue
        adapter_path = "/".join(path.split("/")[:-1])
        try:
            dbus.Interface(bus.get_object("org.bluez", adapter_path),
                           "org.bluez.Adapter1").RemoveDevice(path, timeout=_DBUS_TIMEOUT)
            logger.info("[btpan] forgot device %s", address)
            return {"success": True, "address": address}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc)}
    return {"success": False, "error": "device not found"}


def clear_keys() -> dict:
    """Forget **every** paired/bonded Bluetooth device on the box.

    The nuclear reset for the classic "Couldn't pair … incorrect PIN or
    passkey" failure: that error means one side holds a link key the other no
    longer has, so authentication fails before any PIN is ever involved (this
    NAP uses "just works" pairing — there is no PIN). Removing every bond here,
    then forgetting the box on the phone, guarantees the next attempt is a clean
    first-time pairing with no stale keys on either side.
    """
    try:
        import dbus
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        objs = om.GetManagedObjects(timeout=_DBUS_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc), "removed": 0}
    removed: list[str] = []
    errors: list[str] = []
    for path, ifaces in objs.items():
        d = ifaces.get("org.bluez.Device1")
        if not d or not (d.get("Paired") or d.get("Connected")):
            continue
        addr = str(d.get("Address", ""))
        adapter_path = "/".join(path.split("/")[:-1])
        try:
            dbus.Interface(bus.get_object("org.bluez", adapter_path),
                           "org.bluez.Adapter1").RemoveDevice(path, timeout=_DBUS_TIMEOUT)
            removed.append(addr)
            logger.info("[btpan] cleared bond %s", addr)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{addr or path}: {exc}")
    return {
        "success": not errors,
        "removed": len(removed),
        "addresses": removed,
        "error": "; ".join(errors) if errors else None,
    }


# --- On-demand dependency install -------------------------------------------
# The NAP needs bluez-tools (bt-network, bt-agent) + dnsmasq, which a lean image
# may not ship. Rather than fail with a raw package error, the UI offers an
# "Install dependencies" action that drives this — apt in the background, with a
# streamed log the page polls, exactly like the other on-demand installers.


def missing_tools() -> list[str]:
    """Runtime tools the NAP needs that are not on PATH."""
    return [t for t in _TOOL_PKG if not _tool(t)]


def missing_packages() -> list[str]:
    """apt packages to install to satisfy the missing tools."""
    return sorted({_TOOL_PKG[t] for t in missing_tools()})


_install_lock = threading.Lock()
_install_state = {"running": False, "log": "", "done": False, "ok": None, "error": None}


def _install_append(text: str) -> None:
    with _install_lock:
        # Keep the tail bounded — the page only shows the last lines.
        _install_state["log"] = (_install_state["log"] + text)[-8000:]


def install_status() -> dict:
    with _install_lock:
        snap = dict(_install_state)
    snap["missing_tools"] = missing_tools()
    snap["missing_packages"] = missing_packages()
    return snap


def install_deps() -> dict:
    """Kick off (once) a background apt install of the missing packages."""
    with _install_lock:
        if _install_state["running"]:
            already = True
        else:
            already = False
            _install_state.update(running=True, log="", done=False, ok=None, error=None)
    if not already:
        threading.Thread(target=_do_install, daemon=True, name="btpan-install").start()
    return install_status()


def _do_install() -> None:
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        _install_append("Updating package lists…\n")
        up = subprocess.run(_priv(["apt-get", "update"]), capture_output=True, text=True,
                            timeout=180, env=env)
        _install_append((up.stdout or "")[-1500:] + (up.stderr or "")[-1500:])
        _install_append(f"\nInstalling: {' '.join(_INSTALL_PACKAGES)}\n")
        proc = subprocess.Popen(
            _priv(["apt-get", "install", "-y", "--no-install-recommends"] + _INSTALL_PACKAGES),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
        )
        if proc.stdout:
            for line in proc.stdout:
                _install_append(line)
        proc.wait(timeout=600)
        ok = proc.returncode == 0 and not missing_tools()
        with _install_lock:
            _install_state.update(done=True, ok=ok,
                                  error=None if ok else "Install finished but some tools are still missing.")
        _install_append("\nDone — dependencies installed.\n" if ok
                        else "\nInstall did not complete cleanly.\n")
    except Exception as exc:  # noqa: BLE001
        logger.error("[btpan] dependency install failed: %s", exc)
        with _install_lock:
            _install_state.update(done=True, ok=False, error=str(exc))
        _install_append(f"\nError: {exc}\n")
    finally:
        with _install_lock:
            _install_state["running"] = False
