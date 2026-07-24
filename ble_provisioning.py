#!/usr/bin/env python3
"""
ble_provisioning.py — BlueZ GATT peripheral that lets the Ragnar mobile app
*find* a box over Bluetooth and learn how to reach it over IP.

This is the Pi side of the contract in the Ragnarmobile repo's
``docs/PROTOCOL.md``. It is deliberately a **provisioning** service, not a data
transport:

* iOS cannot speak Bluetooth Classic / RFCOMM without MFi hardware, so BLE GATT
  is the only cross-platform option, and GATT manages only ~5-20 KB/s.
* Ragnar's real API (hundreds of KB per response, plus a Socket.IO stream)
  belongs on Wi-Fi. The box already runs hostapd for the no-infrastructure
  case.

So this service answers exactly one question — *where do I find this box on
IP?* — and then gets out of the way. Everything it exposes fits inside a single
512-byte GATT attribute, so neither side implements chunking.

Adapter contention
------------------
The onboard controller cannot reliably advertise as a peripheral while
:mod:`bt_scanner` is running an active discovery on the *same* adapter. This
service is therefore **off by default** (``ble_provisioning_enabled``) and, when
several controllers are present, prefers one that is not the scanner's. Turning
it on is a deliberate choice, mirroring how the ESP provisioning flows work.

Everything here is receive-mostly: the box advertises and answers reads. The
only writes are the AP-control command, which requires a bonded (encrypted)
link.

Standalone use
--------------
    python3 ble_provisioning.py doctor       # check prerequisites + try to advertise
    python3 ble_provisioning.py run          # register + advertise until Ctrl-C
    python3 ble_provisioning.py selftest     # register, verify, unregister
    python3 ble_provisioning.py info         # print the payloads, no Bluetooth
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import threading
import time
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# GATT contract — these UUIDs are shared verbatim with the mobile app
# (src/ble.ts). Do not change one side without the other.
# ---------------------------------------------------------------------------

SERVICE_UUID = 'fc453ae1-7464-49fb-9018-52ded4f4086d'
CHAR_DEVICE_INFO = '8c310633-e7a1-45e9-b5c5-f7a556d8b24b'
CHAR_NET_STATUS = '7322574d-8a33-4289-af0b-50f11cdd0ed9'
CHAR_AP_CREDS = '2fdc016e-9fd2-405c-b7dc-c36bb2d9070c'
CHAR_AP_CONTROL = 'b8a58eb8-6d03-4cb9-a94e-b4ce7f2f9b2d'

# Single ATT attribute maximum. Payloads are asserted against this so an
# oversized value is caught here, not silently truncated on the wire.
MAX_ATTR_BYTES = 512

# Grace period after a provisioning read before auto-stop frees the adapter.
# Long enough for the phone to also read the AP credentials / retry, short
# enough that the radio comes back quickly. Each read resets the timer.
AUTOSTOP_GRACE_MS = 15000

BLUEZ = 'org.bluez'
DBUS_OM = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROPS = 'org.freedesktop.DBus.Properties'
GATT_MANAGER = 'org.bluez.GattManager1'
GATT_SERVICE = 'org.bluez.GattService1'
GATT_CHRC = 'org.bluez.GattCharacteristic1'
LE_ADV_MANAGER = 'org.bluez.LEAdvertisingManager1'
LE_ADVERTISEMENT = 'org.bluez.LEAdvertisement1'
ADAPTER_IFACE = 'org.bluez.Adapter1'


# ===========================================================================
# Data providers — what the box tells a phone. All defensive: a failure to
# read one field must never take the service down.
# ===========================================================================


def _run(cmd: list[str], timeout: float = 4.0) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout
    except Exception:
        return ''


def _adapter_address(hci: str) -> str:
    """BD address of an adapter, uppercase, or '' if unknown."""
    out = _run(['hciconfig', hci])
    m = re.search(r'BD Address:\s*([0-9A-Fa-f:]{17})', out)
    return m.group(1).upper() if m else ''


def _box_id(hci: str) -> str:
    """Short stable id from the adapter address, e.g. 'b4e2'."""
    addr = _adapter_address(hci)
    if addr:
        return addr.replace(':', '')[-4:].lower()
    # Fall back to the machine-id so the name is still stable across reboots.
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip()[-4:]
    except Exception:
        return '0000'


def _model() -> str:
    try:
        with open('/proc/device-tree/model') as f:
            return f.read().replace('\x00', '').strip()
    except Exception:
        return 'unknown'


def _version(base_dir: str) -> str:
    for name in ('VERSION', 'version.txt'):
        p = os.path.join(base_dir, name)
        try:
            with open(p) as f:
                return f.read().strip()[:32]
        except Exception:
            pass
    # Fall back to a short git description if this is a checkout.
    desc = _run(['git', '-C', base_dir, 'describe', '--tags', '--always']).strip()
    return desc[:32] or 'dev'


# Interfaces we never advertise: loopback, container bridges, and virtual
# veth pairs. Everything else (eth/wlan/usb/tailscale) is a real way in.
_SKIP_IFACE = re.compile(r'^(lo|docker\d|br-|veth|virbr)')


def _interfaces() -> list[dict]:
    """[{name, ip}] for usable IPv4 interfaces, best-effort."""
    out = _run(['ip', '-o', '-4', 'addr', 'show'])
    seen: list[dict] = []
    for line in out.splitlines():
        # "3: wlan0    inet 192.168.1.195/24 ..."
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        if _SKIP_IFACE.match(name):
            continue
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
        if not m:
            continue
        ip = m.group(1)
        if ip.startswith('127.'):
            continue
        seen.append({'name': name, 'ip': ip})
    return seen


class DataProviders:
    """Everything the peripheral needs to answer a read, gathered behind
    small callables so the webapp can inject live state and tests can stub it.
    """

    def __init__(
        self,
        base_dir: str,
        hci: str,
        get_config: Callable[[], dict],
        get_ap_state: Optional[Callable[[], dict]] = None,
        set_ap: Optional[Callable[[bool], bool]] = None,
    ):
        self.base_dir = base_dir
        self.hci = hci
        self._get_config = get_config
        self._get_ap_state = get_ap_state
        self._set_ap = set_ap
        self._box_id = _box_id(hci)

    @property
    def box_id(self) -> str:
        return self._box_id

    @property
    def local_name(self) -> str:
        return f'Ragnar-{self._box_id}'

    def device_info(self) -> dict:
        return {
            'name': 'Ragnar',
            'hostname': socket.gethostname(),
            'model': _model(),
            'version': _version(self.base_dir),
            'box_id': self._box_id,
        }

    def _api_port(self) -> int:
        cfg = self._get_config() or {}
        try:
            return int(os.environ.get('RAGNAR_API_PORT') or cfg.get('web_port') or 8000)
        except (TypeError, ValueError):
            return 8000

    def _ap(self) -> dict:
        if self._get_ap_state:
            try:
                return self._get_ap_state() or {}
            except Exception:
                pass
        return {}

    def net_status(self) -> dict:
        ap = self._ap()
        return {
            'api_port': self._api_port(),
            'ifaces': _interfaces(),
            'ap_active': bool(ap.get('active', False)),
            'ap_ssid': ap.get('ssid'),
        }

    def ap_creds(self) -> dict:
        cfg = self._get_config() or {}
        return {
            'ssid': cfg.get('wifi_ap_ssid', 'Ragnar'),
            'psk': cfg.get('wifi_ap_password', 'ragnarconnect'),
        }

    def apply_ap(self, on: bool) -> bool:
        if not self._set_ap:
            raise RuntimeError('AP control is not wired up on this box')
        return bool(self._set_ap(on))


def _encode(payload: dict, what: str) -> bytes:
    """JSON-encode a payload and enforce the single-attribute size limit."""
    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_ATTR_BYTES:
        # Keep the box answering rather than overflowing: drop to a marker the
        # app can surface. This only trips if an interface list is enormous.
        raw = json.dumps({'error': f'{what} too large'}).encode('utf-8')
    return raw


# ===========================================================================
# BlueZ D-Bus GATT scaffolding
#
# dbus-python + a GLib main loop. Structure follows the canonical BlueZ
# example-gatt-server / example-advertisement, trimmed to this one service.
# Imported lazily inside the server so `info`/unit tests run with no D-Bus.
# ===========================================================================


class BleProvisioningServer:
    """Runs the GATT peripheral in a private GLib main loop thread."""

    def __init__(self, providers: DataProviders, logger=None, auto_stop: bool = False):
        self.providers = providers
        self.logger = logger
        # When True, stop advertising a short grace period after a phone reads
        # the provisioning data, freeing the adapter for Ragnar's other BT work.
        self.auto_stop = auto_stop
        self._thread: Optional[threading.Thread] = None
        self._mainloop = None
        self._glib = None
        self._stop_timer = None
        self._autostopped = False
        self._error: Optional[str] = None
        self._running = False
        self._ready = threading.Event()
        # Populated on the loop thread once registered, for clean teardown.
        self._bus = None
        self._app_path = None
        self._adv_path = None
        self._gatt_manager = None
        self._adv_manager = None

    # -- logging -----------------------------------------------------------
    def _log(self, msg: str, level: str = 'info') -> None:
        if self.logger is not None:
            getattr(self.logger, level, self.logger.info)(f'[ble-prov] {msg}')
        else:
            print(f'[ble-prov] {msg}')

    # -- public API --------------------------------------------------------
    def start(self, timeout: float = 8.0) -> bool:
        """Start the peripheral. Returns True once advertising, else False."""
        if self._running:
            return True
        self._error = None
        self._ready.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name='ble-provisioning', daemon=True
        )
        self._thread.start()
        # Wait for the loop thread to either come up or fail registering.
        self._ready.wait(timeout)
        return self._running and self._error is None

    def stop(self) -> None:
        if self._mainloop is not None:
            try:
                self._mainloop.quit()
            except Exception:
                pass
        self._running = False
        # Wait for the loop thread to finish its teardown (unregister + free the
        # D-Bus object paths) so a subsequent start() on a new adapter doesn't
        # collide with lingering handlers. Never join ourselves (on_error calls
        # stop() from inside the loop thread).
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=4)

    def status(self) -> dict:
        return {
            'running': self._running,
            'error': self._error,
            'adapter': self.providers.hci,
            'name': self.providers.local_name,
            'service_uuid': SERVICE_UUID,
            'auto_stop': self.auto_stop,
            'autostopped': self._autostopped,
        }

    # -- auto-stop (frees the adapter once a phone has provisioned) ---------
    def _on_provisioned(self) -> None:
        """A phone read the network status / AP creds. Arm (or re-arm) the
        auto-stop timer. Runs on the loop thread (D-Bus dispatch), so it can
        touch GLib directly."""
        if not self.auto_stop or self._glib is None:
            return
        if self._stop_timer is not None:
            try:
                self._glib.source_remove(self._stop_timer)
            except Exception:
                pass
        self._stop_timer = self._glib.timeout_add(AUTOSTOP_GRACE_MS, self._autostop_fire)

    def _autostop_fire(self):
        self._stop_timer = None
        self._autostopped = True
        self._log('provisioned — auto-stopping to free the adapter')
        if self._mainloop is not None:
            self._mainloop.quit()
        return False  # one-shot

    # -- loop thread -------------------------------------------------------
    def _run_loop(self) -> None:
        try:
            try:
                import dbus
                import dbus.mainloop.glib
                from gi.repository import GLib
            except ImportError as _imp:
                # These are system apt packages, not pip installable. A box set
                # up before BLE provisioning shipped won't have python3-gi.
                raise RuntimeError(
                    f"{_imp} — BLE provisioning needs python3-gi and python3-dbus. "
                    "Run update_ragnar.sh, or: sudo apt install -y python3-gi python3-dbus"
                )

            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            self._glib = GLib
            bus = dbus.SystemBus()
            self._bus = bus

            adapter_path = f'/org/bluez/{self.providers.hci}'
            adapter_obj = bus.get_object(BLUEZ, adapter_path)

            # Power the adapter on, and explicitly turn Classic discoverability
            # OFF. The app finds the box purely by scanning for the BLE service
            # UUID, and the LE advertisement carries the LocalName (Ragnar-<id>).
            # Being Classic-discoverable would also broadcast the box's *hostname*
            # over Bluetooth — an exposure — and make a scanner flap between the
            # hostname and Ragnar-<id>. Setting it False here also undoes the
            # earlier builds that (wrongly) forced Discoverable on permanently.
            props = dbus.Interface(adapter_obj, DBUS_PROPS)
            props.Set(ADAPTER_IFACE, 'Powered', dbus.Boolean(True))
            try:
                props.Set(ADAPTER_IFACE, 'DiscoverableTimeout', dbus.UInt32(180))
                props.Set(ADAPTER_IFACE, 'Discoverable', dbus.Boolean(False))
            except Exception:
                pass  # non-fatal; LE advertising is independent of this

            self._gatt_manager = dbus.Interface(adapter_obj, GATT_MANAGER)
            self._adv_manager = dbus.Interface(adapter_obj, LE_ADV_MANAGER)

            app = _Application(bus, self.providers, self._on_provisioned)
            self._app_path = app.path
            adv = _Advertisement(bus, 0, self.providers)
            self._adv_path = adv.get_path()

            self._mainloop = GLib.MainLoop()

            def on_registered():
                self._running = True
                self._ready.set()
                self._log(f'advertising as {self.providers.local_name} on {self.providers.hci}')

            def on_error(err, what):
                self._error = f'{what}: {err}'
                self._log(self._error, 'error')
                self._ready.set()
                self.stop()

            self._gatt_manager.RegisterApplication(
                app.path, {},
                reply_handler=lambda: None,
                error_handler=lambda e: on_error(e, 'RegisterApplication'),
            )
            self._adv_manager.RegisterAdvertisement(
                adv.get_path(), {},
                reply_handler=on_registered,
                error_handler=lambda e: on_error(e, 'RegisterAdvertisement'),
            )

            self._mainloop.run()

            # Clean unregister on the way out.
            try:
                self._adv_manager.UnregisterAdvertisement(self._adv_path)
                self._gatt_manager.UnregisterApplication(self._app_path)
            except Exception:
                pass
            # Free the local D-Bus object paths, or a restart on a new adapter
            # hits "there is already a handler for '/one/gode/ragnar/ble'".
            try:
                for svc in app.services:
                    for ch in svc.characteristics:
                        try:
                            ch.remove_from_connection()
                        except Exception:
                            pass
                    try:
                        svc.remove_from_connection()
                    except Exception:
                        pass
                app.remove_from_connection()
                adv.remove_from_connection()
            except Exception:
                pass

        except Exception as e:  # pragma: no cover - hardware/D-Bus dependent
            self._error = str(e)
            self._log(f'failed to start: {e}', 'error')
            self._ready.set()
        finally:
            self._running = False


def _build_dbus_classes():
    """Define the D-Bus service/characteristic/advertisement classes.

    Done inside a function so importing this module never requires dbus/gi;
    only starting the server does.
    """
    import dbus
    import dbus.service

    class InvalidArgs(dbus.exceptions.DBusException):
        _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'

    class NotSupported(dbus.exceptions.DBusException):
        _dbus_error_name = 'org.bluez.Error.NotSupported'

    class Failed(dbus.exceptions.DBusException):
        _dbus_error_name = 'org.bluez.Error.Failed'

    class Application(dbus.service.Object):
        def __init__(self, bus, providers, on_provisioned=None):
            self.path = '/one/gode/ragnar/ble'
            self.services = []
            super().__init__(bus, self.path)
            self.services.append(ProvisioningService(bus, 0, providers, on_provisioned))

        @dbus.service.method(DBUS_OM, out_signature='a{oa{sa{sv}}}')
        def GetManagedObjects(self):
            response = {}
            for service in self.services:
                response[service.get_path()] = service.get_properties()
                for chrc in service.characteristics:
                    response[chrc.get_path()] = chrc.get_properties()
            return response

    class ProvisioningService(dbus.service.Object):
        PATH_BASE = '/one/gode/ragnar/ble/service'

        def __init__(self, bus, index, providers, on_provisioned=None):
            self.path = f'{self.PATH_BASE}{index}'
            self.bus = bus
            self.characteristics = []
            super().__init__(bus, self.path)

            # Reading the network status (the box's IP) or the AP credentials is
            # what "provisioned" means — fire the callback so the server can
            # auto-stop and free the adapter if configured to.
            self.characteristics = [
                Characteristic(bus, 0, self, CHAR_DEVICE_INFO, ['read'],
                               lambda: _encode(providers.device_info(), 'device info')),
                Characteristic(bus, 1, self, CHAR_NET_STATUS, ['read', 'notify'],
                               lambda: _encode(providers.net_status(), 'network status'),
                               on_read=on_provisioned),
                Characteristic(bus, 2, self, CHAR_AP_CREDS, ['encrypt-read'],
                               lambda: _encode(providers.ap_creds(), 'AP credentials'),
                               on_read=on_provisioned),
                ApControlCharacteristic(bus, 3, self, providers),
            ]

        def get_path(self):
            return dbus.ObjectPath(self.path)

        def get_properties(self):
            return {
                GATT_SERVICE: {
                    'UUID': SERVICE_UUID,
                    'Primary': dbus.Boolean(True),
                    'Characteristics': dbus.Array(
                        [c.get_path() for c in self.characteristics], signature='o'
                    ),
                }
            }

    class Characteristic(dbus.service.Object):
        def __init__(self, bus, index, service, uuid, flags, reader, on_read=None):
            self.path = f'{service.path}/char{index}'
            self.bus = bus
            self.uuid = uuid
            self.flags = flags
            self.service = service
            self.reader = reader
            self.on_read = on_read
            self.notifying = False
            super().__init__(bus, self.path)

        def get_path(self):
            return dbus.ObjectPath(self.path)

        def get_properties(self):
            return {
                GATT_CHRC: {
                    'Service': self.service.get_path(),
                    'UUID': self.uuid,
                    'Flags': dbus.Array(self.flags, signature='s'),
                }
            }

        @dbus.service.method(DBUS_PROPS, in_signature='s', out_signature='a{sv}')
        def GetAll(self, interface):
            if interface != GATT_CHRC:
                raise InvalidArgs()
            return self.get_properties()[GATT_CHRC]

        @dbus.service.method(GATT_CHRC, in_signature='a{sv}', out_signature='ay')
        def ReadValue(self, options):
            try:
                data = self.reader()
            except Exception as e:
                raise Failed(str(e))
            if self.on_read is not None:
                try:
                    self.on_read()
                except Exception:
                    pass
            return dbus.Array([dbus.Byte(b) for b in data], signature='y')

        @dbus.service.method(GATT_CHRC, in_signature='aya{sv}')
        def WriteValue(self, value, options):
            raise NotSupported()

        @dbus.service.method(GATT_CHRC)
        def StartNotify(self):
            self.notifying = True

        @dbus.service.method(GATT_CHRC)
        def StopNotify(self):
            self.notifying = False

        @dbus.service.signal(DBUS_PROPS, signature='sa{sv}as')
        def PropertiesChanged(self, interface, changed, invalidated):
            pass

    class ApControlCharacteristic(Characteristic):
        """Write-only AP control. Bonded link enforced via 'encrypt-write'."""

        def __init__(self, bus, index, service, providers):
            super().__init__(bus, index, service, CHAR_AP_CONTROL,
                             ['encrypt-write'], reader=lambda: b'')
            self.providers = providers

        @dbus.service.method(GATT_CHRC, in_signature='aya{sv}')
        def WriteValue(self, value, options):
            try:
                payload = json.loads(bytes(bytearray(value)).decode('utf-8'))
                action = payload.get('action')
            except Exception:
                raise InvalidArgs()
            if action == 'start_ap':
                self.providers.apply_ap(True)
            elif action == 'stop_ap':
                self.providers.apply_ap(False)
            else:
                raise NotSupported()

        @dbus.service.method(GATT_CHRC, in_signature='a{sv}', out_signature='ay')
        def ReadValue(self, options):
            raise NotSupported()

    class Advertisement(dbus.service.Object):
        PATH_BASE = '/one/gode/ragnar/ble/adv'

        def __init__(self, bus, index, providers):
            self.path = f'{self.PATH_BASE}{index}'
            self.providers = providers
            super().__init__(bus, self.path)

        def get_path(self):
            return dbus.ObjectPath(self.path)

        def get_properties(self):
            return {
                LE_ADVERTISEMENT: {
                    'Type': 'peripheral',
                    # The 128-bit service UUID must be in the advertisement so
                    # the app (which scans filtered by it) and iOS background
                    # scanning can discover the box.
                    'ServiceUUIDs': dbus.Array([SERVICE_UUID], signature='s'),
                    'LocalName': dbus.String(self.providers.local_name),
                    'Includes': dbus.Array(['tx-power'], signature='s'),
                }
            }

        @dbus.service.method(DBUS_PROPS, in_signature='s', out_signature='a{sv}')
        def GetAll(self, interface):
            if interface != LE_ADVERTISEMENT:
                raise InvalidArgs()
            return self.get_properties()[LE_ADVERTISEMENT]

        @dbus.service.method(LE_ADVERTISEMENT)
        def Release(self):  # pragma: no cover - called by BlueZ on unregister
            pass

    return Application, Advertisement


# Lazily bound the first time a server actually starts.
_Application = None
_Advertisement = None


def _ensure_classes():
    global _Application, _Advertisement
    if _Application is None:
        _Application, _Advertisement = _build_dbus_classes()


# Wrap start so the D-Bus classes are built on demand.
_orig_run_loop = BleProvisioningServer._run_loop


def _run_loop_with_classes(self):
    try:
        _ensure_classes()
    except Exception as e:  # pragma: no cover
        self._error = f'dbus/gi unavailable: {e}'
        self._log(self._error, 'error')
        self._ready.set()
        return
    _orig_run_loop(self)


BleProvisioningServer._run_loop = _run_loop_with_classes


# ===========================================================================
# Adapter selection
# ===========================================================================


def list_adapters() -> list[str]:
    out = _run(['hciconfig'])
    return re.findall(r'^(hci\d+):', out, re.MULTILINE)


def _adapter_bus(hci: str) -> str:
    """Bus a controller sits on, e.g. 'UART' (built-in) or 'USB' (dongle)."""
    out = _run(['hciconfig', hci])
    m = re.search(r'Bus:\s*(\S+)', out)
    return m.group(1).upper() if m else ''


def list_controllers() -> list[dict]:
    """Every Bluetooth controller with its bus and whether it is built-in.

    The Pi's onboard radio sits on the UART bus; USB dongles (e.g. an Alfa)
    enumerate on USB. Provisioning prefers the built-in one so an Alfa stays
    free for scanning.
    """
    out = []
    for hci in list_adapters():
        bus = _adapter_bus(hci)
        out.append({
            'hci': hci,
            'address': _adapter_address(hci),
            'bus': bus,
            'builtin': bus in ('UART', 'SDIO') or (bus and bus != 'USB'),
        })
    return out


def choose_adapter(preferred: Optional[str] = None) -> Optional[str]:
    """Pick an adapter to advertise on.

    Preference order: an explicit choice, else the built-in (UART) controller,
    else the first adapter. Preferring the built-in one keeps a USB dongle
    (Alfa) free for the active scanners (bt_scanner, WIDS), even if the dongle
    happened to enumerate as hci0.
    """
    controllers = list_controllers()
    if not controllers:
        return None
    names = [c['hci'] for c in controllers]
    if preferred and preferred in names:
        return preferred
    for c in controllers:
        if c['builtin']:
            return c['hci']
    return names[0]


# ===========================================================================
# Webapp integration helper
# ===========================================================================


def build_server(base_dir, get_config, get_ap_state=None, set_ap=None,
                 logger=None, adapter=None) -> Optional[BleProvisioningServer]:
    """Construct (but do not start) a server, or None if no adapter exists."""
    cfg = {}
    try:
        cfg = get_config() or {}
    except Exception:
        pass
    hci = choose_adapter(adapter or cfg.get('ble_provisioning_adapter'))
    if not hci:
        if logger:
            logger.warning('[ble-prov] no Bluetooth adapter available')
        return None
    providers = DataProviders(base_dir, hci, get_config, get_ap_state, set_ap)
    return BleProvisioningServer(
        providers, logger=logger,
        auto_stop=bool(cfg.get('ble_provisioning_autostop', False)),
    )


# ===========================================================================
# CLI
# ===========================================================================


def _cli_info(base_dir: str) -> int:
    hci = choose_adapter() or 'hci0'
    providers = DataProviders(base_dir, hci, lambda: {})
    print(f'adapter:      {hci}')
    print(f'advertised:   {providers.local_name}')
    print(f'service uuid: {SERVICE_UUID}')
    for name, fn in (
        ('device_info', providers.device_info),
        ('net_status', providers.net_status),
        ('ap_creds', providers.ap_creds),
    ):
        payload = fn()
        raw = _encode(payload, name)
        print(f'\n{name} ({len(raw)} B):')
        print('  ' + json.dumps(payload, indent=2).replace('\n', '\n  '))
    return 0


def _cli_run(base_dir: str, seconds: Optional[float] = None) -> int:
    server = build_server(base_dir, lambda: {})
    if server is None:
        print('No Bluetooth adapter — cannot run.')
        return 1
    if not server.start():
        print(f'Failed to start: {server.status().get("error")}')
        return 1
    print(f'Advertising as {server.providers.local_name}. Ctrl-C to stop.')
    try:
        if seconds:
            time.sleep(seconds)
        else:
            while server.status()['running']:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def _cli_selftest(base_dir: str) -> int:
    server = build_server(base_dir, lambda: {})
    if server is None:
        print('SELFTEST: no adapter (expected on a box without Bluetooth)')
        return 0
    ok = server.start(timeout=10)
    st = server.status()
    print(f'SELFTEST: registered={ok} status={st}')
    server.stop()
    time.sleep(0.5)
    return 0 if ok else 1


def _cli_doctor(base_dir: str) -> int:
    """Check every prerequisite and actually try to advertise, printing a
    pass/fail checklist. This is the 'why do I get nothing?' tool."""
    ok = True

    def check(label, passed, hint=''):
        nonlocal ok
        mark = 'PASS' if passed else 'FAIL'
        if not passed:
            ok = False
        print(f'  [{mark}] {label}' + (f'  -> {hint}' if (hint and not passed) else ''))
        return passed

    print('Ragnar BLE provisioning — doctor\n')

    # 1. Python deps (the usual culprit).
    have_dbus = have_gi = False
    try:
        import dbus  # noqa: F401
        have_dbus = True
    except Exception:
        pass
    try:
        import gi  # noqa: F401
        have_gi = True
    except Exception:
        pass
    check('python3-dbus importable', have_dbus, 'sudo apt install -y python3-dbus')
    check('python3-gi importable', have_gi, 'sudo apt install -y python3-gi')

    # 2. BlueZ present.
    check('bluetoothctl present', bool(_run(['which', 'bluetoothctl']).strip()),
          'sudo apt install -y bluez')

    # 3. Controllers.
    controllers = list_controllers()
    check(f'Bluetooth controller found ({len(controllers)})', bool(controllers),
          'no adapter — check hardware / rfkill unblock all')
    for c in controllers:
        print(f'        - {c["hci"]} {c.get("address") or ""} '
              f'{"(built-in)" if c["builtin"] else "(" + (c.get("bus") or "?") + ")"}')

    # 4. rfkill not blocking.
    rf = _run(['rfkill', 'list', 'bluetooth'])
    blocked = 'yes' in rf.lower().split('blocked:', 1)[-1][:40] if 'blocked' in rf.lower() else False
    check('Bluetooth not rfkill-blocked', not blocked, 'sudo rfkill unblock all')

    # 5. Actually advertise for a few seconds.
    if have_gi and have_dbus and controllers:
        server = build_server(base_dir, lambda: {})
        started = server.start(timeout=10) if server else False
        st = server.status() if server else {}
        check('Advertising starts', started, st.get('error') or 'see error above')
        if started:
            print(f'        advertising as "{st.get("name")}" on {st.get("adapter")}')
        if server:
            server.stop()
    else:
        check('Advertising starts', False, 'fix the failures above first')

    print('\n' + ('ALL GOOD — the box is advertising. Scan for the name above '
                  'with a BLE app (e.g. nRF Connect) to confirm over the air.'
                  if ok else 'Fix the FAIL lines above, then re-run: '
                  'sudo python3 ble_provisioning.py doctor'))
    return 0 if ok else 1


def main(argv=None) -> int:
    import sys

    argv = argv if argv is not None else sys.argv[1:]
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cmd = argv[0] if argv else 'info'
    if cmd == 'info':
        return _cli_info(base_dir)
    if cmd == 'run':
        secs = float(argv[1]) if len(argv) > 1 else None
        return _cli_run(base_dir, secs)
    if cmd == 'selftest':
        return _cli_selftest(base_dir)
    if cmd == 'doctor':
        return _cli_doctor(base_dir)
    print(__doc__)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
