# epd_button.py - Hardware button support for 2.7" e-Paper HAT
# GPIO pins: KEY1=5, KEY2=6, KEY3=13, KEY4=19
# Uses gpiozero (same library as the Waveshare EPD driver) to avoid conflicts
#
# Default (not wardriving):
#   KEY1: Swap to Pwnagotchi (with 10s cooldown)
#   KEY2: Flip screen upside down (toggle)
#   KEY3: Next page - rotate through all pages
#   KEY4: Restart Ragnar service
#
# While wardriving is active the keys switch to a wardriving layer:
#   KEY1: Toggle a phone-access AP serving the minimal wardriving page
#   KEY2: Flip the display (same rotation cycle as default)
#   KEY3: Toggle the live e-paper map (GPS track + network dots)
#   KEY4: Connect to a known WiFi (wardriving keeps running)
#
# While Network Diagnostic mode is active (config network_diagnostic_mode) the
# keys become a standalone field-test pad. Each key has a short press and a
# long press (hold ~0.6s); results render on the panel until KEY1 dismisses:
#   KEY1  short: next diagnostic page    long: pause/resume auto-cycle
#   KEY2  short: locate switch port      long: L2 health capture (~12s)
#         (blink the port's link LED)         (STP/rogue-DHCP/storm/dup-IP)
#   KEY3  short: ping the gateway (LAN)  long: ping the internet (WAN, 8.8.8.8)
#   KEY4  short: speedtest               long: DNS Doctor poison/hijack check
#
# Gesture wiring: default & wardriving layers still act on press (unchanged);
# the netdiag layer defers to release (short) / hold (long) so a long press
# doesn't also fire the short action.

import logging
import threading
import time
import os
import subprocess

logger = logging.getLogger(__name__)

# GPIO pin assignments for 2.7" e-Paper HAT buttons
KEY1_PIN = 5
KEY2_PIN = 6
KEY3_PIN = 13
KEY4_PIN = 19

# Other apps that drive the same 2.7" HAT and grab these exact GPIO buttons.
# If one is running it claims the pins first and Ragnar's listener fails with
# 'GPIO busy'. Stopped on demand when wardriving starts so Ragnar can own the
# keys (see EPDButtonListener.ensure_available). Override via config key
# 'wardriving_button_reclaim_services'.
CONFLICTING_BUTTON_SERVICES = ['airprint.service']

# Network Diagnostic sub-pages that the keys cycle through (mirrors
# display.NETDIAG_PAGE_COUNT: 0=LINK, 1=IP, 2=SWITCH). Kept as a local constant
# to avoid importing display.py here (display imports this module).
NETDIAG_PAGE_COUNT = 3

# Net-diag "cards" and the test functions selectable inside each one. On the
# 1.44" LCD HAT the joystick cycles these with Up/Down and runs the highlighted
# one with the centre press (the "card" navigation model); the 2.7" e-Paper HAT
# still fires them from its hardware keys. Kept module-level so both display.py
# (for rendering) and the LCD listener (for dispatch) share one definition.
NETDIAG_CARD_NAMES = ["LINK", "IP", "SWITCH", "DHCP", "WIFI", "SIGNAL",
                      "SPECTRUM", "IFACE", "BT", "ZIGBEE"]
NETDIAG_CARD_FUNCS = {
    0: [("Locate Port", "port"), ("L2 Health", "l2")],            # LINK
    1: [("Ping GW", "ping_gw"), ("Ping WAN", "ping_wan"),
        ("DNS Doctor", "dns"), ("Speedtest", "speedtest")],       # IP
    2: [("Locate Port", "port"), ("L2 Health", "l2")],            # SWITCH
    3: [],                                                         # DHCP (auto)
    4: [],                                                         # WIFI (live)
    5: [],                                                         # SIGNAL (auto)
    # SPECTRUM: the "functions" are band selectors — Up/Down picks which band's
    # channel spectrum is drawn (band_* keys are no-ops on press, see
    # _run_netdiag_test). Only the LCD HAT reaches this card (its
    # NETDIAG_PAGE_COUNT is 8; the e-Paper HAT's is 3).
    6: [("2.4 GHz", "band_24"), ("5 GHz", "band_5"), ("6 GHz", "band_6")],
    # IFACE (card 7): the functions are built at runtime from the interfaces
    # present — use netdiag_card_funcs(), not this dict. Pressing one pins the
    # egress tests (speedtest / pings) to that NIC; "Auto" restores the
    # priority pick (see netdiag_iface_choices).
    # BT / ZIGBEE: the other two 2.4 GHz occupants, scanned on demand rather
    # than continuously — BT discovery and an 802.15.4 sniff both cost radio
    # time, and the Zigbee one needs a HuginnESP that wardriving may be holding.
    # The card shows the last scan until you run another.
    8: [("Scan BT", "bt_scan")],                                   # BT
    9: [("Scan Zigbee", "zb_scan")],                               # ZIGBEE
}

# Which net-diag card is the interface selector (LCD HAT only).
NETDIAG_IFACE_CARD = 7

# Cache for netdiag_iface_choices — the display redraws the IFACE card every
# few seconds and each enumeration shells out to `ip`, so keep it briefly.
_IFACE_CHOICES_CACHE = {'ts': 0.0, 'choices': []}


def _iface_is_usb(name):
    """True when the NIC hangs off USB (a plug-in dongle/adapter)."""
    try:
        return '/usb' in os.path.realpath(f'/sys/class/net/{name}/device')
    except OSError:
        return False


def netdiag_iface_choices():
    """Physical interfaces a field test could originate from, in the fixed
    priority order the HAT tests use: built-in Ethernet, USB Ethernet, wlan1,
    wlan0, remaining wireless. Each entry:
        {'name', 'usb', 'wireless', 'up', 'ipv4'}
    'up' means carrier for wired / operstate up for wireless; 'ipv4' is the
    first address (no CIDR) or None. Cached ~10s."""
    now = time.time()
    if now - _IFACE_CHOICES_CACHE['ts'] < 10:
        return _IFACE_CHOICES_CACHE['choices']
    addrs = {}
    try:
        out = subprocess.run(['ip', '-o', '-4', 'addr', 'show'],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            # "2: eth0 inet 192.168.1.7/24 ..."
            if len(parts) >= 4 and parts[2] == 'inet':
                addrs.setdefault(parts[1], parts[3].split('/')[0])
    except Exception:
        pass
    choices = []
    try:
        names = os.listdir('/sys/class/net')
    except OSError:
        names = []
    for name in names:
        if not name.startswith(('eth', 'en', 'wlan', 'wl')):
            continue  # lo / bridges / VPN tunnels / containers
        wireless = os.path.isdir(f'/sys/class/net/{name}/wireless')
        if wireless:
            try:
                with open(f'/sys/class/net/{name}/operstate') as f:
                    up = f.read().strip() == 'up'
            except OSError:
                up = False
        else:
            try:
                with open(f'/sys/class/net/{name}/carrier') as f:
                    up = f.read().strip() == '1'
            except OSError:  # admin-down reads of carrier raise EINVAL
                up = False
        choices.append({'name': name, 'usb': _iface_is_usb(name),
                        'wireless': wireless, 'up': up,
                        'ipv4': addrs.get(name)})

    def _rank(c):
        if not c['wireless']:
            return (1 if c['usb'] else 0, c['name'])
        if c['name'] == 'wlan1':
            return (2, c['name'])
        if c['name'] == 'wlan0':
            return (3, c['name'])
        return (4, c['name'])

    choices.sort(key=_rank)
    _IFACE_CHOICES_CACHE['ts'] = now
    _IFACE_CHOICES_CACHE['choices'] = choices
    return choices


def netdiag_auto_iface(require_egress=False):
    """The interface the egress tests should originate from when the user
    hasn't pinned one: the first priority-ordered choice that can actually
    send traffic (link up + IPv4). With require_egress the candidate must
    also reach the internet (verified with a device-bound probe) unless it
    already holds the default route — that's what keeps a plugged-in but
    internet-less cable from silently eating the speedtest."""
    try:
        import network_diagnostics as nd
        dflt = nd._default_route_iface()
    except Exception:
        nd, dflt = None, None
    for c in netdiag_iface_choices():
        if not (c['up'] and c['ipv4']):
            continue
        if require_egress and nd is not None and c['name'] != dflt:
            if nd._probe_egress(c['name']) is False:
                continue
        return c['name']
    return None


def netdiag_card_funcs(page):
    """The selectable functions of a net-diag card. Same as NETDIAG_CARD_FUNCS
    except the IFACE card, whose entries are built from the interfaces present
    right now (plus 'Auto' = the priority pick)."""
    if page == NETDIAG_IFACE_CARD:
        return [("Auto", "iface_auto")] + [
            (c['name'], f"iface_{c['name']}") for c in netdiag_iface_choices()]
    return NETDIAG_CARD_FUNCS.get(page, [])

# Hold time (seconds) that separates a short press from a long press in the
# netdiag layer. Comfortably above the 0.3s debounce.
NETDIAG_HOLD_TIME = 0.6

# Display pages
PAGE_MAIN = 0         # Default Ragnar display
PAGE_NETWORK = 1      # Network scanner stats
PAGE_VULN = 2         # Vulnerability scanner stats
PAGE_DISCOVERED = 3   # Discovered hosts
PAGE_ADVANCED = 4     # Advanced scan results
PAGE_TRAFFIC = 5      # Traffic analysis
PAGE_COUNT = 6        # Total number of pages


class EPDButtonListener:
    """Listens for hardware button presses on the 2.7" e-Paper HAT using gpiozero."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.current_page = PAGE_MAIN
        self.flip_screen = False
        self.available = False
        self._buttons = []
        self._swap_cooldown = 0  # timestamp of last swap to prevent double triggers
        self.wardrive_map = False  # KEY3 while wardriving: show live map page
        # LCD HAT only: which wardriving screen the joystick has paged to
        # (0=STATS 1=MAP 2=GPS 3=SKY 4=SESSION 5=VIKING). Read by display.py; the
        # 2.7" e-paper HAT leaves it at 0 and uses wardrive_map instead.
        self.wardrive_page = 0

        # --- Network Diagnostic mode state (read by display.py) ---
        self.netdiag_page = 0          # current sub-page when net-diag mode is on
        self.netdiag_frozen = False    # True = auto-cycle paused (KEY1 long)
        self.netdiag_result = None     # dict of a one-shot test result, or None
        self.netdiag_iface = None      # egress-test NIC pinned via the IFACE
                                       # card; None = Auto (priority pick)
        self.netdiag_seq = 0           # bumped on any key action to wake the display
        # Last on-demand 2.4 GHz neighbour scans, kept so the BT/ZIGBEE cards
        # still show their result after the popup is dismissed (None = never
        # scanned this session). Written by the test worker, read by display.py.
        self.netdiag_bt = None
        self.netdiag_zb = None
        self._netdiag_busy = False     # a test thread is running
        self._held_keys = set()        # keys whose long-press already fired

    def start(self):
        """Start the button listener using gpiozero callbacks."""
        try:
            from gpiozero import Button

            self._buttons = []
            for pin, key in ((KEY1_PIN, 1), (KEY2_PIN, 2), (KEY3_PIN, 3), (KEY4_PIN, 4)):
                btn = Button(pin, pull_up=True, bounce_time=0.3,
                             hold_time=NETDIAG_HOLD_TIME)
                # Default binding: existing single-press behaviour fires on press.
                # The netdiag layer instead classifies short (release) vs long
                # (hold); when_held/when_released are no-ops outside net-diag mode.
                btn.when_pressed = (lambda k=key: self._on_press(k))
                btn.when_held = (lambda k=key: self._on_held(k))
                btn.when_released = (lambda k=key: self._on_release(k))
                self._buttons.append(btn)

            self.available = True
            logger.info(f"EPD button listener started via gpiozero (GPIO {KEY1_PIN},{KEY2_PIN},{KEY3_PIN},{KEY4_PIN})")
        except ImportError:
            logger.info("gpiozero not available - button listener disabled")
        except Exception as e:
            logger.warning(f"Could not start button listener: {e}")

    def stop(self):
        """Stop the button listener and release GPIO."""
        for btn in self._buttons:
            try:
                btn.close()
            except Exception:
                pass
        self._buttons = []

    def ensure_available(self):
        """Make sure Ragnar owns the HAT buttons, reclaiming them if needed.

        Called when wardriving starts. If the listener never got the GPIO
        lines because another app grabbed them first (e.g. airprint.service —
        a standalone Waveshare button app), stop those services and retry once.
        Returns True if the buttons are usable afterwards.
        """
        if self.available:
            return True
        services = self.shared_data.config.get(
            'wardriving_button_reclaim_services', CONFLICTING_BUTTON_SERVICES)
        freed = False
        for svc in services or []:
            if self._stop_service(svc):
                freed = True
        if freed:
            time.sleep(0.5)   # let the kernel release the GPIO lines
            self.stop()       # drop any partial handles from the failed start
            self.start()      # retry claiming the pins
        return self.available

    @staticmethod
    def _stop_service(name):
        """Stop a systemd service holding the HAT buttons (only if active)."""
        try:
            active = subprocess.run(['systemctl', 'is-active', name],
                                    capture_output=True, text=True).stdout.strip()
            if active != 'active':
                return False
            logger.info(f"Reclaiming HAT buttons: stopping {name}")
            subprocess.run(['sudo', 'systemctl', 'stop', name],
                           capture_output=True, text=True, timeout=10)
            return True
        except Exception as e:
            logger.warning(f"Could not stop {name}: {e}")
            return False

    def _is_wardriving_active(self):
        """Return True if the wardriving engine is currently running."""
        try:
            ragnar = getattr(self.shared_data, 'ragnar_instance', None)
            engine = getattr(ragnar, '_wd_engine', None) if ragnar else None
            if engine is not None:
                return bool(getattr(engine, '_running', False))
        except Exception:
            pass
        return False

    def _wifi_manager(self):
        """Return the WiFiManager instance, or None if not reachable."""
        ragnar = getattr(self.shared_data, 'ragnar_instance', None)
        return getattr(ragnar, 'wifi_manager', None) if ragnar else None

    def _netdiag_active(self):
        """True when Network Diagnostic mode owns the keys (config toggle)."""
        try:
            return bool(self.shared_data.config.get('network_diagnostic_mode', False))
        except Exception:
            return False

    # --- Gesture dispatch -------------------------------------------------
    # gpiozero fires when_pressed on every press, when_held after the hold time,
    # and when_released on every release. Default/wardriving layers act on press
    # (as before). In net-diag mode we act on release (short) or hold (long) so a
    # long press never also triggers the short action.

    def _on_press(self, key):
        self._held_keys.discard(key)
        if self._netdiag_active():
            return  # netdiag decides on release/hold
        handler = {1: self._on_key1, 2: self._on_key2,
                   3: self._on_key3, 4: self._on_key4}.get(key)
        if handler:
            handler()

    def _on_held(self, key):
        if not self._netdiag_active():
            return
        self._held_keys.add(key)
        self._netdiag_gesture(key, 'long')

    def _on_release(self, key):
        if not self._netdiag_active():
            return
        if key in self._held_keys:
            self._held_keys.discard(key)
            return  # long press already handled on hold
        self._netdiag_gesture(key, 'short')

    def _on_key1(self):
        """KEY1: wardriving → toggle phone-access AP; else swap to Pwnagotchi."""
        now = time.time()
        if now - self._swap_cooldown < 10:
            logger.debug("KEY1 ignored - cooldown active")
            return
        self._swap_cooldown = now

        if self._is_wardriving_active():
            self._toggle_wardrive_ap()
            return

        try:
            current_mode = self.shared_data.config.get('pwnagotchi_mode', 'ragnar')
            target = 'pwnagotchi' if current_mode != 'pwnagotchi' else 'ragnar'
            logger.info(f"Button KEY1: swapping to {target}")

            from webapp_modern import _schedule_pwn_mode_switch, _write_pwn_status_file, _update_pwn_config, _emit_pwn_status_update
            _write_pwn_status_file('switching', f'Button-triggered swap to {target}', 'swap', {'target_mode': target})
            _update_pwn_config({'pwnagotchi_mode': target, 'pwnagotchi_last_status': f'Swapping to {target} (KEY1 button)'})
            _emit_pwn_status_update()
            _schedule_pwn_mode_switch(target)
        except Exception as e:
            logger.error(f"KEY1 swap trigger failed: {e}")

    def _on_key2(self):
        """KEY2: Cycle display rotation (0° → 90° → 180° → 270°)."""
        _rotations = [0, 90, 180, 270]
        current = getattr(self.shared_data, 'screen_reversed', 0) or 0
        idx = _rotations.index(current) if current in _rotations else 0
        new_rotation = _rotations[(idx + 1) % len(_rotations)]
        self.shared_data.screen_reversed = new_rotation
        logger.info(f"Button KEY2: Display rotation set to {new_rotation}°")

    def _on_key3(self):
        """KEY3: wardriving → toggle live map page; else next page."""
        if self._is_wardriving_active():
            self.wardrive_map = not self.wardrive_map
            logger.info(f"Button KEY3: wardriving map {'ON' if self.wardrive_map else 'OFF'}")
            return
        self.current_page = (self.current_page + 1) % PAGE_COUNT
        page_names = ["Main", "Network", "Vuln", "Discovered", "Advanced", "Traffic"]
        name = page_names[self.current_page] if self.current_page < len(page_names) else str(self.current_page)
        logger.info(f"Button KEY3: Next page -> {name} ({self.current_page})")

    def _on_key4(self):
        """KEY4: wardriving → connect to a known WiFi; else restart service."""
        if self._is_wardriving_active():
            logger.info("Button KEY4: connecting to known WiFi (wardriving continues)...")
            threading.Thread(target=self._connect_known_wifi, daemon=True).start()
            return
        logger.info("Button KEY4: Restarting Ragnar service...")
        threading.Thread(target=self._do_restart, daemon=True).start()

    def _toggle_wardrive_ap(self):
        """KEY1 (wardriving): toggle the phone-access AP on a spare adapter."""
        wifi = self._wifi_manager()
        if wifi is None:
            logger.warning("KEY1: wifi_manager not available; cannot toggle wardrive AP")
            return
        logger.info("Button KEY1: toggling wardriving phone-access AP...")
        threading.Thread(target=wifi.start_wardrive_ap, daemon=True).start()

    def _connect_known_wifi(self):
        """KEY4 (wardriving): connect to a known WiFi without stopping scans."""
        wifi = self._wifi_manager()
        if wifi is None:
            logger.warning("KEY4: wifi_manager not available; cannot connect")
            return
        try:
            ok = wifi.try_connect_known_networks()
            logger.info(f"KEY4: known-WiFi connect {'succeeded' if ok else 'found nothing/failed'}")
        except Exception as e:
            logger.error(f"KEY4: known-WiFi connect error: {e}")

    @staticmethod
    def _do_restart():
        """Restart the ragnar service after a short delay."""
        time.sleep(1)
        subprocess.Popen(['systemctl', 'restart', 'ragnar.service'])

    # ------------------------------------------------------------------
    # Network Diagnostic field-test pad (only while network_diagnostic_mode)
    # ------------------------------------------------------------------

    def _netdiag_gesture(self, key, gesture):
        """Map a (key, short/long) gesture to a net-diag action."""
        self.netdiag_seq += 1   # wake the display promptly
        if key == 1:
            if gesture == 'short':
                # KEY1 short: dismiss a shown result, else advance the page.
                if self.netdiag_result is not None:
                    self.netdiag_result = None
                else:
                    self.netdiag_page = (self.netdiag_page + 1) % NETDIAG_PAGE_COUNT
            else:  # long: pause / resume the auto-cycle
                self.netdiag_frozen = not self.netdiag_frozen
                logger.info(f"Netdiag: auto-cycle {'PAUSED' if self.netdiag_frozen else 'resumed'}")
            return
        action = {
            (2, 'short'): 'port', (2, 'long'): 'l2',
            (3, 'short'): 'ping_gw', (3, 'long'): 'ping_wan',
            (4, 'short'): 'speedtest', (4, 'long'): 'dns',
        }.get((key, gesture))
        if action:
            self._run_netdiag_test(action)

    _NETDIAG_TITLES = {'port': 'LOCATE PORT', 'l2': 'L2 HEALTH',
                       'ping_gw': 'PING GW', 'ping_wan': 'PING WAN',
                       'speedtest': 'SPEEDTEST', 'dns': 'DNS DOCTOR',
                       'bt_scan': 'BLUETOOTH', 'zb_scan': 'ZIGBEE'}

    def _run_netdiag_test(self, kind):
        """Show a 'running' placeholder and run the test on a daemon thread so
        the button callback returns at once (some tests take many seconds)."""
        # SPECTRUM band selectors aren't tests — Up/Down already picked the band
        # the card renders; a press should do nothing rather than pop a result.
        if str(kind).startswith('band_'):
            return
        # IFACE selectors aren't tests either: pressing one pins (or un-pins)
        # the NIC the egress tests originate from; the card redraw shows it.
        if str(kind).startswith('iface_'):
            sel = str(kind)[len('iface_'):]
            self.netdiag_iface = None if sel == 'auto' else sel
            logger.info(f"Netdiag: test interface -> {sel}")
            self.netdiag_seq += 1
            return
        if self._netdiag_busy:
            logger.debug(f"Netdiag test '{kind}' ignored — another is running")
            return
        self._netdiag_busy = True
        self.netdiag_result = {'title': self._NETDIAG_TITLES.get(kind, kind.upper()),
                               'running': True, 'rows': [], 'ts': time.time()}
        self.netdiag_seq += 1
        threading.Thread(target=self._netdiag_test_worker, args=(kind,),
                         daemon=True).start()

    def _netdiag_test_worker(self, kind):
        try:
            res = self._netdiag_execute(kind)
        except Exception as e:
            logger.warning(f"Netdiag test '{kind}' failed: {e}")
            res = {'rows': [('Error', str(e)[:22])]}
        cur = self.netdiag_result or {}
        cur.update(res)
        cur['title'] = cur.get('title') or self._NETDIAG_TITLES.get(kind, kind.upper())
        cur['running'] = False
        cur['ts'] = time.time()
        self.netdiag_result = cur
        self._netdiag_busy = False
        self.netdiag_seq += 1

    def _netdiag_test_iface(self, require_egress=False):
        """The NIC egress tests (speedtest / pings) originate from: the one the
        user pinned on the IFACE card, else the priority auto pick (built-in
        eth → USB eth → wlan1 → wlan0) — see netdiag_auto_iface."""
        if self.netdiag_iface:
            return self.netdiag_iface
        return netdiag_auto_iface(require_egress=require_egress)

    def _netdiag_primary_iface(self):
        """Pick the wired NIC to test: an explicitly pinned wired interface
        first (IFACE card), else a link-up eth*/en*, else any up, else the
        first. Mirrors display._fetch_netdiag_data's selection."""
        sel = self.netdiag_iface
        if sel and os.path.isdir(f'/sys/class/net/{sel}') \
                and not os.path.isdir(f'/sys/class/net/{sel}/wireless'):
            return sel
        try:
            import network_diagnostics as nd
            eth = [i for i in nd.do_interfaces(include_virtual=False).get('interfaces', [])
                   if i.get('type') == 'ethernet'
                   and str(i.get('name', '')).startswith(('eth', 'en'))]
            for i in eth:
                if i.get('link_detected') is True:
                    return i['name']
            for i in eth:
                if str(i.get('operstate', '')).lower() == 'up':
                    return i['name']
            return eth[0]['name'] if eth else None
        except Exception:
            return None

    def _netdiag_execute(self, kind):
        """Run one diagnostic and return {rows, [verdict], [note], [title]} for
        the e-Paper result page. All calls are to network_diagnostics.py."""
        import network_diagnostics as nd

        if kind == 'port':
            iface = self._netdiag_primary_iface()
            if not iface:
                return {'rows': [('Ethernet', 'none found')]}
            # force=True: on a field tool flapping the only uplink is expected.
            r = nd.do_locate_port(iface, count=6, on_ms=800, off_ms=800, force=True)
            if r.get('success'):
                return {'rows': [('Iface', iface), ('Blink', f"{r.get('count', 6)}x ~{round(r.get('duration_s', 0))}s"),
                                 ('Watch', 'switch LINK LED')],
                        'note': 'The port whose link LED blinks in this cadence is yours.'}
            return {'rows': [('Iface', iface), ('Failed', (r.get('error') or '')[:20])]}

        if kind == 'l2':
            iface = self._netdiag_primary_iface()
            if not iface:
                return {'rows': [('Ethernet', 'none found')]}
            r = nd.do_l2_health(iface, seconds=12)
            if not r.get('success'):
                return {'rows': [('L2 health', (r.get('error') or 'failed')[:18])]}
            findings = r.get('findings') or []
            top = findings[0] if findings else {'level': 'ok', 'text': 'no issues'}
            level = {'ok': 'OK', 'info': 'INFO', 'warn': 'WARN'}.get(top.get('level'), '?')
            return {'rows': [('Packets', r.get('packets', 0)),
                             ('Bc/Mc /s', r.get('bcast_mcast_per_s', 0)),
                             ('Verdict', level)],
                    'note': top.get('text')}

        if kind in ('ping_gw', 'ping_wan'):
            iface = self._netdiag_test_iface()
            if kind == 'ping_gw':
                # When pinned to a NIC, ping *that* link's gateway (a USB
                # adapter's segment may have a different one), falling back to
                # the global default gateway.
                target = (nd._iface_default_gateway(iface) if iface else None) \
                    or nd._default_gateway()
                if not target:
                    return {'rows': [('Gateway', 'none')]}
                label = 'Gateway'
            else:
                target = '8.8.8.8'
                label = 'Internet'
            r = nd.do_ping(target, count=4, interface=iface)
            if not r.get('success'):
                return {'rows': [(label, target),
                                 ('Failed', (r.get('error') or '')[:20])]}
            s = r.get('summary') or {}
            loss = s.get('loss_pct')
            rtt = s.get('rtt_avg')
            rows = [(label, target)]
            if iface:
                rows.append(('Iface', iface))
            rows += [('Loss', f"{loss}%" if loss is not None else 'no reply'),
                     ('RTT avg', f"{rtt} ms" if rtt is not None else '—')]
            return {'rows': rows}

        if kind == 'speedtest':
            # require_egress: in Auto mode skip a candidate that verifiably
            # can't reach the internet (e.g. a cable into an isolated switch)
            # instead of failing the whole test on it.
            iface = self._netdiag_test_iface(require_egress=self.netdiag_iface is None)
            r = nd.do_speedtest(iface)
            used = r.get('interface') or iface
            if not r.get('success'):
                rows = [('Speedtest', (r.get('error') or 'failed')[:18])]
                if used:
                    rows.insert(0, ('Iface', used))
                return {'rows': rows}
            return {'rows': [('Iface', used or 'auto'),
                             ('Down', f"{r.get('download_mbps', '?')} Mbps"),
                             ('Up', f"{r.get('upload_mbps', '?')} Mbps"),
                             ('Ping', f"{r.get('ping_ms', '?')} ms")]}

        if kind == 'dns':
            name = self.shared_data.config.get('netdiag_dns_test_name', 'example.com')
            r = nd.do_dns_doctor(name)
            if not r.get('success'):
                return {'rows': [('DNS', (r.get('error') or 'failed')[:18])]}
            p = r.get('poison') or {}
            verdict = p.get('verdict', 'unknown')
            big = {'clean': 'CLEAN', 'suspicious': 'SUSPECT',
                   'hijacked': 'HIJACK'}.get(verdict, verdict.upper())
            reasons = p.get('reasons') or []
            return {'rows': [('Name', name[:20])],
                    'verdict': (big, verdict),
                    'note': reasons[0] if reasons else 'No poisoning signals detected.'}

        if kind == 'bt_scan':
            # The other 2.4 GHz occupant: a BlueZ discovery sweep, same scanner
            # the Wi-Fi analyzer's Bluetooth overlay uses. Stashed on the
            # listener so the BT card keeps showing it once the popup is gone.
            import bt_scanner
            r = bt_scanner.do_scan(duration=8)
            self.netdiag_bt = r
            if r.get('error'):
                return {'rows': [('Bluetooth', 'no adapter')],
                        'note': r.get('error')}
            itf = r.get('interference') or {}
            rows = [('Devices', r.get('device_count', 0)),
                    ('LE/Classic', f"{itf.get('le_count', 0)}/{itf.get('classic_count', 0)}"),
                    ('Close', itf.get('strong_count', 0)),
                    ('Adapter', r.get('controller') or '—')]
            # Which Wi-Fi channel this BT traffic leans on hardest — the reason
            # a field tester cares about BT at all.
            chans = itf.get('wifi_channels') or []
            if chans:
                worst = max(chans, key=lambda c: c.get('pressure') or 0)
                rows.append(('Worst ch', f"{worst.get('wifi_channel')} {worst.get('level', '')}"))
            return {'rows': rows}

        if kind == 'zb_scan':
            # 802.15.4 sniff via a HuginnESP companion. Gate on detect() so a
            # missing/!802.15.4 board reports why instead of timing out.
            import zigbee_scan
            det = zigbee_scan.detect()
            if not det.get('available'):
                self.netdiag_zb = {'error': det.get('error') or 'no Huginn'}
                return {'rows': [('Zigbee', 'no Huginn')],
                        'note': det.get('error')}
            r = zigbee_scan.scan(duration=8)
            self.netdiag_zb = r
            if r.get('error'):
                return {'rows': [('Zigbee', 'scan failed')], 'note': r.get('error')}
            itf = r.get('interference') or {}
            rows = [('Devices', r.get('device_count', 0)),
                    ('Channels', itf.get('channel_count', 0)),
                    ('Close', itf.get('strong_count', 0))]
            markers = itf.get('markers') or []
            if markers:
                busiest = max(markers, key=lambda m: m.get('intensity') or 0)
                rows.append(('Busiest', f"ch{busiest.get('channel')}"))
            if r.get('warning'):
                rows.append(('Note', str(r['warning'])[:18]))
            return {'rows': rows}

        return {'rows': [('Unknown test', kind)]}
