# lcdhat_input.py - Buttons + 5-way joystick for the Waveshare 1.44" LCD HAT
# (ST7735S 128x128). Reuses EPDButtonListener's page state, netdiag test engine
# and default-mode handlers; only the GPIO wiring and the input→action mapping
# differ, because this HAT has 3 keys plus a joystick instead of 4 keys.
#
# GPIO pins (BCM), fixed by the HAT:
#   KEY1 = 21   KEY2 = 20   KEY3 = 16
#   Joystick: Up=6  Down=19  Left=5  Right=26  Press=13
#
# The joystick directions below are given as the user SEES them on the upright
# text, not as the raw GPIO pins: the HAT's joystick is mounted 90° clockwise of
# the panel's text, so a raw "down" push points to the on-screen "right". The
# listener remaps every joystick direction into this visual frame (see
# _visual_dir) and keeps it correct as KEY2 rotates the screen.
#
# KEY1 is the field-tester switch on the LCD HAT: it flips On-Screen Network
# Diagnostic Mode on/off (the e-paper HAT uses KEY1 for the Pwnagotchi swap).
# Because KEY1 owns the toggle in net-diag, the two gateway/internet ping tests
# live on the joystick left/right there instead.
#
# Default layer (not wardriving, not net-diag):
#   Joy Up/Left   : previous display page   (as seen on the text)
#   Joy Down/Right: next display page       (as seen on the text)
#   Joy Press     : start/stop page autoscroll (auto-cycle every 5s)
#   KEY1          : toggle On-Screen Network Diagnostic Mode
#   KEY2          : rotate the screen (0→90→180→270)
#   KEY3 short/long: next display page / restart Ragnar service
#
# Wardriving layer (engine running AND the display is on the main page, which is
# where display.py overrides the dashboard with the wardriving render). The
# joystick pages a carousel of wardriving screens and the keys become wardriving
# actions; everything acts on press:
#   Joy Up/Left   : previous wardriving screen (STATS/MAP/GPS/SKY/SESSION/VIKING)
#   Joy Down/Right: next wardriving screen
#   Joy Press     : jump back to the STATS screen
#   KEY1          : return to the Ragnar screens — steps off the main page so
#                   the default layer takes over. Does NOT stop wardriving.
#   KEY2          : reconnect to a known WiFi (wardriving keeps running)
#   KEY3          : start/stop the phone-access AP
#
# Network Diagnostic layer (config network_diagnostic_mode) — a field-test pad,
# navigated as a stack of "cards": LINK / IP / SWITCH / DHCP / WIFI (SSID+RSSI) /
# SIGNAL (nearby strengths) / SPECTRUM / IFACE / BT / ZIGBEE. Left/Right move between cards;
# Up/Down cycle the test functions inside a card; the centre press runs the
# highlighted one. The three keys are exits/toggles (everything acts on press —
# no long-press here):
#   Joy Left      : previous card    (as seen on the text)
#   Joy Right     : next card        (as seen on the text)
#   Joy Up / Down : cycle the highlighted function inside the card
#   Joy Press     : OK/select — run the highlighted function (or dismiss a result)
#   KEY1          : switch to Ragnar — toggle the mode off (normal screens)
#   KEY2          : exit card → the card-selection menu (press again to leave it)
#   KEY3          : pause / start auto-switch (auto-cycle the cards every 5 s)
# Card functions (Up/Down + press): LINK/SWITCH → Locate Port · L2 Health;
# IP → Ping GW · Ping WAN · DNS Doctor · Speedtest; DHCP/WIFI/SIGNAL are
# read-only. BT and ZIGBEE are the other two 2.4 GHz occupants — each is a
# one-shot scan run with the centre press (~8 s), showing the last result until
# you scan again. The IFACE card pins which NIC the egress tests (speedtest, pings)
# originate from — Up/Down highlights Auto or an interface, press selects it;
# Auto follows the priority order built-in eth → USB eth → wlan1 → wlan0.
# In the card-selection menu any joystick direction moves the highlight and press
# enters the card. See epd_button.netdiag_card_funcs.

import logging
import threading
import time

from epd_button import (EPDButtonListener, PAGE_COUNT, PAGE_MAIN, PAGE_NETWORK,
                        NETDIAG_HOLD_TIME, netdiag_card_funcs)

logger = logging.getLogger(__name__)

# Seconds each normal Ragnar page is shown when page autoscroll is enabled
# (joystick-center toggles it). Matches the net-diag auto-cycle cadence.
AUTOSCROLL_INTERVAL = 5.0

# Number of net-diag sub-pages (LINK / IP / SWITCH / DHCP / WIFI / SIGNAL /
# SPECTRUM / IFACE / BT / ZIGBEE). Mirrors display.NETDIAG_PAGE_COUNT; kept
# local so this module needn't import display.py.
NETDIAG_PAGE_COUNT = 10

# Number of wardriving screens the joystick pages through while wardriving runs
# (STATS / MAP / GPS / SKY / SESSION / VIKING). Mirrors display.WARDRIVE_PAGE_COUNT.
WARDRIVE_PAGE_COUNT = 6

# Button pins
KEY1_PIN = 21
KEY2_PIN = 20
KEY3_PIN = 16

# Joystick pins
JOY_UP_PIN    = 6
JOY_DOWN_PIN  = 19
JOY_LEFT_PIN  = 5
JOY_RIGHT_PIN = 26
JOY_PRESS_PIN = 13

# (pin, logical name) for every input on the HAT.
_INPUTS = (
    (KEY1_PIN,      'key1'),
    (KEY2_PIN,      'key2'),
    (KEY3_PIN,      'key3'),
    (JOY_UP_PIN,    'up'),
    (JOY_DOWN_PIN,  'down'),
    (JOY_LEFT_PIN,  'left'),
    (JOY_RIGHT_PIN, 'right'),
    (JOY_PRESS_PIN, 'press'),
)

# KEY1 is never here — it's a global mode toggle that acts on press in every
# layer. Which other inputs resolve short-vs-long on release/hold depends on the
# mode; see _defers().

# Joystick directions in clockwise order — used to rotate a raw pin direction
# into the frame the user reads on the panel.
_CW_ORDER = ('up', 'right', 'down', 'left')


class LCDHATInputListener(EPDButtonListener):
    """Input listener for the 1.44" LCD HAT (3 keys + 5-way joystick)."""

    def __init__(self, shared_data):
        super().__init__(shared_data)
        self._held_inputs = set()
        self.autoscroll = False           # joystick-center toggles page autoscroll
        self._autoscroll_started = False
        # Net-diag "card" navigation state (see _netdiag_input):
        self.netdiag_view = 'card'        # 'card' (viewing) or 'menu' (card select)
        self.netdiag_func_idx = 0         # highlighted function within the card

    def start(self):
        """Claim the HAT's buttons + joystick via gpiozero."""
        try:
            from gpiozero import Button

            self._buttons = []
            for pin, name in _INPUTS:
                # Long-press only matters for the keys in net-diag mode; the
                # joystick acts immediately on press.
                btn = Button(pin, pull_up=True, bounce_time=0.15,
                             hold_time=NETDIAG_HOLD_TIME)
                btn.when_pressed  = (lambda n=name: self._on_input_press(n))
                btn.when_held     = (lambda n=name: self._on_input_held(n))
                btn.when_released = (lambda n=name: self._on_input_release(n))
                self._buttons.append(btn)

            self.available = True
            self._start_autoscroll_thread()
            logger.info("LCD HAT input listener started (keys 21,20,16 + "
                        "joystick 6,19,5,26,13)")
        except ImportError:
            logger.info("gpiozero not available - LCD HAT input listener disabled")
        except Exception as e:
            logger.warning(f"Could not start LCD HAT input listener: {e}")

    def _start_autoscroll_thread(self):
        """Background ticker that advances the page while autoscroll is on. The
        render loop's _sleep_interruptible wakes on the current_page change, so
        no display-side timer is needed. Paused during net-diag (it has its own
        cycle) and wardriving (so it never yanks you off the wardriving view)."""
        if self._autoscroll_started:
            return
        self._autoscroll_started = True

        def _loop():
            while True:
                time.sleep(AUTOSCROLL_INTERVAL)
                try:
                    if not self.autoscroll:
                        continue
                    if self._netdiag_active():
                        continue
                    if self._is_wardriving_active():
                        continue
                    self.current_page = (self.current_page + 1) % PAGE_COUNT
                except Exception as e:
                    logger.debug(f"autoscroll tick error: {e}")

        threading.Thread(target=_loop, name='lcd-autoscroll', daemon=True).start()

    # --- Gesture dispatch -------------------------------------------------
    # Joystick inputs fire on press. Keys fire on release (short) or hold
    # (long) while in net-diag mode so a long press never also triggers the
    # short action; elsewhere the keys act on press like the 2.7" HAT.

    def _defers(self, name):
        """Inputs that resolve short-vs-long on release/hold (the rest act on
        press). In net-diag every input now acts on press — the tests moved onto
        the joystick's function menu, so KEY2/KEY3 no longer carry a short/long
        pair. Wardriving is press-only too (KEY3 toggles the AP, so a long press
        must not also fire a short one). In the default layer only KEY3 defers
        (short = next page, long = restart)."""
        if self._netdiag_active() or self._wardrive_view():
            return False
        return name == 'key3'

    def _wardrive_view(self):
        """True when the wardriving screens own the inputs: the engine is
        running AND the display is on the main page (where display.py overrides
        the dashboard with the wardriving render). Paging off the main page with
        KEY1 hands the inputs back to the default layer."""
        return self._is_wardriving_active() and self.current_page == PAGE_MAIN

    def _on_input_press(self, name):
        self._held_inputs.discard(name)
        if name == 'key1':
            # KEY1 is the layer's "get me out of here" key. In the wardriving
            # screens it returns to the normal Ragnar pages (wardriving keeps
            # running); everywhere else it flips net-diag on/off. Its
            # release/hold are ignored (not deferred).
            if self._wardrive_view():
                self._wardrive_exit_to_ragnar()
            else:
                self._set_netdiag(not self._netdiag_active())
            return
        if self._defers(name):
            return  # decided on release (short) / hold (long)
        self._dispatch(name, 'short')

    def _on_input_held(self, name):
        if not self._defers(name):
            return
        self._held_inputs.add(name)
        self._dispatch(name, 'long')

    def _on_input_release(self, name):
        if not self._defers(name):
            return
        if name in self._held_inputs:
            self._held_inputs.discard(name)
            return  # long press already handled on hold
        self._dispatch(name, 'short')

    def _dispatch(self, name, gesture):
        if self._netdiag_active():
            self._netdiag_input(name, gesture)
        elif self._wardrive_view():
            self._wardrive_input(name, gesture)
        else:
            self._default_input(name, gesture)

    # --- Orientation ------------------------------------------------------
    def _visual_dir(self, name):
        """Remap a raw joystick pin direction into the direction the user sees
        on the upright text. The HAT's joystick sits 90° clockwise of the panel
        (raw 'down' points to the on-screen 'right'), and the square ST7735S
        render path only realises two orientations — 0° for a 0/90 rotation and
        180° for 180/270 — so fold KEY2's rotation to that and rotate the
        direction to match. Non-directional inputs (keys, press) pass through."""
        if name not in ('up', 'down', 'left', 'right'):
            return name
        try:
            rot = int(getattr(self.shared_data, 'screen_reversed', 0) or 0) % 360
        except (TypeError, ValueError):
            rot = 0
        eff_steps = 0 if rot < 180 else 2          # visual 0° or 180°
        offset = (3 - eff_steps) % 4               # +90° CW panel-mount offset
        idx = _CW_ORDER.index(name)
        return _CW_ORDER[(idx + offset) % 4]

    # --- Default layer (page navigation + key actions) --------------------

    def _default_input(self, name, gesture='short'):
        name = self._visual_dir(name)
        if name in ('up', 'left'):
            self._change_page(-1)
        elif name in ('down', 'right'):
            self._change_page(+1)
        elif name == 'key3':
            if gesture == 'long':
                self._on_key4()        # KEY3 hold: restart service
            else:
                self._change_page(+1)  # KEY3 tap: next page
        elif name == 'press':
            self._toggle_autoscroll()  # joystick center: start/stop autoscroll
        elif name == 'key2':
            self._on_key2()            # rotate screen
        # KEY1 is handled on press in _on_input_press (mode toggle).

    def _change_page(self, step):
        # Any manual navigation cancels autoscroll so it doesn't fight the user.
        if self.autoscroll and step:
            self.autoscroll = False
            logger.info("LCD: page autoscroll OFF (manual navigation)")
        self.current_page = (self.current_page + step) % PAGE_COUNT
        logger.info(f"LCD HAT: page -> {self.current_page}")

    def _toggle_autoscroll(self):
        """Joystick center: start/stop auto-cycling the normal Ragnar pages."""
        self.autoscroll = not self.autoscroll
        logger.info(f"LCD: page autoscroll {'ON' if self.autoscroll else 'OFF'}")

    # --- Wardriving layer (joystick pages the wardriving screens) ----------

    def _wardrive_input(self, name, gesture='short'):
        """Map an input to a wardriving action while the wardriving screens are
        showing:

          Joy Up/Left    : previous wardriving screen
          Joy Down/Right : next wardriving screen
          Joy Press      : jump back to the STATS screen
          KEY1           : return to the Ragnar screens (handled on press)
          KEY2           : reconnect to a known Wi-Fi (wardriving keeps running)
          KEY3           : start/stop the phone-access AP
        """
        if name == 'key2':
            logger.info("LCD KEY2 (wardriving): connecting to known WiFi...")
            threading.Thread(target=self._connect_known_wifi, daemon=True).start()
            return
        if name == 'key3':
            self._toggle_wardrive_ap()
            return

        name = self._visual_dir(name)
        if name in ('up', 'left'):
            self._change_wardrive_page(-1)
        elif name in ('down', 'right'):
            self._change_wardrive_page(+1)
        elif name == 'press':
            self.wardrive_page = 0
            logger.info("LCD wardriving: back to STATS screen")
        # KEY1 is handled on press in _on_input_press (exit to Ragnar view).

    def _change_wardrive_page(self, step):
        self.wardrive_page = (self.wardrive_page + step) % WARDRIVE_PAGE_COUNT
        names = ("STATS", "MAP", "GPS", "SKY", "SESSION", "VIKING")
        label = names[self.wardrive_page] if self.wardrive_page < len(names) else str(self.wardrive_page)
        logger.info(f"LCD wardriving: screen -> {label} ({self.wardrive_page})")

    def _wardrive_exit_to_ragnar(self):
        """KEY1 while wardriving: leave the wardriving screens for the normal
        Ragnar pages. Wardriving itself keeps running — display.py only
        overrides the main page, so stepping off it shows the dashboard again.
        Joystick back round to the main page to return to wardriving."""
        self.wardrive_page = 0
        self.autoscroll = False   # don't let the ticker drag us straight back
        self.current_page = PAGE_NETWORK
        logger.info("LCD KEY1 (wardriving): back to Ragnar view "
                    "(wardriving still running)")

    def _set_netdiag(self, on):
        """Flip Network Diagnostic Mode on/off (KEY1), persist it, wake panel."""
        try:
            self.shared_data.config['network_diagnostic_mode'] = bool(on)
            try:
                self.shared_data.save_config()
            except Exception as e:
                logger.warning(f"Could not persist network_diagnostic_mode: {e}")
            self.netdiag_seq += 1               # wake the display promptly
            if on:
                self.netdiag_page = 0
                self.netdiag_result = None
                self.netdiag_iface = None   # fresh session tests on Auto again
                # Card model: start on the card view, driven manually by the
                # joystick. Auto-switch is off until KEY3 turns it on (frozen =
                # auto-cycle paused).
                self.netdiag_view = 'card'
                self.netdiag_func_idx = 0
                self.netdiag_frozen = True
            logger.info(f"LCD KEY1: Network Diagnostic Mode "
                        f"{'ON' if on else 'OFF'}")
        except Exception as e:
            logger.error(f"LCD net-diag toggle failed: {e}")

    # --- Network Diagnostic layer ----------------------------------------

    def _netdiag_input(self, name, gesture):
        """Map a joystick/key input to a net-diag navigation or test action —
        the "card" model (see the header). Two views:

          * card  : Left/Right switch card, Up/Down cycle the card's functions,
                    Press runs the highlighted function (or dismisses a result).
          * menu  : the card-selection list — any direction moves the highlight,
                    Press enters the card.

        Keys (act on press): KEY1 = switch to Ragnar (handled in _on_input_press),
        KEY2 = exit to card-selection menu, KEY3 = pause/start auto-switch."""
        self.netdiag_seq += 1   # wake the display promptly

        # KEY2 / KEY3 work the same in either view.
        if name == 'key2':
            self.netdiag_view = 'card' if self.netdiag_view == 'menu' else 'menu'
            logger.info(f"Netdiag: {'card menu' if self.netdiag_view == 'menu' else 'card view'}")
            return
        if name == 'key3':
            self.netdiag_frozen = not self.netdiag_frozen
            logger.info(f"Netdiag: auto-switch "
                        f"{'OFF' if self.netdiag_frozen else 'ON'}")
            return

        name = self._visual_dir(name)

        if self.netdiag_view == 'menu':
            if name in ('up', 'left'):
                self.netdiag_page = (self.netdiag_page - 1) % NETDIAG_PAGE_COUNT
            elif name in ('down', 'right'):
                self.netdiag_page = (self.netdiag_page + 1) % NETDIAG_PAGE_COUNT
            elif name == 'press':
                self.netdiag_view = 'card'      # OK/select: enter the card
                self.netdiag_func_idx = 0
            return

        # --- card view ---
        if name == 'left':
            self._netdiag_step_page(-1)
            return
        if name == 'right':
            self._netdiag_step_page(+1)
            return
        if name in ('up', 'down'):
            funcs = netdiag_card_funcs(self.netdiag_page)
            if funcs:
                step = -1 if name == 'up' else 1
                self.netdiag_func_idx = (self.netdiag_func_idx + step) % len(funcs)
            return
        if name == 'press':
            # OK/select: dismiss a shown result, else run the highlighted function.
            if self.netdiag_result is not None:
                self.netdiag_result = None
                return
            funcs = netdiag_card_funcs(self.netdiag_page)
            if funcs:
                idx = self.netdiag_func_idx % len(funcs)
                self._run_netdiag_test(funcs[idx][1])
            return

    def _netdiag_step_page(self, step):
        """Advance/rewind the net-diag card, dismissing a shown result first and
        resetting the in-card function highlight."""
        if self.netdiag_result is not None:
            self.netdiag_result = None
            return
        self.netdiag_page = (self.netdiag_page + step) % NETDIAG_PAGE_COUNT
        self.netdiag_func_idx = 0
