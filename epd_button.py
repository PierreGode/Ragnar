# epd_button.py - Hardware button support for 2.7" e-Paper HAT
# GPIO pins: KEY1=5, KEY2=6, KEY3=13, KEY4=19
# Uses gpiozero (same library as the Waveshare EPD driver) to avoid conflicts
#
# Normal mode:
#   KEY1: Swap to Pwnagotchi (with 10s cooldown)
#   KEY2: Flip screen (cycle rotation 0°→90°→180°→270°)
#   KEY3: Next page - rotate through all pages
#   KEY4: Restart Ragnar service
#
# Wardriving mode (when wardriving_enabled is True in config):
#   KEY1: Start / stop wardriving
#   KEY2: Flip screen (cycle rotation 0°→90°→180°→270°)
#   KEY3: Start AP mode with wardriving-only web portal
#   KEY4: Restart Ragnar service

import logging
import threading
import time
import subprocess

logger = logging.getLogger(__name__)

# GPIO pin assignments for 2.7" e-Paper HAT buttons
KEY1_PIN = 5
KEY2_PIN = 6
KEY3_PIN = 13
KEY4_PIN = 19

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
        self.available = False
        self._buttons = []
        self._swap_cooldown = 0  # timestamp of last swap to prevent double triggers

    def _is_wardriving_mode(self):
        """Return True when Ragnar is in wardriving mode."""
        return bool(self.shared_data.config.get('wardriving_enabled', False))

    def start(self):
        """Start the button listener using gpiozero callbacks."""
        try:
            from gpiozero import Button

            btn1 = Button(KEY1_PIN, pull_up=True, bounce_time=0.3)
            btn2 = Button(KEY2_PIN, pull_up=True, bounce_time=0.3)
            btn3 = Button(KEY3_PIN, pull_up=True, bounce_time=0.3)
            btn4 = Button(KEY4_PIN, pull_up=True, bounce_time=0.3)

            btn1.when_pressed = self._on_key1
            btn2.when_pressed = self._on_key2
            btn3.when_pressed = self._on_key3
            btn4.when_pressed = self._on_key4

            # Keep references so they don't get garbage collected
            self._buttons = [btn1, btn2, btn3, btn4]
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

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _on_key1(self):
        """KEY1: wardriving mode → toggle wardriving start/stop; normal mode → swap Pwnagotchi."""
        if self._is_wardriving_mode():
            threading.Thread(target=self._wardriving_toggle, daemon=True).start()
        else:
            self._pwnagotchi_swap()

    def _on_key2(self):
        """KEY2: Cycle display rotation (0° → 90° → 180° → 270°)."""
        _rotations = [0, 90, 180, 270]
        current = getattr(self.shared_data, 'screen_reversed', 0) or 0
        idx = _rotations.index(current) if current in _rotations else 0
        new_rotation = _rotations[(idx + 1) % len(_rotations)]
        self.shared_data.screen_reversed = new_rotation
        logger.info(f"Button KEY2: Display rotation set to {new_rotation}°")

    def _on_key3(self):
        """KEY3: wardriving mode → start AP with wardriving portal; normal mode → next page."""
        if self._is_wardriving_mode():
            threading.Thread(target=self._start_wardriving_ap, daemon=True).start()
        else:
            self.current_page = (self.current_page + 1) % PAGE_COUNT
            page_names = ["Main", "Network", "Vuln", "Discovered", "Advanced", "Traffic"]
            name = page_names[self.current_page] if self.current_page < len(page_names) else str(self.current_page)
            logger.info(f"Button KEY3: Next page -> {name} ({self.current_page})")

    def _on_key4(self):
        """KEY4: Restart Ragnar service."""
        logger.info("Button KEY4: Restarting Ragnar service...")
        threading.Thread(target=self._do_restart, daemon=True).start()

    # ------------------------------------------------------------------
    # Action helpers
    # ------------------------------------------------------------------

    def _wardriving_toggle(self):
        """Start or stop the wardriving engine (KEY1 in wardriving mode)."""
        try:
            from webapp_modern import _get_wardriving_engine
            engine = _get_wardriving_engine()
            if engine._running:
                logger.info("Button KEY1: Stopping wardriving")
                engine.stop()
            else:
                logger.info("Button KEY1: Starting wardriving")
                engine.scan_interval = self.shared_data.config.get('wardriving_scan_interval', 2)
                engine.start()
        except Exception as e:
            logger.error(f"KEY1 wardriving toggle failed: {e}")

    def _pwnagotchi_swap(self):
        """Swap to Pwnagotchi (KEY1 in normal mode, 10s cooldown)."""
        now = time.time()
        if now - self._swap_cooldown < 10:
            logger.debug("KEY1 swap ignored - cooldown active")
            return
        self._swap_cooldown = now

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

    def _start_wardriving_ap(self):
        """Start AP mode and enable wardriving portal redirect (KEY3 in wardriving mode)."""
        try:
            logger.info("Button KEY3: Starting AP mode for wardriving portal")
            # Signal webapp to redirect AP clients to wardriving kiosk view
            self.shared_data.wardriving_ap_portal = True

            ragnar = getattr(self.shared_data, 'ragnar_instance', None)
            if ragnar and hasattr(ragnar, 'wifi_manager'):
                ragnar.wifi_manager.start_ap_mode()
                logger.info("Button KEY3: AP mode started via wifi_manager")
            else:
                logger.warning("Button KEY3: wifi_manager not available, cannot start AP mode")
        except Exception as e:
            logger.error(f"KEY3 wardriving AP start failed: {e}")

    @staticmethod
    def _do_restart():
        """Restart the ragnar service after a short delay."""
        time.sleep(1)
        subprocess.Popen(['systemctl', 'restart', 'ragnar.service'])
