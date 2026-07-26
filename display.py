#display.py
# Description:
# This file, display.py, is responsible for managing the e-ink display of the Ragnar project, updating it with relevant data and statuses.
# It initializes the display, manages multiple threads for updating shared data and vulnerability counts, and handles the rendering of information
# and images on the display.
#
# Key functionalities include:
# - Initializing the e-ink display (EPD) and handling any errors during initialization.
# - Creating and managing threads to periodically update shared data and vulnerability counts.
# - Rendering various statistics, status icons, and images on the e-ink display.
# - Handling updates to shared data from various sources, including CSV files and system commands.
# - Checking and displaying the status of Bluetooth, Wi-Fi, PAN, and USB connections.
# - Providing methods to update the display with comments from an AI (Commentaireia) and generating images dynamically.

import threading
import time
import os
import re
import signal
import glob
import logging
import random
import sys
import csv
import math
from PIL import Image, ImageDraw, ImageFont
from init_shared import shared_data  
from comment import Commentaireia
from logger import Logger
import subprocess  
from shared import detect_wifi_interface

def _short_scan_error(err):
    """Squeeze a BT/Zigbee scanner error into the ~10 chars the net-diag card's
    value column has. The scanners return sentence-length diagnostics (great in
    the web UI, unreadable on a 128 px panel), so map the ones a field tester
    actually hits to a short reason and clip anything unrecognised."""
    e = str(err or '').lower()
    if 'pyserial' in e:
        return 'no pyserial'
    # The radio check comes first: "this Huginn has no 802.15.4 radio" names a
    # board that IS present, so it must not be reported as a missing one.
    if '802.15.4' in e or 'not compiled' in e:
        return 'no 15.4 rx'
    if 'huginn' in e or 'companion' in e:
        return 'no Huginn'
    if 'busy' in e or 'in use' in e or 'permission' in e or 'cannot open' in e:
        return 'port busy'
    if 'controller' in e or 'adapter' in e or 'bluetoothd' in e or 'rfkill' in e:
        return 'no adapter'
    return str(err or 'failed')[:11]


def _fmt_wd_speed(speed_kmh, unit, decimals=1):
    """Format a km/h speed for the wardriving display in the configured unit.

    Recorded data is always stored in km/h; ``unit`` ('kmh' or 'mph') only
    controls presentation. Returns e.g. '12.3km/h' or '7.6mph'.
    """
    if speed_kmh is None:
        return None
    if unit == 'mph':
        return f"{speed_kmh * 0.621371:.{decimals}f}mph"
    return f"{speed_kmh:.{decimals}f}km/h"


# Map rotation angle → PIL transpose operation
_ROTATION_TRANSPOSE = {
    90:  Image.Transpose.ROTATE_90,
    180: Image.Transpose.ROTATE_180,
    270: Image.Transpose.ROTATE_270,
}


def _render_dimensions(width, height, rotation):
    """Return (render_w, render_h) for the given rotation.

    For 90°/270° the render canvas is portrait (swapped) so that the
    e-paper getbuffer 'Vertical' path maps it correctly to the landscape
    display buffer.  For 0°/180° dimensions stay as-is.
    """
    if rotation in (90, 270):
        return height, width
    return width, height


def _apply_epd_rotation(image, rotation):
    """Apply rotation for the EPD hardware path.

    * 0°   – no-op
    * 180° – PIL ROTATE_180 (same dims, horizontal getbuffer path)
    * 90°  – no-op (image is already portrait, getbuffer vertical handles it)
    * 270° – PIL ROTATE_180 (flips the portrait image, getbuffer vertical gives opposite orientation)
    """
    if rotation == 180:
        return image.transpose(Image.Transpose.ROTATE_180)
    if rotation == 270:
        return image.transpose(Image.Transpose.ROTATE_180)
    return image


def _apply_web_rotation(image, rotation):
    """Apply rotation for the web preview PNG.

    The web preview should match what the user physically sees on the display.
    * 0°   – landscape, show as-is
    * 90°  – portrait, show as-is (getbuffer + physical mount cancel)
    * 180° – landscape upside-down
    * 270° – portrait upside-down (getbuffer + physical mount cancel, image was flipped)
    """
    if rotation in (180, 270):
        return image.transpose(Image.Transpose.ROTATE_180)
    return image

logger = Logger(name="display.py", level=logging.DEBUG)

# Import button listener (only functional on Pi with GPIO)
try:
    from epd_button import EPDButtonListener, PAGE_MAIN, PAGE_NETWORK, PAGE_VULN, PAGE_DISCOVERED, PAGE_ADVANCED, PAGE_TRAFFIC
    from epd_button import (NETDIAG_CARD_FUNCS, NETDIAG_CARD_NAMES,
                            netdiag_card_funcs, netdiag_iface_choices,
                            netdiag_auto_iface)
except ImportError:
    EPDButtonListener = None
    PAGE_MAIN, PAGE_NETWORK, PAGE_VULN, PAGE_DISCOVERED, PAGE_ADVANCED, PAGE_TRAFFIC = 0, 1, 2, 3, 4, 5
    NETDIAG_CARD_NAMES = ["LINK", "IP", "SWITCH", "DHCP", "WIFI", "SIGNAL",
                          "SPECTRUM", "IFACE", "BT", "ZIGBEE"]
    NETDIAG_CARD_FUNCS = {}
    netdiag_card_funcs = (lambda page: [])
    netdiag_iface_choices = (lambda: [])
    netdiag_auto_iface = (lambda require_egress=False: None)

# Network Diagnostic mode: number of auto-cycling sub-pages
# (0=LINK, 1=IP, 2=SWITCH, 3=DHCP, 4=WIFI, 5=SIGNAL, 6=SPECTRUM, 7=IFACE,
# 8=BT, 9=ZIGBEE). See Display._render_netdiag_page.
NETDIAG_PAGE_COUNT = 10
NETDIAG_CYCLE_SECONDS = 5

# Wardriving screens on the 1.44" ST7735S LCD HAT (128x128), paged with the
# joystick while wardriving runs. Mirrored by lcdhat_input.WARDRIVE_PAGE_COUNT.
#   0=STATS  1=MAP  2=GPS  3=SKY  4=SESSION  5=VIKING
# The 2.7" e-paper HAT is unaffected — it keeps its KEY3 stats/map toggle.
WARDRIVE_PAGE_COUNT = 6
(WD_PAGE_STATS, WD_PAGE_MAP, WD_PAGE_GPS, WD_PAGE_SKY,
 WD_PAGE_SESSION, WD_PAGE_VIKING) = range(6)

class Display:
    def __init__(self, shared_data):
        """Initialize the display and start the main image and shared data update threads."""
        self.shared_data = shared_data
        self.config = self.shared_data.config
        self.shared_data.ragnarstatustext2 = "Awakening..."
        self.commentaire_ia = Commentaireia()
        self.semaphore = threading.Semaphore(10)
        self.screen_reversed = self.shared_data.screen_reversed
        self.web_screen_reversed = self.shared_data.web_screen_reversed
        self.main_image = None  # Initialize main_image variable

        # Resolve WiFi interface name once (cached in detect_wifi_interface)
        self._wifi_iface = detect_wifi_interface(self.config.get('wifi_default_interface', 'auto'))

        # Frise position (x=0 since frise is resized to full display width)
        self.frise_positions = {
            "default": {
                "x": 0,
                "y": 160
            }
        }

        try:
            self.epd_helper = self.shared_data.epd_helper
            # MAX7219, LCD1602 and other non-EPD displays set epd_helper to None;
            # skip EPD-specific init — their _run_* method handles setup.
            if self.epd_helper is not None:
                self.epd_helper.init_partial_update()
            logger.info("Display initialization complete.")
        except Exception as e:
            logger.error(f"Error during display initialization: {e}")
            raise

        self.main_image_thread = threading.Thread(target=self.update_main_image)
        self.main_image_thread.daemon = True
        self.main_image_thread.start()

        self.update_shared_data_thread = threading.Thread(target=self.schedule_update_shared_data)
        self.update_shared_data_thread.daemon = True
        self.update_shared_data_thread.start()

        self.update_vuln_count_thread = threading.Thread(target=self.schedule_update_vuln_count)
        self.update_vuln_count_thread.daemon = True
        self.update_vuln_count_thread.start()

        self.scale_factor_x = self.shared_data.scale_factor_x
        self.scale_factor_y = self.shared_data.scale_factor_y

        # Wide display detection (e.g. 2.7" at 176x264 vs reference 122x250)
        self.is_wide = self.scale_factor_x > 1.2
        # y_stretch is no longer needed — scale_factor_y handles vertical spacing
        self.y_stretch = 1.0

        # Hardware button support.
        #  * 1.44" LCD HAT (ST7735S): 3 keys + 5-way joystick (own pin set)
        #  * 2.7" e-Paper HAT: KEY1-KEY4 (only when the panel is "wide")
        # Both drive the same page/net-diag state the render loop reads.
        self.button_listener = None
        if self.config.get("epd_type") == "st7735s":
            try:
                from lcdhat_input import LCDHATInputListener
                self.button_listener = LCDHATInputListener(shared_data)
                self.button_listener.start()
            except Exception as e:
                logger.warning(f"LCD HAT input listener unavailable: {e}")
        elif self.is_wide and EPDButtonListener is not None:
            self.button_listener = EPDButtonListener(shared_data)
            self.button_listener.start()

    def get_frise_position(self):
        """Get the frise position based on the display type."""
        display_type = self.config.get("epd_type", "default")
        position = self.frise_positions.get(display_type, self.frise_positions["default"])
        return (
            int(position["x"] * self.scale_factor_x),
            int(position["y"] * self.scale_factor_y)
        )

    def schedule_update_shared_data(self):
        """Periodically update the shared data with the latest system information."""
        while not self.shared_data.display_should_exit:
            self.update_shared_data()
            time.sleep(5)  # Check every 5 seconds for faster WiFi/SSH status updates

    def schedule_update_vuln_count(self):
        """Periodically update the vulnerability count on the display."""
        while not self.shared_data.display_should_exit:
            self.update_vuln_count()
            time.sleep(300)

    def update_main_image(self):
        """Update the main image on the display with the latest immagegen data."""
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.update_image_randomizer()
                if self.shared_data.imagegen:
                    self.main_image = self.shared_data.imagegen
                else:
                    logger.error("No image generated for current status.")
                time.sleep(random.uniform(self.shared_data.image_display_delaymin, self.shared_data.image_display_delaymax))
            except Exception as e:
                logger.error(f"An error occurred in update_main_image: {e}")

    def get_open_files(self):
        """Get the number of open FD files on the system."""
        try:
            open_files = len(glob.glob('/proc/*/fd/*'))
            logger.debug(f"FD : {open_files}")
            return open_files
        except Exception as e:
            logger.error(f"Error getting open files: {e}")
            return None
        
    def update_vuln_count(self):
        """Update the vulnerability count on the display."""
        import pandas as pd
        with self.semaphore:
            try:
                if not os.path.exists(self.shared_data.vuln_summary_file):
                    df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    df.to_csv(self.shared_data.vuln_summary_file, index=False)
                    self.shared_data.vulnnbr = 0
                    logger.info("Vulnerability summary file created.")
                else:
                    # Get alive hosts from SQLite database instead of CSV
                    try:
                        db_stats = self.shared_data.db.get_stats()
                        alive_hosts = self.shared_data.db.get_all_hosts()
                        alive_macs = {
                            h['mac'] for h in alive_hosts 
                            if h.get('status') == 'alive' and h.get('mac') != 'STANDALONE'
                        }
                        logger.debug(f"Loaded {len(alive_macs)} alive MACs from database")
                    except Exception as e:
                        logger.warning(f"Could not get alive MACs from database: {e}")
                        alive_macs = set()


                    try:
                        # Check if file is not empty and has content
                        if os.path.getsize(self.shared_data.vuln_summary_file) > 0:
                            with open(self.shared_data.vuln_summary_file, 'r') as file:
                                df = pd.read_csv(file)
                        else:
                            logger.debug("vuln_summary file is empty, initializing with empty DataFrame")
                            df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                        logger.warning(f"Could not parse vuln_summary file: {e}, creating new one")
                        df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                        all_vulnerabilities = set()

                        for index, row in df.iterrows():
                            mac_address = row["MAC Address"]
                            if mac_address in alive_macs and mac_address != "STANDALONE":
                                vulnerabilities = row["Vulnerabilities"]
                                if pd.isna(vulnerabilities) or not isinstance(vulnerabilities, str):
                                    continue

                                if vulnerabilities and isinstance(vulnerabilities, str):
                                    all_vulnerabilities.update(vulnerabilities.split("; "))

                        self.shared_data.vulnnbr = len(all_vulnerabilities)
                        logger.debug(f"Updated vulnerabilities count: {self.shared_data.vulnnbr}")

                    if os.path.exists(self.shared_data.livestatusfile):
                        try:
                            # Check if file is not empty and has content
                            if os.path.getsize(self.shared_data.livestatusfile) > 0:
                                with open(self.shared_data.livestatusfile, 'r+') as livestatus_file:
                                    livestatus_df = pd.read_csv(livestatus_file)
                                    if not livestatus_df.empty:
                                        livestatus_df.loc[0, 'Vulnerabilities Count'] = self.shared_data.vulnnbr
                                        livestatus_df.to_csv(self.shared_data.livestatusfile, index=False)
                                        logger.debug(f"Updated livestatusfile with vulnerability count: {self.shared_data.vulnnbr}")
                            else:
                                logger.debug("livestatus file is empty, skipping update")
                        except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                            logger.warning(f"Could not parse livestatus file: {e}")
                    else:
                        logger.error(f"Livestatusfile {self.shared_data.livestatusfile} does not exist.")
            except Exception as e:
                logger.error(f"An error occurred in update_vuln_count: {e}")

    def update_shared_data(self):
        """Update the shared data with the latest system information."""
        import pandas as pd
        with self.semaphore:
            try:
                # Create livestatus file if it doesn't exist
                if not os.path.exists(self.shared_data.livestatusfile):
                    logger.info(f"Creating missing livestatus file: {self.shared_data.livestatusfile}")
                    self.shared_data.create_livestatusfile()
                
                try:
                    # Check if file is not empty and has content
                    if os.path.getsize(self.shared_data.livestatusfile) > 0:
                        with open(self.shared_data.livestatusfile, 'r') as file:
                            livestatus_df = pd.read_csv(file)
                    else:
                        logger.warning("Livestatus file is empty, recreating it")
                        self.shared_data.create_livestatusfile()
                        with open(self.shared_data.livestatusfile, 'r') as file:
                            livestatus_df = pd.read_csv(file)
                except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                    logger.warning(f"Could not parse livestatus file: {e}, recreating it")
                    self.shared_data.create_livestatusfile()
                    with open(self.shared_data.livestatusfile, 'r') as file:
                        livestatus_df = pd.read_csv(file)

                    # Check if DataFrame is empty or has the expected columns
                    if livestatus_df.empty:
                        logger.warning("Livestatus file is empty, skipping data update")
                        return

                    # Ensure required columns exist; add them with default 0 if missing
                    required_columns = ['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count']
                    for column in required_columns:
                        if column not in livestatus_df.columns:
                            logger.warning(f"Column '{column}' missing in livestatus file, initializing with 0")
                            livestatus_df[column] = 0

                    # Check if there's at least one row
                    if len(livestatus_df) == 0:
                        logger.warning("Livestatus file has no data rows, skipping data update")
                        return

                    def _safe_int_from_df(df, column_name):
                        try:
                            value = pd.to_numeric(df[column_name].iloc[0], errors='coerce')
                            if pd.isna(value):
                                return 0
                            return int(value)
                        except Exception as e:
                            logger.debug(f"Could not parse column '{column_name}' from livestatus file: {e}")
                            return 0

                    self.shared_data.portnbr = _safe_int_from_df(livestatus_df, 'Total Open Ports')
                    self.shared_data.targetnbr = _safe_int_from_df(livestatus_df, 'Alive Hosts Count')
                    self.shared_data.networkkbnbr = _safe_int_from_df(livestatus_df, 'All Known Hosts Count')
                    self.shared_data.vulnnbr = _safe_int_from_df(livestatus_df, 'Vulnerabilities Count')

                    # Persist any columns we added so other components stay in sync
                    try:
                        livestatus_df.to_csv(self.shared_data.livestatusfile, index=False)
                    except Exception as e:
                        logger.debug(f"Unable to persist normalized livestatus columns: {e}")

                crackedpw_files = glob.glob(f"{self.shared_data.crackedpwddir}/*.csv")

                total_passwords = 0
                for file in crackedpw_files:
                    try:
                        # Check if file is not empty and has content
                        if os.path.getsize(file) > 0:
                            with open(file, 'r') as f:
                                df = pd.read_csv(f, usecols=[0])
                                if not df.empty:
                                    total_passwords += len(df)
                        else:
                            logger.debug(f"Password file {file} is empty, skipping")
                    except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                        logger.debug(f"Could not parse password file {file}: {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error reading password file {file}: {e}")
                        continue

                self.shared_data.crednbr = total_passwords

                total_data = sum([len(files) for r, d, files in os.walk(self.shared_data.datastolendir)])
                self.shared_data.datanbr = total_data

                total_zombies = sum([len(files) for r, d, files in os.walk(self.shared_data.zombiesdir)])
                self.shared_data.zombiesnbr = total_zombies
                total_attacks = sum([len(files) for r, d, files in os.walk(self.shared_data.actions_dir) if not r.endswith("__pycache__")]) - 2

                self.shared_data.attacksnbr = total_attacks

                self.shared_data.update_stats()
                self.shared_data.manual_mode = self.is_manual_mode()
                if self.shared_data.manual_mode:
                    self.manual_mode_txt = "M"
                else:
                    self.manual_mode_txt = "A"
                
                # Check WiFi connectivity with detailed logging
                wifi_connected = self.is_wifi_connected()
                self.shared_data.wifi_connected = wifi_connected
                logger.info(f"[DISPLAY] WiFi status check: connected={wifi_connected}")

                signal_dbm, signal_quality = self.get_wifi_signal_strength() if wifi_connected else (None, None)
                self.shared_data.wifi_signal_dbm = signal_dbm
                self.shared_data.wifi_signal_quality = signal_quality
                if signal_dbm is not None:
                    logger.debug(f"[DISPLAY] WiFi RSSI: {signal_dbm} dBm, quality={self.shared_data.wifi_signal_quality}%")
                
                self.shared_data.ap_mode_active = self.is_ap_mode_active()
                self.shared_data.ap_client_count = self.get_ap_client_count() if self.shared_data.ap_mode_active else 0
                self.shared_data.usb_active = self.is_usb_connected()
                
                # Update Wi-Fi/AP status text for display
                wifi_status_text = self.get_wifi_status_text()
                self.shared_data.ragnarstatustext2 = wifi_status_text
                logger.info(f"[DISPLAY] WiFi status text: '{wifi_status_text}'")
                
                self.get_open_files()

            except (FileNotFoundError, pd.errors.EmptyDataError) as e:
                logger.error(f"Error: {e}")
            except Exception as e:
                logger.error(f"Error updating shared data: {e}")

    def display_comment(self, status):
        """Display the comment based on the status of the ragnarorch."""
        comment = self.commentaire_ia.get_commentaire(status)
        if comment:
            self.shared_data.ragnarsays = comment
            self.shared_data.ragnarstatustext = self.shared_data.ragnarorch_status
        else:
            pass

    # # # def is_bluetooth_connected(self):
    # # #     """
    # # #     Check if any device is connected to the Bluetooth (pan0) interface by checking the output of 'ip neigh show dev pan0'.
    # # #     """
    # # #     try:
    # # #         result = subprocess.Popen(['ip', 'neigh', 'show', 'dev', 'pan0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # # #         output, error = result.communicate()
    # # #         if result.returncode != 0:
    # # #             logger.error(f"Error executing 'ip neigh show dev pan0': {error}")
    # # #             return False
    # # #         return bool(output.strip())
    # # #     except Exception as e:
    # # #         logger.error(f"Error checking Bluetooth connection status: {e}")
    # # #         return False

    def is_wifi_connected(self):
        """Check if WiFi is connected by checking the current SSID and network connectivity."""
        try:
            # Method 1: Try iwgetid first
            result = subprocess.Popen(['iwgetid', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ssid, error = result.communicate()
            if result.returncode == 0 and ssid.strip():
                logger.debug(f"WiFi connected via iwgetid: SSID={ssid.strip()}")
                return True
            
            # Method 2: Check if we have an active network interface with IP
            result = subprocess.Popen(['ip', 'route', 'get', '8.8.8.8'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            route_output, error = result.communicate()
            if result.returncode == 0 and 'via' in route_output:
                logger.debug(f"WiFi connected via ip route check")
                return True
            
            # Method 3: Check for wlan interface with IP
            result = subprocess.Popen(['ip', 'addr', 'show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            addr_output, error = result.communicate()
            if result.returncode == 0:
                # Look for wlan interfaces with inet addresses
                for line in addr_output.split('\n'):
                    if ('wlan' in line and 'state UP' in line) or ('inet ' in line and 'scope global' in line and ('wlan' in addr_output)):
                        logger.debug(f"WiFi connected via interface check")
                        return True
            
            logger.debug(f"WiFi not detected by any method")
            return False
            
        except Exception as e:
            logger.error(f"Error checking WiFi status: {e}")
            return False

    def _dbm_to_quality(self, signal_dbm):
        """Convert RSSI (dBm) to an approximate 0-100 quality percentage."""
        if signal_dbm is None:
            return None

        quality = int((signal_dbm - (-90)) * 100 / (-30 - (-90)))
        return max(0, min(100, quality))

    def get_wifi_signal_strength(self):
        """Return a tuple (signal_dbm, quality_percent) if available."""
        # Primary method: use `iw dev wlan0 link`
        try:
            result = subprocess.run(['iw', 'dev', self._wifi_iface, 'link'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'signal:' in line:
                        try:
                            raw_value = line.split('signal:')[1].split('dBm')[0].strip()
                            signal_dbm = float(raw_value)
                            return signal_dbm, self._dbm_to_quality(signal_dbm)
                        except (ValueError, IndexError):
                            logger.debug(f"Failed to parse iw signal line: {line.strip()}")
                        break
        except FileNotFoundError:
            logger.debug("`iw` command not available for wifi strength measurement")
        except subprocess.TimeoutExpired:
            logger.debug("Timeout while fetching wifi strength via iw")
        except Exception as e:
            logger.debug(f"Unexpected error while using iw for wifi strength: {e}")

        # Fallback: use `iwconfig`
        try:
            result = subprocess.run(['iwconfig', self._wifi_iface], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                quality = None
                signal_dbm = None
                for line in result.stdout.split('\n'):
                    if 'Link Quality' in line:
                        try:
                            quality_part = line.split('Link Quality=')[1].split(' ')[0]
                            if '/' in quality_part:
                                numerator, denominator = quality_part.split('/')
                                quality = int(float(numerator) / float(denominator) * 100)
                        except (ValueError, IndexError):
                            logger.debug(f"Failed to parse Link Quality line: {line.strip()}")
                    if 'Signal level' in line:
                        try:
                            signal_part = line.split('Signal level=')[1].split(' ')[0]
                            if '/' in signal_part:
                                signal_part = signal_part.split('/')[0]
                            signal_dbm = float(signal_part.replace('dBm', ''))
                        except (ValueError, IndexError):
                            logger.debug(f"Failed to parse Signal level line: {line.strip()}")

                if signal_dbm is not None or quality is not None:
                    if quality is None:
                        quality = self._dbm_to_quality(signal_dbm)
                    if signal_dbm is None and quality is not None:
                        # approximate dbm from quality if needed
                        signal_dbm = (quality / 100) * (-30 - (-90)) + (-90)
                    return signal_dbm, quality
        except FileNotFoundError:
            logger.debug("`iwconfig` command not available for wifi strength measurement")
        except subprocess.TimeoutExpired:
            logger.debug("Timeout while fetching wifi strength via iwconfig")
        except Exception as e:
            logger.debug(f"Unexpected error while using iwconfig for wifi strength: {e}")

        return None, None

    def get_wifi_wave_count(self, quality):
        """Translate a 0-100 quality value into 0-4 wave arcs."""
        if quality is None:
            return 0

        thresholds = [8, 28, 52, 70]
        waves = 0
        for threshold in thresholds:
            if quality >= threshold:
                waves += 1
        return waves

    def render_wifi_wave_indicator(self, image, draw):
        """Render a live Wi-Fi indicator using wave arcs with no dBm text."""
        _sx = getattr(self, 'render_sx', self.scale_factor_x)
        _sy = getattr(self, 'render_sy', self.scale_factor_y)
        base_x = int(3 * _sx)
        base_y = int(8 * _sy)
        scale = min(_sx, _sy)
        signal_dbm = getattr(self.shared_data, 'wifi_signal_dbm', None)
        raw_quality = getattr(self.shared_data, 'wifi_signal_quality', None)
        effective_quality = raw_quality if raw_quality is not None else self._dbm_to_quality(signal_dbm)
        ip_last_octet = self.get_wifi_ip_last_octet()

        waves = self.get_wifi_wave_count(effective_quality)
        if waves <= 0:
            waves = 1  # Always show at least one wave when connected

        base_radius = max(2, int(1.5 * scale))
        wave_spacing = max(2, int(2.5 * scale) + 2)
        line_width = max(1, int(scale) + 1)

        center_x = base_x + base_radius + wave_spacing * 2
        center_y = base_y + base_radius + wave_spacing * 2

        # Draw expanding arcs to mimic Wi-Fi waves
        for i in range(waves):
            radius = max(2, base_radius + (i + 1) * wave_spacing - 4)
            bbox = (
                center_x - radius,
                center_y - radius,
                center_x + radius,
                center_y + radius
            )
            draw.arc(bbox, start=225, end=315, fill=0, width=line_width)

        if ip_last_octet:
            text_x = center_x + wave_spacing + base_radius
            text_y = center_y - base_radius - max(1, int(6 * _sy))
            draw.text((text_x, text_y), ip_last_octet, font=self.shared_data.font_arial9, fill=0)

    def get_wifi_ip_last_octet(self):
        """Get the last octet of the WiFi IP address (e.g., '.211' from '192.168.1.211')."""
        try:
            # Get IP address of wlan0 interface
            result = subprocess.run(['ip', '-4', 'addr', 'show', self._wifi_iface], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                # Parse the output to find the IP address
                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        # Extract IP address (format: "inet 192.168.1.211/24 ...")
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip_with_mask = parts[1]
                            ip_address = ip_with_mask.split('/')[0]
                            # Get the last octet
                            octets = ip_address.split('.')
                            if len(octets) == 4:
                                return f".{octets[3]}"
            return None
        except Exception as e:
            logger.error(f"Error getting WiFi IP address: {e}")
            return None

    def is_ap_mode_active(self):
        """Check if AP mode is currently active."""
        try:
            # Check if hostapd is running
            result = subprocess.run(['pgrep', 'hostapd'], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            
            # Alternative check: see if we're listening on AP interface
            result = subprocess.run(['ip', 'addr', 'show', self._wifi_iface], capture_output=True, text=True)
            if result.returncode == 0 and '192.168.4.1' in result.stdout:
                return True
                
            return False
        except Exception as e:
            logger.error(f"Error checking AP mode status: {e}")
            return False

    def get_ap_client_count(self):
        """Get the number of clients connected to AP mode."""
        try:
            # Try to get from WiFi manager first
            if (hasattr(self.shared_data, 'ragnar_instance') and 
                self.shared_data.ragnar_instance and 
                hasattr(self.shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = self.shared_data.ragnar_instance.wifi_manager
                if hasattr(wifi_mgr, 'ap_clients_count'):
                    return wifi_mgr.ap_clients_count
            
            # Fallback to hostapd_cli
            result = subprocess.run(['hostapd_cli', '-i', self._wifi_iface, 'list_sta'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                clients = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                return len(clients)
            
            return 0
        except Exception as e:
            logger.error(f"Error getting AP client count: {e}")
            return 0

    def get_wifi_status_text(self):
        """Get descriptive text for current Wi-Fi status."""
        try:
            # FIRST: Try system-level WiFi detection (most reliable)
            # Method 1: Try iwgetid first (get SSID if available)
            try:
                result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout.strip():
                    ssid = result.stdout.strip()
                    logger.debug(f"[STATUS] WiFi connected via iwgetid: SSID={ssid}")
                    return f"WiFi: {ssid}"
            except:
                pass
            
            # Method 2: Check if we have network connectivity (WiFi without SSID)
            try:
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and 'via' in result.stdout:
                    logger.debug(f"[STATUS] WiFi connected via ip route check")
                    return "WiFi: Connected"
            except:
                pass
            
            # Method 3: Check for wlan interface with IP
            try:
                result = subprocess.run(['ip', 'addr', 'show'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    # Look for wlan interfaces with inet addresses
                    for line in result.stdout.split('\n'):
                        if ('wlan' in line and 'state UP' in line) or ('inet ' in line and 'scope global' in line and ('wlan' in result.stdout)):
                            logger.debug(f"[STATUS] WiFi connected via interface check")
                            return "WiFi: Connected"
            except:
                pass
            
            # SECONDARY: Try to get status from WiFi manager (if available in same process)
            if (hasattr(self.shared_data, 'ragnar_instance') and 
                self.shared_data.ragnar_instance and 
                hasattr(self.shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = self.shared_data.ragnar_instance.wifi_manager
                
                # Check AP mode status first
                if hasattr(wifi_mgr, 'ap_mode_active') and wifi_mgr.ap_mode_active:
                    # Try to get client count
                    client_count = 0
                    if hasattr(wifi_mgr, 'ap_clients_count'):
                        client_count = wifi_mgr.ap_clients_count
                    
                    if client_count > 0:
                        return f"AP: {client_count} client{'s' if client_count != 1 else ''}"
                    else:
                        return "AP: No clients"
                
                # Check Wi-Fi connection status
                if hasattr(wifi_mgr, 'wifi_connected') and wifi_mgr.wifi_connected:
                    if hasattr(wifi_mgr, 'current_ssid') and wifi_mgr.current_ssid:
                        return f"WiFi: {wifi_mgr.current_ssid}"
                    else:
                        return "WiFi: Connected"
                
                # Check if cycling mode is active
                if hasattr(wifi_mgr, 'cycling_mode') and wifi_mgr.cycling_mode:
                    return "WiFi: Cycling"
            
            # TERTIARY: Check if we're in AP mode at system level
            if self.is_ap_mode_active():
                # Try to get AP client count
                try:
                    result = subprocess.run(['hostapd_cli', '-i', self._wifi_iface, 'list_sta'], 
                                          capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        clients = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        client_count = len(clients)
                        if client_count > 0:
                            return f"AP: {client_count} client{'s' if client_count != 1 else ''}"
                        else:
                            return "AP: No clients"
                    else:
                        return "AP: Active"
                except:
                    return "AP: Active"
            
            logger.debug(f"[STATUS] WiFi not detected by any method")
            return "WiFi: Disconnected"
            
        except Exception as e:
            logger.error(f"Error getting WiFi status text: {e}")
            return "WiFi: Unknown"

    def is_manual_mode(self):
        """Check if the ragnarorch is in manual mode."""
        return self.shared_data.manual_mode

    def is_interface_connected(self, interface):
        """Check if any device is connected to the specified interface."""
        try:
            result = subprocess.Popen(['ip', 'neigh', 'show', 'dev', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = result.communicate()
            if result.returncode != 0:
                logger.error(f"Error executing 'ip neigh show dev {interface}': {error}")
                return False
            return bool(output.strip())
        except Exception as e:
            logger.error(f"Error checking connection status on {interface}: {e}")
            return False

    def is_usb_connected(self):
        """Check if any device is connected to the USB interface."""
        try:
            result = subprocess.Popen(['ip', 'neigh', 'show', 'dev', 'usb0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = result.communicate()
            if result.returncode != 0:
                logger.error(f"Error executing 'ip neigh show dev usb0': {error}")
                return False
            return bool(output.strip())
        except Exception as e:
            logger.error(f"Error checking USB connection status: {e}")
            return False

    def _sleep_interruptible(self, current_page):
        """Sleep for screen_delay but wake early if button changes the page.

        Also watches the wardriving sub-page so the LCD HAT's joystick paging
        through the wardriving screens redraws promptly instead of waiting out
        the full screen_delay.
        """
        if not self.button_listener:
            time.sleep(self.shared_data.screen_delay)
            return
        wd_page = getattr(self.button_listener, 'wardrive_page', 0)
        # Check every 0.1s if page changed, otherwise do full sleep
        steps = max(1, int(self.shared_data.screen_delay / 0.1))
        for _ in range(steps):
            if self.button_listener.current_page != current_page:
                return  # Page changed, skip remaining sleep
            if getattr(self.button_listener, 'wardrive_page', 0) != wd_page:
                return  # Wardriving sub-page changed (joystick)
            time.sleep(0.1)

    def _get_cached_page_data(self, key, fetch_fn, ttl=10):
        """Get cached page data, refreshing if older than ttl seconds."""
        if not hasattr(self, '_page_cache'):
            self._page_cache = {}
        now = time.time()
        cached = self._page_cache.get(key)
        if cached and (now - cached[0]) < ttl:
            return cached[1]
        try:
            data = fetch_fn()
        except Exception as e:
            logger.debug(f"Page data fetch error ({key}): {e}")
            data = cached[1] if cached else None
        self._page_cache[key] = (now, data)
        return data

    def _font_at(self, font_name, size):
        """Return a truetype font at `size`, cached across frames."""
        if not hasattr(self, '_font_size_cache'):
            self._font_size_cache = {}
        size = max(6, int(size))
        key = (font_name, size)
        f = self._font_size_cache.get(key)
        if f is None:
            try:
                from PIL import ImageFont
                f = ImageFont.truetype(os.path.join(self.shared_data.fontdir, font_name), size)
            except Exception:
                f = self.shared_data.font_arial9
            self._font_size_cache[key] = f
        return f

    def _fit_font(self, font_name, base_font, text, max_w):
        """Pick the largest `font_name` size ≤ base that renders `text` within
        `max_w` px. Used so page titles shrink instead of clipping on the 128px
        LCD; on roomy e-paper the base font already fits, so this is a no-op."""
        if not text or base_font is None or base_font.getlength(text) <= max_w:
            return base_font
        base_size = getattr(base_font, 'size', 13)
        for size in range(base_size - 1, 6, -1):
            f = self._font_at(font_name, size)
            if f.getlength(text) <= max_w:
                return f
        return self._font_at(font_name, 7)

    def _draw_page_frame(self, draw, title, hint="K1:Home K2:Flip K3:Next K4:Rst"):
        """Draw standard page frame: border, title, divider, footer."""
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        # Shrink the title to fit the panel width so long names ("NET DNS
        # DOCTOR") aren't clipped mid-word on the narrow LCD.
        font_title = self._fit_font('Viking.TTF', self.shared_data.font_viking,
                                    title, w - int(8 * sx))
        draw.rectangle((1, 1, w - 1, h - 1), outline=0)
        draw.text((int(4 * sx), int(4 * sy)), title, font=font_title, fill=0)
        draw.line((1, int(22 * sy), w - 1, int(22 * sy)), fill=0)
        draw.line((1, h - int(18 * sy), w - 1, h - int(18 * sy)), fill=0)
        # Trim the footer hint so it never overflows a narrow panel (e.g. the
        # 128px LCD HAT); on wider e-paper it already fits, so this is a no-op.
        avail = w - int(8 * sx)
        while hint and font.getlength(hint) > avail:
            hint = hint[:-1]
        draw.text((int(4 * sx), h - int(16 * sy)), hint, font=font, fill=0)

    def _draw_stat_rows(self, draw, y, stats):
        """Draw key-value stat rows. Returns final y position."""
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        # Tighten row spacing on a short panel so tall pages (up to ~7 rows) fit
        # a 128px square without spilling into the footer band.
        line_h = int(12 * sy) if h < 150 else int(14 * sy)
        pad_x = int(6 * sx)
        for label, value in stats:
            val_str = str(value)[:22]
            draw.text((pad_x, y), label, font=font, fill=0)
            draw.text((w - pad_x - font.getlength(val_str), y), val_str, font=font, fill=0)
            y += line_h
        return y

    def _draw_adapter_rows(self, draw, y, rows):
        """Draw verbose per-adapter rows as one left-aligned line each.

        Unlike _draw_stat_rows the value is rendered next to the label with a
        small dynamic gap (no right-align, no 22-char truncation), so longer
        values like '19 Networks, M RSSI: -63 dBm [2.4]' survive intact and
        the value gets every available pixel of row width. If the combined
        string still overflows, it's trimmed character-by-character until it
        fits.
        """
        w = getattr(self, 'render_w', self.shared_data.width)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        line_h = int(14 * sy)
        pad_x = int(6 * sx)
        right_edge = w - pad_x
        gap_px = int(6 * sx)  # small visual breathing room between label and value
        for label, value in rows:
            label_str = str(label)
            label_w = font.getlength(label_str)
            value_x = pad_x + int(label_w) + gap_px
            text = str(value)
            # Trim from the end until the value fits between its start column
            # and the right edge.
            available = right_edge - value_x
            while text and font.getlength(text) > available:
                text = text[:-1]
            draw.text((pad_x, y), label_str, font=font, fill=0)
            draw.text((value_x, y), text, font=font, fill=0)
            y += line_h
        return y

    def _draw_scrollable_rows(self, image, draw, top_y, bottom_y, row_groups):
        """Draw stat-row groups into the vertical band [top_y, bottom_y).

        row_groups is a list of ('rows', [(label, value), ...]) and/or
        ('divider', None) entries, drawn in order via _draw_stat_rows. When
        the combined content is taller than the band (e.g. the Discovered
        page's 9 rows on a 128px LCD HAT), it's rendered to an offscreen
        strip and a window is slid over it — a slow triangle-wave scroll
        driven by wall-clock time — instead of drawing statically and
        spilling past bottom_y into the footer.
        """
        w = getattr(self, 'render_w', self.shared_data.width)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        available_h = bottom_y - top_y

        def _emit(d, y0):
            y = y0
            for kind, payload in row_groups:
                if kind == 'divider':
                    y += int(2 * sy)
                    d.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
                    y += int(4 * sy)
                else:
                    y = self._draw_stat_rows(d, y, payload)
            return y

        total_h = _emit(ImageDraw.Draw(Image.new('1', (w, 1), 255)), 0)

        if total_h <= available_h:
            _emit(draw, top_y)
            return

        strip = Image.new('1', (w, total_h), 255)
        _emit(ImageDraw.Draw(strip), 0)

        overflow = total_h - available_h
        speed_px_s = 14.0   # slow scroll — easy to read while it moves
        hold_s = 1.5        # pause at each end so the extremes are readable
        scroll_s = overflow / speed_px_s
        cycle = 2 * hold_s + 2 * scroll_s
        t = time.time() % cycle
        if t < hold_s:
            offset = 0.0
        elif t < hold_s + scroll_s:
            offset = (t - hold_s) * speed_px_s
        elif t < 2 * hold_s + scroll_s:
            offset = float(overflow)
        else:
            offset = overflow - (t - 2 * hold_s - scroll_s) * speed_px_s
        offset = max(0, min(overflow, int(offset)))

        image.paste(strip.crop((0, offset, w, offset + available_h)), (0, top_y))

    # ------------------------------------------------------------------
    # Network Diagnostic mode (Ethernet-focused, internet-independent)
    # ------------------------------------------------------------------

    def _netdiag_sleep(self, seconds, bl=None, seq0=0):
        """Sleep up to `seconds`, waking early if the display is exiting, the
        network-diagnostic toggle is switched off, or a HAT key fired (the
        button listener bumps netdiag_seq), so key presses feel responsive."""
        steps = max(1, int(seconds / 0.1))
        for _ in range(steps):
            if self.shared_data.display_should_exit:
                return
            if not self.shared_data.config.get('network_diagnostic_mode', False):
                return
            if bl is not None and getattr(bl, 'netdiag_seq', 0) != seq0:
                return
            time.sleep(0.1)

    def _fetch_netdiag_data(self):
        """Gather Ethernet-focused diagnostics for the net-diag e-Paper mode.

        Every source is local (ip / ethtool / lldpctl / resolv.conf), so this
        works with no internet at all — the whole point when you're plugged
        into a switch to diagnose it. Reuses network_diagnostics.py."""
        import network_diagnostics as nd
        ifaces = nd.do_interfaces(include_virtual=False).get('interfaces', [])
        # Physical wired NICs only: kernel names them eth*/en* (eth0, enp*, eno*,
        # ens*, enx*, end*). This excludes VPN/tunnel/bridge/container ifaces
        # (tailscale0, wg0, tun0, docker0, br0, veth*) that do_interfaces still
        # reports as 'ethernet' because they aren't wireless.
        eth_list = [i for i in ifaces
                    if i.get('type') == 'ethernet'
                    and str(i.get('name', '')).startswith(('eth', 'en'))]
        # Prefer a link-up ethernet port, then any 'up' port, then the first.
        eth = next((i for i in eth_list if i.get('link_detected') is True), None)
        if eth is None:
            eth = next((i for i in eth_list
                        if str(i.get('operstate', '')).lower() == 'up'), None)
        if eth is None and eth_list:
            eth = eth_list[0]

        gw_ip = nd._default_gateway()
        gateway = {'ip': gw_ip, 'ptr': nd._reverse_dns(gw_ip) if gw_ip else None}
        _, nameservers, _ = nd._read_resolv_conf()

        lldp = {'installed': True, 'neighbor': None}
        res = nd.do_lldp()
        if not res.get('success'):
            if res.get('missing_tool'):
                lldp['installed'] = False
        else:
            neighbors = res.get('neighbors') or []
            if eth:
                lldp['neighbor'] = next(
                    (n for n in neighbors if n.get('local_interface') == eth.get('name')), None)
            if lldp['neighbor'] is None and neighbors:
                lldp['neighbor'] = neighbors[0]
        return {'eth': eth, 'eth_count': len(eth_list),
                'gateway': gateway, 'dns': nameservers, 'lldp': lldp}

    def _netdiag_dhcp(self):
        """Non-blocking rogue-DHCP summary for the e-Paper DHCP page. The scan
        (nmap broadcast-dhcp-discover) takes ~10s, so it runs in a background
        thread and the page shows the last result — the render never blocks.
        Refreshes at most every ~3 min, and only while this page is on screen."""
        st = getattr(self, '_netdiag_dhcp_state', None)
        if st is None:
            st = self._netdiag_dhcp_state = {'ts': 0, 'data': None, 'scanning': False}
        now = time.time()
        if not st['scanning'] and (now - st['ts']) > 180:
            st['scanning'] = True

            def _worker():
                try:
                    import network_diagnostics as nd
                    d = nd.do_dhcp_guardian(quick=True)   # rogue-server only, fast-ish
                except Exception as e:
                    logger.debug(f"netdiag dhcp fetch error: {e}")
                    d = None
                if d:
                    st['data'] = d
                st['ts'] = time.time()
                st['scanning'] = False

            threading.Thread(target=_worker, daemon=True).start()
        return st

    def _fetch_wifi_link(self):
        """Current wireless association for the net-diag WIFI page. Fast and
        passive: reads `iw dev <iface> link` (no scan). Returns a dict with
        ssid=None when the radio isn't associated."""
        iface = getattr(self, '_wifi_iface', None) or 'wlan0'
        info = {'iface': iface, 'ssid': None, 'signal': None, 'quality': None,
                'freq': None, 'band': None, 'channel': None, 'rate': None,
                'bssid': None}
        try:
            r = subprocess.run(['iw', 'dev', iface, 'link'],
                               capture_output=True, text=True, timeout=3)
        except Exception as e:
            logger.debug(f"wifi link fetch error: {e}")
            return info
        out = r.stdout or ''
        if r.returncode != 0 or 'Not connected' in out or not out.strip():
            return info
        m = re.search(r'Connected to ([0-9a-fA-F:]{17})', out)
        if m:
            info['bssid'] = m.group(1)
        m = re.search(r'SSID:\s*(.+)', out)
        if m:
            info['ssid'] = m.group(1).strip()
        m = re.search(r'freq:\s*(\d+)', out)
        if m:
            info['freq'] = int(m.group(1))
            try:
                import wifi_analyzer as wa
                info['band'], info['channel'] = wa.freq_to_channel(info['freq'])
            except Exception:
                pass
        m = re.search(r'signal:\s*(-?\d+)', out)
        if m:
            info['signal'] = int(m.group(1))
            info['quality'] = self._dbm_to_quality(info['signal'])
        m = re.search(r'tx bitrate:\s*([\d.]+)\s*MBit/s', out)
        if m:
            info['rate'] = float(m.group(1))
        return info

    def _netdiag_scan_iface(self):
        """Pick the WiFi interface to scan for the SIGNAL/SPECTRUM cards: the
        adapter that supports the MOST bands, so a tri-band dongle (e.g. the
        Alfa AWUS036AXM) is used for 5/6 GHz instead of a 2.4-only onboard
        radio. The connected onboard radio is what `detect_wifi_interface`
        returns, but it can't see 5/6 GHz — this looks at each radio's real
        band capability. Cached ~2 min; falls back to the onboard interface."""
        cached = getattr(self, '_netdiag_scan_if', None)
        if cached and (time.time() - getattr(self, '_netdiag_scan_if_ts', 0)) < 120:
            return cached
        iface = getattr(self, '_wifi_iface', None) or 'wlan0'
        try:
            import wifi_analyzer as wa
            cands = [i for i in wa.list_wifi_interfaces()
                     if i.get('type') != 'monitor' and i.get('bands')]
            if cands:
                # Most bands wins; prefer 6 GHz- then 5 GHz-capable on ties.
                best = max(cands, key=lambda i: (len(set(i['bands'])),
                                                 '6' in i['bands'], '5' in i['bands']))
                if best['iface'] != iface:
                    logger.info(f"netdiag spectrum: scanning {best['iface']} "
                                f"(bands {'/'.join(best['bands'])}) instead of {iface}")
                iface = best['iface']
        except Exception as e:
            logger.debug(f"netdiag scan-iface pick error: {e}")
        self._netdiag_scan_if = iface
        self._netdiag_scan_if_ts = time.time()
        return iface

    def _netdiag_wifi_scan(self):
        """Background-cached passive scan for the net-diag SIGNAL/SPECTRUM pages.
        A full passive scan takes several seconds, so it runs in a worker thread
        and the page shows the last result — the render never blocks. Full
        discovery sweeps run at most ~every 45s, and only while a wifi page is
        on screen; between them a fast poll re-visits just the listed APs'
        channels every ~1s so the signal bars move live. Scans the widest-band
        adapter (see _netdiag_scan_iface) so 5/6 GHz show up."""
        st = getattr(self, '_netdiag_wifi_state', None)
        if st is None:
            st = self._netdiag_wifi_state = {'ts': 0, 'aps': None, 'scanning': False,
                                             'spectrum': None, 'bands': None, 'iface': None,
                                             'fast_ts': 0, 'fast_scanning': False}
        now = time.time()
        if (not st['scanning'] and not st.get('fast_scanning', False)
                and (now - st['ts']) > 45):
            st['scanning'] = True

            def _worker():
                aps = None
                spectrum = bands = None
                iface = self._netdiag_scan_iface()
                try:
                    import wifi_analyzer as wa
                    d = wa.do_scan(interface=iface, band='all')
                    if 'error' not in d:
                        aps = sorted(d.get('aps', []),
                                     key=lambda a: -(a.get('signal') or -999))[:5]
                        # Full per-channel spectrum feeds the SPECTRUM card too.
                        spectrum = d.get('spectrum') or {}
                        bands = d.get('supported_bands') or {}
                except Exception as e:
                    logger.debug(f"netdiag wifi scan error: {e}")
                st['iface'] = iface
                if aps is not None:
                    st['aps'] = aps
                    st['spectrum'] = spectrum
                    st['bands'] = bands
                st['ts'] = time.time()
                st['scanning'] = False

            threading.Thread(target=_worker, daemon=True).start()
        elif (st.get('aps') and not st['scanning']
              and not st.get('fast_scanning', False)
              and (now - st.get('fast_ts', 0)) > 1.0):
            # Fast path: passively re-visit only the channels of the APs
            # already on screen. Values update in place (no re-sort) so the
            # rows stay put while their bars move.
            st['fast_scanning'] = True

            def _fast_worker():
                try:
                    import wifi_analyzer as wa
                    iface = st.get('iface') or self._netdiag_scan_iface()
                    freqs = sorted({int(round(a['freq'])) for a in (st.get('aps') or [])
                                    if a.get('freq')})
                    sig = wa.fast_signal_poll(iface, freqs)
                    for a in (st.get('aps') or []):
                        s = sig.get(a.get('bssid'))
                        if s is not None:
                            a['signal'] = s
                except Exception as e:
                    logger.debug(f"netdiag fast signal poll error: {e}")
                st['fast_ts'] = time.time()
                st['fast_scanning'] = False

            threading.Thread(target=_fast_worker, daemon=True).start()
        return st

    def _draw_signal_bar(self, draw, y, dbm, x0, x1):
        """One horizontal signal bar between x0..x1, fill ∝ quality, dBm at the
        right edge. Returns the bar's bottom y."""
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        q = self._dbm_to_quality(dbm) if dbm is not None else 0
        q = q or 0
        bar_h = int(9 * sy)
        dbm_txt = f"{int(dbm)}" if dbm is not None else "—"
        dbm_w = font.getlength(dbm_txt) + int(5 * sx)
        bar_x1 = x1 - dbm_w
        if bar_x1 > x0:
            draw.rectangle([x0, y, bar_x1, y + bar_h], outline=0)
            fill_w = int((bar_x1 - x0) * q / 100.0)
            if fill_w > 0:
                draw.rectangle([x0, y, x0 + fill_w, y + bar_h], fill=0)
        draw.text((bar_x1 + int(4 * sx), y - int(1 * sy)), dbm_txt, font=font, fill=0)
        return y + bar_h

    def _draw_signal_bars(self, draw, y, aps):
        """SSID + signal-strength bar list for the net-diag SIGNAL page."""
        w = getattr(self, 'render_w', self.shared_data.width)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        pad_x = int(6 * sx)
        row_h = int(15 * sy)
        name_w = int(46 * sx)          # left column reserved for the SSID
        for ap in aps:
            ssid = ap.get('ssid') or 'hidden'
            s = ssid
            while s and font.getlength(s) > name_w:
                s = s[:-1]
            draw.text((pad_x, y), s or '·', font=font, fill=0)
            self._draw_signal_bar(draw, y, ap.get('signal'),
                                  pad_x + name_w, w - pad_x)
            y += row_h

    def _render_netdiag_menu(self, image, draw, highlight):
        """The card-selection menu (reached with KEY2 on the LCD HAT): list the
        net-diag cards and highlight the current one. The joystick moves the
        highlight; the centre press opens that card. No title header — the list
        starts at the top so all cards fit on the short panel."""
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        font = self.shared_data.font_arial9
        # Thin border + footer hint only (no "NET CARDS" title / top divider),
        # reclaiming that space for the list.
        draw.rectangle((1, 1, w - 1, h - 1), outline=0)
        foot_y = h - int(18 * sy)
        draw.line((1, foot_y, w - 1, foot_y), fill=0)
        hint = "K2 back · press=open"
        avail_hint = w - int(8 * sx)
        while hint and font.getlength(hint) > avail_hint:
            hint = hint[:-1]
        draw.text((int(4 * sx), h - int(16 * sy)), hint, font=font, fill=0)
        pad_x = int(8 * sx)
        n = len(NETDIAG_CARD_NAMES)
        # Fit every card between the top and the footer divider. The lower bound
        # is the font's own height, not a fixed 11 px: with ten cards on the
        # 128 px panel a taller floor would push the last row through the footer
        # divider rather than tightening the rows.
        top = int(3 * sy)
        min_row = max(9, int(font.size) + 1) if hasattr(font, 'size') else 9
        row_h = max(min_row, min(int(15 * sy), (foot_y - top) // max(1, n)))
        # Only inset the text when the row is tall enough to spare the pixel —
        # at the tightest packing it would push a descender into the next row's
        # highlight bar.
        text_dy = int(1 * sy) if row_h > min_row else 0
        y = top
        for i, nm in enumerate(NETDIAG_CARD_NAMES):
            sel = (i == highlight % n)
            label = f"{i + 1}. {nm}"
            if sel:
                draw.rectangle([int(3 * sx), y,
                                w - int(3 * sx), y + row_h - int(1 * sy)], fill=0)
                draw.text((pad_x, y + text_dy), label, font=font, fill=1)
            else:
                draw.text((pad_x, y + text_dy), label, font=font, fill=0)
            y += row_h

    def _render_netdiag_page(self, image, draw, page, frozen=False, func_idx=-1):
        """Render one network-diagnostic sub-page. Space on the panel is scarce,
        so each page shows only the handful of facts an engineer actually needs
        when diagnosing a switch port or a wireless link. On the LCD HAT the
        footer shows the highlighted in-card function (Up/Down cycles it, the
        centre press runs it); ``func_idx`` is the selection (-1 = none)."""
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        data = self._get_cached_page_data('netdiag', self._fetch_netdiag_data, ttl=10)
        names = NETDIAG_CARD_NAMES
        name = names[page % len(names)]
        state = "auto" if not frozen else "manual"
        render_w = getattr(self, 'render_w', self.shared_data.width)
        funcs = netdiag_card_funcs(page)
        if render_w < 150:
            # Narrow LCD HAT: show the page counter + the highlighted function
            # (the joystick's Up/Down selects it, press runs it). Cards with no
            # functions just show the auto/manual state.
            if funcs and func_idx >= 0:
                hint = f"{page + 1}/{NETDIAG_PAGE_COUNT} >{funcs[func_idx % len(funcs)][0]}"
            else:
                hint = f"{page + 1}/{NETDIAG_PAGE_COUNT} {state}"
        else:
            hint = f"{page + 1}/{NETDIAG_PAGE_COUNT} {state}  K1nav K2port K3png K4dns"
        self._draw_page_frame(draw, f"NET {name}", hint=hint)
        y = int(28 * sy)
        if not data:
            self._draw_stat_rows(draw, y, [("Status", "gathering...")])
            return
        eth = data.get('eth')

        if page == 0:  # LINK — physical link state
            if not eth:
                self._draw_stat_rows(draw, y, [("Ethernet", "not found"),
                                               ("Ports seen", str(data.get('eth_count', 0)))])
                return
            link = ('UP' if eth.get('link_detected') is True
                    else 'DOWN' if eth.get('link_detected') is False
                    else str(eth.get('operstate', '?')).upper())
            an = eth.get('autoneg')
            an_s = 'on' if an is True else ('off' if an is False else '—')
            self._draw_stat_rows(draw, y, [
                ("Iface", eth.get('name', '?')),
                ("Link", link),
                ("Speed", eth.get('speed') or '—'),
                ("Duplex", eth.get('duplex') or '—'),
                ("Auto-neg", an_s),
                ("MAC", eth.get('mac') or '—'),
            ])

        elif page == 1:  # IP — addressing & reachability basics
            gw = data.get('gateway') or {}
            dns = data.get('dns') or []
            ipv4 = (eth.get('ipv4') if eth else []) or []
            rows = [
                ("Method", (eth.get('ip_method') if eth else None) or '—'),
                ("IPv4", ipv4[0] if ipv4 else 'none'),
            ]
            if len(ipv4) > 1:
                rows.append(("IPv4#2", ipv4[1]))
            rows.append(("Gateway", gw.get('ip') or '—'))
            if gw.get('ptr'):
                rows.append(("GW name", gw.get('ptr')))
            if dns:
                rows.append(("DNS", dns[0]))
            if len(dns) > 1:
                rows.append(("DNS#2", dns[1]))
            self._draw_stat_rows(draw, y, rows)

        elif page == 2:  # SWITCH — LLDP/CDP neighbour + PoE
            lldp = data.get('lldp') or {}
            if not lldp.get('installed', True):
                self._draw_stat_rows(draw, y, [("LLDP", "not installed"),
                                               ("Enable via", "Switch tab")])
                return
            n = lldp.get('neighbor')
            if not n:
                self._draw_stat_rows(draw, y, [("Switch", "none seen"),
                                               ("Announce", "~30s wait")])
                return
            poe = n.get('poe')
            if poe and poe.get('powered'):
                bits = []
                if poe.get('type'):
                    bits.append(poe['type'])                    # af/at/bt
                via = poe.get('power_via')
                if via:
                    bits.append('mid' if via == 'midspan' else 'end')
                w = poe.get('allocated_w') or poe.get('requested_w')
                if w:
                    bits.append(f"{w}W")
                poe_s = ' '.join(bits) or 'yes'
            elif poe:
                poe_s = poe.get('device_type') or 'no'
            else:
                poe_s = '—'
            self._draw_stat_rows(draw, y, [
                ("Switch", n.get('switch_name') or '—'),
                ("Port", n.get('port_descr') or n.get('port_id') or '—'),
                ("VLAN", n.get('vlan_id') or '—'),
                ("PoE", poe_s),
                ("Proto", n.get('protocol') or '—'),
                ("Mgmt IP", n.get('mgmt_ip') or '—'),
            ])

        elif page == 3:  # DHCP — rogue-server / snooping watch
            st = self._netdiag_dhcp()
            d = st.get('data')
            if not d:
                self._draw_stat_rows(draw, y, [
                    ("DHCP", "scanning..." if st.get('scanning') else "no data"),
                    ("Wait", "~10s"),
                ])
                return
            servers = d.get('servers') or []
            verdict = str(d.get('verdict', '?')).upper()
            rows = [
                ("Verdict", verdict),
                ("Servers", str(d.get('server_count', 0))),
            ]
            if servers:
                s0 = servers[0]
                rows.append(("Server", s0.get('server_id') or '—'))
                rows.append(("Offers GW", s0.get('router') or '—'))
            rows.append(("Your GW", d.get('gateway') or '—'))
            if d.get('rogue_count'):
                rows.append(("ROGUE!", str(d.get('rogue_count'))))
            self._draw_stat_rows(draw, y, rows)

        elif page == 4:  # WIFI — current wireless association (SSID + RSSI)
            wl = self._fetch_wifi_link()
            if not wl.get('ssid'):
                self._draw_stat_rows(draw, y, [("WiFi", "not connected"),
                                               ("Iface", wl.get('iface') or '—')])
                return
            rows = [("SSID", wl['ssid'])]
            if wl.get('signal') is not None:
                rows.append(("RSSI", f"{wl['signal']} dBm"))
                rows.append(("Quality", f"{wl['quality']}%"))
            if wl.get('band'):
                rows.append(("Band/Ch", f"{wl['band']}G ch{wl['channel']}"))
            if wl.get('rate'):
                rows.append(("Rate", f"{int(wl['rate'])} Mbps"))
            yy = self._draw_stat_rows(draw, y, rows)
            # A live signal bar under the facts (walk around to find dead spots).
            if wl.get('signal') is not None:
                sx = getattr(self, 'render_sx', self.scale_factor_x)
                w = getattr(self, 'render_w', self.shared_data.width)
                pad_x = int(6 * sx)
                self._draw_signal_bar(draw, yy + int(3 * sy), wl['signal'],
                                      pad_x, w - pad_x)

        elif page == 5:  # SIGNAL — nearby networks' signal strengths (scan)
            st = self._netdiag_wifi_scan()
            aps = st.get('aps')
            if not aps:
                self._draw_stat_rows(draw, y, [
                    ("Signal", "scanning..." if st.get('scanning') else "no data"),
                    ("Wait", "~5s"),
                ])
                return
            self._draw_signal_bars(draw, y, aps)

        elif page == 6:  # SPECTRUM — per-channel occupancy graph (band via func_idx)
            st = self._netdiag_wifi_scan()
            spectrum = st.get('spectrum')
            if spectrum is None:
                self._draw_stat_rows(draw, y, [
                    ("Spectrum", "scanning..." if st.get('scanning') else "no data"),
                    ("Wait", "~5s"),
                ])
                return
            band = ['2.4', '5', '6'][(func_idx if func_idx >= 0 else 0) % 3]
            self._draw_spectrum(draw, y, band, spectrum, st.get('bands') or {},
                                st.get('iface'))

        elif page == 7:  # IFACE — which NIC the egress tests originate from.
            # Up/Down highlights Auto or an interface (footer hint), press pins
            # it. '*' marks the active selection; each row shows the NIC's IP
            # (usable), 'no IP' (link up but unaddressed) or 'down'.
            bl = self.button_listener
            sel = getattr(bl, 'netdiag_iface', None) if bl else None
            auto = netdiag_auto_iface()
            rows = [(("*" if sel is None else "") + "Auto",
                     f"> {auto}" if auto else 'none usable')]
            for c in netdiag_iface_choices():
                nm = c['name']
                if len(nm) > 10:   # enx<mac> names — keep head + MAC tail
                    nm = nm[:5] + '~' + nm[-4:]
                label = ("*" if sel == c['name'] else "") + nm
                if c['usb'] and len(label) <= 9:
                    label += " USB"
                status = c['ipv4'] or ('no IP' if c['up'] else 'down')
                rows.append((label, status))
            self._draw_stat_rows(draw, y, rows)

        elif page == 8:  # BT — on-demand Bluetooth/BLE neighbours (press scans)
            self._draw_neighbour_card(draw, y, 'bt')

        else:  # page 9: ZIGBEE — on-demand 802.15.4 sniff (press scans)
            self._draw_neighbour_card(draw, y, 'zigbee')

    def _draw_neighbour_card(self, draw, y, which):
        """The BT / ZIGBEE cards: the last on-demand 2.4 GHz neighbour scan.

        Both are one-shot rather than background-polled — BT discovery and an
        802.15.4 sniff each cost radio time, and Zigbee needs a HuginnESP that
        wardriving may be holding — so the card shows the previous result (or a
        prompt) and the joystick press runs a new scan. `which` is 'bt' or
        'zigbee'; the payloads differ only in the per-device fields.
        """
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        bl = self.button_listener
        res = getattr(bl, 'netdiag_bt' if which == 'bt' else 'netdiag_zb', None) if bl else None

        if not res:
            label = 'BT' if which == 'bt' else 'Zigbee'
            self._draw_stat_rows(draw, y, [(label, 'no scan'),
                                           ('Press', 'scans'),
                                           ('Takes', '~8s')])
            return
        if res.get('error'):
            self._draw_stat_rows(draw, y, [('Failed', _short_scan_error(res['error'])),
                                           ('Press', 'retries')])
            return

        itf = res.get('interference') or {}
        rows = [('Devices', res.get('device_count', 0))]
        if which == 'bt':
            rows.append(('LE/Clsc', f"{itf.get('le_count', 0)}/{itf.get('classic_count', 0)}"))
        else:
            rows.append(('Channels', itf.get('channel_count', 0)))
        # Age matters on a one-shot card — a stale scan shouldn't read as live.
        ts = res.get('timestamp')
        if isinstance(ts, (int, float)) and ts > 0:
            age = max(0, int(time.time() - ts))
            rows.append(('Age', f"{age}s" if age < 120 else f"{age // 60}m"))
        yy = self._draw_stat_rows(draw, y, rows)

        # Strongest few neighbours as name/addr + signal bars — the same "who is
        # loud near me" read the SIGNAL card gives for Wi-Fi.
        devices = (res.get('devices') or [])[:3]
        if devices:
            aps = []
            for d in devices:
                if which == 'bt':
                    name = d.get('name') or d.get('vendor') or (d.get('mac') or '')[-8:]
                else:
                    # Channel first (it's what decides Wi-Fi overlap) then the
                    # device's own address — the PAN ID repeats across a mesh,
                    # so it can't tell two rows apart in the narrow name column.
                    addr = str(d.get('addr') or d.get('short_addr') or '')
                    if addr.lower().startswith('0x'):
                        addr = addr[2:]
                    ch = d.get('channel')
                    name = f"c{ch} {addr}" if ch is not None else addr
                aps.append({'ssid': str(name), 'signal': d.get('rssi')})
            self._draw_signal_bars(draw, yy + int(2 * sy), aps)

    def _draw_spectrum(self, draw, y, band, spectrum, supported, iface=None):
        """Channel-occupancy spectrum for one band on the LCD HAT: a bar per
        channel, height ∝ strongest AP's signal there, with DFS/radar channels
        drawn hollow and the busiest channel tick-marked. This is the analyzer's
        signature 'Bar' view shrunk to 128 px. `band` is '2.4'|'5'|'6'; `iface`
        (the scanned adapter) is shown so it's obvious which radio 5/6 GHz
        come from."""
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        pad_x = int(6 * sx)
        band_lbl = {'2.4': '2.4G', '5': '5G', '6': '6G'}.get(band, band)

        # Adapter name, right-aligned on the header row (answers "which radio?").
        if iface:
            iw = font.getlength(iface)
            draw.text((w - pad_x - iw, y), iface, font=font, fill=0)
            hdr_avail = w - 2 * pad_x - iw - int(4 * sx)
        else:
            hdr_avail = w - 2 * pad_x

        info = spectrum.get(band) or {}
        chans = info.get('channels') or []
        if not chans:
            reason = 'not supported' if not supported.get(band, True) else 'no APs seen'
            draw.text((pad_x, y), band_lbl, font=font, fill=0)
            self._draw_stat_rows(draw, y + int(13 * sy),
                                 [(reason, ""), ("Up/Down", "= band")])
            return

        # Header (left): band · AP count · strongest signal + its channel,
        # trimmed so it never runs into the right-aligned adapter name.
        best = max(chans, key=lambda c: (c.get('max_signal') is not None,
                                         c.get('max_signal') or -999))
        best_sig = best.get('max_signal')
        hdr = f"{band_lbl}  {info.get('ap_count', 0)}AP"
        if best_sig is not None:
            hdr += f"  ch{best.get('channel')} {int(best_sig)}"
        while hdr and font.getlength(hdr) > hdr_avail:
            hdr = hdr[:-1]
        draw.text((pad_x, y), hdr, font=font, fill=0)

        # Plot area under the header, leaving a row for channel-axis labels
        # above the footer divider (h - 18·sy) so they don't collide with it.
        top = y + int(13 * sy)
        bottom = h - int(28 * sy)
        axis_y = bottom
        x0, x1 = pad_x, w - pad_x
        if bottom - top < int(10 * sy) or x1 - x0 < 8:
            return
        draw.line((x0, axis_y, x1, axis_y), fill=0)         # baseline
        n = len(chans)
        slot = (x1 - x0) / float(n)
        bar_w = max(1, int(slot) - 1)
        plot_h = axis_y - top
        for i, c in enumerate(chans):
            bx = int(x0 + i * slot)
            sig = c.get('max_signal')
            q = self._dbm_to_quality(sig) if sig is not None else 0
            bh = int(plot_h * (q or 0) / 100.0)
            if bh <= 0:
                continue
            by = axis_y - bh
            if c.get('radar'):                              # DFS/radar → hollow
                draw.rectangle([bx, by, bx + bar_w, axis_y], outline=0)
            else:
                draw.rectangle([bx, by, bx + bar_w, axis_y], fill=0)
            if c is best and bh > 0:                        # mark the busiest
                draw.line((bx, by - int(3 * sy), bx + bar_w, by - int(3 * sy)), fill=0)

        # Channel-axis ticks: label first, middle and last channel numbers.
        for i in (0, n // 2, n - 1):
            lab = str(chans[i].get('channel'))
            lx = int(x0 + i * slot)
            lx = min(lx, x1 - int(font.getlength(lab)))
            draw.text((max(x0, lx), axis_y + int(1 * sy)), lab, font=font, fill=0)

    def _draw_wrapped_note(self, draw, y, text, max_lines=3):
        """Word-wrap a short note across up to max_lines using the small font."""
        w = getattr(self, 'render_w', self.shared_data.width)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        pad_x = int(6 * sx)
        avail = w - 2 * pad_x
        lines, cur = [], ''
        for word in str(text).split():
            trial = (cur + ' ' + word).strip()
            if font.getlength(trial) <= avail or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = word
                if len(lines) >= max_lines:
                    break
        if cur and len(lines) < max_lines:
            lines.append(cur)
        line_h = int(11 * sy)
        for ln in lines[:max_lines]:
            draw.text((pad_x, y), ln, font=font, fill=0)
            y += line_h
        return y

    def _render_netdiag_result(self, image, draw, result):
        """Render a one-shot netdiag test result (triggered by a HAT key). Holds
        on screen until KEY1 returns to the auto-cycling pages."""
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        title = str(result.get('title') or 'TEST')
        running = result.get('running')
        hint = "running..." if running else "K1 back to pages"
        self._draw_page_frame(draw, f"NET {title}", hint=hint)
        y = int(28 * sy)
        if running:
            self._draw_stat_rows(draw, y, [("Status", "running..."),
                                           ("Please", "wait a few s")])
            return
        verdict = result.get('verdict')
        if verdict:
            big = str(verdict[0])
            font_big = self.shared_data.font_viking
            tw = font_big.getlength(big)
            draw.text(((w - tw) / 2, y), big, font=font_big, fill=0)
            y += int(24 * sy)
        y = self._draw_stat_rows(draw, y, result.get('rows') or [])
        note = result.get('note')
        if note:
            self._draw_wrapped_note(draw, y + int(3 * sy), note)

    def _commit_netdiag_frame(self, image):
        """Push a rendered netdiag frame to the panel and the web mirror."""
        epd_img = _apply_epd_rotation(image, self.screen_reversed)
        self.epd_helper.display_partial(epd_img)
        self.epd_helper.display_partial(epd_img)
        web_img = _apply_web_rotation(image, self.web_screen_reversed)
        try:
            with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                web_img.save(img_file)
                img_file.flush()
                os.fsync(img_file.fileno())
        except Exception:
            pass

    def _render_main_compact(self, image, draw, W, H):
        """Compact PAGE_MAIN layout for a small square panel (e.g. the 128x128
        LCD HAT). The default dashboard is authored for a ~122x250 canvas, so on
        a 128-tall panel its absolute coordinates fall off-screen and the speech
        text collides with the 78px character sprite. This lays the same
        elements out to fit: header, two icon+count stat rows, the mood lines,
        the speech line beside a shrunk character, all inside 128x128."""
        sd = self.shared_data
        font = sd.font_arial9
        # --- frame + header ---
        # The header keeps a small connection glyph in the top-left corner and
        # the battery in the top-right, so the centred title is fitted to the
        # middle strip only (never colliding with either) and the divider sits
        # below all three.
        draw.rectangle((0, 0, W - 1, H - 1), outline=0)
        # Left connection glyph + IP octet, confined to the top-left so they
        # clear the title. `left_used` grows to whatever they occupy so the
        # title padding can step around them.
        left_used = 2
        try:
            if getattr(sd, 'ap_mode_active', False):
                ap_text = "AP"
                if getattr(sd, 'ap_client_count', 0) > 0:
                    ap_text = f"AP:{sd.ap_client_count}"
                draw.text((2, 3), ap_text, font=font, fill=0)
                left_used = 2 + int(font.getlength(ap_text))
            elif getattr(sd, 'wifi_connected', False):
                try:
                    q = getattr(sd, 'wifi_signal_quality', None)
                    if q is None:
                        q = self._dbm_to_quality(getattr(sd, 'wifi_signal_dbm', None))
                    waves = max(1, min(3, self.get_wifi_wave_count(q)))
                except Exception:
                    waves = 3
                cx, cy = 4, 13
                for i in range(waves):
                    r = 3 + i * 3
                    draw.arc((cx - r, cy - r, cx + r, cy + r), start=225, end=315, fill=0, width=1)
                left_used = 14
                try:
                    ip_octet = self.get_wifi_ip_last_octet()
                except Exception:
                    ip_octet = None
                if ip_octet:
                    draw.text((15, 4), ip_octet, font=font, fill=0)
                    left_used = 15 + int(font.getlength(ip_octet))
        except Exception:
            pass
        # Battery %, top-right (PiSugar)
        bat_w = 0
        try:
            _ri = getattr(sd, 'ragnar_instance', None)
            _ps = getattr(_ri, 'pisugar_listener', None) if _ri else None
            if _ps and _ps.available:
                bl = _ps.get_battery_level()
                if bl is not None:
                    bt = f"{int(round(bl))}%{'+' if _ps.is_charging() else ''}"
                    bat_w = int(font.getlength(bt)) + 3
                    draw.text((W - bat_w + 1, 3), bt, font=font, fill=0)
        except Exception:
            pass
        # Centre the title in the strip between the glyph/IP and the battery.
        left_pad = max(18, left_used + 2)
        right_pad = max(18, bat_w)
        avail = W - left_pad - right_pad
        title_font = self._fit_font('Viking.TTF', sd.font_viking, "RAGNAR", avail)
        tw = title_font.getlength("RAGNAR")
        draw.text((left_pad + (avail - tw) / 2, 1), "RAGNAR", font=title_font, fill=0)
        draw.line((1, 16, W - 1, 16), fill=0)

        # --- two icon+count stat rows (icons ~30% smaller so they fit) ---
        icon_h = 13   # 18px source icons scaled down ~30%

        def _fit_icon(icon):
            if icon is None:
                return None
            try:
                if icon.height > icon_h:
                    ratio = icon_h / icon.height
                    return icon.resize((max(1, int(icon.width * ratio)), icon_h), Image.NEAREST)
            except Exception:
                return icon
            return icon

        def _row(y, items):
            slot = W // len(items)
            for i, (icon, val) in enumerate(items):
                x = i * slot + 2
                icon = _fit_icon(icon)
                if icon is not None:
                    try:
                        image.paste(icon, (x, y))
                        tx = x + icon.width + 1
                    except Exception:
                        tx = x + icon_h + 1
                else:
                    tx = x
                draw.text((tx, y + 2), str(val), font=font, fill=0)

        _row(20, [(getattr(sd, 'target', None), sd.targetnbr),
                  (getattr(sd, 'port', None),   sd.portnbr),
                  (getattr(sd, 'vuln', None),   sd.vulnnbr),
                  (getattr(sd, 'cred', None),   sd.crednbr)])
        _row(37, [(getattr(sd, 'zombie', None),  sd.zombiesnbr),
                  (getattr(sd, 'data', None),    sd.datanbr),
                  (getattr(sd, 'money', None),   sd.coinnbr),
                  (getattr(sd, 'attacks', None), sd.attacksnbr)])
        draw.line((1, 54, W - 1, 54), fill=0)

        # --- mood / status lines ---
        try:
            sd.update_ragnarstatus()
        except Exception:
            pass
        draw.text((3, 56), str(getattr(sd, 'ragnarstatustext', '') or '')[:24], font=font, fill=0)
        draw.text((3, 66), str(getattr(sd, 'ragnarstatustext2', '') or '')[:24], font=font, fill=0)

        # --- character sprite, shrunk into the bottom-right corner ---
        vk_w = 0
        vk = getattr(sd, 'imagegen', None)
        if vk is not None:
            try:
                target_h = 46
                if vk.height > target_h:
                    ratio = target_h / vk.height
                    vk = vk.resize((max(1, int(vk.width * ratio)), target_h), Image.NEAREST)
                vk_w = vk.width
                image.paste(vk, (W - vk_w - 1, H - vk.height - 1))
            except Exception:
                vk_w = 0

        # --- speech, wrapped into the space left of the sprite ---
        says = str(getattr(sd, 'ragnarsays', '') or '')
        if says:
            avail_w = W - vk_w - 6
            try:
                lines = sd.wrap_text(says, sd.font_arialbold, avail_w)
            except Exception:
                lines = [says]
            y = 82
            for line in lines:
                if y > H - 12:
                    break
                draw.text((3, y), line, font=sd.font_arialbold, fill=0)
                bb = sd.font_arialbold.getbbox(line)
                y += (bb[3] - bb[1]) + 2

    def _fetch_network_data(self):
        """Fetch real host data from database."""
        sd = self.shared_data
        try:
            hosts = sd.db.get_all_hosts()
            alive = [h for h in hosts if h.get('status') == 'alive']
            total_ports = 0
            for h in hosts:
                ports_str = h.get('ports', '')
                if ports_str:
                    total_ports += len([p for p in str(ports_str).split(';') if p.strip()])
            return {
                'total': len(hosts),
                'alive': len(alive),
                'ports': total_ports,
                'hosts': hosts[:8],
            }
        except Exception as e:
            logger.debug(f"DB host fetch error: {e}")
            return None

    def _fetch_vuln_intel_data(self):
        """Fetch real vulnerability intelligence from scan files."""
        sd = self.shared_data
        vuln_dir = getattr(sd, 'vulnerabilities_dir', None)
        if not vuln_dir or not os.path.exists(vuln_dir):
            return None
        scans = 0
        hosts_set = set()
        services = 0
        scripts = 0
        recent_targets = []
        try:
            for fname in os.listdir(vuln_dir):
                fpath = os.path.join(vuln_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                if fname.endswith('_vuln_scan.txt'):
                    scans += 1
                    ip = fname.split('_')[0] if '_' in fname else fname
                    hosts_set.add(ip)
                    if len(recent_targets) < 5:
                        recent_targets.append(ip)
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read()
                        for line in content.split('\n'):
                            if '/tcp' in line or '/udp' in line:
                                services += 1
                            if '|' in line and '_' in line:
                                scripts += 1
                    except Exception:
                        pass
                elif fname.startswith('lynis_') and fname.endswith('_pentest.txt'):
                    scans += 1
                    parts = fname.replace('lynis_', '').replace('_pentest.txt', '')
                    hosts_set.add(parts)
        except Exception as e:
            logger.debug(f"Vuln intel scan error: {e}")
        return {
            'scans': scans,
            'hosts': len(hosts_set),
            'services': services,
            'scripts': scripts,
            'targets': recent_targets,
        }

    def _count_cred_file(self, filepath):
        """Count credential entries in a CSV file."""
        try:
            if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                return 0
            with open(filepath, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                return sum(1 for row in reader if row)
        except Exception:
            return 0

    def _fetch_discovered_data(self):
        """Fetch real credentials, loot, and attack data."""
        sd = self.shared_data
        creds = {}
        for svc, attr in [('SSH', 'sshfile'), ('SMB', 'smbfile'), ('FTP', 'ftpfile'),
                          ('Telnet', 'telnetfile'), ('RDP', 'rdpfile'), ('SQL', 'sqlfile')]:
            filepath = getattr(sd, attr, '')
            creds[svc] = self._count_cred_file(filepath) if filepath else 0
        total_creds = sum(creds.values())
        loot_count = 0
        try:
            if os.path.exists(sd.datastolendir):
                for _, _, files in os.walk(sd.datastolendir):
                    loot_count += len([f for f in files if not f.endswith('.log')])
        except Exception:
            pass
        attack_count = 0
        try:
            attacks_dir = os.path.join(sd.logsdir, 'attacks')
            if os.path.exists(attacks_dir):
                import json as json_mod
                for fname in os.listdir(attacks_dir):
                    if fname.endswith('.json'):
                        try:
                            with open(os.path.join(attacks_dir, fname), 'r') as f:
                                data = json_mod.load(f)
                            if isinstance(data, list):
                                attack_count += len(data)
                        except Exception:
                            pass
        except Exception:
            pass
        return {
            'creds': creds,
            'total_creds': total_creds,
            'loot': loot_count,
            'attacks': attack_count,
            'zombies': getattr(sd, 'zombiesnbr', 0),
        }

    def _fetch_advanced_data(self):
        """Fetch real advanced vulnerability scanner data."""
        scanner = getattr(self.shared_data, '_advanced_vuln_scanner', None)
        if not scanner:
            return None
        try:
            available = scanner.get_available_scanners()
            summary = scanner.get_summary()
            active = scanner.get_active_scans_list()
            return {
                'scanners': available,
                'summary': summary,
                'active_scans': active,
            }
        except Exception as e:
            logger.debug(f"Advanced scanner data error: {e}")
            return None

    def _fetch_traffic_data(self):
        """Fetch real traffic analyzer data."""
        analyzer = getattr(self.shared_data, '_traffic_analyzer', None)
        if not analyzer:
            return None
        try:
            summary = analyzer.get_summary()
            return summary
        except Exception as e:
            logger.debug(f"Traffic analyzer data error: {e}")
            return None

    def _render_network_page(self, image, draw):
        """Render Page 2: Network Scanner - real host data from database."""
        self._draw_page_frame(draw, "NETWORK SCAN")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        sd = self.shared_data
        y = int(28 * sy)
        line_h = int(14 * sy)
        pad_x = int(6 * sx)
        row_h = int(12 * sy)

        data = self._get_cached_page_data('network', self._fetch_network_data)

        if data:
            stats = [
                ("Hosts alive", f"{data['alive']}/{data['total']}"),
                ("Open ports", str(data['ports'])),
                ("Credentials", str(getattr(sd, 'crednbr', 0))),
                ("Status", str(getattr(sd, 'ragnarorch_status', 'IDLE'))),
            ]
            y = self._draw_stat_rows(draw, y, stats)

            # Divider before host list
            y += int(2 * sy)
            draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
            y += int(4 * sy)

            # List actual discovered hosts
            hosts = data.get('hosts', [])
            max_rows = (h - int(18 * sy) - y) // row_h
            for host in hosts[:max_rows]:
                ip = host.get('ip', '?')
                status = host.get('status', '?')
                ports = host.get('ports', '')
                port_count = len([p for p in str(ports).split(';') if p.strip()]) if ports else 0
                line = f"{ip}"
                extra = f"{status[:3]} p:{port_count}"
                draw.text((pad_x, y), line, font=font, fill=0)
                draw.text((w - pad_x - font.getlength(extra), y), extra, font=font, fill=0)
                y += row_h
        else:
            stats = [
                ("Hosts found", str(getattr(sd, 'targetnbr', 0))),
                ("Open ports", str(getattr(sd, 'portnbr', 0))),
                ("Credentials", str(getattr(sd, 'crednbr', 0))),
                ("Network KB", str(getattr(sd, 'networkkbnbr', 0))),
                ("Status", str(getattr(sd, 'ragnarorch_status', 'IDLE'))),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_vuln_page(self, image, draw):
        """Render Page 3: Vulnerability Scanner - real scan intel from files."""
        self._draw_page_frame(draw, "VULN INTEL")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        sd = self.shared_data
        y = int(28 * sy)
        row_h = int(12 * sy)
        pad_x = int(6 * sx)

        data = self._get_cached_page_data('vuln_intel', self._fetch_vuln_intel_data, ttl=30)

        if data:
            stats = [
                ("Vulns found", str(getattr(sd, 'vulnnbr', 0))),
                ("Scan reports", str(data['scans'])),
                ("Hosts scanned", str(data['hosts'])),
                ("Services", str(data['services'])),
                ("Script outputs", str(data['scripts'])),
            ]
            y = self._draw_stat_rows(draw, y, stats)

            # Show recent scan targets
            targets = data.get('targets', [])
            if targets:
                y += int(2 * sy)
                draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
                y += int(4 * sy)
                draw.text((pad_x, y), "Recent targets:", font=font, fill=0)
                y += row_h
                max_rows = (h - int(18 * sy) - y) // row_h
                for ip in targets[:max_rows]:
                    draw.text((int(10 * sx), y), ip, font=font, fill=0)
                    y += row_h
        else:
            stats = [
                ("Vulns found", str(getattr(sd, 'vulnnbr', 0))),
                ("Attacks avail", str(getattr(sd, 'attacksnbr', 0))),
                ("Hosts scanned", str(getattr(sd, 'targetnbr', 0))),
                ("No scan files", ""),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_discovered_page(self, image, draw):
        """Render Page 4: Discovered - real credentials, loot, and attack data."""
        self._draw_page_frame(draw, "DISCOVERED")
        h = getattr(self, 'render_h', self.shared_data.height)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        top_y = int(28 * sy)
        bottom_y = h - int(18 * sy)

        data = self._get_cached_page_data('discovered', self._fetch_discovered_data, ttl=15)

        if data:
            creds = data['creds']
            stats = [
                ("SSH creds", str(creds.get('SSH', 0))),
                ("SMB creds", str(creds.get('SMB', 0))),
                ("FTP creds", str(creds.get('FTP', 0))),
                ("Telnet", str(creds.get('Telnet', 0))),
                ("RDP creds", str(creds.get('RDP', 0))),
                ("SQL creds", str(creds.get('SQL', 0))),
            ]
            summary = [
                ("Data stolen", f"{data['loot']} files"),
                ("Attack logs", str(data['attacks'])),
                ("Zombies", str(data['zombies'])),
            ]
            self._draw_scrollable_rows(image, draw, top_y, bottom_y,
                                        [('rows', stats), ('divider', None), ('rows', summary)])
        else:
            stats = [
                ("Credentials", str(getattr(self.shared_data, 'crednbr', 0))),
                ("Data files", str(getattr(self.shared_data, 'datanbr', 0))),
                ("Zombies", str(getattr(self.shared_data, 'zombiesnbr', 0))),
            ]
            self._draw_stat_rows(draw, top_y, stats)

    def _render_advanced_page(self, image, draw):
        """Render Page 5: Advanced Vuln Scanner - real scanner status and findings."""
        self._draw_page_frame(draw, "ADV SCANNER")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        y = int(28 * sy)
        line_h = int(14 * sy)
        row_h = int(12 * sy)
        pad_x = int(6 * sx)

        data = self._get_cached_page_data('advanced', self._fetch_advanced_data, ttl=5)

        if data:
            scanners = data.get('scanners', {})
            summary = data.get('summary', {})
            active = data.get('active_scans', [])
            sev = summary.get('severity_counts', {})

            # Scanner availability
            scanner_items = []
            for name in ['nuclei', 'nikto', 'zap']:
                if name == 'zap':
                    running = scanners.get('zap_running', False)
                    status = "Running" if running else ("Ready" if scanners.get(name) else "N/A")
                else:
                    status = "Ready" if scanners.get(name) else "N/A"
                scanner_items.append((name.capitalize(), status))

            for label, value in scanner_items:
                draw.text((pad_x, y), label, font=font, fill=0)
                draw.text((w - pad_x - font.getlength(value), y), value, font=font, fill=0)
                y += line_h

            y += int(2 * sy)
            draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
            y += int(4 * sy)

            # Findings summary
            total = summary.get('total_findings', 0)
            draw.text((pad_x, y), "Findings", font=font, fill=0)
            draw.text((w - pad_x - font.getlength(str(total)), y), str(total), font=font, fill=0)
            y += line_h

            # Severity breakdown on one line each
            crit = sev.get('critical', 0)
            high = sev.get('high', 0)
            med = sev.get('medium', 0)
            low = sev.get('low', 0)
            sev_line = f"C:{crit} H:{high} M:{med} L:{low}"
            draw.text((pad_x, y), sev_line, font=font, fill=0)
            y += line_h

            # Active scans
            active_count = len([s for s in active if s.get('status') == 'running'])
            draw.text((pad_x, y), "Active scans", font=font, fill=0)
            draw.text((w - pad_x - font.getlength(str(active_count)), y), str(active_count), font=font, fill=0)
            y += line_h

            # Show running scan details
            for scan in active:
                if scan.get('status') == 'running' and y < h - int(32 * sy):
                    stype = scan.get('scan_type', '?')[:8]
                    progress = scan.get('progress_percent', 0)
                    line = f"{stype} {progress}%"
                    draw.text((int(10 * sx), y), line, font=font, fill=0)
                    y += row_h
        else:
            stats = [
                ("Scanner", "Not available"),
                ("Vulns found", str(getattr(self.shared_data, 'vulnnbr', 0))),
                ("Status", str(getattr(self.shared_data, 'ragnarstatustext', 'IDLE'))),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_traffic_page(self, image, draw):
        """Render Page 6: Traffic Analysis - real capture data."""
        self._draw_page_frame(draw, "TRAFFIC")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        y = int(28 * sy)

        data = self._get_cached_page_data('traffic', self._fetch_traffic_data, ttl=3)

        if data:
            status = data.get('status', 'stopped')
            pkts_sec = data.get('packets_per_second', 0)
            throughput = data.get('throughput_mbps', 0)
            total_pkts = data.get('total_packets', 0)
            total_bytes_h = data.get('total_bytes_human', '0 B')
            unique_hosts = data.get('unique_hosts', 0)
            connections = data.get('active_connections', 0)
            alerts = data.get('total_alerts', 0)
            dns = data.get('dns_queries_captured', 0)

            status_str = status.upper()
            stats = [
                ("Capture", status_str),
                ("Pkts/sec", f"{pkts_sec:.1f}"),
                ("Throughput", f"{throughput:.2f} Mbps"),
                ("Total pkts", str(total_pkts)),
                ("Total data", str(total_bytes_h)),
                ("Hosts seen", str(unique_hosts)),
                ("Connections", str(connections)),
                ("Alerts", str(alerts)),
                ("DNS queries", str(dns)),
            ]
            self._draw_stat_rows(draw, y, stats)
        else:
            stats = [
                ("Traffic", "Not available"),
                ("WiFi", "On" if self.shared_data.wifi_connected else "Off"),
                ("Status", str(getattr(self.shared_data, 'ragnarorch_status', 'IDLE'))),
            ]
            self._draw_stat_rows(draw, y, stats)

    # ------------------------------------------------------------------
    # Wardriving display page (EPD e-paper + used by other displays)
    # ------------------------------------------------------------------

    def _get_wardriving_data(self):
        """Fetch current wardriving status from the engine (if running)."""
        try:
            from webapp_modern import _get_wardriving_engine
            engine = _get_wardriving_engine()
            status = engine.get_status()
            return status
        except Exception:
            return None

    def _wd_compact_page(self):
        """Which wardriving screen the LCD joystick has paged to (0..N-1)."""
        try:
            return int(getattr(self.button_listener, 'wardrive_page', 0) or 0) % WARDRIVE_PAGE_COUNT
        except (TypeError, ValueError, AttributeError):
            return WD_PAGE_STATS

    def _render_wardriving_page_compact(self, image, draw, wd):
        """Dispatch to the wardriving screen the joystick has selected on the
        1.44" ST7735S LCD HAT (128x128). See WARDRIVE_PAGE_COUNT."""
        page = self._wd_compact_page()
        if page == WD_PAGE_MAP:
            self._render_wd_compact_map(image, draw, wd)
        elif page == WD_PAGE_GPS:
            self._render_wd_compact_gps(image, draw, wd)
        elif page == WD_PAGE_SKY:
            self._render_wd_compact_sky(image, draw, wd)
        elif page == WD_PAGE_SESSION:
            self._render_wd_compact_session(image, draw, wd)
        elif page == WD_PAGE_VIKING:
            self._render_wd_compact_viking(image, draw, wd)
        else:
            self._render_wd_compact_stats(image, draw, wd)

    def _draw_wd_compact_chrome(self, draw, title=None):
        """Shared border + footer for the compact wardriving screens.

        The footer carries the LCD HAT's wardriving key map (K1 leaves for the
        Ragnar screens, K2 reconnects Wi-Fi, K3 toggles the phone AP) plus a
        "n/N" page counter so the joystick paging is discoverable. Returns the
        y of the footer divider so callers know where their content band ends.
        """
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        font = self.shared_data.font_arial9

        draw.rectangle((1, 1, w - 1, h - 1), outline=0)

        ap_on = getattr(self.shared_data, 'wardrive_ap_active', False)
        hint = "K1Exit K2WiFi K3APoff" if ap_on else "K1Exit K2WiFi K3AP"
        page_str = f"{self._wd_compact_page() + 1}/{WARDRIVE_PAGE_COUNT}"

        footer_y = h - int(18 * sy)
        draw.line((1, footer_y, w - 1, footer_y), fill=0)

        # Page counter is pinned right; the hint is trimmed to whatever is left
        # so a longer hint never overruns it on the 128 px panel.
        pw = font.getlength(page_str)
        draw.text((w - int(4 * sx) - pw, h - int(16 * sy)), page_str, font=font, fill=0)
        avail = w - int(8 * sx) - pw - int(4 * sx)
        _hint = hint
        while _hint and font.getlength(_hint) > avail:
            _hint = _hint[:-1]
        draw.text((int(4 * sx), h - int(16 * sy)), _hint, font=font, fill=0)

        if title:
            tw = font.getlength(title)
            draw.text(((w - tw) / 2, int(3 * sy)), title, font=font, fill=0)

        return footer_y

    def _wd_compact_not_running(self, draw, wd):
        """Shared 'Starting.../Stopped' placeholder. True if it was drawn."""
        if wd and wd.get('running'):
            return False
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        font = self.shared_data.font_arial9
        font_row = self.shared_data.font_arial11
        never_started = not (wd and wd.get('session_id'))
        if self.shared_data.config.get('wardriving_on_boot', False) and never_started:
            msg1, msg2 = "Starting...", "Waiting for engine"
        else:
            msg1, msg2 = "Stopped", "Enable in WebUI"
        draw.text(((w - font_row.getlength(msg1)) / 2, int(45 * sy)), msg1, font=font_row, fill=0)
        draw.text(((w - font.getlength(msg2)) / 2, int(62 * sy)), msg2, font=font, fill=0)
        return True

    def _render_wd_compact_stats(self, image, draw, wd):
        """Compact wardriving layout for the 1.44" ST7735S LCD HAT (128x128).

        The square panel is too small for the full stat page, so we drop the
        "WARDRIVING" header entirely and show only what matters on the move:
        the 2.4 / 5 / 6 GHz network counts, GPS fix, and companion status.
        The key controls stay in the footer.
        """
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        font = self.shared_data.font_arial9
        font_row = self.shared_data.font_arial11
        font_lbl = self._font_at('Arial.ttf', int(9 * sy))
        font_num = self._font_at('Arial.ttf', int(22 * sy))

        # Border + footer controls (drawn first so the content band knows its
        # bottom). Colons/spaces dropped so the whole hint fits 128px.
        self._draw_wd_compact_chrome(draw)

        # Not running: centred status placeholder (starting vs stopped).
        if self._wd_compact_not_running(draw, wd):
            return

        st = wd.get('stats', {})
        gps = wd.get('gps', {})

        # --- Band counts: 2.4 / 5 / 6 GHz as a three-column grid ---
        bands = [
            ("2.4G", st.get('band_2_4ghz', 0)),
            ("5G",   st.get('band_5ghz', 0)),
            ("6G",   st.get('band_6ghz', 0)),
        ]
        col_w = (w - 2) / 3.0
        y_lbl = int(6 * sy)
        # A long drive pushes counts into the thousands, and a fixed size would
        # spill each number into its neighbour's column. Shrink the shared
        # number font until the widest of the three fits its column — one size
        # for all three so they stay visually consistent.
        max_num_w = col_w - int(4 * sx)
        widest = max((str(v) for _, v in bands), key=font_num.getlength)
        num_size = int(22 * sy)
        while num_size > 8 and font_num.getlength(widest) > max_num_w:
            num_size -= 1
            font_num = self._font_at('Arial.ttf', num_size)

        # Vertically centre the numbers in the band under the labels, so the
        # row stays balanced at whatever size the fit above settled on.
        band_top = int(18 * sy)
        band_bot = int(46 * sy)
        for i, (label, val) in enumerate(bands):
            cx = 1 + col_w * (i + 0.5)
            lw = font_lbl.getlength(label)
            draw.text((cx - lw / 2, y_lbl), label, font=font_lbl, fill=0)
            vs = str(val)
            bbox = font_num.getbbox(vs)
            vw, vh = bbox[2] - bbox[0], bbox[3] - bbox[1]
            ty = band_top + (band_bot - band_top - vh) / 2 - bbox[1]
            draw.text((cx - vw / 2 - bbox[0], ty), vs, font=font_num, fill=0)

        y = int(48 * sy)
        draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
        y += int(6 * sy)

        # --- GPS + Companion rows (right-aligned key/value, roomy font) ---
        if gps.get('has_fix'):
            gps_str = f"{gps.get('latitude', 0):.3f},{gps.get('longitude', 0):.3f}"
        elif gps.get('connected'):
            in_view = gps.get('satellites_in_view')
            if isinstance(in_view, (int, float)) and in_view > 0:
                gps_str = f"Search {int(in_view)}v"
            else:
                gps_str = "Searching"
        else:
            gps_str = "No GPS"

        companions = wd.get('companions') or []
        active = [c for c in companions if c.get('connected')]
        if active:
            first = active[0].get('name') or 'Companion'
            comp_str = first if len(active) == 1 else f"{first}+{len(active) - 1}"
        else:
            comp_str = "None"

        # Speed row: only while we have a fix and are actually moving, so a
        # stationary stop doesn't waste one of the few rows this panel affords.
        rows = [("GPS", gps_str)]
        spd = gps.get('speed_kmh')
        if gps.get('has_fix') and spd is not None and spd > 0:
            unit = self.config.get('wardriving_speed_unit', 'kmh')
            rows.append(("Spd", _fmt_wd_speed(spd, unit)))
        rows.append(("Comp", comp_str))

        pad_x = int(6 * sx)
        line_h = int(18 * sy)
        for label, value in rows:
            val_str = str(value)
            vw = font_row.getlength(val_str)
            # Trim the value if it would collide with the label.
            while val_str and pad_x + font_row.getlength(label) + int(6 * sx) > w - pad_x - vw:
                val_str = val_str[:-1]
                vw = font_row.getlength(val_str)
            draw.text((pad_x, y), label, font=font_row, fill=0)
            draw.text((w - pad_x - vw, y), val_str, font=font_row, fill=0)
            y += line_h

    def _wd_compact_rows(self, draw, rows, top, footer_y):
        """Draw right-aligned key/value rows in a compact screen's content band,
        stopping before the footer divider so nothing overprints the hints."""
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        font_row = self.shared_data.font_arial11
        pad_x = int(6 * sx)
        # 13px lines fit 7 rows in the 128px panel's content band; at 15 the
        # last row (GPS course / session trackpoints) fell off the bottom.
        line_h = int(13 * sy)
        y = top
        for label, value in rows:
            if y + line_h > footer_y:
                break
            val_str = str(value)
            vw = font_row.getlength(val_str)
            # Trim the value if it would collide with the label.
            while val_str and pad_x + font_row.getlength(label) + int(6 * sx) > w - pad_x - vw:
                val_str = val_str[:-1]
                vw = font_row.getlength(val_str)
            draw.text((pad_x, y), label, font=font_row, fill=0)
            draw.text((w - pad_x - vw, y), val_str, font=font_row, fill=0)
            y += line_h
        return y

    def _render_wd_compact_gps(self, image, draw, wd):
        """Compact GPS detail screen — the fix quality behind the stats page's
        one-line summary: position, altitude, satellites, HDOP, speed, course."""
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        footer_y = self._draw_wd_compact_chrome(draw, title="GPS")
        if self._wd_compact_not_running(draw, wd):
            return

        gps = (wd.get('gps') or {})
        rows = []
        if gps.get('has_fix'):
            lat, lon = gps.get('latitude'), gps.get('longitude')
            rows.append(("Lat", f"{lat:.5f}" if isinstance(lat, (int, float)) else "-"))
            rows.append(("Lon", f"{lon:.5f}" if isinstance(lon, (int, float)) else "-"))
            alt = gps.get('altitude')
            if isinstance(alt, (int, float)):
                rows.append(("Alt", f"{alt:.0f}m"))
        elif gps.get('connected'):
            rows.append(("Fix", "Searching"))
        else:
            rows.append(("Fix", "No GPS"))

        used = gps.get('satellites')
        in_view = gps.get('satellites_in_view')
        if isinstance(used, (int, float)) or isinstance(in_view, (int, float)):
            u = int(used) if isinstance(used, (int, float)) else 0
            v = int(in_view) if isinstance(in_view, (int, float)) else 0
            rows.append(("Sats", f"{u}/{v}"))
        hdop = gps.get('hdop')
        if isinstance(hdop, (int, float)) and hdop > 0:
            rows.append(("HDOP", f"{hdop:.1f}"))

        spd = gps.get('speed_kmh')
        if isinstance(spd, (int, float)):
            unit = self.config.get('wardriving_speed_unit', 'kmh')
            rows.append(("Spd", _fmt_wd_speed(spd, unit)))
        course = gps.get('course')
        if gps.get('has_fix') and isinstance(course, (int, float)):
            rows.append(("Crs", f"{course:.0f}"))

        self._wd_compact_rows(draw, rows, int(15 * sy), footer_y)

    def _wd_sky_data(self):
        """Per-satellite sky list (constellation/az/elev/snr) from the live GPS,
        for the compact SKY screen. Pulled straight off the running engine's
        GPSManager (the same get_sky_view() the web sky view polls) since the
        wardriving status dict doesn't carry the per-satellite detail. Returns
        [] when GPS isn't running or nothing is being tracked."""
        try:
            from webapp_modern import _get_wardriving_engine
            engine = _get_wardriving_engine()
            if engine and getattr(engine, '_gps', None) and engine._running:
                return engine._gps.get_sky_view() or []
        except Exception:
            pass
        return []

    def _render_wd_compact_sky(self, image, draw, wd):
        """Compact GPS sky view — a polar plot of the satellites in view, the
        graphical twin of the web sky view. North is up, the outer circle is the
        horizon (elevation 0°) and the centre is the zenith (90°); each satellite
        sits at its azimuth/elevation. Dots are filled for a strong signal and
        hollow for a weak one, so a glance shows both geometry and fix quality."""
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        font = self.shared_data.font_arial9
        footer_y = self._draw_wd_compact_chrome(draw, title="SKY")
        if self._wd_compact_not_running(draw, wd):
            return

        top = int(15 * sy)
        bottom = footer_y - int(2 * sy)
        cx = w / 2.0
        cy = (top + bottom) / 2.0
        radius = min(w / 2.0, (bottom - top) / 2.0) - int(9 * sx)

        # Horizon + a mid ring at elevation 45°, then the N/E/S/W crosshairs so
        # the azimuth of each satellite is readable.
        draw.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), outline=0)
        mid = radius / 2.0
        draw.ellipse((cx - mid, cy - mid, cx + mid, cy + mid), outline=0)
        draw.line((cx, cy - radius, cx, cy + radius), fill=0)
        draw.line((cx - radius, cy, cx + radius, cy), fill=0)

        for lbl, dx, dy in (("N", 0, -1), ("S", 0, 1), ("E", 1, 0), ("W", -1, 0)):
            lw = font.getlength(lbl)
            lx = cx + dx * (radius + int(6 * sx)) - lw / 2.0
            ly = cy + dy * (radius + int(6 * sy)) - int(5 * sy)
            draw.text((lx, ly), lbl, font=font, fill=0)

        sats = self._wd_sky_data()
        if not sats:
            gps = (wd.get('gps') or {})
            msg = "Searching..." if gps.get('connected') else "No GPS"
            draw.text(((w - font.getlength(msg)) / 2, cy - int(4 * sy)),
                      msg, font=font, fill=0)
            return

        plotted = 0
        for s in sats:
            az, elev = s.get('az'), s.get('elev')
            if not isinstance(az, (int, float)) or not isinstance(elev, (int, float)):
                continue
            elev = max(0.0, min(90.0, float(elev)))
            r = radius * (90.0 - elev) / 90.0
            a = math.radians(float(az))
            x = cx + r * math.sin(a)
            y = cy - r * math.cos(a)
            snr = s.get('snr')
            strong = isinstance(snr, (int, float)) and snr >= 25
            dot = int(2 * sx)
            if strong:
                draw.ellipse((x - dot, y - dot, x + dot, y + dot), fill=0)
            else:
                draw.ellipse((x - dot, y - dot, x + dot, y + dot), outline=0)
            plotted += 1

        cnt = f"{plotted} sat"
        draw.text((int(3 * sx), top), cnt, font=font, fill=0)

    def _render_wd_compact_session(self, image, draw, wd):
        """Compact session totals — the running tally the stats page's band
        columns don't show: duration, security mix, Bluetooth, cells, track."""
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        footer_y = self._draw_wd_compact_chrome(draw, title="SESSION")
        if self._wd_compact_not_running(draw, wd):
            return

        st = (wd.get('stats') or {})

        dur = st.get('duration_seconds')
        if isinstance(dur, (int, float)) and dur >= 0:
            total = int(dur)
            h, rem = divmod(total, 3600)
            m, s = divmod(rem, 60)
            dur_str = f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"
        else:
            dur_str = "-"

        rows = [
            ("Time", dur_str),
            ("Nets", st.get('total_networks', 0)),
            ("Open", st.get('open_networks', 0)),
            ("WEP", st.get('wep_networks', 0)),
            ("BT", st.get('bluetooth_devices', 0)),
            ("Cell", st.get('cell_towers', 0)),
            ("Zig", st.get('zigbee_devices', 0)),
            ("Track", st.get('gps_trackpoints', 0)),
        ]
        self._wd_compact_rows(draw, rows, int(15 * sy), footer_y)

    def _render_wd_compact_map(self, image, draw, wd):
        """Compact live map — GPS breadcrumb + located networks, auto-scaled to
        the 128x128 panel. Same data as the e-paper map page, drawn without the
        big title frame so the plot gets nearly the whole screen."""
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        font = self.shared_data.font_arial9
        footer_y = self._draw_wd_compact_chrome(draw, title="MAP")
        if self._wd_compact_not_running(draw, wd):
            return

        track, nets, here = self._wardrive_map_points(wd)
        top = int(14 * sy)
        bottom = footer_y - int(2 * sy)
        left = int(3 * sx)
        right = w - int(3 * sx)

        pts = list(track) + nets + ([here] if here else [])
        if not pts:
            msg = "Waiting for GPS..."
            draw.text(((w - font.getlength(msg)) / 2, (top + bottom) / 2),
                      msg, font=font, fill=0)
            return

        lats = [p[0] for p in pts]
        lons = [p[1] for p in pts]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        lon_scale = math.cos(math.radians((min_lat + max_lat) / 2.0)) or 1.0
        d_lat = max(max_lat - min_lat, 1e-5)
        d_lon = max((max_lon - min_lon) * lon_scale, 1e-5)
        scale = min((right - left) / d_lon, (bottom - top) / d_lat)
        off_x = left + ((right - left) - d_lon * scale) / 2.0
        off_y = top + ((bottom - top) - d_lat * scale) / 2.0

        def X(lon):
            return off_x + (lon - min_lon) * lon_scale * scale

        def Y(lat):
            return off_y + (max_lat - lat) * scale

        # Networks first so the track draws over them.
        for lat, lon in nets:
            x, y = X(lon), Y(lat)
            draw.point((x, y), fill=0)
        if len(track) > 1:
            draw.line([(X(p[1]), Y(p[0])) for p in track], fill=0, width=1)
        if here:
            x, y = X(here[1]), Y(here[0])
            r = int(3 * sx)
            draw.ellipse((x - r, y - r, x + r, y + r), outline=0)
            draw.ellipse((x - 1, y - 1, x + 1, y + 1), fill=0)

    def _render_wd_compact_viking(self, image, draw, wd):
        """Full-screen Ragnar viking — the 'am I still alive?' glance screen.

        Uses the live animated character sprite when one is loaded so the panel
        moves, falling back to the static ragnar1 mascot. Scaled up to fill the
        content band above the footer, preserving aspect ratio.
        """
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        w = getattr(self, 'render_w', self.shared_data.width)
        font = self.shared_data.font_arial9
        footer_y = self._draw_wd_compact_chrome(draw)

        sd = self.shared_data
        vk = getattr(sd, 'imagegen', None) or getattr(sd, 'ragnar1', None)
        top = int(2 * sy)
        band_h = footer_y - top - int(2 * sy)
        if vk is None or band_h <= 0:
            msg = "RAGNAR"
            draw.text(((w - font.getlength(msg)) / 2, footer_y / 2), msg, font=font, fill=0)
            return
        try:
            # Fill the band on the tighter axis so the whole viking stays visible.
            ratio = min((w - 4) / vk.width, band_h / vk.height)
            if ratio > 0:
                vk = vk.resize((max(1, int(vk.width * ratio)),
                                max(1, int(vk.height * ratio))), Image.NEAREST)
            image.paste(vk, ((w - vk.width) // 2, top + (band_h - vk.height) // 2))
        except Exception as e:
            logger.debug(f"viking page render failed: {e}")

    def _wardrive_map_points(self, wd=None):
        """Pull the live session's GPS track, located networks and current fix.

        Shared by the e-paper map page and the compact LCD map so both plot
        exactly the same data. Returns (track, nets, here) with here=None when
        there is no fix; every point is a (lat, lon) pair.
        """
        track, nets, here = [], [], None
        try:
            from webapp_modern import _get_wardriving_engine
            engine = _get_wardriving_engine()
            session = getattr(engine, 'session', None)
            wd = wd if wd is not None else (self._get_wardriving_data() or {})
            gps = (wd or {}).get('gps') or {}
            if gps.get('has_fix'):
                lat, lon = gps.get('latitude'), gps.get('longitude')
                if lat is not None and lon is not None:
                    here = (lat, lon)
            if session is not None:
                track = [p for p in (session.get_gps_track() or [])
                         if isinstance(p, (list, tuple)) and p[0] is not None and p[1] is not None]
                for n in session.get_networks(limit=2000):
                    lat = n.get('best_lat') if n.get('best_lat') else n.get('latitude')
                    lon = n.get('best_lon') if n.get('best_lon') else n.get('longitude')
                    if lat and lon and not (lat == 0 and lon == 0):
                        nets.append((lat, lon))
        except Exception:
            pass
        return track, nets, here

    def _render_wardriving_page(self, image, draw):
        """Render a wardriving status page for EPD e-paper displays."""
        # Tiny 1.44" ST7735S LCD HAT (128x128): the full stat page won't fit,
        # so render a header-less essentials-only layout instead.
        _w = getattr(self, 'render_w', self.shared_data.width)
        _h = getattr(self, 'render_h', self.shared_data.height)
        if _w < 150 and _h < 150:
            self._render_wardriving_page_compact(image, draw, self._get_wardriving_data())
            return
        ap_on = getattr(self.shared_data, 'wardrive_ap_active', False)
        hint = "K1:AP-off K2:Flip K3:Map K4:WiFi" if ap_on else "K1:AP K2:Flip K3:Map K4:WiFi"
        self._draw_page_frame(draw, "WARDRIVING", hint=hint)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        y = int(26 * sy)

        wd = self._get_wardriving_data()
        if not wd or not wd.get('running'):
            # If wardriving-on-boot is enabled and the engine has never started
            # a session yet, show "Starting..." — the engine is racing WiFi
            # startup. Once a session has existed, fall back to "Stopped" so
            # a user who manually stopped doesn't see a misleading message.
            never_started = not (wd and wd.get('session_id'))
            if self.shared_data.config.get('wardriving_on_boot', False) and never_started:
                stats = [
                    ("Status", "Starting..."),
                    ("Tip", "Waiting for engine"),
                ]
            else:
                stats = [
                    ("Status", "Stopped"),
                    ("Tip", "Enable in WebUI"),
                ]
            self._draw_stat_rows(draw, y, stats)
            return

        st = wd.get('stats', {})
        gps = wd.get('gps', {})

        # WiFi connection status line (same as regular Ragnar EPD).
        # Only shown when actually connected — "Connected WiFi" is the renamed
        # row and is treated as a non-static field per the e-paper spec.
        wifi_connected = self.is_wifi_connected()
        wifi_str = None
        if wifi_connected:
            ip_octet = self.get_wifi_ip_last_octet() or ""
            wifi_str = f"* {ip_octet}" if ip_octet else "*"

        # GPS status line — GPS row is static, always rendered.
        if gps.get('has_fix'):
            gps_str = f"{gps.get('latitude', 0):.4f},{gps.get('longitude', 0):.4f}"
        elif gps.get('connected'):
            # Mirror the web UI, which shows how many satellites are visible
            # before a fix is acquired. Peak SNR is added so antenna placement
            # can be judged live (kept compact to fit the 22-char value width).
            in_view = gps.get('satellites_in_view')
            snr = gps.get('snr_max')
            if isinstance(in_view, (int, float)) and in_view > 0:
                if isinstance(snr, (int, float)) and snr > 0:
                    gps_str = f"Searching {int(in_view)}v/{int(snr)}dB"
                else:
                    gps_str = f"Searching ({int(in_view)} vis)"
            else:
                gps_str = "Searching..."
        else:
            gps_str = "No GPS"

        # Static rows are always rendered: Networks, Open/WEP, 2.4 GHz, 5 GHz.
        # "Connected WiFi" and 6 GHz are only added when they have a value.
        stats_top = []
        # Phone-access AP (KEY1) — show its URL so the user knows where to browse.
        if ap_on:
            ap_url = getattr(self.shared_data, 'wardrive_ap_url', '') or ''
            stats_top.append(("AP Web", ap_url or "on"))
        if wifi_str is not None:
            stats_top.append(("Connected WiFi", wifi_str))
        stats_top.extend([
            ("Networks", str(st.get('total_networks', 0))),
            ("Open/WEP", f"{st.get('open_networks', 0)}/{st.get('wep_networks', 0)}"),
            ("2.4 GHz", str(st.get('band_2_4ghz', 0))),
            ("5 GHz", str(st.get('band_5ghz', 0))),
        ])
        if st.get('band_6ghz', 0) > 0:
            stats_top.append(("6 GHz", str(st.get('band_6ghz', 0))))

        # Per-adapter rows. Format requested:
        #   wlan0    19 Networks, M RSSI: -63 dBm [2.4]
        #   wlan1    12 Networks, M RSSI: -65 dBm [5]
        #   wlan2    0 ERR busy -16
        # Rendered left-aligned (not the right-aligned key/value style) so the
        # verbose value isn't truncated at 22 chars.
        details = wd.get('interface_details') or []
        coverage = (wd.get('coverage') or {}).get('per_interface', {})
        band_mode = wd.get('band_mode', 'redundant')
        adapter_rows = []
        for d in details:
            name = d.get('name', '?')
            nets = d.get('networks', 0)
            err = d.get('scan_error')
            sweep = d.get('sweep_bands') or []
            cov = coverage.get(name) or {}
            median = cov.get('best_rssi_median')

            if err:
                # Compact "command failed: Device or resource busy (-16)" → "busy -16"
                short = err.replace('command failed: ', '')
                short = re.sub(r'\s*\(-?(\d+)\)', r' -\1', short).strip()
                val = f"{nets} ERR {short}"
            else:
                val = f"{nets} Networks"
                if median:
                    val += f", M RSSI: {median} dBm"
                if band_mode == 'split' and sweep:
                    val += f" [{'/'.join(sweep)}]"
            adapter_rows.append((name, val))

        # Static rows: Bluetooth and GPS are always rendered.
        # Cell and Cameras are only shown when > 0.
        stats_bottom = [
            ("Bluetooth", str(st.get('bluetooth_devices', 0))),
        ]
        if st.get('cell_towers', 0) > 0:
            stats_bottom.append(("Cell", str(st.get('cell_towers', 0))))
        if st.get('zigbee_devices', 0) > 0:
            stats_bottom.append(("Zigbee", str(st.get('zigbee_devices', 0))))
        if st.get('cameras', 0) > 0:
            stats_bottom.append(("Cameras", str(st.get('cameras', 0))))
        stats_bottom.append(("GPS", gps_str))

        # Sats / Speed only shown when GPS has a fix.
        if gps.get('has_fix'):
            sats = gps.get('satellites')
            if isinstance(sats, (int, float)) and sats > 0:
                stats_bottom.append(("Sats", str(sats)))
            spd = gps.get('speed_kmh')
            if spd is not None and spd > 0:
                unit = self.config.get('wardriving_speed_unit', 'kmh')
                stats_bottom.append(("Speed", _fmt_wd_speed(spd, unit)))

        # Companions — show each connected device separately so the user can
        # see a Huginn + Piglet + Piglet Core at a glance.
        companions = wd.get('companions') or []
        active_companions = [c for c in companions if c.get('connected')]
        if active_companions:
            for c in active_companions:
                label = c.get('name') or 'Companion'
                stats_bottom.append(("Companion", label))
                nets = c.get('networks', 0)
                if nets > 0:
                    stats_bottom.append(("  Nets", str(nets)))
                nodes = c.get('mesh_node_count', 0)
                if nodes > 0:
                    stats_bottom.append(("  Nodes", str(nodes)))
                ble = c.get('esp_ble_count', 0)
                if ble > 0:
                    stats_bottom.append(("  BLE", str(ble)))
                zig = c.get('esp_zigbee_count', 0)
                if zig > 0:
                    stats_bottom.append(("  Zigbee", str(zig)))
        else:
            stats_bottom.append(("Companion", "None"))

        # Render: top rows (right-aligned key/value), then adapter rows
        # (left-aligned single line so the long value survives), then bottom rows.
        y = self._draw_stat_rows(draw, y, stats_top)
        y = self._draw_adapter_rows(draw, y, adapter_rows)
        if band_mode and len(details) >= 2:
            y = self._draw_adapter_rows(draw, y, [("Mode", band_mode)])
        self._draw_stat_rows(draw, y, stats_bottom)

    def _render_wardriving_map_page(self, image, draw):
        """Render a live wardriving map (GPS breadcrumb + network dots).

        Toggled by KEY3 while wardriving. Auto-scales the current session's
        GPS track and located networks to the screen; the current fix is
        marked with a ringed dot.
        """
        ap_on = getattr(self.shared_data, 'wardrive_ap_active', False)
        hint = "K1:AP-off K2:Flip K3:Stats K4:WiFi" if ap_on else "K1:AP K2:Flip K3:Stats K4:WiFi"
        self._draw_page_frame(draw, "WARDRIVE MAP", hint=hint)
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9

        # Plot rectangle between the title divider and the footer divider.
        top = int(24 * sy)
        bottom = h - int(20 * sy)
        left = int(3 * sx)
        right = w - int(3 * sx)

        # Pull track + located networks straight from the live session.
        track, nets, here = self._wardrive_map_points()

        pts = list(track) + nets + ([here] if here and here[0] is not None else [])
        if not pts:
            draw.text((left + int(4 * sx), top + int(20 * sy)),
                      "Waiting for GPS fix...", font=font, fill=0)
            return

        lats = [p[0] for p in pts]
        lons = [p[1] for p in pts]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        mid_lat = (min_lat + max_lat) / 2.0
        lon_scale = math.cos(math.radians(mid_lat)) or 1.0
        d_lat = max(max_lat - min_lat, 1e-5)
        d_lon = max((max_lon - min_lon) * lon_scale, 1e-5)
        scale = min((right - left) / d_lon, (bottom - top) / d_lat)
        off_x = left + ((right - left) - d_lon * scale) / 2.0
        off_y = top + ((bottom - top) - d_lat * scale) / 2.0

        def to_xy(lat, lon):
            x = off_x + (lon - min_lon) * lon_scale * scale
            # invert Y so north is up
            y = off_y + (max_lat - lat) * scale
            return int(x), int(y)

        # Network dots (background)
        for lat, lon in nets:
            x, y = to_xy(lat, lon)
            draw.point((x, y), fill=0)

        # Track polyline
        prev = None
        for p in track:
            xy = to_xy(p[0], p[1])
            if prev is not None:
                draw.line((prev[0], prev[1], xy[0], xy[1]), fill=0)
            prev = xy

        # Current position — ringed marker
        if here and here[0] is not None:
            x, y = to_xy(here[0], here[1])
            draw.ellipse((x - 3, y - 3, x + 3, y + 3), outline=0)
            draw.ellipse((x - 1, y - 1, x + 1, y + 1), fill=0)

        # Footer counts (just above the frame's key-hint line)
        info = f"{len(track)}pts {len(nets)}net"
        draw.text((right - int(font.getlength(info)) - int(2 * sx), top + int(2 * sy)),
                  info, font=font, fill=0)

    # ------------------------------------------------------------------
    # GC9A01 round-display renderer
    # ------------------------------------------------------------------

    def _run_gc9a01(self):
        """Dedicated render loop for the GC9A01 1.28″ round colour TFT.

        Animates the existing e-paper BMP frame sequences (resources/images/status/)
        in full colour on the round display, cycling at ~1 fps.  Each status has
        its own tint colour so the mascot visually reflects what Ragnar is doing.

        Layout (240×240 circle):
          ┌──────────────────────┐
          │     RAGNAR  (title)  │  y≈8  – white, Viking font
          │   ┌──────────────┐   │
          │   │  mascot anim │   │  y≈30–175 – tinted BMP frames, animated
          │   └──────────────┘   │
          │   ── STATUS TEXT ──  │  y≈182 – coloured by state
          │      wifi ssid       │  y≈207 – white/dim
          └──────────────────────┘
        Outer ring colour: green=connected, cyan=scanning, amber=AP, red=error/offline
        """
        from PIL import Image as _Image, ImageDraw as _ImageDraw, ImageFont as _ImageFont, ImageOps as _ImageOps

        SIZE       = 240
        MASCOT_SZ  = 140   # px — upscaled from 78×78 source
        ANIM_TICKS = 2     # loop ticks per frame advance (tick = 0.5 s → 1 s/frame)
        TICK_SLEEP = 0.5   # seconds per tick

        # ── colour palette ───────────────────────────────────────────────
        C_BG    = (0,   0,   0)
        C_WHITE = (255, 255, 255)
        C_GRAY  = (160, 160, 160)
        C_GREEN = (50,  200,  80)
        C_RED   = (220,  50,  50)
        C_CYAN  = (0,   200, 220)
        C_AMBER = (220, 160,   0)
        RING_W  = 6

        # Mascot tint colours keyed by partial status name
        TINT_MAP = {
            "IDLE":          (150, 200, 255),  # soft blue
            "NetworkScanner":(0,   220, 220),  # cyan
            "NmapVuln":      (0,   220, 220),  # cyan
            "SSHBrute":      (255,  80,  80),  # red
            "SMBBrute":      (255,  80,  80),
            "FTPBrute":      (255,  80,  80),
            "RDPBrute":      (255,  80,  80),
            "TelnetBrute":   (255,  80,  80),
            "SQLBrute":      (255, 120,  60),
            "StealFiles":    (255, 160,  40),  # amber
            "StealData":     (255, 160,  40),
            "LogStandalone": (180, 180, 180),  # gray
        }

        def _tint_for(status):
            s = status or "IDLE"
            for key, col in TINT_MAP.items():
                if key.lower() in s.lower():
                    return col
            return C_WHITE

        # ── fonts ────────────────────────────────────────────────────────
        fonts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "fonts")
        arial_path  = os.path.join(fonts_dir, "Arial.ttf")
        viking_path = os.path.join(fonts_dir, "Creamy.ttf")
        try:
            font_title  = _ImageFont.truetype(viking_path, 22)
            font_ssid   = _ImageFont.truetype(arial_path,  14)
            _font_status_cache = {}
            def _status_font(text, max_px=200):
                """Return the largest font that fits `text` within max_px."""
                # At y=182 the circle chord is narrower than the full 240px diameter.
                # Compute usable width: 2*sqrt(r^2 - (y - cx)^2) minus ring border.
                import math
                _r, _cx, _cy = 120, 120, 120
                _chord = 2 * math.sqrt(max(0, _r**2 - (182 - _cy)**2))
                max_px = min(max_px, int(_chord) - 2 * RING_W - 8)  # 8px safety margin
                for size in (18, 16, 14, 12, 11, 10, 9):
                    if size not in _font_status_cache:
                        try:
                            _font_status_cache[size] = _ImageFont.truetype(arial_path, size)
                        except Exception:
                            _font_status_cache[size] = _ImageFont.load_default()
                    f = _font_status_cache[size]
                    try:
                        w = f.getbbox(text)[2] - f.getbbox(text)[0]
                    except Exception:
                        w = len(text) * size
                    if w <= max_px:
                        return f
                return _font_status_cache.get(9, _ImageFont.load_default())
        except Exception:
            font_title = font_ssid = _ImageFont.load_default()
            def _status_font(text, max_px=200):
                return _ImageFont.load_default()

        # ── mascot tint colour (user-configurable via web UI) ────────────
        def _parse_hex(hex_str, fallback=(150, 200, 255)):
            try:
                h = hex_str.lstrip("#")
                return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
            except Exception:
                return fallback

        def _mascot_tint():
            """Return current tint RGB, re-read from config each call so live
            web-UI changes take effect without restarting the service."""
            return _parse_hex(self.config.get("gc9a01_mascot_color", "#96C8FF"))

        # ── frame cache: (status, frame_idx, tint) → RGBA sprite ─────────
        _frame_cache = {}

        def _get_colorized_frame(status, idx, tint):
            key = (status, idx, tint)
            if key in _frame_cache:
                return _frame_cache[key]
            series = getattr(self.shared_data, "image_series", {})
            frames = series.get(status) or series.get("IDLE") or []
            if not frames:
                _frame_cache[key] = None
                return None
            src = frames[idx % len(frames)]
            tint = _tint_for(status)
            try:
                gray  = src.convert("L").resize((MASCOT_SZ, MASCOT_SZ), _Image.LANCZOS)
                alpha = _ImageOps.invert(gray)   # dark pixels → opaque, white → transparent
                sprite = _Image.new("RGBA", (MASCOT_SZ, MASCOT_SZ), tint + (255,))
                sprite.putalpha(alpha)
                _frame_cache[key] = sprite
            except Exception as exc:
                logger.debug("GC9A01: colorize error: %s", exc)
                _frame_cache[key] = None
            return _frame_cache[key]

        def _frame_count(status):
            series = getattr(self.shared_data, "image_series", {})
            frames = series.get(status) or series.get("IDLE") or []
            return max(1, len(frames))

        # ── state helpers ─────────────────────────────────────────────────
        def _text_state():
            sd = self.shared_data
            net_text = getattr(sd, "ragnarstatustext2", "") or ""
            return (
                getattr(sd, "wifi_connected",   False),
                net_text,
                getattr(sd, "ap_mode_active",   False),
                getattr(sd, "ragnarstatustext", "IDLE"),
            )

        def _ring_col(wifi_on, ap_on, status):
            if ap_on:            return C_AMBER
            if not wifi_on:      return C_RED
            s = (status or "").upper()
            if any(k in s for k in ("SCAN", "BRUTE", "STEAL", "INJECT")): return C_CYAN
            if any(k in s for k in ("ERROR", "FAIL")):                     return C_RED
            return C_GREEN

        def _status_col(wifi_on, ap_on, status):
            if ap_on:            return C_AMBER
            if not wifi_on:      return C_RED
            s = (status or "").upper()
            if any(k in s for k in ("SCAN", "BRUTE", "STEAL", "INJECT")): return C_CYAN
            if any(k in s for k in ("ERROR", "FAIL")):                     return C_RED
            return C_GREEN

        def _render(wifi_on, ssid, ap_on, status_text, mascot_rgba, info_label, info_col):
            import math as _math
            img  = _Image.new("RGB", (SIZE, SIZE), C_BG)
            draw = _ImageDraw.Draw(img)

            # Circular clip mask
            mask = _Image.new("L", (SIZE, SIZE), 0)
            _ImageDraw.Draw(mask).ellipse((0, 0, SIZE - 1, SIZE - 1), fill=255)

            # Ring border
            draw.ellipse((0, 0, SIZE - 1, SIZE - 1),
                         outline=_ring_col(wifi_on, ap_on, status_text), width=RING_W)

            # Title
            title = "RAGNAR"
            try:
                tb = font_title.getbbox(title)
                tx = (SIZE - (tb[2] - tb[0])) // 2
            except Exception:
                tx = 80
            draw.text((tx, 8), title, font=font_title, fill=C_WHITE)

            # Mascot sprite
            if mascot_rgba is not None:
                mw, mh = mascot_rgba.size
                mx = (SIZE - mw) // 2
                my = 32 + (MASCOT_SZ - mh) // 2
                img.paste(mascot_rgba, (mx, my), mascot_rgba)

            # ── Left panel: WiFi signal ───────────────────────────────────
            sd = self.shared_data
            rssi  = getattr(sd, "wifi_signal_dbm",     None)
            qual  = getattr(sd, "wifi_signal_quality",  None)
            font_side = font_ssid  # 14px
            panel_y   = 100
            # Compute safe inward x so panels stay inside the circle at panel_y
            _chord = 2 * _math.sqrt(max(0, 120**2 - (panel_y - 120)**2))
            panel_x = int((SIZE - _chord) / 2) + RING_W + 6   # left panel x
            right_x_limit = SIZE - panel_x                     # right panel right edge

            if not wifi_on:
                draw.text((panel_x, panel_y),      "WiFi", font=font_side, fill=C_RED)
                draw.text((panel_x, panel_y + 16), " OFF", font=font_side, fill=C_RED)
            elif rssi is not None:
                # Signal bar indicator (4 bars)
                bars = 1 if rssi >= -90 else 0
                bars = 2 if rssi >= -75 else bars
                bars = 3 if rssi >= -65 else bars
                bars = 4 if rssi >= -55 else bars
                bar_col = C_RED if bars <= 1 else C_AMBER if bars == 2 else C_GREEN
                for b in range(4):
                    bh = 4 + b * 3   # bar heights: 4,7,10,13
                    bx = panel_x + b * 7
                    by = panel_y + 13 - bh
                    col = bar_col if b < bars else C_GRAY
                    draw.rectangle([bx, by, bx + 4, panel_y + 13], fill=col)
                dbm_str = f"{int(rssi)}d"
                draw.text((panel_x, panel_y + 17), dbm_str, font=font_side, fill=C_GRAY)
            else:
                draw.text((panel_x, panel_y), "N/A", font=font_side, fill=C_GRAY)

            # ── Right panel: Target count ─────────────────────────────────
            targets = getattr(sd, "total_targetnbr", 0) or 0
            # Right-align within the right sliver
            tgt_label1 = "TGTS"
            tgt_label2 = str(targets)
            try:
                w1 = font_side.getbbox(tgt_label1)[2] - font_side.getbbox(tgt_label1)[0]
                w2 = font_side.getbbox(tgt_label2)[2] - font_side.getbbox(tgt_label2)[0]
            except Exception:
                w1 = w2 = 28
            rx1 = right_x_limit - w1
            rx2 = right_x_limit - w2
            draw.text((rx1, panel_y),      tgt_label1, font=font_side, fill=C_GRAY)
            draw.text((rx2, panel_y + 16), tgt_label2, font=font_side, fill=C_GREEN)

            # Status text — same size as info line below (font_ssid / 14px)
            st = (status_text or "IDLE").upper()
            s_col = _status_col(wifi_on, ap_on, status_text)
            f_st  = font_ssid
            try:
                sb = f_st.getbbox(st)
                sx = (SIZE - (sb[2] - sb[0])) // 2
            except Exception:
                sx = 60
            draw.text((sx, 182), st, font=f_st, fill=s_col)

            # Rotating info line
            try:
                nb = font_ssid.getbbox(info_label)
                nx = (SIZE - (nb[2] - nb[0])) // 2
            except Exception:
                nx = 60
            draw.text((nx, 207), info_label, font=font_ssid, fill=info_col)

            # Apply circular mask (black corners)
            result = _Image.new("RGB", (SIZE, SIZE), C_BG)
            result.paste(img, mask=mask)
            return result

        # ── main animation loop ───────────────────────────────────────────
        self.epd_helper.init_partial_update()

        _anim_tick   = 0
        _frame_idx   = 0
        _last_status = None
        _last_text   = None
        _last_fidx   = -1
        _info_tick   = 0   # increments each TICK_SLEEP; drives rotating bottom line

        # Info slots cycle every 20 ticks (10 s each); 3 slots = 30 s period
        # Slot 0: scan target / current IP
        # Slot 1: targets found + creds
        # Slot 2: WiFi/network (the "every 30 s" network glimpse)
        INFO_SLOT_TICKS = 20   # 10 s per slot
        INFO_SLOTS      = 3

        def _info_line(slot, wifi_on, ssid, ap_on):
            sd = self.shared_data
            if slot == 2:
                # Network slot
                if ap_on:
                    return ssid if ssid.startswith("AP") else "AP MODE", C_AMBER
                if not wifi_on:
                    return "NOT CONNECTED", C_RED
                return (ssid.removeprefix("WiFi: ") if ssid else "Connected"), C_GRAY
            if slot == 0:
                # Current scan target — bjornstatustext2 holds network or IP being scanned
                target = getattr(sd, "bjornstatustext2", "") or ""
                if target:
                    label = target if len(target) <= 20 else target[-20:]
                    return label, C_CYAN
                # Fallback: gateway
                gw = (getattr(sd, "gateway_info", {}) or {}).get("gateway_ip", "")
                return (f"GW: {gw}" if gw else "Scanning..."), C_CYAN
            # slot == 1: targets + creds
            targets = getattr(sd, "total_targetnbr", 0) or 0
            creds   = getattr(sd, "crednbr",        0) or 0
            vulns   = getattr(sd, "vulnnbr",         0) or 0
            return f"T:{targets} C:{creds} V:{vulns}", C_GREEN

        def _render_wd_gc9a01():
            """Render wardriving dashboard on GC9A01 240×240 round TFT."""
            wd = self._get_wardriving_data()
            st = wd.get('stats', {}) if wd else {}
            gps = wd.get('gps', {}) if wd else {}

            img = _Image.new("RGB", (SIZE, SIZE), C_BG)
            draw = _ImageDraw.Draw(img)

            # Outer ring — green if GPS fix, amber if searching, red if no GPS
            if gps.get('has_fix'):
                ring_col = C_GREEN
            elif gps.get('connected'):
                ring_col = C_AMBER
            else:
                ring_col = C_RED
            draw.ellipse((0, 0, SIZE - 1, SIZE - 1), outline=ring_col, width=RING_W)

            # Title
            title = "WARDRIVING"
            try:
                tb = font_title.getbbox(title)
                tx = (SIZE - (tb[2] - tb[0])) // 2
            except Exception:
                tx = 50
            draw.text((tx, 8), title, font=font_title, fill=C_WHITE)

            # Network count — large, centered
            total = str(st.get('total_networks', 0))
            try:
                nb = font_title.getbbox(total)
                nx = (SIZE - (nb[2] - nb[0])) // 2
            except Exception:
                nx = 100
            draw.text((nx, 45), total, font=font_title, fill=C_GREEN)
            try:
                lb = font_ssid.getbbox("networks")
                lx = (SIZE - (lb[2] - lb[0])) // 2
            except Exception:
                lx = 80
            draw.text((lx, 72), "networks", font=font_ssid, fill=C_GRAY)

            # Stats rows
            y = 98
            line_h = 20
            open_n = st.get('open_networks', 0)
            wep_n = st.get('wep_networks', 0)
            wpa_n = st.get('wpa_networks', 0)
            draw.text((30, y), f"Open:{open_n}  WEP:{wep_n}  WPA:{wpa_n}", font=font_side, fill=C_WHITE)
            y += line_h
            b24 = st.get('band_2_4ghz', 0)
            b5 = st.get('band_5ghz', 0)
            b6 = st.get('band_6ghz', 0)
            draw.text((30, y), f"2.4G:{b24} 5G:{b5} 6G:{b6}", font=font_side, fill=C_CYAN)
            y += line_h
            bt_n = st.get('bluetooth_devices', 0)
            cell_n = st.get('cell_towers', 0)
            cam_n = st.get('cameras', 0)
            zig_n = st.get('zigbee_devices', 0)
            bt_line = f"BT:{bt_n} Cell:{cell_n} Cam:{cam_n}"
            if zig_n:
                bt_line += f" Zig:{zig_n}"
            draw.text((30, y), bt_line, font=font_side, fill=C_AMBER)
            y += line_h
            scans = wd.get('scans_completed', 0) if wd else 0
            draw.text((30, y), f"Scans: {scans}", font=font_side, fill=C_GRAY)

            # GPS status
            if gps.get('has_fix'):
                gps_str = f"{gps.get('latitude', 0):.4f},{gps.get('longitude', 0):.4f}"
                gps_col = C_GREEN
            elif gps.get('connected'):
                gps_str = "GPS searching..."
                gps_col = C_AMBER
            else:
                gps_str = "No GPS"
                gps_col = C_RED
            try:
                gb = font_ssid.getbbox(gps_str)
                gx = (SIZE - (gb[2] - gb[0])) // 2
            except Exception:
                gx = 40
            draw.text((gx, 182), gps_str, font=font_ssid, fill=gps_col)

            # Sats info — used/in-view (+ peak SNR), matching the web UI so the
            # number of visible satellites and signal strength are shown even
            # before a fix is acquired.
            in_view = gps.get('satellites_in_view')
            snr = gps.get('snr_max')
            if isinstance(in_view, (int, float)) and in_view > 0:
                sats_str = f"Sats: {gps.get('satellites', 0)}/{int(in_view)}"
            else:
                sats_str = f"Sats: {gps.get('satellites', '-')}"
            if isinstance(snr, (int, float)) and snr > 0:
                sats_str += f" SNR{int(snr)}"
            try:
                sb = font_ssid.getbbox(sats_str)
                sx = (SIZE - (sb[2] - sb[0])) // 2
            except Exception:
                sx = 80
            draw.text((sx, 207), sats_str, font=font_ssid, fill=C_GRAY)

            # Circular mask
            result = _Image.new("RGB", (SIZE, SIZE), C_BG)
            result.paste(img, mask=mask)
            return result

        while not self.shared_data.display_should_exit:
            try:
                wifi_on, ssid, ap_on, status_text = _text_state()
                orch_status = getattr(self.shared_data, "ragnarorch_status", "IDLE") or "IDLE"
                self.shared_data.update_ragnarstatus()

                # Wardriving display override for GC9A01
                wd_check = self._get_wardriving_data()
                if wd_check and wd_check.get('running'):
                    output = _render_wd_gc9a01()
                    output = output.transpose(_Image.Transpose.FLIP_LEFT_RIGHT)
                    self.epd_helper.display_partial(output)
                    try:
                        web_path = os.path.join(self.shared_data.webdir, "screen.png")
                        web_img = output.transpose(_Image.Transpose.FLIP_LEFT_RIGHT)
                        with open(web_path, "wb") as f:
                            web_img.save(f); f.flush(); os.fsync(f.fileno())
                    except Exception:
                        pass
                    time.sleep(TICK_SLEEP)
                    continue

                # Reset animation when status changes
                if orch_status != _last_status:
                    _frame_idx   = 0
                    _anim_tick   = 0
                    _last_status = orch_status
                    _frame_cache.clear()  # tint may change with new status

                # Advance animation frame
                _anim_tick += 1
                if _anim_tick >= ANIM_TICKS:
                    _anim_tick  = 0
                    _frame_idx  = (_frame_idx + 1) % _frame_count(orch_status)

                tint = _mascot_tint()
                info_slot = (_info_tick // INFO_SLOT_TICKS) % INFO_SLOTS
                info_label, info_col = _info_line(info_slot, wifi_on, ssid, ap_on)
                _info_tick += 1

                text_changed  = (wifi_on, ssid, ap_on, status_text, info_label) != _last_text
                frame_changed = _frame_idx != _last_fidx
                color_changed = tint != getattr(self, "_gc9a01_last_tint", None)

                if text_changed or frame_changed or color_changed:
                    sprite = _get_colorized_frame(orch_status, _frame_idx, tint)
                    self._gc9a01_last_tint = tint
                    output = _render(wifi_on, ssid, ap_on, status_text, sprite, info_label, info_col)
                    output = output.transpose(_Image.Transpose.FLIP_LEFT_RIGHT)
                    self.epd_helper.display_partial(output)
                    _last_text  = (wifi_on, ssid, ap_on, status_text, info_label)
                    _last_fidx  = _frame_idx

                    try:
                        web_path = os.path.join(self.shared_data.webdir, "screen.png")
                        web_img = output.transpose(_Image.Transpose.FLIP_LEFT_RIGHT)
                        with open(web_path, "wb") as f:
                            web_img.save(f); f.flush(); os.fsync(f.fileno())
                    except Exception:
                        pass

            except Exception as exc:
                logger.error("GC9A01 render error: %s", exc)

            time.sleep(TICK_SLEEP)

    # ------------------------------------------------------------------
    # LCD1602 16x2 character LCD display loop
    # ------------------------------------------------------------------

    def _run_lcd1602(self):
        """LCD1602 16×2 display loop with two independent rotation timers.

        Top row (15 s each):
          Slot 0 — WiFi SSID          e.g. "Tango Down 5G  "
          Slot 1 — IP address         e.g. "192.168.1.100  "
          Slot 2 — Ragnar status      e.g. "NetworkScanner "

        Bottom row (5 s each, 3 slots):
          Slot 0 — "Targets: 42     "
          Slot 1 — "Vuln: 4         "
          Slot 2 — "Credentials: 0  "

        Handles I2C errors gracefully — forces full re-init on next tick.
        """
        import subprocess
        from resources.waveshare_epd import lcd1602 as _lcd1602_mod

        TOP_INTERVAL    = 15.0  # seconds per top-row slot
        TOP_SLOTS       = 3
        BOTTOM_INTERVAL = 5.0   # seconds per bottom-row slot
        BOTTOM_SLOTS    = 3
        TICK_SLEEP      = 0.5   # polling interval (seconds)

        def _get_ssid():
            try:
                res = subprocess.run(
                    ["iwgetid", "-r"], capture_output=True, text=True, timeout=2
                )
                ssid = res.stdout.strip()
                if ssid:
                    return ssid
            except Exception:
                pass
            if getattr(self.shared_data, "ap_enabled", False):
                return "AP MODE"
            return "No Network"

        def _get_ip():
            try:
                res = subprocess.run(
                    ["hostname", "-I"], capture_output=True, text=True, timeout=2
                )
                ip = res.stdout.strip().split()[0]
                if ip:
                    return ip
            except Exception:
                pass
            return "No IP"

        def _get_status():
            status = getattr(self.shared_data, "ragnarstatustext", None) or "IDLE"
            return str(status)

        def _render_lcd_preview(row0: str, row1: str):
            """Write a simulated LCD1602 image to screen.png for the web preview tab."""
            try:
                # Colours — classic green-on-dark LCD backlit look
                BEZEL_COLOR  = (20, 28, 20)
                BG_COLOR     = (10, 22, 10)
                CHAR_COLOR   = (80, 255, 100)
                CURSOR_COLOR = (40, 120, 50)   # darker fill for empty char cells

                BEZEL       = 14   # px border around the LCD panel
                PAD_X       = 18   # horizontal padding inside the panel
                PAD_Y       = 12   # vertical padding inside the panel
                ROW_GAP     = 10   # gap between the two character rows
                FONT_SIZE   = 28

                # Try common monospace fonts available on the Pi and Windows
                font = None
                for fp in (
                    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
                    "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
                    "C:/Windows/Fonts/cour.ttf",
                ):
                    try:
                        font = ImageFont.truetype(fp, size=FONT_SIZE)
                        break
                    except Exception:
                        pass
                if font is None:
                    font = ImageFont.load_default()

                # Measure a single character to size the canvas
                probe = Image.new("RGB", (1, 1))
                bb = ImageDraw.Draw(probe).textbbox((0, 0), "W", font=font)
                char_w = bb[2] - bb[0]
                char_h = bb[3] - bb[1]

                panel_w = PAD_X * 2 + char_w * 16
                panel_h = PAD_Y * 2 + char_h * 2 + ROW_GAP
                img_w   = panel_w + BEZEL * 2
                img_h   = panel_h + BEZEL * 2

                img  = Image.new("RGB", (img_w, img_h), BEZEL_COLOR)
                draw = ImageDraw.Draw(img)

                # LCD panel background
                draw.rectangle(
                    [BEZEL, BEZEL, BEZEL + panel_w - 1, BEZEL + panel_h - 1],
                    fill=BG_COLOR,
                )

                # Draw each row of 16 characters
                for row_idx, text in enumerate((row0, row1)):
                    text = (text or "").ljust(16)[:16]
                    x = BEZEL + PAD_X
                    y = BEZEL + PAD_Y + row_idx * (char_h + ROW_GAP)
                    draw.text((x, y), text, font=font, fill=CHAR_COLOR)

                webdir = getattr(self.shared_data, "webdir", None)
                if webdir:
                    img.save(os.path.join(webdir, "screen.png"))
            except Exception as exc:
                logger.error(f"LCD1602 preview render error: {exc}")

        # ── Initialise display ──────────────────────────────────────────
        _i2c_raw = self.config.get("lcd1602_i2c_address", "0x27")
        i2c_addr = int(_i2c_raw, 16) if isinstance(_i2c_raw, str) else int(_i2c_raw)
        i2c_bus  = int(self.config.get("lcd1602_i2c_bus", 1))

        epd = _lcd1602_mod.EPD(i2c_address=i2c_addr, i2c_bus=i2c_bus)
        try:
            epd.init()
        except Exception as exc:
            logger.error(f"LCD1602 init failed: {exc}")

        _last_line0    = None
        _last_line1    = None
        _top_slot      = 0
        _bottom_slot   = 0
        _top_start     = time.monotonic() - TOP_INTERVAL     # trigger write on first tick
        _bottom_start  = time.monotonic() - BOTTOM_INTERVAL  # trigger write on first tick

        # ── Main loop ───────────────────────────────────────────────────
        _hw_line0 = None   # tracks what is currently written to hardware
        _hw_line1 = None
        while not self.shared_data.display_should_exit:
            # — compute current content (slot timers + data) —
            try:
                sd  = self.shared_data
                now = time.monotonic()

                # — advance top slot —
                if now - _top_start >= TOP_INTERVAL:
                    _top_slot  = (_top_slot + 1) % TOP_SLOTS
                    _top_start = now

                # — advance bottom slot —
                if now - _bottom_start >= BOTTOM_INTERVAL:
                    _bottom_slot  = (_bottom_slot + 1) % BOTTOM_SLOTS
                    _bottom_start = now

                # — gather data —
                targets = getattr(sd, "total_targetnbr", 0) or 0
                vulns   = getattr(sd, "vulnnbr",          0) or 0
                creds   = getattr(sd, "crednbr",          0) or 0

                # — build top line —
                if _top_slot == 0:
                    line0 = _get_ssid()
                elif _top_slot == 1:
                    line0 = _get_ip()
                else:
                    line0 = _get_status()
                line0 = line0.ljust(16)[:16]

                # — build bottom line —
                if _bottom_slot == 0:
                    line1 = f"Targets: {targets}"
                elif _bottom_slot == 1:
                    line1 = f"Vuln: {vulns}"
                else:
                    line1 = f"Credentials: {creds}"
                line1 = line1.ljust(16)[:16]

                # — Wardriving display override for LCD1602 —
                wd_lcd = self._get_wardriving_data()
                if wd_lcd and wd_lcd.get('running'):
                    st_lcd = wd_lcd.get('stats', {})
                    gps_lcd = wd_lcd.get('gps', {})
                    total_n = st_lcd.get('total_networks', 0)
                    if gps_lcd.get('has_fix'):
                        line0 = f"WD:{total_n} GPS:OK"
                    elif gps_lcd.get('connected'):
                        line0 = f"WD:{total_n} GPS:..."
                    else:
                        line0 = f"WD:{total_n} NoGPS"
                    line0 = line0.ljust(16)[:16]
                    open_n = st_lcd.get('open_networks', 0)
                    wpa_n = st_lcd.get('wpa_networks', 0)
                    scans = wd_lcd.get('scans_completed', 0)
                    line1 = f"O:{open_n} W:{wpa_n} S:{scans}"
                    line1 = line1.ljust(16)[:16]

                # — update web preview whenever content changes —
                if line0 != _last_line0 or line1 != _last_line1:
                    _render_lcd_preview(line0, line1)
                    _last_line0 = line0
                    _last_line1 = line1

            except Exception as exc:
                logger.error(f"LCD1602 data error: {exc}")

            # — write to hardware (isolated so I2C errors don't block preview) —
            try:
                if not epd._initialized:
                    epd.init()
                    _hw_line0 = None   # force full rewrite after reinit
                    _hw_line1 = None
                if _last_line0 is not None and _last_line0 != _hw_line0:
                    epd.write_line(0, _last_line0)
                    _hw_line0 = _last_line0
                if _last_line1 is not None and _last_line1 != _hw_line1:
                    epd.write_line(1, _last_line1)
                    _hw_line1 = _last_line1
            except Exception as exc:
                logger.error(f"LCD1602 hardware write error: {exc}")
                epd._initialized = False
                _hw_line0 = None
                _hw_line1 = None

            time.sleep(TICK_SLEEP)

        # ── Cleanup on exit ─────────────────────────────────────────────
        try:
            epd.Clear()
            epd.sleep()
        except Exception as exc:
            logger.error(f"LCD1602 shutdown error: {exc}")

    # ------------------------------------------------------------------
    # SSD1306 0.96" 128x64 monochrome OLED display loop
    # ------------------------------------------------------------------

    def _run_ssd1306(self):
        """Main display loop for SSD1306 0.96\" 128x64 monochrome OLED.

        Renders a compact status dashboard with header bar, WiFi info,
        target/credential counters, and a cycling info ticker at the bottom.
        """
        from PIL import Image as _Image, ImageDraw as _ImageDraw, ImageFont as _ImageFont
        import os

        W          = 128
        H          = 64
        TICK_SLEEP = 0.5    # seconds between ticks
        PNG_EVERY  = 10     # save screen.png every N ticks

        # ── Initialise display ──────────────────────────────────────────
        from resources.waveshare_epd import ssd1306 as _ssd1306_mod
        _i2c_raw = self.config.get("ssd1306_i2c_address", "0x3C")
        i2c_addr = int(_i2c_raw, 16) if isinstance(_i2c_raw, str) else int(_i2c_raw)
        epd = _ssd1306_mod.EPD(i2c_address=i2c_addr)
        epd.init()
        brightness = int(self.config.get("display_brightness", 8))
        epd.contrast(min(255, brightness * 17))  # map 0-15 → 0-255

        # ── Load fonts once ─────────────────────────────────────────────
        _font_path = os.path.join(
            os.path.dirname(__file__), "resources", "fonts", "Arial.ttf"
        )

        def _load_font(size):
            try:
                return _ImageFont.truetype(_font_path, size)
            except Exception:
                return _ImageFont.load_default()

        font_hdr  = _load_font(10)   # header bar text
        font_body = _load_font(9)    # all other lines

        _png_counter  = 0
        _scroll_pos   = 0   # pixel offset for header scroll

        # Width (px) available in the header beside "RAGNAR " prefix
        _RAGNAR_LABEL = "RAGNAR "
        try:
            _ragnar_w = font_hdr.getbbox(_RAGNAR_LABEL)[2]
        except Exception:
            _ragnar_w = len(_RAGNAR_LABEL) * 6
        _HDR_STATUS_W = W - _ragnar_w - 2   # pixels available for scrolling status

        # ── WiFi helper (same method used by gc9a01) ─────────────────────
        def _get_wifi():
            """Return (connected: bool, ssid: str, ip: str)."""
            import subprocess
            try:
                result = subprocess.run(
                    ["iwgetid", "-r"], capture_output=True, text=True, timeout=2
                )
                ssid = result.stdout.strip()
                if ssid:
                    # Get IP from shared_data
                    ip = getattr(self.shared_data, "ipaddress", "") or ""
                    return True, ssid, ip
            except Exception:
                pass
            if getattr(self.shared_data, "ap_enabled", False):
                return True, "AP MODE", getattr(self.shared_data, "ipaddress", "") or ""
            return False, "", getattr(self.shared_data, "ipaddress", "") or ""

        # ── Render helper ───────────────────────────────────────────────
        def _render(scroll_px):
            sd = self.shared_data

            # --- collect data --------------------------------------------------
            orch_status = (getattr(sd, "ragnarorch_status", "IDLE") or "IDLE").upper()
            wifi_on, ssid, ip = _get_wifi()

            targets = getattr(sd, "total_targetnbr", 0) or 0
            creds   = getattr(sd, "crednbr",        0) or 0
            vulns   = getattr(sd, "vulnnbr",         0) or 0

            status2 = (getattr(sd, "bjornstatustext2", "") or "").strip()

            # --- layout strings ------------------------------------------------
            wifi_line    = ("WiFi: " + ssid[:18]) if wifi_on else "NOT CONNECTED"
            target_line  = (">" + status2[:20]) if status2 else ("IP: " + ip if ip else "Scanning...")
            tc_line      = "TARGETS: {}   CREDS: {}".format(targets, creds)
            vuln_line    = "VULNERABILITIES: {}".format(vulns)

            # --- draw ----------------------------------------------------------
            img  = _Image.new("1", (W, H), 0)
            draw = _ImageDraw.Draw(img)

            # Header bar: white filled rectangle
            draw.rectangle((0, 0, W - 1, 12), fill=255)
            draw.text((2, 1), _RAGNAR_LABEL, font=font_hdr, fill=0)

            # Scrolling status text clipped to right portion of header
            # Build scroll string with padding so it wraps smoothly
            scroll_str = orch_status + "   "
            try:
                full_w = font_hdr.getbbox(scroll_str)[2]
            except Exception:
                full_w = len(scroll_str) * 6
            # Render into a temp image and paste a window of it
            tmp = _Image.new("1", (max(full_w * 2, _HDR_STATUS_W + 4), 12), 255)
            tdraw = _ImageDraw.Draw(tmp)
            tdraw.text((0, 1),        scroll_str, font=font_hdr, fill=0)
            tdraw.text((full_w, 1),   scroll_str, font=font_hdr, fill=0)
            offset = scroll_px % full_w
            crop   = tmp.crop((offset, 0, offset + _HDR_STATUS_W, 12))
            img.paste(crop, (_ragnar_w, 0))

            # Thin divider line at y=13
            draw.line((0, 13, W - 1, 13), fill=255)

            # Body lines
            draw.text((0, 15), wifi_line,   font=font_body, fill=255)
            draw.text((0, 26), target_line, font=font_body, fill=255)
            draw.text((0, 37), tc_line,     font=font_body, fill=255)
            draw.text((0, 48), vuln_line,   font=font_body, fill=255)

            return img

        def _render_wd():
            """Render wardriving dashboard on SSD1306 128x64."""
            wd = self._get_wardriving_data()
            st = wd.get('stats', {}) if wd else {}
            gps = wd.get('gps', {}) if wd else {}

            total = st.get('total_networks', 0)
            open_n = st.get('open_networks', 0)
            wpa_n = st.get('wpa_networks', 0)
            bt_n = st.get('bluetooth_devices', 0)
            cell_n = st.get('cell_towers', 0)
            zig_n = st.get('zigbee_devices', 0)
            scans = wd.get('scans_completed', 0) if wd else 0

            if gps.get('has_fix'):
                spd = gps.get('speed_kmh')
                gps_str = f"{gps.get('latitude', 0):.4f},{gps.get('longitude', 0):.4f}"
                if spd is not None:
                    unit = self.config.get('wardriving_speed_unit', 'kmh')
                    gps_str += f" {_fmt_wd_speed(spd, unit, decimals=0)}"
            elif gps.get('connected'):
                in_view = gps.get('satellites_in_view')
                snr = gps.get('snr_max')
                if isinstance(in_view, (int, float)) and in_view > 0:
                    if isinstance(snr, (int, float)) and snr > 0:
                        gps_str = f"GPS srch {int(in_view)}v/{int(snr)}dB"
                    else:
                        gps_str = f"GPS searching {int(in_view)} vis"
                else:
                    gps_str = "GPS searching..."
            else:
                gps_str = "No GPS"

            img = _Image.new("1", (W, H), 0)
            draw = _ImageDraw.Draw(img)

            # Header bar
            draw.rectangle((0, 0, W - 1, 12), fill=255)
            draw.text((2, 1), "WARDRIVING", font=font_hdr, fill=0)

            # Body
            draw.text((0, 15), f"Net:{total} Open:{open_n} WPA:{wpa_n}", font=font_body, fill=255)
            _zig = f" Zig:{zig_n}" if zig_n else ""
            draw.text((0, 26), f"BT:{bt_n} Cell:{cell_n}{_zig} Scans:{scans}", font=font_body, fill=255)
            draw.text((0, 37), gps_str[:22], font=font_body, fill=255)

            return img

        # ── Main loop ───────────────────────────────────────────────────
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.update_ragnarstatus()

                # Wardriving display override
                wd_data = self._get_wardriving_data()
                if wd_data and wd_data.get('running'):
                    img = _render_wd()
                else:
                    img = _render(_scroll_pos)
                epd.init()
                buf = epd.getbuffer(img)
                epd.displayPartial(buf)
                _scroll_pos += 2   # advance scroll 2px per tick (0.5s → ~4px/s)
                # Save screen.png for web preview every PNG_EVERY ticks
                _png_counter += 1
                if _png_counter >= PNG_EVERY:
                    _png_counter = 0
                    try:
                        web_path = os.path.join(self.shared_data.webdir, "screen.png")
                        with open(web_path, "wb") as f:
                            img.save(f)
                            f.flush()
                            os.fsync(f.fileno())
                    except Exception:
                        pass

            except Exception as exc:
                logger.error("SSD1306 render error: %s", exc)

            time.sleep(TICK_SLEEP)

        # ── Cleanup on exit ─────────────────────────────────────────────
        try:
            epd.Clear()
            epd.sleep()
        except Exception as exc:
            logger.error("SSD1306 shutdown error: %s", exc)

    def _run_max7219(self):
        """Scrolling status display for MAX7219 cascaded LED matrix panels."""
        from PIL import Image as _Image, ImageDraw as _ImageDraw, ImageFont as _ImageFont
        from resources.waveshare_epd import max7219 as _max7219_mod
        import os

        epd_type        = self.config.get("epd_type", "max7219_8panel")
        cascaded        = 4 if epd_type == "max7219_4panel" else 8
        brightness      = int(self.config.get("display_brightness", 8))
        spi_port        = int(self.config.get("max7219_spi_port", 0))
        spi_device      = int(self.config.get("max7219_spi_device", 0))
        block_orient    = int(self.config.get("max7219_block_orientation", -90))

        W = cascaded * 8  # 32 or 64
        H = 8
        TICK_SLEEP = 0.1   # seconds per scroll tick
        PNG_EVERY  = 50    # save screen.png every N ticks (~5s)

        epd = _max7219_mod.EPD(
            cascaded=cascaded,
            spi_port=spi_port,
            spi_device=spi_device,
            brightness=brightness,
            block_orientation=block_orient,
        )
        epd.init()

        # ── Font ──────────────────────────────────────────────────────────
        _font_path = os.path.join(os.path.dirname(__file__), "resources", "fonts", "DejaVuSansMono.ttf")

        def _load_font(size):
            try:
                return _ImageFont.truetype(_font_path, size)
            except Exception:
                return _ImageFont.load_default()

        font  = _load_font(9)
        _y_off = -font.getbbox("A")[1]  # shift glyphs up so row 0 is used

        # ── Helpers ───────────────────────────────────────────────────────
        def _text_width(text):
            try:
                return font.getbbox(text)[2]
            except Exception:
                return len(text) * 6

        def _get_wifi():
            try:
                import subprocess
                ssid = subprocess.check_output(
                    ["iwgetid", "-r"], stderr=subprocess.DEVNULL
                ).decode().strip()
                return ("WIFI: " + ssid).upper() if ssid else "WIFI: NONE"
            except Exception:
                return "WIFI: NONE"

        def _get_ip():
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return f"IP: {ip}"
            except Exception:
                return "IP: NONE"

        def _get_db_stats():
            try:
                db = getattr(self.shared_data, 'db', None)
                if db and callable(getattr(db, 'get_stats', None)):
                    return db.get_stats()
            except Exception:
                pass
            return {}

        def _get_targets():
            try:
                stats = _get_db_stats()
                count = stats.get('total_hosts', 0)
                return f"TARGETS FOUND: {count}"
            except Exception:
                return "TARGETS FOUND: 0"

        def _get_credentials():
            try:
                db = getattr(self.shared_data, 'db', None)
                if db:
                    with db.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT COUNT(*) FROM hosts WHERE (
                                (steal_files_ssh    IS NOT NULL AND steal_files_ssh    != '' AND steal_files_ssh    != '[]') OR
                                (steal_files_rdp    IS NOT NULL AND steal_files_rdp    != '' AND steal_files_rdp    != '[]') OR
                                (steal_files_ftp    IS NOT NULL AND steal_files_ftp    != '' AND steal_files_ftp    != '[]') OR
                                (steal_files_smb    IS NOT NULL AND steal_files_smb    != '' AND steal_files_smb    != '[]') OR
                                (steal_files_telnet IS NOT NULL AND steal_files_telnet != '' AND steal_files_telnet != '[]') OR
                                (steal_data_sql     IS NOT NULL AND steal_data_sql     != '' AND steal_data_sql     != '[]')
                            )
                        """)
                        count = cursor.fetchone()[0]
                        return f"CREDENTIALS STOLEN: {count}"
            except Exception:
                pass
            return "CREDENTIALS STOLEN: 0"

        def _get_vulns():
            try:
                stats = _get_db_stats()
                count = stats.get('hosts_with_vulns', 0)
                return f"VULNERABILITIES: {count}"
            except Exception:
                return "VULNERABILITIES: 0"

        def _get_status():
            try:
                status = getattr(self.shared_data, 'ragnarstatustext', '') or \
                         getattr(self.shared_data, 'current_action', '') or ''
                return status.upper()[:30] if status else "STATUS: IDLE"
            except Exception:
                return "STATUS: IDLE"

        # ── Scroll loop ───────────────────────────────────────────────────
        _tick       = 0
        _scroll_x   = W          # start off-screen right
        _msg_idx    = 0
        _messages   = []
        _msg_refresh_every = 200  # refresh message list every 200 ticks (~20s)

        def _build_messages():
            # Wardriving display override for MAX7219
            wd_max = self._get_wardriving_data()
            if wd_max and wd_max.get('running'):
                st_max = wd_max.get('stats', {})
                gps_max = wd_max.get('gps', {})
                total_n = st_max.get('total_networks', 0)
                gps_str = "FIX" if gps_max.get('has_fix') else ("..." if gps_max.get('connected') else "NO")
                return [
                    "* WARDRIVING *",
                    f"NETWORKS: {total_n}",
                    f"GPS: {gps_str}",
                    f"SCANS: {wd_max.get('scans_completed', 0)}",
                ]
            return [
                "* RAGNAR *",
                _get_targets(),
                _get_credentials(),
                _get_vulns(),
                _get_wifi(),
                _get_ip(),
                _get_status(),
            ]

        _messages = _build_messages()
        _current_msg = _messages[0]
        _msg_w = _text_width(_current_msg)

        while not self.shared_data.display_should_exit:
            # Refresh messages periodically
            if _tick % _msg_refresh_every == 0:
                _messages = _build_messages()

            # Build frame
            img  = _Image.new("1", (W, H), 0)
            draw = _ImageDraw.Draw(img)
            draw.text((_scroll_x, _y_off), _current_msg, font=font, fill=1)

            epd.display(epd.getbuffer(img))

            # Save web thumbnail
            if _tick % PNG_EVERY == 0:
                try:
                    png_path = os.path.join(os.path.dirname(__file__), "web", "screen.png")
                    # Scale up 4× so it's visible in browser
                    img.resize((W * 4, H * 4), _Image.NEAREST).convert("RGB").save(png_path)
                except Exception:
                    pass

            # Advance scroll
            _scroll_x -= 1
            if _scroll_x < -_msg_w:
                # Message fully scrolled off — advance to next
                _msg_idx = (_msg_idx + 1) % len(_messages)
                _current_msg = _messages[_msg_idx]
                _msg_w = _text_width(_current_msg)
                _scroll_x = W  # reset to right edge

            _tick += 1
            import time as _time
            _time.sleep(TICK_SLEEP)

        epd.Clear()
        epd.sleep()

    def run(self):
        """Main loop for updating the EPD display with shared data."""
        if self.config.get("epd_type") == "gc9a01":
            self._run_gc9a01()
            return

        if self.config.get("epd_type") == "ssd1306":
            self._run_ssd1306()
            return

        if self.config.get("epd_type") == "lcd1602":
            self._run_lcd1602()
            return

        if self.config.get("epd_type") in ("max7219_4panel", "max7219_8panel"):
            self._run_max7219()
            return

        # Wait for deferred initialization (fonts, images) to finish
        # before attempting to render anything.
        if hasattr(self.shared_data, 'wait_for_deferred_init'):
            self.shared_data.wait_for_deferred_init(timeout=30)
        self.manual_mode_txt = ""
        while not self.shared_data.display_should_exit:
            try:
                self.epd_helper.init_partial_update()
                # Pull latest orientation settings so web toggles take effect without restarting the service.
                self.screen_reversed = self.shared_data.screen_reversed
                self.web_screen_reversed = self.shared_data.web_screen_reversed
                self.display_comment(self.shared_data.ragnarorch_status)

                # Compute render dimensions — portrait for 90°/270°
                render_w, render_h = _render_dimensions(
                    self.shared_data.width, self.shared_data.height, self.screen_reversed)
                # Store for sub-page renderers
                self.render_w = render_w
                self.render_h = render_h
                ref_w = self.shared_data.config.get('ref_width', 122)
                ref_h = self.shared_data.config.get('ref_height', 250)
                if self.screen_reversed in (90, 270):
                    self.render_sx = render_w / ref_w
                    self.render_sy = render_h / ref_h
                else:
                    self.render_sx = self.scale_factor_x
                    self.render_sy = self.scale_factor_y

                image = Image.new('1', (render_w, render_h))
                draw = ImageDraw.Draw(image)
                draw.rectangle((0, 0, render_w, render_h), fill=255)

                # Check if button listener wants a different page
                current_page = PAGE_MAIN
                if self.button_listener and self.button_listener.available:
                    current_page = self.button_listener.current_page

                # Network Diagnostic display mode: an Ethernet-focused,
                # internet-independent field screen (link / addressing / switch
                # port via LLDP). Web-toggled; it overrides every normal page
                # and auto-cycles its sub-pages every NETDIAG_CYCLE_SECONDS.
                # Rendered + committed here so the standard page pipeline is
                # bypassed entirely while active.
                if self.shared_data.config.get('network_diagnostic_mode', False):
                    # The 2.7" HAT keys drive this mode (see epd_button.py): the
                    # button listener owns the current page / freeze state and
                    # posts one-shot test results for us to render.
                    bl = (self.button_listener
                          if (self.button_listener and self.button_listener.available)
                          else None)
                    seq0 = getattr(bl, 'netdiag_seq', 0) if bl else 0
                    result = getattr(bl, 'netdiag_result', None) if bl else None
                    if result is not None:
                        try:
                            self._render_netdiag_result(image, draw, result)
                        except Exception as e:
                            logger.debug(f"netdiag result render error: {e}")
                        self._commit_netdiag_frame(image)
                        # Refresh ~1s while a test runs so completion shows fast;
                        # once done, hold the result until a key wakes us.
                        self._netdiag_sleep(1.0 if result.get('running') else NETDIAG_CYCLE_SECONDS, bl, seq0)
                        continue
                    frozen = bool(getattr(bl, 'netdiag_frozen', False)) if bl else False
                    view = getattr(bl, 'netdiag_view', 'card') if bl else 'card'
                    if bl is not None:
                        page = bl.netdiag_page % NETDIAG_PAGE_COUNT
                    else:
                        page = getattr(self, '_netdiag_page', 0) % NETDIAG_PAGE_COUNT
                    try:
                        if view == 'menu':
                            self._render_netdiag_menu(image, draw, page)
                        else:
                            func_idx = getattr(bl, 'netdiag_func_idx', -1) if bl else -1
                            self._render_netdiag_page(image, draw, page,
                                                      frozen=frozen, func_idx=func_idx)
                    except Exception as e:
                        logger.debug(f"netdiag render error: {e}")
                    # Auto-cycle the cards only while auto-switch is on (not
                    # frozen) and not in the selection menu.
                    if not frozen and view != 'menu':
                        nextp = (page + 1) % NETDIAG_PAGE_COUNT
                        if bl is not None:
                            bl.netdiag_page = nextp
                            if hasattr(bl, 'netdiag_func_idx'):
                                bl.netdiag_func_idx = 0
                        else:
                            self._netdiag_page = nextp
                    self._commit_netdiag_frame(image)
                    # WIFI/SIGNAL cards held in manual mode redraw every second
                    # so the RSSI readings and bars move live as you walk
                    # around; everything else keeps the normal cycle.
                    live = (frozen and view != 'menu'
                            and NETDIAG_CARD_NAMES[page % len(NETDIAG_CARD_NAMES)]
                            in ("WIFI", "SIGNAL"))
                    self._netdiag_sleep(1.0 if live else NETDIAG_CYCLE_SECONDS,
                                        bl, seq0)
                    continue
                # Not in net-diag mode: drop any stale one-shot result / freeze so
                # re-entering the mode later starts clean on the pages.
                if self.button_listener is not None and getattr(self.button_listener, 'netdiag_result', None) is not None:
                    self.button_listener.netdiag_result = None
                    self.button_listener.netdiag_frozen = False

                # Wardriving display override: render the wardriving page when
                # the engine is running, OR — if wardriving-on-boot is set and
                # the engine has never run yet (no session_id) — render the
                # "Starting..." placeholder instead of briefly flashing the
                # regular dashboard. Once a session has existed, we respect
                # the engine's actual state (running vs. user-stopped).
                _wd_override = False
                if current_page == PAGE_MAIN:
                    wd_data = self._get_wardriving_data()
                    wd_boot = self.shared_data.config.get('wardriving_on_boot', False)
                    is_running = bool(wd_data and wd_data.get('running'))
                    never_started = not (wd_data and wd_data.get('session_id'))
                    if is_running or (wd_boot and never_started):
                        # KEY3 toggles a live map while wardriving is running.
                        show_map = (is_running and self.button_listener
                                    and getattr(self.button_listener, 'wardrive_map', False))
                        if show_map:
                            self._render_wardriving_map_page(image, draw)
                        else:
                            self._render_wardriving_page(image, draw)
                        _wd_override = True

                if not _wd_override:
                    if current_page == PAGE_NETWORK:
                        self._render_network_page(image, draw)
                    elif current_page == PAGE_VULN:
                        self._render_vuln_page(image, draw)
                    elif current_page == PAGE_DISCOVERED:
                        self._render_discovered_page(image, draw)
                    elif current_page == PAGE_ADVANCED:
                        self._render_advanced_page(image, draw)
                    elif current_page == PAGE_TRAFFIC:
                        self._render_traffic_page(image, draw)
                    else:
                        pass  # Fall through to main page rendering below

                if current_page != PAGE_MAIN or _wd_override:
                    # Non-main pages are fully rendered above, skip to display
                    epd_img = _apply_epd_rotation(image, self.screen_reversed)
                    self.epd_helper.display_partial(epd_img)
                    self.epd_helper.display_partial(epd_img)
                    web_img = _apply_web_rotation(image, self.web_screen_reversed)
                    with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                        web_img.save(img_file)
                        img_file.flush()
                        os.fsync(img_file.fileno())
                    self._sleep_interruptible(current_page)
                    continue

                # === PAGE_MAIN: Default Ragnar display ===
                # Scale factors spread positions across the full physical canvas
                # For 90°/270° we render in portrait so W < H.
                W = render_w
                H = render_h
                # Small square panels (e.g. the 128x128 LCD HAT) can't fit the
                # tall e-paper dashboard — its absolute coords fall off-screen and
                # the speech text collides with the character sprite. Render a
                # dedicated compact layout instead and commit it directly.
                if render_w < 150 and 100 <= render_h < 170:
                    try:
                        self._render_main_compact(image, draw, W, H)
                    except Exception as e:
                        logger.debug(f"compact main render error: {e}")
                    epd_img = _apply_epd_rotation(image, self.screen_reversed)
                    self.epd_helper.display_partial(epd_img)
                    self.epd_helper.display_partial(epd_img)
                    web_img = _apply_web_rotation(image, self.web_screen_reversed)
                    with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                        web_img.save(img_file)
                        img_file.flush()
                        os.fsync(img_file.fileno())
                    self._sleep_interruptible(PAGE_MAIN)
                    continue
                ref_w = self.shared_data.config.get('ref_width', 122)
                ref_h = self.shared_data.config.get('ref_height', 250)
                if self.screen_reversed in (90, 270):
                    sx = render_w / ref_w   # portrait: 480/122 ≈ 3.93
                    sy = render_h / ref_h   # portrait: 800/250 = 3.2
                else:
                    sx = self.scale_factor_x
                    sy = self.scale_factor_y

                # Check PiSugar once per frame for title sizing + battery text
                _pisugar_available = False
                try:
                    _ri = getattr(self.shared_data, 'ragnar_instance', None)
                    _ps = getattr(_ri, 'pisugar_listener', None) if _ri else None
                    _pisugar_available = _ps and _ps.available
                except Exception:
                    pass
                if _pisugar_available:
                    draw.text((int(40 * sx), int(6 * sy)), "RAGNAR", font=self.shared_data.font_viking_sm, fill=0)
                else:
                    draw.text((int(37 * sx), int(5 * sy)), "RAGNAR", font=self.shared_data.font_viking, fill=0)
                draw.text((int(110 * sx), int(170 * sy)), self.manual_mode_txt, font=self.shared_data.font_arial14, fill=0)
                
                # Show AP status or WiFi status in the top-left corner
                if hasattr(self.shared_data, 'ap_mode_active') and self.shared_data.ap_mode_active:
                    ap_text = "AP"
                    if hasattr(self.shared_data, 'ap_client_count') and self.shared_data.ap_client_count > 0:
                        ap_text = f"AP:{self.shared_data.ap_client_count}"
                    draw.text((int(3 * sx), int(3 * sy)), ap_text, font=self.shared_data.font_arial9, fill=0)
                elif self.shared_data.wifi_connected:
                    self.render_wifi_wave_indicator(image, draw)
                if self.shared_data.pan_connected:
                    image.paste(self.shared_data.connected, (int(104 * sx), int(3 * sy)))
                if self.shared_data.usb_active:
                    image.paste(self.shared_data.usb, (int(90 * sx), int(4 * sy)))

                # Battery percentage (PiSugar) - flush right in header
                if _pisugar_available:
                    try:
                        bat_level = _ps.get_battery_level()
                        if bat_level is not None:
                            bat_level = int(round(bat_level))
                            charging = _ps.is_charging()
                            bat_text = f"{bat_level}%+" if charging else f"{bat_level}%"
                            bbox = self.shared_data.font_arial9.getbbox(bat_text)
                            text_w = bbox[2] - bbox[0]
                            tx = W - text_w - 1
                            draw.text((tx, int(10 * sy)),
                                      bat_text, font=self.shared_data.font_arial9, fill=0)
                    except Exception:
                        pass

                # Stats — positions scaled to fill the physical width/height,
                # but icon images stay at their original pixel size.
                stats = [
                    (self.shared_data.target,    (int(8 * sx),   int(22 * sy)), (int(28 * sx),  int(22 * sy)), str(self.shared_data.targetnbr)),
                    (self.shared_data.port,      (int(47 * sx),  int(22 * sy)), (int(67 * sx),  int(22 * sy)), str(self.shared_data.portnbr)),
                    (self.shared_data.vuln,      (int(86 * sx),  int(22 * sy)), (int(106 * sx), int(22 * sy)), str(self.shared_data.vulnnbr)),
                    (self.shared_data.cred,      (int(8 * sx),   int(41 * sy)), (int(28 * sx),  int(41 * sy)), str(self.shared_data.crednbr)),
                    (self.shared_data.money,     (int(3 * sx),   int(172 * sy)), (int(3 * sx),  int(192 * sy)), str(self.shared_data.coinnbr)),
                    (self.shared_data.level,     (int(2 * sx),   int(217 * sy)), (int(4 * sx),  int(237 * sy)), str(self.shared_data.levelnbr)),
                    (self.shared_data.zombie,    (int(47 * sx),  int(41 * sy)), (int(67 * sx),  int(41 * sy)), str(self.shared_data.zombiesnbr)),
                    (self.shared_data.networkkb, (int(102 * sx), int(190 * sy)), (int(102 * sx), int(208 * sy)), str(self.shared_data.networkkbnbr)),
                    (self.shared_data.data,      (int(86 * sx),  int(41 * sy)), (int(106 * sx), int(41 * sy)), str(self.shared_data.datanbr)),
                    (self.shared_data.attacks,   (int(100 * sx), int(218 * sy)), (int(102 * sx), int(237 * sy)), str(self.shared_data.attacksnbr)),
                ]

                for img, img_pos, text_pos, text in stats:
                    image.paste(img, img_pos)
                    draw.text(text_pos, text, font=self.shared_data.font_arial9, fill=0)

                self.shared_data.update_ragnarstatus()
                image.paste(self.shared_data.ragnarstatusimage, (int(3 * sx), int(60 * sy)))
                draw.text((int(35 * sx), int(65 * sy)), self.shared_data.ragnarstatustext, font=self.shared_data.font_arial9, fill=0)
                draw.text((int(35 * sx), int(75 * sy)), self.shared_data.ragnarstatustext2, font=self.shared_data.font_arial9, fill=0)

                # Frise ribbon
                if self.shared_data.frise is not None:
                    frise_img = self.shared_data.frise
                    if frise_img.width != W - 2:
                        frise_img = frise_img.resize((W - 2, frise_img.height), Image.NEAREST)
                    image.paste(frise_img, (1, int(160 * sy)))

                # Frame & dividers — span full physical width
                draw.rectangle((1, 1, W - 1, H - 1), outline=0)
                draw.line((1, int(20 * sy), W - 1, int(20 * sy)), fill=0)
                draw.line((1, int(59 * sy), W - 1, int(59 * sy)), fill=0)
                draw.line((1, int(87 * sy), W - 1, int(87 * sy)), fill=0)

                lines = self.shared_data.wrap_text(self.shared_data.ragnarsays, self.shared_data.font_arialbold, W - 4)
                y_text = int(90 * sy)

                # Character image — centred on the full canvas
                if self.main_image is not None:
                    cx = (W - self.main_image.width) // 2
                    cy = H - self.main_image.height
                    image.paste(self.main_image, (cx, cy))
                else:
                    logger.error("Main image not found in shared_data.")

                for line in lines:
                    draw.text((int(4 * sx), y_text), line, font=self.shared_data.font_arialbold, fill=0)
                    y_text += (self.shared_data.font_arialbold.getbbox(line)[3] - self.shared_data.font_arialbold.getbbox(line)[1]) + 3

                if self.screen_reversed and self.screen_reversed in _ROTATION_TRANSPOSE:
                    epd_img = _apply_epd_rotation(image, self.screen_reversed)
                else:
                    epd_img = image

                self.epd_helper.display_partial(epd_img)
                self.epd_helper.display_partial(epd_img)

                web_img = _apply_web_rotation(image, self.web_screen_reversed)
                with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                    web_img.save(img_file)
                    img_file.flush()
                    os.fsync(img_file.fileno())

                self._sleep_interruptible(PAGE_MAIN)
            except Exception as e:
                logger.error(f"An error occurred: {e}")

def handle_exit_display(signum, frame, display_thread, exit_process=True):
    """Handle the exit signal and close the display."""
    global should_exit
    shared_data.display_should_exit = True
    logger.info("Exit signal received. Waiting for the main loop to finish...")
    try:
        if main_loop and hasattr(main_loop, 'epd_helper') and main_loop.epd_helper:
            main_loop.epd_helper.sleep()
    except Exception as e:
        logger.error(f"Error while closing the display: {e}")

    if display_thread and display_thread.is_alive():
        display_thread.join()

    logger.info("Main loop finished. Clean exit.")

    if exit_process:
        sys.exit(0)

# Declare main_loop globally
main_loop = None

if __name__ == "__main__":
    try:
        logger.info("Starting main loop...")
        main_loop = Display(shared_data)
        display_thread = threading.Thread(target=main_loop.run)
        display_thread.start()
        logger.info("Main loop started.")
        
        signal.signal(signal.SIGINT, lambda signum, frame: handle_exit_display(signum, frame, display_thread))
        signal.signal(signal.SIGTERM, lambda signum, frame: handle_exit_display(signum, frame, display_thread))
    except Exception as e:
        logger.error(f"An exception occurred during program execution: {e}")
        handle_exit_display(signal.SIGINT, None, display_thread)
        sys.exit(1)
