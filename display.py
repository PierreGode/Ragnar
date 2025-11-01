#display.py
# Description:
# This file, display.py, is responsible for managing the e-ink display of the Bjorn project, updating it with relevant data and statuses.
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
import pandas as pd
import signal
import glob
import logging
import random
import sys
from PIL import Image, ImageDraw
from init_shared import shared_data  
from comment import Commentaireia
from logger import Logger
import subprocess  

logger = Logger(name="display.py", level=logging.DEBUG)

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

        # Define frise positions for different display types
        self.frise_positions = {
            "epd2in7": {
                "x": 50,
                "y": 160
            },
            "default": {  # Default position for other display types
                "x": 0,
                "y": 160
            }
        }

        try:
            self.epd_helper = self.shared_data.epd_helper
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
            time.sleep(25)

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
        with self.semaphore:
            try:
                if not os.path.exists(self.shared_data.vuln_summary_file):
                    df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    df.to_csv(self.shared_data.vuln_summary_file, index=False)
                    self.shared_data.vulnnbr = 0
                    logger.info("Vulnerability summary file created.")
                else:
                    if os.path.exists(self.shared_data.netkbfile):
                        with open(self.shared_data.netkbfile, 'r') as file:
                            netkb_df = pd.read_csv(file)
                            alive_macs = set(netkb_df[(netkb_df["Alive"] == 1) & (netkb_df["MAC Address"] != "STANDALONE")]["MAC Address"])
                    else:
                        alive_macs = set()

                    with open(self.shared_data.vuln_summary_file, 'r') as file:
                        df = pd.read_csv(file)
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
                        with open(self.shared_data.livestatusfile, 'r+') as livestatus_file:
                            livestatus_df = pd.read_csv(livestatus_file)
                            livestatus_df.loc[0, 'Vulnerabilities Count'] = self.shared_data.vulnnbr
                            livestatus_df.to_csv(self.shared_data.livestatusfile, index=False)
                            logger.debug(f"Updated livestatusfile with vulnerability count: {self.shared_data.vulnnbr}")
                    else:
                        logger.error(f"Livestatusfile {self.shared_data.livestatusfile} does not exist.")
            except Exception as e:
                logger.error(f"An error occurred in update_vuln_count: {e}")

    def update_shared_data(self):
        """Update the shared data with the latest system information."""
        with self.semaphore:
            try:
                with open(self.shared_data.livestatusfile, 'r') as file:
                    livestatus_df = pd.read_csv(file)
                    self.shared_data.portnbr = livestatus_df['Total Open Ports'].iloc[0]
                    self.shared_data.targetnbr = livestatus_df['Alive Hosts Count'].iloc[0]
                    self.shared_data.networkkbnbr = livestatus_df['All Known Hosts Count'].iloc[0]
                    self.shared_data.vulnnbr = livestatus_df['Vulnerabilities Count'].iloc[0]

                crackedpw_files = glob.glob(f"{self.shared_data.crackedpwddir}/*.csv")

                total_passwords = 0
                for file in crackedpw_files:
                    with open(file, 'r') as f:
                        total_passwords += len(pd.read_csv(f, usecols=[0]))

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
                self.shared_data.wifi_connected = self.is_wifi_connected()
                self.shared_data.ap_mode_active = self.is_ap_mode_active()
                self.shared_data.ap_client_count = self.get_ap_client_count() if self.shared_data.ap_mode_active else 0
                self.shared_data.usb_active = self.is_usb_connected()
                
                # Update Wi-Fi/AP status text for display
                wifi_status_text = self.get_wifi_status_text()
                self.shared_data.ragnarstatustext2 = wifi_status_text
                
                self.get_open_files()

            except (FileNotFoundError, pd.errors.EmptyDataError) as e:
                logger.error(f"Error: {e}")
            except Exception as e:
                logger.error(f"Error updating shared data: {e}")

    def display_comment(self, status):
        """Display the comment based on the status of the ragnarorch."""
        comment = self.commentaire_ia.get_commentaire(status)
        if comment:
            self.shared_data.bjornsay = comment
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
        """Check if WiFi is connected by checking the current SSID."""
        try:
            result = subprocess.Popen(['iwgetid', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ssid, error = result.communicate()
            if result.returncode != 0:
                logger.error(f"Error executing 'iwgetid -r': {error}")
                return False
            return bool(ssid.strip())
        except Exception as e:
            logger.error(f"Error checking WiFi status: {e}")
            return False

    def is_ap_mode_active(self):
        """Check if AP mode is currently active."""
        try:
            # Check if hostapd is running
            result = subprocess.run(['pgrep', 'hostapd'], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            
            # Alternative check: see if we're listening on AP interface
            result = subprocess.run(['ip', 'addr', 'show', 'wlan0'], capture_output=True, text=True)
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
            result = subprocess.run(['hostapd_cli', '-i', 'wlan0', 'list_sta'], 
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
            # Try to get status from WiFi manager first (more accurate)
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
                
                return "WiFi: Disconnected"
            
            # Fallback to system commands if WiFi manager not available
            # Check if we're in AP mode first
            if self.is_ap_mode_active():
                # Try to get AP client count
                try:
                    result = subprocess.run(['hostapd_cli', '-i', 'wlan0', 'list_sta'], 
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
            
            # Check if Wi-Fi is connected
            result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                ssid = result.stdout.strip()
                return f"WiFi: {ssid}"
            
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

    def run(self):
        """Main loop for updating the EPD display with shared data."""
        self.manual_mode_txt = ""
        while not self.shared_data.display_should_exit:
            try:
                self.epd_helper.init_partial_update()
                self.display_comment(self.shared_data.ragnarorch_status)
                image = Image.new('1', (self.shared_data.width, self.shared_data.height))
                draw = ImageDraw.Draw(image)
                draw.rectangle((0, 0, self.shared_data.width, self.shared_data.height), fill=255)
                draw.text((int(37 * self.scale_factor_x), int(5 * self.scale_factor_y)), "BJORN", font=self.shared_data.font_viking, fill=0)
                draw.text((int(110 * self.scale_factor_x), int(170 * self.scale_factor_y)), self.manual_mode_txt, font=self.shared_data.font_arial14, fill=0)
                
                # Show AP status or WiFi status in the top-left corner
                if hasattr(self.shared_data, 'ap_mode_active') and self.shared_data.ap_mode_active:
                    # Show AP status with client count
                    ap_text = f"AP"
                    if hasattr(self.shared_data, 'ap_client_count') and self.shared_data.ap_client_count > 0:
                        ap_text = f"AP:{self.shared_data.ap_client_count}"
                    draw.text((int(3 * self.scale_factor_x), int(3 * self.scale_factor_y)), ap_text, font=self.shared_data.font_arial9, fill=0)
                elif self.shared_data.wifi_connected:
                    image.paste(self.shared_data.wifi, (int(3 * self.scale_factor_x), int(3 * self.scale_factor_y)))
                # # # if self.shared_data.bluetooth_active:
                # # #     image.paste(self.shared_data.bluetooth, (int(23 * self.scale_factor_x), int(4 * self.scale_factor_y)))
                if self.shared_data.pan_connected:
                    image.paste(self.shared_data.connected, (int(104 * self.scale_factor_x), int(3 * self.scale_factor_y)))
                if self.shared_data.usb_active:
                    image.paste(self.shared_data.usb, (int(90 * self.scale_factor_x), int(4 * self.scale_factor_y)))

                stats = [
                    (self.shared_data.target, (int(8 * self.scale_factor_x), int(22 * self.scale_factor_y)), (int(28 * self.scale_factor_x), int(22 * self.scale_factor_y)), str(self.shared_data.targetnbr)),
                    (self.shared_data.port, (int(47 * self.scale_factor_x), int(22 * self.scale_factor_y)), (int(67 * self.scale_factor_x), int(22 * self.scale_factor_y)), str(self.shared_data.portnbr)),
                    (self.shared_data.vuln, (int(86 * self.scale_factor_x), int(22 * self.scale_factor_y)), (int(106 * self.scale_factor_x), int(22 * self.scale_factor_y)), str(self.shared_data.vulnnbr)),
                    (self.shared_data.cred, (int(8 * self.scale_factor_x), int(41 * self.scale_factor_y)), (int(28 * self.scale_factor_x), int(41 * self.scale_factor_y)), str(self.shared_data.crednbr)),
                    (self.shared_data.money, (int(3 * self.scale_factor_x), int(172 * self.scale_factor_y)), (int(3 * self.scale_factor_x), int(192 * self.scale_factor_y)), str(self.shared_data.coinnbr)),
                    (self.shared_data.level, (int(2 * self.scale_factor_x), int(217 * self.scale_factor_y)), (int(4 * self.scale_factor_x), int(237 * self.scale_factor_y)), str(self.shared_data.levelnbr)),
                    (self.shared_data.zombie, (int(47 * self.scale_factor_x), int(41 * self.scale_factor_y)), (int(67 * self.scale_factor_x), int(41 * self.scale_factor_y)), str(self.shared_data.zombiesnbr)),
                    (self.shared_data.networkkb, (int(102 * self.scale_factor_x), int(190 * self.scale_factor_y)), (int(102 * self.scale_factor_x), int(208 * self.scale_factor_y)), str(self.shared_data.networkkbnbr)),
                    (self.shared_data.data, (int(86 * self.scale_factor_x), int(41 * self.scale_factor_y)), (int(106 * self.scale_factor_x), int(41 * self.scale_factor_y)), str(self.shared_data.datanbr)),
                    (self.shared_data.attacks, (int(100 * self.scale_factor_x), int(218 * self.scale_factor_y)), (int(102 * self.scale_factor_x), int(237 * self.scale_factor_y)), str(self.shared_data.attacksnbr)),
                ]

                for img, img_pos, text_pos, text in stats:
                    image.paste(img, img_pos)
                    draw.text(text_pos, text, font=self.shared_data.font_arial9, fill=0)

                self.shared_data.update_bjornstatus()
                image.paste(self.shared_data.bjornstatusimage, (int(3 * self.scale_factor_x), int(60 * self.scale_factor_y)))
                draw.text((int(35 * self.scale_factor_x), int(65 * self.scale_factor_y)), self.shared_data.ragnarstatustext, font=self.shared_data.font_arial9, fill=0)
                draw.text((int(35 * self.scale_factor_x), int(75 * self.scale_factor_y)), self.shared_data.ragnarstatustext2, font=self.shared_data.font_arial9, fill=0)

                # Get frise position based on display type
                frise_x, frise_y = self.get_frise_position()
                image.paste(self.shared_data.frise, (frise_x, frise_y))

                draw.rectangle((1, 1, self.shared_data.width - 1, self.shared_data.height - 1), outline=0)
                draw.line((1, 20, self.shared_data.width - 1, 20), fill=0)
                draw.line((1, 59, self.shared_data.width - 1, 59), fill=0)
                draw.line((1, 87, self.shared_data.width - 1, 87), fill=0)

                lines = self.shared_data.wrap_text(self.shared_data.bjornsay, self.shared_data.font_arialbold, self.shared_data.width - 4)
                y_text = int(90 * self.scale_factor_y)

                if self.main_image is not None:
                    image.paste(self.main_image, (self.shared_data.x_center1, self.shared_data.y_bottom1))
                else:
                    logger.error("Main image not found in shared_data.")

                for line in lines:
                    draw.text((int(4 * self.scale_factor_x), y_text), line, font=self.shared_data.font_arialbold, fill=0)
                    y_text += (self.shared_data.font_arialbold.getbbox(line)[3] - self.shared_data.font_arialbold.getbbox(line)[1]) + 3

                if self.screen_reversed:
                    image = image.transpose(Image.ROTATE_180)

                self.epd_helper.display_partial(image)
                self.epd_helper.display_partial(image)

                if self.web_screen_reversed:
                    image = image.transpose(Image.ROTATE_180)
                with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                    image.save(img_file)
                    img_file.flush()
                    os.fsync(img_file.fileno())
                
                time.sleep(self.shared_data.screen_delay)
            except Exception as e:
                logger.error(f"An error occurred: {e}")

def handle_exit_display(signum, frame, display_thread):
    """Handle the exit signal and close the display."""
    global should_exit
    shared_data.display_should_exit = True
    logger.info("Exit signal received. Waiting for the main loop to finish...")
    try:
        if main_loop and main_loop.epd:
            main_loop.epd.init(main_loop.epd.sleep)
            main_loop.epd.Dev_exit()
    except Exception as e:
        logger.error(f"Error while closing the display: {e}")
    display_thread.join()
    logger.info("Main loop finished. Clean exit.")
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
