#!/usr/bin/env python3
"""
AirSnitch Wi-Fi Client Isolation Testing Module for Ragnar

Tests whether a Wi-Fi network properly enforces client isolation using three attack vectors:
  - GTK Abuse: checks if clients share a group transient key
  - Gateway Bouncing: tests IP-layer isolation bypass via the gateway
  - Port Stealing: tests whether an attacker can intercept victim traffic

Source: https://github.com/vanhoefm/airsnitch

WARNING: Only run against networks you own or have explicit written permission to test.
"""

import os
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Optional

# Required attributes for Ragnar action framework
b_class = "AirSnitch"
b_module = "airsnitch"
b_status = "airsnitch_scan"
b_port = None   # Standalone – not tied to a specific port
b_parent = None

AIRSNITCH_REPO = "https://github.com/vanhoefm/airsnitch.git"
DEFAULT_TIMEOUT = 120  # seconds per test


class AirSnitchRunner:
    """
    Low-level wrapper around the airsnitch.py command-line tool.
    Handles installation, configuration, and execution.
    """

    def __init__(self, install_dir: str, logger: logging.Logger):
        self.install_dir = Path(install_dir)
        self.logger = logger
        self.script = self.install_dir / "airsnitch.py"

    # ------------------------------------------------------------------
    # Installation helpers
    # ------------------------------------------------------------------

    def is_installed(self) -> bool:
        return self.script.exists()

    def install(self) -> bool:
        """Clone and set up the AirSnitch repository."""
        try:
            if not self.install_dir.exists():
                self.logger.info(f"Cloning AirSnitch into {self.install_dir} …")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", AIRSNITCH_REPO, str(self.install_dir)],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode != 0:
                    self.logger.error(f"git clone failed: {result.stderr.strip()}")
                    return False

            setup = self.install_dir / "setup.sh"
            if setup.exists():
                self.logger.info("Running AirSnitch setup.sh …")
                result = subprocess.run(
                    ["bash", str(setup)],
                    cwd=str(self.install_dir),
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode != 0:
                    self.logger.warning(f"setup.sh exited {result.returncode}: {result.stderr[:500]}")

            # Make the script executable
            self.script.chmod(self.script.stat().st_mode | 0o111)
            self.logger.info("AirSnitch installed successfully.")
            return True

        except Exception as exc:
            self.logger.error(f"AirSnitch installation failed: {exc}")
            return False

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def write_client_conf(
        self,
        conf_path: Path,
        victim_ssid: str,
        victim_psk: str,
        attacker_ssid: str,
        attacker_psk: str,
        victim_bssid: Optional[str] = None,
    ) -> None:
        """Write a wpa_supplicant-style client.conf for AirSnitch."""
        victim_bssid_line = f"\n    bssid={victim_bssid}" if victim_bssid else ""
        conf = (
            "ctrl_interface=wpaspy_ctrl\n\n"
            "network={\n"
            '    id_str="victim"\n'
            f'    ssid="{victim_ssid}"\n'
            "    key_mgmt=WPA-PSK\n"
            f'    psk="{victim_psk}"{victim_bssid_line}\n'
            "}\n\n"
            "network={\n"
            '    id_str="attacker"\n'
            f'    ssid="{attacker_ssid}"\n'
            "    key_mgmt=WPA-PSK\n"
            f'    psk="{attacker_psk}"\n'
            "}\n"
        )
        conf_path.write_text(conf)

    # ------------------------------------------------------------------
    # Test runners
    # ------------------------------------------------------------------

    def _run(self, args: list, timeout: int = DEFAULT_TIMEOUT) -> dict:
        """Execute airsnitch.py with the given arguments and return parsed output."""
        cmd = ["python3", str(self.script)] + args
        self.logger.info(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.install_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"returncode": -1, "stdout": "", "stderr": "Timed out"}
        except Exception as exc:
            return {"returncode": -1, "stdout": "", "stderr": str(exc)}

    def test_gtk_shared(
        self, iface_victim: str, iface_attacker: str, same_bss: bool = False
    ) -> dict:
        """Test GTK Abuse – checks whether victim and attacker receive the same group key."""
        bss_flag = "--same-bss" if same_bss else "--other-bss"
        raw = self._run(
            [iface_victim, "--check-gtk-shared", iface_attacker,
             "--no-ssid-check", bss_flag]
        )
        vulnerable = "gtk is shared" in raw["stdout"].lower()
        return {
            "test": "gtk_shared",
            "vulnerable": vulnerable,
            "same_bss": same_bss,
            **raw,
        }

    def test_gateway_bouncing(
        self, iface_victim: str, iface_attacker: str, same_bss: bool = False
    ) -> dict:
        """Test Gateway Bouncing – checks IP-layer isolation via the gateway."""
        bss_flag = "--same-bss" if same_bss else "--other-bss"
        raw = self._run(
            [iface_victim, "--c2c-ip", iface_attacker,
             "--no-ssid-check", bss_flag]
        )
        vulnerable = "client to client traffic at ip layer is allowed" in raw["stdout"].lower()
        return {
            "test": "gateway_bouncing",
            "vulnerable": vulnerable,
            "same_bss": same_bss,
            **raw,
        }

    def test_port_steal_downlink(
        self, iface_victim: str, iface_attacker: str, server: str = "8.8.8.8"
    ) -> dict:
        """Test Downlink Port Stealing across different access points."""
        raw = self._run(
            [iface_victim, "--c2c-port-steal", iface_attacker,
             "--no-ssid-check", "--other-bss", "--server", server]
        )
        vulnerable = "success" in raw["stdout"].lower() or "intercepted" in raw["stdout"].lower()
        return {
            "test": "port_steal_downlink",
            "vulnerable": vulnerable,
            "server": server,
            **raw,
        }

    def test_port_steal_uplink(
        self, iface_victim: str, iface_attacker: str,
        same_bss: bool = False, server: Optional[str] = None
    ) -> dict:
        """Test Uplink Port Stealing."""
        bss_flag = "--same-bss" if same_bss else "--other-bss"
        args = [iface_victim, "--c2c-port-steal-uplink", iface_attacker,
                "--no-ssid-check", bss_flag]
        if server:
            args += ["--server", server]
        raw = self._run(args)
        vulnerable = "success" in raw["stdout"].lower() or "intercepted" in raw["stdout"].lower()
        return {
            "test": "port_steal_uplink",
            "vulnerable": vulnerable,
            "same_bss": same_bss,
            "server": server,
            **raw,
        }


# ==============================================================================
# Ragnar action wrapper
# ==============================================================================

class AirSnitch:
    """
    Ragnar action wrapper for AirSnitch Wi-Fi client isolation testing.

    Configuration (read from shared_data.config):
        airsnitch_iface_victim   – wireless interface acting as victim   (default: wlan1)
        airsnitch_iface_attacker – wireless interface acting as attacker (default: wlan2)
        airsnitch_tests          – list of tests to run; options:
                                     "gtk", "gateway", "port_steal_down", "port_steal_up"
                                   (default: all four)
        airsnitch_same_bss       – bool, True to test same BSS scenarios (default: False)
        airsnitch_server         – pingable server IP for port-steal tests (default: "8.8.8.8")
    """

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.port = None   # Standalone action
        self.b_parent_action = None
        self.logger = logging.getLogger(__name__)

        install_dir = os.path.join(
            getattr(shared_data, "currentdir", "/opt/ragnar"),
            "tools", "airsnitch",
        )
        self.runner = AirSnitchRunner(install_dir, self.logger)
        self.results_dir = Path(
            getattr(shared_data, "logsdir", "/tmp/ragnar_logs"), "airsnitch"
        )
        self.results_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cfg(self, key: str, default=None):
        cfg = getattr(self.shared_data, "config", {})
        return cfg.get(key, default)

    def _save_results(self, results: dict) -> Path:
        ts = int(time.time())
        path = self.results_dir / f"airsnitch_{ts}.json"
        path.write_text(json.dumps(results, indent=2, default=str))
        self.logger.info(f"AirSnitch results saved to {path}")
        return path

    # ------------------------------------------------------------------
    # Entry point called by Ragnar orchestrator
    # ------------------------------------------------------------------

    def execute(self, ip=None, port=None, row=None, status_key=None):
        """Run the configured AirSnitch tests and persist results."""
        self.logger.info("AirSnitch: starting Wi-Fi client isolation test")

        # Ensure AirSnitch is available
        if not self.runner.is_installed():
            self.logger.info("AirSnitch not installed – attempting installation …")
            if not self.runner.install():
                self.logger.error("AirSnitch installation failed – skipping")
                return "failed"

        iface_victim   = self._cfg("airsnitch_iface_victim",   "wlan1")
        iface_attacker = self._cfg("airsnitch_iface_attacker", "wlan2")
        tests          = self._cfg("airsnitch_tests",          ["gtk", "gateway", "port_steal_down", "port_steal_up"])
        same_bss       = self._cfg("airsnitch_same_bss",       False)
        server         = self._cfg("airsnitch_server",         "8.8.8.8")

        self.logger.info(
            f"AirSnitch: victim={iface_victim} attacker={iface_attacker} "
            f"same_bss={same_bss} tests={tests}"
        )

        results = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "iface_victim": iface_victim,
            "iface_attacker": iface_attacker,
            "tests": {},
        }

        try:
            if "gtk" in tests:
                self.logger.info("AirSnitch: running GTK shared-key test …")
                results["tests"]["gtk_shared"] = self.runner.test_gtk_shared(
                    iface_victim, iface_attacker, same_bss=same_bss
                )

            if "gateway" in tests:
                self.logger.info("AirSnitch: running gateway bouncing test …")
                results["tests"]["gateway_bouncing"] = self.runner.test_gateway_bouncing(
                    iface_victim, iface_attacker, same_bss=same_bss
                )

            if "port_steal_down" in tests:
                self.logger.info("AirSnitch: running downlink port-steal test …")
                results["tests"]["port_steal_downlink"] = self.runner.test_port_steal_downlink(
                    iface_victim, iface_attacker, server=server
                )

            if "port_steal_up" in tests:
                self.logger.info("AirSnitch: running uplink port-steal test …")
                results["tests"]["port_steal_uplink"] = self.runner.test_port_steal_uplink(
                    iface_victim, iface_attacker, same_bss=same_bss, server=server
                )

            # Summarise findings
            vulnerable_tests = [
                name for name, data in results["tests"].items()
                if isinstance(data, dict) and data.get("vulnerable")
            ]
            results["summary"] = {
                "total_tests": len(results["tests"]),
                "vulnerable_count": len(vulnerable_tests),
                "vulnerable_tests": vulnerable_tests,
                "network_isolated": len(vulnerable_tests) == 0,
            }

            self._save_results(results)

            if vulnerable_tests:
                self.logger.warning(
                    f"AirSnitch: network FAILS client isolation – "
                    f"vulnerable to: {', '.join(vulnerable_tests)}"
                )
            else:
                self.logger.info("AirSnitch: network passes client isolation tests")

            return "success"

        except Exception as exc:
            self.logger.error(f"AirSnitch execution error: {exc}", exc_info=True)
            results["error"] = str(exc)
            self._save_results(results)
            return "failed"

    def get_latest_results(self) -> Optional[dict]:
        """Return the most recent saved results, or None if none exist."""
        files = sorted(self.results_dir.glob("airsnitch_*.json"), reverse=True)
        if not files:
            return None
        try:
            return json.loads(files[0].read_text())
        except Exception:
            return None
