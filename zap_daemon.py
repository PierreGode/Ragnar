# zap_daemon.py

import os
import shutil
import socket
import subprocess
import threading
import time
from typing import Optional


class ZapDaemonManager:
    def __init__(
        self,
        logger,
        host: str = "127.0.0.1",
        port: int = 8090,
        api_key: Optional[str] = None,
        max_start_retries: int = 3,
        startup_timeout: float = 15.0,
        retry_delay: float = 3.0,
        monitor_interval: float = 30.0,
    ) -> None:
        self.logger = logger
        self.host = host
        self.port = port
        self.api_key = api_key
        self.max_start_retries = max_start_retries
        self.startup_timeout = startup_timeout
        self.retry_delay = retry_delay
        self.monitor_interval = monitor_interval
        self._missing_binary = False
        self._stop_event = threading.Event()

    def resolve_zap_path(self) -> Optional[str]:
        env_paths = [
            os.getenv("RAGNAR_ZAP_PATH"),
            os.getenv("ZAP_PATH"),
            os.getenv("ZAPROXY_PATH"),
            os.getenv("ZAP_SH"),
        ]
        for candidate in env_paths:
            if candidate and os.path.exists(candidate):
                return candidate

        for binary in ("zap.sh", "zap", "zaproxy"):
            resolved = shutil.which(binary)
            if resolved:
                return resolved

        for candidate in ("/usr/share/zaproxy/zap.sh", "/opt/zap/zap.sh"):
            if os.path.exists(candidate):
                return candidate

        return None

    def _is_port_open(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=2):
                return True
        except OSError:
            return False

    def _wait_for_ready(self, timeout: float) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            if self._is_port_open():
                return True
            time.sleep(0.5)
        return False

    def start_daemon(self) -> bool:
        if self._is_port_open():
            return True

        zap_path = self.resolve_zap_path()
        if not zap_path:
            if not self._missing_binary:
                self.logger.warning(
                    "ZAP daemon binary not found. Set RAGNAR_ZAP_PATH or install ZAP."
                )
                self._missing_binary = True
            return False

        self._missing_binary = False
        args = [
            zap_path,
            "-daemon",
            "-host",
            self.host,
            "-port",
            str(self.port),
        ]

        if self.api_key:
            args.extend(["-config", f"api.key={self.api_key}"])
        else:
            args.extend(["-config", "api.disablekey=true"])

        for attempt in range(1, self.max_start_retries + 1):
            try:
                self.logger.info(f"Starting ZAP daemon (attempt {attempt})...")
                subprocess.Popen(
                    args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception as exc:
                self.logger.error(f"Failed to launch ZAP daemon: {exc}")
            else:
                if self._wait_for_ready(self.startup_timeout):
                    self.logger.info("ZAP daemon is running.")
                    return True

            self.logger.warning("ZAP daemon not ready yet; retrying...")
            time.sleep(self.retry_delay)

        self.logger.error("ZAP daemon failed to start after retries.")
        return False

    def ensure_daemon(self) -> bool:
        if self._is_port_open():
            return True
        return self.start_daemon()

    def stop(self) -> None:
        self._stop_event.set()

    def monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.ensure_daemon()
            except Exception as exc:
                self.logger.error(f"ZAP daemon monitor error: {exc}")
            self._stop_event.wait(self.monitor_interval)
