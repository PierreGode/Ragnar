"""
notify_sinks.py - Additional notification sinks beyond Pushover.

Ragnar already generates good alerts (Watchtower, asset inventory, new
devices/vulns/creds) but the only way they leave the box is Pushover. That
makes the device an ornament for anyone who does not want a Pushover account.

This module adds two low-friction egress paths that are popular in homelabs:

* **ntfy**  — POST to an ntfy topic (https://ntfy.sh or self-hosted).
              No account required for public topics; a token unlocks
              auth-protected topics. Native phone apps exist for
              Android/iOS/desktop.

* **webhook** — generic JSON POST (or a Slack-flavoured {text} block).
              Fits Discord/Slack/Mattermost/anything that eats JSON.

Both are optional, independently enabled, and share the same
`deliver(title, message, priority)` entry point so callers never need to
know which sink is live. Delivery is fire-and-forget from the caller's
perspective; failures are logged and never raise.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_NTFY_SERVER = "https://ntfy.sh"
_HTTP_TIMEOUT = 10
_MIN_INTERVAL_S = 1.0  # per-sink politeness


class _RateLimit:
    def __init__(self):
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            gap = time.time() - self._last
            if gap < _MIN_INTERVAL_S:
                time.sleep(_MIN_INTERVAL_S - gap)
            self._last = time.time()


def _post(url: str, data: bytes, headers: dict, timeout: int = _HTTP_TIMEOUT) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body


def _priority_to_ntfy(priority: int) -> str:
    """Map Pushover-style priority (-2..2) onto ntfy priority names."""
    if priority >= 2:
        return "urgent"
    if priority == 1:
        return "high"
    if priority <= -2:
        return "min"
    if priority == -1:
        return "low"
    return "default"


class NtfySink:
    """Push a notification to an ntfy topic."""

    type = "ntfy"

    def __init__(self, cfg: dict):
        self._rl = _RateLimit()
        self.reload(cfg)

    def reload(self, cfg: dict) -> None:
        server = (cfg.get("ntfy_server") or DEFAULT_NTFY_SERVER).rstrip("/")
        if not server.startswith("http"):
            server = "https://" + server
        self.server = server
        self.topic = (cfg.get("ntfy_topic") or "").strip()
        self.token = (cfg.get("ntfy_token") or "").strip()
        self.enabled = bool(cfg.get("ntfy_enabled", False)) and bool(self.topic)

    def send(self, title: str, message: str, priority: int = 0) -> dict:
        if not self.enabled:
            return {"success": False, "message": "ntfy not configured"}
        url = f"{self.server}/{self.topic}"
        headers = {
            "Title": title.encode("utf-8", "replace").decode("latin-1", "replace"),
            "Priority": _priority_to_ntfy(priority),
            "Tags": "shield,skull",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._rl.wait()
        try:
            status, _body = _post(url, message.encode("utf-8"), headers)
            if 200 <= status < 300:
                logger.info("ntfy notification sent: %s", title)
                return {"success": True, "message": "ntfy sent"}
            logger.warning("ntfy returned HTTP %s for %s", status, title)
            return {"success": False, "message": f"ntfy HTTP {status}"}
        except Exception as exc:
            logger.error("ntfy send failed: %s", exc)
            return {"success": False, "message": str(exc)}


class WebhookSink:
    """POST a JSON payload (or Slack-style text block) to an arbitrary URL."""

    type = "webhook"

    def __init__(self, cfg: dict):
        self._rl = _RateLimit()
        self.reload(cfg)

    def reload(self, cfg: dict) -> None:
        self.url = (cfg.get("webhook_url") or "").strip()
        self.flavour = (cfg.get("webhook_flavour") or "json").strip().lower()
        self.enabled = bool(cfg.get("webhook_enabled", False)) and bool(self.url)

    def send(self, title: str, message: str, priority: int = 0) -> dict:
        if not self.enabled:
            return {"success": False, "message": "webhook not configured"}
        if self.flavour == "slack":
            payload = {"text": f"*{title}*\n{message}"}
        else:
            payload = {
                "source": "ragnar",
                "title": title,
                "message": message,
                "priority": priority,
                "ts": int(time.time()),
            }
        self._rl.wait()
        try:
            status, _body = _post(
                self.url,
                json.dumps(payload).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            if 200 <= status < 300:
                logger.info("webhook notification sent: %s", title)
                return {"success": True, "message": "webhook sent"}
            logger.warning("webhook returned HTTP %s for %s", status, title)
            return {"success": False, "message": f"webhook HTTP {status}"}
        except Exception as exc:
            logger.error("webhook send failed: %s", exc)
            return {"success": False, "message": str(exc)}


class NotifySinks:
    """Fan-out manager for the non-Pushover sinks."""

    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self._lock = threading.Lock()
        self._sinks = []
        self.reload()

    def reload(self) -> None:
        cfg = self.shared_data.config if self.shared_data is not None else {}
        with self._lock:
            self._sinks = [NtfySink(cfg), WebhookSink(cfg)]

    def any_enabled(self) -> bool:
        with self._lock:
            return any(s.enabled for s in self._sinks)

    def send(self, title: str, message: str, priority: int = 0) -> None:
        """Deliver to every enabled sink. Never raises."""
        with self._lock:
            sinks = list(self._sinks)
        for sink in sinks:
            if sink.enabled:
                try:
                    sink.send(title, message, priority)
                except Exception as exc:  # belt and braces
                    logger.error("notify sink %s raised: %s", sink.type, exc)


# Module-level singleton so call sites stay simple.
_sinks: Optional[NotifySinks] = None
_sinks_lock = threading.Lock()


def get_sinks(shared_data=None) -> NotifySinks:
    global _sinks
    with _sinks_lock:
        if _sinks is None:
            _sinks = NotifySinks(shared_data)
        return _sinks


def deliver(title: str, message: str, priority: int = 0, shared_data=None) -> None:
    """Fire-and-forget delivery to every configured non-Pushover sink."""
    sinks = get_sinks(shared_data)
    threading.Thread(
        target=sinks.send, args=(title, message, priority), daemon=True
    ).start()
