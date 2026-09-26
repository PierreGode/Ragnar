#!/usr/bin/env python3
"""
Push Notification Service for Ragnar
Sends push notifications for security events via every configured channel:
Pushover (phone push) and/or Slack (incoming webhook).
"""

import logging
import threading
import time

logger = logging.getLogger(__name__)

PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"
SLACK_WEBHOOK_PREFIX = "https://hooks.slack.com/"


class PushoverService:
    """Push-notification dispatcher (historical name kept for its many callers).

    send() fans each message out to every configured channel — Pushover and/or
    a Slack incoming webhook — so all alert sources reach both."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._lock = threading.Lock()
        # Tracks already-notified items to avoid spamming
        self._notified_devices = set()   # set of IPs ever notified (persisted across restarts via DB load)
        self._offline_devices = set()    # IPs that went offline this session (for back-online detection)
        self._last_notified_vuln_count = 0  # last count we sent a vuln alert for
        self._notified_creds = 0         # last known cred count
        self._last_send_ts = 0.0         # rate-limit: min 2 s between sends
        self._startup_ts = time.time()   # suppress device notifications shortly after restart
        self._startup_grace_s = 90       # seconds to wait before sending device alerts
        self._load_known_state_from_db()

    # ------------------------------------------------------------------
    # DB state loader — prevents restart-triggered false notifications
    # ------------------------------------------------------------------

    def _load_known_state_from_db(self):
        """Pre-populate _notified_devices and _last_notified_vuln_count from the DB
        so that a restart does not re-notify about already-known devices/vulns."""
        try:
            db = getattr(self.shared_data, 'db', None)
            if db is None:
                return
            with db.get_connection() as conn:
                cursor = conn.cursor()
                # Load all known IPs
                cursor.execute("SELECT ip FROM hosts WHERE ip IS NOT NULL AND ip != ''")
                rows = cursor.fetchall()
                with self._lock:
                    for row in rows:
                        # sqlite3.Row supports index access but has no .get()
                        ip = row[0] if row else ''
                        if ip:
                            self._notified_devices.add(ip)
                # Load current vuln count as baseline (so we only alert on genuinely new ones)
                cursor.execute(
                    "SELECT COUNT(*) FROM hosts "
                    "WHERE vulnerabilities IS NOT NULL AND vulnerabilities != '' AND vulnerabilities != 'None'"
                )
                row = cursor.fetchone()
                baseline = row[0] if row else 0
                with self._lock:
                    self._last_notified_vuln_count = baseline
                # Load credential baseline count
                try:
                    cursor.execute("SELECT COUNT(*) FROM hosts WHERE credentials IS NOT NULL AND credentials != '' AND credentials != 'None'")
                    cred_row = cursor.fetchone()
                    cred_baseline = cred_row[0] if cred_row else 0
                    with self._lock:
                        self._notified_creds = cred_baseline
                except Exception:
                    pass  # credentials column may not exist
            logger.debug(
                f"Pushover: loaded {len(self._notified_devices)} known IPs, "
                f"vuln baseline={baseline} from DB"
            )
        except Exception as e:
            logger.debug(f"Pushover DB state load skipped: {e}")

    # ------------------------------------------------------------------
    # Key helpers (reads from .env via EnvManager)
    # ------------------------------------------------------------------

    def _get_keys(self):
        """Return (user_key, api_token) or (None, None) if not configured."""
        try:
            from env_manager import EnvManager
            em = EnvManager()
            user_key = em.get_env_key("RAGNAR_PUSHOVER_USER_KEY")
            api_token = em.get_env_key("RAGNAR_PUSHOVER_API_TOKEN")
            return user_key, api_token
        except Exception as e:
            logger.debug(f"Pushover key lookup failed: {e}")
            return None, None

    def _get_slack_webhook(self):
        """Return the Slack incoming-webhook URL, or None if not configured."""
        try:
            from env_manager import EnvManager
            url = EnvManager().get_env_key("RAGNAR_SLACK_WEBHOOK_URL")
            return url or None
        except Exception as e:
            logger.debug(f"Slack webhook lookup failed: {e}")
            return None

    def pushover_configured(self):
        """Return True when both Pushover keys are present."""
        user_key, api_token = self._get_keys()
        return bool(user_key and api_token)

    def slack_configured(self):
        """Return True when a Slack webhook URL is present."""
        return bool(self._get_slack_webhook())

    def is_configured(self):
        """Return True when at least one delivery channel is configured."""
        return self.pushover_configured() or self.slack_configured()

    def is_enabled(self):
        """Return True when push notifications are configured and enabled in config."""
        return self.shared_data.config.get("pushover_enabled", False) and self.is_configured()

    # ------------------------------------------------------------------
    # Core send
    # ------------------------------------------------------------------

    def send(self, message, title="Ragnar", priority=0, sound="pushover"):
        """Send a notification to every configured channel (Pushover, Slack).

        Returns dict with success/message; success is True when at least one
        channel delivered."""
        results = {}
        if self.pushover_configured():
            results["Pushover"] = self._send_pushover(message, title, priority, sound)
        webhook = self._get_slack_webhook()
        if webhook:
            results["Slack"] = self._send_slack(webhook, message, title, priority)
        if not results:
            return {"success": False, "message": "No notification channel configured"}
        ok = [name for name, r in results.items() if r.get("success")]
        failed = [f"{name}: {r.get('message')}" for name, r in results.items() if not r.get("success")]
        if ok:
            msg = f"Notification sent via {', '.join(ok)}"
            if failed:
                msg += f" (failed — {'; '.join(failed)})"
            return {"success": True, "message": msg, "channels": results}
        return {"success": False, "message": "; ".join(failed), "channels": results}

    def _send_slack(self, webhook, message, title="Ragnar", priority=0):
        """POST a message to a Slack incoming webhook."""
        if not webhook.startswith(SLACK_WEBHOOK_PREFIX):
            return {"success": False, "message": "Slack webhook URL must start with " + SLACK_WEBHOOK_PREFIX}
        try:
            import urllib.request
            import json

            prefix = ":rotating_light: " if priority and int(priority) >= 1 else ""
            payload = json.dumps({"text": f"{prefix}*{title}*\n{message}"}).encode("utf-8")
            req = urllib.request.Request(
                webhook, data=payload, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", "replace").strip()
                if resp.status == 200:
                    logger.info(f"Slack notification sent: {title}")
                    return {"success": True, "message": "Notification sent"}
                logger.warning(f"Slack webhook error: {resp.status} {body}")
                return {"success": False, "message": f"Slack error: {body or resp.status}"}
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return {"success": False, "message": str(e)}

    def _send_pushover(self, message, title="Ragnar", priority=0, sound="pushover"):
        """POST a message to the Pushover API."""
        user_key, api_token = self._get_keys()
        if not user_key or not api_token:
            return {"success": False, "message": "Pushover keys not configured"}

        # Simple rate-limit (2 s)
        with self._lock:
            now = time.time()
            elapsed = now - self._last_send_ts
            if elapsed < 2.0:
                time.sleep(2.0 - elapsed)
            self._last_send_ts = time.time()

        try:
            import urllib.request
            import urllib.parse
            import json

            payload = urllib.parse.urlencode({
                "token": api_token,
                "user": user_key,
                "message": message,
                "title": title,
                "priority": priority,
                "sound": sound,
            }).encode("utf-8")

            req = urllib.request.Request(PUSHOVER_API_URL, data=payload, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if body.get("status") == 1:
                    logger.info(f"Pushover notification sent: {title}")
                    return {"success": True, "message": "Notification sent"}
                else:
                    err = body.get("errors", ["Unknown error"])
                    logger.warning(f"Pushover API error: {err}")
                    return {"success": False, "message": f"Pushover error: {err}"}

        except Exception as e:
            logger.error(f"Pushover send failed: {e}")
            return {"success": False, "message": str(e)}

    # ------------------------------------------------------------------
    # Event helpers (called from webapp update loop)
    # ------------------------------------------------------------------

    def _in_startup_grace(self):
        """Return True if still within the post-restart grace period."""
        return (time.time() - self._startup_ts) < self._startup_grace_s

    def notify_new_devices(self, new_ips):
        """Notify about devices that have NEVER been seen before (deduped against DB)."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_new_device", True):
            return
        truly_new = [ip for ip in new_ips if ip not in self._notified_devices]
        if not truly_new:
            return
        self._notified_devices.update(truly_new)
        # Suppress notification during startup grace period — just record the IPs
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed new-device alert for {len(truly_new)} IP(s) during startup grace")
            return
        count = len(truly_new)
        ip_list = ", ".join(sorted(truly_new)[:5])
        suffix = f" (+{count - 5} more)" if count > 5 else ""
        msg = f"⚔️ {count} new device(s) discovered on the network for the first time:\n{ip_list}{suffix}"
        threading.Thread(target=self.send, args=(msg, "Ragnar — New Device"), daemon=True).start()

    def notify_device_lost(self, lost_ips):
        """Notify when devices go offline (and remember them for back-online detection)."""
        if not self.is_enabled():
            return
        # Always track offline state even if notifications are disabled, so back-online works
        self._offline_devices.update(lost_ips)
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed device-lost alert for {len(lost_ips)} IP(s) during startup grace")
            return
        if not self.shared_data.config.get("pushover_notify_device_lost", False):
            return
        if not lost_ips:
            return
        count = len(lost_ips)
        ip_list = ", ".join(sorted(lost_ips)[:5])
        suffix = f" (+{count - 5} more)" if count > 5 else ""
        msg = f"🛡️ {count} device(s) went offline:\n{ip_list}{suffix}"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Device Lost"), daemon=True).start()

    def notify_device_back_online(self, appeared_ips):
        """Notify when a previously known device that went offline comes back online."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_device_back_online", False):
            return
        # Only alert for IPs we actually saw go offline this session
        back_online = [ip for ip in appeared_ips
                       if ip in self._notified_devices and ip in self._offline_devices]
        if not back_online:
            return
        # Remove from offline tracking since they're back
        self._offline_devices.difference_update(back_online)
        count = len(back_online)
        ip_list = ", ".join(sorted(back_online)[:5])
        suffix = f" (+{count - 5} more)" if count > 5 else ""
        msg = f"📶 {count} device(s) back online:\n{ip_list}{suffix}"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Device Back Online"), daemon=True).start()

    def notify_new_vulnerabilities(self, new_total):
        """Notify about newly discovered vulnerabilities (compares against last notified count)."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_new_vulnerability", True):
            return
        with self._lock:
            if new_total <= self._last_notified_vuln_count:
                return
            delta = new_total - self._last_notified_vuln_count
            self._last_notified_vuln_count = new_total
        # Suppress notification during startup grace — just absorb the baseline
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed vuln alert (delta={delta}) during startup grace")
            return
        msg = f"🔥 {delta} new vulnerability/vulnerabilities found! (total: {new_total})"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Vulnerability Alert", 1), daemon=True).start()

    def notify_new_credentials(self, new_count, total):
        """Notify when new credentials are captured."""
        if not self.is_enabled():
            return
        if not self.shared_data.config.get("pushover_notify_new_credential", True):
            return
        if new_count <= 0:
            return
        if total == self._notified_creds:
            return
        self._notified_creds = total
        # Suppress notification during startup grace — just absorb the baseline
        if self._in_startup_grace():
            logger.debug(f"Pushover: suppressed credential alert during startup grace")
            return
        msg = f"🗝️ {new_count} new credential(s) captured! (total: {total})"
        threading.Thread(target=self.send, args=(msg, "Ragnar — Credentials"), daemon=True).start()

    def notify_wardrive_upload(self, message, title="Ragnar — Wardrive upload", priority=0):
        """Summary of a finished wardrive's auto-upload (one per drive, sent once
        every service has a final result). Gated by pushover_enabled +
        pushover_notify_wardrive_upload."""
        if not self.is_enabled():
            return False
        if not self.shared_data.config.get("pushover_notify_wardrive_upload", True):
            return False
        threading.Thread(target=self.send, args=(message[:1024], title, priority), daemon=True).start()
        return True

    # ------------------------------------------------------------------
    # RuSense (WiFi-CSI camera-free surveillance) alerts
    # ------------------------------------------------------------------
    # Maps each RuSense event kind to the config flag that gates it. The
    # background sensing monitor in webapp_modern.py does the edge detection
    # (empty<->occupied, motion onset, count threshold, node offline) and calls
    # notify_rusense(); this layer enforces enable/config gating and a per-kind
    # cooldown so a flapping signal can't spam the Pushover account.
    _RUSENSE_FLAGS = {
        "presence": "rusense_notify_presence",
        "motion": "rusense_notify_motion",
        "people": "rusense_notify_people",
        "node_offline": "rusense_notify_node_offline",
        "inactivity": "rusense_notify_inactivity",
    }

    def rusense_enabled(self, kind):
        """True when RuSense alerts are on, Pushover is usable, and `kind` is enabled."""
        if not self.is_enabled():
            return False
        if not self.shared_data.config.get("rusense_notify_enabled", False):
            return False
        flag = self._RUSENSE_FLAGS.get(kind)
        return bool(flag and self.shared_data.config.get(flag, False))

    def notify_rusense(self, kind, message, title="Ragnar — RuSense", priority=0, sound="pushover"):
        """Send a RuSense sensing alert if `kind` is enabled and off cooldown.

        Returns True if a send was dispatched, False if gated/throttled. The
        actual HTTP POST happens on a daemon thread so the caller's monitor
        loop never blocks on the network.
        """
        if not self.rusense_enabled(kind):
            return False
        # Per-kind cooldown — suppress repeats of the SAME event kind within the
        # configured window. Distinct kinds never throttle each other.
        if not hasattr(self, "_rusense_last_sent"):
            self._rusense_last_sent = {}
        try:
            cooldown = float(self.shared_data.config.get("rusense_notify_cooldown_s", 60))
        except (TypeError, ValueError):
            cooldown = 60.0
        now = time.time()
        with self._lock:
            last = self._rusense_last_sent.get(kind, 0.0)
            if now - last < cooldown:
                return False
            self._rusense_last_sent[kind] = now
        threading.Thread(
            target=self.send, args=(message, title, priority, sound), daemon=True
        ).start()
        return True

    def notify_net_integrity(self, message, priority=1, sound="siren"):
        """Send a network-integrity alert (DNS poisoning / ARP spoofing detected).

        Gated by pushover_enabled + configuration; deduped so the SAME ongoing
        condition isn't re-sent every monitor cycle (the caller only invokes this
        on a transition into a bad verdict, and this adds a cooldown backstop).
        Sent on a daemon thread so the monitor loop never blocks. Returns True if
        a send was dispatched."""
        if not self.is_enabled():
            return False
        if not self.shared_data.config.get("pushover_notify_net_integrity", True):
            return False
        try:
            cooldown = float(self.shared_data.config.get("net_integrity_notify_cooldown_s", 300))
        except (TypeError, ValueError):
            cooldown = 300.0
        now = time.time()
        with self._lock:
            last = getattr(self, "_net_integrity_last_sent", 0.0)
            if now - last < cooldown:
                return False
            self._net_integrity_last_sent = now
        threading.Thread(
            target=self.send,
            args=(message, "Ragnar — Network integrity", priority, sound),
            daemon=True,
        ).start()
        return True

    def notify_watchtower(self, message, priority=1, sound="siren"):
        """Send a unified-Watchtower alert (a standalone watcher — arp_guard,
        ndpwatch, wifiwatch, certwatch, … — raised a high/critical finding).

        Gated by pushover_enabled + watchtower_notify_enabled, with a cooldown
        backstop so a burst of watcher alerts in one poll can't page repeatedly.
        The caller (the Watchtower monitor loop) already dedupes per finding, so
        this is the last line of defence against notification spam. Sent on a
        daemon thread so the poll loop never blocks. Returns True if dispatched."""
        if not self.is_enabled():
            return False
        if not self.shared_data.config.get("watchtower_notify_enabled", True):
            return False
        try:
            cooldown = float(self.shared_data.config.get("watchtower_notify_cooldown_s", 300))
        except (TypeError, ValueError):
            cooldown = 300.0
        now = time.time()
        with self._lock:
            last = getattr(self, "_watchtower_last_sent", 0.0)
            if now - last < cooldown:
                return False
            self._watchtower_last_sent = now
        threading.Thread(
            target=self.send,
            args=(message, "Ragnar — Watchtower", priority, sound),
            daemon=True,
        ).start()
        return True
