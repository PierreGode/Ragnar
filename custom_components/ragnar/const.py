"""Constants for the Ragnar integration."""

from __future__ import annotations

DOMAIN = "ragnar"

# Config entry keys
CONF_HOST = "host"
CONF_PORT = "port"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_SSL = "ssl"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SCAN_INTERVAL = "scan_interval"

DEFAULT_PORT = 8000
DEFAULT_SSL = False
DEFAULT_VERIFY_SSL = False
DEFAULT_SCAN_INTERVAL = 30  # seconds

# Ragnar API paths (see webapp_modern.py)
API_AUTH_STATUS = "/api/auth/status"
API_AUTH_LOGIN = "/api/auth/login"
API_RUSENSE_PRESENCE = "/api/rusense/presence"
API_RUSENSE_VITALS = "/api/rusense/vitals-history?hours=1"
API_SENSING_STATUS = "/api/sensing/status"
API_WATCHTOWER = "/api/net/watchtower"
API_INCIDENTS = "/api/net/incidents"
API_STATUS = "/api/status"

# Event fired on the HA bus for each new security alert
EVENT_SECURITY_ALERT = f"{DOMAIN}_security_alert"
