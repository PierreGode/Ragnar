# Notification sinks: ntfy and webhooks

Ragnar alerts (new devices, vulnerabilities, credentials, Watchtower, RuSense,
wardrive uploads) can now leave the box without a Pushover account.

## ntfy

1. Install the ntfy app (Android/iOS/desktop) or use any HTTP client.
2. Pick a topic name (keep it unguessable, e.g. `ragnar-a8f3k2`).
3. In **Config → ntfy / Webhook Notifications**:
   - **Enable ntfy Notifications** = on
   - **ntfy Server** = `https://ntfy.sh` (or your self-hosted instance)
   - **ntfy Topic** = your topic name
   - **ntfy Access Token** = optional; required for protected topics

## Webhook

- **Webhook URL** = any HTTPS endpoint that accepts POST
- **Webhook Format**:
  - `json` — `{"source":"ragnar","title","message","priority","ts"}`
  - `slack` — `{"text":"*title*\nmessage"}` (Slack/Discord-compatible)

## Behaviour

- Sinks and Pushover are independent; enable any combination.
- Each notify toggle under Pushover Notifications still applies (new device,
  vulnerability, credentials, ...) — they now gate *all* sinks, not just
  Pushover.
- Settings apply without a service restart.
- Failures are logged and never interrupt scanning.

## Credit

Contributed by [@SneezeGUI](https://github.com/SneezeGUI).
