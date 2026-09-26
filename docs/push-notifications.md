# Push Notifications

**Config → Push Notifications** sends Ragnar's alerts to your phone or team chat.
Two delivery channels are supported, and every configured channel receives every
alert:

| Channel | What you need | Stored in `.env` as |
|---|---|---|
| **Pushover** | A User Key + an application API Token from [pushover.net](https://pushover.net/) | `RAGNAR_PUSHOVER_USER_KEY`, `RAGNAR_PUSHOVER_API_TOKEN` |
| **Slack** | An [Incoming Webhook](https://api.slack.com/messaging/webhooks) URL (`https://hooks.slack.com/...`) for the target channel | `RAGNAR_SLACK_WEBHOOK_URL` |

Configure one or both, tick **Enable Push Notifications**, and use
**Send Test Notification** — the result names which channels delivered (and why any
failed). Saving keys or a webhook switches notifications on automatically.

## What gets sent

The trigger checkboxes (new device, new vulnerability, new credential, device
offline / back online, wardrive auto-upload summary) apply to all channels. The
same channels also carry Network Integrity, Watchtower, incident-correlation and
RuSense alerts — each gated by its own toggle in its tab.

High-priority alerts (vulnerabilities, integrity/Watchtower pages) are prefixed with
`:rotating_light:` in Slack.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET/POST/DELETE | `/api/pushover/keys` | Pushover key status / save / remove |
| GET/POST/DELETE | `/api/slack/webhook` | Slack webhook status / save / remove |
| POST | `/api/pushover/test` | Send a test to every configured channel |

The master switch is still the `pushover_enabled` config key (name kept for
compatibility with existing configs).
