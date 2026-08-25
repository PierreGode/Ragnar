# SIEM & Outbound Forwarding

Ragnar's detectors are only as useful as the places their findings can reach. Until
now every alert died inside the box — the Watchtower pane and a Pushover message
were the only exits. **SIEM forwarding** is the enterprise exit: it ships every
normalized alert to the collector your organization already runs.

It reuses the one point where **every** detector converges — the Watchtower poll
cycle — so a single tap covers all of it: the standalone watchers (arp_guard,
ndpwatch, wifiwatch, certwatch, snmpwatch, isiswatch, igmpwatch, legacywatch,
wpswatch), the in-app vendor CVE guards, ssh/telnet watch, the
[asset inventory](asset-inventory.md), and anything added later.

> Because egress happens in the Watchtower cycle, **Watchtower must be enabled**
> for anything to leave the box. The Assets tab warns you if it isn't.

## Supported collectors

| Type | Transport | Payload |
|---|---|---|
| `syslog` | UDP or TCP (optionally **TLS**), RFC 5424 or RFC 3164 framing | **CEF** (ArcSight / Splunk / Microsoft Sentinel), **LEEF** (IBM QRadar), or plain text |
| `splunk_hec` | HTTPS | Splunk HTTP Event Collector (ECS-shaped JSON, token auth) |
| `elastic` | HTTP(S) | Elasticsearch / OpenSearch `_bulk` index of ECS docs (basic or API-key auth) |
| `webhook` | HTTP(S) | generic `{source, count, alerts:[…ECS…]}` JSON POST |
| `slack` | HTTP(S) | a Slack/Mattermost/Teams-compatible `{text}` block |

Everything is **stdlib-only** (`socket`, `ssl`, `urllib`) — it runs on a Pi Zero
2 W as happily as on a rack server — and every delivery is **best-effort and
time-bounded**: a dead or slow collector can never block or crash the monitor loop.

## Field mapping

Each normalized Ragnar alert (`ts`, `source`, `severity`, `title`, `codes`, `src`,
`target`) maps cleanly:

- **CEF** — `CEF:0|Ragnar|Ragnar|1.0|<source:code>|<title>|<0-10 sev>|rt=…
  src=… dst=… cs1=<codes> cs2=<ragnar severity> msg=<title>`
- **LEEF** — `LEEF:2.0|Ragnar|Ragnar|1.0|<source:code>|` + tab-delimited
  `devTime/sev/cat/src/dst/policy/msg`.
- **ECS** (HEC / Elastic / webhook) — `@timestamp`, `event.module/dataset/severity`,
  `rule.name/id`, `source.ip`, `destination.address`, `ragnar.*`.

Ragnar severity → syslog severity → CEF/LEEF 0-10:

| Ragnar | syslog | CEF/LEEF |
|---|---|---|
| critical | 2 (crit) | 10 |
| high | 3 (err) | 8 |
| medium | 4 (warn) | 5 |
| low | 5 (notice) | 3 |
| info | 6 (info) | 1 |

## Configuring targets

In the **Assets** tab, under **SIEM & Outbound Forwarding**:

1. Toggle **Enabled** and pick a **min severity** floor (default `high` — only
   high/critical leave the box).
2. **Add a target**: choose a type, give it a name, fill the fields, **Add**.
3. **Send test** (all) or **Test** (one) pushes a synthetic alert so you can
   confirm the collector receives it before relying on it.

### Keeping secrets out of the config file

Target settings live in `config/shared_config.json` (which is git-ignored). To keep
a token or password out of that file entirely, put it in `.env` and reference it:

```
# .env
RAGNAR_SPLUNK_HEC=3f8c…your-hec-token…
```

then set the target's **Token** field to `env:RAGNAR_SPLUNK_HEC`. Any target value
of the form `env:NAME` is resolved from the environment at send time. Secrets are
always redacted (`***`) in the API and UI.

## Example targets

```jsonc
// Syslog CEF to a Splunk/QRadar/Sentinel collector over UDP
{ "type": "syslog", "name": "soc-splunk", "host": "10.0.0.20",
  "port": 514, "protocol": "udp", "format": "cef" }

// QRadar LEEF over TCP+TLS
{ "type": "syslog", "name": "qradar", "host": "qradar.corp", "port": 6514,
  "protocol": "tcp", "tls": true, "format": "leef", "rfc": "5424" }

// Splunk HTTP Event Collector (token from .env)
{ "type": "splunk_hec", "name": "splunk-hec",
  "url": "https://splunk:8088/services/collector",
  "token": "env:RAGNAR_SPLUNK_HEC", "index": "ragnar", "sourcetype": "ragnar:alert" }

// Elasticsearch bulk index
{ "type": "elastic", "name": "elastic", "url": "https://es:9200",
  "index": "ragnar-alerts", "username": "elastic", "password": "env:RAGNAR_ES_PW" }

// Slack / Teams / Mattermost incoming webhook
{ "type": "slack", "name": "soc-channel", "url": "https://hooks.slack.com/services/…" }
```

## Configuration keys

```jsonc
"siem_enabled": false,
"siem_min_severity": "high",   // forward floor: critical/high/medium/low/info
"siem_targets": []             // list of target dicts (as above)
```

## Files & CLI

- `siem_forwarder.py` — the module. Self-test: `python3 siem_forwarder.py --self-test`.
- Ad-hoc send from the CLI:
  ```
  python3 siem_forwarder.py --send-test --type syslog --host 10.0.0.20 \
      --port 514 --protocol udp --format cef
  ```

## API

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/siem` | current config (secrets redacted), targets, last result |
| `POST` | `/api/siem/config` | `{enabled, min_severity, targets?}` |
| `POST` | `/api/siem/targets/add` | `{target}` |
| `POST` | `/api/siem/targets/remove` | `{index}` |
| `POST` | `/api/siem/test` | send a synthetic alert (`{target}` inline, `{index}` stored, or all) |
