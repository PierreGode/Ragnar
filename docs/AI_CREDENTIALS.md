# AI-assisted credentials

The bruteforce connectors (SSH, FTP, Telnet, SMB, SQL, RDP) used to spray the
cartesian product of `data/input/dictionary/users.txt` x `passwords.txt` —
tens of thousands of attempts per host, blind to what the target actually is.

When **AI-Assisted Credentials** is enabled, each connector first asks the
configured OpenAI-compatible endpoint (OpenAI, Ollama, MiMo, OpenRouter, ...)
for a small set of **ranked** (user, password) pairs grounded in:

* IP, hostname, MAC address / OUI
* open ports and any known banners
* previously captured credentials for that host

Those pairs are tried **before** the wordlist spray. The wordlist always
remains as the fallback, so nothing regresses if AI is disabled or down.

## Why this helps

A host named `nas-01`, a Synology OUI, or a `vsftpd 2.3.4` banner tells the
model more than a generic 10k-password list. ~25 targeted attempts often beat
9,800 blind ones — especially on a Pi Zero class device where the spray is the
bottleneck.

## Config

| Key | Default | Meaning |
|---|---|---|
| `ai_creds_enabled` | `false` | Master switch |
| `ai_creds_max_pairs` | `25` | Cap on model-suggested pairs per host/service (1–50) |

Also requires the normal AI settings (`ai_enabled`, `ai_base_url`, model,
token) to be configured — see `docs/AI_INTEGRATION.md`.

## Behaviour

* **Fail-open** — any AI error returns no pairs and the connector uses the
  wordlist only. Attacks never depend on the model being up.
* **Cached** — 3 model calls max per (host, service) per 6h window so a re-run does not re-query.
* **Deduped** — AI pairs are merged in front of the wordlist without repeats.
* Results still go through the normal credential store / `CredentialChecker`,
  so a known-good pair is verified rather than re-sprayed.

## Credit

Contributed by [@SneezeGUI](https://github.com/SneezeGUI).
