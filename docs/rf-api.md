# RF instrument API

Everything the RF Waterfall and the Signal Analyzer do is a plain HTTP call, so
the instrument can be driven by a script, a cron job or another machine —
sweep a band overnight, arm a trigger from a shell script, pull measurements
into a notebook. This is the reference for those calls. The pages themselves are
just clients of it.

Base URL is the Ragnar web UI (`http://<unit>:8000` by default). Requests take
and return JSON; `POST` bodies are JSON objects. Errors come back as
`{"ok": false, "error": "…"}` with a message meant to be read, not parsed.

**One radio, one job.** The dongle can do one thing at a time. Calls that need
it (a capture, a harmonic check, an image check) refuse with `busy` rather than
interrupting whatever is running — see [Concurrency](#concurrency).

---

## Sweeping (RTL-SDR)

| Call | Does |
| --- | --- |
| `GET /api/net/rtl/status` | Is a dongle present, which model, what is wrong if not |
| `POST /api/net/rtl/power/start` | Start a sweep. `{band}` (`315`/`433`/`868`/`915`/`subghz`) or `{lo_hz, hi_hz}` |
| `POST /api/net/rtl/power/stop` | Stop it |
| `GET /api/net/rtl/power/frames?since=<seq>` | New rows since `seq`, plus `band_hz`, `floor_dbm`, `engine`, `rbw_hz`, `detector`, `overload`, `dc` (centre spike: `{mode: shown\|outside\|filled, tuner_hz, fill_hz}`), `max_hold` |
| `GET\|POST /api/net/rtl/tuning` | Read or set `ppm`, `gain`, `agc`, `fft`, `avg`, `window`, `bins`, `detector`, `bias_t`, `direct`, `conv_hz`, `hide_dc` (hide the RTL-SDR centre spike; default on) |
| `POST /api/net/rtl/calibrate` | PPM from a reference: `{true_mhz, near_mhz}` |
| `POST /api/net/rtl/tuning/reset` | Restore the shipped defaults (gain, detector, resolution, hardware options) |
| `POST /api/net/rtl/reset` | USB-reset a silent dongle; if it is missing or stuck, run the self-heal recovery instead |
| `GET\|POST /api/net/rtl/health` | Self-heal watcher: state, port, recent USB drops, kernel evidence, history; `POST {enabled}` switches it |
| `POST /api/net/rtl/heal` | Run the recovery ladder now (power-cycles the port a stuck dongle is on) |

A frame is `{seq, ts, power[]}` where `power` has `bins` entries spread evenly
over `band_hz`. Poll `frames` with the last `seq` you saw; nothing is lost
between polls as long as you keep up (the ring holds a few hundred rows).

`gain` takes a number in dB, `"managed"` (the default: the gain is held where
the front end has headroom, see
[managed gain](rf-waterfall.md#managed-gain)) or `"auto"` (the dongle's own AGC,
which clips). Settings are saved to `data/rf_settings.json` and survive a
restart.

`overload` is `{level: ok|near|overload, clip_frac, headroom_db, gain, managed}` — see
[Front-end health](rf-waterfall.md#front-end-health-and-proving-a-signal-is-real).
Treat `overload` as "these numbers are wrong", not as a warning to log.

## Measuring

| Call | Does |
| --- | --- |
| `POST /api/net/rtl/image-check` | `{freq_hz, bw_hz}` → is this a real signal, a mixer image, or the DC spike |
| `POST /api/net/rtl/harmonics` | `{freq_hz, bw_hz, n}` → 2×…n× the carrier, each in dBc |
| `POST /api/net/rtl/limit/alarm` | Log a limit violation (the page uses this for Watchtower) |
| `GET /api/net/rtl/df/position`, `POST` | This unit's position for direction finding |
| `POST /api/net/rtl/df` | `{freq_mhz, bw_khz, secs}` → every mesh unit measures it; returns a fix |
| `GET /api/mesh/rf/level` | Peer-facing: this unit's level at a frequency (used by `/df`) |

Both `image-check` and `harmonics` retune the radio several times and take
seconds, then restore the sweep that was running.

## Capturing

| Call | Does |
| --- | --- |
| `POST /api/net/rtl/iq/start` | `{center_hz, sr_hz, seconds, name, label}` — raw IQ to SigMF |
| `GET /api/net/rtl/iq/status` | Progress, or the error |
| `POST /api/net/rtl/iq/stop` | Stop early |
| `GET /api/net/rtl/iq/list` | Captures on the box |
| `GET /api/net/rtl/iq/file?name=…&kind=data\|meta` | Download either half of a SigMF pair |
| `POST /api/net/rtl/iq/rename`, `…/iq/delete` | Housekeeping |

The waterfall keeps running during a capture: the capture feeds it rows.

### Armed trigger

| Call | Does |
| --- | --- |
| `POST /api/net/rtl/trigger/arm` | `{mask[] \| level_db, f0_hz, f1_hz, pre_s, post_s, max_events, min_gap_s, margin_db, name}` |
| `POST /api/net/rtl/trigger/disarm` | Stop watching (and close any capture in progress) |
| `GET /api/net/rtl/trigger/status` | `{armed, recording, pre_buffered_s, count, events[]}` |

`mask` is a per-column limit line in dB (any length — it is stretched onto the
row); `level_db` is a flat line. `pre_s` is how many seconds *before* the event
to keep, which is the point of the whole thing. Each event writes a SigMF pair
and appears in `events[]` with the frequency, how far over the mask it was, and
the file name. See
[Trigger and capture](rf-waterfall.md#trigger-and-capture-armed-recording-with-a-lead-in).

## Unattended survey

| Call | Does |
| --- | --- |
| `POST /api/net/rtl/survey/start` | `{bands[], dwell_s, rounds, label}` |
| `POST /api/net/rtl/survey/stop`, `GET …/survey/status` | Control and progress |
| `GET /api/net/rtl/survey/list`, `…/survey/report?name=`, `…/survey/report.csv?name=` | Results |
| `POST /api/net/rtl/survey/delete` | Remove a report |

## Baseline (change detection → Watchtower)

`POST /api/net/rtl/baseline/arm`, `POST …/baseline/clear`,
`GET …/baseline/status`. Learns the normal spectrum, then alerts on new or
vanished carriers and on broadband jamming.

## Analysis (offline, no radio needed)

All under `/api/net/rtl/analyze/`. Selection arguments are shared:
`name` (the capture), `f_offset` (Hz from the capture centre), `bw` (Hz),
`t0`/`t1` (seconds).

| Call | Does |
| --- | --- |
| `GET summary`, `GET list` | Capture metadata; captures available |
| `GET spectrogram`, `GET psd`, `GET envelope`, `GET measure` | The plots and a windowed measurement |
| `GET bursts`, `GET signals` | Packet detection; every simultaneous carrier |
| `GET classify`, `GET modulation_quality` | What modulation; FM deviation and AM depth |
| `GET demod`, `GET pulse`, `GET frames`, `GET fingerprint`, `POST diff` | Bits, pulse symbols, framing, device fingerprint, field diffing |
| `GET constellation`, `GET constellation_demod` | Scatter; PSK recovery with EVM |
| `GET dechirp`, `GET cyclic`, `GET filter`, `GET decode433` | LoRa chirps, cyclostationary features, filtering, rtl_433 over the file |
| `GET annotations`, `POST annotate`, `POST annotation/delete` | Annotations on a capture |
| `POST upload` | Bring in a `.sub`, raw IQ or SigMF from elsewhere |

## Other radios and modes

- **HackRF sweep**: `GET /api/net/sdr/status`, `POST /api/net/sdr/start`
  (`{lo_mhz, hi_mhz, lna, vga, amp, antenna, bin_hz}`), `POST …/sdr/stop`,
  `GET …/sdr/frames?since=`.
- **Local Radio**: `GET /api/net/radio/status`, `GET /api/net/radio/stream`
  (MP3 stream; `{freq_mhz, mode, squelch}` as query parameters),
  `POST /api/net/radio/stop`.
- **ISM decode (rtl_433)**: `POST /api/net/rtl/ism/start`, `…/ism/stop`,
  `GET /api/net/rtl/ism/devices`.
- **Session recording** (the sweep, not IQ): `POST /api/net/rtl/record/start`,
  `…/record/stop`, `GET …/record/list`, `…/record/get?name=`.
- **Install / diagnose / selftest**: `POST /api/net/rtl/install`,
  `GET /api/net/rtl/diagnose`, `GET /api/net/rtl/selftest`,
  `GET /api/net/sdr/selftest`, `GET /api/net/radio/selftest`.

## Concurrency

One dongle serves one job. A call that needs the radio while something else has
it answers `{"ok": false, "error": "busy — this unit's dongle is in use"}`.
Scripts should either stop what is running first, or treat `busy` as "try
again". The sweep is the exception: `image-check` and `harmonics` borrow the
radio and put the sweep back when they finish.

Never restart a capture per event in a loop. Opening and closing the RTL2832U
repeatedly can leave it unresponsive until it is physically replugged; the
backend serialises captures and waits for the USB device to settle, but a script
that starts a sweep every 200 ms defeats that.

## Worked example

```bash
A=http://localhost:8000

# sweep the 433 ISM band with the RMS detector and a sane gain
curl -s -X POST $A/api/net/rtl/tuning  -H 'Content-Type: application/json' \
     -d '{"gain":28,"detector":"rms"}'
curl -s -X POST $A/api/net/rtl/power/start -H 'Content-Type: application/json' \
     -d '{"band":"433"}'
sleep 8

# check the front end is not clipping before believing anything
curl -s "$A/api/net/rtl/power/frames?since=999999" | jq '.overload'

# arm: record 1 s before and 2 s after anything 10 dB over the floor,
# stop after 20 captures
curl -s -X POST $A/api/net/rtl/trigger/arm -H 'Content-Type: application/json' \
     -d '{"level_db":-62,"pre_s":1,"post_s":2,"max_events":20,"min_gap_s":5}'

# ... later: what did it catch, and analyse the first one
curl -s $A/api/net/rtl/trigger/status | jq '.events[] | {name, freq_hz, excess_db}'
curl -s "$A/api/net/rtl/analyze/summary?name=trig-20260922-221500" | jq
```
