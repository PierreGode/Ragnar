# legacywatch / wpswatch lab

Validation tiers for the two standalone watch modules, from cheapest (runs
anywhere) to most realistic (needs a wireless-capable Linux host).

| Tier | Command | Runs on the Ragnar dev box? |
|---|---|---|
| self-test | `python3 python/legacywatch.py --self-test` · `… wpswatch.py --self-test` | yes (no root, no Scapy, no radio) |
| conformance | `python3 python/legacywatch_conformance.py` · `… wpswatch_conformance.py` | yes |
| replay (real Scapy path) | build a pcap then `--replay` it (below) | yes (needs Scapy) |
| live (hwsim) | `sudo lab/hwsim_lab.sh {legacy\|wps}` | **no** — needs `mac80211_hwsim` + tcpreplay + root |

## Replay path (validated)

`make_lab_pcap.py` reuses the modules' own frame builders, so the lab traffic is
exactly what the offline tests assert on, and writes a `LINKTYPE_IEEE802_11_
RADIOTAP` (127) pcap — files only, no sockets, no radio state.

```sh
cd lab
python3 make_lab_pcap.py legacy /tmp/legacy.pcap
python3 ../python/legacywatch.py --replay /tmp/legacy.pcap --echo

python3 make_lab_pcap.py wps /tmp/wps.pcap
python3 ../python/wpswatch.py --replay /tmp/wps.pcap --echo
```

This drives the *real* Scapy `PcapReader` → `process_packet()` path (everything
the live sniffer does except the radio front-end). Observed on the dev box:
legacywatch → 10 finding codes, wpswatch → 8 finding codes.

## Live path (hwsim, hardware/root-gated)

`hwsim_lab.sh` loads `mac80211_hwsim` with two virtual radios, puts both in
monitor mode on channel 6, runs the watcher live on `wlan1`, and injects the
test pcap on `wlan0` with `tcpreplay`. It then asserts that the expected finding
codes appeared in the live JSONL output, and tears the module + interfaces down
on exit.

```sh
sudo apt-get install -y tcpreplay iw          # once
sudo lab/hwsim_lab.sh legacy
sudo lab/hwsim_lab.sh wps
```

Status: **written, not yet run** — the Ragnar dev box is headless with no
wireless stack, so `modprobe mac80211_hwsim` is unavailable there. Run it on any
Linux host (or VM) with the module present. Injection stays entirely on the
virtual radios; no frame leaves the machine.

## Topology

```
  make_lab_pcap.py ──▶ radiotap pcap
                            │  tcpreplay -i wlan0 (monitor)
                            ▼
        mac80211_hwsim virtual medium (channel 6)
                            │  Scapy monitor sniff
                            ▼
        legacywatch/wpswatch -i wlan1 ──▶ alerts.jsonl ──▶ (assert codes)
```

A `mac80211_hwsim` medium is used rather than a veth pair because a veth is
`DLT_EN10MB`; these modules require `DLT_IEEE802_11_RADIOTAP`.
