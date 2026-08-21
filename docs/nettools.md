# 🛡️ Authority Verification Across the Stack

The **Network** tab in the Ragnar web interface is a built-in engine for
**verifying authority across the stack** — at every layer, someone claims to be
the legitimate authority (the root bridge, the default gateway, the DNS
resolver, the DHCP server, the routing neighbour, the name responder, the SMB
server), and each tool here answers one question: *is that claim genuine, or is
an impostor asserting authority it shouldn't have?* It runs straight from the
device that's already sitting on the segment you care about, so it sees what the
segment sees — plus the everyday diagnostics you'd normally reach for a laptop
and a bag of CLI tools to do.

It is split into three sub-tabs: **Diagnostics**, **Switch & L2/L3**, and
**Interfaces**.

> **Co-authored by [Solarflere](https://www.instagram.com/solarflere).** The
> Authority Verification suite was designed and built in collaboration with Solarflere.

<img width="2160" height="3684" alt="image" src="https://github.com/user-attachments/assets/d0d25a5d-1027-4712-babc-3f3b9b99efc5" />




### Tool index

| Tool | Sub-tab | Endpoint |
|------|---------|----------|
| [Ping](#ping) | Diagnostics | `POST /api/net/ping` |
| [Traceroute](#traceroute) | Diagnostics | `POST /api/net/traceroute` |
| [MTR](#mtr) | Diagnostics | `POST /api/net/mtr` |
| [WHOIS](#whois) | Diagnostics | `POST /api/net/whois` |
| [IP Attribution (country/ASN/ISP/abuse)](ip-intel.md) | Diagnostics | `POST /api/net/ip-intel` |
| [DNS Doctor (poisoning check)](#dns-doctor) | Diagnostics | `POST /api/net/dns` |
| [ARP Poisoning](#arp-poisoning) | Diagnostics | `GET /api/net/arp-check`, `/arp-baseline` |
| [MAC Watch](#mac-watch) | Diagnostics | `GET /api/net/mac-watch`, `POST /api/net/mac-watch-reset` |
| [DHCP Guardian](#dhcp-guardian) | Switch & L2/L3 | `GET /api/net/dhcp-guardian`, `POST /api/net/dhcp-baseline` |
| [DHCP Snooping (inline)](#dhcp-snooping-inline) | Switch & L2/L3 | `GET /api/net/dhcp-snoop` + `/dhcp-snoop/status`, `/config`, `/setup` |
| [Network Integrity Monitor](#-network-integrity-monitor) | Diagnostics | `GET /api/net/integrity` + config |
| [Watchtower (unified watcher alerts)](watchtower.md) | Diagnostics | `GET /api/net/watchtower` + config |
| [Incident correlation (attack chains)](incident-correlation.md) | Diagnostics | `GET /api/net/incidents` + config |
| [Path MTU / Black-hole](#path-mtu--black-hole) | Diagnostics | `POST /api/net/pmtu` |
| [Captive Portal Check](#captive-portal-check) | Diagnostics | `GET /api/net/captive-portal` |
| [LAN Throughput (iperf3)](#lan-throughput-iperf3) | Diagnostics | `POST /api/net/iperf3`, `/iperf3-server` |
| [Speed Test](#speed-test) | Diagnostics | `POST /api/net/speedtest` |
| [Live Flow Telemetry](#live-flow-telemetry) | Diagnostics | `GET /api/net/flows` |
| [PTP Timing Detection](#ptp-timing-detection) | Diagnostics | `POST /api/net/ptp` |
| [On-Screen Network Diagnostic Mode](#-on-screen-network-diagnostic-mode) | Diagnostics (toggle) | config `network_diagnostic_mode` |
| [Switch Discovery + PoE](#switch-discovery-lldp--cdpv1v2--edp--fdp) | Switch & L2/L3 | `GET /api/net/lldp` |
| [ARP Scan](#arp-scan) | Switch & L2/L3 | `GET /api/net/arp-scan` |
| [L2 Link Health](#l2-link-health) | Switch & L2/L3 | `POST /api/net/l2-health` |
| [IGMP Watch](#igmp-watch) | Switch & L2/L3 | `GET /api/net/igmp-watch`, `POST /api/net/igmp-baseline` |
| [TLS Watch](#tls-watch) | Switch & L2/L3 | `GET /api/net/tls-watch` |
| [IPv6 First-Hop Watch](#ipv6-first-hop-watch) | Switch & L2/L3 | `GET /api/net/ipv6-watch`, `POST /api/net/ipv6-baseline` |
| [NDP Watch](#ndp-watch) | Switch & L2/L3 | `GET /api/net/ndp-watch`, `POST /api/net/ndp-baseline` |
| [IPv6 RA Guard](#ipv6-ra-guard) | Diagnostics | `GET /api/net/raguard`, `POST /api/net/raguard` `{action: harden}` |
| [NTP Watch](#ntp-watch) | Diagnostics | `GET /api/net/ntp-watch`, `POST /api/net/ntp-baseline` |
| [ICMP Watch](#icmp-watch) | Switch & L2/L3 | `GET /api/net/icmp-watch`, `POST /api/net/icmp-baseline` |
| [SNMP Watch](#snmp-watch) | Diagnostics | `GET /api/net/snmp-watch`, `POST /api/net/snmp-baseline` |
| [Cert Watch](#cert-watch) | Diagnostics | `POST /api/net/cert-watch`, `POST /api/net/cert-baseline` |
| [STP/BPDU Watch](#stpbpdu-watch) | Switch & L2/L3 | `GET /api/net/stp-watch`, `POST /api/net/stp-baseline` |
| [DTP Watch](#dtp-watch) | Switch & L2/L3 | `GET /api/net/dtp-watch`, `POST /api/net/dtp-baseline` |
| [CDP Watch](#cdp-watch) | Switch & L2/L3 | `GET /api/net/cdp-watch`, `POST /api/net/cdp-baseline` |
| [VTP Watch](#vtp-watch) | Switch & L2/L3 | `GET /api/net/vtp-watch`, `POST /api/net/vtp-baseline` |
| [SMB Watch](#smb-watch) | Switch & L2/L3 | `GET /api/net/smb-watch`, `POST /api/net/smb-baseline` |
| [Relay/Coercion Watch](#relaycoercion-watch) | Switch & L2/L3 | `GET /api/net/relay-watch`, `POST /api/net/relay-baseline` |
| [LDAP Watch](#ldap-watch) | Switch & L2/L3 | `GET /api/net/ldap-watch` |
| [FHRP Watch](#fhrp-watch) | Switch & L2/L3 | `GET /api/net/fhrp-watch`, `POST /api/net/fhrp-baseline` |
| [EIGRP Watch](#eigrp-watch) | Switch & L2/L3 | `GET /api/net/eigrp-watch`, `POST /api/net/eigrp-baseline` |
| [IS-IS Watch](#is-is-watch) | Switch & L2/L3 | `GET /api/net/isis-watch`, `POST /api/net/isis-baseline` |
| [OSPF Security Scanner](#ospf-security-scanner) | Switch & L2/L3 | `GET /api/net/ospf-watch`, `POST /api/net/ospf-baseline` |
| [BGP Path Watch](#bgp-path-watch) | Switch & L2/L3 | `GET /api/net/bgp-watch`, `POST /api/net/bgp-baseline` |
| [BGP Collector & Path Asymmetry](#bgp-collector--path-asymmetry-control-plane--data-plane) | Switch & L2/L3 | `GET/POST /api/net/bgp-collector`, `/api/net/owd-reflector`, `POST /api/net/path-asymmetry` |
| [Cisco Guard](#cisco-guard) | Switch & L2/L3 | `GET /api/net/cisco-guard` |
| [Juniper Guard](#juniper-guard) | Switch & L2/L3 | `GET /api/net/juniper-guard` |
| [Arista Guard](#arista-guard) | Switch & L2/L3 | `GET /api/net/arista-guard` |
| [Comware Guard](#comware-guard) | Switch & L2/L3 | `GET /api/net/comware-guard` |
| [Locate Port](#locate-port) | Switch & L2/L3 | `POST /api/net/locate-port` |
| [PCAP Analyzer](#pcap-analyzer) | Switch & L2/L3 | `POST /api/net/pcap` |
| [Interfaces](#interface-list) | Interfaces | `GET /api/net/interfaces` |
| [Network Identity](#network-identity) | Interfaces | `GET /api/net/identity` |
| [ISP / WAN + VPN Detection](#isp--wan-detection) | Interfaces | `GET /api/net/isp` |
| [VPN Egress Check](#vpn-egress-check) | Interfaces | `GET /api/net/vpn-check` |

---

## One-click install for missing tools

Most of these tools shell out to standard Linux utilities (`ping`, `mtr`,
`lldpd`, `arp-scan`, …). If one isn't present, Ragnar doesn't just show a dead
error — it shows an **Install** button. Clicking it runs a whitelisted
`apt-get install` for the exact package that provides the missing binary, then
re-runs the tool automatically. The button disappears once the tool is
available.

If a previous package operation on the box was interrupted (the classic
`dpkg was interrupted, you must manually run 'dpkg --configure -a'` state),
the installer detects it, runs the recovery automatically, and retries — so the
button works without you having to drop to a shell.

Installable packages are whitelisted (`iputils-ping`, `traceroute`, `mtr-tiny`,
`whois`, `speedtest-cli`, `lldpd`, `arp-scan`, `ethtool`, `curl`, `dnsutils`,
`iperf3`, `tcpdump`), so the tool name is never interpolated into a shell
command.

**Scapy** (for the routing-scanner end-to-end self-test) is installable the same
way — the **Detector Self-Test** panel in Switch & L2/L3 has an **Install Scapy**
button that installs `python3-scapy` (falling back to `pip`). It's optional: the
IGMP / OSPF / BGP scanners work fully without it; Scapy only adds the end-to-end
leg that crafts real packets → pcap → `tcpdump` → parse to exercise the whole
capture path.

### Detector Self-Test (Switch & L2/L3)
A one-click **Run self-test** that validates the IGMP, **IPv6 first-hop**, **NDP**, **RA Guard**,
**NTP**, **ICMP**, **SNMP**, **TLS-cert**, **STP**, **DTP**, **CDP**, **VTP**, **SMB**, **Relay/Coercion**, **EIGRP**, **IS-IS**, **FHRP**, OSPF and BGP detectors — plus the **BGP speaker** (codec/framer/FSM/RIB) and
**path-asymmetry / OWD** engine — by running each classifier against crafted attack
captures (no root, no external network) and reports per-suite pass/fail. With Scapy
installed it also runs the end-to-end packet-crafting leg for the capture-based
scanners, and Cert Watch grades a real self-signed cert over a local (loopback)
handshake. This is how you confirm the routing-security detectors are working on a
given box without waiting for a real attack — endpoint `GET /api/net/routing-selftest`.
The same checks run headless via
`python3 network_diagnostics.py {igmp,ipv6,raguard,ntp,icmp,snmp,tls,ospf,bgp}-selftest` and each module's
`selftest()`.

---

## 🖥️ On-Screen Network Diagnostic Mode

A toggle at the top of the Diagnostics sub-tab turns the **on-board display**
(e-Paper HAT or the 1.44" LCD HAT) into a standalone, Ethernet-focused field
tool — so you can plug the device
into a switch and read the essentials off the screen with **no laptop and no
internet**. Everything shown is gathered locally (`ip` / `ethtool` /
`lldpctl` / `resolv.conf`), so it works on an isolated or dead network.

The display auto-cycles six pages every **5 seconds**:

1. **LINK** — the physical wired port: interface, link up/down, negotiated
   speed, duplex, auto-negotiation, MAC. (Instantly spot a port that fell back
   to 100 Mbps or half-duplex.)
2. **IP** — addressing: DHCP vs static, IPv4/CIDR, default gateway (with its
   reverse-DNS name), and DNS servers.
3. **SWITCH** — the switch you're plugged into, via LLDP/CDP: switch name, the
   **exact port** (e.g. `GigabitEthernet1/0/12`), VLAN, **PoE** class/wattage,
   protocol, and management IP.
4. **DHCP** — the [DHCP Guardian](#dhcp-guardian) rogue-server watch: verdict,
   how many DHCP servers answered, the server-id and gateway it offers vs. your
   active gateway, and a **ROGUE!** count if a fake server is present. The scan
   runs in the background so the page never blocks the cycle.
5. **WIFI** — the wireless link you're on: **SSID**, **RSSI** (dBm) + quality %,
   band/channel and TX rate, with a live signal bar under the facts (walk around
   to find dead spots). Read passively from `iw dev … link` — no scan. Held in
   manual mode, the WIFI and SIGNAL cards **redraw every second** instead of
   the normal 5 s cycle, so the readings track you in real time.
6. **SIGNAL** — a bar chart of the **strongest nearby networks' signal
   strengths** (SSID + RSSI), from a background [passive Wi-Fi
   scan](wifi-analyzer.md) so the page never blocks. Between full discovery
   sweeps (~45 s) a **fast poll re-visits just the listed APs' channels every
   second**, so the bars move live as you walk — rows stay put, only the
   values change.
7. **SPECTRUM** — the [WiFi Spectrum Analyzer](wifi-analyzer.md)'s **Bar view on
   the panel**: a live **channel-occupancy graph** for one band (a bar per
   channel, height ∝ the strongest AP's signal there, **DFS/radar channels drawn
   hollow**, the busiest channel tick-marked), with the band, AP count and
   strongest channel + the **scanned adapter name** in the header. The ↑/↓
   joystick picks the **band** (2.4 / 5 / 6 GHz); an unsupported band says so.
   Shares the same background passive scan as SIGNAL, so it never blocks the
   cycle. *(LCD HAT only — the 2.7" e-Paper HAT's card set stops at SWITCH.)*
8. **IFACE** — pick which NIC the **egress tests** (Speed test, Ping GW, Ping
   WAN) originate from. ↑/↓ highlights **Auto** or an interface, press selects
   it; `*` marks the active choice and each row shows the NIC's IP, *no IP* or
   *down*. **Auto** follows a fixed priority — **built-in Ethernet → USB
   Ethernet → wlan1 → wlan0** — taking the first interface that is up and
   addressed (and, for the speed test, verified able to reach the internet with
   a device-bound probe), so a plugged-in cable is what gets tested instead of
   whatever holds the default route. The selection resets to Auto each time the
   mode is switched on. *(LCD HAT only.)*
9. **BT** — an on-demand **Bluetooth/BLE discovery sweep** (the same BlueZ
   scanner behind the analyzer's [Bluetooth overlay](wifi-analyzer.md)), so the
   card answers "what else is in 2.4 GHz?" next to SPECTRUM. Shows the device
   count, the **LE/Classic** split, how many are close, the adapter, and the
   **Wi-Fi channel carrying the most BT pressure**, then the loudest devices by
   name/vendor with RSSI bars. Needs a controller that is present and unblocked
   (`rfkill unblock bluetooth`), else the card reads *no adapter*.
   *(LCD HAT only.)*
10. **ZIGBEE** — an on-demand **802.15.4 sniff** via a **HuginnESP** companion
    (the same capture behind the [Zigbee overlay](wifi-analyzer.md)). Shows the
    device count, how many distinct channels are in use, how many are close, the
    busiest channel, then the loudest devices as `c<channel> <addr>` with RSSI
    bars. Needs a Huginn on USB with an 802.15.4 radio (ESP32-C5/C6/H2), else
    the card reads *no Huginn* or *no 15.4 rx*. *(LCD HAT only.)*

    **These two are one-shot, by design.** Unlike the Wi-Fi cards nothing polls
    in the background: the **centre press runs the scan** (~8 s) and the card
    then shows that result — with an **Age** so a stale scan can't be mistaken
    for a live one — until you press again. BT discovery and an 802.15.4 sniff
    each cost radio time (and the Huginn may be busy), so leaving them on the
    5 s auto-cycle would re-trigger a scan every time the card came round.

   **Which radio it scans:** the SIGNAL and SPECTRUM cards auto-select the
   **widest-band adapter present** — so a tri-band dongle (e.g. the **Alfa
   AWUS036AXM**, 2.4/5/6 GHz) is used for 5/6 GHz instead of the connected
   2.4-only onboard radio. The header shows that interface name; if you only
   see 2.4 GHz, plug in the Alfa (or another 5/6 GHz-capable adapter) and the
   card switches to it automatically.

The wired pages focus on the **physical** wired NIC (`eth*` / `en*`), ignoring
VPN, tunnel, bridge and container interfaces; the WIFI/SIGNAL/SPECTRUM pages use
the wireless interface. Toggle it off to restore the normal Ragnar display. The
setting is persisted (`network_diagnostic_mode` in the config) and shared across
sessions.

#### Field-test key pad (2.7" HAT)

On the 2.7" e-Paper HAT the four hardware keys become a **standalone field
tester** while this mode is active — so you can run live tests on the switch
with no laptop. Each key has a **short press** and a **long press** (hold
~0.6 s); a test's result stays on the panel until **KEY1** dismisses it. Outside
this mode the keys keep their normal Ragnar / wardriving behaviour (they act on
press) — the netdiag layer only takes over the keys when the toggle is on.

| Key | Short press | Long press (hold ~0.6 s) |
|-----|-------------|--------------------------|
| **KEY1** | Next diagnostic page | **Pause / resume** the auto-cycle |
| **KEY2** | **Locate port** — blink the switch link LED | **L2 health** capture (~12 s) |
| **KEY3** | **Ping the gateway** (LAN) | **Ping the internet** (`8.8.8.8`, WAN) |
| **KEY4** | **Speed test** | **DNS Doctor** — poisoning/hijack verdict |

KEY4-long resolves a preset hostname (`netdiag_dns_test_name`, default
`example.com`, since the panel has no keyboard) and shows a big
**CLEAN / SUSPECT / HIJACK** verdict. Tests run on a background thread so a key
press is never blocked, and the panel wakes immediately on a press rather than
waiting out the 5 s cycle.

The speed test and pings originate from the **priority interface** — built-in
Ethernet → USB Ethernet → wlan1 → wlan0, first one up and addressed (the speed
test also verifies it can reach the internet) — not from whatever holds the
default route, so plugging in a cable is enough to test the cable. The result
page shows the interface used.

#### Field-test pad (1.44" LCD HAT + joystick)

The Waveshare **1.44" LCD HAT** (ST7735S, 128×128) carries **3 keys plus a
5-way joystick**. On this HAT **KEY1 is the mode switch** — it toggles On-Screen
Network Diagnostic Mode on/off directly (no web UI needed). Select the HAT in
**Display settings** as *"1.44" ST7735S LCD HAT + joystick"*.

The mode is navigated as a stack of **cards** — `LINK · IP · SWITCH · DHCP ·
WIFI · SIGNAL · SPECTRUM · IFACE · BT · ZIGBEE`. **Left/Right move between cards; Up/Down
cycle the test functions *inside* a card; the centre press runs the highlighted
one** (the footer shows `>` + its name). While the mode is on:

| Input | Action |
|-------|--------|
| **KEY1** | **Switch to Ragnar** — toggle the mode off, back to the normal screens |
| **Joystick ← / →** | Previous / next **card** |
| **Joystick ↑ / ↓** | Cycle the highlighted **function** inside the card |
| **Joystick press** | **OK / select** — run the highlighted function (or dismiss a shown result) |
| **KEY2** | **Card-selection menu** — an overview list of the cards; press again to leave it |
| **KEY3** | **Pause / start auto-switch** — auto-cycle the cards every 5 s (off by default) |

The functions selectable inside each card (Up/Down, then press):

| Card | Functions |
|------|-----------|
| **LINK** / **SWITCH** | **Locate port** (blink the switch link LED) · **L2 health** capture (~12 s) |
| **IP** | **Ping gateway** (LAN) · **Ping internet** (`8.8.8.8`, WAN) · **DNS Doctor** (poison/hijack verdict) · **Speed test** |
| **DHCP** / **WIFI** / **SIGNAL** | read-only (no functions) |
| **SPECTRUM** | Up/Down selects the **band** (2.4 / 5 / 6 GHz) whose live channel-occupancy spectrum is drawn (scanned on the widest-band adapter — plug in the Alfa for 5/6 GHz); press does nothing (nothing to run) |
| **IFACE** | Up/Down highlights **Auto** or a NIC; press **pins the egress tests** (Speed test / pings) to it. Auto = built-in eth → USB eth → wlan1 → wlan0 |
| **BT** | **Scan BT** — press runs a ~8 s Bluetooth/BLE discovery sweep; the card then shows that result (with its age) until you scan again |
| **ZIGBEE** | **Scan Zigbee** — press runs a ~8 s 802.15.4 sniff on the HuginnESP; the card then shows that result (with its age) until you scan again |

In the **card-selection menu** any joystick direction moves the highlight and
press opens that card. The joystick arrows above are **as you read them on the
screen**: the HAT's joystick is physically mounted 90° clockwise of the panel's
text, so the listener remaps each push into the on-screen frame and re-aligns
automatically when the display is rotated.

Outside net-diag mode the joystick pages through the normal Ragnar screens and a
**joystick press starts/stops page autoscroll** (auto-cycle every 5 s); **KEY1**
toggles this diagnostic mode, **KEY2** rotates the screen, and **KEY3** is next
page (tap) or restart the service (hold).

> Applies to the e-Paper / LCD display. Headless installs (no display) accept
> the toggle but have nothing to render it on.

---

## 🩺 Diagnostics

Reachability, path and bandwidth testing to any target — plus application-layer
service-security checks (**NTP** time integrity, **SNMP** cleartext exposure, and
**TLS/certificate** hygiene).

### Ping
ICMP echo to a host or IP. Reports the raw output plus a parsed summary
(packets transmitted/received, loss %, and RTT min/avg/max). Count is
configurable (1–15). A 100 % loss result is still reported as a successful
*run* — the summary tells the story, so you can distinguish "tool failed" from
"host is down".

- Endpoint: `POST /api/net/ping` · binary: `ping` (`iputils-ping`)

### Traceroute
Hop-by-hop path to a target (numeric, one probe per hop, bounded wait), up to a
configurable max-hops (1–30). Useful for finding where along the path a
connection breaks or slows down.

- Endpoint: `POST /api/net/traceroute` · binary: `traceroute`

### MTR
A traceroute + ping hybrid that samples every hop over several cycles and
reports **per-hop loss and latency** — the fastest way to spot which single hop
on a path is dropping packets or adding jitter. Results are shown as a table
(Hop, Host, Loss %, Avg/Best/Worst ms, Jitter) with cells colour-coded by
severity.

On a multi-homed box you can pick the **start point** — a dropdown of this
host's local IPv4 addresses — to force the probes out of a specific
interface/path (`mtr -a`). The source is validated against the host's real
addresses before use.

- Endpoint: `POST /api/net/mtr` · binary: `mtr` (`mtr-tiny`)

### WHOIS
Registration/ownership lookup for a domain or IP.

- Endpoint: `POST /api/net/whois` · binary: `whois`

### DNS Doctor
Resolves a hostname through **every system resolver plus public 1.1.1.1 /
8.8.8.8**, and reports per resolver: the **answers**, **query latency**, the
**DNSSEC AD** (authenticated) flag, and status. Also reports **DoH** (443) and
**DoT** (853) reachability. Far more than a name→IP lookup: it's a
resolver-health and **DNS-poisoning / hijack detector**.

Alongside the per-resolver table it runs active poisoning probes and returns a
`poison` verdict — **clean**, **suspicious**, or **hijacked** — with the reasons:

- **NXDOMAIN rewriting** — queries a random name that *cannot* exist; a resolver
  that synthesizes an address for it is rewriting DNS (ISP redirect / typo /
  captive page). The public resolvers act as the control.
- **Private/bogon answer for a public name** — an RFC1918 / loopback / reserved
  address returned for a public hostname (redirect, blocklist sinkhole, portal).
- **SERVFAIL / DNSSEC-bogus** — a validating resolver refusing a name others
  resolve is the signature of a tampered (DNSSEC-bogus) record.
- **Resolver divergence** — the system/ISP resolver's answer shares nothing with
  the public resolvers' (split-DNS, or a hijack if unexpected). CDN/anycast
  variance is tolerated, so this is a *soft* signal.
- **DoH cross-check** — resolves the same name over Cloudflare DoH (encrypted,
  tamper-resistant) and compares to the plaintext answer; a mismatch is a strong
  sign of on-path :53 spoofing.
- **Known-answer anchors** — checks domains with a stable, published answer
  (`dns.google`→8.8.8.8); a resolver whose answer
  shares nothing with the documented set is drift/poisoning.
- **ASN-level consensus** — maps each resolver's answers to their origin ASN (via
  Team Cymru) and flags a system resolver answering in a *different ASN* than the
  public resolvers. Unlike the raw-IP "divergence" soft signal, this survives
  CDN/anycast (which share an ASN), so an ASN mismatch is a **strong** signal.
- **DNSSEC negative control** — `dnssec-failed.org` *must* SERVFAIL on a
  validating resolver; if it resolves, DNSSEC validation is broken here
  (downgrade/stripping) and the AD/SERVFAIL signals can't be trusted this cycle.
- **Transport race** — sends one query and briefly listens for a *second,
  conflicting* answer — the signature of an off-path spoofer racing the real
  resolver (Kaminsky cache-poisoning). Plain UDP; needs no elevated privileges.

Strong signals (NXDOMAIN rewrite, bogon answer, DoH mismatch, anchor mismatch,
ASN divergence, failed DNSSEC control, transport race) → **hijacked**; soft
signals (SERVFAIL, raw-IP divergence) → **suspicious**. The verdict is shown as a
banner in the web panel, is available on the e-Paper **KEY4-long** result page,
and drives the [Network Integrity Monitor](#-network-integrity-monitor).

- Endpoint: `POST /api/net/dns` `{name}` · binaries: `dig` (`dnsutils`), `curl`

### ARP Poisoning
Detects **ARP spoofing / MITM** from the kernel neighbour table (`ip neigh`) —
no packet capture needed. Two signals, returned as a **clean / suspicious /
spoofed** verdict:

- **Gateway MAC change** — the default gateway's IP→MAC binding is compared
  against a **trusted baseline**. An attacker who ARP-replies as the gateway to
  intercept traffic changes that MAC — the classic man-in-the-middle signature →
  **spoofed**. The first check *learns* the current gateway MAC as the baseline
  (`data/arp_baseline.json`); after a legitimate router swap, **Trust current
  gateway** re-learns it.
- **Subnet impersonation** — one MAC answering for many IPs (≥4) in the
  neighbour table, i.e. a host impersonating much of the segment → **suspicious**
  (the gateway's own MAC is excluded so a router fronting its address is fine).

An **interface selector** scopes the check to one segment — that interface's own
default gateway (a higher-metric uplink still counts) and only the neighbours on
it — which is the right lens on a **multi-homed** box; *Auto* uses the default
route and the full neighbour table. The result shows the verdict, the interface
checked, the current vs. trusted gateway MAC (highlighted on mismatch), the
neighbour count, any impersonator MACs and the reasons. This
is the *active* complement to the passive duplicate-IP check in
[L2 Link Health](#l2-link-health), and it feeds the
[Network Integrity Monitor](#-network-integrity-monitor).

This snapshot view is complemented by a **standalone live-stream monitor** —
[arp_guard](arp_guard.md) (`python/arp_guard.py`) — a four-layer packet pipeline
(binding-flap · gratuitous-ARP rate/breadth · per-packet structural sanity ·
out-of-band trusted-MAC pins) that catches the attack **in progress** (a raw-byte
parser, JSON-lines alerts, pcap `--replay`, and a hardened daemon), which a
neighbour-table snapshot can't see.

- Endpoints: `GET /api/net/arp-check`,
  `GET|POST /api/net/arp-baseline` `{action:reset}` · uses `ip neigh` (iproute2)

### MAC Watch
**Detection-only** MAC-spoofing + randomization monitor — it *never spoofs or
randomizes anything itself*. Passive: it reads the kernel neighbour table
(`ip neigh`) and, optionally, runs an `arp-scan` sweep to widen coverage. Three
jobs, rolled into one **clean / randomization / fhrp / suspicious / spoofed**
verdict:

1. **Spoofing / cloning** (current *and* past):
   - **Disguised vendor** — a registered vendor OUI wearing the
     locally-administered (LAA) bit. A real OUI can't legitimately carry that
     bit, so it's the classic MAC-spoof signature → **spoofed**. Detected by
     clearing the LAA bit and matching the underlying OUI against the vendor DB.
   - **Clone** — one MAC bound to several IPs at once (the gateway is excluded).
   - **Past spoofing** — an IP whose MAC *changed identity* over time. History
     is persisted (`data/mac_watch.json`), so identity flips survive restarts;
     a randomized↔randomized flip is treated as benign privacy rotation, not a
     spoof.
2. **Randomization** — privacy (LAA, vendor-less) MACs are reported as an
   **aggregate inventory** (count · short-lived/ephemeral · virtual/VM), not one
   finding per MAC, so a Wi-Fi segment full of iPhones doesn't bury a real
   spoof. Docker / QEMU / VirtualBox / Parallels ranges are bucketed separately.
3. **Tracking** — an IP that cycles through **≥2 randomized MACs** over time is
   one device rotating to hide; its addresses are grouped into a followable
   track so it can be traced across the MACs it hides behind.
4. **FHRP (HSRP/VRRP/GLBP) virtual-MAC awareness** — first-hop-redundancy
   protocols give several physical routers one shared *virtual* MAC that is
   legitimately shared and **moves between boxes on failover** — behaviour a
   naive identity monitor misreads as spoofing. MAC Watch recognizes the
   virtual-MAC formats (HSRP v1 `00:00:0c:07:ac:GG`, HSRP v2 `00:00:0c:9f:fX:XX`,
   VRRP `00:00:5e:00:01:VV`, VRRPv3/IPv6 `00:00:5e:00:02:VV`, GLBP `00:07:b4:…`)
   so the gateway's redundancy MAC is **inventoried (INFO), never flagged as a
   clone/spoof**. The inverse is the alarm: it learns which IPs are FHRP VIPs
   (any IP ever answered by a virtual MAC, plus declared `fhrp_declared_vips`)
   and raises **spoofed** if a VIP is suddenly answered by a *non-virtual* MAC —
   an ARP-spoof of the redundancy group. This is the identity-forensics side of
   the `arp_guard` / [FHRP Watch](#fhrp-watch) cross-pivot; reconcile its
   inventory against FHRP Watch findings.

Every MAC is classified as **Vendor** (universal/burned-in), **FHRP virtual**
(HSRP/VRRP/GLBP redundancy), **Spoofed**
(vendor OUI + LAA bit), **Randomized** (privacy), or **Virtual/VM**. Vendor
names come from the `arp-scan` / `nmap` OUI database
(`/usr/share/arp-scan/ieee-oui.txt`, ~35k prefixes) with a built-in seed
fallback; the table is filtered to universal prefixes only so an LAA range in a
full manuf file can't be mistaken for a real vendor. This host's own NIC MACs
are always excluded.

- **Interface selector** — *Auto (default route)* or a specific NIC
  (WiFi / LAN labelled). It targets the `arp-scan` sweep at that segment; the
  neighbour-table read is kernel-global. The result shows the exact **source**
  (`arp-scan sweep on wlan0` vs `neighbour table (all interfaces)`).
- **Scan** runs the sweep; **Quick** reads the neighbour table only (no traffic
  generated, works unprivileged); **Reset history** clears the store;
  **Export CSV** downloads every observed MAC (MAC · type · vendor · IPs · flag
  · note), the scanned interface in the filename.
- Results list all findings — spoofed, cloned, tracked devices, past MAC
  changes, the randomization inventory — plus a **full table of every MAC
  observed**, worst class first.

Cross-MAC tracking here is **IP-anchored and capture-free** — honest but
limited. True device tracking across a MAC *and* IP change needs 802.11
probe-request fingerprinting, which is monitor-mode only; MAC Watch labels its
tracking as the neighbour-table approximation.

- Endpoints: `GET /api/net/mac-watch` `?scan=0|1&interface=<if>`,
  `POST /api/net/mac-watch-reset` · store: `data/mac_watch.json` · uses
  `ip neigh` (iproute2) + optional `arp-scan`; OUI DB from `arp-scan`/`nmap`

### 🛡️ Network Integrity Monitor
The one **passive, alerting** tool in the suite (everything else is on-demand).
When enabled it runs a fast core every cycle (default **every 5 min**) — the
[DNS Doctor](#dns-doctor) poisoning check, the [ARP Poisoning](#arp-poisoning)
check, the [DHCP Guardian](#dhcp-guardian) rogue-server check, and the instant
[IPv6 RA Guard](#ipv6-ra-guard) posture read — derives an overall verdict
(**clean / suspicious / compromised**) and:

- Surfaces a live **dashboard chip** (Overall + every check) in the Diagnostics
  sub-tab, worst-first, with reasons and last-check time.
- Sends a **Pushover alert** when *any* check *worsens* into a bad state (on the
  transition, not every cycle, with a cooldown backstop). Active attacks
  (hijack / injection / poisoning / coercion / VLAN-hop / root-hijack …) page as
  **compromised**; posture/deviation findings (weak-auth, SMBv1, unsigned SMB,
  name-exposure …) as **suspicious**. An already-alerted condition is
  **remembered per check** (persisted in `data/net_integrity_alerts.json`, so
  service restarts and updates don't re-page standing findings) — a run that
  comes back quiet (`unknown` / `no-traffic`, or a DNS answer that momentarily
  agrees with public resolvers) does *not* re-arm the alert, so a finding the
  scanner only sees on some cycles pages once, not on every sighting. It
  re-alerts only if the check **escalates** (suspicious → compromised), if it
  stayed clean for a **full 24 h** and then returned, or — optionally — as a
  periodic reminder while it persists (`net_integrity_realert_hours`, default
  `0` = never remind).

**Extended monitoring** (on by default alongside the monitor) additionally
**rotates the whole passive-scanner suite** through the background poller —
STP · DTP · CDP · VTP · IGMP · IPv6 first-hop · NDP · FHRP · OSPF · EIGRP · IS-IS · BGP · SMB ·
Relay/Coercion · NTP · ICMP · SNMP · Cert · TLS · LDAP · Cisco/Juniper/Arista/Comware Guards.
The vendor switch/router guards (Cisco/Juniper/Arista/Comware) are **LAN-only** —
the rotation runs them only when a genuine wired uplink is up (over that wired
NIC, never `wlan0`), so a Wi-Fi-only unit never auto-runs them and Comware can't
falsely report VRF/MPLS findings off wlan. Each stays available on demand via
its **Scan** button regardless of link type.
Because each of those
does a short `tcpdump` capture, they're run a **round-robin batch at a time**
(default 3 per cycle, configurable) so a cycle stays ~1 minute; a full sweep
completes over several cycles, and each scanner self-noops cheaply when its
protocol isn't on the segment. The dashboard shows every scanner's last-known
verdict even on cycles it didn't run. Each scanner **learns its baseline on
first sight**, so run the monitor on a trusted network first (or use each
card's "Trust current").

**Capture interface.** The capture-based scanners (and the DHCP Guardian check)
listen on a **link-up wired port first** — the same auto used by the Switch &
L2/L3 cards. That matters for the sensor deployment: Ragnar plugged into a
switch port to watch it (mirror/SPAN or an isolated VLAN with no gateway) while
managed over WiFi. The default route sits on `wlan0`, but STP/DTP/CDP/VTP/FHRP
frames only exist on the cable — following the default route there would leave
the monitor blind on the exact segment it's meant to watch. Pin a specific
interface with the **capture on** selector (`net_integrity_interface`); with no
wired link it falls back to the default-route interface. The path-scoped checks
(DNS Doctor, RA-Guard posture) always test the host's actual traffic path, so
they're unaffected. The status line shows which interface the last cycle
captured on.

**Off by default**, because it makes outbound DNS/DoH calls each cycle — opt in
with the toggle. **Check now** runs the fast core immediately (works even while
the monitor is off); the extended scanners run on the background rotation.

- Endpoint: `GET /api/net/integrity` · config: `net_integrity_monitor_enabled`,
  `net_integrity_interval_min`, `net_integrity_check_dhcp`,
  `net_integrity_extended_enabled`, `net_integrity_batch_size`,
  `net_integrity_interface` (`''` = auto: wired link-up → default route),
  `pushover_notify_net_integrity`, `net_integrity_notify_cooldown_s`,
  `net_integrity_realert_hours`

### Path MTU / Black-hole
Discovers the **path MTU** to a target and flags an **MTU black hole** — a hop
that silently drops full-size packets, the classic "ping works but big
transfers / HTTPS / VPN hang" fault. A PMTU below 1500 points at tunnel
overhead (PPPoE/VPN) or a misconfigured hop. Measured with a `ping -M do`
(don't-fragment) binary search — no extra tool, and it won't stall on
unresponsive hops the way a full path trace can.

- Endpoint: `POST /api/net/pmtu` `{target}` · binary: `ping`

### Captive Portal Check
Detects hotel / guest-WiFi **HTTP interception** by probing the same
connectivity-check endpoints operating systems use (`generate_204`,
`captive.apple.com`). A wrong status, a redirect, or a login page instead of the
expected body means the network is hijacking HTTP.

- Endpoint: `GET /api/net/captive-portal` · binary: `curl`

### LAN Throughput (iperf3)
Measures **real throughput to another node on your network** — the test an
internet speed test can't do, and the right way to validate that a cable, port
or switch actually delivers its rated speed. Point it at any iperf3 server (up
or download, TCP or UDP with jitter/loss), and it reports Mbps plus TCP
**retransmits** (a retransmit count above zero on a LAN is a red flag for a
duplex mismatch or a bad cable). A **built-in server** toggle lets another
device throughput-test *against* this box — it shows the addresses to point the
other end at.

- Endpoints: `POST /api/net/iperf3` `{server,duration,reverse,udp}`,
  `POST /api/net/iperf3-server` `{action:start|stop}` · binary: `iperf3`

### Speed Test
Download/upload/latency bandwidth test. Supports both the Ookla `speedtest` CLI
and the Python `speedtest-cli`, reporting download/upload in Mbps, ping in ms,
and the chosen server and ISP. If neither client is present it self-installs
`speedtest-cli` on demand so the button always works.

**Interface selector.** `Auto (Ethernet first)` prefers a wired port, so a
multi-homed box tests the cable rather than whatever holds the default route.
When Auto lands on the default-route interface it runs **unbound** — the kernel's
normal path, identical to having no selector at all. It only binds when
deliberately leaving that path. The result line reports `via <iface>`.

**Pinning binds the device, not the address.** This distinction is the whole
ballgame on a box whose WiFi and LAN face the same router:

- `speedtest-cli --source <ip>` sets a source *address*. It does **not** force
  egress — the kernel still routes by destination, so the packet leaves via the
  default-route NIC carrying the *other* NIC's address. That is indistinguishable
  from spoofing, and an AP drops a frame whose source IP isn't that station's
  lease. Result: `Cannot retrieve speedtest configuration / urlopen error timed
  out`, on an interface that has perfectly good internet.
- `SO_BINDTODEVICE` binds the *device* and actually pins the traffic. Ragnar uses
  the Ookla client's `--interface` when that client is present, otherwise
  `python/speedtest_bind.py`, which patches the socket layer with
  `SO_BINDTODEVICE` and runs the same python client. (Needs `CAP_NET_RAW`.)

Don't identify the client by binary name: on Debian/Raspberry Pi OS
`/usr/bin/speedtest` is usually just an entry-point alias for the python
speedtest-cli and **rejects** `--interface`. Ragnar asks `--help` instead.

**Reachability is measured, not inferred.** Before a bound test, Ragnar
TCP-probes the internet with the socket bound to that device, so it never claims
an interface "has no route to the internet" when it demonstrably has one. A
default route is not proof (the gateway may not work), and source-binding proves
nothing at all — a probe bound to docker0's *address* reaches the internet fine,
because the packet simply leaves via WiFi. Picking an interface with no address,
or one the probe shows cannot reach the internet, fails fast with the real reason
instead of hanging for the timeout.

- Endpoint: `POST /api/net/speedtest` · binary: `speedtest-cli` or `speedtest`

### Live Flow Telemetry
Per-connection kernel stats from `ss -ti` for every established TCP flow: **RTT**,
**min-RTT**, **retransmits** and MSS. It's the dependency-free version of the
eBPF per-flow visibility the big shops run — an RTT far above a flow's min-RTT
means **bufferbloat/queuing**, and any **retransmits** mean loss. Flows are
ranked worst-first. (If `bpftrace` is installed it's reported as the engine;
otherwise the always-present `ss` path is used.)

- Endpoint: `GET /api/net/flows` · binary: `ss` (iproute2, always present)

### PTP Timing Detection
Detects **IEEE-1588 / PTPv2** on the segment — the precision-time protocol
behind AV-over-IP, financial trading and 5G fronthaul. Sniffs the PTP event/
general UDP ports and the 802.1AS ethertype and reports whether a grandmaster is
announcing, the message types, and the domain(s). This is a field "is PTP here?"
check; precise clock-offset measurement needs a running `ptp4l`. (Standardised
TWAMP/OWAMP SLA testing is a natural next step but needs a cooperating reflector
on the far end.)

- Endpoint: `POST /api/net/ptp` `{interface, seconds}` · binary: `tcpdump`

### IPv6 RA Guard
The **defence** half of IPv6 first-hop security. Where
[IPv6 First-Hop Watch](#ipv6-first-hop-watch) (Switch & L2/L3) **detects** a rogue
RA / DHCPv6 / ICMPv6-Redirect on the wire, RA Guard audits **this host's own IPv6
settings** so a rogue first-hop can't take effect even if it reaches you — and can
**harden** them in one click. It is active but sends **no packets**: it reads
`/proc/sys/net/ipv6/conf/*` and the routing table. It grades every IPv6 interface
(physical NICs first, container/VPN virtuals collapsed) on:

- **`accept_redirects`** — accepting an **ICMPv6 Redirect** lets any on-link host
  reroute your traffic (a Layer-3 MITM). A host should never accept them.
  → verdict **redirect-open**.
- **`accept_ra_rtr_pref`** — honouring the RA **Router-Preference** field lets a rogue
  **`pref high`** RA jump ahead of the real router. → verdict **ra-pref-open**.
- **`accept_ra`** — accepting RAs (SLAAC) at all. Normal, but only safe if the switch
  enforces RA-Guard. → verdict **ra-open** (advisory).
- Fully closed → **hardened**; IPv6 off on the interface → **ipv6-off**.

It also shows **which IPv6 default gateway the host has actually accepted** right now
(and whether it came from an RA). The **Harden** action sets the two safe sysctls —
`accept_redirects=0` and `accept_ra_rtr_pref=0` — for `all`/`default` and every IPv6
interface, applies them live, and persists them to
`/etc/sysctl.d/99-ragnar-raguard.conf` so they survive a reboot. **`accept_ra` is
deliberately left untouched** — turning it off would drop IPv6 connectivity on a
legitimate SLAAC network; that trade-off is surfaced as advice (pair with a switch
RA-Guard) rather than forced.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py raguard              # audit only
python3 network_diagnostics.py raguard --harden     # apply + persist safe sysctls
python3 network_diagnostics.py raguard-selftest     # self-test the grader, no root
```

`raguard-selftest` drives the grader with synthetic posture dicts
(hardened / redirect-open / ra-pref-open / ra-open / ipv6-off / all-scope override /
multi-interface roll-up) plus a read-only live leg that grades the real host.

- Endpoint: `GET /api/net/raguard` (check), `POST /api/net/raguard` `{action: harden}`

### NTP Watch
NTP (**UDP/123**) is the network's **clock of record**. It touches every layer, but
the attack surface is **Layer-7**: a rogue NTP server that answers clients — or
**broadcasts** — with the **wrong time** silently poisons every downstream
timestamp. Wrong time breaks **TLS / Kerberos validity windows**, invalidates
**MFA/TOTP** codes, corrupts **audit logs**, and — in a precision-critical shop
(medical lab, finance, industrial control) — falsifies **lab-result and
chain-of-custody records**, where a few seconds of skew is a real incident. Yet
almost nobody watches 123. This scanner is **passive and detection-only**: it never
sends an NTP query. One short `tcpdump` window over `udp port 123` (captured with a
per-packet Unix timestamp via `-tt`) is parsed and classified:

- **Time injection** — a source whose served **transmit timestamp** disagrees with
  the **segment consensus** (the median of all sources) — or, when only one source
  is seen, with the **local clock** — beyond a threshold (default **2 s**; honest
  sources agree to well under a second passively). This is the core attack: someone
  is serving a skewed clock. If *every* source agrees but all disagree with the
  local clock, that's flagged too (the host clock is wrong, or all sources shifted).
- **Rogue server** — an NTP server answering on the segment that **isn't in the
  learned baseline**. Clients may silently prefer it.
- **Kiss-o'-Death** — a **stratum-0** reply (RFC 5905 KoD, e.g. `RATE` / `DENY`). A
  rogue uses KoD to make clients **back off legitimate time sources** — a time-sync
  DoS that softens them up for a rogue server.
- **Stratum spoof** — a source claiming **Stratum 1** (primary / GPS reference) it
  shouldn't, or a known server **lowering its stratum** to win client preference.
- **Broadcast** — a **mode-Broadcast** time source: hosts in broadcast client mode
  accept it blindly, a classic injection vector on modern unicast networks.
- **Recon** — NTP **mode 6/7** (`ntpq` control / `monlist`) traffic: reconnaissance
  or amplification abuse.
- **Anomaly** — an implausible **root dispersion**, a **leap-alarm** (unsynchronized)
  source, or a **reference-ID loop** (refid equals the source's own address).
- **Autokey** — an **Autokey** (RFC 5906) **extension field** on the wire. Autokey is
  deprecated and is the network-reachable attack surface for **CVE-2014-9295** (the
  `ntpd` `crypto_recv()` stack-overflow → **RCE** as the ntpd user) and its siblings
  (CVE-2014-9750, CVE-2016-1547). The capture adds `-x`, so the NTP payload bytes are
  reconstructed and the extension field is parsed directly (independent of the
  dissector). Fires on **any** NTP packet — server replies *and* inbound client/peer
  packets — because the overflow is delivered *to* the victim. Ordinary symmetric-key
  authentication (a 4/20/24-octet MAC) is **not** Autokey and never trips it — the
  28-octet RFC 7822 extension-field floor separates the two.
- **Autokey exploit** — a **malformed** Autokey EF: the declared length or the
  internal **value length** (`crypto_recv()`'s copy length) runs **past the packet**,
  is **misaligned**, or is structurally impossible. That value-length overflow is the
  specific signature of **CVE-2014-9295 / CVE-2014-9750** and escalates to a
  **critical** verdict (ranked as such by the Network Integrity Monitor).

The **first scan learns** the trusted time source(s) + their stratum into
`data/ntp_watch.json`; after a legitimate NTP change, click **Trust current** to
re-learn. Every result carries a **mitigation advisory**: pin clients to known
servers (prefer authenticated **NTS** or symmetric keys), restrict UDP 123 to
expected hosts, and disable `monitor` (mode 6/7) on servers.

> Passive over a capture window, NTP Watch catches **gross time injection, rogue and
> broadcast sources, KoD, and stratum/mode abuse** — not sub-millisecond clock
> *discipline* accuracy (that needs an active, round-trip measurement). It answers
> "**is something on this segment serving the wrong time, or trying to?**"

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py ntp-watch [--iface eth0] [--seconds 15] [--json]
python3 network_diagnostics.py ntp-selftest    # self-test the detectors, no root
```

`ntp-selftest` drives the real parser + classifier with synthetic captures (clean /
time-injection / rogue-server / kod / stratum-spoof / broadcast / recon / anomaly /
parse), and — when [Scapy](https://scapy.net) is installed — crafts a real NTP
server reply into a pcap and parses it back through `tcpdump`, exercising the
capture→parse path end to end.

- Endpoint: `GET /api/net/ntp-watch` `{interface, seconds}`,
  `POST /api/net/ntp-baseline` `{action: reset}` · binary: `tcpdump`

### SNMP Watch
SNMP **v1 and v2c** authenticate with a plaintext **community string** — effectively
a device password carried in the clear on *every* request. Anyone passively sniffing
the segment harvests it: the **read** community (very often the default `public`)
exposes the full device config / MIB, and a **write** community — revealed the moment
a `SetRequest` crosses the wire — lets an attacker who captured it **reconfigure the
device**: change routes, ACLs, SNMP itself, or bounce interfaces. **v3** fixes this
with the User Security Model (authentication + privacy/encryption). This scanner is
**passive and detection-only**: one short `tcpdump` window over UDP **161/162**,
parsed and classified. It never sends an SNMP request. What it flags:

- **Write-exposed** — a `SetRequest` in v1/v2c: a **write community is on the wire**,
  i.e. sniff it and you own the device. The most severe finding.
- **Cleartext** — any v1/v2c traffic: the community string is exposed. Worse when
  it's a **well-known default** (`public`, `private`, `community`, `cisco`, …) —
  trivially guessable even without a sniffer. The community strings actually seen are
  listed so you know exactly what leaked.
- **Community reuse (blast radius)** — a cleartext community accepted by **2+
  agents**: sniff it once, gain that access on every one. Reported as a
  `community_reuse[]` block (community → the agents that accept it), **HIGH**, and
  **CRITICAL** if that community was ever seen writing (one capture = write access
  to N devices).
- **Amplification** — a `GetBulk` with a large **max-repetitions**: the SNMP
  reflection / amplification DDoS vector (a small request eliciting a huge response).
- **Enumeration** — one host issuing many `GetNext` / `GetBulk` requests: walking the
  MIB (SNMP reconnaissance).
- **Clean** — only **SNMPv3** (authenticated/encrypted), or no SNMP at all.

The parser reads tcpdump's SNMP decode, including its convention of **omitting
`C="…"` for the default `public` community** (so a v1/v2c message with no community
shown is correctly treated as `public`). The first scan learns the segment's SNMP
**agents + community strings** into `data/snmp_watch.json` so later scans can
highlight **new** exposure (a new insecure agent or a new community appearing);
**Trust current** re-learns. The verdict always reflects the cleartext reality —
v1/v2c is insecure regardless of baseline. Every result carries a **mitigation
advisory**: migrate to **SNMPv3 (authPriv, SHA + AES)**; if v1/v2c must remain,
confine SNMP to a management VLAN with ACLs, use unique non-default read-only
community strings, and disable SNMP on devices that don't need it.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py snmp-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py snmp-selftest    # self-test the detectors, no root
```

`snmp-selftest` drives the real parser + classifier with synthetic captures (clean /
cleartext / write-exposed / community-reuse / amplification / enumeration / parse),
and — when [Scapy](https://scapy.net) is installed — crafts real SNMP v2c Get/Set
messages into a pcap and parses them back through `tcpdump`, confirming the
`public`-hidden inference and write-community detection end to end.

For a **standalone deep monitor** — a pure-Python BER decoder with per-message
severity, **SNMPv3 msgFlags mode analysis** (noAuthNoPriv/authNoPriv/authPriv/
privNoAuth), **plaintext-scopedPDU detection** (catching v3 that claims privacy
but ships a plaintext PDU), an **OID-hint pass** (CISCO-CONFIG-COPY / usmUser /
ifAdminStatus / …), and the community-reuse correlator — see
[snmpwatch](snmpwatch.md) (`snmpwatch.py`).

- Endpoint: `GET /api/net/snmp-watch` `{interface, seconds}`,
  `POST /api/net/snmp-baseline` `{action: reset}` · binary: `tcpdump`

### Cert Watch
Internal networks are full of TLS services — router/switch admin UIs, NAS boxes,
hypervisors, printers, IoT — with certificates **nobody audits**: long expired,
self-signed, hostname-mismatched, or signed with weak crypto. Unlike the passive
scanners in this guide, a certificate checker is inherently **active** — it must
complete a TLS handshake to read the cert, and **TLS 1.3 encrypts the Certificate
message**, so passive sniffing can't read modern certs at all. It therefore lives in
the **Diagnostics** tab with the other active tools (ping / traceroute / speed test),
and runs in two phases:

- **Passive discovery** (optional, tick *Discover*) — one short `tcpdump` window over
  TLS **ClientHellos** to find the TLS servers active on the segment (server
  **IP:port + SNI**), so you don't have to type them. Best-effort; the SNI is still in
  the clear in the ClientHello even under TLS 1.3. Needs Scapy's TLS layer for SNI,
  else falls back to server IP:port.
- **Active grading** — connect to each target (typed as `host` / `host:port`, and/or
  discovered), fetch the presented certificate **even when it fails validation** (an
  unverified fallback fetch), and grade it. Chain trust is checked against the system
  CA store; hostname matching (wildcard-aware, SAN then CN) is done independently so
  *why* a cert is bad is unambiguous.

Per-target verdicts, worst first: **expired** · **not-yet-valid** · **self-signed** ·
**untrusted** (chain doesn't build to a trusted CA — private CA or missing
intermediate) · **hostname-mismatch** · **weak-crypto** (SHA-1/MD5 signature,
RSA < 2048, or a weak/anon/NULL/RC4/DES cipher) · **deprecated-tls** (SSLv3 / TLS 1.0 /
TLS 1.1 negotiated) · **expiring** (valid but < 21 days left) · **valid**. Each result
carries the subject / issuer / SAN, validity dates + days-remaining, key type + size,
signature algorithm, and the negotiated protocol + cipher. A learned **fingerprint
baseline** (`data/cert_watch.json`, per `host:port`) flags a certificate that
**changed** between scans — a rotation, or a possible **MITM** — and *Trust current*
re-learns. Targets are always explicit (typed, or discovered on your own segment), and
runs are capped — this is device-hygiene auditing of your own network, not a scanner.

Uses Python's `ssl` + the `cryptography` library (no external binary for grading;
`tcpdump` is only needed for the optional discovery phase). Every result carries a
**mitigation advisory**: re-issue from a trusted internal CA (or ACME/Let's Encrypt
for internet-facing services), put every hostname/IP in the SAN, use RSA ≥ 2048 or
ECDSA P-256 with SHA-256+, disable TLS 1.0/1.1, and automate renewal.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py cert-watch router.local 192.168.1.1:443 nas:5001
python3 network_diagnostics.py cert-watch --discover --iface eth0    # find + grade
python3 network_diagnostics.py tls-selftest    # self-test the grader, no root
```

`tls-selftest` drives the real classifier with synthetic certs built by
`cryptography` (valid / expired / not-yet-valid / self-signed / untrusted /
hostname-mismatch / weak-crypto / deprecated-tls / expiring / wildcard-match), then
runs an **end-to-end** leg that starts a local TLS server with a self-signed cert and
grades it through the real handshake path — no root, no network.

- Endpoint: `POST /api/net/cert-watch` `{targets, discover, interface, seconds}`,
  `POST /api/net/cert-baseline` `{action: reset}` · Python: `cryptography` ·
  binary: `tcpdump` (discovery only)

## 🔌 Switch & L2/L3

Layer-2 discovery: what switch you're plugged into, and what else is on the
segment.

### Switch Discovery (LLDP / CDPv1/v2 / EDP / FDP)
Discovers the **neighbouring switch** by listening to its link-layer discovery
announcements. Ragnar runs `lldpd` configured with `-c -e -f -s`, so in addition
to standard **LLDP** it decodes:

| Flag | Protocol | Vendor |
|------|----------|--------|
| `-c` | CDPv1 / CDPv2 | Cisco |
| `-e` | EDP | Extreme |
| `-f` | FDP | Foundry / Brocade |
| `-s` | SONMP | Nortel / Avaya |

For each local interface it shows the discovered switch **name**, the
**protocol** it was learned via, the switch **port** you're connected to, the
**VLAN** id/name, **PoE** state, and the switch's **management IP**.

Switches announce roughly every 30 seconds, so after plugging in give it up to
a minute for the first neighbour to appear. Results export to CSV.

**Interface selector.** The same Auto/WiFi/LAN dropdown as the other Switch
L2/L3 cards. **Auto (all interfaces)** reports every neighbour this box can
hear; picking one local port limits discovery to it — on a multi-homed Ragnar
(LAN cable + USB NIC + WiFi) that is the difference between *"which switch is
**this** port plugged into"* and a merged list you have to eyeball. Filtering is
done by `lldpctl` itself, and an unknown interface name is rejected rather than
returning an empty list that looks like "no switch found". When a chosen port
has no neighbours, the note says so and suggests switching back to Auto.

- Endpoint: `GET /api/net/lldp` · optional `?interface=<name>` · binary:
  `lldpctl` (`lldpd`)

#### PoE detection
A PoE-capable switch advertises its power state in the LLDP/LLDP-MED
**Power-via-MDI TLV**, which `lldpd` decodes. Ragnar parses this into a **PoE**
column showing:

- **Device type** — PSE (the switch is sourcing power) or PD
- Whether power is **enabled / being delivered** (a green ⚡ marks a port that's
  actively powered)
- **Type** — the PoE standard: **af** (802.3af, ≤15.4 W), **at** (802.3at /
  PoE+, ≤30 W) or **bt** (802.3bt / PoE++, classes 5–8). Derived from the
  power-type field and the advertised class.
- **Mode** — **active**. An LLDP power TLV means the PSE does standards-based
  802.3 detection/classification, i.e. active PoE. Passive PoE injectors put
  voltage on the wire with no negotiation and advertise nothing, so they can't
  be confirmed from the powered device over LLDP — the tool only ever affirms
  *active*, it never falsely claims *passive*.
- **Delivery** — **endspan** (power comes from the switch itself) vs **midspan**
  (a separate power injector between switch and device). Inferred from which
  pairs carry power — data pairs / Alternative A ⇒ endspan, spare pairs /
  Alternative B ⇒ midspan. Best-effort: 802.3at/bt drive all four pairs, so
  treat this as indicative rather than definitive.
- **Power class** (e.g. class 3) and **allocated / requested wattage**

> **Note:** this reflects PoE *as advertised by the switch over LLDP*. An
> unmanaged/passive PoE injector, or a switch with LLDP-MED power TLVs turned
> off, won't advertise it — so a blank PoE column means "not advertised", not a
> guaranteed "no power".

### ARP Scan
Sweeps the local segment with ARP to enumerate **live hosts**, returning IP,
MAC and (where known) NIC vendor for each responder. The fastest way to
inventory a subnet you're attached to. An **interface selector**
(Auto / WiFi / LAN) targets the sweep at a chosen segment — Auto prefers a
link-up wired port, falling back to the default-route interface. Results
export to CSV.

- Endpoint: `GET /api/net/arp-scan[?interface=<iface>]` · binary: `arp-scan`

> This is an **inventory** sweep, not a security check. For ARP **spoofing /
> poisoning** detection (gateway-MAC watch + subnet impersonation), see
> [ARP Poisoning](#arp-poisoning) in the Diagnostics sub-tab.

### DHCP Guardian
**DHCP-snooping-style** monitor — the DHCP layer is the one L2 service the suite
hadn't covered, and arguably the highest-value one after DNS: whoever answers
DHCP hands you your gateway and DNS, so a rogue DHCP server is a turnkey
man-in-the-middle. **Detection-only** — it never runs a DHCP server or hands out
leases. Two signals, rolled into a **clean / rogue / starvation** verdict:

- **Rogue / fake DHCP server** — an active `broadcast-dhcp-discover` provokes
  *every* DHCP server on the segment to OFFER. More than one distinct server, a
  server that isn't the **trusted baseline**, or one offering a gateway/DNS that
  differs from the one you're actually using → **rogue** (DHCP steering). The
  first scan *learns* the current single server as trusted
  (`data/dhcp_baseline.json`); after a legitimate DHCP/router change, **Trust
  current server** re-learns it. The offered gateway is cross-checked against the
  [ARP Poisoning](#arp-poisoning) baseline, so a DHCP steer backed by ARP
  spoofing reads as one **combined DHCP+ARP MITM** finding.
- **DHCP starvation** — a short passive `tcpdump` capture counts client
  DISCOVER/REQUEST messages and the **distinct client hardware addresses**
  (chaddr) behind them; a burst of many distinct chaddrs in a few seconds is the
  pool-exhaustion signature (the classic precursor that clears the field for a
  rogue server) → **starvation**.

The result shows the verdict, every DHCP server that answered (server-id,
offered gateway/DNS, lease, and a trusted / new / rogue badge), the starvation
capture stats, and the gateway's ARP verdict. An **interface selector**
(Auto / WiFi / LAN) targets the scan at a chosen segment. It feeds the
[Network Integrity Monitor](#-network-integrity-monitor) (rogue-server check
only, so the background cycle stays fast) and adds a **DHCP page** to the
[On-Screen Network Diagnostic Mode](#-on-screen-network-diagnostic-mode).

- Endpoints: `GET /api/net/dhcp-guardian` `?interface=<if>&seconds=<n>&quick=0|1`,
  `GET|POST /api/net/dhcp-baseline` `{action:reset}` · store:
  `data/dhcp_baseline.json` · binaries: `nmap`
  (broadcast-dhcp-discover) + `tcpdump`

### DHCP Snooping (inline)
The **enterprise-grade** version of [DHCP Guardian](#dhcp-guardian), for when the
Pi has **two NICs bridged inline** (it sits between the client segment and the
uplink, so every DHCP packet transits it). This is the managed-switch *DHCP
snooping* model, and it's strictly stronger than active probing — **detection
only** (it never drops or rewrites a frame; inline blocking is a deliberate
future opt-in).

- **Trusted vs. untrusted ports** — you mark the uplink NIC (toward the real
  DHCP server) *trusted* and the client NIC *untrusted*. A DHCP **server**
  message (OFFER/ACK/NAK) that ingresses the **untrusted** port is a rogue
  server *by definition* — zero false positives, no baseline needed. Ingress
  port is read from `tcpdump -i any -Q in` (LINUX_SLL2 tags each frame with its
  interface).
- **Binding table** — every OFFER/ACK records **client-MAC ↔ assigned-IP ↔
  server ↔ lease ↔ ingress-port**, the same table a switch keeps, and the basis
  for spotting IP spoofing / feeding dynamic ARP inspection later.
- **Starvation** — distinct client hardware addresses (chaddr) flooding
  DISCOVERs are counted straight off the wire.

Bring your own bridge or SPAN/mirror port, or use the **guarded setup helper**
to enslave two wired NICs into `rgsnoop0` — it refuses the management /
default-route / wireless interface so it can't cut its own link. verdict:
**clean / rogue / starvation**.

> **Needs the inline hardware.** With no bridge the box only sees broadcast
> DISCOVERs (unicast OFFERs won't transit), so `status` reports *not inline yet*
> until two NICs share a bridge. This is the natural home for a 2-Ethernet
> (OTG-hub) build; pair it with the hardware watchdog the installer enables.

- Endpoints: `GET /api/net/dhcp-snoop` `?trusted=<if>&untrusted=<if>&seconds=<n>`,
  `GET /api/net/dhcp-snoop/status`, `GET|POST /api/net/dhcp-snoop/config`
  `{trusted,untrusted}`, `POST /api/net/dhcp-snoop/setup`
  `{action:create|destroy,iface_a,iface_b}` · store: `data/dhcp_snoop.json` ·
  binaries: `tcpdump`, `ip`

### L2 Link Health
Listens **passively** on an interface for a few seconds (`tcpdump`) and reports
what's wrong at Layer 2 — no configuration, just plug in and scan:

- **STP** — root bridge(s) seen and topology-change churn. Multiple roots or a
  flood of TCNs is the fingerprint of a **loop** or merged/segmented domains.
- **CDP / LLDP / DTP / VTP** control frames present (DTP = the port may
  auto-negotiate a trunk).
- **Broadcast / multicast rate** — a high rate flags a **broadcast storm**.
- **Rogue DHCP** — more than one DHCP server answering on the segment.
- **Rogue IPv6 RA** — more than one Router Advertisement source.
- **Duplicate IP** — the same IP claimed by different MACs (conflicting ARP).

Findings are ranked (warn / info / ok). This is the one-tap "why is this
segment misbehaving" check that normally needs a laptop and Wireshark. An
**interface selector** (Auto / WiFi / LAN) targets the capture at a chosen
segment — Auto prefers a link-up wired port, falling back to the default-route
interface.

- Endpoint: `POST /api/net/l2-health` `{interface?, seconds}` · binary: `tcpdump`

### IGMP Watch
A **passive** IGMP-snooping security scanner for the IPv4 multicast control
plane — **detection-only**: it never joins a group, sends a query, or becomes a
querier. One short `tcpdump` window is parsed and classified into four things:

- **Storm / flood** — an IGMP report/query rate far above normal (IGMP is
  intrinsically low-volume), or a single source flooding reports. This is a real
  multicast DoS and a switch-CPU exhaustion vector.
- **Anomaly** — more than one **querier** on the segment. There must be exactly
  one; a second, lower-IP querier is the classic *"become the querier to draw
  all multicast to yourself"* attack. Also flags mixed query versions
  (a v3→v2/v1 downgrade), a **spoofed querier** (a query sourced from 0.0.0.0), a
  message that arrived with an **IP TTL other than 1** (IGMP is link-local — a
  higher TTL means off-link injection / a spoofed source), a report/leave for a
  **non-multicast** (outside 224.0.0.0/4) address, a **membership report for a
  reserved group** (224.0.0.1 all-hosts / .2 all-routers — never joined via
  IGMP), and a **join/leave flap** (a host toggling a group, thrashing the
  snooping table). A per-source **leave flood** is flagged as a storm.
- **Reconnaissance** — one host joining a wide spread of **distinct groups** —
  multicast stream enumeration.
- **Unauthorized join** — a host on an **admin-scoped** (239/8), **globally-scoped**
  or **SSM** (232/8) group it has never been seen on, measured against a learned
  baseline. Link-local control groups (224.0.0.0/24) and normal service discovery
  (mDNS, SSDP) are recognised and not flagged.

Following the passive-floor doctrine (see [MAC Watch](#mac-watch) /
[L2 Link Health](#l2-link-health)), thresholds sit above ordinary chatter so a
healthy segment reads clean. The **first scan learns** the current querier(s) and
host→group memberships as the trusted baseline (`data/igmp_watch.json`); after a
legitimate multicast/router change, click **Trust current** to re-learn. Comfortable
on a Pi Zero 2 W even off a busy SPAN, since IGMP is low-rate control traffic.

There is also a small **CLI** (no web app needed):

```
python3 network_diagnostics.py igmp-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py igmp-selftest     # self-test the detectors, no root
```

`igmp-selftest` drives the real parser + classifier with synthetic captures
(clean / storm / rogue-querier / recon / unauthorized / spoofed-querier /
bad-TTL / non-multicast / reserved-group / join-leave-flap / leave-storm / v3
group-record parse), and — when [Scapy](https://scapy.net) is installed —
additionally crafts real IGMP packets into a pcap and parses them back through
`tcpdump`, exercising the capture→parse path end to end.

For a **standalone deep monitor** — a pure-Python binary IGMP decoder with the
full control-plane detector matrix (flood / anomaly / recon / policy), a
data-plane sysfs rate sampler (`mcast_flood_no_members` and friends), an
out-of-band SNMP tier with a capability cache, learn→enforce policy, SQLite, and
a hardened daemon — see [igmpwatch](igmpwatch.md) (`python3 -m igmpwatch`).

- Endpoint: `GET /api/net/igmp-watch` `{interface, seconds}`,
  `POST /api/net/igmp-baseline` `{action: reset}` · binary: `tcpdump`

### TLS Watch
A **passive** TLS/QUIC handshake observer — the session/presentation-layer
(OSI L5/L6) detector, companion to the active [Cert Watch](#cert-watch). It is
**detection-only**: it never connects or probes, it sniffs handshakes off the
wire. One short `tcpdump` window over the TLS ports (443/8443/993/995/465/990/
4433) and QUIC (UDP/443) is dissected and, per handshake, yields:

- **Fingerprints** — **JA4** and **JA4_r** (raw) client fingerprints to the FoxIO
  specification, plus legacy **JA3 / JA3S**. Match a client JA4 against a denylist
  of known-bad families.
- **Identity / negotiation** — SNI, ALPN, offered vs. negotiated TLS version,
  chosen cipher, ECH presence.
- **SWEET32 / `CVE-2016-2183` *(new in v3)*** — when the server negotiates a 64-bit
  block cipher (DES/3DES), the ServerHello carries that suite in cleartext, so it is
  named as **`cve_2016_2183_negotiated`** (high, *exposure* class — the vulnerable
  condition is observed directly, not inferred from a version banner). A client that
  merely *offers* 3DES is recorded as **`cve_2016_2183_client_offer`** (info,
  *posture*) — near-universal for years and harmless unless a server takes the offer.
  RC2/IDEA 64-bit suites share the birthday-bound weakness but fall outside the CVE's
  named DES/3DES scope, so they get a distinct **`weak_block_cipher_64bit`** (warn)
  that keeps the CVE's coverage claim exact. NVD/CISA-ADP score the CVE 7.5 HIGH.
- **Certificate posture (TLS 1.2 over TCP only)** — subject/issuer, SANs, validity
  window, self-issued flag, signature hash, and findings: `cert_expired`,
  `cert_not_yet_valid`, `cert_self_signed`, `cert_short_chain`, `cert_weak_sig`,
  and **`sni_cert_mismatch`** — SNI not covered by the presented certificate, the
  passive **interception** signal.

**The one hard constraint:** the Certificate message is passively observable
**only for TLS 1.2 over TCP**. TLS 1.3 encrypts it under the handshake secret and
QUIC is always 1.3, so on modern traffic you get fingerprints, SNI, ALPN and
version/cipher, but the certificate is a black box. This is a property of the
protocols, not the tool; every `cert_*` finding is scoped to TLS 1.2 by
construction.

**QUIC** Initial packets are recovered passively — the Initial keys derive from
the client's Destination Connection ID plus a public constant salt (RFC 9001
§5.2 for v1, RFC 9369 for v2), so it is arithmetic over captured bytes, never an
active operation. The client Initial's CRYPTO stream is reassembled into the
ClientHello and fingerprinted with proto `q`.

The verdict escalates to **compromised** on an `sni_cert_mismatch` or JA4 denylist
hit, **suspicious** on any other high/warn finding (weak cipher, expired cert,
legacy version), else **clean**. Needs a SPAN/mirror port to see other hosts on a
switched segment.

**Deduplicated results.** A browser routinely opens several parallel connections
to the same host, and a QUIC client may retransmit its Initial — all with an
identical fingerprint. These are collapsed into **one result** keyed on the
client identity (proto · client IP · server IP:port · JA4 · SNI), carrying a
`count` of how many connections merged (shown as `×N` in the table). QUIC
retransmits are deduped at parse time (one session per connection); the
representative is upgraded to whichever duplicate actually observed the server,
so a completed handshake is never masked by an aborted one.

**JA4S** (the server fingerprint) is licensed under the **FoxIO License 1.1**, not
the BSD/MIT that covers the rest, so it lives in a separate, clearly identified
file (`ja4s.py`) and is **off by default** — Ragnar never computes it unless the
operator sets both `tls_watch.ENABLE_JA4S` and `tls_watch.ACKNOWLEDGE_JA4S_LICENSE`.

There is also a small **CLI**:

```
python3 network_diagnostics.py tls-watch [--iface eth0] [--seconds 12] [--no-quic] [--json]
python3 network_diagnostics.py tls-selftest      # self-test the detectors, no root
python3 tls_watch.py --selftest                  # the module's own KAT harness
```

`tls-selftest` pins the fingerprint math to FoxIO's published JA4 vector
(`t13d1516h2_8daaf6152771_e5627efa2ab1`), JA3S to `771,49200,`, the QUIC key
schedule to RFC 9001 (v1) and RFC 9369 (v2), and — with [Scapy](https://scapy.net)
installed — crafts a TLS-1.2 SNI-mismatch session and a QUIC Initial into a pcap
and classifies them end to end.

- Endpoint: `GET /api/net/tls-watch` `{interface, seconds, no_quic}` · Python:
  `scapy` (dissection), `cryptography` (X.509 + QUIC AEAD) · binary: `tcpdump`

### IPv6 First-Hop Watch
The **most-overlooked LAN attack today**, and a genuine gap in most toolkits. Every
modern OS ships with **IPv6 enabled and _preferred_** over IPv4 — even on networks
where "nobody deploys IPv6" and nobody's watching it. So an attacker who broadcasts
a rogue **Router Advertisement** (ICMPv6 type 134) or stands up a rogue **DHCPv6**
server silently becomes the segment's **default gateway and/or DNS** — the classic
**SLAAC attack** and **mitm6** — while a tech staring at IPv4 / ARP / DHCP sees
nothing wrong. This scanner is **passive and detection-only**: it never sends an RA,
never answers a solicit, never touches routing. One short `tcpdump` window over
ICMPv6 RA/RS/Redirect + DHCPv6 (udp 546/547) is parsed and classified:

- **Rogue RA** — a Router Advertisement from a router **not in the learned baseline**
  (a new default gateway), a **second, conflicting** router, an RA that **injects a
  DNS server** (RDNSS option) or a new prefix, an RA with **`pref high`** (an
  attacker biasing host router-selection), or **router-lifetime 0** (an RA that
  *deprecates* the real router — the RA "kill" / DoS trick).
- **Rogue DHCPv6** — a DHCPv6 **ADVERTISE / REPLY / RECONFIGURE** from a server not
  in the baseline. This is **mitm6's signature**: it answers DHCPv6 solicits handing
  out the attacker as **DNS** (no gateway — it pairs with WPAD) to relay and
  NTLM-capture.
- **Rogue redirect** — an **ICMPv6 Redirect** (type 137) from a source that isn't a
  known router: the IPv6 twin of the ICMP-redirect MITM, steering your IPv6 traffic
  through an attacker's next-hop. (Harden the host against these with
  [IPv6 RA Guard](#ipv6-ra-guard).)
- **Storm** — a Router Advertisement **flood** (e.g. THC `fake_router6`), by rate.
- **Anomaly** — first-hop IPv6 seen where the baseline expected none, or a
  managed/other-flag change that alters how hosts get addresses.

The **first scan learns** the trusted router(s) + DHCPv6 server(s) into
`data/ipv6_watch.json`; after a legitimate IPv6 change, click **Trust current** to
re-learn. Because RAs are intrinsically rare, a healthy segment reads clean. Every
result carries a **mitigation advisory**: enable switch **RA-Guard** (RFC 6105) and
DHCPv6 snooping on access ports; if IPv6 is genuinely unused, filter ICMPv6 RA /
DHCPv6 or disable IPv6 on hosts to remove the vector entirely.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py ipv6-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py ipv6-selftest    # self-test the detectors, no root
```

`ipv6-selftest` drives the real parser + classifier with synthetic captures
(clean / rogue-ra / rogue-dhcpv6 / storm / anomaly / multi-line RA parse), and —
when [Scapy](https://scapy.net) is installed — crafts a real Router Advertisement
(with prefix + RDNSS options) into a pcap and parses it back through `tcpdump`,
exercising the capture→parse path end to end.

- Endpoint: `GET /api/net/ipv6-watch` `{interface, seconds}`,
  `POST /api/net/ipv6-baseline` `{action: reset}` · binary: `tcpdump`

### NDP Watch
The **IPv6 twin of [ARP Watch](#arp-poisoning--mitm-detection)**, and the missing half
of a capability most toolkits only ship for IPv4. ARP Watch catches IPv4 cache
poisoning; [IPv6 First-Hop Watch](#ipv6-first-hop-watch) catches rogue RA / DHCPv6
(mitm6) — but **neither catches the direct IPv6 analogue of ARP poisoning**: a forged
**Neighbor Advertisement** (ICMPv6 type 136) that claims someone else's address,
poisons every neighbour's **ND cache**, and puts an attacker **on-path** (THC
`parasite6`). On any dual-stack LAN — i.e. almost every LAN — that's an open door a
v4-only defender never sees. This scanner is **passive and detection-only**: it never
sends an NA and never answers a solicit. One short `tcpdump` window over ICMPv6
Neighbor Solicitation / Advertisement (135/136, captured with Ethernet source MACs)
is parsed and classified:

- **Spoofed** — two or more **different MACs claim one target IPv6 address**
  (`parasite6`); the **default router** advertised by a MAC other than the trusted
  one (**NDP router poisoning** / IPv6 MITM); or a **learned host's owner-MAC
  changing** (ND cache takeover). The binding a spoofer forges is the NA's *target
  link-layer address* option — the watch reads that, not just the Ethernet source.
- **dad-dos** — one MAC answering the **Duplicate Address Detection** probe (NA) for
  many addresses it doesn't own: THC **`dos-new-ip6`**, which defends *every* claim so
  no host on the segment can pick an IPv6 address — a SLAAC **denial of service**.
- **Storm** — a Neighbor Advertisement **flood** (e.g. `flood_advertise6`), by rate.

The **first scan learns** the trusted target→MAC bindings and seeds the **default
router** binding from the kernel neighbour table into `data/ndp_watch.json`; after a
legitimate device/router change, click **Trust current** to re-learn. Every result
carries a **mitigation advisory**: enable switch **IPv6 Snooping / ND Inspection**
(the RA-Guard family, RFC 6620 **SAVI**) on access ports; if IPv6 is genuinely unused,
disable it on hosts to remove the neighbour-cache attack surface entirely.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py ndp-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py ndp-selftest     # self-test the detectors, no root
```

`ndp-selftest` drives the real parser + classifier with synthetic captures (clean /
spoofed-conflict / router-poison / binding-changed / dad-dos / storm, plus NA and DAD
parse checks), and — when [Scapy](https://scapy.net) is installed — crafts a real
Neighbor Advertisement (with the target link-layer address option) into a pcap and
parses it back through `tcpdump -e`, exercising the capture→parse path end to end.

For a **standalone continuous daemon** — the IPv6 counterpart to
[arp_guard](arp_guard.md), with a raw-byte ND parser, **20 coded findings**
(`NDP-001…020`: NA cache-poison/flap, rogue-RA, prefix/RDNSS hijack,
router-preference, RA/RS/NS floods, DAD-DoS, spoofed Redirect, hop-limit-≠-255,
…) merged per packet, JSON-lines, and pcap `--replay` — see
[ndpwatch](ndpwatch.md) (`python/ndpwatch.py`).

- Endpoint: `GET /api/net/ndp-watch` `{interface, seconds}`,
  `POST /api/net/ndp-baseline` `{action: reset}` · binary: `tcpdump`

### ICMP Watch
The **ICMP Redirect** (type 5) is the classic **Layer-3 man-in-the-middle**. Any
host on the segment can forge a Redirect that appears to come from the real gateway
and tell a victim *"for destination X, use next-hop Y instead"* — steering that
traffic **through the attacker**. It needs **no ARP poisoning and no gateway
compromise**, and historically most hosts honoured redirects by default, so it's an
easy, quiet insertion. Related L3 ICMP abuses ride the same wire. This scanner is
**passive and detection-only**: one short `tcpdump` window over IPv4 `icmp`, parsed
and classified against the host's **authoritative default gateway** (never learned
from redirect sources — those could be the attacker). It never sends an ICMP packet.
What it flags:

- **Redirect** — an ICMP Redirect steering traffic to a **next-hop that isn't a
  known gateway** (attacker insertion), or **from a source that isn't the gateway**
  (spoofed). The headline MITM. On a modern switched network redirects are rare
  enough that even a "benign-looking" one (gateway → another known router) is
  surfaced as an **anomaly** to verify.
- **Rogue IRDP** — an ICMP **Router Advertisement** (type 9) from a non-gateway
  host: the ICMP Router Discovery Protocol gateway-injection MITM (IRDP is
  effectively obsolete, so any type-9 from a non-router is suspect).
- **Flood** — an ICMP storm (**ping-flood / smurf**, or a redirect flood) by rate.
- **Tunnel** — ICMP **echo** packets with **oversized payloads** (normal ping is
  ~64 B): the ICMP-tunnelling / data-exfiltration covert-channel tell.
- **Recon** — ICMP **timestamp / address-mask / information** requests that
  enumerate hosts and leak facts.

The host's default gateway is **always trusted**, plus any gateway learned into
`data/icmp_watch.json` on the first scan; after a legitimate router change click
**Trust current** to re-seed. Every result carries a **mitigation advisory**:
ignore redirects on hosts (`net.ipv4.conf.all.accept_redirects=0`) and stop sending
them on the gateway (`send_redirects=0`), disable IRDP, and rate-limit / filter the
recon ICMP types at the edge. **ICMPv6 Redirects (type 137)** are covered separately
by [IPv6 First-Hop Watch](#ipv6-first-hop-watch).

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py icmp-watch [--iface eth0] [--seconds 12] [--json]
python3 network_diagnostics.py icmp-selftest    # self-test the detectors, no root
```

`icmp-selftest` drives the real parser + classifier with synthetic captures (clean /
redirect / rogue-irdp / flood / tunnel / recon / anomaly / redirect parse), and —
when [Scapy](https://scapy.net) is installed — crafts a real ICMP Redirect into a
pcap and parses it back through `tcpdump`, exercising the capture→parse path end to
end.

- Endpoint: `GET /api/net/icmp-watch` `{interface, seconds}`,
  `POST /api/net/icmp-baseline` `{action: reset}` · binary: `tcpdump`

### STP/BPDU Watch
A **passive** spanning-tree security scanner covering **802.1D STP / 802.1w RSTP /
802.1s MSTP** (IEEE group MAC `01:80:c2:00:00:00`) and **Cisco PVST+ / Rapid-PVST+**
(per-VLAN, group MAC `01:00:0c:cc:cc:cd`). **Detection-only** — it never sends a BPDU.

Spanning tree prevents L2 loops by electing a **root bridge** (the switch with the
numerically lowest Bridge ID = priority + MAC) and blocking redundant paths back
toward it. BPDUs carry the election and are multicast in the clear with **no
authentication**, so an attacker who injects a BPDU claiming a **superior root**
(priority 0 — the Yersinia "claim root role" move) wins the election, becomes the
root bridge, and the tree reconverges to pull traffic through them (subnet-wide L2
MITM). BPDU/TCN floods force constant reconvergence (DoS) and MAC-table flushing
(which turns the switch into a hub — an aid to sniffing). What it flags:

- **root-hijack** — a BPDU advertising a root **superior** to the baseline root
  (lower priority, or equal priority + lower MAC): a root-bridge takeover. This is
  the top finding — an active L2 MITM.
- **rogue-bridge** — a new bridge (Bridge-ID MAC) participating in spanning tree that
  isn't in the baseline (an unexpected switch, or a spoofed bridge).
- **bpdu-flood** — an elevated BPDU rate: a reconvergence-storm DoS.
- **topology-change** — TCN / TC-flag churn: repeated topology changes flushing the
  MAC tables (instability, or a TCN-flood attack).

The BPF is `(ether dst 01:80:c2:00:00:00) or (ether dst 01:00:0c:cc:cc:cd)`, captured
with `tcpdump -e` for the sender MAC. For PVST+ the per-VLAN root is carried in the
Bridge-ID's extended system-id, so the scanner tracks a root **per VLAN/instance**.
The first scan **learns** the current root(s) and legitimate bridges as the baseline
(`data/stp_watch.json`); after a legitimate topology change, click "Trust current".
The real hardening — which this tool exists to nudge you toward — is **BPDU Guard**
(+ PortFast) on edge/access ports and **Root Guard** on ports toward downstream
switches, plus pinning your real root/backup-root to priority 0/4096. **API:**
`GET /api/net/stp-watch`, `POST /api/net/stp-baseline`. **CLI:** `stp-watch`,
`stp-selftest`.

### SMB Watch
A **passive** Windows-endpoint attack-surface scanner in three parts (one capture),
**detection-only**. Parts 1–2 target the two most common internal-network findings,
which share one kill chain (**Responder → NTLM → SMB relay**); Part 3 adds a
**Kerberos downgrade / roasting** watch over the same capture.

**Part 1 — SMBv1.** SMBv1 is the deprecated (2014) SMB dialect and the **EternalBlue /
WannaCry / NotPetya (MS17-010)** vector — disabled by default on modern Windows but
still lurking on legacy NAS, printers and old hosts. SMBv1 frames carry the magic
`\xffSMB` (SMB2/3 use `\xfeSMB`), so they're identified on the wire; from the SMB
**command byte + response flag** the scanner separates a *real* SMBv1 session
(tree-connect / session-setup, or a server negotiate-**response**) from a harmless
multi-dialect negotiate **offer**, so a modern client that merely lists SMBv1 in its
dialects isn't a false positive.

**Part 2 — LLMNR / NBT-NS / mDNS poisoning.** When DNS fails, Windows falls back to
these broadcast/multicast name-resolution protocols (LLMNR udp/5355, NBT-NS udp/137,
mDNS udp/5353). **Responder / Inveigh** answer those queries with the attacker's IP;
the victim then authenticates to the attacker and leaks **NTLMv2 hashes** (offline
crack or relay). Nothing legitimate *answers* LLMNR/NBT-NS, so a host that does is a
poisoner. What it flags:

- **poisoning** — a host answering LLMNR/NBT-NS (Responder/Inveigh), or an mDNS host
  claiming foreign / high-value names. **WPAD** and ISATAP targeting is called out.
- **spoof-conflict** — one name answered by two hosts with different IPs (a poisoner
  racing the real owner).
- **smbv1-active** / **smbv1-offered** — SMBv1 in use, or merely offered.
- **name-exposure** — LLMNR/NBT-NS queries present at all: hosts are one Responder
  away from credential theft; disable via GPO.

**Part 3 — Kerberos downgrade / roasting (tcp+udp 88).** The same capture also reads
Kerberos KDC traffic. Kerberos is ASN.1/DER; the fields a passive downgrade watch needs
(message type, requested/issued **etypes**, the service **SPN**, and whether an AS-REQ
carried **PA-ENC-TIMESTAMP** pre-auth) all sit near the start of each message, so a
small tolerant DER walker reads them straight off the wire — no full dissector, and it
keeps working on packets truncated by the capture snaplen. What it flags:

- **kerberoast** — a **TGS-REQ** for a service SPN (`sname` ≠ `krbtgt`) that forces
  **RC4** (etype 23) with no AES offered, so the returned service ticket is encrypted
  with the account's RC4 key and **crackable offline** (Rubeus / `GetUserSPNs`); also a
  KDC that actually **issues** an RC4 service ticket. *Fix:* AES-only + long/gMSA
  passwords on service accounts.
- **asrep-roast** — an **AS-REQ with no pre-auth** (the account has *"do not require
  Kerberos preauthentication"*), especially one answered by an **AS-REP** — the AS-REP
  is an offline-crackable hash (`GetNPUsers`). *Fix:* require pre-auth on every account.
- **krb-downgrade** — the KDC actually **issues a DES/RC4 ticket** (weak encryption in
  real use), or a client offers **only** weak etypes (AES stripped/disabled).
- **krb-exposure** — RC4/DES still **enabled alongside** AES (legacy encryption that a
  roaster can force).

Kerberos attack verdicts are **never** baselined away; the baseline only remembers the
**known KDC IPs + realms** to annotate output (a *new* KDC is called out).

Capture is done by `tcpdump -w` into a pcap (SMB tcp/445+139, LLMNR/NBT-NS/mDNS,
Kerberos tcp+udp/88) and **dissected with Scapy** — modern tcpdump no longer decodes SMB
and never decoded LLMNR/NBT-NS, so Scapy is required (Detector Self-Test → **Install
Scapy**). The first scan **learns** the accepted mDNS responders (printers/Macs
announcing themselves), any SMBv1 hosts, and the Kerberos KDCs/realms as the baseline
(`data/smb_watch.json`); LLMNR/NBT-NS answers and Kerberos downgrade/roasting are
**never** baselined away. The hardening it nudges toward: disable SMBv1, turn off
LLMNR (GPO) and NBT-NS (per-adapter / DHCP option 001), enforce **SMB signing** so
captured NTLM can't be relayed, and set accounts/DCs to **AES-only** Kerberos with
pre-auth required. **API:** `GET /api/net/smb-watch`, `POST /api/net/smb-baseline`.
**CLI:** `smb-watch`, `smb-selftest`.

### Relay/Coercion Watch
A **passive** NTLM-relay + authentication-coercion scanner — the **defensive
counterpart** to [SMB Watch](#smb-watch). Where SMB Watch catches the *harvest* (a host
answering LLMNR/NBT-NS), this catches the *relay* and the *coercion* that feed it.
NTLM has no channel binding by default, so an attacker who obtains an NTLM
authentication — by poisoning, or by **coercing** a host to authenticate — can relay
it to another service and act as the victim (`ntlmrelayx`). **Detection-only**
(tcpdump → pcap → Scapy). What it flags:

- **coercion-attempt** — an MSRPC call over 445/135 that forces a host to
  authenticate, identified by the interface UUID in the RPC bind (matched by its
  DCE/RPC little-endian wire encoding): **PetitPotam** (MS-EFSRPC), **PrinterBug /
  SpoolSample** (MS-RPRN, plus the coercion opnum 65/66 to avoid flagging legit
  printing), **DFSCoerce** (MS-DFSNM), **ShadowCoerce** (MS-FSRVP).
- **relay-suspected** — the *same* NTLMSSP server challenge seen from **two different
  servers**: a captured challenge being replayed through a relay.
- **signing-not-required** — a server that negotiated SMB without signing *required*
  (read from the SMB2 NEGOTIATE `SecurityMode`): the posture that makes captured NTLM
  relayable in the first place.

The BPF is `tcp port 445 or tcp port 139 or tcp port 135`, captured at snaplen 1024 so
the RPC bind/opnum and NTLMSSP messages stay intact; **Scapy** dissects it. The first
scan **learns** the accepted unsigned servers as the baseline
(`data/relay_watch.json`); coercion and relay signals are **never** baselined away.
The hardening it drives: enforce **SMB signing** everywhere, enable **LDAP signing +
channel binding** on DCs, turn on **Extended Protection for Authentication (EPA)**,
disable the Print Spooler on DCs, and patch (or RPC-filter) the coercion vectors.
**API:** `GET /api/net/relay-watch`, `POST /api/net/relay-baseline`. **CLI:**
`relay-watch`, `relay-selftest`.

### LDAP Watch
A **passive** Active-Directory / LDAP observer — **detection-only, it never
transmits**. It sniffs LDAP (**tcp/389**, Global Catalog **tcp/3268**), LDAPS /
GC-S (**636 / 3269**, seen only as encrypted flows — the LDAP inside is TLS Watch's
job), and connectionless **CLDAP** (**udp/389**). TCP byte streams are reassembled
per flow and the **BER/ASN.1 `LDAPMessage`** envelope is decoded by a **hand-rolled
definite-length decoder** (no library dissectors), which also tolerates
snaplen-truncated packets. Everything is parsed straight off the wire (`ldap_watch.py`
is a standalone module, imported by the toolbox).

What it flags:

- **cleartext-bind-credentials** / **sasl-plaintext-cleartext** — a simple or
  SASL PLAIN/LOGIN/EXTERNAL bind whose password crosses **cleartext** 389/3268; the
  credential is recoverable straight from the capture. *(compromised)*
- **anonymous-bind** / **unauthenticated-bind** — an anonymous bind, or the RFC 4513
  §5.1.2 "unauthenticated" mechanism (a non-empty DN with an **empty** password) the
  server may silently treat as anonymous. *(suspicious)*
- **starttls-stripped** — a StartTLS `ExtendedRequest` (OID `1.3.6.1.4.1.1466.20037`)
  that is **refused** or after which the flow keeps talking cleartext — a
  downgrade / TLS-strip. *(compromised)*
- **directory-enumeration** — a whole-subtree `(objectClass=*)` from a domain base, or
  a high volume of searches from one source — the **BloodHound / ldapdomaindump**
  signature. *(suspicious)*
- **sensitive-attribute** — a query for password/LAPS/gMSA/ACL material or
  **`servicePrincipalName`** (Kerberoast recon; ties into [SMB Watch](#smb-watch)'s
  Kerberos leg). *(warn, or high over cleartext)*
- **filter-injection** — an assertion value carrying **unescaped** filter
  metacharacters (`)(`, bare `(`/`)`), i.e. an LDAP-injection / auth-bypass probe.
  *(compromised)*
- **brute-force** — many binds from one client, or many `invalidCredentials` (49)
  responses toward one client — password spraying / brute force. *(compromised)*
- **cldap-reflection** / **cldap-amplification** — a CLDAP query from an off-subnet
  (spoofable) source, or a response several times larger than its query — the DC is a
  usable **UDP reflection/amplification** vector. *(warn / high)*
- **external-referral** *(new in v3)* — a referral or `SearchResultReference` that
  steers a client to an LDAP/CLDAP host **outside your own subnets**. This is the
  **LDAPNightmare** steering primitive: **CVE-2024-49113** (the Windows LDAP / LSASS
  denial-of-service) and **CVE-2024-49112** (LDAP-client remote code execution) both
  work by feeding a victim's LDAP client a crafted referral pointing at an
  attacker-controlled server, so that out-of-subnet referral is caught on the wire.
  Only **IP-literal** targets outside the local nets fire it — hostnames can't be
  placed passively and in-forest referrals to your own subnets stay silent, so it
  does not false-positive on legitimate cross-domain referrals. *(compromised)*

Verdict is **clean → suspicious → compromised**. Capture is a short passive **Scapy**
sniff (Scapy is imported lazily, so `--selftest` and offline parsing need zero
third-party deps). The findings engine is pure Python and self-tests without root via
fabricated BER messages (`ldap_watch.py --selftest`, and `tests/test_ldapwatch.py`).

For **continuous** monitoring there is an opt-in **least-privilege systemd unit**
(`scripts/ragnar-ldapwatch.service`) that runs `ldap_watch.py --daemon` with **only
`CAP_NET_RAW`** and streams **JSON-lines** findings (one object per line) to
`/var/log/ragnar/ldapwatch.jsonl` for the web UI + Pushover.

Hardening it drives: require **LDAPS/StartTLS** and reject simple binds on cleartext,
**disable anonymous binds**, enforce **LDAP signing + channel binding (EPA)** on DCs,
and restrict **UDP/389** at the edge. **API:** `GET /api/net/ldap-watch`. **CLI:**
`ldap-watch`, `ldap-selftest`.

### DTP Watch
A **passive** VLAN-hopping / switch-spoofing scanner for Cisco's **Dynamic Trunking
Protocol** (proprietary; group MAC `01:00:0c:cc:cc:cc`, SNAP OUI `0x00000c`, PID
`0x2004`). **Detection-only** — it never transmits a DTP frame.

DTP auto-negotiates whether a switch port becomes an 802.1Q/ISL **trunk**. A port
left in the default `dynamic auto` / `dynamic desirable` mode will form a trunk with
*anything* that sends DTP "desirable" frames — so an attacker plugs into an access
port, forges DTP desirable (Yersinia's "enable trunking"), the port trunks to them,
and they can now see and inject into **every VLAN** on the switch. This is the
classic VLAN hop. DTP should never appear on an access segment; the fix is
`switchport mode access` + `switchport nonegotiate` on every user port. What it flags:

- **vlan-hop** — trunk-forming DTP (on/desirable/auto) from a **new** speaker not in
  the baseline: an active switch-spoofing attempt.
- **trunk-negotiation** — trunk-forming DTP present at all (the port isn't
  `nonegotiate`, so it's exploitable) even from a known switch.
- **dtp-enabled** — DTP frames present but not negotiating a trunk. Advisory / learn.
- **trailing-data** — non-zero bytes *after* a frame's declared length (see the
  shared note below). Shared with CDP/VTP/EIGRP/FHRP/OSPF Watch.

> **Trailing-data / Etherleak (CDP · DTP · VTP · EIGRP · FHRP · OSPF Watch).**
> Honest Ethernet padding is all zeros, so *non-zero* bytes past a frame's
> declared length (the 802.3 length field for the Cisco SNAP protocols, the IPv4
> total-length for the IP ones) mean data smuggled behind a valid advert (covert
> channel) or a NIC/driver leaking kernel memory into the pad (Etherleak,
> CVE-2003-0001). These watchers capture with `-xx`, reconstruct the raw frames,
> and raise a **trailing-data** verdict on any non-zero trailer (a kept 4-byte
> FCS is excluded). A more severe verdict on the same scan is left in place.

The scan uses `tcpdump -e` (to capture the sender's MAC) with the BPF
`ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2004`, which isolates DTP from the
other protocols sharing that Cisco group MAC (CDP/VTP/UDLD/PAgP). DTP hellos are ~30s
apart, so the default window is longer (30s). The first scan **learns** the current
DTP speakers (the real switches) as the baseline (`data/dtp_watch.json`); "Trust
current" re-learns. **API:** `GET /api/net/dtp-watch`, `POST /api/net/dtp-baseline`.
**CLI:** `dtp-watch`, `dtp-selftest`.

### CDP Watch
A **passive** flood / spoof / information-leak scanner for Cisco's **Discovery
Protocol** (proprietary; the same group MAC `01:00:0c:cc:cc:cc` as DTP, SNAP OUI
`0x00000c`, PID `0x2000`). **Detection-only** — it never transmits a CDP frame.

CDP is **on by default** on virtually every Cisco device and, with **no
authentication**, broadcasts to anyone on the segment a remarkable amount about the
switch: the **device hostname**, the **full IOS software version** (which maps
directly to known **CVEs**), the **hardware platform/model**, a **management IP**, the
**native VLAN**, the **VTP domain**, the **voice VLAN**, and the **port-ID**. The
[LLDP/CDP Switch Discovery](#switch-discovery-lldp) tool *uses* that to map a network;
CDP Watch looks at the same frames from the attacker's side and flags their abuse:

- **flood** — a spray of CDP frames / many distinct device-IDs in one window
  (Yersinia `cdp` flood): fills the switch's CDP neighbour table and spikes its CPU —
  a denial of service.
- **spoof** — a **new CDP speaker** not in the learned baseline (a rogue device
  injecting a fake neighbour), including a **fake Cisco IP Phone** advertising a Voice
  VLAN — the CDP half of a **VoIP-VLAN-hop**.
- **cdp-enabled** — CDP is present at all: the scan surfaces **exactly what it leaks**
  here (IOS version, model, management IP, native/voice VLAN) so you can see the
  reconnaissance an attacker on that port gets for free. Advisory / learn.
- **cdpwn** — an **attack-in-flight exploit shape** for the five Armis **CDPwn**
  CVEs. A byte-level TLV parser runs over the reconstructed frames and flags:
  oversized **DeviceID** (`CDP-042`, CVE-2020-3110) / **PortID** (`CDP-043`,
  CVE-2020-3111) / generic string (`CDP-044`), **format-string** metacharacters in
  a string TLV (`CDP-045`, CVE-2020-3118, printf-accurate `%n` scan), malformed
  **Power-Request** with absurd level count (`CDP-046`, CVE-2020-3119), an absurd
  **Addresses** count (`CDP-047`, CVE-2020-3120), and TLV length over/underrun
  (`CDP-040`/`CDP-041`). It also does **version screening** (`CDP-020…024`): a
  platform/version/device-id match (IP Phone, IP Camera, IOS-XR, NX-OS, FXOS/
  Firepower — plain IOS/IOS-XE deliberately excluded, per Cisco's advisory)
  attaches the CVEs to verify that device against. `TTL=0` withdrawals (`CDP-050`)
  and the shared trailing-data check (`CDP-052`) round it out.

The scan uses `tcpdump -e` with the BPF
`ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000`, isolating CDP from the other
protocols on that Cisco group MAC (DTP/VTP/UDLD/PAgP). CDP hellos are ~60s apart, so
the default window is longer (30s). The first scan **learns** the current CDP speakers
(the real switches/phones) as the baseline (`data/cdp_watch.json`); "Trust current"
re-learns. Every result carries a **mitigation advisory**: disable CDP on access/edge
ports (`no cdp enable`, or `no cdp run` globally if unused), and prefer **LLDP** with
minimal TLVs where discovery is genuinely needed.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py cdp-watch [--iface eth0] [--seconds 30] [--json]
python3 network_diagnostics.py cdp-selftest     # self-test the detector, no root
```

`cdp-selftest` drives the real parser + classifier with synthetic captures (clean /
spoof / fake-phone VoIP-hop / cdp-enabled leak / flood / field-parse), and — when
[Scapy](https://scapy.net) is installed — crafts a real CDP frame into a pcap and
parses it back through `tcpdump -e`, exercising the capture→parse path end to end.
**API:** `GET /api/net/cdp-watch`, `POST /api/net/cdp-baseline`.

### VTP Watch
A **passive** bomb / rogue-server scanner for Cisco's **VLAN Trunking Protocol**
(proprietary; the same group MAC `01:00:0c:cc:cc:cc` as CDP/DTP, SNAP OUI `0x00000c`,
PID `0x2003`). **Detection-only** — it never transmits a VTP frame.

VTP synchronises the **VLAN database** across a VTP domain, and its entire security
model rests on one 32-bit **configuration revision number**: the switch advertising
the **highest** revision in the domain wins, and every other switch (in server/client
mode) **overwrites its VLAN database** to match. So a rogue switch — or a single
forged Summary Advertisement — that carries the domain name and a higher revision
silently **rewrites, and can delete, every VLAN across the whole domain**. That's the
**VTP bomb**: a one-frame, domain-wide outage. VTPv1/2 offer **no per-port
authentication** (only an optional weak MD5 domain password). What it flags:

- **revision-bomb** — a config revision **higher than the learned baseline** coming
  from a source that **isn't the known VTP server**: the VLAN-database-overwrite
  attack. (A higher revision from the *known* server is treated as a legitimate VLAN
  edit — reported as `vtp-enabled`, with a "Trust current" prompt.)
- **rogue-server** — a **new VTP speaker**, or a **different VTP domain name**, than
  the baseline: a rogue switch positioned to seize VLAN management.
- **vtp-enabled** — VTP present, or a legit revision bump from the known server.
  Advisory / learn.

The scan uses `tcpdump -e` with the BPF
`ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2003`, isolating VTP from the other
protocols on that Cisco group MAC (CDP/DTP/UDLD/PAgP). (Note tcpdump prints the config
revision in **hex** — `Config Rev a` is 10.) The first scan **learns** the domain,
revision and server (`data/vtp_watch.json`); "Trust current" re-learns after a
legitimate VLAN change. Every result carries a **mitigation advisory**: run switches
in `vtp mode transparent` (or VTPv3 with a password) unless you truly need domain-wide
VLAN sync, always set a VTP password, and **always zero a switch's config-revision
before connecting it** — a client/server switch with a higher revision overwrites the
domain's VLAN database on connect.

Small **CLI** (no web app needed):

```
python3 network_diagnostics.py vtp-watch [--iface eth0] [--seconds 30] [--json]
python3 network_diagnostics.py vtp-selftest     # self-test the detector, no root
```

`vtp-selftest` drives the real parser + classifier with synthetic captures (clean /
revision-bomb / legit-bump / rogue-server / rogue-domain / learn / hex-revision
parse), and — when [Scapy](https://scapy.net) is installed — crafts a real VTP Summary
Advertisement into a pcap and parses it back through `tcpdump -e`, exercising the
capture→parse path end to end. **API:** `GET /api/net/vtp-watch`,
`POST /api/net/vtp-baseline`.

### FHRP Watch
A **passive** hijack scanner for the **First Hop Redundancy Protocols** — **HSRP**
(Cisco, UDP 1985), **VRRP** (RFC 5798, IP proto 112), **GLBP** (Cisco, UDP 3222)
and **CARP** (BSD, IP proto 112). **Detection-only** — it never sends an FHRP
packet or joins an election; it captures one short window of the multicast hellos
and classifies them against a learned baseline.

FHRP is how two or more routers share a single **virtual gateway** (one virtual
IP + MAC that floats to whichever router is *active*), so hosts keep working when a
router dies. The active router is chosen by **priority**, and the hellos are
multicast in the clear with weak or no authentication (HSRP's default is the
plaintext string `cisco`; VRRPv3 has none). That makes FHRP a classic MITM target:
an attacker who can see the hellos injects a forged hello with **priority 255 +
preempt**, wins the election, and becomes everyone's default gateway — all
off-subnet traffic now flows through them (Yersinia, Loki, `scapy`). What it flags:

- **Hijack** — a speaker that isn't in the baseline advertising a **winning**
  priority (≥ the current active, or ≥ 250/255), or an **HSRP Coup** (an active
  takeover message). This is a live gateway takeover.
- **Rogue speaker** — a new speaker in a group that isn't (yet) winning: FHRP
  injection in progress; watch for a following priority rise.
- **Priority change** — a *known* speaker whose priority jumped up. Could be a
  legitimate reconfiguration or the pre-stage of a takeover.
- **Weak / no auth** — plaintext HSRP auth or VRRP `authtype none/simple`. This is
  the enabler; the fix is MD5/HMAC (HSRP key-chains, VRRP AH) plus filtering FHRP
  multicast off access ports.

**GLBP gets its own decoder and two hijack planes.** Neither `tcpdump` nor Scapy
dissects GLBP, so it is decoded by a **hand-rolled byte parser** (per the Wireshark
GLBP dissector: a 12-byte header then type/length/value TLVs — Hello, Virtual
Forwarder, Auth). GLBP splits the gateway job across **two independent elections**,
so it has two distinct hijacks:

- **AVG (Active Virtual Gateway)** — one router owns the vIP and, crucially, decides
  which virtual MAC each host is handed. Seizing it (a winning Hello priority) is a
  takeover **worse than HSRP**: the attacker chooses *who* to MITM. This reuses the
  priority rules above (surfaces as **hijack**).
- **AVF (Active Virtual Forwarder)** — up to four AVFs each own a virtual MAC and
  forward a slice of the hosts. **glbp-avf-hijack** fires when a non-baseline speaker
  goes **Active** for a forwarder (or the same vMAC re-homes to a new source): it
  quietly captures that forwarder's slice while the AVG election stays
  healthy-looking — the stealthiest FHRP takeover. **glbp-weight-skew** fires when a
  forwarder's advertised **weight** shifts far enough to steer which hosts route
  through it (selective capture without an election change).

The first scan **learns** the current groups, their active speakers/priorities, and
the **GLBP forwarders** (owner, vMAC, weight per group/forwarder) as the trusted
baseline (`data/fhrp_watch.json`); after a legitimate router/priority/forwarder
change, click **Trust current** to re-learn. Capture is done to a pcap (BPF
`(udp and (port 1985 or port 3222)) or (ip proto 112) or (ip6 proto 112)`), replayed
through `tcpdump -r … -v` for the HSRP/VRRP/CARP parse and byte-decoded with Scapy
for GLBP; CARP stays best-effort. Put the Pi on the routed VLAN or a SPAN/mirror to
see the hellos. **API:** `GET /api/net/fhrp-watch`, `POST /api/net/fhrp-baseline`.
**CLI:** `fhrp-watch`, `fhrp-selftest`.

### EIGRP Watch
A **passive** routing-security scanner for Cisco's **EIGRP** — its interior gateway
protocol and the Cisco-world alternative to OSPF (mechanically it's an *advanced
distance-vector* protocol rather than link-state, but it fills the same IGP role).
EIGRP runs over **IP proto 88**, multicast **224.0.0.10** (and `ff02::a` for IPv6).
**Detection-only** — it never forms an adjacency, sends a hello, or injects a route.

Like OSPF, EIGRP is unprotected on the wire unless an **HMAC-MD5/SHA authentication
key-chain** is configured, so any host on the segment can peer and inject **Update**
packets with attractive metrics to blackhole or MITM traffic. The advantage here:
unlike OSPF (whose LSA internals `tcpdump` leaves opaque), `tcpdump` **fully decodes
EIGRP's route TLVs** — the advertised prefix, next-hop and metrics are visible — so
this scanner sees route injection directly. What it flags:

- **injection** — a prefix that isn't in the baseline being advertised, or a known
  prefix now pointing at a **different next-hop** (route / next-hop hijack). This is
  the money finding — a forged route steering traffic.
- **rogue-router** — a new EIGRP speaker (source / AS) not in the baseline
  (adjacency spoofing).
- **storm** — an EIGRP flood (hello / query storm) by rate.
- **anomaly** — a **K-value** or **AS-number** mismatch between speakers (a misconfig
  that blocks peering, or a crafted hello probing the segment).
- **weak-auth** — EIGRP packets with **no Authentication TLV** (the enabler for
  every injection attack).

The BPF is `ip proto 88 or ip6 proto 88`. IPv4 route TLVs (internal + external, with
next-hop, origin-router/AS and metrics) are fully decoded; **IPv6 EIGRP** yields the
speaker, AS, auth state and K-values but not per-prefix detail (this `tcpdump` build
prints the v6 route TLV as `Unknown TLV (0x0402)`). Put the Pi on the routed VLAN or
a SPAN/mirror to see EIGRP. The first scan **learns** the current routers and the
advertised prefix→next-hop map as the baseline (`data/eigrp_watch.json`); after a
legitimate topology change, click "Trust current". **API:** `GET /api/net/eigrp-watch`,
`POST /api/net/eigrp-baseline`. **CLI:** `eigrp-watch`, `eigrp-selftest`.
Validate it against **real** FRR EIGRP + injected attacks in an isolated
network-namespace lab — see the [EIGRP FRR Namespace Lab](eigrp_lab.md)
(`eigrp_lab.sh` + `eigrp_inject.py`).

### IS-IS Watch
A **passive** routing-security scanner for **IS-IS** (ISO/IEC 10589) — the third
interior gateway protocol alongside OSPF and EIGRP, and the one that dominates
**ISP / service-provider and data-center cores**. **Detection-only** — it never forms
an adjacency, sends a hello, or injects an LSP.

IS-IS is architecturally unusual: it runs **directly on L2** (ISO CLNS, LLC DSAP
`0xFE`) — *not* over IP — so IP ACLs never touch it, and its only real protection is
the **TLV-10 authentication** (a cleartext password or HMAC-MD5). On a broadcast LAN
its PDUs go to the AllL1ISs (`01:80:c2:00:00:14`) and AllL2ISs (`01:80:c2:00:00:15`)
multicast MACs: **IIH** (Hello) forms adjacencies, **LSP** (Link State PDU) carries
the topology and reachable prefixes, and **CSNP/PSNP** sync the database. Without
authentication, any host on the segment can peer and inject LSPs with attractive
metrics to blackhole or MITM traffic (the IS-IS analogue of OSPF LSA injection).
`tcpdump` fully decodes IS-IS — including the reachable prefixes in LSPs and the
**dynamic-hostname TLV (#137)** that maps a system-id to a router name — so this
scanner sees injection directly and can name the routers. What it flags:

- **injection** — an LSP from a system-id **not** in the baseline, a **new /
  re-homed** reachable prefix (an LSP hijack steering traffic), or an **LSP purge**
  (Remaining Lifetime 0, deleting a router's LSP from every database in the area — a
  blackhole). The money findings.
- **rogue-router** — a new IS-IS speaker (system-id) sending hellos, not in baseline
  (adjacency spoofing).
- **storm** — an IIH/LSP flood by rate.
- **anomaly** — a **duplicate system-id** seen from two MACs (a spoof); a **new
  area address** on a known router; the **overload (OL) bit** set (traffic steering
  / denial); an **LSP sequence number** near the `0xFFFFFFFF` wrap (a seq-number
  attack forcing the owner to purge + re-originate); or **mixed authentication** —
  one system seen both keyed and un-keyed (a spoofed PDU racing the real router's).
- **weak-auth** — a PDU with **no Authentication TLV** or a **cleartext** password
  (the injection enabler).

The BPF is the two IS-IS multicast MACs, captured with `tcpdump -e` for the sender.
The first scan **learns** the current routers (resolved to hostnames via TLV 137),
their areas, and the advertised prefix→originator map as the baseline
(`data/isis_watch.json`); after a legitimate topology change, click "Trust current".
Because IS-IS rides directly on L2, the hardening is HMAC authentication at both
levels plus restricting which access ports may carry it. **API:**
`GET /api/net/isis-watch`, `POST /api/net/isis-baseline`. **CLI:** `isis-watch`,
`isis-selftest`. For a **standalone deep monitor** — a pure-Python binary TLV
parser with the full 16-detector set (adds HMAC-MD5-vs-SHA, DIS-takeover, P2P
three-way, hello-padding, narrow-metrics, malformed-PDU), per-code severity +
dedup, baseline learning and a hardened daemon — see
[isiswatch](isiswatch.md) (`isiswatch.py`).

### OSPF Security Scanner
A **passive** routing-security scanner for OSPF (the interior routing control
plane, IP proto 89 / multicast 224.0.0.5–6). **Detection-only** — it never forms
an adjacency, floods an LSA, or touches the LSDB; it just captures one short
window and classifies it. OSPF is the classic route-poisoning target: without
cryptographic auth, any host on the segment can inject LSAs and silently redirect
traffic. What it flags:

- **Weak / no authentication** — Auth Type 0 (none) or 1 (plaintext). This is the
  enabler for every injection attack and the one thing always visible on the wire;
  it surfaces a CVE/OSV advisory.
- **Anomaly** — a new/rogue OSPF router (adjacency spoofing), a **duplicate
  Router-ID** (conflict/spoof), Hello parameter mismatch, or mixed OSPF versions.
- **Injection** — an LSA whose **Advertising Router** never announced itself (a
  spoofed/injected LSA), a **MaxSequence** (0x7fffffff) or **MaxAge** fight-provoking
  LSA, **fight-back** (one LSA re-originated rapidly = the owner countering an
  active injection), or a **new AS-External (Type-5)** originator (route injection /
  default-route hijack).
- **Storm** — an LS-Update flood (control-plane DoS).

Design is inspired by **[OSPFwatcher](https://github.com/Vadims06/ospfwatcher)**
(topology-change monitoring) and **FRR-MAD** (expected-vs-observed LSDB anomaly
detection), approximated passively from the wire with a learned baseline — the
first scan learns the routers and Type-5 originators (`data/ospf_watch.json`),
**Trust current** re-learns after a legitimate change. Follows the passive-floor
doctrine so a healthy segment reads clean. Put the Pi on the **routed VLAN or a
SPAN/mirror** to observe OSPF.

**On vulnerabilities vs [OSV](https://osv.dev):** OSPF carries no software version
on the wire, so a version→CVE lookup isn't possible passively — the scanner
detects the *exposure conditions* instead (weak auth; opaque/TE LSAs, which are
the trigger for FRRouting ospfd DoS crashes such as CVE-2024-27913 /
CVE-2025-61107 / CVE-2025-61105, and equivalent Cisco ASA/FTD OSPF-LSA advisories)
and points at OSV for the version lookup. It **detects, never exploits**, and is
harmless to the network.

Small **CLI** (no web app / no root for the self-test):

```
python3 network_diagnostics.py ospf-watch [--iface eth0] [--seconds 15] [--json]
python3 network_diagnostics.py ospf-selftest
```

`ospf-selftest` drives the parser + classifier with synthetic captures (clean /
weak-auth / rogue-router / spoofed-LSA / MaxSequence / LSA-field parse) and, when
[Scapy](https://scapy.net) (`scapy.contrib.ospf`) is present, crafts a real OSPF
packet into a pcap and parses it back through `tcpdump` end to end.

- Endpoint: `GET /api/net/ospf-watch` `{interface, seconds}`,
  `POST /api/net/ospf-baseline` `{action: reset}` · binary: `tcpdump`

### BGP Path Watch
The L3-edge companion to the OSPF scanner — a **passive** BGP routing-security
scanner (TCP/179). **Detection-only**: it never opens a session or announces /
withdraws a route. BGP is where traffic gets silently redirected across the
Internet edge, so where it's visible this is the highest-value watch. It flags:

- **Injection (hijack)** — an announced prefix whose **origin AS changed** vs the
  learned baseline (prefix/origin hijack), or a **new more-specific** of a
  baseline prefix (sub-prefix hijack — the most effective real-world BGP attack).
- **Anomaly** — a new/rogue **peer** (new AS or BGP-ID), a **NOTIFICATION** /
  session reset (teardown/flap), a **bogon/martian** prefix announcement, a
  **reserved/documentation ASN** in a received path, an **AS-path loop**, or a
  **BLACKHOLE** community (65535:666).
- **Storm** — an UPDATE churn/flood, or a per-peer **prefix-count spike**
  (full-table route leak).
- **Weak session** — BGP seen but **no TCP-MD5/TCP-AO** signature (RFC 2385/5925),
  exposed to off-path session-reset attacks. Advisory only.

> **Visibility caveat:** unlike OSPF (multicast, on the broadcast domain), BGP is
> **unicast TCP/179 between routers** — the Pi must be **inline, on a SPAN/mirror,
> or a peer** to observe it. Private ASNs (RFC 6996, e.g. 65001) are treated as
> normal, since internal/DC fabric is the most likely place to see BGP passively.

The first scan learns the peers and prefix→origin map as the baseline
(`data/bgp_watch.json`); **Trust current** re-learns after a legitimate change.
As with OSPF, software-version CVEs aren't on the wire, so exposure conditions are
flagged (weak auth; malformed-UPDATE crash class — **CVE-2023-38802** /
**CERT VU#347067**) with an [OSV](https://osv.dev) pointer for the version lookup.

**ASN enrichment:** origin ASNs and peer IPs are enriched with AS **owner names**
+ country via [Team Cymru's IP-to-ASN](https://team-cymru.com/community-services/ip-asn-mapping/)
whois service, so a hijack reads `AS64500 (SOME-HOSTER, RU)` instead of a bare
number. This needs **outbound TCP/43** to `whois.cymru.com` and **fails soft** —
if your NOC egress filters it, the scan degrades to AS-number-only (a blocked
egress is negatively cached for 5 min so it doesn't add a timeout to every scan).
Results are cached for a day. Disable with `?enrich=0` on the endpoint or
`--no-enrich` on the CLI.

Small **CLI** (no web app / no root for the self-test):

```
python3 network_diagnostics.py bgp-watch [--iface eth0] [--seconds 15] [--json]
python3 network_diagnostics.py bgp-selftest
```

`bgp-selftest` drives the parser + classifier with synthetic captures (clean /
origin-hijack / sub-prefix hijack / session-reset / bogon-prefix / UPDATE parse)
and, when [Scapy](https://scapy.net) (`scapy.contrib.bgp`) is present, crafts a
real BGP packet into a pcap and parses it back through `tcpdump`.

- Endpoint: `GET /api/net/bgp-watch` `{interface, seconds}`,
  `POST /api/net/bgp-baseline` `{action: reset}` · binary: `tcpdump`

### BGP Collector & Path Asymmetry (control-plane ↔ data-plane)
Where BGP Path Watch is a passive **capture** scanner, this is the active-but-safe
pairing of **routing truth** with a **measured** data-plane symptom. Two cooperating
pieces:

**Receive-only BGP collector** (`bgp_speaker.py`) — a from-scratch BGP speaker
(RFC 4271 + 4-octet ASN RFC 6793) that opens a real session to a peer to *learn its
RIB*, but is **receive-only**: the FSM (Idle → Connect → OpenSent → OpenConfirm →
Established) sends only OPEN / KEEPALIVE and **never an UPDATE**, so it structurally
**cannot advertise or withdraw a route**. It decodes UPDATEs into an Adj-RIB-In with
per-prefix **churn/flap tracking** (a prefix changing origin/next-hop faster than a
threshold is marked *flapping*, and the previous AS-path is remembered so a change
shows as `old → new`) and longest-prefix lookup. Point it at a router
configured to peer with the Pi's AS (a route-server client / passive peer works well).

**Multi-carrier mode** — start **one session per carrier-facing router** (each with
its own thread + RIB) by passing a `peers` list instead of a single peer. When a
convergence/asymmetry event fires, the verdict then **names which carrier moved and
which are stable** — so a multi-homed operator knows which ISP to call. The scope is
inferred from the pattern: *one* carrier's covering prefix churning → the change is
in that carrier's AS or an upstream peer of it; *all* covering carriers moving
together → upstream of every one of them (the origin AS or a shared major transit).
Single-peer (`peer_ip`/`peer_as`) still works unchanged.

**One-way-delay probe** (`path_asymmetry.py`) — a tiny UDP prober/reflector using the
OWAMP/TWAMP 4-timestamp model (T1 send, T2 remote-recv, T3 remote-send, T4 recv). It
computes forward and reverse delay separately and derives **path asymmetry**. Because
a single unsynced clock pair can't separate a constant offset from a constant
asymmetry, it uses the **Paxson min-pair estimator** (θ̂ = (min fwd − min rev)/2) to
cancel the clock offset and report *change-sensitive* asymmetry with hysteresis — so
it flags a **shift** in asymmetry without false-alarming on a static clock skew. Tick
**clocks PTP/GPS-synced** only if both ends are truly synchronized, in which case the
absolute number is trustworthy. Run the **reflector** on the far node (or here) so the
other side can measure both directions.

**Correlator** — when a collector session is `Established`, each asymmetry event is
annotated with control-plane truth from the RIB(s): the covering prefix, origin AS,
AS-path, whether that prefix is currently flapping, and how recently it changed. With
multiple carrier sessions the correlator produces a **per-carrier breakdown**
(`carriers_confirmed` / `carriers_stable`) and, when any carrier's covering prefix
churned within the correlation window, upgrades the verdict to **`confirmed`** with a
line like `confirmed [Carrier-A confirm; Carrier-B, Carrier-C stable] :: BGP RIB
corroborates: Carrier-A: prefix 9.9.9.0/24 AS-path [64512, 64520] → [64512, 64530]`.
Otherwise it labels the event **route-churn** (flapping), **recent path shift** (a
fresh but stable change), or **stable / data-plane** (no matching control-plane
change — the asymmetry is below BGP, e.g. a congested or re-routed transit leg).

> **Safety:** the collector never originates routing information, and the OWD probe is
> a handful of small UDP datagrams — neither injects state into the network. Both are
> long-lived daemons managed with start/stop/status; nothing is persisted to disk.

- Endpoints: `GET/POST /api/net/bgp-collector` `{action: start|stop|status|rib,
  local_as, router_id, port, hold, peer_ip, peer_as` (single) or `peers: [{ip, as,
  name}, …]` (multi-carrier), `peer` (name, for per-session stop/rib)`}`,
  `GET/POST /api/net/owd-reflector` `{action: start|stop|status, port}`,
  `POST /api/net/path-asymmetry` `{target, count, clock_synced}`
- CLI: `python3 path_asymmetry.py reflector [port]` runs a standalone reflector;
  `bgp_speaker.py` and `path_asymmetry.py` each expose `selftest()`, aggregated into
  the Detector Self-Test panel (`GET /api/net/routing-selftest`).

### Vendor CVE Guards (Cisco · Juniper · Arista)

Three passive, **detection-only** vendor guards watch a network segment and report
**three classes** of evidence about a tracked set of router/switch CVEs — never
transmitting, probing, or authenticating:

- **Posture** — a version/platform fingerprint screened against the CVE catalog.
  Always a *"verify THIS device"* note, never a vulnerable/not-vulnerable verdict:
  a banner can be stale or spoofed, and a train absent from an advisory is *inferred
  from silence, not confirmed patched*.
- **Exposure** — the enabling condition for a CVE is visibly present on the wire
  (cleartext SNMP, a default community, an HTTP UI or Telnet to infrastructure, a
  reachable management listener). Actionable **without** knowing the version.
- **Attack** — an exploitation primitive observed in transit.

Findings roll up to one verdict per scan: **clean** < **observed** (a vendor device
seen, no CVE-relevant finding) < **posture** < **exposure** < **attack**. `observed`
and `clean` rank benign in the Network Integrity Monitor; **attack** ranks critical.
Each guard captures one short passive `tcpdump` window (`-x`, so the L4 payload bytes
are reconstructed from the hex dump for byte-level checks). There is **no TCP
reassembly**, so a segmented HTTP/Telnet attack is best-effort — a hit is
high-confidence, a miss inconclusive — and thresholds are **structural anomaly
bounds** set well above legitimate traffic, not published vendor constants. Every
guard exposes a `selftest()` (synthetic records + a Scapy pcap→`tcpdump`→parse
end-to-end leg) aggregated into the Detector Self-Test panel.

#### Cisco Guard
Cisco IOS / IOS-XE / NX-OS routers, switches and edge/core devices. Firewalls
(ASA/Firepower/FTD/FMC) are **screened out of scope** (`CG-009`), not misclassified.
Capture surface: SNMP (161/162), Telnet (23), HTTP UIs (80/8080/8443), IKEv2
(500/4500). Detects, among others: **`CG-101` cleartext SNMP** and **`CG-102`
default community** (the credential half of the actively-exploited **CVE-2025-20352**
SNMP overflow); **`CG-201`/`CG-202`** the SNMP **OID-arc-flood / oversized-field**
overflow shape (BER-parsed); **`CG-103`** HTTP web-UI cleartext; **`CG-104`** Telnet
to infrastructure and **`CG-270`** an NX-OS Telnet **shell-escape** (the in-the-wild
**CVE-2024-20399** Velvet-Ant shape); **`CG-220`** a VLAN tag-stack anomaly
(**CVE-2024-20434** Catalyst-9000 DoS); plus IOS-XE / NX-OS version-in-range postures.
- Endpoint: `GET /api/net/cisco-guard` `{interface, seconds}` · binary: `tcpdump`
- CLI: `python3 network_diagnostics.py cisco-guard [--iface I] [--seconds N] [--json]`

#### Juniper Guard
Juniper J-Web (SRX/EX), Session Smart Router, Junos Space and Junos-Evolved. Fully
dissects cleartext HTTP to **J-Web** (80/8080) and the Junos-Evolved **On-Box Anomaly
Detection API** (8160), and reads the TLS ClientHello **SNI** (443/8443). Detects the
byte-exact **CVE-2023-36844..36847** J-Web attack shapes — **`JNPR-011` PHPRC** and
**`JNPR-012` LD_PRELOAD** environment-variable injection, **`JNPR-010`**
unauthenticated file upload, and **`JNPR-014`** the two correlated from one source as
an **RCE chain** — plus **`JNPR-050`/`JNPR-051`** the **CVE-2026-21902** anomaly-API
RCE and **`JNPR-030`** Junos-Space stored-XSS (**CVE-2025-59978**) injection attempts.
Passive version extraction is a known dead end for this vendor, so version postures
are **not** claimed.
- Endpoint: `GET /api/net/juniper-guard` `{interface, seconds}` · binary: `tcpdump`
- CLI: `python3 network_diagnostics.py juniper-guard [--iface I] [--seconds N] [--json]`

#### Arista Guard
Arista **EOS** switches, routers and edge/core devices. Non-EOS Arista products
(CloudVision / VeloCloud / DANZ / Awake) are **screened out of scope** (`AG-009`).
Reads the EOS version/platform from **LLDP** (`AG-001`/`AG-005`), parses **RADIUS**
(1812/1813/1645/1646) for the **BlastRADIUS** (**CVE-2024-3596**) conditions —
**`AG-101`** cleartext, **`AG-102`** a missing Message-Authenticator, **`AG-202`** an
unauthenticated response, and **`AG-201`** an oversized attribute (the forgery shape)
— screens **SSH banners** (22) for the **regreSSHion** window (**`AG-104`**,
CVE-2024-6387/6409), and flags management listeners **`AG-103`** gNMI/gNOI
(6030/9339/50051), **`AG-108`** CVX (9979), **`AG-106`** VXLAN decap (4789/8472), plus
**`AG-205`** a VLAN tag-stack CPU-punt anomaly (**CVE-2024-5872**).
- Endpoint: `GET /api/net/arista-guard` `{interface, seconds}` · binary: `tcpdump`
- CLI: `python3 network_diagnostics.py arista-guard [--iface I] [--seconds N] [--json]`

#### Comware Guard
HPE Comware / Huawei **VRF-hopping** (MPLS label injection). Detects **CVE-2015-5434**
(HPE Comware 5/7, H3C, HP) and the identical-signature **CVE-2015-8087** (Huawei): an
attacker on a PE-CE attachment circuit pre-encapsulates their own **MPLS shim header**
so the PE forwards the frame into another tenant's VRF, crossing the isolation boundary.
The detection is **structural** — a labelled frame (ethertype `0x8847`/`0x8848`) on a
customer/access port *should not exist by construction*, the same zero-false-positive
property as inline DHCP snooping — and keys on the **frame**, not a vendor string, so one
rule set covers both vendors. **Segment role is load-bearing:** on a `ce` (customer/access)
port MPLS presence *is* the attack (**`VRF-001`**, CRITICAL); on a `core` port the presence
rules go quiet but the structural rules stay armed; `unknown` is treated as `ce` so
detection fails loud (**`VRF-011`**). Also flags label **sweeps** (**`VRF-002`/`VRF-003`** —
the published PoC brute-forces labels 1000–1500 in 500 frames), reserved labels
(**`VRF-009`**), malformed/no-BOS stacks (**`VRF-006`**), stack-depth/TTL/trailing anomalies,
MPLS inside a VLAN tag (**`VRF-014`**), LDP control-plane exposure on the CE side
(**`VRF-012`**), and passive **Comware/H3C platform adjacency** from LLDP/CDP
(**`VRF-015`**) correlated with a labelled frame (**`VRF-016`**, CRITICAL). Full frames are
reconstructed from the `tcpdump -e -xx` hex dump so the label stack is parsed directly;
validated against the published PoC pcap (506 frames → `VRF-001/002/003/014/015/016/018`).
- Endpoint: `GET /api/net/comware-guard` `{interface, seconds, role}` · binary: `tcpdump`
- CLI: `python3 network_diagnostics.py comware-guard [--iface I] [--seconds N] [--role ce|core|unknown] [--json]`

> **Watchtower feed.** All four vendor guards append their findings as JSON-lines to
> `/var/log/ragnar/<guard>.jsonl` (time-window deduplicated), so [Watchtower](#watchtower)
> tails them into the unified alert pane and single Pushover path alongside the standalone
> watcher daemons — automatically whenever Extended Monitoring is on.

### Locate Port
Physically find **which switch port** the device is plugged into — the software
equivalent of a cable tester / toner probe. It blinks a **per-port LED** on the
chosen wired interface in a timed cadence (a configurable number of blinks);
watch the switch and the port pulsing in sync is the one.

Switches vary in **which LED they drive** off which event, so there are **two
methods** (same card, pick one):

- **Link flap** (`method: flap`, default) — links the port **down/up** each
  cycle, so the **LINK** LED goes dark/lit. Genuinely drops the link for a
  moment each cycle, so it briefly interrupts traffic on that port; if Ragnar is
  reachable *through* that port the UI freezes until the sequence finishes, so
  the tool refuses the interface carrying the default route unless you confirm.
  Always restores the link when done.
- **Traffic burst** (`method: burst`) — floods dense bursts of raw broadcast
  Ethernet frames (EtherType `0x88b5`, ~25–30k pps) with idle gaps, so the
  **ACTIVITY** LED pulses in the cadence while the **link stays up the whole
  time**. Never drops connectivity, so it's **safe on any port including the
  default route** — no confirmation needed. Raw `AF_PACKET` egress needs no
  IP/route on the interface. Some switches only blink their per-port LED on
  traffic, not on link changes — this covers those.

On a **managed** switch you don't need either — Switch Discovery already reports
the exact port over LLDP/CDP. Locate Port is the fallback for **unmanaged**
switches that only have link/activity LEDs.

Notes and safety:
- Physical Ethernet only (`eth*`/`en*`) — locating a switch port only works on a
  wired link. Both methods require the port's link to be up (a cable in the
  switch); a dead/unplugged port can't blink.
- The **interface selector** defaults to **Auto (wired)**, which picks the
  link-up Ethernet port; with no wired link it errors rather than guessing.
- Runs in the background so it completes even if your session blips.

- Endpoint: `POST /api/net/locate-port` `{interface?, count, method, force}` ·
  `flap` uses `ip link`, `burst` uses a raw `AF_PACKET` socket

### PCAP Analyzer
Get instant triage of a capture — the Wireshark *Statistics* menu in one click.
There are **three ways to feed it a capture**, all landing on the same analysis
(and the same *Explain with AI* button):

1. **Analyze upload** — upload a `.pcap` / `.pcapng` from your machine
   (Wireshark, `tcpdump`, the L2 Link Health scan, a SPAN/mirror port, …).
2. **📁 Open stored pcap** — browse captures **already on the box**. Ragnar does a
   bounded scan of sensible locations (its own capture dir, the app tree, `/tmp`,
   `/var/tmp`, home dirs) and lists every `.pcap`/`.pcapng`/`.cap` it finds,
   newest first — pick one and analyze it in place. Selection is confined to
   those roots and magic-byte checked, so it can't be used to read arbitrary
   files off disk.
3. **🎥 Capture live** — record fresh traffic yourself: pick an **interface**
   (defaults to **Auto (wired first)**, which picks the best **link-up** NIC in
   the order LAN → USB LAN → `wlan1` → `wlan0`, then falls back to the
   default-route interface so it always resolves — even on a box whose cables
   are down and that's managed over Wi-Fi), a **duration** (3–60 s), and an
   optional **BPF filter** (e.g. `tcp port 443 or host 10.0.0.5`). The interface
   list is pre-populated on tab load, like every other picker in this section.
   Ragnar runs a passive `tcpdump -w` for the window, saves the
   pcap under `data/pcaps/` (so it also shows up in *Open stored pcap*), and
   analyzes it immediately. Capturing needs root — the Ragnar service already
   runs as root.

   **📡 Monitor mode** (Wi-Fi adapters only) — tick it to capture raw **802.11**
   instead of the adapter's own managed traffic: beacons, deauth/disassoc, and
   nearby devices' frames. Leave **channel** blank to **sweep** 2.4/5 GHz
   (hops 1/6/11 + common 5 GHz channels for a broad survey), or set a channel to
   **park** there and focus on one AP. Ragnar flips
   the radio into monitor mode via the same primitive the Wi-Fi Defense tools use
   (a separate `ragmon0` vif where the driver allows it, otherwise switching the
   adapter itself) and **always restores it afterward**. The resulting 802.11
   capture feeds the analyzer's Wi-Fi/AP breakdown (deauth reasons, retries,
   SSIDs). Best with a dedicated adapter (e.g. an Alfa) — monitor mode briefly
   takes that card off its network. Needs a radio that supports monitor mode.

Every source then shows:

- **Summary** — packets, size, duration, average packet size, data rate,
  capture start/end and encapsulation (via `capinfos`).
- **Protocol hierarchy** — the full frame/byte breakdown per protocol
  (`tshark -z io,phs`), so you see at a glance what the capture is made of.
- **Top talkers** — the busiest IP conversations by exact byte count
  (aggregated from raw frame lengths, so the numbers are precise).
- **Expert info** — tshark's analysis flags grouped by severity: TCP
  **retransmissions**, **resets**, **duplicate ACKs**, zero-window, **malformed**
  packets, etc. — the fastest way to spot loss and protocol trouble.

**Wi-Fi / AP captures** get a dedicated analysis (when the capture contains
802.11 frames — i.e. a monitor-mode or AP-side capture). This is built to answer
the question field techs live with: **why are clients dropping?** It decodes:

- **Deauthentication & disassociation reason codes** (e.g. 15 = 4-way handshake
  timeout, 7 = class-3 frame from a non-associated STA, 4 = inactivity, 14 = MIC
  failure), counted and broken down **per client** so you see who's dropping.
- **Auth / association failure status codes** (e.g. 17 = AP can't handle more
  STAs / capacity).
- **EAPOL** (4-way handshake) volume, **retry rate** (RF-health proxy), and the
  **SSIDs** seen.
- Plain-language **heuristic findings** (handshake timeouts → PSK/RADIUS/timing,
  high retries → RF interference, capacity rejects, etc.) — useful even without
  AI.

**🧠 Explain with AI** — if the OpenAI integration is configured (see
[AI Integration](AI_INTEGRATION.md)), one click hands the capture summary to the
model (GPT-5-nano via the Responses API) with a senior-network-engineer prompt
that diagnoses **what is wrong with the network across the whole stack** — L2
issues (ARP/broadcast/multicast storms, duplicate IPs, spanning-tree churn), TCP
health (retransmissions, resets, zero-windows, dup-ACKs, high RTT), DNS/DHCP
failures, TLS/handshake errors, and — for 802.11 captures — deauth/disassoc
reason codes and retry rates driving client drops. It returns a
**Verdict / Evidence / Other factors / Fix it** root-cause analysis, ranked by
impact and grounded in the actual counts, codes, and expert findings (it won't
invent data that isn't in the summary). If AI isn't enabled, the tool still shows
the full decoded breakdown — the AI just adds the interpretation.

**📄 Export as PDF** — turn the current analysis into a printable one-page report
(summary, protocol hierarchy, top talkers, Wi-Fi breakdown, and expert findings)
and hand it to the browser's print dialog → *Save as PDF*. If you generated an
**AI analysis** first (🧠 Explain with AI), its Verdict / Evidence / Fix-it
write-up is included in the report too. Runs entirely client-side (no external
libraries, works offline on a Pi); allow pop-ups for the report window.

The upload is size-guarded (100 MB), magic-byte validated (real pcap/pcapng
only), analyzed **read-only** with `tshark`, and the temp file is deleted
immediately after. Nothing is stored.

- Endpoints: `POST /api/net/pcap` (multipart `file` — upload),
  `GET /api/net/pcap/stored` (list captures on the box),
  `POST /api/net/pcap/stored/analyze` (analyze a chosen stored path),
  `POST /api/net/pcap/capture` (`interface` / `seconds` / `bpf` — record + analyze),
  `POST /api/ai/pcap` (AI interpretation) · binary: `tshark` (+ `capinfos`),
  `tcpdump` (for live capture)

---

## 🔗 Interfaces

The physical/link truth about this device's own network interfaces, plus the
identity of the network it's attached to.

### Interface list
For every interface (Ethernet and WiFi; virtual/loopback optionally included):

- **Type** — **ethernet**, **wifi**, or **VPN**. VPN/tunnel links (WireGuard,
  Tailscale, OpenVPN in tun *and* tap mode, ZeroTier, PPP/L2TP, GRE/IPsec, …)
  are detected robustly — by the interface's tun/tap device flags and link type
  (`ip -d link`, `wg show`), not just its name — so even a custom-named tunnel
  is flagged as **VPN** rather than being mistaken for a real wired port. (VM
  tap interfaces like `vnet*`/`macvtap*` are treated as virtual, not VPN.)
- **MAC address** and **operational state** (up/down)
- **IPv4 / IPv6 addresses** (link-local `fe80::` filtered out)
- **IP method** — how the address was obtained: `dhcp`, `static`,
  `dhcp-failed` (APIPA 169.254.x.x, i.e. DHCP was attempted but no server
  answered), or `link-down`
- **Link details** (wired) via `ethtool` — negotiated **speed**, **duplex**,
  **auto-negotiation** on/off, and whether **link is detected**
- **VLAN** id and protocol when the interface is a VLAN sub-interface

This tells you at a glance whether a port negotiated at the speed/duplex you
expect (a half-duplex or 100 Mbps link where you expected gigabit is a classic
cabling/auto-neg fault), and whether an interface actually pulled a DHCP lease.

- Endpoint: `GET /api/net/interfaces` · binary: `ethtool` for link details
  (address/method info uses `ip`, always present)

### Network Identity
A best-effort summary of the network Ragnar is *attached to*, merged from
several sources (with provenance reported, since no single source is
authoritative):

- **Hostname / FQDN** of this device
- **DNS search domain(s)** and **nameservers** — pulled from
  `/etc/resolv.conf`, and when that only shows the systemd-resolved stub
  (`127.0.0.53`), the real upstream servers are recovered from
  `nmcli` / `resolvectl`
- **Default gateway** IP, with its **reverse-DNS (PTR)** name — often reveals
  the router/firewall model or naming scheme
- **Traffic via VPN** — whether this host's internet traffic is egressing
  through a VPN. Reads the IPv4 **default route**: if it leaves via a tunnel
  interface (`tun*`/`wg*`/`tailscale0`/…) the answer is **yes (via `<iface>`)**,
  even when the physical uplink is a normal `eth0`/`wlan0`. This catches
  full-tunnel VPNs / exit nodes that silently reroute everything.

**Per-interface scope.** By default the card shows the **default-route** view.
Pick an **interface** from the selector to see the network *that NIC* is
attached to instead — its own **gateway** (that segment's DHCP gateway, even
when it's a higher-metric / non-active default) and its own **nameservers +
search domains** (from `resolvectl`/`nmcli` per-link data; falls back to the
global view, clearly flagged, when the system exposes no per-link DNS). This is
the "the one I'm testing" case: a second dongle on a test LAN whose gateway and
DNS are invisible in the default-route summary because another NIC carries the
default route. The VPN egress check auto-targets the same interface.

- Endpoint: `GET /api/net/identity` — optional `?interface=<name>` to scope to
  one NIC

### ISP / WAN Detection
Detects the **public IP and ISP/ASN reached *through each interface***. On a
**multi-WAN** box (two or more uplinks to different providers) this is the fast
way to answer "which physical link goes to which ISP, and is each one actually
reaching the internet?" — invaluable when one of several uplinks is flaky or
resistant.

For each interface with a usable IPv4, Ragnar runs a lookup **bound to that
interface** (`curl --interface <iface>`, which forces egress out that link via
`SO_BINDTODEVICE` regardless of the routing table) and reports:

- **ISP** and **ASN** (e.g. `Tele2 Sverige AB` / `AS1257`)
- **Public IP** seen from the internet through that link
- **Location** (city / region / country) of that egress
- **Source** — which geo-IP service answered
- **VPN** — is this link *behind* a VPN? Flagged when the interface is itself a
  tunnel (`🔒 WireGuard`, `🔒 Tailscale`, `🔒 OpenVPN`, …), or when the public
  egress ASN belongs to a known VPN provider/backbone (`🔒 likely (mullvad)`,
  `m247`, …). The VPN **technology** is identified from the interface's link
  type (`ip -d link`) and name (Tailscale/NordVPN/Mullvad/ProtonVPN/ZeroTier/
  GRE/IPsec…), and for WireGuard the **peer endpoint** (the VPN server `IP:port`)
  is shown when the `wg` tool is available. A tunnel with no separate internet
  egress is shown as the VPN it is rather than as a failed WAN. The ASN-based
  provider match is best-effort ("likely"), since many VPNs share hosting ASNs.

Lookups use **ipinfo.io** over HTTPS first, falling back to **ip-api.com**. A
VPN tunnel with no separate internet egress is shown as the VPN it is (technology
+ endpoint); a genuinely **dead WAN** — a non-tunnel interface with no working
internet path — reports an explicit error rather than a value, which is itself
the diagnostic you're after.

> **Privacy:** this makes an outbound request to a third-party geo-IP service,
> revealing the device's public IP to it. It is **on-demand only** (triggered by
> the *Detect ISPs* button), never polled in the background.

- Endpoint: `GET /api/net/isp` (all interfaces) or
  `GET /api/net/isp?interface=<iface>` · binary: `curl`

> The **Speed Test** in Diagnostics also reports the ISP for the default path
> (from the speedtest client's own geolocation) — ISP / WAN Detection is the
> per-interface complement for multi-homed setups.

### VPN Egress Check
A focused **"is my traffic leaving through a VPN?"** verdict for one path,
combining every signal Ragnar has. It follows the **default route** by default,
or a specific `interface` if you pass one (e.g. to test the LAN path while WiFi
carries the default route). Returns **vpn / likely / no / unknown**:

- **Local tunnel** — the egress interface is itself a tunnel (WireGuard /
  Tailscale / OpenVPN / IPsec / GRE …), identified from the link type
  (`ip -d link`) and name, with the WireGuard **peer endpoint** when `wg` is
  available.
- **Known-VPN egress IP** — the public egress IP falls inside a **known
  VPN-provider range** (an ASN-derived list synced locally from
  [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) and checked offline).
  This is the signal that catches a VPN running **on the router**, where
  Ragnar's own NIC looks like an ordinary LAN port.
- **Tor exit** — the egress is confirmed a Tor exit node via the Tor Project's
  own checker (again catching Tor/VPN upstream on the router).
- **Provider ASN name** — the egress ISP/ASN name matches a commercial-VPN
  provider or VPN-hosting backbone (`mullvad`, `m247`, …) → *likely* (best-effort,
  since many VPNs share hosting ASNs).

This complements the per-interface [ISP / WAN Detection](#isp--wan-detection)
above: that answers "which link goes to which ISP", this answers "is *this* path
behind a VPN — including one running on the router that the interface heuristics
alone would miss".

> **Privacy:** makes outbound calls (geo-IP + the Tor checker) bound to the
> tested interface. On-demand only, never polled.

- Endpoint: `GET /api/net/vpn-check` or
  `GET /api/net/vpn-check?interface=<iface>` · binary: `curl`

---
All tools are served under `/api/net/*` by `network_diagnostics.py`, a
self-contained module wrapped so a failure there can never take down the rest of
the web app. Every tool executes on demand when you click it — with one opt-in
exception, the [Network Integrity Monitor](#-network-integrity-monitor), which
watches for DNS poisoning and ARP spoofing in the background and can push you an
alert.
## Design notes

- **Never blocks, never crashes the app.** The command runner treats a missing
  binary as exit code 127, a timeout as 124, and any other failure as a plain
  error string — no tool can hang the web UI or raise into the request handler.
- **On-demand by default.** Tools run when you ask them to; the ones that touch
  the wire (Locate Port's link-flap, L2 Link Health and PTP captures, ISP/VPN
  lookups) are always explicit, button-triggered actions. The single background
  poller is the opt-in [Network Integrity Monitor](#-network-integrity-monitor),
  which is off unless you enable it.
- **CSV export** is available for the Switch Discovery, ARP Scan, MAC Watch,
  Interfaces, Network Identity and ISP / WAN tables.
- **Offline-capable.** Everything except the internet-facing tools (Speed Test,
  ISP/WAN detection, DoH/DoT reachability) works with no internet at all —
  ping/MTR to local hosts, DNS against local resolvers, LLDP/PoE, ARP scan,
  L2 health, interfaces, PMTU, iperf3, flow telemetry, PTP and Locate Port are
  all local to the segment, which is the whole point of a field tool.

---

*Authority Verification suite co-authored by [Solarflere](https://www.instagram.com/solarflere).*
