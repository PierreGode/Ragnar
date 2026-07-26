# Ragnar Mesh

Ragnar has always been a single-box tool: one Pi, one LAN, one web UI. That
works right up until the box you care about is in someone else's data centre
and you are not.

Ragnar Mesh links units over [Tailscale](https://tailscale.com) so every one of
them is reachable by a stable private address regardless of NAT, CGNAT or the
firewall in front of it — and so each unit can see what its neighbours are
seeing.

**There is no controller.** Every unit publishes its own report and reads its
peers'. There is no master to configure, no collector whose failure blinds the
rest, and no "primary" that has to be rebuilt if it dies. The unit you happen to
be logged into renders the mesh; so would any other.

---

## Contents

- [Why Tailscale](#why-tailscale)
- [What the mesh adds over the Tailscale console](#what-the-mesh-adds-over-the-tailscale-console)
- [Fleet security findings](#fleet-security-findings)
- [Unit identity — the Viking army](#unit-identity--the-viking-army)
- [Deploying a unit](#deploying-a-unit)
  - [Path 1 — during imaging (unattended)](#path-1--during-imaging-unattended)
  - [Path 2 — during install](#path-2--during-install)
  - [Path 3 — later, from the web UI](#path-3--later-from-the-web-ui)
- [Reaching the whole far-side LAN](#reaching-the-whole-far-side-lan)
- [Backup access when Ragnar itself is wedged](#backup-access-when-ragnar-itself-is-wedged)
- [Security model](#security-model)
- [Cross-site incident correlation](#cross-site-incident-correlation)
- [Configuration reference](#configuration-reference)
- [Runbook: remote data-centre deployment](#runbook-remote-data-centre-deployment)
- [Troubleshooting](#troubleshooting)

---

## Why Tailscale

The transport problem — NAT traversal, key distribution, device authorization,
per-user ACLs — is solved, and solved better than a security tool should attempt
on its own. Ragnar does not reimplement any of it. It uses WireGuard via
Tailscale for transport and identity, and adds only the part Tailscale has no
opinion about: what Ragnar itself is seeing.

Concretely, the mesh depends on Tailscale for:

| Concern | Handled by |
|---|---|
| Reaching a unit behind CGNAT | Tailscale (WireGuard + DERP) |
| Proving which unit is calling | Tailscale (`whois` over the local API) |
| Who may reach a unit at all | Tailscale ACLs |
| Approving / revoking a device | Tailscale admin console |
| Unattended enrolment | Tailscale pre-authorized keys |
| Unit health, alerts, incidents | **Ragnar** |
| Cross-site attack-chain fusion | **Ragnar** |

---

## What the mesh adds over the Tailscale console

The Tailscale console is a genuinely good device console, and for "is the Jersey
box up?" you should just use it. It knows nothing about Ragnar, though.

The Mesh tab knows things the console cannot:

- **Ragnar is down but the box is not.** A unit that answers WireGuard but not
  Ragnar's API shows as **degraded**, not offline. That distinction is the
  difference between "send someone to site" and "restart a service".
- **Undervoltage.** The classic remote-Pi failure, invisible over SSH until the
  SD card starts corrupting itself. Read straight from the SoC's throttle
  register and surfaced per unit.
- **Node-key expiry.** Surfaced *before* it strands a unit — see below.
- **Alert posture per site.** Worst current Watchtower severity, alert counts,
  open incident counts, ranked across the mesh.
- **Attack chains that cross sites.** See
  [cross-site incident correlation](#cross-site-incident-correlation).

### The node-key trap

A **user-owned** Tailscale node key expires on the tailnet's schedule (180 days
by default). When it does, the unit silently drops off the tailnet — and the
only fix is physical access to a box that may be in another country.

A **tag-owned** node key does not expire. This is the single most important
detail in this document, which is why Ragnar tags every unit it enrols
(`tag:ragnar-mesh`) and why the Mesh tab escalates loudly as an expiry
approaches:

| Days remaining | State | Shown |
|---|---|---|
| No expiry (tagged) | `ok` | "Key does not expire (tagged node)." |
| > 14 | `ok` | quiet |
| 4–14 | `warn` | amber banner on the unit card |
| 0–3 | `critical` | amber banner, top of tab |
| expired | `expired` | red banner — needs on-site re-auth |

---

## Unit identity — the Viking army

Units are **individuals, not clones**. A mesh of boxes all called `raspberry` is
one nobody can reason about out loud, and "the one at 100.78.0.11" is not a
sentence anyone wants to say twice.

Every unit therefore has two identifiers:

| | Example | Set by | Purpose |
|---|---|---|---|
| **Viking name** | `Bjorn Ironside` | derived, overridable | Who the unit *is* |
| **Unit number** | `Unit 02` | operator (`mesh_unit_id`, 1–99) | Position in the army |

Cards are titled with the name and subtitled with the rest:

```
Bjorn Ironside
Unit 02 · Jersey DC · 100.78.0.9
```

### Names are derived, not assigned

A unit is **born named**. There is no allocation step, no central registry and
no controller handing names out — which there could not be anyway, since the
mesh has no controller by design.

The name is derived from the machine's own identity (`/etc/machine-id`, falling
back to the Pi's CPU serial and then the hostname), so:

- every box gets a distinct name with zero configuration
- **the same box keeps its name across reinstalls** — a unit that is reflashed
  comes back as itself, not as a stranger
- the derivation is pure and offline; nothing is looked up or registered

48 given names × 24 epithets = 1,152 combinations. Override with
`mesh_viking_name` if you would rather choose:

```sh
python3 -c "import mesh_manager; print(mesh_manager.derive_viking_name())"
```

### Clashes are detected, not prevented

Both identifiers are set independently on each unit, so nothing *prevents* a
collision. Rather than silently rendering an ambiguous view, the mesh says so:

> Two units are both numbered **Unit 03**. Every report naming that number is
> ambiguous — renumber one of them.

> Two units both answer to **Bjorn Ironside**. Names are derived independently
> with no central allocator, so this can happen — rename one in
> Config → Ragnar Mesh.

Name collisions are uncommon but not negligible: with 1,152 combinations, a mesh
of 8 units has roughly a 2–3% chance of one, and a mesh of 25 about 24%. That is
exactly why it is checked rather than assumed away.

Units with no number assigned are counted and reported too. A unit works fine
without a number; it is just harder to talk about.

---

## Deploying a unit

Three paths, all landing in the same place. Pick by how much access you have to
the box at deploy time.

### Path 1 — during imaging (unattended)

The one to use when someone else is racking the hardware. The technician plugs
in power and ethernet and walks away — no login, no credentials handed over, no
instructions beyond "plug it in".

Write `ragnar-mesh.conf` to the **boot partition** of the SD card (Raspberry Pi
Imager's advanced options can do this, or just drop the file on the FAT
partition after flashing):

```sh
# /boot/ragnar-mesh.conf   (or /boot/firmware/ragnar-mesh.conf)
RAGNAR_MESH_AUTHKEY="tskey-auth-xxxxxxxxxxxxxxxxxxxx"
RAGNAR_MESH_UNIT_ID="2"
RAGNAR_MESH_LABEL="Jersey DC"
RAGNAR_MESH_ROUTES="10.20.0.0/24"
```

The unit names itself; there is no name to supply here.

On first boot the unit installs Tailscale, joins the tailnet tagged, sets its
unit number and label, and advertises the LAN subnet.

**The file is shredded after use.** An auth key on an SD card is a credential on
physical media; it has no reason to outlive the join it performs. Generate the
key with:

- `reusable = false` — one card, one join
- `expiry = 90 minutes` (or however long until the tech powers it on)
- `ephemeral = false` — the unit should persist across reboots
- tagged `tag:ragnar-mesh` — so the node key never expires

Spent, short-lived and single-use means a card lost *after* boot carries nothing
of value.

### Path 2 — during install

`install_ragnar.sh` offers mesh setup near the end. It is opt-in — decline and
nothing Tailscale-related is installed. Accept and you can paste an auth key
immediately or defer to the web UI.

Non-interactive installs skip the prompt entirely when `RAGNAR_MESH_AUTHKEY` is
set in the environment or a boot config is present.

### Path 3 — later, from the web UI

Open the **Ragnar Mesh** tab. It is a two-step funnel:

1. **Install Tailscale.** If the client is not present, the tab shows an
   **Install Tailscale** button. It runs the same `scripts/setup_mesh.sh install`
   the installer uses, in the background, and streams the log; when the binary
   appears it moves you straight to step 2. (Prefer the shell?
   `curl -fsSL https://tailscale.com/install.sh | sh`, then reload the tab.)
2. **Join mesh.** Enter unit number, site label, auth key and any LAN subnets to
   advertise. Joining sets `mesh_enabled`, which is what makes every subsequent
   `update_ragnar.sh` keep Tailscale installed and current.

### Why `update` does not install Tailscale by itself

A stock Ragnar deliberately ships **without** Tailscale, and `update_ragnar.sh`
installs it only once a unit has opted in — an auth key in the environment, a
`/boot/ragnar-mesh.conf`, or `mesh_enabled: true` in the config. This is on
purpose: a security tool should not silently add an outbound mesh dependency to
every box on every update. So on a fresh unit that has never touched the mesh,
"I ran update and Tailscale still isn't there" is expected — use the **Install
Tailscale** button (or join once), and updates maintain it from then on.

---

## Reaching the whole far-side LAN

A unit can advertise its local subnets:

```sh
tailscale set --advertise-routes=10.20.0.0/24
```

or via **Ragnar Mesh → Join mesh → Advertise LAN subnets**.

Once the route is **approved in the Tailscale admin console** (it is not live
until then), every device on the far-side LAN becomes addressable by its real IP
from anywhere on your tailnet. This is what turns a remote Ragnar from "a sensor
you can read" into "a way into the site":

- Ragnar's own scanners run *locally* at the remote site, at full fidelity —
  ARP, LLDP, DHCP, 802.11 and every other L2 detector needs to be on the wire,
  and it is.
- You reach the rack's switches, iDRACs and hosts directly from your laptop.

Two warnings worth taking seriously:

1. **A subnet router is a hole into that network.** Scope it with Tailscale ACLs
   to the people who need it, not to the whole tailnet.
2. **Ragnar scans.** A subnet router plus Ragnar's active tooling in a colo you
   do not own can look exactly like an intrusion to whoever runs it. Get that in
   writing before you deploy.

---

## Backup access when Ragnar itself is wedged

There are three ways into a unit, and they are worth keeping distinct because
they fail for different reasons.

### 1. Ragnar's web UI over Tailscale

The normal path. Fails when Ragnar fails.

### 2. Tailscale SSH

Enrolment enables **Tailscale SSH** (`--ssh`) by default: a shell on the unit
with no port forward, no bastion and no key distribution, gated by tailnet ACLs
and optionally session-recorded.

This is the reason to deploy a Pi as a remote-hands device at all — when
Ragnar's web UI is unreachable, the SSH path is independent of *it*. But both
ride the same WireGuard tunnel, so anything that breaks the tunnel breaks both.

### 3. Raspberry Pi Connect — the independent fallback

[Raspberry Pi Connect](https://connect.raspberrypi.com) shares **nothing** with
Tailscale: different vendor, different transport, different credentials,
different control plane. That independence is its entire value. It is the way in
when:

- the tailnet ACLs were misconfigured and locked you out
- a node key expired and the unit dropped off the tailnet
- `tailscaled` will not start after an update
- you are debugging Tailscale itself

Ragnar reports its state on the Mesh tab — installed, signed in, and therefore
actually usable — but never enables it. Signing in requires an interactive
browser flow that cannot be automated from the unit, and enabling a second
remote-access path is an operator's decision, not a program's.

Run these **as your login user (e.g. `pi`), not as root** — Connect is a
per-user service:

```sh
sudo apt install rpi-connect
rpi-connect on          # starts the per-user service
rpi-connect signin      # open the link it prints to link your account
rpi-connect status
```

The Mesh tab reports three distinct states — **Active** (signed in, a real
fallback), **Running, not signed in** (service up but no account linked, *not*
yet usable), and **Installed but off** — and names the login user the commands
belong to.

> **Root vs the login user.** Ragnar runs as root, but Connect runs under your
> login user's session. Ragnar queries that session (not root's), so a box
> signed in as `pi` shows **Active** even though the web service is root. If you
> run `rpi-connect` commands, run them as that same user or they act on the
> wrong (empty) session.

**"Installed but off" but I thought I set it up?** Two things trip people up,
and both make the card *correct*, not wrong:

* **It is per-unit and per-user.** Signing in on one Pi does nothing for
  another. Each unit you want reachable via Connect must be signed in on that
  box, as its own login user.
* **Linger.** If you run `rpi-connect on` over SSH without enabling linger, the
  per-user service stops the moment your session ends — so it works while you're
  logged in and is dead an hour later. Enable it once:
  ```sh
  sudo loginctl enable-linger pi      # the login user Connect runs as
  ```
  This is the single most common reason Connect "stops working" on a headless
  Pi. Confirm with `loginctl show-user pi -p Linger`.

> **Set this up before you ship the hardware.** Every one of these paths is
> trivial to establish with the box on your desk and impossible to establish
> once it is 1,500 km away and unreachable.

---

## Security model

Ragnar is an offensive/recon toolbox. Putting it on a network where more people
can reach it deserves care.

### Unit-to-unit authentication

Peer API calls are authenticated by **WireGuard identity, not a shared secret**.
There is no bearer token to mint, ship, rotate or leak. When a request arrives,
the receiving unit asks its local `tailscaled` who owns the source address and
checks the answer carries the mesh tag.

The gate is deliberately narrow:

| Property | Rule |
|---|---|
| Methods | `GET` only — a peer can observe, never actuate |
| Paths | `/api/mesh/*` only; the other ~290 routes stay session-gated |
| Identity | Must carry `mesh_tag` (default `tag:ragnar-mesh`) |
| Source | Must be a real tailnet address (100.64/10 or `fd7a:115c:a1e0::/48`) |
| Loopback | Rejected — a proxied request's true origin is unknowable at that layer |
| Failure | Fails closed: no Tailscale, no answer, or no tag ⇒ 401 |

**Tailnet membership alone is not enough.** Your laptop is a fully authenticated
tailnet node; it is not a Ragnar unit, and it must log in like anyone else.
Without the tag check, every phone and laptop on the tailnet would inherit
Ragnar's full toolset.

Only two routes are peer-readable:

- `GET /api/mesh/unit` — this unit's health report
- `GET /api/mesh/alerts` — this unit's recent Watchtower alerts

### Never Funnel

`tailscale serve` (tailnet-only) is supported and exposed in the UI.
`tailscale funnel` publishes to the open internet and is **not** — for a box
full of offensive tooling that would be an unambiguous mistake.

### Publishing: HTTP by default, HTTPS opt-in

Publishing at all is optional — peers and operators can always reach a unit
directly at `http://100.x.y.z:8000`. `serve` only buys a friendly hostname and,
with certificates, real TLS.

**Publish** serves the UI over plain HTTP on port 80. It needs no certificate,
works on every tailnet, is still tailnet-only, and is how units are actually
reached — so it is the default:

```sh
sudo tailscale serve --bg --http 80 http://127.0.0.1:8000
```

**Publish (HTTPS)** is the opt-in. It needs the tailnet's *HTTPS Certificates*
feature switched on (admin console → **DNS → HTTPS Certificates**); without it
there is no certificate to issue for the unit's MagicDNS name.

That opt-in is guarded because the failure is nasty: with the feature disabled,
`tailscale serve --https` does **not** return an error — it blocks indefinitely,
even with stdin closed, so it is not a prompt waiting for an answer. The only
symptom is an unexplained timeout. Ragnar therefore checks `CertDomains`
*before* invoking the command and refuses in milliseconds with a link to the
setting, and the UI disables the HTTPS button entirely until certificates are
available.

**Stop** fully unpublishes either scheme — you never have to remember which one
you turned on.

> `tailscale serve` writes tailnet-wide config and needs root. The packaged
> Ragnar service runs as root, so this is only a problem for a hand-started
> instance — in which case run `sudo tailscale set --operator=$USER` once.

### Serve + kiosk is refused

`tailscale serve` proxies from `tailscaled`, so every request reaches Flask from
`127.0.0.1`. Kiosk mode grants unauthenticated access to exactly that address.
Neither setting is wrong alone; together they would expose the entire UI, with
no login, to every device on the tailnet.

Ragnar refuses that combination with a `409` and an explanation rather than
letting you configure your way into it silently.

### Suggested ACL shape

```jsonc
{
  "tagOwners": { "tag:ragnar-mesh": ["autogroup:admin"] },
  "acls": [
    // Units talk to each other on the Ragnar web port.
    { "action": "accept", "src": ["tag:ragnar-mesh"],
      "dst": ["tag:ragnar-mesh:8000"] },
    // Only named operators reach the UI and SSH.
    { "action": "accept", "src": ["group:ragnar-ops"],
      "dst": ["tag:ragnar-mesh:8000,22"] }
  ],
  "ssh": [
    { "action": "check", "src": ["group:ragnar-ops"],
      "dst": ["tag:ragnar-mesh"], "users": ["root", "ragnar"] }
  ]
}
```

---

## Fleet security findings

Each unit card in the Mesh tab shows that unit's own **security findings**,
severity-ranked, pulled live over the mesh — so one pane answers "what has every
box found?" without opening each unit in turn. Findings come from the four
places Ragnar already records them, normalized into one list:

| Category | Source |
|---|---|
| `vulnerability` | the vulnerability scanner (host\:port, CVE/score, service) |
| `integrity` | the Network Integrity Monitor (failing DNS/ARP/DHCP/RA checks) |
| `watchtower` | the standalone passive watchers (arp_guard, ndpwatch, …) |
| `incident` | named cross-signal campaigns from the incident engine |

Each unit serves its own findings at `GET /api/mesh/findings` — the third and
last peer-readable route, read-only like the others. A coordinator does not
compute anything about its peers; it just displays what each already found.

### Launching a unit's live views

Every unit card carries launch buttons — **Traffic**, **Threats**, **Integrity**,
**Watchtower**, **Vulnerabilities** — that open *that unit's own* live view in a
new tab (deep-linked to the feature). This is deliberate: a peer already serves
its full UI on the tailnet, so the honest way to "watch the Jersey traffic
analyzer" is to open Jersey's own analyzer, authenticated as yourself — not to
pipe its heavy live capture cross-unit or to let one box drive another's tools.
Launching stays within each unit's own auth boundary; the mesh only ever
*reads* summaries.

> Cross-unit launches rely on your browser being able to reach the peer's
> tailnet address — which it can, since you are already on the tailnet to reach
> this unit. If a peer publishes over `serve`, its MagicDNS name works too.

## Cross-site incident correlation

Each unit pulls its peers' Watchtower alerts and folds them into its **own**
[incident engine](incident-correlation.md). Every unit therefore holds an
independently-derived, correlated view of the whole mesh — there is no collector
whose loss blinds everyone.

The subtlety is address collision. Mesh units sit on different LANs that reuse
the same address space, so alerts are ingested under the originating unit's name
as a **scope**:

| Entity | Scoped? | Why |
|---|---|---|
| Private IP (RFC1918, CGNAT, link-local, reserved) | **yes** | `192.168.1.1` in Jersey is a different machine than in Stockholm |
| SSID | **yes** | "Guest WiFi" exists at every site |
| Public IP | no | One scanner hitting two sites is one campaign — the thing a mesh is *for* |
| MAC | no | A NIC seen at two sites is the same NIC |

Fusing the site-local ones would manufacture incidents out of coincidence;
failing to fuse the global ones would miss the only attacks a mesh is uniquely
able to see.

Alerts arrive stamped with `mesh_unit` and `mesh_unit_id`, and are de-duplicated
per peer so a rolling window re-served every poll does not inflate an incident's
alert count on every tick.

---

## Configuration reference

Config tab → **Ragnar Mesh (Tailscale)**, or `config/shared_config.json`.

| Key | Default | Meaning |
|---|---|---|
| `mesh_enabled` | `false` | Master switch. Off means no peer polling at all. |
| `mesh_tag` | `tag:ragnar-mesh` | Authorization boundary for unit-to-unit calls. |
| `mesh_unit_id` | `0` | This unit's number. `0` = unassigned. |
| `mesh_viking_name` | `""` | This unit's name. Blank = derive from the machine itself. |
| `mesh_site_label` | `""` | Where the box physically is ("Jersey DC"). |
| `mesh_node_port` | `8000` | Port peers serve their API on. |
| `mesh_poll_interval` | `60` | Seconds between peer refreshes (minimum 15). |
| `mesh_poll_timeout` | `6` | Per-peer HTTP timeout. Kept short so one dead unit cannot stall the view. |
| `mesh_aggregate_alerts` | `true` | Pull peers' alerts into the local incident engine. |
| `mesh_alert_limit` | `50` | Max alerts pulled per peer per poll. |

Environment variables (imaging / unattended):
`RAGNAR_MESH_AUTHKEY`, `RAGNAR_MESH_UNIT_ID`, `RAGNAR_MESH_LABEL`,
`RAGNAR_MESH_ROUTES`, `RAGNAR_MESH_HOSTNAME`, `RAGNAR_MESH_TAG`.

### CLI

```sh
python3 mesh_manager.py              # human-readable mesh status
python3 mesh_manager.py --json       # machine-readable
python3 mesh_manager.py --self-test  # no root, no tailnet, no network needed
```

---

## Runbook: remote data-centre deployment

The scenario this was built for — a unit in a data centre you cannot visit,
installed by a technician you do not want to hand credentials to.

**Before shipping the hardware**

1. In the Tailscale admin console, ensure `tag:ragnar-mesh` exists and is listed
   under `tagOwners`.
2. Generate an auth key: pre-authorized, **reusable off**, **expiry 90 min**,
   **tagged** `tag:ragnar-mesh`.
3. Flash the card, install Ragnar, and write `/boot/ragnar-mesh.conf` with the
   key, the unit number, the site label and the LAN subnet you expect on site.
4. Power the unit on once at your desk to confirm it appears in the console and
   in your own Mesh tab. Then power it down and ship it.

   *Skipping this step means discovering a typo after the box is 1,500 km away.*

**On site (the technician)**

5. Rack it, plug in power, plug in ethernet. That is the whole job.

**Back at your desk**

6. The unit appears in **Ragnar Mesh** within a minute or two.
7. Approve its advertised subnet route in the Tailscale console.
8. Confirm the unit card shows a green dot, plausible CPU/disk, no undervoltage,
   and a key state of `ok`.
9. Confirm Tailscale SSH works — *before* you need it.

**If it does not appear**

- Nothing in the console at all ⇒ the unit never reached the internet. That is
  the site's network or the cable, not Ragnar.
- In the console but not in the Mesh tab ⇒ it joined untagged, or with a
  different tag. Check `tailscale status --json` on the unit.
- In the Mesh tab but **degraded** ⇒ WireGuard is up and Ragnar is not. SSH in.

---

## Troubleshooting

**"Tailscale is not installed on this node."**
Click **Install Tailscale** in the Mesh tab — that is the intended fix. It runs
in the background and reveals the join step when done. Update did not install it
because the unit had not opted into the mesh yet
([why](#why-update-does-not-install-tailscale-by-itself)). To do it by hand
instead:
```sh
curl -fsSL https://tailscale.com/install.sh | sh
sudo systemctl enable --now tailscaled
```
Or re-run `sudo ./scripts/setup_mesh.sh install`, then reload the tab.

**The Install Tailscale button says it did not complete.**
Expand the log it shows. The usual causes are no outbound internet (the vendor
script pulls from `tailscale.com` and `pkgs.tailscale.com`) or, on a
hand-started Ragnar not running as root, no passwordless sudo — the packaged
service runs as root and is unaffected.

**"tailscaled is not responding."**
`sudo systemctl status tailscaled`. Ragnar reads the daemon's local API socket
at `/var/run/tailscale/tailscaled.sock` and needs root — which the Ragnar
service already has.

**A peer shows "Not polled yet" and the footer says "Peer data has not been
polled yet".**
The peer is tagged and reachable, but this unit has never polled it — almost
always because **`mesh_enabled` is off**. Tagging a node in the Tailscale
console puts it *in* the mesh; `mesh_enabled` is the separate switch that makes
this unit actually *poll* its peers, and only Ragnar's Join flow sets it. The
tab shows a banner with a one-click **Enable data sharing** button; that flips
`mesh_enabled` and starts the poller. (Peers that were genuinely polled and
failed read "Ragnar not answering" instead — a different state.)

**A peer shows "Ragnar not answering".**
This one *was* polled and the peer's API did not respond — but "did not respond"
covers four different faults, so **click the card's `Diagnose` button**. It
probes the peer live from this unit and names the actual cause:

| Result | Meaning | Fix |
|---|---|---|
| **Port closed** (refused) | Nothing is listening on the port | The peer's Ragnar is down, crashed, or on another port. `sudo systemctl status ragnar` on that box; check `mesh_node_port`. |
| **Port filtered** (timeout) | The port is blocked, not closed | Your ACL doesn't permit `tag:ragnar-mesh:8000` between units, or a host firewall (ufw/iptables) does. Tailnet membership alone does not open the port. |
| **Rejected** (401) | The peer answered but refused this unit | This unit isn't recognised as a tagged mesh peer. Confirm **this** unit carries the tag (the peer authorises the caller). |
| **Wrong service** | Something else is on the port | Not Ragnar — check the port number. |

The ACL rule most first-time meshes are missing:

```jsonc
{ "action": "accept", "src": ["tag:ragnar-mesh"], "dst": ["tag:ragnar-mesh:8000"] }
```

**"They sense each other but don't share data" / units show "On tailnet · not
in mesh".**
This is the most common first-run confusion, and it is a tagging issue, not a
connection issue. A unit can be fully on the tailnet — you can reach it, and
other units can see it — yet carry no `tag:ragnar-mesh`. The whole mesh keys off
that tag, so Ragnar will not treat an untagged node as a mesh unit and no data
flows. An **interactive `tailscale up` login never applies a tag** (only a
pre-authorized key with `--advertise-tags`, or a manual edit, does), which is
why hand-joined units land here.

The Mesh tab now says so directly: the status pill reads *On tailnet · not in
mesh*, and a banner names the untagged devices. To fix, tag **every** unit:

- *Per device in the console:* Machines → the device → **⋯ → Edit ACL tags** →
  add `tag:ragnar-mesh`.
- *Or re-join with a tagged key:* `tailscale up --advertise-tags=tag:ragnar-mesh`.

The tag must be listed under `tagOwners` in your ACL policy first, e.g.
`"tagOwners": { "tag:ragnar-mesh": ["autogroup:admin"] }`. Tagging also stops
the node key expiring — a double win for a remote unit.

**Units are tagged and connected but still no data.**
Check `mesh_enabled` is `true` on each (Config → Ragnar Mesh, or re-run Join).
Tagging puts a unit *in* the mesh; `mesh_enabled` is what makes it *poll* peers
and pool alerts. The tab flags this case too.

**"The auth key was rejected."**
Expired, already spent (`reusable = false` and already used), or from a
different tailnet. Keys applying a tag also require the key's owner to be listed
in that tag's `tagOwners`.

**Publishing over HTTPS returns 409.**
Kiosk mode is enabled. See [Serve + kiosk is refused](#serve--kiosk-is-refused).

**"HTTPS certificates are not enabled for this tailnet."**
You clicked **Publish (HTTPS)** on a tailnet without certificates. Either enable
**DNS → HTTPS Certificates** in the admin console, or just use **Publish** (the
default, plain HTTP). See
[Publishing: HTTP by default, HTTPS opt-in](#publishing-http-by-default-https-opt-in).
Confirm with:
```sh
tailscale status --json | grep -i certdomains
```
An empty or absent `CertDomains` means certificates cannot be issued.

**`tailscale serve` timed out.**
Fixed in the mesh code — the precondition is now checked before the command
runs. If you hit it from the shell directly, it is the same cause: HTTPS
certificates are off and the command will never return. `Ctrl-C` and use the
HTTP form.

---

## See also

- [Watchtower](watchtower.md) — the unified alert feed each unit publishes
- [Incident correlation](incident-correlation.md) — how alerts become attack chains
- [Authority verification & network tools](nettools.md)
