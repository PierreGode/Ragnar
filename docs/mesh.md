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
  - [Mesh Health card](#mesh-health-card)
  - [Mesh Nodes list and the node page](#mesh-nodes-list-and-the-node-page)
- [Unit identity — the Viking army](#unit-identity--the-viking-army)
- [Tailscale console: one-time setup](#tailscale-console-one-time-setup)
- [Separate meshes on one tailnet](#separate-meshes-on-one-tailnet)
- [Deploying a unit](#deploying-a-unit)
  - [Path 1 — during imaging (unattended)](#path-1--during-imaging-unattended)
  - [Path 2 — during install](#path-2--during-install)
  - [Path 3 — later, from the web UI](#path-3--later-from-the-web-ui)
- [Reaching the whole far-side LAN](#reaching-the-whole-far-side-lan)
- [Backup access when Ragnar itself is wedged](#backup-access-when-ragnar-itself-is-wedged)
- [The Ragnar Mobile app](#the-ragnar-mobile-app)
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

In the web UI (Ragnar Mesh → *This unit's identity*) a 🎲 rolls a fresh random
name from the full historic roster — 136 given names × 48 epithets = 6,528
combinations, drawn from real Viking-age history and the Icelandic sagas (kings
and jarls, explorers, saga figures) — and a custom name lets you pick the
portrait gender explicitly.

The **auto-derived** default name (the one a box is born with) deliberately
draws from the original, frozen 48 × 24 pool, *not* the larger roster. Because
derivation is `hash % pool_size`, growing the pool would remap every seed and
rename boxes that never chose a name — so the default pool is held constant and
the extra names are offered only on demand via the dice. Growing the roster
therefore renames nobody.

Override from the shell with `mesh_viking_name` if you would rather choose:

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

## Tailscale console: one-time setup

Do this **once per tailnet**, before deploying any unit. It creates the tag, an
auth key that carries it, and — only if you want TLS on the friendly hostname —
HTTPS certificates. Everything here happens at
[login.tailscale.com](https://login.tailscale.com); nothing is Ragnar-specific
yet.

### 1. Create the mesh tag (do this first)

A tag is "created" by listing it in your ACL policy under `tagOwners` — there is
no separate button. **Access Controls → edit the policy** and add:

```jsonc
{ "tagOwners": { "tag:ragnar-mesh": ["autogroup:admin"] } }
```

This must exist **before** you can put the tag on an auth key or a device, so do
it first. (Full policy example in [Suggested ACL shape](#suggested-acl-shape).)

> ⚠️ **Use lowercase: `ragnar-mesh`, not `Ragnar-mesh`.** Tailscale tags may only
> contain lowercase letters, numbers and hyphens — an uppercase tag is rejected.
> Ragnar also defaults to `tag:ragnar-mesh` (the `mesh_tag` config), and the tag
> is the mesh's whole authorization boundary, so it must match **exactly** on
> every unit. If you genuinely want a different tag, that's fine — but then set
> `mesh_tag` to the same value on every unit, and keep it lowercase. For almost
> everyone: just use `tag:ragnar-mesh` and change nothing.

So to answer the common question directly: **`Ragnar-mesh` is *not* correct —
use `ragnar-mesh`.**

### 2. Generate a tagged auth key

**Settings → Keys → Generate auth key.** The one setting that matters is the
**tag** — assign `tag:ragnar-mesh` (this is what makes the node key non-expiring
and enrols the unit into the mesh). Then:

| Option | Set to | Why |
|---|---|---|
| **Tags** | `tag:ragnar-mesh` | Authorizes the unit into the mesh; makes its node key never expire. |
| **Reusable** | on for several units, off for one | One reusable key can enrol a whole batch; a single-use key is tidier for one box. |
| **Ephemeral** | **off** | Units must persist across reboots — ephemeral nodes vanish when they disconnect. |
| **Expiration** | short if the key will sit on an SD card | The key only needs to live until the unit powers on and joins; see Path 1. |

Copy the `tskey-auth-…` value — it is shown **once**. That key is what you hand
to Ragnar (boot config, installer, or the **Join** form). You do **not** run
`tailscale up` by hand.

### 3. (Optional) HTTPS certificates

Only needed if you intend to use the **Publish (HTTPS)** button — plain-HTTP
publishing and all unit-to-unit polling work fine without it. **DNS →** confirm
**MagicDNS** is enabled (it usually is) **→ enable HTTPS Certificates.** See
[Publishing: HTTP by default, HTTPS opt-in](#publishing-http-by-default-https-opt-in).

### 4. About "Add a device → Linux server"

You *can* use the console's **Add a device → Linux** flow, but note it just
generates a tagged `tailscale up --authkey=…` command. For Ragnar you don't run
that yourself — take the key and let Ragnar join (any path below), so it applies
the right flags, sets the unit number/label, and advertises subnets for you. A
unit that joins with a **tagged key already carries the tag** and appears in
**Machines** tagged, with no manual step.

If a unit was ever brought up *interactively* (no key, e.g. `tailscale up` by
hand), it will be **untagged** — fix it in **Machines → the device → the ⋯ menu
→ Edit ACL tags → add `tag:ragnar-mesh`**. Ragnar's Mesh tab detects this exact
"on the tailnet but not in the mesh" state and says so.

---

## Separate meshes on one tailnet

One Tailscale account can host **several completely separate Ragnar meshes** at
once. They are told apart only by their tag:

| Mesh | Mesh tag | Share-guest tag |
|---|---|---|
| **Main** (the default) | `tag:ragnar-mesh` | `tag:ragnar-share` |
| A second, isolated mesh | `tag:ragnar-mesh-2` | `tag:ragnar-share-2` |
| Named however you like | `tag:ragnar-mesh-lab` | `tag:ragnar-share-lab` |

The separation is real, not cosmetic. Every trust check
(`caller_is_mesh_peer`) and every peer scan filters on the **exact** tag, so a
unit tagged `tag:ragnar-mesh-2` is invisible to — and rejected by — a
`tag:ragnar-mesh` unit even though they share a coordination server. A unit
publishes to and reads from **only** the mesh whose tag it carries. The share
tag is derived from the mesh tag automatically, so a share-only guest of
`ragnar-mesh-2` carries `ragnar-share-2` and can never reach a host on a
different mesh that happens to share the tailnet.

**When you'd want this:** separate customers or sites that must never see each
other's findings; a `lab` mesh for testing kept apart from `prod`; a managed-
service operator running several independent fleets from one Tailscale account.

**The "mesh name" is just a suffix.** Leave it blank and you get the main mesh —
nothing changes and you can ignore this whole section. Give a short name (`2`,
`lab`, `jersey`) and the unit joins `tag:ragnar-mesh-<name>` instead. The name
is lowercased and reduced to a DNS label (`[a-z0-9-]`), so `Lab 1` becomes
`lab-1`; pasting the whole `tag:ragnar-mesh-2` or `ragnar-mesh-2` also works.

### Console setup for an extra mesh

Each mesh tag is a **separate tag you must own** in the ACL, exactly like the
default one. Add every mesh (and its paired share tag) under `tagOwners`:

```jsonc
{
  "tagOwners": {
    "tag:ragnar-mesh":    ["autogroup:admin"],
    "tag:ragnar-share":   ["autogroup:admin"],
    "tag:ragnar-mesh-2":  ["autogroup:admin"],
    "tag:ragnar-share-2": ["autogroup:admin"]
  }
}
```

Then generate a tagged auth key carrying `tag:ragnar-mesh-2` for units that
belong to that mesh, and keep the `grants`/`acls` rules scoped **within** each
tag (`src` and `dst` both `tag:ragnar-mesh-2`) so the two meshes stay isolated
at the network layer too, not only in Ragnar.

### How to set the mesh name

- **Web UI (Join form):** the **Mesh name** field. Blank = main mesh.
- **Installer (interactive):** the installer asks for a mesh name after the site
  label.
- **Unattended / boot config:** set `RAGNAR_MESH_SUFFIX="2"` (friendly form) or
  `RAGNAR_MESH_TAG="tag:ragnar-mesh-2"` (explicit full tag). The explicit tag
  wins if both are set.

A unit records the mesh it joined in its `mesh_tag` config, so a later re-join
from the web UI keeps it on the same mesh unless you change the field.

### Hardening a shared tailnet: the mesh secret

The tag says "this node is in mesh X". On a **shared** tailnet that is only as
trustworthy as your ACL's `tagOwners`: a misconfiguration — or anyone with
console/admin access to the account — could tag a hostile box into another
customer's mesh, and the tag check alone would then accept it. The **mesh
secret** closes that gap.

It is a per-mesh pre-shared key. Every legitimate unit of one mesh holds the
same secret; each request carries an HMAC proof of it (never the raw secret, so
a connecting attacker cannot harvest it). A box that merely forged the tag has
no secret, produces no valid proof, and is **rejected**. Membership now needs
**both** the tag **and** the secret — one ACL slip is no longer a breach.

- **Opt-in.** Enforced only when a mesh has a secret set. A mesh with no secret
  behaves exactly as before, so nothing breaks on update.
- **It does not replace locking `tagOwners`** — it is the safety net so a single
  misconfiguration is not fatal. Keep doing both.
- **It is a shared secret.** Whoever can already read files off a member box has
  it — but they would already own that box.

**Arm it:**

- **Web UI (Join form):** the **Mesh secret** field. On the *first* unit of a new
  mesh, tick **Generate** — Ragnar mints a strong secret and **downloads it as a
  file** the moment the unit joins. The secret is **never shown on screen and
  cannot be retrieved** afterwards; that download is your one copy. Open the file
  and paste the value into the **Mesh secret** field when you join every other
  unit of that mesh. Lost it? **Leave** and re-join to mint a new one.
- **Unattended / boot config:** set `RAGNAR_MESH_SECRET="rms_…"` (the same value
  on every unit of the mesh).

**Moving a unit to another mesh** is deliberately a re-provision, not a silent
edit: **Leave the mesh** (this logs the unit out of the tailnet — it stays
installed and drops its old secret), then **Join** the new mesh with its own
auth key *and* its own secret. Editing the tag in the Tailscale console alone
does **not** move a unit cleanly.

> **Genuinely separate customers?** The strongest isolation is still a separate
> Tailscale account per customer — one account is one administrative trust
> boundary. Tags + a mesh secret segment *within* one account and are solid
> defence-in-depth, but they cannot undo an admin who can retag from the console.

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
# Optional — place this box in a separate mesh (see "Separate meshes on one
# tailnet"). Blank/omitted = the main mesh. The key's tag must match.
# RAGNAR_MESH_SUFFIX="2"
# Optional — arm the mesh secret (same value on every unit of the mesh).
# RAGNAR_MESH_SECRET="rms_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
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
   advertise. Leave **Mesh name** blank for the main mesh, or name a
   [separate mesh](#separate-meshes-on-one-tailnet). Joining sets `mesh_enabled`,
   which is what makes every subsequent `update_ragnar.sh` keep Tailscale
   installed and current.

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

## The Ragnar Mobile app

[Ragnar Mobile](https://github.com/PierreGode/Ragnarmobile) (iOS + Android) is a
first-class mesh client. It does **not** connect to a unit by local IP and has
no Bluetooth path — it reaches units exclusively over the mesh, which is what
makes one phone able to jump between a box on your desk and a box in a data
centre without reconfiguration.

**How it finds units — and why it needs no Tailscale token.** The app never
talks to the Tailscale API. It connects to one unit and reads that unit's
[`/api/mesh/status`](#mesh-nodes-list-and-the-node-page), which already lists
every peer (Viking name, `100.x` address, online state, tag) because the unit
speaks to its own `tailscaled`. So a single login exposes the whole fleet, and
switching units just repoints the app at another peer's `http://<100.x>:8000`.

**What the operator needs, once:**

1. **Tailscale connected on the phone**, signed into the same tailnet as the
   units. This is what makes the `100.x` addresses reachable.
2. **One unit's Tailscale address** typed into the app — its MagicDNS name
   (`bjorn.tailXXXX.ts.net`) or `100.x` — plus a normal Ragnar login. Every
   other unit is then discovered from the mesh; nothing else is entered.

**Why this is safe.** The app authenticates to each unit exactly as the web UI
does — Ragnar's existing session login (`/api/auth/login`). The mesh reaching a
unit is not the same as being authorized on it: an operator's phone is a real
tailnet node and must still sign in, precisely as
[the mesh security model](#unit-to-unit-authentication) requires of any
non-unit caller. Reading `/api/mesh/status` is a session-authenticated GET, the
same as any other read the app makes.

For units to answer the phone on port 8000, the tailnet ACL must permit it —
the [suggested ACL shape](#suggested-acl-shape) already opens
`tag:ragnar-mesh:8000` between mesh members; add the operator's user or device
as a source there too if the phone is not itself tagged.

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
| Methods | Any `GET` for reads, plus a short **exact-path** write allowlist: `POST /api/mesh/control`, the scan-delegation writes, and `POST /api/mesh/update` |
| Paths | `/api/mesh/*` for reads; each write is matched by **exact path** so `join`/`leave`/`serve`/`peer-control`/`update-all` stay session-only. The other ~290 routes stay session-gated |
| Identity | Must carry `mesh_tag` (default `tag:ragnar-mesh`) |
| Source | Must be a real tailnet address (100.64/10 or `fd7a:115c:a1e0::/48`) |
| Loopback | Rejected — a proxied request's true origin is unknowable at that layer |
| Failure | Fails closed: no Tailscale, no answer, or no tag ⇒ 401 |

**Tailnet membership alone is not enough.** Your laptop is a fully authenticated
tailnet node; it is not a Ragnar unit, and it must log in like anyone else.
Without the tag check, every phone and laptop on the tailnet would inherit
Ragnar's full toolset.

Peer-readable routes:

- `GET /api/mesh/unit` — this unit's health report
- `GET /api/mesh/alerts` — this unit's recent Watchtower alerts
- `GET /api/mesh/findings` — this unit's security findings + per-feature summaries

### Remote scan control

The mesh is read-mostly, but a tagged peer may also **start and stop the four
monitors** on another unit — traffic analyzer, external threat monitor, network
integrity monitor, and Watchtower — so the fleet can be driven from any single
pane rather than SSHing box to box.

This is the one write the peer gate allows, and it is fenced in on every side:

- **One route.** `POST /api/mesh/control`, matched by exact path. Nothing else
  accepts a peer write.
- **Body is itself an allowlist.** The payload is `{feature, action}` where
  `feature ∈ {traffic, threats, integrity, watchtower}` and
  `action ∈ {start, stop}`. There is no free-form command; an unknown feature or
  action is a 400. See `_MESH_CONTROLLABLE` / `_mesh_apply_control`.
- **Idempotent.** Starting a running monitor (or stopping a stopped one) is a
  success, so a button press converges to the asked state.
- **Symmetric, by design.** Any tagged unit can control any other — the
  controller-free "Viking army" model, where the tag *is* the trust boundary.
  A unit that carries the mesh tag is already fully trusted (it can read every
  other unit's findings); letting it also flip a monitor adds no principal that
  could not already observe everything. If you do not want a unit actuated
  remotely, do not tag it into the mesh.

The operator's browser never talks to a peer directly (it is not on the
tailnet). Clicking Start/Stop on the node page POSTs to the **local** unit's
`/api/mesh/peer-control`, which relays the command over the tailnet with the
peer's WireGuard identity — exactly how peer data is pulled. A command aimed at
the local unit is applied directly with no network hop.

### Fleet update — "Update mesh"

The **Update mesh** card at the bottom of the Ragnar Mesh tab runs the same git
update as *Config → Updates*, but across the whole fleet in one press. Clicking
**Update all units** POSTs to the local unit's `/api/mesh/update-all`, which:

- updates this unit directly (no network hop), and
- relays `POST /api/mesh/update` to every tagged peer over the tailnet, in
  parallel, with the peer's WireGuard identity — the same relay pattern as
  peer-control and polling.

Each node runs `git_updater.update` against **its own** checkout. `/api/mesh/update`
is the second exact-path peer write on the gate: a peer can make this unit *run an
update*, but it can never choose *what* runs — only `git_updater` against this
checkout is ever invoked.

- **Only updates a unit that is behind.** A node already on the latest commit is
  a genuine no-op — it does not reinstall dependencies and it does **not** restart.
  Only a node that actually pulls new code runs post-update and restarts itself.
- **Self last.** The fan-out updates every peer first and this unit last, so the
  results have been collected before this box restarts; the restart is detached,
  so the response still reaches the browser.
- **One line per node.** The card reports each unit's outcome: `already up to
  date`, `updated → <commit>, restarting`, `unreachable`, or the error.

The card also shows two live counters — **available units in the mesh** (reachable
Ragnar units, including this one) and **with pending updates** (how many of those
are behind). The pending count rides in each unit's `/api/mesh/unit` report as an
`update` block. A git fetch on every peer poll would be far too expensive on a Pi
Zero, so each unit refreshes its own update posture on a throttle (`_MESH_UPDATE_TTL`,
15 min) and serves it from cache in between — the count can therefore trail reality
by up to that window.

Because updating restarts any unit that changes, the card confirms before it runs.

### Fleet deployment — export / import config

Bringing up several Ragnars by hand means flipping the same switches on every
unit. The **Fleet Config** card (*Config tab → System Management*) removes that:
configure one unit the way you want, **Export Config** to a JSON file, then
**Import Config** on each of the others so the same options come up identically.

- **Export** (`GET /api/config/export`) downloads a portable
  `ragnar-config-<host>-<timestamp>.json`. It carries the feature switches,
  intervals, list settings and notification preferences — **not** secrets or
  per-unit state. Secret placeholders (the OpenAI token lives in `.env`, never
  the config) and device-local keys (`mac_scan_blacklist`,
  `rusense_node_positions`/`_names`, `web_bind_interface`) are stripped, and
  display/hardware keys are split into their own group.
- **Import** (`POST /api/config/import`) applies the file through the *same*
  code path as a normal Settings save, so imported toggles fire their real side
  effects (kiosk install/teardown, AI reload, socket refresh). It accepts the
  exported file or a hand-edited flat config dict; excluded keys are dropped
  again defensively whatever the shape.
- **Display & hardware settings** (`epd_type`, orientation, brightness, i2c
  addresses, …) are **skipped by default** — leave the checkbox off when units
  have different screens, so an imported `epd_type` can't restart the service or
  blank the panel on a unit with a different display. Tick *"Also apply display
  & hardware settings"* only for an identical fleet.

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

Each unit serves its own findings at `GET /api/mesh/findings`. A coordinator
does not compute anything about its peers; it just displays what each already
found. See [Mesh Nodes list and the node page](#mesh-nodes-list-and-the-node-page) for the node page.

### Mesh Health card

Above the node list sits a single **Mesh Health** card — the answer to "is
anything wrong across the fleet?" without scrolling thousands of rows. It is
rolled up **server-side** (`summary.health` in `GET /api/mesh/status`), so the
browser only paints six counts and a few chips no matter how large the mesh is:

- **Nodes / Online / Need attention / Unreachable / Open alerts / Open incidents.**
  A node "needs attention" if it is unreachable, its node key is expiring, it
  reports undervoltage, or it is carrying a high/critical finding.
- A **headline** pill — green *All clear* when nothing needs attention, otherwise
  coloured by the worst finding anywhere in the mesh.
- A **severity distribution** (how many nodes are at each worst severity) and
  **condition chips** (undervoltage, key expiring, not polled yet, published)
  that appear only when non-zero, so a healthy mesh stays quiet.

### Mesh Nodes list and the node page

The **Mesh Nodes** list is a flat column of compact **banner rows**, one per
node — name, unit number, location (site label), IP, online/offline, alert and
incident counts, a worst-severity badge, a **Published** badge, and an **Open**
button. Rows are deliberately light: a mesh of hundreds of them is still a small
DOM, so the list stays responsive even on a Pi Zero. Heavy per-feature detail is
*not* rendered for the list — only for the single node you open.

**Open** swaps the list for the **node page**: one generic full page that renders
whichever node you opened — its resource metrics, each feature's live view
(Traffic throughput and protocol mix; threat-intel risk counts; the integrity
monitor's per-check verdicts; recent Watchtower alerts; the vulnerability list),
the remote Start/Stop controls, and the direct link. Only one node's detail is
live at a time, which is what keeps a large mesh affordable in the browser. A
**← Back to Mesh Nodes** button returns to the list.

All of it renders **from the unit you are looking at**: it already pulled each
peer's data over the tailnet, so the page needs **no connection between your
browser and the peer**. This matters because tailnet IPs (`100.x.y.z`) are only
reachable from devices *on* the tailnet — if you are browsing this UI over the
LAN or a tunnel, your browser cannot open a peer's `100.x.y.z:8000` directly, but
the node page still works because the Ragnar server did the fetching.

The node page also carries an *"Open full UI ↗"* link that opens that unit's own
web UI in a new tab — clearly caveated ("tailnet only"): unlike the page itself
(which renders from pulled data), a direct link only works when your **browser**
is itself on the tailnet, because a peer's `100.x` address / MagicDNS name is
only routable from tailnet members. The link prefers the unit's **published**
hostname when it reports one — a green **Published** badge appears alongside —
and falls back to `http://<tailnet-ip>:<port>` otherwise. Publish state is local
to each node (Tailscale does not share it), so each unit reports its own in
`GET /api/mesh/unit` and peers display it.

Beyond showing what each unit found, the node page can **start and stop that
unit's monitor remotely** — a Start/Stop control appears for the four
controllable features (Traffic, Threats, Integrity, Watchtower), reflecting the
live running state. The command is relayed server-side over the tailnet; see
[Remote scan control](#remote-scan-control) for the security model. Any tagged
unit can drive any other — the trust boundary is the mesh tag, so the way to
keep a unit from being actuated remotely is simply not to tag it into the mesh.

## File transfer

The **Ragnar Mesh → File Transfer** sub-tab moves files between units. Transport
reuses the mesh channel — plain HTTP to a peer's `http://[tailnet-ip]:8000`, which
Tailscale already wraps in **WireGuard**, so nothing is added to encrypt the wire.
Authorization is the same **WireGuard-identity + mesh-tag** check as every other
peer call: the receiver's `POST /api/mesh/files/push` is exact-path allowlisted for
tagged peers and does nothing but write into a **quarantined inbox** — never a live
folder. A unit can refuse incoming files entirely (**Accept incoming** toggle /
`mesh_file_receive`).

Flow:

- **Send** — pick a destination unit, then either drag-and-drop a file from your
  computer, **browse this unit's own files** (“Send a file from this unit” opens a
  picker over Uploads/Backups and the scan/loot folders), or use the **Send**
  (paper-plane) action on any row in the **Files** tab. Files already on the unit
  stream straight to the peer; a file dropped from your machine is staged on the
  unit first. Sends run in the background with live progress.
- **Vault files** can be sent too: an unlocked Vault decrypts the file on send. Note
  it then exists as plaintext on the receiving unit's disk (the link itself stays
  WireGuard-encrypted) until the operator files it.
- **Receive** — arrivals land in the unit's **Inbox** (under `data/mesh_inbox/`,
  gitignored). The receiving operator picks where each file goes — an Uploads/Backups
  folder, or the Vault — with **Save**, or drops it with **Discard**. Nothing is
  auto-filed. A badge appears on the **Inbox** entry in the Files-tab Directories
  list and on the File Transfer sub-tab.

Endpoints: `POST /api/mesh/files/push` (receiver), `POST /api/mesh/files/send`
(operator), `GET /api/mesh/transfers`, `GET /api/mesh/inbox`,
`POST /api/mesh/inbox/{save,discard}`, `POST /api/mesh/files/config`. Per-file size
ceiling is 4 GB.

## Mesh Share

> **Detailed guide:** [mesh-share.md](mesh-share.md) covers the full picture —
> the Mesh Share folder, direct transfers, and all three ways to share with
> someone **outside** your mesh (tag-guest, share-only Join, and token +
> node-share/Funnel), with step-by-step "who does what".

The **Ragnar Mesh → Mesh Share** sub-tab is a folder every unit publishes to the
whole mesh. It is **not** a central store: each unit serves its own shared list
(`data/mesh_share/`), and the catalog is assembled on demand by asking every online
peer for theirs. Each entry shows the **filename** and its **owner** (the Viking
name of the unit that actually holds the file).

- **Share files** — publish file(s) from your computer to this unit's shared folder;
  they immediately appear mesh-wide with you as the owner.
- **Fetch** — pull any peer's shared file **directly from its owner** (peer-to-peer
  over Tailscale) and save it into a folder you pick — an Uploads/Backups folder or
  the Vault. The file only leaves the owner when someone fetches it.
- **Unshare** — stop publishing one of your own files (the file itself is not
  deleted).

The listing (`GET /api/mesh/share/local`) and the file stream
(`GET /api/mesh/share/download`) are plain reads, so they use the mesh's existing
WireGuard-identity + tag authorization; publishing, fetching and unsharing are
operator-only (`POST /api/mesh/share/{add,remove,fetch}`), and `GET /api/mesh/share`
is the aggregate catalog.

### Share-only guest access (`tag:ragnar-share`)

Sometimes you want to let **one outside person** send files to your Ragnar —
without making them a full mesh unit, without them seeing your other Ragnars, and
without any other action or view. That is what the **share-guest** role is for.

A share-guest is a device that joins **your** tailnet carrying the tag
`tag:ragnar-share` (not `tag:ragnar-mesh`). Ragnar recognises that tag and grants
it exactly one capability by default:

- **Send files to you** — `POST /api/mesh/files/push` (lands in your quarantined
  inbox, same as any mesh transfer; you still choose where each file is saved).

Everything else — the dashboard, scan control, node lists, findings, config, even
the *list* of what is in your Mesh Share — is denied. The guest does not appear as
a Ragnar in your mesh, and cannot enumerate your other units.

Optionally, you can let share-guests also **browse and fetch** your Mesh Share
folder (read-only): toggle **"Let share-guests browse & fetch this folder"** in
**Ragnar Mesh → Mesh Share**. Off by default (send-only). This flips
`mesh_share_guest_read`, which opens *only* `GET /api/mesh/share/local` and
`GET /api/mesh/share/download` to the guest tag — never the operator write routes.

#### One tailnet, two tags

The guest joins the **same tailnet as your Ragnar** — there is no second Tailscale
network. Tailscale can only bind one node to one tailnet at a time, so this works
cleanly when the guest is a plain Tailscale client (a phone or laptop with the app
+ a browser), not a second Ragnar that is already meshed elsewhere. The wall
between "guest" and "unit" is the **tag + ACL**, not a separate network.

#### Setup — the owner mints a tagged auth key

1. In the Tailscale admin console, allow the tag and scope it to *only* your
   Ragnar's web port:

   ```jsonc
   {
     "tagOwners": {
       "tag:ragnar-mesh":  ["autogroup:admin"],
       "tag:ragnar-share": ["autogroup:admin"]
     },
     "acls": [
       // your units talk to each other (unchanged)
       { "action": "accept", "src": ["tag:ragnar-mesh"],
         "dst": ["tag:ragnar-mesh:8000"] },
       // a share-guest may reach ONLY this one Ragnar, ONLY on :8000.
       // Pin dst to your receiving unit's tag or IP — never tag:ragnar-mesh,
       // or the guest could reach every unit.
       { "action": "accept", "src": ["tag:ragnar-share"],
         "dst": ["tag:ragnar-mesh:8000"] }
     ]
   }
   ```

   Tighten `dst` to a single host (e.g. the unit's Tailscale IP `100.x.y.z:8000`)
   if you do not want the guest reachable to every `tag:ragnar-mesh` unit.

2. Generate a **pre-authorized, tagged** auth key (Settings → Keys → Generate auth
   key → *Tags:* `tag:ragnar-share`). Hand that key to the guest.

3. The guest joins your tailnet with it:

   ```bash
   tailscale up --authkey=tskey-auth-... --advertise-tags=tag:ragnar-share
   ```

   …then opens `http://<your-ragnar-tailscale-ip>:8000` and sends you files. They
   see only your one unit's send surface — nothing else.

The share tag Ragnar trusts defaults to the one paired with this unit's mesh —
`tag:ragnar-share` on the main mesh, `tag:ragnar-share-2` on `ragnar-mesh-2`
(see [Separate meshes on one tailnet](#separate-meshes-on-one-tailnet)), so
guests stay confined to the mesh they joined. Override it explicitly with
`mesh_share_tag` in config if you need a different tag. Revoking access is one
click in the Tailscale console — disable the key or the guest's node.

### Share tokens & remote shares (Ragnar ↔ Ragnar, across tailnets)

The tag model above needs the sender to live on **your** tailnet. When both sides
already run their own separate mesh — two Ragnars in different orgs — a node can't
join a second tailnet, so tag identity can't carry. For that case Ragnar adds a
**share token**: a secret the receiver issues and the sender presents as an HTTP
`Authorization: Bearer` header. Auth is the token, not the tailnet, so it works
over Tailscale **node-sharing** or **Funnel** between separate tailnets. A valid
token grants exactly one thing — `POST /api/mesh/files/push` into the inbox — and
honours the same `mesh_file_receive` off-switch. Both sides drive it entirely from
**Ragnar Mesh → Mesh Share → Outside your mesh**; no Tailscale-console step.

**To let someone send to you** (you are the receiver):

1. **Share tokens → + New token**, name it for the person. The full token
   (`rgnr-share-…`) is shown **once** — copy it. The list afterwards shows only a
   masked preview; lost tokens are revoked, not recovered.
2. Give them that token plus this unit's Tailscale address (`100.x.y.z:8000`, or a
   MagicDNS name / Funnel URL if the two of you are on different tailnets).
3. **Revoke** removes the row and the token stops working immediately.

**To send to a remote** (you are the sender):

1. **Remote shares → + Add remote share**: a **name**, their **address**, and the
   **token** they gave you.
2. Each saved remote gets a **Send file** button; transfers show up in the normal
   **Transfers** list with SHA-256 integrity checking, same as a mesh send.

Reaching a remote on a *different* tailnet still needs a network path — share that
one Ragnar node to the other tailnet (Tailscale **node-sharing**), or expose
`:8000` with **Funnel**. Same-tailnet remotes just work. Config keys:
`mesh_share_tokens` (issued tokens, secret) and `mesh_remote_shares` (saved
targets, holds their tokens) — both live only in this unit's config, never synced.

| Route | Who | What |
|---|---|---|
| `POST /api/mesh/files/push` | share-guest **or** valid token | drop one file in the inbox |
| `GET /api/mesh/share/{local,download}` | share-guest, if `mesh_share_guest_read` | browse/fetch Mesh Share |
| `GET/POST/DELETE /api/mesh/share/tokens` | operator | issue/list(masked)/revoke tokens |
| `GET/POST/DELETE /api/mesh/remote-shares[/…]` | operator | manage send targets |
| `POST /api/mesh/remote-shares/<id>/send` | operator | send a file to a saved remote |

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
| `mesh_tab_enabled` | `true` | Show the Ragnar Mesh **tab** in the UI. Cosmetic only — hiding it never joins/leaves the mesh. Toggle in Config → Ragnar Mesh. |
| `mesh_enabled` | `false` | Master switch. Off means no peer polling at all. |
| `mesh_tag` | `tag:ragnar-mesh` | Authorization boundary for unit-to-unit calls — and which mesh this unit belongs to. Suffixed tags (`tag:ragnar-mesh-2`) select a [separate mesh](#separate-meshes-on-one-tailnet). Set via the Join form's **Mesh name**, not usually by hand. |
| `mesh_secret` | `""` | Opt-in **second factor over the tag** (see [Hardening a shared tailnet](#hardening-a-shared-tailnet-the-mesh-secret)). All units of one mesh share it; peers must prove it in addition to the tag. Blank = tag-only. Set via the Join form's **Mesh secret**; cleared on **Leave**. A generated secret is **downloaded once** at join and never shown on screen or retrievable through the UI (status exposes only a "set" boolean). |
| `mesh_unit_id` | `0` | This unit's number. `0` = unassigned. |
| `mesh_viking_name` | `""` | This unit's name. Blank = derive from the machine itself. |
| `mesh_site_label` | `""` | Where the box physically is ("Jersey DC"). |
| `mesh_node_port` | `8000` | Port peers serve their API on. |
| `mesh_poll_interval` | `60` | Seconds between peer refreshes (minimum 15). |
| `mesh_poll_timeout` | `6` | Per-peer HTTP timeout. Kept short so one dead unit cannot stall the view. |
| `mesh_aggregate_alerts` | `true` | Pull peers' alerts into the local incident engine. |
| `mesh_alert_limit` | `50` | Max alerts pulled per peer per poll. |
| `mesh_share_tag` | derived from `mesh_tag` | Tailscale tag trusted for **share-only guests** (send files to this unit, nothing else). Defaults to the share tag paired with this unit's mesh (`tag:ragnar-share`, or `tag:ragnar-share-2` on `ragnar-mesh-2`); set explicitly only to override. |
| `mesh_share_guest_read` | `false` | Also let share-guests browse & fetch the Mesh Share folder (read-only). Off = send-only. |
| `mesh_share_tokens` | `[]` | Secret **share tokens** this unit issued; a remote presents one (Bearer) to push into the inbox. Managed from the UI. |
| `mesh_remote_shares` | `[]` | Saved outbound **remote-share** targets (name + address + their token) this unit can send files to. |

Environment variables (imaging / unattended):
`RAGNAR_MESH_AUTHKEY`, `RAGNAR_MESH_UNIT_ID`, `RAGNAR_MESH_LABEL`,
`RAGNAR_MESH_ROUTES`, `RAGNAR_MESH_HOSTNAME`, `RAGNAR_MESH_TAG`,
`RAGNAR_MESH_SUFFIX` (friendly form of the mesh tag — `2` ⇒ `tag:ragnar-mesh-2`;
`RAGNAR_MESH_TAG` wins if both are set), `RAGNAR_MESH_SECRET` (the opt-in mesh
secret — set the same value on every unit of the mesh).

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
