# Mesh Share & File Transfer

How Ragnar units move files to each other, and how you let someone **outside**
your mesh send you files — safely, over Tailscale, without giving them anything
else.

This is the detailed reference. For the wider mesh (auth model, ACLs, fleet
update, incident correlation) see [mesh.md](mesh.md).

---

## The one idea to hold on to

There are **two separate jobs** in every scenario here. Keeping them apart makes
the rest obvious:

| Job | Who does it | Notes |
|---|---|---|
| **Transport** — get the bytes from A to B, through firewalls/NAT | **Tailscale, always** | This is Tailscale's whole purpose. Nothing in Ragnar replaces it. |
| **Authorization** — decide *who* is allowed to do *what* | **Ragnar** (a tag, or a token) | This is the only thing the tag/token does. |

So "authenticated by a token, not the tailnet" only ever means *the token decides
who's allowed*. **Tailscale still carries the traffic, encrypted, every time.**

The second rule that governs everything below:

> **A machine can only be on ONE tailnet at a time.**
> Joining a second tailnet *removes* the machine from the first. This is a
> Tailscale fact, not a Ragnar limitation, and it's why there are several options
> instead of one.

---

## Part 1 — Mesh Share (inside your own mesh)

**Ragnar Mesh → Mesh Share** is a folder every unit in *your* mesh publishes to
the whole mesh. It is **not** a central store: each unit keeps its own shared
list under `data/mesh_share/`, and the catalog is assembled on demand by asking
every online peer for theirs. Each entry shows the **filename** and its **owner**
(the Viking name of the unit that actually holds the file).

| Button | What it does |
|---|---|
| **⬆ Share files** | Publish file(s) from your computer to *this* unit's shared folder. They appear mesh-wide immediately, with you as owner. |
| **Fetch** | Pull a peer's shared file **directly from its owner** (peer-to-peer over Tailscale) into a folder you pick — an Uploads/Backups folder or the Vault. The file only leaves the owner when someone fetches it. |
| **Unshare** | Stop publishing one of your own files. The file itself is not deleted. |

Who can do what here: publishing, fetching and unsharing are **operator-only**
(your login). Reads (`/api/mesh/share/local`, `/api/mesh/share/download`) use the
mesh's normal WireGuard-identity + `tag:ragnar-mesh` authorization, so only your
own units see the catalog.

### Direct unit-to-unit transfer

Separately from the shared folder, you can push a single file straight to one
peer's **inbox** (Mesh → File Transfer, or the per-row **Send** in Files). The
file lands quarantined; the receiving operator chooses where to save it (an
Uploads/Backups folder, or the Vault). Transfers are streamed with **SHA-256**
integrity checking and shown in the **Transfers** list. A unit can turn receiving
off entirely with **Accept incoming** (`mesh_file_receive`).

---

## Part 2 — Sharing with someone OUTSIDE your mesh

Everything in this part lives in **Ragnar Mesh → Mesh Share → "Outside your
mesh"**. The goal is always the same: let one outside person move files to/from
you, and **nothing else** — no dashboard, no scans, no roster, no other units.

Ragnar gives that person one of two *roles*, and the traffic reaches you by one of
three *network paths*. Pick the row that matches your situation:

| Your situation | Role | Network path | Section |
|---|---|---|---|
| The other side is a **plain device** (phone/laptop) or a Ragnar **not yet on any tailnet** | Tag: `tag:ragnar-share` | They join **your** tailnet | [2A](#2a-tag-based-share-guest-the-simple-case) |
| A Ragnar that's **on your tailnet** should instead become a share-only guest **on someone else's** tailnet | Tag: `tag:ragnar-share` | It **switches** tailnets (leaves yours) | [2B](#2b-join-share-only-switch-a-box-onto-their-tailnet) |
| **Both** boxes must stay on their **own separate** meshes at the same time | Token: `rgnr-share-…` | **Node-share** or **Funnel** bridges the two tailnets | [2C](#2c-share-token--remote-share-two-separate-meshes) |

> Rule of thumb: **if either side can join the other's tailnet, use the tag
> (2A/2B) — it's the simplest and exposes nothing.** Reach for the token (2C) only
> when both sides are locked to their own mesh.

---

### 2A — Tag-based share-guest (the simple case)

The outside sender joins **your** tailnet carrying `tag:ragnar-share`. Tailscale
connects them to your box straight through both firewalls (that's what Tailscale
does), and the tag confines them to send-only.

```
Their device (USA)                       Your Ragnar (Sweden)
┌──────────────────┐                     ┌──────────────────┐
│ Tailscale        │◄──── Tailscale ────►│ Tailscale        │
│ tag:ragnar-share │   NAT traversal     │ tag:ragnar-mesh  │
└──────────────────┘   (both firewalled) └──────────────────┘
        └── joins YOUR tailnet with the auth key you gave them ──┘
```

**You (the receiver) do:**

1. In the Tailscale admin console, allow the tag and scope it to *only* your
   Ragnar's web port (see the [ACL snippet](#tailscale-acl-for-the-share-tag)).
2. Generate a **pre-authorized auth key** tagged `tag:ragnar-share`
   (Settings → Keys → Generate auth key → *Tags:* `tag:ragnar-share`).
3. Send that key to the other person.

**They do:** join your tailnet with it, then open `http://<your-tailscale-ip>:8000`
and send. Either

- run `tailscale up --authkey=… --advertise-tags=tag:ragnar-share` themselves, or
- if their side is a Ragnar, use its **🔗 Join a tailnet (share-only)** button
  (see [2B](#2b-join-share-only-switch-a-box-onto-their-tailnet)) — no terminal.

**What they can do:** exactly one thing — `POST /api/mesh/files/push` into your
inbox. Optionally you can also let share-guests **browse & fetch your Mesh Share**
folder (read-only) with the **"Let share-guests browse & fetch this folder"**
toggle (`mesh_share_guest_read`, off by default). Everything else is denied; they
never appear as a unit and can't enumerate your other boxes.

---

### 2B — Join (share-only): switch a box onto their tailnet

Use this when **a Ragnar of yours** should become a share-only guest on **someone
else's** tailnet, driven from the web UI instead of a terminal.

**Ragnar Mesh → Mesh Share → 🔗 Join a tailnet (share-only)** → paste the auth key
they gave you (tagged `tag:ragnar-share`) → **Join**. Ragnar logs out of its
current tailnet first, then joins theirs advertising `tag:ragnar-share`, with SSH
and route-acceptance off.

> ⚠ **This moves the box.** Because of the one-tailnet rule, if the unit was in
> your own mesh, joining here **removes it from your mesh** and puts it on theirs.
> If you want it to stay in your mesh *and* reach their tailnet, don't use Join —
> use [2C](#2c-share-token--remote-share-two-separate-meshes) instead.

Under the hood this calls `POST /api/mesh/join` with
`tags:["tag:ragnar-share"]` and `switch_tailnet:true` (the logout-first switch).
The join is recorded locally (`mesh_share_only`), so this box knows it is a guest
even if Tailscale doesn't echo the tag back on `Self`.

**What a share-only unit sees on its own screen:** the shared **folder**, but not
the mesh. Its Ragnar Mesh tab shows a *"share-only guest"* notice and **no peer
roster** (no fleet summary, no mesh controls, no device monitoring). Its **Mesh
Share tab is fully live**, though: it sees every unit's shared files and can fetch
them (each host must have enabled **Let share-guests browse & fetch**), and mesh
units can **send files to it** — it appears in their File Transfer picker as a
*(guest)* recipient and receives into its inbox. The host-only *"Outside your
mesh"* tools (issue tokens, add remote shares, join a tailnet) and the guest-read
toggle are hidden on a guest — a guest hosts nobody.

> **Two things are separate:** the **roster** (who's a monitored mesh unit — a
> guest is *not* on it) and the **share folder** (a shared drop-zone — a guest
> *is* a full participant, both fetching and receiving).
(The Tailscale ACL is what actually confines it on the wire; the UI just stops it
enumerating machines it has no business in.)

---

### 2C — Share token + remote share (two separate meshes)

Use this when **both** boxes must stay on their **own** separate meshes — e.g. two
Ragnar fleets in different orgs. Neither can join the other's tailnet, so tag
identity can't carry. Instead the receiver issues a **share token** — a secret the
sender presents as an HTTP `Authorization: Bearer` header. Tailscale still carries
the traffic; the token just authorizes the one push.

Because the two are on different tailnets, you also need a **network bridge**
between them — one of:

| Bridge | Reachable by | Privacy | When |
|---|---|---|---|
| **Node-sharing** | only who you share the node with | 🔒 WireGuard, private | **Preferred.** Share the one receiving Ragnar node to the sender. |
| **Funnel** | anyone on the internet with the URL | 🔓 TLS-encrypted but public | Only if node-sharing isn't possible. **The token is then the only thing stopping strangers — never run Funnel without it.** |

**Receiver (you) do:**

1. **Share tokens → + New token**, name it. The full token (`rgnr-share-…`) is
   shown **once** — copy it. The list afterward shows only a masked preview; a
   lost token is revoked and re-issued, not recovered.
2. Give the token + your unit's Tailscale address to the sender.
3. Bridge the network: **share this Ragnar node** to them (Tailscale
   Machines → your node → Share…), or enable **Funnel** on `:8000`.

**Sender (them) do:**

1. **Remote shares → + Add remote share**: a **name**, your **address**
   (`100.x.y.z:8000`, MagicDNS name, or Funnel URL), and the **token** you gave.
2. Use the per-row **Send file** button. Transfers appear in the normal Transfers
   list with SHA-256 checking.

**Is node-sharing giving them my whole Ragnar?** No, on two counts:

- **Tailscale ACL** scopes the share to one port — pin it to `:8000` so they
  can't reach SSH (22) or anything else:
  ```jsonc
  { "action": "accept", "src": ["them@example.com"], "dst": ["<your-node>:8000"] }
  ```
- **Ragnar's own auth** caps `:8000` anyway — the dashboard/files/scans need your
  login; the token unlocks only "push a file to the inbox." So the real exposure
  is identical to any share-guest: *they can drop a file in your inbox.*

**The token has no permissions to configure.** It's a plain secret; Ragnar
hard-limits what it grants (`POST /api/mesh/files/push`, nothing else). Don't
confuse it with a Tailscale auth key (`tskey-…`, used only for *joining*).

---

## Roles at a glance — who can do what

| Capability | Operator (your login) | Mesh peer `tag:ragnar-mesh` | Share-guest `tag:ragnar-share` | Token holder `rgnr-share-…` |
|---|:--:|:--:|:--:|:--:|
| Dashboard, scans, config, files | ✅ | — | — | — |
| Read any `/api/mesh/*` (roster, findings, health) | ✅ | ✅ (GET) | — | — |
| Push a file to the inbox (`/api/mesh/files/push`) | ✅ | ✅ | ✅ | ✅ |
| Browse/fetch Mesh Share (`/share/local`, `/share/download`) | ✅ | ✅ | only if `mesh_share_guest_read` | — |
| Issue/revoke tokens, manage remote shares | ✅ | — | — | — |
| Appears as a unit in your mesh | — | ✅ | ❌ | ❌ |

All non-operator pushes still honour the **Accept incoming** off-switch
(`mesh_file_receive`) — turning receiving off stops guests and token holders too.
Everything fails **closed**: no tailscaled, no valid tag, or no valid token ⇒ 401.

---

## Tailscale ACL for the share tag

Allow the tag and scope it so a share-guest reaches **only** your Ragnar's web
port — never `tag:ragnar-mesh` broadly, or the guest could reach every unit:

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

    // a share-guest may reach ONLY the receiving unit, ONLY on :8000.
    // Pin dst to that one unit's tag or Tailscale IP.
    { "action": "accept", "src": ["tag:ragnar-share"],
      "dst": ["tag:ragnar-mesh:8000"] }
  ]
}
```

Tighten `dst` to a single host (e.g. `100.x.y.z:8000`) if you don't want the
share-guest reachable to every `tag:ragnar-mesh` unit. Revoking access is one
click in the Tailscale console — disable the key or the guest's node.

---

## API routes

| Route | Method | Who | What |
|---|---|---|---|
| `/api/mesh/share` | GET | operator / peer | aggregate catalog (this unit + online peers) |
| `/api/mesh/share/local` | GET | operator / peer / guest\* | this unit's shared list |
| `/api/mesh/share/download` | GET | operator / peer / guest\* | stream one shared file |
| `/api/mesh/share/add` | POST | operator | publish file(s) to the shared folder |
| `/api/mesh/share/remove` | POST | operator | unshare one of your files |
| `/api/mesh/share/fetch` | POST | operator | fetch a peer's file into a folder |
| `/api/mesh/files/push` | POST | operator / peer / guest / **token** | drop one file in the inbox |
| `/api/mesh/files/send` | POST | operator | send a file to a mesh peer |
| `/api/mesh/inbox` | GET | operator | list quarantined inbox items |
| `/api/mesh/inbox/save` | POST | operator | file an inbox item into a folder/Vault |
| `/api/mesh/inbox/discard` | POST | operator | delete an inbox item |
| `/api/mesh/files/config` | POST | operator | toggle `mesh_file_receive` / `mesh_share_guest_read` |
| `/api/mesh/share/tokens` | GET / POST | operator | list (masked) / mint a share token |
| `/api/mesh/share/tokens/<id>` | DELETE | operator | revoke a share token |
| `/api/mesh/remote-shares` | GET / POST | operator | list (masked) / add a remote target |
| `/api/mesh/remote-shares/<id>` | DELETE | operator | forget a remote target |
| `/api/mesh/remote-shares/<id>/send` | POST | operator | send a file to a saved remote |
| `/api/mesh/join` | POST | operator | join/switch tailnet (share-only when `tags:["tag:ragnar-share"]`) |

\* guest reads only when `mesh_share_guest_read` is on.

---

## Configuration reference

Config tab → **Ragnar Mesh (Tailscale)**, or `config/shared_config.json`.

| Key | Default | Meaning |
|---|---|---|
| `mesh_file_receive` | `true` | Master **Accept incoming** switch. Off ⇒ no unit, guest or token can push. |
| `mesh_share_tag` | `tag:ragnar-share` | Tailscale tag trusted as a share-only guest. |
| `mesh_share_only` | `false` | Set when **this** unit joined as a share-only guest (2B). Hides the mesh from its own UI. Cleared on leave / normal join. |
| `mesh_share_guest_read` | `false` | Also let share-guests browse & fetch the Mesh Share folder (read-only). |
| `mesh_share_tokens` | `[]` | Secret share tokens this unit issued (each: id, label, token, created). |
| `mesh_remote_shares` | `[]` | Saved outbound remote-share targets (name + address + their token). |

Tokens and remote shares live only in **this** unit's config and are never synced
to peers. Token secrets are returned in full **once** at creation; the list route
returns only a masked preview.

---

## Security model in one paragraph

Transport is always Tailscale (WireGuard, or TLS for Funnel) — encrypted in
transit regardless of role. Authorization is layered and fails closed: a request
must be the logged-in operator, or a WireGuard-proven `tag:ragnar-mesh` peer, or a
`tag:ragnar-share` guest, or carry a valid Bearer share token — and even then the
non-operator roles can do **only** what the table above allows, gated further by
`mesh_file_receive`. Received files are quarantined in an inbox and never written
to a live folder until the operator chooses where. Node-shares should be
ACL-scoped to `:8000`; Funnel must always be paired with a token because it is
public.

---

## See also

- [mesh.md](mesh.md) — the full Ragnar Mesh (auth model, fleet update, ACLs,
  incident correlation), including the [share-guest](mesh.md#share-only-guest-access-tagragnar-share) subsection.
- [vault.md](vault.md) — the encrypted Vault that inbox items and fetches can be
  saved into.
