# Safe — Encrypted File Vault

The **Safe** is a password-protected, size-capped vault in the **Files** tab for
storing sensitive files encrypted at rest. Nothing in it can be listed, previewed,
downloaded or added without unlocking it with the password first.

## Using the Safe

1. Open the **Files** tab and click **Upload to Safe**.
2. **First time (setup):** choose how much disk space to reserve for the Safe and
   set a password (twice). Click **Create Safe** — it is created and unlocked.
3. **Later (locked):** enter the password and click **Unlock**.
4. **Unlocked:** you see a usage bar and the file list. Use **+ Add files** to
   store encrypted files, and the per-file **view / download / delete** actions.
   Click **Lock** in the header to re-lock immediately.

The Safe **auto-locks after 15 minutes of inactivity**. After that, the password
is required again — the encryption key is wiped from memory.

> **There is no password recovery.** The key is derived from your password and is
> never stored. If you forget it, the files cannot be decrypted — by you or anyone.

## How it works

- **Cipher:** each file is encrypted with **AES-256-GCM** (authenticated
  encryption — tampering is detected on read). A fresh 12-byte nonce is generated
  per file and stored alongside the ciphertext.
- **Key derivation:** the AES key is derived from your password with **scrypt**
  (`N=2¹⁴, r=8, p=1`) and a random 16-byte salt. The key exists **only in server
  memory** while the Safe is unlocked; locking (or the idle timeout) wipes it.
- **Password verifier:** setup encrypts a fixed token so a later unlock can confirm
  the password is correct — without ever storing the password or the key.
- **Encrypted index:** the list of file names and sizes is itself stored encrypted
  (`index.enc`), so even the metadata is unreadable while locked.
- **Size cap:** the reserved size you pick at setup is enforced as a quota; uploads
  that would exceed it are rejected. The setup picker is also clamped to the free
  space on the data disk.

## On-disk layout

Everything lives under `data/safe/`:

| Path | Contents |
|------|----------|
| `vault.json` | Public metadata only: scrypt salt, KDF params, the password verifier, and the size cap. No key, no password. |
| `index.enc` | AES-GCM encrypted JSON list of entries (`id`, `name`, `size`, `mime`, `modified`). |
| `blobs/<id>.bin` | AES-GCM encrypted file contents (`nonce ‖ ciphertext`). |

Because `data/` is not committed to git, the vault never leaves the device through
the repo. Files are written `0600`.

## API

All endpoints are under `/api/safe/` and are used by the Files tab UI:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/safe/status` | GET | Configured / unlocked state, usage, size limits, free disk. |
| `/api/safe/setup` | POST | Create the vault (`password`, `size_mb`). One-time. |
| `/api/safe/unlock` | POST | Unlock with `password` for this server session. |
| `/api/safe/lock` | POST | Wipe the in-memory key. |
| `/api/safe/list` | GET | List stored files (requires unlock). |
| `/api/safe/upload` | POST | Encrypt & store uploaded file(s) (requires unlock). |
| `/api/safe/download` | GET | Decrypt & stream a file by `id` (requires unlock). |
| `/api/safe/preview` | GET | Inline text/image preview by `id` (requires unlock). |
| `/api/safe/delete` | POST | Remove a file by `id` (requires unlock). |

While locked, the file endpoints return `403` with `{"locked": true}`.

## Limitations

- Unlock state is **global to the server process**, not per browser session — once
  unlocked, any authenticated client of that unit can use the Safe until it locks.
  Keep the Safe locked when unattended, and run Ragnar behind its login.
- Reserved size is a **quota**, not a pre-allocated container — it bounds how much
  the Safe may use, it doesn't hide the vault's existence.
