# Vault — Encrypted File Store

The **Vault** is a password-protected, size-capped store in the **Files** tab for
storing sensitive files encrypted at rest. Nothing in it can be listed, previewed,
downloaded or added without unlocking it with the password first.

## Using the Vault

The **Files** tab header has two Vault buttons:

- **Set up Vault / Unlock Vault / Lock Vault** — a single button whose label follows
  the Vault's state. First use runs setup; when locked it prompts to unlock; when
  unlocked it turns green and locks the Vault on click.
- **Upload to Vault** — jumps straight to the file picker when unlocked, or opens
  the setup/unlock dialog first if needed.

Typical flow:

1. **First time (setup):** click **Set up Vault**, choose how much disk space to
   reserve, and set a password (twice). Click **Create Vault** — it is created and
   unlocked.
2. **Later (locked):** click **Unlock Vault** and enter the password.
3. **Unlocked:** a **🔒 Vault** folder appears in the **Directories** list. Click it
   to browse the Vault in the main pane like any other folder. You can:
   - **Create subfolders** (**+ New folder**) and nest them arbitrarily,
   - **Upload into the folder you're viewing** (**⬆ Add files**),
   - navigate with the **breadcrumb**, the **Back** and **Up** buttons, or the
     **.. (Up)** row,
   - **view / download / rename / delete** files, and **rename or delete a folder**
     (delete removes everything inside it).

   Files and folders in **Uploads** / **Backups** support the same New folder,
   upload-here, rename and delete actions and Back/Up navigation.

   The Vault dialog shows a usage summary with a **Browse files** shortcut into the
   same view.

The Vault **auto-locks after 15 minutes of inactivity**. After that, the password
is required again — the encryption key is wiped from memory, the **🔒 Vault** folder
disappears from Directories, and the header button returns to **Unlock Vault**.

### Deleting the Vault

The unlock dialog has a **Delete Vault & erase all files…** option. It requires you
to enter your password and then explicitly confirm; on approval the entire vault
(`vault.json`, the encrypted index and every blob) is permanently erased and you
can set up a fresh Vault. The password must be **correct** — it is verified server
side before anything is deleted, so a wrong password (or someone without it) cannot
wipe your files. There is no recovery.

> **There is no password recovery.** The key is derived from your password and is
> never stored. If you forget it, the files cannot be decrypted — by you or anyone.

## How it works

- **Cipher:** each file is encrypted with **AES-256-GCM** (authenticated
  encryption — tampering is detected on read). A fresh 12-byte nonce is generated
  per file and stored alongside the ciphertext.
- **Key derivation:** the AES key is derived from your password with **scrypt**
  (`N=2¹⁴, r=8, p=1`) and a random 16-byte salt. The key exists **only in server
  memory** while the Vault is unlocked; locking (or the idle timeout) wipes it.
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
| `index.enc` | AES-GCM encrypted JSON `{files, folders}`: each file entry has `id`, `name`, `size`, `mime`, `modified`, and its virtual folder `dir`; `folders` is the list of folder paths so empty folders persist. Folder names are encrypted too. |
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
| `/api/safe/destroy` | POST | Permanently erase the whole Vault (verifies `password` first). |
| `/api/safe/list` | GET | List a folder's files + subfolders (`?dir=`) (requires unlock). |
| `/api/safe/mkdir` | POST | Create a subfolder (`dir` parent + `name`) (requires unlock). |
| `/api/safe/rename` | POST | Rename a file (`id`) or folder (`folder`) to `name` (requires unlock). |
| `/api/safe/upload` | POST | Encrypt & store uploaded file(s) into `dir` (requires unlock). |
| `/api/safe/download` | GET | Decrypt & stream a file by `id`; `?inline=1` renders in-browser instead of downloading (requires unlock). |
| `/api/safe/preview` | GET | Inline text/image/PDF preview by `id` (requires unlock). |
| `/api/safe/delete` | POST | Remove a file by `id`, or a folder (+contents) by `folder` (requires unlock). |

While locked, the file endpoints return `403` with `{"locked": true}`.

## Limitations

- Unlock state is **global to the server process**, not per browser session — once
  unlocked, any authenticated client of that unit can use the Vault until it locks.
  Keep the Vault locked when unattended, and run Ragnar behind its login.
- Reserved size is a **quota**, not a pre-allocated container — it bounds how much
  the Vault may use, it doesn't hide the vault's existence.
