"""Encrypted "Safe" vault for the Files tab.

A password-protected, size-capped store where files are encrypted at rest with
AES-256-GCM. The encryption key is derived from the user's password with scrypt
and only ever lives in server memory while the Safe is unlocked. Locking (or the
idle timeout) wipes the key, after which nothing in the Safe can be listed,
previewed, downloaded or added again without the password.

Layout on disk (under <datadir>/safe/):
    vault.json     - public metadata: kdf params, password verifier, size cap
    index.enc      - AES-GCM encrypted JSON list of entries {id,name,size,...}
    blobs/<id>.bin - AES-GCM encrypted file contents (nonce || ciphertext)

Nothing in blobs/ or index.enc is readable without the password; vault.json holds
only the salt and a verifier token (never the key or the password itself).
"""

import os
import json
import time
import uuid
import base64
import threading

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# scrypt work factors — tuned to stay usable on a Pi Zero while remaining a real
# barrier. N=2**14 keeps derivation well under a second on ARM.
_KDF_N = 2 ** 14
_KDF_R = 8
_KDF_P = 1
_KEY_LEN = 32          # AES-256
_NONCE_LEN = 12        # AES-GCM standard nonce
_VERIFIER_TOKEN = b"RAGNAR_SAFE_VERIFIER_V1"

# How long the Safe stays unlocked without activity before the key is wiped.
IDLE_TIMEOUT_SECONDS = 15 * 60

# Hard ceilings for the configurable size cap.
MIN_SIZE_BYTES = 8 * 1024 * 1024              # 8 MB
MAX_SIZE_BYTES = 64 * 1024 * 1024 * 1024      # 64 GB


class SafeError(Exception):
    """Raised for expected, user-facing Safe failures (bad password, full, etc.)."""


class SafeLockedError(SafeError):
    """Raised when an operation needs an unlocked Safe but it is locked."""


class SafeVault:
    """Manages a single on-disk encrypted vault plus its in-memory unlock state."""

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.blobs_dir = os.path.join(base_dir, 'blobs')
        self.meta_path = os.path.join(base_dir, 'vault.json')
        self.index_path = os.path.join(base_dir, 'index.enc')
        self._lock = threading.RLock()
        # In-memory unlock state — never persisted.
        self._key = None
        self._expires_at = 0.0

    # ── configuration state ────────────────────────────────────────────────
    def is_configured(self):
        return os.path.isfile(self.meta_path)

    def _load_meta(self):
        with open(self.meta_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _derive_key(self, password, salt):
        kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_KDF_N, r=_KDF_R, p=_KDF_P)
        return kdf.derive(password.encode('utf-8'))

    # ── unlock / lock ──────────────────────────────────────────────────────
    def _is_unlocked(self):
        return self._key is not None and time.time() < self._expires_at

    def _touch(self):
        """Refresh the idle timeout after a successful authorized op."""
        self._expires_at = time.time() + IDLE_TIMEOUT_SECONDS

    def _require_key(self):
        if not self._is_unlocked():
            # Expired since last touch — wipe stale key.
            self._key = None
            raise SafeLockedError('Safe is locked')
        self._touch()
        return self._key

    def lock(self):
        with self._lock:
            self._key = None
            self._expires_at = 0.0

    def unlock(self, password):
        with self._lock:
            if not self.is_configured():
                raise SafeError('Safe is not set up yet')
            meta = self._load_meta()
            salt = base64.b64decode(meta['kdf']['salt'])
            key = self._derive_key(password, salt)
            # Validate against the stored verifier before trusting the key.
            try:
                blob = base64.b64decode(meta['verifier'])
                AESGCM(key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], _VERIFIER_TOKEN)
            except (InvalidTag, ValueError, KeyError):
                raise SafeError('Incorrect password')
            self._key = key
            self._touch()

    def _verify_password(self, password):
        """Return True if `password` matches the configured Safe, else raise."""
        meta = self._load_meta()
        salt = base64.b64decode(meta['kdf']['salt'])
        key = self._derive_key(password, salt)
        try:
            blob = base64.b64decode(meta['verifier'])
            AESGCM(key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], _VERIFIER_TOKEN)
        except (InvalidTag, ValueError, KeyError):
            raise SafeError('Incorrect password')
        return True

    def destroy(self, password):
        """Permanently erase the whole vault after verifying the password.

        Removes vault.json, the encrypted index and every encrypted blob. There
        is no recovery — this is the deliberate 'reset the Safe' escape hatch.
        """
        import shutil
        with self._lock:
            if not self.is_configured():
                raise SafeError('Safe is not set up')
            self._verify_password(password)
            try:
                shutil.rmtree(self.base_dir)
            except OSError as exc:
                raise SafeError('Could not remove Safe: %s' % exc)
            self._key = None
            self._expires_at = 0.0

    # ── setup ──────────────────────────────────────────────────────────────
    def setup(self, password, size_bytes):
        with self._lock:
            if self.is_configured():
                raise SafeError('Safe is already set up')
            if not password or len(password) < 6:
                raise SafeError('Password must be at least 6 characters')
            size_bytes = int(size_bytes)
            if size_bytes < MIN_SIZE_BYTES or size_bytes > MAX_SIZE_BYTES:
                raise SafeError('Requested size is out of the allowed range')

            os.makedirs(self.blobs_dir, exist_ok=True)
            salt = os.urandom(16)
            key = self._derive_key(password, salt)

            # Verifier token lets a later unlock confirm the password without
            # storing it: encrypt a known constant, decrypt-check on unlock.
            nonce = os.urandom(_NONCE_LEN)
            verifier = nonce + AESGCM(key).encrypt(nonce, _VERIFIER_TOKEN, _VERIFIER_TOKEN)

            meta = {
                'version': 1,
                'created_at': time.time(),
                'size_limit_bytes': size_bytes,
                'kdf': {
                    'name': 'scrypt',
                    'salt': base64.b64encode(salt).decode('ascii'),
                    'n': _KDF_N, 'r': _KDF_R, 'p': _KDF_P, 'length': _KEY_LEN,
                },
                'verifier': base64.b64encode(verifier).decode('ascii'),
            }
            tmp = self.meta_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(meta, f)
            os.replace(tmp, self.meta_path)
            try:
                os.chmod(self.meta_path, 0o600)
            except OSError:
                pass

            self._key = key
            self._touch()
            # Initialise an empty encrypted index.
            self._write_index(self._blank_index())

    # ── AES-GCM helpers ────────────────────────────────────────────────────
    def _encrypt(self, key, plaintext, aad):
        nonce = os.urandom(_NONCE_LEN)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

    def _decrypt(self, key, blob, aad):
        return AESGCM(key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], aad)

    # ── encrypted index ────────────────────────────────────────────────────
    # The index is a dict {'files': [...], 'folders': [...]}. Each file entry
    # carries a 'dir' (normalized virtual folder path, '' = root); 'folders' is
    # the list of folder paths so that empty folders persist.
    @staticmethod
    def _blank_index():
        return {'files': [], 'folders': []}

    @staticmethod
    def _norm_dir(d):
        """Normalize a virtual folder path; '' is the root. Rejects traversal."""
        if not d:
            return ''
        parts = [p for p in str(d).replace('\\', '/').split('/') if p not in ('', '.')]
        for p in parts:
            if p == '..' or len(p) > 100:
                raise SafeError('Invalid folder path')
        return '/'.join(parts)

    def _read_index(self, key):
        if not os.path.isfile(self.index_path):
            return self._blank_index()
        with open(self.index_path, 'rb') as f:
            blob = f.read()
        try:
            raw = self._decrypt(key, blob, b'safe-index')
        except InvalidTag:
            raise SafeError('Safe index is corrupt or key mismatch')
        data = json.loads(raw.decode('utf-8'))
        # Migrate the original flat-list format to the folder-aware dict.
        if isinstance(data, list):
            data = {'files': [dict(e, dir=e.get('dir', '')) for e in data], 'folders': []}
        data.setdefault('files', [])
        data.setdefault('folders', [])
        for e in data['files']:
            e.setdefault('dir', '')
        return data

    def _write_index(self, data):
        blob = self._encrypt(self._key, json.dumps(data).encode('utf-8'), b'safe-index')
        tmp = self.index_path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(blob)
        os.replace(tmp, self.index_path)
        try:
            os.chmod(self.index_path, 0o600)
        except OSError:
            pass

    # ── status ─────────────────────────────────────────────────────────────
    def status(self):
        with self._lock:
            configured = self.is_configured()
            unlocked = self._is_unlocked()
            info = {
                'configured': configured,
                'unlocked': unlocked,
                'idle_timeout': IDLE_TIMEOUT_SECONDS,
            }
            if configured:
                meta = self._load_meta()
                info['size_limit_bytes'] = meta.get('size_limit_bytes', 0)
                info['created_at'] = meta.get('created_at')
            if unlocked:
                data = self._read_index(self._key)
                info['file_count'] = len(data['files'])
                info['folder_count'] = len(data['folders'])
                info['used_bytes'] = sum(int(e.get('size', 0)) for e in data['files'])
                info['expires_at'] = self._expires_at
                self._touch()
            return info

    # ── file operations (all require unlock) ───────────────────────────────
    def list_dir(self, dir=''):
        """Return the files and immediate subfolders inside a virtual folder."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            dir = self._norm_dir(dir)
            if dir and dir not in data['folders']:
                raise SafeError('Folder not found in Safe')
            files = sorted((e for e in data['files'] if e.get('dir', '') == dir),
                           key=lambda e: e.get('name', '').lower())
            subs = []
            for fp in data['folders']:
                parent = fp.rsplit('/', 1)[0] if '/' in fp else ''
                if parent == dir:
                    subs.append({'path': fp, 'name': fp.rsplit('/', 1)[-1]})
            subs.sort(key=lambda f: f['name'].lower())
            return {'dir': dir, 'files': files, 'folders': subs}

    # Backwards-compatible flat listing (all files, ignoring folders).
    def list_files(self):
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            return sorted(data['files'], key=lambda e: e.get('name', '').lower())

    def mkdir(self, path):
        """Create a folder (and any missing ancestors) inside the Safe."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            path = self._norm_dir(path)
            if not path:
                raise SafeError('Folder name required')
            cur = ''
            for p in path.split('/'):
                cur = p if not cur else cur + '/' + p
                if cur not in data['folders']:
                    data['folders'].append(cur)
            self._write_index(data)
            return path

    def add_file(self, filename, data_bytes, mime=None, dir=''):
        with self._lock:
            key = self._require_key()
            meta = self._load_meta()
            limit = int(meta.get('size_limit_bytes', 0))
            data = self._read_index(key)
            dir = self._norm_dir(dir)
            if dir and dir not in data['folders']:
                raise SafeError('Target folder does not exist')
            used = sum(int(e.get('size', 0)) for e in data['files'])
            if used + len(data_bytes) > limit:
                free = max(0, limit - used)
                raise SafeError(
                    'Not enough space in the Safe (%d bytes free, need %d)' % (free, len(data_bytes)))

            file_id = uuid.uuid4().hex
            blob = self._encrypt(key, data_bytes, file_id.encode('ascii'))
            blob_path = os.path.join(self.blobs_dir, file_id + '.bin')
            with open(blob_path, 'wb') as f:
                f.write(blob)
            try:
                os.chmod(blob_path, 0o600)
            except OSError:
                pass

            data['files'].append({
                'id': file_id,
                'name': filename,
                'size': len(data_bytes),
                'mime': mime or 'application/octet-stream',
                'modified': time.time(),
                'dir': dir,
            })
            self._write_index(data)
            return file_id

    def read_file(self, file_id):
        """Return (entry, plaintext_bytes) for a stored file."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            entry = next((e for e in data['files'] if e.get('id') == file_id), None)
            if not entry:
                raise SafeError('File not found in Safe')
            blob_path = os.path.join(self.blobs_dir, file_id + '.bin')
            if not os.path.isfile(blob_path):
                raise SafeError('File data missing from Safe')
            with open(blob_path, 'rb') as f:
                blob = f.read()
            try:
                plaintext = self._decrypt(key, blob, file_id.encode('ascii'))
            except InvalidTag:
                raise SafeError('File failed integrity check')
            return entry, plaintext

    def _remove_blob(self, file_id):
        blob_path = os.path.join(self.blobs_dir, file_id + '.bin')
        try:
            if os.path.isfile(blob_path):
                os.remove(blob_path)
        except OSError:
            pass

    def delete_file(self, file_id):
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            keep = [e for e in data['files'] if e.get('id') != file_id]
            if len(keep) == len(data['files']):
                raise SafeError('File not found in Safe')
            self._remove_blob(file_id)
            data['files'] = keep
            self._write_index(data)

    def delete_folder(self, path):
        """Delete a folder and everything inside it (files + subfolders)."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            path = self._norm_dir(path)
            if not path or path not in data['folders']:
                raise SafeError('Folder not found in Safe')
            prefix = path + '/'
            doomed = [e for e in data['files']
                      if e.get('dir', '') == path or e.get('dir', '').startswith(prefix)]
            for e in doomed:
                self._remove_blob(e['id'])
            data['files'] = [e for e in data['files'] if e not in doomed]
            data['folders'] = [fp for fp in data['folders']
                               if not (fp == path or fp.startswith(prefix))]
            self._write_index(data)

    @staticmethod
    def _clean_name(name):
        name = (name or '').strip()
        if not name or '/' in name or '\\' in name or name in ('.', '..'):
            raise SafeError('Invalid name')
        return name

    def rename_file(self, file_id, new_name):
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            new_name = self._clean_name(new_name)
            entry = next((e for e in data['files'] if e.get('id') == file_id), None)
            if not entry:
                raise SafeError('File not found in Safe')
            entry['name'] = new_name
            self._write_index(data)
            return new_name

    def rename_folder(self, path, new_name):
        """Rename a folder, re-homing its subfolders and the files inside it."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            path = self._norm_dir(path)
            new_name = self._clean_name(new_name)
            if not path or path not in data['folders']:
                raise SafeError('Folder not found in Safe')
            parent = path.rsplit('/', 1)[0] if '/' in path else ''
            new_path = self._norm_dir((parent + '/' + new_name) if parent else new_name)
            if new_path == path:
                return path
            if new_path in data['folders']:
                raise SafeError('A folder with that name already exists')
            old_prefix = path + '/'

            def remap(p):
                if p == path:
                    return new_path
                if p.startswith(old_prefix):
                    return new_path + '/' + p[len(old_prefix):]
                return p

            data['folders'] = [remap(fp) for fp in data['folders']]
            for e in data['files']:
                e['dir'] = remap(e.get('dir', ''))
            self._write_index(data)
            return new_path

    def move_file(self, file_id, dest_dir):
        """Move a file to another folder (just re-homes its 'dir')."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            dest = self._norm_dir(dest_dir)
            if dest and dest not in data['folders']:
                raise SafeError('Target folder does not exist')
            entry = next((e for e in data['files'] if e.get('id') == file_id), None)
            if not entry:
                raise SafeError('File not found in Safe')
            entry['dir'] = dest
            self._write_index(data)
            return dest

    def move_folder(self, path, dest_parent):
        """Move a folder (and its whole subtree) under a different parent."""
        with self._lock:
            key = self._require_key()
            data = self._read_index(key)
            path = self._norm_dir(path)
            dest_parent = self._norm_dir(dest_parent)
            if not path or path not in data['folders']:
                raise SafeError('Folder not found in Safe')
            if dest_parent == path or dest_parent.startswith(path + '/'):
                raise SafeError("A folder can't be moved into itself")
            if dest_parent and dest_parent not in data['folders']:
                raise SafeError('Target folder does not exist')
            name = path.rsplit('/', 1)[-1]
            new_path = self._norm_dir((dest_parent + '/' + name) if dest_parent else name)
            if new_path == path:
                return path
            if new_path in data['folders']:
                raise SafeError('A folder with that name already exists there')
            old_prefix = path + '/'

            def remap(p):
                if p == path:
                    return new_path
                if p.startswith(old_prefix):
                    return new_path + '/' + p[len(old_prefix):]
                return p

            data['folders'] = [remap(fp) for fp in data['folders']]
            for e in data['files']:
                e['dir'] = remap(e.get('dir', ''))
            self._write_index(data)
            return new_path
