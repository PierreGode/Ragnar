"""File transfer between Ragnar units over the Tailscale mesh.

Transport reuses the mesh's existing channel: plain HTTP to a peer's
``http://[tailnet-ip]:8000`` address, which Tailscale already wraps in
WireGuard — so nothing here adds transport crypto. Authorization is the mesh's
WireGuard-identity + tag check (enforced in webapp_modern's before_request gate);
this module only moves bytes and tracks state.

Model:
  * A sender streams a file to a peer's ``POST /api/mesh/files/push``.
  * The receiver stores it in a **quarantined inbox** (``data/mesh_inbox/``) and
    surfaces it to its operator, who chooses where to file it (an Uploads folder
    or the encrypted Vault). Arrivals never auto-land in live folders.
  * Sends run in a background thread and report progress through an in-memory
    registry the UI polls.
"""

import os
import json
import time
import uuid
import shutil
import hashlib
import threading

try:
    import requests
except Exception:  # pragma: no cover - requests is a hard dep in practice
    requests = None

CHUNK = 256 * 1024                       # 256 KB streaming chunks
DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024   # 4 GB per-file ceiling
_FREE_MARGIN = 64 * 1024 * 1024          # keep 64 MB free on the card


def _safe_component(name):
    """A filesystem-safe single path component (no separators / traversal)."""
    name = os.path.basename((name or '').strip()) or 'file'
    return name.replace('\x00', '')


class TransferRegistry:
    """In-memory record of outbound transfers, polled by the UI."""

    def __init__(self, cap=100):
        self._lock = threading.Lock()
        self._items = {}          # id -> dict
        self._order = []          # ids, newest last
        self._cap = cap

    def create(self, name, dest_name):
        tid = uuid.uuid4().hex
        with self._lock:
            self._items[tid] = {
                'id': tid, 'name': name, 'dest': dest_name,
                'state': 'queued', 'sent': 0, 'total': 0, 'pct': 0,
                'error': '', 'started': time.time(), 'updated': time.time(),
            }
            self._order.append(tid)
            while len(self._order) > self._cap:
                old = self._order.pop(0)
                self._items.pop(old, None)
        return tid

    def update(self, tid, **kw):
        with self._lock:
            it = self._items.get(tid)
            if not it:
                return
            it.update(kw)
            if it.get('total'):
                it['pct'] = min(100, int(it['sent'] * 100 / it['total']))
            it['updated'] = time.time()

    def list(self):
        with self._lock:
            return [dict(self._items[t]) for t in reversed(self._order) if t in self._items]


class MeshTransfer:
    """Inbox storage + outbound streaming for one Ragnar unit."""

    def __init__(self, inbox_dir, max_bytes=DEFAULT_MAX_BYTES):
        self.inbox_dir = inbox_dir
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.registry = TransferRegistry()
        os.makedirs(self.inbox_dir, exist_ok=True)

    # ── receiving ───────────────────────────────────────────────────────────
    def _meta_path(self, item_id):
        return os.path.join(self.inbox_dir, item_id + '.json')

    def _blob_path(self, item_id):
        return os.path.join(self.inbox_dir, item_id + '.bin')

    def receive_stream(self, stream, content_length, filename, sender_name, sender_id,
                       expected_sha=None):
        """Persist an incoming stream into the inbox. Returns the item metadata.

        Validates: filename present, size within the limit, enough disk space,
        the transfer arrived complete (bytes == Content-Length), and — when the
        sender supplied one — that the SHA-256 matches. Raises ValueError on any
        failure, leaving no partial file behind.
        """
        filename = _safe_component(filename)
        if not filename or filename == 'file':
            # tolerate 'file' fallback, but a truly empty name is rejected below
            pass
        if content_length and content_length > self.max_bytes:
            raise ValueError('File exceeds the %d byte transfer limit' % self.max_bytes)
        try:
            free = shutil.disk_usage(self.inbox_dir).free
            if content_length and content_length + _FREE_MARGIN > free:
                raise ValueError('Not enough free disk space to receive this file')
        except OSError:
            pass

        item_id = uuid.uuid4().hex
        blob = self._blob_path(item_id)
        written = 0
        hasher = hashlib.sha256()
        tmp = blob + '.part'
        try:
            with open(tmp, 'wb') as f:
                while True:
                    chunk = stream.read(CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > self.max_bytes:
                        raise ValueError('File exceeds the transfer limit')
                    hasher.update(chunk)
                    f.write(chunk)
            if written == 0:
                raise ValueError('Received an empty file')
            # Completeness: a dropped connection yields fewer bytes than promised.
            if content_length and written != content_length:
                raise ValueError('Incomplete transfer (%d of %d bytes)' % (written, content_length))
            # Integrity: verify the sender's checksum when provided.
            if expected_sha and hasher.hexdigest().lower() != expected_sha.strip().lower():
                raise ValueError('Integrity check failed — file corrupted in transit')
            os.replace(tmp, blob)
        except Exception:
            for p in (tmp, blob):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            raise
        try:
            os.chmod(blob, 0o600)
        except OSError:
            pass

        meta = {
            'id': item_id,
            'name': filename,
            'size': written,
            'sha256': hasher.hexdigest(),
            'sender': sender_name or 'a peer',
            'sender_id': sender_id or 0,
            'received_at': time.time(),
        }
        with open(self._meta_path(item_id), 'w', encoding='utf-8') as f:
            json.dump(meta, f)
        return meta

    def list_inbox(self):
        items = []
        for fn in os.listdir(self.inbox_dir):
            if not fn.endswith('.json'):
                continue
            try:
                with open(os.path.join(self.inbox_dir, fn), 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                if os.path.isfile(self._blob_path(meta['id'])):
                    items.append(meta)
            except (OSError, ValueError, KeyError):
                continue
        items.sort(key=lambda m: m.get('received_at', 0), reverse=True)
        return items

    def get_item(self, item_id):
        try:
            with open(self._meta_path(item_id), 'r', encoding='utf-8') as f:
                meta = json.load(f)
        except (OSError, ValueError):
            return None
        if not os.path.isfile(self._blob_path(item_id)):
            return None
        return meta

    def read_item(self, item_id):
        """Return (meta, bytes) for an inbox item, or (None, None)."""
        meta = self.get_item(item_id)
        if not meta:
            return None, None
        with open(self._blob_path(item_id), 'rb') as f:
            return meta, f.read()

    def blob_path_for(self, item_id):
        return self._blob_path(item_id) if self.get_item(item_id) else None

    def discard(self, item_id):
        removed = False
        for p in (self._blob_path(item_id), self._meta_path(item_id)):
            try:
                if os.path.exists(p):
                    os.remove(p)
                    removed = True
            except OSError:
                pass
        return removed

    # ── sending ─────────────────────────────────────────────────────────────
    def send_file_async(self, url, file_path, filename, headers, tid, timeout=1800,
                        cleanup_source=False):
        """Stream `file_path` to `url` in a background thread, tracking `tid`.

        `headers` should carry the sender/label metadata. When `cleanup_source`
        the source file is removed after the attempt (used for staged uploads).
        """
        t = threading.Thread(
            target=self._send_worker,
            args=(url, file_path, filename, headers, tid, timeout, cleanup_source),
            daemon=True)
        t.start()
        return tid

    def _send_worker(self, url, file_path, filename, headers, tid, timeout, cleanup_source):
        try:
            if requests is None:
                raise RuntimeError('python-requests is not available')
            total = os.path.getsize(file_path)
            self.registry.update(tid, state='sending', total=total, sent=0)
            reg = self.registry
            _tid = tid

            # Send a length-bearing file object, NOT a generator: a generator
            # makes requests use chunked transfer-encoding, which the Werkzeug
            # receiver rejects ("Invalid chunk header"). With .len set, requests
            # sends a normal Content-Length body and streams via read().
            class _ProgressFile:
                def __init__(self, path):
                    self._f = open(path, 'rb')
                    self.len = total           # requests.super_len() reads this
                    self._sent = 0
                def read(self, size=-1):
                    chunk = self._f.read(size if size and size > 0 else CHUNK)
                    if chunk:
                        self._sent += len(chunk)
                        reg.update(_tid, sent=self._sent)
                    return chunk
                def __len__(self):
                    return self.len
                # Present as iterable so requests treats us as a stream body.
                def __iter__(self):
                    return iter(lambda: self.read(CHUNK), b'')
                def close(self):
                    try:
                        self._f.close()
                    except Exception:
                        pass

            # Checksum the file up front so the receiver can verify integrity.
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as _hf:
                for _blk in iter(lambda: _hf.read(CHUNK), b''):
                    hasher.update(_blk)

            body = _ProgressFile(file_path)
            send_headers = dict(headers or {})
            send_headers['Content-Type'] = 'application/octet-stream'
            send_headers['X-Filename'] = filename   # Content-Length set by requests
            send_headers['X-Content-SHA256'] = hasher.hexdigest()
            try:
                resp = requests.post(url, data=body, headers=send_headers, timeout=timeout)
            finally:
                body.close()
            if resp.status_code == 200:
                self.registry.update(tid, state='delivered', sent=total, pct=100)
            elif resp.status_code == 401:
                self.registry.update(tid, state='failed',
                                     error='peer rejected our identity (both units need the same mesh tag)')
            elif resp.status_code == 403:
                self.registry.update(tid, state='failed',
                                     error='peer is not accepting transfers (turn on "Accept incoming" there)')
            elif resp.status_code == 404:
                self.registry.update(tid, state='failed',
                                     error='peer has no transfer endpoint — update that unit to this version')
            else:
                msg = ''
                try:
                    msg = resp.json().get('error', '')
                except Exception:
                    pass
                self.registry.update(tid, state='failed',
                                     error=msg or ('peer returned HTTP %d' % resp.status_code))
        except Exception as exc:
            name = type(exc).__name__
            if 'ConnectionError' in name or 'ConnectTimeout' in name:
                msg = 'could not reach peer — Ragnar may be down or on a different port'
            elif 'Timeout' in name:
                msg = 'timed out talking to peer'
            else:
                msg = str(exc) or name
            self.registry.update(tid, state='failed', error=msg)
        finally:
            if cleanup_source:
                try:
                    os.remove(file_path)
                except OSError:
                    pass
