#!/usr/bin/env python3
"""Bluetooth link — the mobile app's small requests, carried over BLE.

This is how the mobile app talks to a unit over Bluetooth, with no network
between the phone and the unit at all — in a car, in the field: the app's
ordinary API requests travel over two GATT characteristics and are answered by
the same Flask routes that answer them over HTTP. Bluetooth never hands out
the unit's IP address; it carries the requests themselves.

It is for SMALL things: dashboard numbers, wardrive status, start/stop, the
phone's GPS fixes, toggles. BLE moves some tens of kB/s, so a response that is
still large after compression is refused with 413 and the app says that view
needs Wi-Fi. Streams (the waterfall, event streams) are refused with 415.

    phone                               unit
    ─────                               ────
    write  LINK_RX  ── frames ──▶  LinkHub ──▶ Flask (in-process)
    notify LINK_TX  ◀── frames ──  LinkHub ◀── response

Wire format
    frame    = id:u16 | seq:u16 (bit 15 = last frame) | payload      (big endian)
    message  = UTF-8 JSON {"t":"hello"|"auth", ...}            (opening the link)
             | 0x00 | counter:u64 | sealed JSON {"t":"req", ...}     (a request)
    answer   = status:u16 | flags:u8 | body       flags: 1 = zlib, 2 = JSON
             | 0xFF 0xFF | sealed answer                  (the answer to a request)

Access and encryption
    The link code (shown on Settings → Bluetooth) is the key to the link. Phone
    and unit run SPAKE2 over it (Ed25519 group, libsodium): each side proves it
    knows the code and both end up with fresh session keys, while someone
    listening learns nothing they can test a guess against. Guessing therefore
    takes one connection per guess, and the unit locks after five wrong ones.
    Every request and answer after that is sealed with ChaCha20-Poly1305 under
    those keys; a request counter that only goes up stops replays. The unit's
    own login still applies on top, exactly as over HTTP.

This file has no D-Bus or GLib in it: ble_peripheral.py owns the radio and
hands frames in and out, so everything here is testable without Bluetooth.
"""

import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

# GATT contract — shared verbatim with the mobile app (src/blelink.ts).
CHAR_LINK_RX = 'a3f1c2d4-5b6e-4f70-8a91-b2c3d4e5f601'   # app → unit, write
CHAR_LINK_TX = 'a3f1c2d4-5b6e-4f70-8a91-b2c3d4e5f602'   # unit → app, notify

PROTOCOL_VERSION = 2
FRAME_HEADER = 4
LAST = 0x8000

FLAG_ZLIB = 1
FLAG_JSON = 2

MAX_REQUEST_BYTES = 64 * 1024          # a reassembled request
MAX_RAW_BYTES = 1536 * 1024            # a response before compression
MAX_RESPONSE_BYTES = 128 * 1024        # a response as sent (≈ 6 s at 20 kB/s)
REQUEST_DEADLINE_S = 20.0
SESSION_IDLE_S = 30 * 60
MAX_CLIENTS = 8

# Wrong link codes: after this many in a row the unit stops answering auth for
# a while, doubling each time. Eight digits and this make guessing pointless.
FAILS_BEFORE_LOCK = 5
LOCK_START_S = 60
LOCK_MAX_S = 15 * 60

# Headers the app may set on a relayed request.
_ALLOWED_HEADERS = {'x-ragnar-target'}

# Never answered over the link: streams, and the link's own endpoints.
_BLOCKED_PREFIXES = ('/api/ble/link/',)
_STREAM_TYPES = ('text/event-stream', 'multipart/x-mixed-replace')


def new_code() -> str:
    """A fresh 8-digit link code."""
    return f'{secrets.randbelow(10 ** 8):08d}'


# ---------------------------------------------------------------------------
# Key exchange and sealing — shared verbatim with the app (src/linkproto.ts)
# ---------------------------------------------------------------------------
#
#   w = SHA-512("ragnar-link-v2/w" | code)  reduced to a scalar
#   app:   X = x·G + w·M          unit:  Y = y·G + w·N
#   K = x·(Y − w·N) = y·(X − w·M)
#   prk = SHA-256("ragnar-link-v2" | lp(cid) | lp(X) | lp(Y) | lp(K) | lp(w))
#   key(label) = HMAC-SHA256(prk, label)       lp(b) = len:u16 | b
#
# M and N are fixed points nobody knows a logarithm of:
# from_uniform(SHA-256("ragnar-link-v2/M")) and (".../N").

try:
    from nacl import bindings as _na
    CRYPTO_OK = bool(_na.has_crypto_core_ed25519)
except Exception:  # pragma: no cover - PyNaCl is in requirements.txt
    _na = None
    CRYPTO_OK = False

_CTX = b'ragnar-link-v2'
_M = bytes.fromhex('54d28217e7247d0c21a3df6dad1279f144259dd04bae51e7dca6a732446b2115')
_N = bytes.fromhex('8d6bece57b38af98b2c111ea50f54c697e2360af125e0ffedf7f9ccdc7b26aae')
SEALED_REQUEST = b'\x00'
SEALED_ANSWER = b'\xff\xff'


def _lp(data: bytes) -> bytes:
    return struct.pack('>H', len(data)) + data


def _code_scalar(code: str) -> bytes:
    return _na.crypto_core_ed25519_scalar_reduce(
        hashlib.sha512(_CTX + b'/w' + code.encode()).digest())


def _random_scalar() -> bytes:
    return _na.crypto_core_ed25519_scalar_reduce(os.urandom(64))


def _session_keys(cid: str, X: bytes, Y: bytes, K: bytes, w: bytes) -> dict:
    prk = hashlib.sha256(_CTX + _lp(cid.encode()) + _lp(X) + _lp(Y) + _lp(K) + _lp(w)).digest()

    def key(label: bytes) -> bytes:
        return hmac.new(prk, label, hashlib.sha256).digest()

    return {'proof_app': key(b'proof app'), 'proof_unit': key(b'proof unit'),
            'a2u': key(b'app to unit'), 'u2a': key(b'unit to app')}


def unit_exchange(code: str, cid: str, X: bytes, y: Optional[bytes] = None):
    """The unit's half: (Y, session keys) for a phone's X. ValueError if X is
    not a point a real phone would send."""
    try:
        if len(X) != 32 or not _na.crypto_core_ed25519_is_valid_point(X):
            raise ValueError('bad point')
        w = _code_scalar(code)
        y = y or _random_scalar()
        Y = _na.crypto_core_ed25519_add(
            _na.crypto_scalarmult_ed25519_base_noclamp(y),
            _na.crypto_scalarmult_ed25519_noclamp(w, _N))
        K = _na.crypto_scalarmult_ed25519_noclamp(
            y, _na.crypto_core_ed25519_sub(X, _na.crypto_scalarmult_ed25519_noclamp(w, _M)))
    except ValueError:
        raise
    except Exception as e:           # libsodium refuses the identity point
        raise ValueError(str(e))
    return Y, _session_keys(cid, X, Y, K, w)


def app_start(code: str, x: Optional[bytes] = None):
    """The phone's half, first step: (x, X). Here for the tests and tools; the
    app does the same in linkproto.ts."""
    x = x or _random_scalar()
    X = _na.crypto_core_ed25519_add(
        _na.crypto_scalarmult_ed25519_base_noclamp(x),
        _na.crypto_scalarmult_ed25519_noclamp(_code_scalar(code), _M))
    return x, X


def app_finish(code: str, cid: str, x: bytes, X: bytes, Y: bytes) -> dict:
    """The phone's half, second step: the session keys."""
    if len(Y) != 32 or not _na.crypto_core_ed25519_is_valid_point(Y):
        raise ValueError('bad point')
    w = _code_scalar(code)
    try:
        K = _na.crypto_scalarmult_ed25519_noclamp(
            x, _na.crypto_core_ed25519_sub(Y, _na.crypto_scalarmult_ed25519_noclamp(w, _N)))
    except Exception as e:
        raise ValueError(str(e))
    return _session_keys(cid, X, Y, K, w)


def _nonce(counter: int) -> bytes:
    return b'\x00\x00\x00\x00' + struct.pack('>Q', counter)


def seal_request(key: bytes, counter: int, plain: bytes) -> bytes:
    return SEALED_REQUEST + struct.pack('>Q', counter) + \
        _na.crypto_aead_chacha20poly1305_ietf_encrypt(plain, b'req', _nonce(counter), key)


def open_request(key: bytes, raw: bytes):
    """(counter, plain). Raises on anything not sealed with ``key``."""
    counter = struct.unpack('>Q', raw[1:9])[0]
    return counter, _na.crypto_aead_chacha20poly1305_ietf_decrypt(
        raw[9:], b'req', _nonce(counter), key)


def seal_answer(key: bytes, counter: int, plain: bytes) -> bytes:
    """An answer is sealed under its request's counter, which ties the two."""
    return SEALED_ANSWER + _na.crypto_aead_chacha20poly1305_ietf_encrypt(
        plain, b'res', _nonce(counter), key)


def open_answer(key: bytes, counter: int, raw: bytes) -> bytes:
    if raw[:2] != SEALED_ANSWER:
        raise ValueError('not sealed')
    return _na.crypto_aead_chacha20poly1305_ietf_decrypt(raw[2:], b'res', _nonce(counter), key)


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def split_frames(msg_id: int, payload: bytes, frame_size: int) -> list:
    """Cut a message into frames of at most ``frame_size`` bytes each."""
    room = max(1, frame_size - FRAME_HEADER)
    chunks = [payload[i:i + room] for i in range(0, len(payload), room)] or [b'']
    if len(chunks) > LAST:
        raise ValueError('message too long to frame')
    out = []
    for seq, chunk in enumerate(chunks):
        flag = LAST if seq == len(chunks) - 1 else 0
        out.append(struct.pack('>HH', msg_id & 0xFFFF, seq | flag) + chunk)
    return out


class Reassembler:
    """Puts frames back together. One per connected phone."""

    def __init__(self, limit: int = MAX_REQUEST_BYTES):
        self.limit = limit
        self._parts: dict = {}

    def feed(self, frame: bytes):
        """Returns (id, message) when a message completes, else None.

        Raises ValueError on a frame that cannot belong to a valid message, so
        the caller can drop the phone's half-built state.
        """
        if len(frame) < FRAME_HEADER:
            raise ValueError('short frame')
        msg_id, seq = struct.unpack('>HH', frame[:FRAME_HEADER])
        last = bool(seq & LAST)
        seq &= ~LAST
        buf = self._parts.get(msg_id)
        if seq == 0:
            buf = self._parts[msg_id] = [0, bytearray()]
        if buf is None or buf[0] != seq:
            self._parts.pop(msg_id, None)
            raise ValueError('frame out of order')
        buf[0] += 1
        buf[1] += frame[FRAME_HEADER:]
        if len(buf[1]) > self.limit:
            self._parts.pop(msg_id, None)
            raise ValueError('message too large')
        if len(self._parts) > 16:               # abandoned half-messages
            for stale in list(self._parts)[:-16]:
                self._parts.pop(stale, None)
        if not last:
            return None
        self._parts.pop(msg_id, None)
        return msg_id, bytes(buf[1])


def pack_response(status: int, body: bytes, is_json: bool = True) -> bytes:
    flags = FLAG_JSON if is_json else 0
    if len(body) > 256:
        packed = zlib.compress(body, 6)
        if len(packed) < len(body):
            body, flags = packed, flags | FLAG_ZLIB
    return struct.pack('>HB', status, flags) + body


def unpack_response(data: bytes):
    """(status, body, is_json) — the inverse of pack_response (tests, tools)."""
    status, flags = struct.unpack('>HB', data[:3])
    body = data[3:]
    if flags & FLAG_ZLIB:
        body = zlib.decompress(body)
    return status, body, bool(flags & FLAG_JSON)


def _json_response(status: int, obj: dict) -> bytes:
    return pack_response(status, json.dumps(obj, separators=(',', ':')).encode())


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def answer_frame_size(mtu) -> int:
    """Largest answer frame for a connection's ATT MTU.

    A notification's own header is 3 bytes. Another 9 are left free: with a
    phone that accepts several notifications in one packet (every recent
    Android), BlueZ adds a length field per value, and a value that fills the
    MTU to the last byte is never sent — nor is anything after it. Measured on
    a Pi 5 with BlueZ 5.82: 514-byte frames at MTU 517 stopped every answer.
    Never below the BLE floor of 20.
    """
    try:
        mtu = int(mtu or 23)
    except (TypeError, ValueError):
        mtu = 23
    return max(20, min(mtu, 517) - 12)


class _Peer:
    """A phone on the air right now (one BLE connection)."""

    def __init__(self):
        self.rx = Reassembler()
        self.cid: Optional[str] = None
        self.pending: Optional[dict] = None   # keys of an exchange not yet proven
        self.keys: Optional[dict] = None      # keys of the open link
        self.counter = 0                      # highest request counter seen
        self.frame_size = 20
        self.last = time.monotonic()

    @property
    def authed(self) -> bool:
        return self.keys is not None


class LinkHub:
    """Answers link messages. Owns no radio — see ble_peripheral.py."""

    def __init__(self, app, get_config: Callable[[], dict], logger=None,
                 save_config: Optional[Callable[[], None]] = None):
        self.app = app
        self._get_config = get_config
        self._save_config = save_config
        self.logger = logger
        self._peers: dict = {}
        self._cookies: dict = {}         # cid -> {name: value}, survives reconnects
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='ble-link')
        self._fails = 0
        self._locked_until = 0.0
        self._lock_len = LOCK_START_S
        self._stats = {'requests': 0, 'bytes_out': 0, 'last_request': 0.0, 'refused': 0}
        #: called (from a worker thread) whenever a phone is talking to us
        self.on_activity: Optional[Callable[[], None]] = None

    # -- configuration -----------------------------------------------------
    def _cfg(self) -> dict:
        try:
            cfg = self._get_config()
            return cfg if cfg is not None else {}
        except Exception:
            return {}

    def code(self) -> str:
        """The link code, created the first time it is needed."""
        cfg = self._cfg()
        code = str(cfg.get('ble_link_code') or '')
        if not (code.isdigit() and len(code) == 8):
            code = new_code()
            cfg['ble_link_code'] = code
            if self._save_config:
                try:
                    self._save_config()
                except Exception:
                    pass
        return code

    def forget_clients(self) -> None:
        """Drop every phone's session (after the code changes)."""
        with self._lock:
            self._peers.clear()
            self._cookies.clear()

    def status(self) -> dict:
        now = time.monotonic()
        with self._lock:
            live = sum(1 for p in self._peers.values() if p.authed and now - p.last < 30)
            st = dict(self._stats)
        st['connected'] = live
        st['locked_for'] = max(0, int(self._locked_until - now))
        if st['last_request']:
            st['last_request_age'] = int(time.time() - st.pop('last_request'))
        else:
            st.pop('last_request')
        return st

    # -- frames in ---------------------------------------------------------
    def on_frame(self, peer_key: str, frame: bytes, mtu: int,
                 send: Callable[[list], None]) -> None:
        """A frame arrived from a phone. ``send(frames)`` is how to answer it;
        it may be called later, from another thread."""
        now = time.monotonic()
        with self._lock:
            for k in [k for k, p in self._peers.items() if now - p.last > SESSION_IDLE_S]:
                self._peers.pop(k, None)
            peer = self._peers.get(peer_key)
            if peer is None:
                peer = self._peers[peer_key] = _Peer()
            peer.last = now
            peer.frame_size = answer_frame_size(mtu)
        try:
            done = peer.rx.feed(bytes(frame))
        except ValueError:
            peer.rx = Reassembler()
            return
        if done is None:
            return
        msg_id, raw = done
        # Opened here, in arrival order: the request counter must only go up.
        self._dispatch(self._answer, peer, msg_id, self._open(peer, raw), send)

    def _dispatch(self, fn, *args) -> None:
        """Run an answer off the GLib loop. Prefers the pool; falls back to a
        short-lived thread.

        Python 3.14's ThreadPoolExecutor refuses new work with "cannot schedule
        new futures after interpreter shutdown" once it believes the interpreter
        is finalising. A long-lived Ragnar (seen on the Python 3.14 image) trips
        that check while the web app is still serving, which left every phone's
        hello unanswered and the app timing out. The answer still has to go out,
        so fall back to a plain daemon thread when the pool refuses it."""
        try:
            self._pool.submit(fn, *args)
        except RuntimeError:
            threading.Thread(target=fn, args=args, daemon=True,
                             name='ble-link-answer').start()

    def drop_peer(self, peer_key: str) -> None:
        with self._lock:
            self._peers.pop(peer_key, None)

    # -- answering ---------------------------------------------------------
    def _open(self, peer: _Peer, raw: bytes) -> dict:
        """Read one message: a sealed request, or the plain JSON that opens the
        link. Returns a job for _run()."""
        relink = {'out': _json_response(401, {'error': 'link code required', 'link_auth': True})}
        if raw[:1] == SEALED_REQUEST:
            with self._lock:
                keys = peer.keys
                if not keys or len(raw) < 9 + 16:
                    return relink
                try:
                    counter, plain = open_request(keys['a2u'], raw)
                except Exception:
                    return relink
                if counter <= peer.counter:
                    return relink
                peer.counter = counter
            try:
                msg = json.loads(plain.decode('utf-8'))
                if not isinstance(msg, dict) or msg.get('t') != 'req':
                    raise ValueError
            except Exception:
                return {'out': _json_response(400, {'error': 'bad request'}),
                        'seal': (keys['u2a'], counter)}
            return {'req': msg, 'seal': (keys['u2a'], counter)}
        try:
            msg = json.loads(raw.decode('utf-8'))
            if not isinstance(msg, dict):
                raise ValueError
        except Exception:
            return {'out': _json_response(400, {'error': 'bad request'})}
        if msg.get('t') in ('hello', 'auth'):
            return {'plain': msg}
        return relink            # a request is only ever answered sealed

    def _run(self, peer: _Peer, job: dict) -> bytes:
        try:
            if 'req' in job:
                out = self._request(peer, job['req'])
            elif 'plain' in job:
                out = self._hello(peer, job['plain']) if job['plain']['t'] == 'hello' \
                    else self._auth(peer, job['plain'])
            else:
                out = job['out']
        except Exception as e:  # never let a worker die silently
            if self.logger:
                self.logger.error(f'[ble-link] {e}')
            out = _json_response(500, {'error': 'link error'})
        if 'seal' in job:
            key, counter = job['seal']
            out = seal_answer(key, counter, out)
        with self._lock:
            self._stats['bytes_out'] += len(out)
        return out

    def _answer(self, peer: _Peer, msg_id: int, job: dict, send) -> None:
        out = self._run(peer, job)
        try:
            send(split_frames(msg_id, out, peer.frame_size))
        except Exception:
            pass
        if self.on_activity:
            try:
                self.on_activity()
            except Exception:
                pass

    def _locked(self) -> Optional[bytes]:
        with self._lock:
            wait = self._locked_until - time.monotonic()
        if wait > 0:
            return _json_response(429, {'error': 'Too many wrong codes. Try again later.',
                                        'retry_in': int(wait) + 1})
        return None

    def _hello(self, peer: _Peer, msg: dict) -> bytes:
        """First step: the phone's X in, the unit's Y out."""
        with self._lock:
            peer.pending = peer.keys = None
            peer.counter = 0
        if not CRYPTO_OK:
            return _json_response(503, {'error': 'This Ragnar is missing PyNaCl — run its update.'})
        if msg.get('v') != PROTOCOL_VERSION:
            return _json_response(426, {'error': 'Update the Ragnar Mobile app.',
                                        'v': PROTOCOL_VERSION})
        locked = self._locked()
        if locked:
            return locked
        cid = str(msg.get('cid') or '')[:64]
        try:
            X = bytes.fromhex(str(msg.get('x') or ''))
            if not cid:
                raise ValueError('no client id')
            Y, keys = unit_exchange(self.code(), cid, X)
        except ValueError:
            return _json_response(400, {'error': 'bad hello'})
        with self._lock:
            peer.cid = cid
            peer.pending = keys
        return _json_response(200, {'v': PROTOCOL_VERSION, 'y': Y.hex(),
                                    'max_response': MAX_RESPONSE_BYTES})

    def _auth(self, peer: _Peer, msg: dict) -> bytes:
        """Second step: the phone proves it reached the same keys (it knows the
        code); the unit proves the same back."""
        locked = self._locked()
        if locked:
            return locked
        with self._lock:
            keys, peer.pending = peer.pending, None    # one attempt per hello
        if not keys:
            return _json_response(400, {'error': 'hello first'})
        try:
            proof = bytes.fromhex(str(msg.get('proof') or ''))
        except ValueError:
            proof = b''
        ok = hmac.compare_digest(keys['proof_app'], proof)
        now = time.monotonic()
        with self._lock:
            if ok:
                self._fails = 0
                self._lock_len = LOCK_START_S
                peer.keys = keys
                peer.counter = 0
            else:
                self._fails += 1
                self._stats['refused'] += 1
                if self._fails >= FAILS_BEFORE_LOCK:
                    self._fails = 0
                    self._locked_until = now + self._lock_len
                    self._lock_len = min(self._lock_len * 2, LOCK_MAX_S)
        if not ok:
            return _json_response(401, {'error': 'Wrong link code.', 'link_auth': True})
        return _json_response(200, {'ok': True, 'proof': keys['proof_unit'].hex()})

    def _request(self, peer: _Peer, msg: dict) -> bytes:
        method = str(msg.get('m') or 'GET').upper()
        path = str(msg.get('p') or '')
        if method not in ('GET', 'POST', 'DELETE') or not path.startswith('/api/'):
            return _json_response(403, {'error': 'Not available over Bluetooth.'})
        bare = path.split('?', 1)[0]
        if bare.startswith(_BLOCKED_PREFIXES):
            return _json_response(403, {'error': 'Not available over Bluetooth.'})

        headers = {'X-Ragnar-Link': 'ble'}
        for k, v in (msg.get('h') or {}).items():
            if str(k).lower() in _ALLOWED_HEADERS:
                headers[str(k)] = str(v)
        with self._lock:
            jar = dict(self._cookies.get(peer.cid) or {})
        if jar:
            headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in jar.items())

        kwargs = {'method': method, 'headers': headers, 'buffered': False}
        if msg.get('b') is not None:
            kwargs['json'] = msg['b']

        with self._lock:
            self._stats['requests'] += 1
            self._stats['last_request'] = time.time()

        client = self.app.test_client(use_cookies=False)
        resp = client.open(path, **kwargs)
        try:
            self._keep_cookies(peer.cid, resp)
            mimetype = (resp.mimetype or '').lower()
            if mimetype in _STREAM_TYPES:
                return _json_response(415, {'error': 'Live streams need Wi-Fi or the mesh.',
                                            'bluetooth_limit': True})
            # send_file() answers are "direct passthrough"; read them like any other.
            resp.direct_passthrough = False
            deadline = time.monotonic() + REQUEST_DEADLINE_S
            body = bytearray()
            for chunk in resp.iter_encoded():
                body += chunk
                if len(body) > MAX_RAW_BYTES or time.monotonic() > deadline:
                    return self._too_large(len(body))
            packed = pack_response(resp.status_code, bytes(body),
                                   is_json=mimetype == 'application/json')
            if len(packed) > MAX_RESPONSE_BYTES:
                return self._too_large(len(body))
            return packed
        finally:
            try:
                resp.close()
            except Exception:
                pass

    @staticmethod
    def _too_large(size: int) -> bytes:
        return _json_response(413, {
            'error': 'Too much data for Bluetooth — this needs Wi-Fi or the mesh.',
            'bluetooth_limit': True, 'bytes': size,
        })

    def _keep_cookies(self, cid, resp) -> None:
        fresh = {}
        for raw in resp.headers.getlist('Set-Cookie'):
            pair = raw.split(';', 1)[0]
            if '=' in pair:
                name, value = pair.split('=', 1)
                fresh[name.strip()] = value.strip()
        if not fresh or not cid:
            return
        with self._lock:
            jar = self._cookies.pop(cid, {})
            for name, value in fresh.items():
                if value:
                    jar[name] = value
                else:
                    jar.pop(name, None)       # the server cleared it (logout)
            self._cookies[cid] = jar          # re-insert: most recently used last
            while len(self._cookies) > MAX_CLIENTS:
                self._cookies.pop(next(iter(self._cookies)))

    # -- whole messages (the development simulator) -------------------------
    def message(self, peer_key: str, raw: bytes) -> bytes:
        """Answer one complete request message synchronously. The browser build
        of the app has no Bluetooth; it posts link messages to the unit over
        HTTP instead, so the same code path can be reviewed from a desk."""
        with self._lock:
            peer = self._peers.get(peer_key)
            if peer is None:
                peer = self._peers[peer_key] = _Peer()
            peer.last = time.monotonic()
        return self._run(peer, self._open(peer, raw))


if __name__ == '__main__':  # tiny self-check, no Bluetooth needed
    frames = split_frames(7, os.urandom(1000), 185)
    r = Reassembler()
    got = [r.feed(f) for f in frames][-1]
    print('frames:', len(frames), 'roundtrip:', got is not None and len(got[1]) == 1000)
