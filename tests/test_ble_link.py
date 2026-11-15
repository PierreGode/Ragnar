"""The Bluetooth link: the app's small requests carried over BLE.

No radio here — ble_link.py is pure Python on purpose. A small Flask app stands
in for Ragnar's, and frames are passed in and out by hand.
"""
import json
import os
import sys
import threading

import pytest
from flask import Flask, Response, jsonify, request, session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import ble_link
from ble_link import LinkHub, Reassembler, split_frames, unpack_response


def _app():
    app = Flask(__name__)
    app.secret_key = 'test'

    @app.route('/api/ping')
    def ping():
        return jsonify({'pong': True, 'link': request.headers.get('X-Ragnar-Link'),
                        'target': request.headers.get('X-Ragnar-Target'),
                        'evil': request.headers.get('X-Evil')})

    @app.route('/api/echo', methods=['POST'])
    def echo():
        return jsonify(request.get_json())

    @app.route('/api/login', methods=['POST'])
    def login():
        session['user'] = 'pierre'
        return jsonify({'ok': True})

    @app.route('/api/me')
    def me():
        return jsonify({'user': session.get('user')})

    @app.route('/api/big')
    def big():
        return jsonify({'rows': ['x' * 50] * int(request.args.get('n', 10))})

    @app.route('/api/random')
    def rnd():
        return Response(os.urandom(int(request.args.get('n', 10))), mimetype='application/octet-stream')

    @app.route('/api/stream')
    def stream():
        def gen():
            while True:
                yield 'data: x\n\n'
        return Response(gen(), mimetype='text/event-stream')

    @app.route('/api/csv')
    def csv():
        return Response('a,b\n1,2\n', mimetype='text/csv')

    @app.route('/secret.html')
    def page():
        return 'page'

    return app


class Phone:
    """Drives a hub the way the app does: frames in, frames out."""

    def __init__(self, hub, key='dev1', cid='cid-1', mtu=185):
        self.hub, self.key, self.cid, self.mtu = hub, key, cid, mtu
        self.rx = Reassembler(limit=10 ** 7)
        self.next_id = 1
        self.nonce = None

    def call(self, msg):
        done = threading.Event()
        got = {}

        def send(frames):
            for f in frames:
                assert len(f) <= self.mtu - 3
                r = self.rx.feed(f)
                if r:
                    got['r'] = r
                    done.set()

        msg_id = self.next_id
        self.next_id += 1
        for f in split_frames(msg_id, json.dumps(msg).encode(), 160):
            self.hub.on_frame(self.key, f, self.mtu, send)
        assert done.wait(10), 'no answer'
        rid, raw = got['r']
        assert rid == msg_id
        status, body, is_json = unpack_response(raw)
        return status, (json.loads(body) if is_json else body)

    def hello(self):
        status, body = self.call({'t': 'hello', 'cid': self.cid})
        assert status == 200
        self.nonce = body['nonce']
        return body

    def auth(self, code):
        status, body = self.call({'t': 'auth', 'mac': ble_link.auth_mac(code, self.nonce, self.cid)})
        self.nonce = body.get('nonce', self.nonce)
        return status, body

    def connect(self, code):
        self.hello()
        assert self.auth(code)[0] == 200
        return self

    def req(self, method, path, body=None, headers=None):
        return self.call({'t': 'req', 'm': method, 'p': path, 'b': body, 'h': headers or {}})


@pytest.fixture
def hub():
    cfg = {'ble_link_code': '12345678'}
    return LinkHub(_app(), get_config=lambda: cfg)


def test_frames_round_trip_at_every_size():
    for size in (0, 1, 15, 16, 17, 181, 1000, 70000):
        payload = os.urandom(size)
        frames = split_frames(9, payload, 20)
        assert all(len(f) <= 20 for f in frames)
        r = Reassembler(limit=10 ** 6)
        out = [r.feed(f) for f in frames]
        assert out[-1] == (9, payload) and all(o is None for o in out[:-1])


def test_reassembler_rejects_gaps_and_oversize():
    frames = split_frames(1, b'x' * 100, 20)
    r = Reassembler()
    r.feed(frames[0])
    with pytest.raises(ValueError):
        r.feed(frames[2])                       # frame 1 went missing
    r = Reassembler(limit=50)
    with pytest.raises(ValueError):
        for f in frames:
            r.feed(f)


def test_interleaved_messages_keep_apart():
    a, b = split_frames(1, b'A' * 60, 20), split_frames(2, b'B' * 60, 20)
    r = Reassembler()
    done = [r.feed(f) for pair in zip(a, b) for f in pair]
    assert (1, b'A' * 60) in done and (2, b'B' * 60) in done


def test_nothing_is_answered_before_the_code(hub):
    p = Phone(hub)
    p.hello()
    status, body = p.req('GET', '/api/ping')
    assert status == 401 and body['link_auth'] is True


def test_right_code_opens_the_link_and_requests_reach_flask(hub):
    p = Phone(hub).connect('12345678')
    status, body = p.req('GET', '/api/ping', headers={'X-Ragnar-Target': 'node9', 'X-Evil': '1'})
    assert status == 200 and body == {'pong': True, 'link': 'ble', 'target': 'node9', 'evil': None}
    assert p.req('POST', '/api/echo', {'a': [1, 2]}) == (200, {'a': [1, 2]})


def test_wrong_code_is_refused_and_a_nonce_is_single_use(hub):
    p = Phone(hub)
    p.hello()
    first = p.nonce
    status, body = p.auth('00000000')
    assert status == 401 and body['nonce'] != first
    # Replaying the answer to the old nonce must not work, even with the right code.
    status, body = p.call({'t': 'auth', 'mac': ble_link.auth_mac('12345678', first, p.cid)})
    assert status == 401
    p.nonce = body['nonce']
    assert p.auth('12345678')[0] == 200


def test_guessing_locks_the_link(hub):
    p = Phone(hub)
    p.hello()
    for _ in range(ble_link.FAILS_BEFORE_LOCK):
        assert p.auth('00000000')[0] == 401
    status, body = p.auth('12345678')            # even the right code now waits
    assert status == 429 and body['retry_in'] > 0
    assert hub.status()['locked_for'] > 0


def test_login_cookie_survives_a_reconnect_but_not_another_phone(hub):
    p = Phone(hub).connect('12345678')
    assert p.req('POST', '/api/login', {})[0] == 200
    assert p.req('GET', '/api/me')[1] == {'user': 'pierre'}
    again = Phone(hub, key='dev1-new-address', cid='cid-1').connect('12345678')
    assert again.req('GET', '/api/me')[1] == {'user': 'pierre'}
    other = Phone(hub, key='dev2', cid='cid-2').connect('12345678')
    assert other.req('GET', '/api/me')[1] == {'user': None}


def test_only_api_paths_and_no_streams(hub):
    p = Phone(hub).connect('12345678')
    assert p.req('GET', '/secret.html')[0] == 403
    assert p.req('GET', '/api/ble/link/sim')[0] == 403
    assert p.req('PUT', '/api/ping')[0] == 403
    status, body = p.req('GET', '/api/stream')
    assert status == 415 and body['bluetooth_limit'] is True


def test_compressible_answers_pass_and_incompressible_ones_are_refused(hub):
    p = Phone(hub, mtu=517).connect('12345678')
    status, body = p.req('GET', '/api/big?n=20000')          # ~1 MB of JSON, tiny zipped
    assert status == 200 and len(body['rows']) == 20000
    status, body = p.req('GET', f'/api/random?n={ble_link.MAX_RESPONSE_BYTES + 5000}')
    assert status == 413 and body['bluetooth_limit'] is True
    status, body = p.req('GET', '/api/random?n=2000')
    assert status == 200 and len(body) == 2000              # binary comes back as bytes
    assert p.req('GET', '/api/csv') == (200, b'a,b\n1,2\n')


def test_switching_the_link_off_refuses_everything(hub):
    cfg = {'ble_link_code': '12345678', 'ble_link_enabled': False}
    off = LinkHub(_app(), get_config=lambda: cfg)
    p = Phone(off)
    assert p.call({'t': 'hello', 'cid': 'c'})[0] == 403


def test_a_code_is_created_and_saved_when_there_is_none():
    cfg, saved = {}, []
    hub = LinkHub(_app(), get_config=lambda: cfg, save_config=lambda: saved.append(1))
    code = hub.code()
    assert code.isdigit() and len(code) == 8 and cfg['ble_link_code'] == code and saved
    assert hub.code() == code


def test_whole_message_path_used_by_the_simulator(hub):
    hello = json.loads(unpack_response(hub.message('sim:a', json.dumps({'t': 'hello', 'cid': 'c9'}).encode()))[1])
    mac = ble_link.auth_mac('12345678', hello['nonce'], 'c9')
    assert unpack_response(hub.message('sim:a', json.dumps({'t': 'auth', 'mac': mac}).encode()))[0] == 200
    status, body, is_json = unpack_response(
        hub.message('sim:a', json.dumps({'t': 'req', 'm': 'GET', 'p': '/api/ping'}).encode()))
    assert status == 200 and is_json and json.loads(body)['pong'] is True
    assert unpack_response(hub.message('sim:b', json.dumps({'t': 'req', 'm': 'GET', 'p': '/api/ping'}).encode()))[0] == 401
