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
        self.keys = None
        self.pending = None
        self.counter = 0
        self.air = []                      # every byte that crossed, both ways

    def raw(self, payload):
        """One message out, one message back, as bytes."""
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
        self.air.append(payload)
        for f in split_frames(msg_id, payload, 160):
            self.hub.on_frame(self.key, f, self.mtu, send)
        assert done.wait(10), 'no answer'
        rid, answer = got['r']
        assert rid == msg_id
        self.air.append(answer)
        return answer

    @staticmethod
    def _decode(answer):
        status, body, is_json = unpack_response(answer)
        return status, (json.loads(body) if is_json else body)

    def call(self, msg):
        return self._decode(self.raw(json.dumps(msg).encode()))

    def hello(self, code):
        x, X = ble_link.app_start(code)
        status, body = self.call({'t': 'hello', 'v': 2, 'cid': self.cid, 'x': X.hex()})
        if status == 200:
            self.pending = ble_link.app_finish(code, self.cid, x, X, bytes.fromhex(body['y']))
        return status, body

    def auth(self, code):
        """The whole opening: exchange, then proofs both ways."""
        status, body = self.hello(code)
        if status != 200:
            return status, body
        status, body = self.call({'t': 'auth', 'proof': self.pending['proof_app'].hex()})
        if status == 200:
            assert bytes.fromhex(body['proof']) == self.pending['proof_unit']
            self.keys, self.counter = self.pending, 0
        return status, body

    def connect(self, code):
        assert self.auth(code)[0] == 200
        return self

    def req(self, method, path, body=None, headers=None):
        msg = json.dumps({'t': 'req', 'm': method, 'p': path, 'b': body, 'h': headers or {}}).encode()
        self.counter += 1
        answer = self.raw(ble_link.seal_request(self.keys['a2u'], self.counter, msg))
        if answer[:2] != ble_link.SEALED_ANSWER:
            return self._decode(answer)          # the unit asking for a new opening
        return self._decode(ble_link.open_answer(self.keys['u2a'], self.counter, answer))


KAT = {
    'X': '60ea4c559dadee57cd6da5309fdee86e8f2b0648432ac6fa27b49f23d8b2c85f',
    'Y': 'e21e2427cd528d486dc1fbf864bd0de81008cd32da78a16f63157fc2cc6eb9d5',
    'keys': {
        'proof_app': 'caf151027f95ecc3c959bbbb81de385b3647d50a12175271b200e44ef1ec1841',
        'proof_unit': 'c4bf8c1747ae4ba2a45e878992391524961fd3b68718703648a862a7e375a2a4',
        'a2u': '489fe57910d8181021ffc9169620af8b7af0c13b4014803cb22de50052d26730',
        'u2a': 'e2de7ba54b0cbf5a2e7f10af78d979e67b953b28e8c1602a8730647fc834b07d',
    },
    'request': '000000000000000007b398c5c5157efee5b15c064450367a478db1ceeffac2d480fee1f7',
    'answer': 'ffff51993da0a2993957982c77c1430465dd5243dd4c11',
}


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
    # in the clear
    status, body = p.call({'t': 'req', 'm': 'GET', 'p': '/api/ping'})
    assert status == 401 and body['link_auth'] is True
    # sealed with keys the unit never agreed to
    p.keys = ble_link._session_keys('c', b'x' * 32, b'y' * 32, b'k' * 32, b'w' * 32)
    status, body = p.req('GET', '/api/ping')
    assert status == 401 and body['link_auth'] is True
    # after the exchange but before the proof
    p.hello('12345678')
    p.keys, p.counter = p.pending, 0
    assert p.req('GET', '/api/ping')[0] == 401


def test_right_code_opens_the_link_and_requests_reach_flask(hub):
    p = Phone(hub).connect('12345678')
    status, body = p.req('GET', '/api/ping', headers={'X-Ragnar-Target': 'node9', 'X-Evil': '1'})
    assert status == 200 and body == {'pong': True, 'link': 'ble', 'target': 'node9', 'evil': None}
    assert p.req('POST', '/api/echo', {'a': [1, 2]}) == (200, {'a': [1, 2]})


def test_both_ends_reach_the_same_keys_only_with_the_same_code():
    x, X = ble_link.app_start('12345678')
    Y, unit = ble_link.unit_exchange('12345678', 'c', X)
    assert ble_link.app_finish('12345678', 'c', x, X, Y) == unit
    assert ble_link.app_finish('12345679', 'c', x, X, Y) != unit
    assert ble_link.app_finish('12345678', 'other-phone', x, X, Y) != unit
    assert len({unit['a2u'], unit['u2a'], unit['proof_app'], unit['proof_unit']}) == 4
    # a second run of the same code shares nothing with the first
    assert ble_link.unit_exchange('12345678', 'c', X)[1] != unit


def test_known_answer_shared_with_the_app():
    """The same numbers are checked in the app's tests (linkproto.test.ts)."""
    x = bytes.fromhex('0b' * 31 + '00')
    y = bytes.fromhex('0c' * 31 + '00')
    _, X = ble_link.app_start('12345678', x)
    Y, keys = ble_link.unit_exchange('12345678', 'cid-1', X, y)
    assert X.hex() == KAT['X'] and Y.hex() == KAT['Y']
    assert {k: v.hex() for k, v in keys.items()} == KAT['keys']
    assert ble_link.seal_request(keys['a2u'], 7, b'{"t":"req"}').hex() == KAT['request']
    assert ble_link.seal_answer(keys['u2a'], 7, b'\x00\xc8\x02{}').hex() == KAT['answer']


def test_points_a_real_phone_would_not_send_are_refused(hub):
    p = Phone(hub)
    for bad in ('', '00' * 32, '01' + '00' * 31, 'ff' * 32, 'zz', '12' * 31):
        assert p.call({'t': 'hello', 'v': 2, 'cid': 'c', 'x': bad})[0] == 400
    _, X = ble_link.app_start('12345678')
    assert p.call({'t': 'hello', 'v': 1, 'cid': 'c', 'x': X.hex()})[0] == 426
    assert p.call({'t': 'hello', 'v': 2, 'cid': '', 'x': X.hex()})[0] == 400


def test_wrong_code_is_refused_and_a_proof_is_single_use(hub):
    p = Phone(hub)
    assert p.auth('00000000')[0] == 401
    # One proof per exchange: a second try needs a new hello.
    p.hello('12345678')
    assert p.call({'t': 'auth', 'proof': '00' * 32})[0] == 401
    assert p.call({'t': 'auth', 'proof': p.pending['proof_app'].hex()})[0] == 400
    assert p.auth('12345678')[0] == 200


def test_guessing_locks_the_link(hub):
    p = Phone(hub)
    for _ in range(ble_link.FAILS_BEFORE_LOCK):
        assert p.auth('00000000')[0] == 401
    status, body = p.auth('12345678')            # even the right code now waits
    assert status == 429 and body['retry_in'] > 0
    assert hub.status()['locked_for'] > 0


def test_the_air_carries_nothing_readable_and_nothing_to_test_a_code_against(hub):
    p = Phone(hub).connect('12345678')
    assert p.req('POST', '/api/echo', {'wigle_api_token': 'SECRET-TOKEN-VALUE'})[1] == \
        {'wigle_api_token': 'SECRET-TOKEN-VALUE'}
    air = b''.join(p.air)
    for word in (b'SECRET', b'wigle', b'/api/echo', b'12345678'):
        assert word not in air
    # The proofs that did cross are keyed by the exchange, so they differ every
    # time and say nothing about the code on their own.
    q = Phone(hub, key='dev2').connect('12345678')
    assert q.keys['proof_app'] != p.keys['proof_app']


def test_a_recorded_request_cannot_be_replayed_or_altered(hub):
    p = Phone(hub).connect('12345678')
    msg = json.dumps({'t': 'req', 'm': 'POST', 'p': '/api/echo', 'b': {'n': 1}, 'h': {}}).encode()
    sealed = ble_link.seal_request(p.keys['a2u'], 1, msg)
    first = p.raw(sealed)
    assert first[:2] == ble_link.SEALED_ANSWER
    assert unpack_response(p.raw(sealed))[0] == 401                 # replay
    bent = bytearray(ble_link.seal_request(p.keys['a2u'], 2, msg))
    bent[-1] ^= 1
    assert unpack_response(p.raw(bytes(bent)))[0] == 401            # altered
    # an answer only opens under its own request's counter
    with pytest.raises(Exception):
        ble_link.open_answer(p.keys['u2a'], 2, first)
    p.counter = 5
    assert p.req('GET', '/api/ping')[0] == 200


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


def test_a_code_is_created_and_saved_when_there_is_none():
    cfg, saved = {}, []
    hub = LinkHub(_app(), get_config=lambda: cfg, save_config=lambda: saved.append(1))
    code = hub.code()
    assert code.isdigit() and len(code) == 8 and cfg['ble_link_code'] == code and saved
    assert hub.code() == code


def test_whole_message_path_used_by_the_simulator(hub):
    def post(peer, msg):
        return hub.message(peer, json.dumps(msg).encode())

    x, X = ble_link.app_start('12345678')
    hello = json.loads(unpack_response(post('sim:a', {'t': 'hello', 'v': 2, 'cid': 'c9', 'x': X.hex()}))[1])
    keys = ble_link.app_finish('12345678', 'c9', x, X, bytes.fromhex(hello['y']))
    assert unpack_response(post('sim:a', {'t': 'auth', 'proof': keys['proof_app'].hex()}))[0] == 200
    req = json.dumps({'t': 'req', 'm': 'GET', 'p': '/api/ping'}).encode()
    answer = hub.message('sim:a', ble_link.seal_request(keys['a2u'], 1, req))
    status, body, is_json = unpack_response(ble_link.open_answer(keys['u2a'], 1, answer))
    assert status == 200 and is_json and json.loads(body)['pong'] is True
    assert unpack_response(hub.message('sim:b', ble_link.seal_request(keys['a2u'], 1, req)))[0] == 401


def test_what_is_readable_before_the_code_names_only_a_ragnar():
    """The one readable characteristic is open to anyone in radio range, so it
    must not say where the unit is or what it runs."""
    import ble_peripheral
    info = ble_peripheral.DataProviders('/nonexistent', 'hci0', lambda: {}, link=object()).device_info()
    assert set(info) == {'name', 'box_id', 'link'} and info['link'] == 1
    assert ble_peripheral.DataProviders('/nonexistent', 'hci0', lambda: {}).device_info()['link'] == 0
    for gone in ('net_status', 'ap_creds', 'apply_ap'):
        assert not hasattr(ble_peripheral.DataProviders, gone)


def test_answers_still_go_out_when_the_thread_pool_refuses(hub):
    """Python 3.14's ThreadPoolExecutor can refuse new work with "cannot
    schedule new futures after interpreter shutdown" on a long-lived process
    that is still serving. The link must fall back to a plain thread so a
    phone's hello is still answered (otherwise every Kali/3.14 box times out)."""
    def refuse(*a, **k):
        raise RuntimeError('cannot schedule new futures after interpreter shutdown')
    hub._pool.submit = refuse
    status, body = Phone(hub).hello('12345678')
    assert status == 200 and 'y' in body
