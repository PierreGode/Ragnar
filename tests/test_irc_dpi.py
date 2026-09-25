"""Unit tests for irc_dpi.IRCDPIParser."""

import pytest

from irc_dpi import IRCDPIParser, parse_irc_line


# ---------------------------------------------------------------------------
# parse_irc_line
# ---------------------------------------------------------------------------

def test_parse_simple_command():
    prefix, cmd, params = parse_irc_line("NICK Wiz")
    assert prefix == ""
    assert cmd == "NICK"
    assert params == ["Wiz"]


def test_parse_with_prefix():
    prefix, cmd, params = parse_irc_line(":server.example 001 nick :Welcome!")
    assert prefix == "server.example"
    assert cmd == "001"
    assert params == ["nick", "Welcome!"]


def test_parse_trailing_with_spaces():
    prefix, cmd, params = parse_irc_line("PRIVMSG #chan :hello world from bot")
    assert cmd == "PRIVMSG"
    assert params == ["#chan", "hello world from bot"]


def test_parse_empty_returns_none():
    assert parse_irc_line("") is None
    assert parse_irc_line("\r\n") is None


def test_parse_lowercase_command_normalises():
    _, cmd, _ = parse_irc_line("join #channel")
    assert cmd == "JOIN"


# ---------------------------------------------------------------------------
# feed_payload + session reconstruction
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    return IRCDPIParser(interface='lo')


def _feed(parser, src, dst, sport, dport, ts, text):
    return parser.feed_payload(src, dst, sport, dport, ts,
                               text.encode('utf-8'))


def test_feed_full_client_session(parser):
    bot_ip = '192.168.1.73'
    c2_ip = '203.0.113.10'
    c_port, s_port = 54321, 6667

    _feed(parser, bot_ip, c2_ip, c_port, s_port, 1.0,
          "NICK bot01\r\nUSER bot01 0 * :bot01\r\n")
    _feed(parser, bot_ip, c2_ip, c_port, s_port, 2.0,
          "JOIN #control\r\n")
    _feed(parser, c2_ip, bot_ip, s_port, c_port, 2.5,
          ":server.example 001 bot01 :Welcome to the IRC Network\r\n"
          ":operator!op@host PRIVMSG #control :!exec whoami\r\n")
    _feed(parser, bot_ip, c2_ip, c_port, s_port, 3.0,
          "PRIVMSG #control :root\r\n")

    sessions = parser.get_sessions()
    assert len(sessions) == 1
    s = sessions[0]
    assert s['client_ip'] == bot_ip
    assert s['server_ip'] == c2_ip
    assert s['server_port'] == s_port
    assert s['nick'] == 'bot01'
    assert s['user'] == 'bot01'
    assert '#control' in s['channels']
    assert s['cmd_counts'].get('PRIVMSG') == 2
    assert any('Welcome' in b for b in s['server_banner'])


def test_feed_handles_partial_frames(parser):
    bot_ip = '192.168.1.73'
    c2_ip = '203.0.113.10'
    # Split a single line across two payloads
    msgs1 = _feed(parser, bot_ip, c2_ip, 54321, 6667, 1.0, "NICK b")
    msgs2 = _feed(parser, bot_ip, c2_ip, 54321, 6667, 1.1, "ot01\r\n")
    assert msgs1 == []
    assert len(msgs2) == 1
    assert msgs2[0].command == 'NICK'
    assert msgs2[0].params == ['bot01']


def test_feed_handles_multiple_lines_per_payload(parser):
    msgs = _feed(parser, '10.0.0.1', '10.0.0.2', 4000, 6667, 1.0,
                 "NICK a\r\nUSER a 0 * :a\r\nJOIN #x\r\n")
    cmds = [m.command for m in msgs]
    assert cmds == ['NICK', 'USER', 'JOIN']


def test_feed_ignores_non_irc_ports(parser):
    # Neither port is in the IRC port list -> no parsing, no session
    msgs = _feed(parser, '10.0.0.1', '10.0.0.2', 4000, 80, 1.0,
                 "GET / HTTP/1.1\r\n")
    assert msgs == []
    assert parser.get_sessions() == []


def test_feed_drops_binary_garbage(parser):
    bot_ip, c2_ip = '10.0.0.1', '10.0.0.2'
    # Binary control chars at the start of a 'line' -> not IRC
    payload = b'\x00\x01\x02\x03lots of garbage\n'
    msgs = parser.feed_payload(bot_ip, c2_ip, 1234, 6667, 1.0, payload)
    assert msgs == []


def test_buffer_size_cap_prevents_runaway_growth(parser):
    parser.MAX_BUFFER_PER_FLOW = 64
    # Send >64 bytes without a newline -> buffer should reset
    junk = b'A' * 200
    parser.feed_payload('10.0.0.1', '10.0.0.2', 1234, 6667, 1.0, junk)
    # Now send a proper line; the previous garbage must not bleed in.
    msgs = _feed(parser, '10.0.0.1', '10.0.0.2', 1234, 6667, 2.0,
                 "NICK clean\r\n")
    assert len(msgs) == 1
    assert msgs[0].params == ['clean']


def test_part_removes_channel(parser):
    src, dst = '10.0.0.1', '10.0.0.2'
    _feed(parser, src, dst, 4000, 6667, 1.0, "JOIN #a,#b\r\n")
    _feed(parser, src, dst, 4000, 6667, 2.0, "PART #a\r\n")
    s = parser.get_session(src, dst, 6667)
    assert '#a' not in s['channels']
    assert '#b' in s['channels']


def test_session_event_callback_fires(parser):
    events = []
    parser._on_event = lambda sess, msg: events.append((sess.client_ip, msg.command))
    _feed(parser, '10.0.0.1', '10.0.0.2', 4000, 6667, 1.0,
          "NICK x\r\nJOIN #y\r\n")
    cmds = [e[1] for e in events]
    assert 'NICK' in cmds and 'JOIN' in cmds


def test_clear_resets_state(parser):
    _feed(parser, '10.0.0.1', '10.0.0.2', 4000, 6667, 1.0, "NICK x\r\n")
    assert parser.get_sessions()
    parser.clear()
    assert parser.get_sessions() == []
