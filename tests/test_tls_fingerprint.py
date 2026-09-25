"""Unit tests for tls_fingerprint.JA3Collector."""

from unittest.mock import patch

import pytest

from tls_fingerprint import JA3Collector, JA3Match, _looks_like_md5, load_signatures


JA3_KNOWN = "72a589da586844d7f0818ce684948eea"  # Trickbot in seed DB
JA3_UNKNOWN = "deadbeefdeadbeefdeadbeefdeadbeef"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _line(*fields):
    return '|'.join(str(f) for f in fields)


@pytest.fixture
def collector():
    sigs = {
        JA3_KNOWN: JA3Match(
            ja3=JA3_KNOWN, label="Trickbot", confidence="high",
            source="test", category="malware",
        ),
    }
    return JA3Collector(interface='lo', signatures=sigs)


# ---------------------------------------------------------------------------
# Tiny utilities
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("s,expected", [
    (JA3_KNOWN, True),
    (JA3_KNOWN.upper(), False),  # we expect already-lowered hashes
    ("short", False),
    ("", False),
    ("g" * 32, False),
])
def test_looks_like_md5(s, expected):
    assert _looks_like_md5(s) is expected


def test_load_signatures_missing_file(tmp_path):
    p = tmp_path / 'nope.yaml'
    assert load_signatures(str(p)) == {}


def test_load_signatures_parses_valid_yaml(tmp_path):
    yaml = pytest.importorskip("yaml")
    p = tmp_path / 'sigs.yaml'
    p.write_text(
        "- ja3: " + JA3_KNOWN + "\n"
        "  label: TestThing\n"
        "  confidence: high\n"
        "  source: unit-test\n"
        "  category: malware\n"
    )
    sigs = load_signatures(str(p))
    assert JA3_KNOWN in sigs
    assert sigs[JA3_KNOWN].label == "TestThing"


def test_load_signatures_skips_invalid_entries(tmp_path):
    yaml = pytest.importorskip("yaml")
    p = tmp_path / 'sigs.yaml'
    p.write_text(
        "- ja3: not-a-hash\n  label: x\n"
        "- ja3: " + JA3_KNOWN + "\n  label: y\n"
    )
    sigs = load_signatures(str(p))
    assert list(sigs.keys()) == [JA3_KNOWN]


# ---------------------------------------------------------------------------
# process_line
# ---------------------------------------------------------------------------

def test_process_line_creates_record(collector):
    line = _line("1700000000", "192.168.1.5", "1.2.3.4", "443",
                 JA3_UNKNOWN, "example.com")
    rec = collector.process_line(line)
    assert rec is not None
    assert rec.src_ip == "192.168.1.5"
    assert rec.ja3 == JA3_UNKNOWN
    assert rec.sni == "example.com"
    assert "1.2.3.4" in rec.dst_ips
    assert 443 in rec.dst_ports
    assert rec.count == 1
    assert rec.match is None  # unknown JA3


def test_process_line_classifies_known_signature(collector):
    line = _line("1700000000", "192.168.1.5", "1.2.3.4", "443",
                 JA3_KNOWN, "evil.example")
    rec = collector.process_line(line)
    assert rec.match is not None
    assert rec.match.label == "Trickbot"
    assert rec.match.category == "malware"


def test_process_line_rejects_garbage(collector):
    assert collector.process_line("") is None
    assert collector.process_line("|||") is None
    assert collector.process_line(
        _line("ts", "x", "y", "z", "not-a-hash", "")
    ) is None


def test_process_line_aggregates_repeats(collector):
    line = _line("1700000000", "192.168.1.5", "1.2.3.4", "443",
                 JA3_UNKNOWN, "example.com")
    collector.process_line(line)
    line2 = _line("1700000001", "192.168.1.5", "5.6.7.8", "443",
                  JA3_UNKNOWN, "example.com")
    rec = collector.process_line(line2)
    assert rec.count == 2
    assert {"1.2.3.4", "5.6.7.8"} <= rec.dst_ips


def test_match_callback_fires_only_on_new_known(collector):
    hits = []
    collector._on_match = lambda r: hits.append(r)
    line = _line("1700000000", "192.168.1.5", "1.2.3.4", "443",
                 JA3_KNOWN, "evil.example")
    collector.process_line(line)
    collector.process_line(line)  # duplicate -> no new callback
    assert len(hits) == 1


def test_get_records_orders_classified_first(collector):
    collector.process_line(_line("1700000000", "10.0.0.1", "1.1.1.1", "443",
                                 JA3_UNKNOWN, "a.example"))
    collector.process_line(_line("1700000010", "10.0.0.2", "2.2.2.2", "443",
                                 JA3_KNOWN, "b.example"))
    recs = collector.get_records()
    assert recs[0]['match'] is not None
    assert recs[0]['ja3'] == JA3_KNOWN


def test_max_records_evicts_oldest():
    c = JA3Collector(interface='lo', signatures={})
    c.MAX_RECORDS = 3
    for i in range(5):
        c.process_line(_line(f"170000000{i}", f"10.0.0.{i}", "1.1.1.1",
                             "443", f"{'a' * 32}", f"h{i}"))
    assert len(c._records) == 3


def test_is_available_reflects_tshark_presence():
    with patch('shutil.which', return_value=None):
        c = JA3Collector(interface='lo', signatures={})
        assert c.is_available() is False
        assert c.start() is False
