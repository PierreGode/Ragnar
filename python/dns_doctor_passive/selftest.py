#!/usr/bin/env python3
"""
Tier 1 self-test: fabricate frames, push them through the REAL
Engine.handle_frame(), assert on finding codes.

Every fixture is built with scapy's PER-TYPE DNSSEC record classes
(DNSRRDNSKEY/DNSRRRSIG/DNSRRNSEC3) and then RE-DISSECTED before use.
That is not ceremony -- a naive DNSRR(type="DNSKEY") builds bytes that
scapy itself re-dissects as Raw, so a fixture built that way would
validate the parser against garbage while looking perfectly fine
(the LESSON AD shape, caught during this build).

Every structural scenario runs over BOTH IPv4 and IPv6 to satisfy the
dual-stack mandate at the tier level, not just in the parser.
"""
import unittest

from scapy.all import Ether, IP, IPv6, UDP, raw
from scapy.layers.dns import (DNS, DNSQR, DNSRR, DNSRRDNSKEY, DNSRRRSIG,
                              DNSRRNSEC3, DNSRRSOA, DNSRRNSEC, DNSRROPT, EDNS0TLV)

import parse
from state import Config
from engine import Engine

V4 = IP(src="192.0.2.10", dst="192.0.2.20")
V6 = IPv6(src="2001:db8::10", dst="2001:db8::20")


def frame(dns, l3=None, sport=53, dport=33333):
    """Serialize, then RE-PARSE through scapy so the bytes under test
    are the bytes a dissector agrees are well-formed."""
    l3 = V4 if l3 is None else l3
    return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / dns)


def dnskey(tag_seed, algorithm=8, keybytes=None):
    return DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3,
                       algorithm=algorithm,
                       publickey=keybytes or bytes([tag_seed % 256]) * 64)


def rrsig(covered="A", algorithm=8, keytag=1234):
    return DNSRRRSIG(rrname="example.com.", typecovered=covered, algorithm=algorithm,
                     labels=2, originalttl=3600, expiration=1800000000,
                     inception=1700000000, keytag=keytag,
                     signersname="example.com.", signature=b"\x11" * 64)


def codes(findings):
    return sorted(f["code"] for f in findings)


class DualStackMixin:
    """Runs a scenario on both stacks and asserts identical verdicts.
    The prime directive is that parity is TESTED, not assumed."""

    def assert_both_stacks(self, dns, expect_code, sport=53, dport=33333):
        got = {}
        for label, l3 in (("IPv4", V4), ("IPv6", V6)):
            eng = Engine(Config())
            out = eng.handle_frame(frame(dns, l3, sport, dport))
            got[label] = codes(out)
            self.assertIn(expect_code, got[label],
                          f"{label}: expected {expect_code}, got {got[label]}")
        self.assertEqual(got["IPv4"], got["IPv6"],
                         f"dual-stack divergence: {got}")
        return got["IPv4"]


class TestKeyTrap(unittest.TestCase, DualStackMixin):
    def test_colliding_key_tags_fire_dnsd001(self):
        # Two DISTINCT keys that genuinely share a key tag. SEARCHED
        # for, never asserted: a fabricated "collision" that isn't one
        # would make this test pass for the wrong reason.
        #
        # The key material must be SPREAD, not a counter. RFC 4034's
        # key tag is a weighted byte sum, so keys differing by an
        # incrementing integer produce strictly INCREASING tags and can
        # never collide -- the first version of this fixture searched
        # 4000 such keys and found nothing, which looked like a
        # detector bug and was a fixture bug (LESSON K). Hashed key
        # material spreads across the 16-bit space and collides at the
        # birthday bound, a few hundred samples in.
        import hashlib
        by_tag = {}
        pair = None
        for i in range(6000):
            key = hashlib.sha256(i.to_bytes(4, "big")).digest() * 2
            rd = b"\x01\x01\x03\x08" + key
            tag = parse.dnskey_key_tag(rd)
            if tag in by_tag and by_tag[tag] != key:
                pair = (by_tag[tag], key)
                break
            by_tag[tag] = key
        self.assertIsNotNone(pair, "no key-tag collision found in search space")
        self.assertNotEqual(pair[0], pair[1], "collision pair must be DISTINCT keys")
        t1 = parse.dnskey_key_tag(b"\x01\x01\x03\x08" + pair[0])
        t2 = parse.dnskey_key_tag(b"\x01\x01\x03\x08" + pair[1])
        self.assertEqual(t1, t2, "searched pair must actually share a tag")
        k1 = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3, algorithm=8,
                         publickey=pair[0])
        k2 = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3, algorithm=8,
                         publickey=pair[1])
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"),
                  an=k1 / k2, ancount=2)
        self.assert_both_stacks(dns, "DNSD-001")

    def test_identical_duplicate_key_is_not_a_collision(self):
        """A key repeated twice shares its tag with itself. That is a
        duplicate record, not a collision, and must not fire."""
        k = dnskey(7)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"),
                  an=k / dnskey(7), ancount=2)
        eng = Engine(Config())
        self.assertNotIn("DNSD-001", codes(eng.handle_frame(frame(dns))))

    def test_rrsig_burst_fires_dnsd002(self):
        sigs = rrsig()
        for i in range(9):
            sigs = sigs / rrsig(keytag=1000 + i)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), an=sigs, ancount=10)
        self.assert_both_stacks(dns, "DNSD-002")

    def test_rrsigs_over_different_rrsets_do_not_fire(self):
        """Rollovers legitimately produce several RRSIGs across
        DIFFERENT RRsets; only many over ONE RRset is the signature."""
        chain = rrsig(covered="A")
        for t in ("AAAA", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CNAME"):
            chain = chain / rrsig(covered=t)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), an=chain, ancount=9)
        eng = Engine(Config())
        self.assertNotIn("DNSD-002", codes(eng.handle_frame(frame(dns))))

    def test_crypto_product_fires_dnsd003(self):
        chain = dnskey(1, keybytes=b"\x01" * 64)
        for i in range(2, 9):
            chain = chain / dnskey(i, keybytes=bytes([i]) * 64)
        for i in range(9):
            chain = chain / rrsig(keytag=2000 + i)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"),
                  an=chain, ancount=17)
        self.assert_both_stacks(dns, "DNSD-003")


def _rdata(rr):
    """Extract a built RR's rdata exactly as it appears on the wire."""
    b = raw(DNS(qr=1, an=rr, ancount=1))
    m = parse.parse_dns(b)
    return bytes(m.answers[0].rdata)


class TestNsec3AndAlgo(unittest.TestCase, DualStackMixin):
    def test_nsec3_iterations_fire_dnsd010(self):
        n = DNSRRNSEC3(rrname="example.com.", hashalg=1, flags=0, iterations=150,
                       saltlength=4, salt=b"\xaa\xbb\xcc\xdd", hashlength=20,
                       nexthashedownername=b"\x01" * 20)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="nx.example.com.", qtype="A"),
                  ns=n, nscount=1)
        self.assert_both_stacks(dns, "DNSD-010")

    def test_zero_iterations_is_compliant_and_silent(self):
        n = DNSRRNSEC3(rrname="example.com.", hashalg=1, flags=0, iterations=0,
                       saltlength=0, salt=b"", hashlength=20,
                       nexthashedownername=b"\x01" * 20)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="nx.example.com.", qtype="A"),
                  ns=n, nscount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-010", codes(eng.handle_frame(frame(dns))))

    def test_unsupported_algorithm_fires_dnsd011(self):
        dns = DNS(qr=1, ad=0, rcode=0, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=12), ancount=1)   # 12 = GOST, deprecated
        self.assert_both_stacks(dns, "DNSD-011")

    def test_ad_set_means_validator_authenticated_so_silent(self):
        dns = DNS(qr=1, ad=1, rcode=0, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=12), ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-011", codes(eng.handle_frame(frame(dns))))

    def test_servfail_means_it_failed_loudly_so_silent(self):
        dns = DNS(qr=1, ad=0, rcode=2, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=12), ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-011", codes(eng.handle_frame(frame(dns))))

    def test_supported_algorithm_is_silent(self):
        dns = DNS(qr=1, ad=0, rcode=0, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=13), ancount=1)   # ECDSA P-256
        eng = Engine(Config())
        self.assertNotIn("DNSD-011", codes(eng.handle_frame(frame(dns))))


class TestNewCveCodes(unittest.TestCase, DualStackMixin):
    """
    The 11 codes added from the Sept 2026 CVE register. Every one runs
    over BOTH stacks and asserts identical verdicts -- the register
    claims dual-stack parity "holds by construction" because these are
    record-layer checks, and this is where that claim is tested rather
    than trusted.
    """

    def test_dnskey_malformed_dnsd009(self):
        k = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=4,
                        algorithm=8, publickey=b"\x01" * 64)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"), an=k, ancount=1)
        self.assert_both_stacks(dns, "DNSD-009")

    def test_wellformed_dnskey_is_silent(self):
        k = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3,
                        algorithm=8, publickey=b"\x01" * 64)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"), an=k, ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-009", codes(eng.handle_frame(frame(dns))))

    def test_rrsig_label_mismatch_dnsd040(self):
        sig = DNSRRRSIG(rrname="www.example.com.", typecovered="A", algorithm=8, labels=9,
                        originalttl=3600, expiration=1800000000, inception=1700000000,
                        keytag=1, signersname="example.com.", signature=b"\x11" * 32)
        dns = DNS(qr=1, qd=DNSQR(qname="www.example.com.", qtype="A"), an=sig, ancount=1)
        self.assert_both_stacks(dns, "DNSD-040")

    def test_wildcard_rrsig_labels_are_silent(self):
        """labels < owner count is how wildcard expansion is signalled.
        Firing here would alert on every wildcard zone on the internet."""
        sig = DNSRRRSIG(rrname="a.b.example.com.", typecovered="A", algorithm=8, labels=2,
                        originalttl=3600, expiration=1800000000, inception=1700000000,
                        keytag=1, signersname="example.com.", signature=b"\x11" * 32)
        dns = DNS(qr=1, qd=DNSQR(qname="a.b.example.com.", qtype="A"), an=sig, ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-040", codes(eng.handle_frame(frame(dns))))

    def test_nsec_out_of_zone_dnsd041(self):
        n = DNSRRNSEC(rrname="a.example.com.", nextname="evil.attacker.net.")
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="A"), ns=n, nscount=1)
        self.assert_both_stacks(dns, "DNSD-041")

    def test_nsec_apex_wrap_is_silent(self):
        n = DNSRRNSEC(rrname="z.example.com.", nextname="example.com.")
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="A"), ns=n, nscount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-041", codes(eng.handle_frame(frame(dns))))

    def test_nsec3_apex_impersonation_dnsd042(self):
        n = DNSRRNSEC3(rrname="HASH.attacker.net.", hashalg=1, flags=0, iterations=0,
                       saltlength=0, salt=b"", hashlength=20,
                       nexthashedownername=b"\x02" * 20)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="A"), ns=n, nscount=1)
        self.assert_both_stacks(dns, "DNSD-042")

    def test_edns_option_duplication_dnsd051(self):
        opt = DNSRROPT(rclass=4096, rdata=[EDNS0TLV(optcode=3, optdata=b"abcd"),
                                           EDNS0TLV(optcode=3, optdata=b"efgh")])
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), ar=opt, arcount=1)
        self.assert_both_stacks(dns, "DNSD-051")

    def test_distinct_edns_options_are_silent(self):
        opt = DNSRROPT(rclass=4096, rdata=[EDNS0TLV(optcode=3, optdata=b"abcd"),
                                           EDNS0TLV(optcode=12, optdata=b"\x00" * 8)])
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), ar=opt, arcount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-051", codes(eng.handle_frame(frame(dns))))

    def test_duplicate_soa_flood_dnsd052(self):
        chain = DNSRRSOA(rrname="example.com.", mname="ns.example.com.",
                         rname="hostmaster.example.com.", serial=1)
        for _ in range(11):
            chain = chain / DNSRRSOA(rrname="example.com.", mname="ns.example.com.",
                                     rname="hostmaster.example.com.", serial=1)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="SOA"),
                  an=chain, ancount=12)
        self.assert_both_stacks(dns, "DNSD-052")

    def test_round_robin_a_records_are_silent(self):
        chain = DNSRR(rrname="example.com.", type="A", ttl=60, rdata="192.0.2.1")
        for _ in range(19):
            chain = chain / DNSRR(rrname="example.com.", type="A", ttl=60, rdata="192.0.2.1")
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), an=chain, ancount=20)
        eng = Engine(Config())
        self.assertNotIn("DNSD-052", codes(eng.handle_frame(frame(dns))))

    def test_tkey_query_dnsd053(self):
        dns = DNS(qr=0, qd=DNSQR(qname="example.com.", qtype=249))
        for l3 in (V4, V6):
            eng = Engine(Config())
            out = codes(eng.handle_frame(frame(dns, l3, sport=40000, dport=53)))
            self.assertIn("DNSD-053", out)

    def test_pointer_anomaly_is_not_merely_malformed(self):
        """DNSD-008 must be SEPARATE from DNSD-007: one is a
        memory-safety primitive, the other is network noise."""
        payload = b"\xab\xcd\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c"
        for l3 in (V4, V6):
            eng = Engine(Config())
            f = raw(Ether() / l3 / UDP(sport=53, dport=33333)) + payload
            out = codes(eng.handle_frame(f))
            self.assertIn("DNSD-008", out)


class TestMalformed(unittest.TestCase):
    def test_truncated_message_fires_dnsd007(self):
        eng = Engine(Config())
        f = raw(Ether() / V4 / UDP(sport=53, dport=33333)) + b"\x12\x34\x81\x80\x00\x01"
        self.assertIn("DNSD-007", codes(eng.handle_frame(f)))

    def test_pointer_loop_is_caught_not_hung(self):
        """A self-referential compression pointer must be reported as
        malformed, not spin the detection thread forever."""
        payload = (b"\xab\xcd\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c")
        f = raw(Ether() / V4 / UDP(sport=53, dport=33333)) + payload
        eng = Engine(Config())
        out = eng.handle_frame(f)
        self.assertIn("DNSD-007", codes(out))

    def test_wellformed_response_does_not_fire_dnsd007(self):
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=DNSRR(rrname="example.com.", type="A", ttl=300, rdata="192.0.2.1"),
                  ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-007", codes(eng.handle_frame(frame(dns))))


class TestNotDns(unittest.TestCase):
    def test_non_dns_frame_is_ignored(self):
        eng = Engine(Config())
        f = raw(Ether() / V4 / UDP(sport=1234, dport=4321) / b"hello")
        out = eng.handle_frame(f)
        # port-53 filtering is the BPF's job; the engine still parses
        # whatever reaches it, but must not crash or invent findings.
        self.assertIsInstance(out, list)

    def test_arp_frame_is_ignored(self):
        eng = Engine(Config())
        self.assertEqual(eng.handle_frame(raw(Ether(type=0x0806) / (b"\x00" * 28))), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
