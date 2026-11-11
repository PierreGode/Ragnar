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
from scapy.all import Ether, UDP

import parse
import spf as spf_tier
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


class TestMdnsTier(unittest.TestCase):
    """
    The mDNS tier, over both stacks. Matter is IPv6-first, so the v6
    path carries most of the real signal and is tested first-class
    rather than as an afterthought.
    """

    @staticmethod
    def _frame(l3, records, qr=True, sport=5353, dport=5353):
        an = None
        for rr in records:
            an = rr if an is None else an / rr
        dns = DNS(qr=1 if qr else 0, an=an, ancount=len(records))
        return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / dns)

    @staticmethod
    def _ptr(service, instance="Hall Light"):
        return DNSRR(rrname=f"{service}.local.", type="PTR", ttl=4500,
                     rdata=f"{instance}.{service}.local.")

    def _v4(self, ttl=255):
        return IP(src="192.168.1.50", dst="224.0.0.251", ttl=ttl)

    def _v6(self, hlim=255):
        p = IPv6(src="2001:db8:1::50", dst="ff02::fb")
        p.hlim = hlim
        return p

    def test_matter_census_both_stacks(self):
        for label, l3 in (("IPv4", self._v4()), ("IPv6", self._v6())):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
            self.assertIn("DNSD-070", got, f"{label}: {got}")

    def test_zwave_zip_gateway_census(self):
        # DNSD-079: a Silicon Labs Z/IP Gateway advertising _z-wave._udp.
        # Bare presence, both stacks, once per instance.
        for label, l3 in (("IPv4", self._v4()), ("IPv6", self._v6())):
            eng = Engine(Config())
            got = codes(eng.handle_frame(
                self._frame(l3, [self._ptr("_z-wave._udp", "ZIPGateway-01")])))
            self.assertIn("DNSD-079", got, f"{label}: {got}")
        # Once per instance.
        eng = Engine(Config())
        f = self._frame(self._v4(), [self._ptr("_z-wave._udp", "ZIPGateway-01")])
        self.assertIn("DNSD-079", codes(eng.handle_frame(f, now=1.0)))
        self.assertNotIn("DNSD-079", codes(eng.handle_frame(f, now=2.0)),
                         "re-announcement must be suppressed")
        # A bare PTR (no TXT) yields the device type from the instance
        # label, but no TXT keys and -- the point -- no device name.
        eng = Engine(Config())
        out = eng.handle_frame(
            self._frame(self._v4(), [self._ptr("_z-wave._udp", "ZIPGateway-02")]))
        ev = [x["evidence"] for x in out if x["code"] == "DNSD-079"][0]
        self.assertEqual(ev["fingerprint"].get("device_type"), "ZIPGateway-02")
        self.assertNotIn("device_name", ev["fingerprint"])
        self.assertNotIn("product_id", ev["fingerprint"])

    def test_thread_border_router_census(self):
        eng = Engine(Config())
        got = codes(eng.handle_frame(
            self._frame(self._v6(), [self._ptr("_meshcop._udp", "Border Router")])))
        self.assertIn("DNSD-073", got, got)

    def test_commissionable_and_commissioner(self):
        for svc, code in (("_matterc._udp", "DNSD-071"), ("_matterd._udp", "DNSD-072")):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(self._v4(), [self._ptr(svc)])))
            self.assertIn(code, got, f"{svc}: {got}")

    def test_census_reports_once_per_instance(self):
        eng = Engine(Config())
        f = self._frame(self._v4(), [self._ptr("_matter._tcp", "Lamp A")])
        self.assertIn("DNSD-070", codes(eng.handle_frame(f)))
        self.assertNotIn("DNSD-070", codes(eng.handle_frame(f)),
                         "re-announcement must be suppressed")

    def test_ttl_violation_both_stacks(self):
        for label, l3 in (("IPv4 TTL", self._v4(ttl=64)), ("IPv6 hop limit", self._v6(hlim=64))):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
            self.assertIn("DNSD-074", got, f"{label}: {got}")

    def test_compliant_ttl_is_silent(self):
        for l3 in (self._v4(), self._v6()):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
            self.assertNotIn("DNSD-074", got, got)

    def test_off_link_unicast_reflector(self):
        cfg = Config(mdns_local_prefixes=("192.168.1.0/24",))
        eng = Engine(cfg)
        l3 = IP(src="192.168.1.50", dst="203.0.113.77", ttl=255)
        got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
        self.assertIn("DNSD-076", got, got)

    def test_on_link_unicast_is_a_legitimate_qu_reply(self):
        cfg = Config(mdns_local_prefixes=("192.168.1.0/24",))
        eng = Engine(cfg)
        l3 = IP(src="192.168.1.50", dst="192.168.1.77", ttl=255)
        got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
        self.assertNotIn("DNSD-076", got, got)

    def test_mdns_never_triggers_unicast_dns_codes(self):
        """Port routing. Every mDNS name ends in .local, so without
        the split the bailiwick detector alone would fire on nearly
        every announcement on the network."""
        from findings import FINDINGS as _F
        dns_codes = {c for c, m in _F.items() if m["klass"] != "mdns"}
        eng = Engine(Config(mdns_local_prefixes=("192.168.1.0/24",)))
        got = set(codes(eng.handle_frame(
            self._frame(self._v4(), [self._ptr("_matter._tcp"),
                                     self._ptr("_meshcop._udp", "BR")]))))
        self.assertFalse(got & dns_codes, f"leaked unicast-DNS codes: {got & dns_codes}")


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



# ======================================================================
# DDNS / rDNS tiers
# ======================================================================

def ddns_frame(payload, l3=None, sport=33333, dport=53):
    l3 = V4 if l3 is None else l3
    return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / payload)


def update_wire(zone="example.com.", adds=(("host1", "A", "192.0.2.10"),),
                keyname=None, prereq_only=False):
    """UPDATE built by dnspython, an INDEPENDENT implementation.

    The detectors read a hand-rolled parser; if the fixtures came from
    a hand-rolled serializer too, a shared misreading of RFC 2136's
    section semantics would be invisible here (LESSON A).
    """
    import base64
    import dns.update, dns.tsigkeyring, dns.name
    kw = {}
    if keyname:
        kw = {"keyring": dns.tsigkeyring.from_text(
                  {keyname: base64.b64encode(b"0" * 32).decode()}),
              "keyname": keyname,
              "keyalgorithm": dns.name.from_text("hmac-sha256.")}
    u = dns.update.Update(zone, **kw)
    if prereq_only:
        u.present("host9")
        return u.to_wire()
    for n, t, v in adds:
        u.add(n, 300, t, v)
    return u.to_wire()


def update_response(request_wire, rcode=0, tsig=None):
    import struct
    txid = int.from_bytes(request_wire[0:2], "big")
    flags = 0x8000 | (5 << 11) | rcode
    hdr = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 1 if tsig else 0)
    off = 12
    while request_wire[off] != 0:
        off += 1 + request_wire[off]
    zone_sec = request_wire[12:off + 1] + request_wire[off + 1:off + 5]
    return hdr + zone_sec + (tsig or b"")


def tsig_bytes(mac_size=32, mac=None, err=0, algo=b"\x0bhmac-sha256\x00"):
    import struct
    mac = mac if mac is not None else b"\x22" * 32
    rd = (algo + (0).to_bytes(6, "big") + struct.pack("!HH", 300, mac_size) + mac
          + struct.pack("!HHH", 0x1234, err, 0))
    return b"\x01k\x00" + struct.pack("!HHIH", parse.T_TSIG, 255, 0, len(rd)) + rd


# Matched client/server L3 pairs per family, so a response is keyed on
# the same conversation as its request.
PAIRS = (
    ("IPv4", IP(src="10.0.0.5", dst="10.0.0.1"), IP(src="10.0.0.1", dst="10.0.0.5")),
    ("IPv6", IPv6(src="fd00::5", dst="fd00::1"), IPv6(src="fd00::1", dst="fd00::5")),
)


class TestDdnsTier(unittest.TestCase):
    """Every DDNS scenario on BOTH stacks, with identical verdicts
    asserted -- the prime directive is that parity is tested, not
    assumed."""

    def _exchange(self, cfg, req, cli, srv, rcode=0, tsig=None, now=1.0):
        eng = Engine(cfg)
        first = eng.handle_frame(ddns_frame(req, cli, 33333, 53), now=now)
        second = eng.handle_frame(
            ddns_frame(update_response(req, rcode, tsig), srv, 53, 33333), now=now + 0.01)
        return eng, codes(first), codes(second)

    def test_unsigned_update_accepted_both_stacks(self):
        got = {}
        for label, cli, srv in PAIRS:
            _, c1, c2 = self._exchange(Config(), update_wire(), cli, srv)
            self.assertEqual(c1, [], f"{label}: the request alone must report nothing")
            self.assertIn("DNSD-080", c2, f"{label}: got {c2}")
            got[label] = c2
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_rejected_update_is_silent_both_stacks(self):
        for label, cli, srv in PAIRS:
            for rcode in (5, 9, 6, 8):
                _, _, c2 = self._exchange(Config(), update_wire(), cli, srv, rcode=rcode)
                self.assertEqual(c2, [], f"{label}: rcode {rcode} must be silent, got {c2}")

    def test_prereq_only_update_is_silent_both_stacks(self):
        """An UPDATE with an empty update section mutates nothing, so a
        NOERROR says only that the prerequisite held. RFC 4703 DHCP
        clients send this on every renewal."""
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(prereq_only=True), cli, srv)
            self.assertEqual(c2, [], f"{label}: got {c2}")

    def test_tsig_bypass_both_stacks(self):
        got = {}
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(keyname="k."), cli, srv,
                                      rcode=0, tsig=tsig_bytes(err=16))
            self.assertIn("DNSD-081", c2, f"{label}: got {c2}")
            self.assertNotIn("DNSD-080", c2,
                             f"{label}: a signed update is never an unsigned one")
            got[label] = c2
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_notauth_with_badsig_is_correct_behaviour(self):
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(keyname="k."), cli, srv,
                                      rcode=9, tsig=tsig_bytes(err=16))
            self.assertEqual(c2, [], f"{label}: got {c2}")

    def test_clean_signed_update_is_silent(self):
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(keyname="k."), cli, srv,
                                      rcode=0, tsig=tsig_bytes(err=0))
            self.assertEqual(c2, [], f"{label}: got {c2}")

    def test_unexpected_source_needs_config(self):
        out_cidr = {"IPv4": IP(src="203.0.113.9", dst="10.0.0.1"),
                    "IPv6": IPv6(src="2001:db8:bad::9", dst="fd00::1")}
        allow = ("10.0.0.0/24", "fd00::/64")
        for label, cli, _srv in PAIRS:
            eng = Engine(Config(ddns_allowed_updater_prefixes=allow))
            got = codes(eng.handle_frame(ddns_frame(update_wire(), out_cidr[label]), now=1.0))
            self.assertIn("DNSD-082", got, f"{label}: got {got}")
            eng = Engine(Config(ddns_allowed_updater_prefixes=allow))
            self.assertEqual(
                codes(eng.handle_frame(ddns_frame(update_wire(), cli), now=1.0)), [],
                f"{label}: an in-allowlist source must be silent")
            eng = Engine(Config())
            self.assertEqual(
                codes(eng.handle_frame(ddns_frame(update_wire(), out_cidr[label]), now=1.0)), [],
                f"{label}: unconfigured means silent, never 'everything is unexpected'")


class TestRdnsTier(unittest.TestCase):

    @staticmethod
    def _q(name, qtype="PTR"):
        import dns.message
        return dns.message.make_query(name, qtype).to_wire()

    INT = ("10.0.0.0/8", "fd00::/8")
    ULA = ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
           "0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.")

    def test_private_leak_both_families_and_both_transports(self):
        cases = (
            ("v4 private over v4", "1.0.0.10.in-addr.arpa.",
             IP(src="10.0.0.5", dst="8.8.8.8")),
            ("v6 ULA over v4", self.ULA, IP(src="10.0.0.5", dst="9.9.9.9")),
            ("v4 private over v6", "1.0.0.10.in-addr.arpa.",
             IPv6(src="fd00::5", dst="2001:4860:4860::8888")),
            ("v6 ULA over v6", self.ULA, IPv6(src="fd00::5", dst="2001:4860:4860::8888")),
        )
        for label, name, l3 in cases:
            eng = Engine(Config(rdns_internal_prefixes=self.INT))
            got = codes(eng.handle_frame(ddns_frame(self._q(name), l3), now=1.0))
            self.assertIn("DNSD-090", got, f"{label}: got {got}")

    def test_internal_destination_is_ordinary_business(self):
        for l3 in (IP(src="10.0.0.5", dst="10.0.0.1"), IPv6(src="fd00::5", dst="fd00::1")):
            eng = Engine(Config(rdns_internal_prefixes=self.INT))
            self.assertEqual(
                codes(eng.handle_frame(ddns_frame(self._q("1.0.0.10.in-addr.arpa."), l3),
                                       now=1.0)), [])

    def test_doc_range_is_not_private(self):
        """RFC 5737 203.0.113/24 is documentation space, not private
        addressing -- Python's ipaddress disagrees, and that
        disagreement is what let a mutation survive the mDNS suite."""
        eng = Engine(Config(rdns_internal_prefixes=self.INT))
        self.assertEqual(
            codes(eng.handle_frame(ddns_frame(self._q("5.113.0.203.in-addr.arpa."),
                                              IP(src="10.0.0.5", dst="8.8.8.8")), now=1.0)), [])

    def test_unconfigured_is_silent(self):
        eng = Engine(Config())
        self.assertEqual(
            codes(eng.handle_frame(ddns_frame(self._q("1.0.0.10.in-addr.arpa."),
                                              IP(src="10.0.0.5", dst="8.8.8.8")), now=1.0)), [])

    def test_ip6_walk_both_transports(self):
        prefix = "20010db800000000"
        names = [".".join(reversed(prefix + f"{i:016x}")) + ".ip6.arpa." for i in range(80)]
        got = {}
        for label, l3 in (("IPv4", IP(src="198.51.100.9", dst="10.0.0.1")),
                          ("IPv6", IPv6(src="2001:db8::9", dst="fd00::1"))):
            eng = Engine(Config())
            out = []
            for i, nm in enumerate(names):
                out += eng.handle_frame(ddns_frame(self._q(nm), l3, sport=40000 + i * 7),
                                        now=1.0 + i * 0.1)
            got[label] = codes(out)
            self.assertIn("DNSD-091", got[label], f"{label}: got {got[label]}")
            self.assertEqual(got[label].count("DNSD-091"), 1,
                             f"{label}: once per window, not once per query")
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_scattered_lookups_do_not_fire(self):
        """The mail-server shape: many distinct ip6.arpa names with no
        shared delegation. Count and distinctness alone would fire."""
        import random
        random.seed(3)
        eng = Engine(Config())
        out = []
        for i in range(200):
            full = "".join(random.choice("0123456789abcdef") for _ in range(32))
            nm = ".".join(reversed(full)) + ".ip6.arpa."
            out += eng.handle_frame(
                ddns_frame(self._q(nm), IP(src="198.51.100.9", dst="10.0.0.1"),
                           sport=40000 + i * 7), now=1.0 + i * 0.1)
        self.assertEqual(codes(out), [], f"got {codes(out)}")


class TestSigredAndTsig(unittest.TestCase):

    @staticmethod
    def _sigred(rtype=parse.T_RRSIG, sig_len=65260):
        import struct
        hdr = struct.pack("!HHHHHH", 0x5151, 0x8180, 1, 1, 0, 0)
        question = b"\x00" + struct.pack("!HH", 1, 1)
        owner = b"\xc0\x0c"
        sig_fixed = struct.pack("!HBBIIIH", 1, 8, 2, 3600, 1800000000, 1700000000, 0x003f)
        rdata = sig_fixed + struct.pack("!H", 0xC000 | 46) + b"\x3f" * sig_len
        rr = owner + struct.pack("!HHIH", rtype, 1, 3600, len(rdata)) + rdata
        return hdr + question + rr

    def _tcp(self, payload, l3, sport=53, dport=33333):
        from scapy.all import TCP
        return raw(Ether() / l3 / TCP(sport=sport, dport=dport, seq=1000, flags="PA")
                   / (len(payload).to_bytes(2, "big") + payload))

    def test_sigred_both_types_both_stacks(self):
        for rtype, label in ((parse.T_RRSIG, "RRSIG"), (parse.T_SIG, "SIG")):
            got = {}
            for fam, l3 in (("IPv4", IP(src="10.0.0.1", dst="10.0.0.5")),
                            ("IPv6", IPv6(src="fd00::1", dst="fd00::5"))):
                eng = Engine(Config())
                out = eng.handle_frame(self._tcp(self._sigred(rtype), l3), now=1.0)
                got[fam] = codes(out)
                self.assertIn("DNSD-044", got[fam], f"{label}/{fam}: got {got[fam]}")
            self.assertEqual(got["IPv4"], got["IPv6"],
                             f"{label}: dual-stack divergence {got}")

    def test_near_miss_is_silent(self):
        eng = Engine(Config())
        out = eng.handle_frame(self._tcp(self._sigred(sig_len=60000),
                                         IP(src="10.0.0.1", dst="10.0.0.5")), now=1.0)
        self.assertNotIn("DNSD-044", codes(out))

    def test_tsig_structure_both_stacks(self):
        import struct
        hdr = struct.pack("!HHHHHH", 0x4242, 0x8000, 1, 0, 0, 1)
        body = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        bad = hdr + body + tsig_bytes(mac_size=200, mac=b"\x11" * 32)
        good = hdr + body + tsig_bytes()
        got = {}
        for fam, l3 in (("IPv4", IP(src="10.0.0.1", dst="10.0.0.5")),
                        ("IPv6", IPv6(src="fd00::1", dst="fd00::5"))):
            eng = Engine(Config())
            got[fam] = codes(eng.handle_frame(ddns_frame(bad, l3, 53, 33333), now=1.0))
            self.assertIn("DNSD-054", got[fam], f"{fam}: got {got[fam]}")
            eng = Engine(Config())
            self.assertEqual(codes(eng.handle_frame(ddns_frame(good, l3, 53, 33333), now=1.0)),
                             [], f"{fam}: a well-formed TSIG must be silent")
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")



# ======================================================================
# Matter / Thread fingerprint
# ======================================================================

def mdns_txt(service, instance, pairs):
    from scapy.layers.dns import DNSRR
    return DNSRR(rrname=f"{instance}.{service}.local.", type="TXT", ttl=4500,
                 rdata=pairs)


def mdns_ptr(service, instance):
    from scapy.layers.dns import DNSRR
    return DNSRR(rrname=f"{service}.local.", type="PTR", ttl=4500,
                 rdata=f"{instance}.{service}.local.")


def mdns_fp_frame(l3, records):
    from scapy.layers.dns import DNS
    an = None
    for r in records:
        an = r if an is None else an / r
    return raw(Ether() / l3 / UDP(sport=5353, dport=5353)
               / DNS(qr=1, an=an, ancount=len(records)))


MV4 = IP(src="192.168.77.50", dst="224.0.0.251", ttl=255)
MV6 = IPv6(src="fd00:77::50", dst="ff02::fb", hlim=255)
MPFX = ("192.168.77.0/24", "fd00:77::/64")
OP_INST = "2906C908D115D362-8FC7772401CD0696"


class TestMatterFingerprint(unittest.TestCase):
    """Fingerprint extraction on both stacks, with identical verdicts.
    Matter is IPv6-first, so the v6 path is the one that matters most
    here even though the record content is transport-independent."""

    def _fp(self, cfg, l3, records, code):
        eng = Engine(cfg)
        out = eng.handle_frame(mdns_fp_frame(l3, records))
        hits = [x for x in out if x["code"] == code]
        self.assertTrue(hits, f"expected {code}, got {codes(out)}")
        return hits[0]["evidence"]["fingerprint"]

    def test_operational_identity_both_stacks(self):
        got = {}
        for label, l3 in (("IPv4", MV4), ("IPv6", MV6)):
            fp = self._fp(Config(mdns_local_prefixes=MPFX), l3,
                          [mdns_ptr("_matter._tcp", OP_INST),
                           mdns_txt("_matter._tcp", OP_INST, ["SII=5000"])],
                          "DNSD-070")
            self.assertEqual(fp.get("compressed_fabric_id"), "2906c908d115d362", label)
            self.assertEqual(fp.get("node_id"), "8fc7772401cd0696", label)
            got[label] = fp
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_zwave_fingerprint_both_stacks(self):
        # Identity by product and network position -- and crucially
        # NO device name, because Z-Wave does not put one on the wire.
        ZI = "Static Controller [d24ac4700200]"
        TXT = [b"txtvers=1", b"productID=0x0301:0x0001", b"epid=0",
               b"icon=4096", b"info=" + bytes([0x25, 0x00, 0x13]),
               b"securityClasses=" + bytes([0x80, 0x01])]
        got = {}
        for label, l3 in (("IPv4", MV4), ("IPv6", MV6)):
            fp = self._fp(Config(mdns_local_prefixes=MPFX), l3,
                          [mdns_ptr("_z-wave._udp", ZI),
                           mdns_txt("_z-wave._udp", ZI, TXT)],
                          "DNSD-079")
            self.assertEqual(fp.get("device_type"), "Static Controller", label)
            self.assertEqual(fp.get("home_id"), "d24ac470", label)
            self.assertEqual(fp.get("product_id"), "0x0301:0x0001", label)
            self.assertEqual(fp.get("endpoint_id"), "0", label)
            self.assertEqual(fp.get("security_classes_hex"), "8001", label)
            self.assertNotIn("device_name", fp)
            self.assertFalse(any("info" in k for k in fp), f"info leaked: {fp}")
            got[label] = fp
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_device_name_is_captured_verbatim(self):
        for label, l3 in (("IPv4", MV4), ("IPv6", MV6)):
            fp = self._fp(Config(mdns_local_prefixes=MPFX), l3,
                          [mdns_ptr("_matterc._udp", "AB3C7F1E2D4A5B6C"),
                           mdns_txt("_matterc._udp", "AB3C7F1E2D4A5B6C",
                                    ["VP=4151+1", "DT=266", "DN=Dave's Bedroom Lamp"])],
                          "DNSD-071")
            self.assertEqual(fp.get("device_name"), "Dave's Bedroom Lamp", label)
            self.assertEqual(fp.get("vendor_product"), "4151+1", label)
            self.assertEqual(fp.get("device_type"), 266, label)

    def test_thread_dn_is_a_domain_not_a_device_name(self):
        """Matter's 'dn' is the user-chosen device name; Thread's is
        the domain name. A merged key table would file one as the
        other."""
        for label, l3 in (("IPv4", MV4), ("IPv6", MV6)):
            fp = self._fp(Config(mdns_local_prefixes=MPFX), l3,
                          [mdns_ptr("_meshcop._udp", "MyHub"),
                           mdns_txt("_meshcop._udp", "MyHub",
                                    ["tv=1.3.0", "nn=Guest-Thread", "dn=DefaultDomain"])],
                          "DNSD-073")
            self.assertEqual(fp.get("thread_domain_name"), "DefaultDomain", label)
            self.assertNotIn("device_name", fp, label)
            self.assertEqual(fp.get("network_name"), "Guest-Thread", label)

    def test_ephemeral_endpoint_does_not_inherit_txt(self):
        """A Thread border router advertises the same instance name
        under _meshcop._udp and _meshcop-e._udp."""
        eng = Engine(Config(mdns_local_prefixes=MPFX))
        out = eng.handle_frame(mdns_fp_frame(MV4, [
            mdns_ptr("_meshcop._udp", "MyHub"),
            mdns_txt("_meshcop._udp", "MyHub", ["vn=Nordic"]),
            mdns_ptr("_meshcop-e._udp", "MyHub")]))
        by = {x["code"]: x["evidence"]["fingerprint"] for x in out}
        self.assertIn("DNSD-078", by, codes(out))
        self.assertEqual(by["DNSD-073"].get("vendor_name"), "Nordic")
        self.assertEqual(by["DNSD-078"], {})

    def test_sb_and_omr_are_never_interpreted(self):
        fp = self._fp(Config(mdns_local_prefixes=MPFX), MV4,
                      [mdns_ptr("_meshcop._udp", "MyHub"),
                       mdns_txt("_meshcop._udp", "MyHub",
                                [b"sb=" + bytes.fromhex("00000e31"),
                                 b"omr=" + bytes.fromhex("40fd11223344556600")])],
                      "DNSD-073")
        self.assertEqual(fp.get("state_bitmap"), "00000e31")
        self.assertEqual(fp.get("omr_prefix"), "40fd11223344556600")
        for derived in ("connection_mode", "thread_role", "bbr_primary",
                        "interface_status", "availability"):
            self.assertNotIn(derived, fp,
                             "nothing may be derived from a bit layout this build "
                             "could not pin")

    def test_device_name_switch(self):
        recs = [mdns_ptr("_matterc._udp", "X1"),
                mdns_txt("_matterc._udp", "X1", ["DN=Dave's Bedroom Lamp"])]
        fp = self._fp(Config(mdns_local_prefixes=MPFX,
                             mdns_include_device_name=False), MV4, recs, "DNSD-071")
        self.assertNotIn("Dave", str(fp))
        self.assertIn("redacted", str(fp.get("device_name", "")))
        self.assertTrue(Config().mdns_include_device_name,
                        "DN is on by default")


class TestCommissioningWindow(unittest.TestCase):

    @staticmethod
    def _frame(l3, cm, extra=()):
        pairs = list(extra) + ([f"CM={cm}"] if cm is not None else [])
        return mdns_fp_frame(l3, [mdns_ptr("_matterc._udp", "X1"),
                                  mdns_txt("_matterc._udp", "X1", pairs)])

    def test_open_window_both_stacks(self):
        for cm in (1, 2):
            got = {}
            for label, l3 in (("IPv4", MV4), ("IPv6", MV6)):
                eng = Engine(Config(mdns_local_prefixes=MPFX))
                out = eng.handle_frame(self._frame(l3, cm))
                got[label] = codes(out)
                self.assertIn("DNSD-077", got[label], f"{label} CM={cm}: {got[label]}")
            self.assertEqual(got["IPv4"], got["IPv6"],
                             f"dual-stack divergence at CM={cm}: {got}")

    def test_closed_and_absent_and_junk_are_silent(self):
        for cm, why in ((0, "CM=0 means closed"),
                        (None, "no CM key at all"),
                        ("open", "a non-numeric CM is a typo, not a finding")):
            for l3 in (MV4, MV6):
                eng = Engine(Config(mdns_local_prefixes=MPFX))
                out = eng.handle_frame(self._frame(l3, cm, extra=["VP=4151+1"]))
                self.assertNotIn("DNSD-077", codes(out), why)

    def test_one_report_per_state_not_per_packet(self):
        eng = Engine(Config(mdns_local_prefixes=MPFX))
        n = [len([x for x in eng.handle_frame(self._frame(MV4, cm))
                  if x["code"] == "DNSD-077"]) for cm in (1, 1, 1, 2, 2)]
        self.assertEqual(n, [1, 0, 0, 1, 0], n)

    def test_alarm_names_the_device(self):
        eng = Engine(Config(mdns_local_prefixes=MPFX))
        out = eng.handle_frame(self._frame(MV4, 1, extra=["DN=Hall Light"]))
        f = [x for x in out if x["code"] == "DNSD-077"][0]
        self.assertEqual(f["evidence"]["fingerprint"].get("device_name"), "Hall Light")



# ======================================================================
# LLMNR / NBNS / encrypted transport / DNS-SD / TSIG posture
# ======================================================================

def hdr5(qr=0, opcode=0, qd=1, an=0, ns=0, ar=0, txid=0x1234):
    import struct
    return struct.pack("!HHHHHH", txid, (qr << 15) | (opcode << 11), qd, an, ns, ar)


def dn5(s):
    return b"".join(bytes([len(l)]) + l for l in s.encode().split(b".") if l) + b"\x00"


# Per-conversation TCP sequence numbers. A multi-message fixture that
# frames every message at the same sequence number is, on a real
# wire, message two claiming message one's bytes and contradicting
# them -- and once reassembly arrived DNSD-160 said so, correctly, on
# a previously-green XFR test. The fixture was wrong, not the
# detector. Only ever advances, so a fresh Engine anchors its stream
# base wherever the conversation happens to be.
_F5_SEQ = {}


def f5(payload, l3, sport, dport, tcp=False):
    from scapy.all import TCP
    if tcp:
        framed = len(payload).to_bytes(2, "big") + payload
        key = (getattr(l3, "src", "?"), getattr(l3, "dst", "?"), sport, dport)
        seq = _F5_SEQ.get(key, 1000)
        _F5_SEQ[key] = seq + len(framed)
        l4 = TCP(sport=sport, dport=dport, seq=seq, flags="PA") / framed
    else:
        l4 = UDP(sport=sport, dport=dport) / payload
    return raw(Ether() / l3 / l4)


class TestLlmnrTier(unittest.TestCase):

    GROUPS = (("IPv4", IP(src="192.168.1.50", dst="224.0.0.252")),
              ("IPv6", IPv6(src="fd00::50", dst="ff02::1:3")))

    @staticmethod
    def _q(name, qr=0):
        import struct
        return (hdr5(qr=qr) + dn5(name) + struct.pack("!HH", 1, 1))

    def test_presence_both_stacks(self):
        got = {}
        for label, l3 in self.GROUPS:
            eng = Engine(Config())
            out = eng.handle_frame(f5(self._q("printer"), l3, 50000, 5355), now=1.0)
            got[label] = codes(out)
            self.assertIn("DNSD-110", got[label], label)
        self.assertEqual(got["IPv4"], got["IPv6"], f"divergence: {got}")

    def test_ttl_is_not_a_violation(self):
        """RFC 4795 s2.5 permits ANY TTL. The mDNS rule (RFC 6762 s11,
        255 is a MUST) must not be transferred here -- it would fire on
        conforming traffic."""
        for ttl in (1, 64, 128, 255):
            eng = Engine(Config(mdns_local_prefixes=("192.168.1.0/24",)))
            out = eng.handle_frame(
                f5(self._q("printer"), IP(src="192.168.1.50", dst="224.0.0.252", ttl=ttl),
                   50000, 5355), now=1.0)
            self.assertNotIn("DNSD-074", codes(out), f"TTL {ttl}")

    def test_wrong_group_and_unicast(self):
        for label, bad in (("IPv4", IP(src="192.168.1.50", dst="239.1.2.3")),
                           ("IPv6", IPv6(src="fd00::50", dst="ff02::dead"))):
            eng = Engine(Config())
            self.assertIn("DNSD-111",
                          codes(eng.handle_frame(f5(self._q("x"), bad, 50000, 5355),
                                                 now=1.0)), label)
        # A unicast response is legitimate, not a scope violation.
        eng = Engine(Config())
        out = eng.handle_frame(f5(self._q("x", qr=1),
                                  IP(src="192.168.1.60", dst="192.168.1.50"),
                                  5355, 50000), now=1.0)
        self.assertNotIn("DNSD-111", codes(out))

    def test_wpad_query_only(self):
        for label, l3 in self.GROUPS:
            eng = Engine(Config())
            self.assertIn("DNSD-112",
                          codes(eng.handle_frame(f5(self._q("wpad"), l3, 50000, 5355),
                                                 now=1.0)), label)
        eng = Engine(Config())
        out = eng.handle_frame(f5(self._q("wpad", qr=1),
                                  IP(src="192.168.1.60", dst="192.168.1.50"),
                                  5355, 50000), now=1.0)
        self.assertNotIn("DNSD-112", codes(out),
                         "the poisoned answer is smbwatch's half")


class TestNbnsTier(unittest.TestCase):

    @staticmethod
    def _q(name, qtype=None, opcode=0, suffix=0x00, txid=0x1234):
        import struct
        qtype = parse.T_NB if qtype is None else qtype
        return (hdr5(opcode=opcode, txid=txid)
                + bytes([parse.NBNS_NAME_LABEL_LEN])
                + parse.encode_nbns_label(name, suffix) + b"\x00"
                + struct.pack("!HH", qtype, 1))

    SRC = IP(src="192.168.1.70", dst="192.168.1.255")

    def test_codec_round_trip(self):
        for name, suffix in (("WPAD", 0x00), ("DC01", 0x1B), ("FILESRV01", 0x20)):
            enc = parse.encode_nbns_label(name, suffix)
            self.assertEqual(len(enc), 32)
            self.assertEqual(parse.decode_nbns_label(enc), (name, suffix))
        for bad in (b"Z" * 32, b"a" * 32, b"A" * 31, b""):
            self.assertIsNone(parse.decode_nbns_label(bad))

    def test_wpad_and_presence(self):
        eng = Engine(Config())
        out = eng.handle_frame(f5(self._q("WPAD"), self.SRC, 137, 137), now=1.0)
        self.assertIn("DNSD-120", codes(out))
        self.assertIn("DNSD-121", codes(out))
        f = [x for x in out if x["code"] == "DNSD-121"][0]
        self.assertEqual(f["evidence"]["netbios"]["netbios_name"], "WPAD")

    def test_registration_does_not_reach_ddns(self):
        """NBNS opcode 5 is NAME REGISTRATION; DNS opcode 5 is UPDATE.
        A Windows registration storm must not be reported as unsigned
        dynamic updates being accepted."""
        eng = Engine(Config(ddns_allowed_updater_prefixes=("10.0.0.0/8",)))
        out = eng.handle_frame(
            f5(self._q("PC01", opcode=parse.NBNS_OPCODE_REGISTRATION),
               IP(src="203.0.113.9", dst="192.168.1.255"), 137, 137), now=1.0)
        self.assertFalse([c for c in codes(out) if c.startswith("DNSD-08")],
                         codes(out))
        self.assertEqual(len(eng.pending), 0)

    def test_nbstat_is_rate_based(self):
        eng = Engine(Config())
        out = eng.handle_frame(f5(self._q("H1", qtype=parse.T_NBSTAT), self.SRC,
                                  137, 137), now=1.0)
        self.assertNotIn("DNSD-122", codes(out), "one NBSTAT is ordinary browsing")
        eng = Engine(Config())
        got = []
        for i in range(12):
            got += eng.handle_frame(
                f5(self._q(f"H{i}", qtype=parse.T_NBSTAT, txid=i), self.SRC, 137, 137),
                now=1.0 + i * 0.1)
        self.assertIn("DNSD-122", codes(got))
        self.assertEqual(codes(got).count("DNSD-122"), 1)


class TestEncryptedTransport(unittest.TestCase):

    TLS = b"\x16\x03\x01\x00\x10handshake"
    QUIC = bytes([0xC3, 0, 0, 0, 1]) + b"initial"
    OWN = ("10.0.0.0/24", "fd00::/64")

    def test_dot_doq_both_stacks(self):
        for label, inside, outside in (
                ("IPv4", IP(src="10.0.0.9", dst="10.0.0.1"),
                 IP(src="10.0.0.9", dst="1.1.1.1")),
                ("IPv6", IPv6(src="fd00::9", dst="fd00::1"),
                 IPv6(src="fd00::9", dst="2606:4700::1111"))):
            eng = Engine(Config(dns_own_resolver_prefixes=self.OWN))
            out = eng.handle_frame(f5(self.TLS, inside, 50000, 853, tcp=True), now=1.0)
            self.assertIn("DNSD-130", codes(out), label)
            self.assertIs(out[0]["evidence"]["inside_own_resolvers"], True, label)
            eng = Engine(Config(dns_own_resolver_prefixes=self.OWN))
            out = eng.handle_frame(f5(self.TLS, outside, 50000, 853, tcp=True), now=1.0)
            self.assertIs(out[0]["evidence"]["inside_own_resolvers"], False, label)
            eng = Engine(Config(dns_own_resolver_prefixes=self.OWN))
            self.assertIn("DNSD-131",
                          codes(eng.handle_frame(f5(self.QUIC, outside, 50000, 853),
                                                 now=1.0)), label)

    def test_unconfigured_is_undecidable(self):
        eng = Engine(Config())
        out = eng.handle_frame(f5(self.TLS, IP(src="10.0.0.9", dst="1.1.1.1"),
                                  50000, 853, tcp=True), now=1.0)
        self.assertIsNone(out[0]["evidence"]["inside_own_resolvers"])

    def test_udp_853_without_quic_is_silent(self):
        for payload in (b"\x00not-quic", bytes([0x80]) + b"nofixed", b""):
            eng = Engine(Config(dns_own_resolver_prefixes=self.OWN))
            self.assertEqual(eng.handle_frame(
                f5(payload, IP(src="10.0.0.9", dst="9.9.9.9"), 50000, 853), now=1.0), [])

    def test_nothing_is_parsed_from_an_encrypted_session(self):
        eng = Engine(Config(dns_own_resolver_prefixes=self.OWN))
        eng.handle_frame(f5(self.TLS, IP(src="10.0.0.9", dst="1.1.1.1"), 50000, 853,
                            tcp=True), now=1.0)
        self.assertEqual(eng.stats.parsed, 0)

    def test_ddr_and_doh_precursor(self):
        import dns.message, dns.rrset
        for name in ("_dns.resolver.arpa.", "_dns.isp.example."):
            eng = Engine(Config())
            w = dns.message.make_query(name, "SVCB").to_wire()
            out = eng.handle_frame(f5(w, IP(src="10.0.0.9", dst="10.0.0.1"), 50000, 53),
                                   now=1.0)
            self.assertIn("DNSD-132", codes(out), name)
        eng = Engine(Config())
        r = dns.message.make_response(dns.message.from_wire(
            dns.message.make_query("dns.google.", "A").to_wire()))
        r.answer.append(dns.rrset.from_text("dns.google.", 300, "IN", "A", "8.8.8.8"))
        out = eng.handle_frame(f5(r.to_wire(), IP(src="10.0.0.1", dst="10.0.0.9"),
                                  53, 50000), now=1.0)
        f = [x for x in out if x["code"] == "DNSD-133"][0]
        self.assertEqual(f["evidence"]["correlation"]["join"], "tls_sni")
        self.assertEqual(f["evidence"]["correlation"]["addresses"], ["8.8.8.8"])


class TestDnssdAndTsigPosture(unittest.TestCase):

    def test_unicast_enumeration_only(self):
        import dns.message
        eng = Engine(Config())
        w = dns.message.make_query("_services._dns-sd._udp.example.com.", "PTR").to_wire()
        self.assertIn("DNSD-100",
                      codes(eng.handle_frame(f5(w, IP(src="198.51.100.9", dst="10.0.0.1"),
                                                50000, 53), now=1.0)))
        eng = Engine(Config())
        w = dns.message.make_query("_services._dns-sd._udp.local.", "PTR").to_wire()
        self.assertNotIn("DNSD-100",
                         codes(eng.handle_frame(f5(w, IP(src="198.51.100.9", dst="10.0.0.1"),
                                                   50000, 53), now=1.0)),
                         ".local is ordinary Bonjour browsing")

    @staticmethod
    def _tsig(algo, fudge=300, mac_size=32, declared_mac=None):
        import struct
        declared = mac_size if declared_mac is None else declared_mac
        rd = (algo + (0).to_bytes(6, "big") + struct.pack("!HH", fudge, declared)
              + b"\x11" * mac_size + struct.pack("!HHH", 0x1234, 0, 0))
        return b"\x01k\x00" + struct.pack("!HHIH", parse.T_TSIG, 255, 0, len(rd)) + rd

    def _msg(self, rr, qr=1):
        import struct
        return hdr5(qr=qr, ar=1) + dn5("example.com") + struct.pack("!HH", 1, 1) + rr

    def test_weak_algorithm_and_fudge(self):
        for l3 in (IP(src="10.0.0.1", dst="10.0.0.5"), IPv6(src="fd00::1", dst="fd00::5")):
            eng = Engine(Config())
            out = eng.handle_frame(f5(self._msg(self._tsig(dn5("hmac-sha1"), mac_size=20)),
                                      l3, 53, 50000), now=1.0)
            self.assertIn("DNSD-140", codes(out))
            eng = Engine(Config())
            out = eng.handle_frame(f5(self._msg(self._tsig(dn5("hmac-sha256"), fudge=3600)),
                                      l3, 53, 50000), now=1.0)
            self.assertIn("DNSD-141", codes(out))
            eng = Engine(Config())
            out = eng.handle_frame(f5(self._msg(self._tsig(dn5("hmac-sha256"))),
                                      l3, 53, 50000), now=1.0)
            self.assertEqual(codes(out), [], "a current algorithm at 300s is silent")

    def test_broken_tsig_posture_is_suppressed(self):
        eng = Engine(Config())
        out = eng.handle_frame(
            f5(self._msg(self._tsig(dn5("hmac-sha256"), fudge=65535, mac_size=32,
                                    declared_mac=200)),
               IP(src="10.0.0.1", dst="10.0.0.5"), 53, 50000), now=1.0)
        self.assertIn("DNSD-054", codes(out))
        self.assertNotIn("DNSD-141", codes(out),
                         "the fields of a record that does not parse mean nothing")

    def test_sig0(self):
        import struct
        rd = (struct.pack("!HBBIIIH", 0, 8, 0, 0, 1800000000, 1700000000, 1234)
              + dn5("key.example.com") + b"\x55" * 64)
        rr = b"\x00" + struct.pack("!HHIH", parse.T_SIG, 255, 0, len(rd)) + rd
        for l3 in (IP(src="10.0.0.5", dst="10.0.0.1"), IPv6(src="fd00::5", dst="fd00::1")):
            eng = Engine(Config())
            out = eng.handle_frame(f5(self._msg(rr, qr=0), l3, 50000, 53), now=1.0)
            self.assertIn("DNSD-142", codes(out))



# ======================================================================
# Zone transfer, continued (061-064)
# ======================================================================

def xq(zone, qt):
    import dns.message
    return dns.message.make_query(zone, qt).to_wire()


def xsoa(owner, serial=1):
    import dns.rrset
    return dns.rrset.from_text(owner, 300, "IN", "SOA",
                               f"ns1.example.com. root.example.com. "
                               f"{serial} 3600 600 86400 300")


def xa(name="www.example.com.", addr="192.0.2.1"):
    import dns.rrset
    return dns.rrset.from_text(name, 300, "IN", "A", addr)


def xresp(zone, qt, rrsets, rcode=0, with_question=True):
    import dns.message
    m = dns.message.make_response(dns.message.from_wire(xq(zone, qt)))
    m.set_rcode(rcode)
    if not with_question:
        m.question = []
    for rs in rrsets:
        m.answer.append(rs)
    return m.to_wire()


def xf(payload, l3, sport, dport, tcp=True):
    from scapy.all import TCP
    if tcp:
        # Sequence advances per conversation -- see _F5_SEQ above for
        # why a fixed sequence number is a contradicting stream.
        framed = len(payload).to_bytes(2, "big") + payload
        key = (getattr(l3, "src", "?"), getattr(l3, "dst", "?"), sport, dport)
        seq = _F5_SEQ.get(key, 1000)
        _F5_SEQ[key] = seq + len(framed)
        return raw(Ether() / l3 / TCP(sport=sport, dport=dport, seq=seq, flags="PA")
                   / framed)
    return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / payload)


class TestXfrDisclosure(unittest.TestCase):

    SEC = ("10.0.0.0/8", "fd00::/64")
    PAIRS = (
        ("IPv4", IP(src="203.0.113.9", dst="10.0.0.1"),
         IP(src="10.0.0.1", dst="203.0.113.9"),
         IP(src="10.0.0.5", dst="10.0.0.1"), IP(src="10.0.0.1", dst="10.0.0.5")),
        ("IPv6", IPv6(src="2001:db8:bad::9", dst="fd00::1"),
         IPv6(src="fd00::1", dst="2001:db8:bad::9"),
         IPv6(src="fd00::5", dst="fd00::1"), IPv6(src="fd00::1", dst="fd00::5")),
    )
    FULL = None

    def setUp(self):
        self.FULL = [xsoa("example.com."), xa(), xsoa("example.com.")]

    def _exchange(self, cfg, cli, srv, rrsets, qt="AXFR", rcode=0):
        eng = Engine(cfg)
        first = eng.handle_frame(xf(xq("example.com.", qt), cli, 50000, 53), now=1.0)
        out = eng.handle_frame(xf(xresp("example.com.", qt, rrsets, rcode=rcode),
                                  srv, 53, 50000), now=1.01)
        return codes(first), codes(out)

    def test_outside_client_both_stacks(self):
        got = {}
        for label, out_cli, out_srv, ok_cli, ok_srv in self.PAIRS:
            c1, c2 = self._exchange(Config(xfr_allowed_secondary_prefixes=self.SEC),
                                    out_cli, out_srv, self.FULL)
            self.assertNotIn("DNSD-061", c1, f"{label}: the query alone")
            self.assertIn("DNSD-061", c2, f"{label}: {c2}")
            got[label] = c2
            _, c2ok = self._exchange(Config(xfr_allowed_secondary_prefixes=self.SEC),
                                     ok_cli, ok_srv, self.FULL)
            self.assertNotIn("DNSD-061", c2ok, f"{label}: a permitted secondary")
        self.assertEqual(got["IPv4"], got["IPv6"], f"divergence: {got}")

    def test_rejected_and_incomplete_and_unconfigured(self):
        out_cli, out_srv = self.PAIRS[0][1], self.PAIRS[0][2]
        for rcode in (5, 9, 3):
            _, c2 = self._exchange(Config(xfr_allowed_secondary_prefixes=self.SEC),
                                   out_cli, out_srv, [], rcode=rcode)
            self.assertNotIn("DNSD-061", c2, f"rcode {rcode} is the ACL working")
        _, c2 = self._exchange(Config(xfr_allowed_secondary_prefixes=self.SEC),
                               out_cli, out_srv,
                               [xsoa("example.com."), xa()])
        self.assertNotIn("DNSD-061", c2, "no terminating SOA is not a completed transfer")
        _, c2 = self._exchange(Config(), out_cli, out_srv, self.FULL)
        self.assertNotIn("DNSD-061", c2, "silent with no configured secondaries")


class TestIxfrSoaApex(unittest.TestCase):
    """CVE-2021-25214, and the conforming IXFR it must not fire on."""

    CLI = IP(src="10.0.0.5", dst="10.0.0.1")
    SRV = IP(src="10.0.0.1", dst="10.0.0.5")

    def _ex(self, rrsets, qt="IXFR", cli=None, srv=None):
        eng = Engine(Config())
        eng.handle_frame(xf(xq("example.com.", qt), cli or self.CLI, 50000, 53), now=1.0)
        return codes(eng.handle_frame(
            xf(xresp("example.com.", qt, rrsets), srv or self.SRV, 53, 50000), now=1.01))

    def test_non_apex_soa_both_stacks(self):
        bad = [xsoa("example.com.", 3), xsoa("example.com.", 2), xa(),
               xsoa("sub.example.com.", 3), xsoa("example.com.", 3)]
        for label, cli, srv in (("IPv4", self.CLI, self.SRV),
                                ("IPv6", IPv6(src="fd00::5", dst="fd00::1"),
                                 IPv6(src="fd00::1", dst="fd00::5"))):
            self.assertIn("DNSD-062", self._ex(bad, cli=cli, srv=srv), label)

    def test_conforming_six_soa_ixfr_is_silent(self):
        """RFC 1995's own example response carries SIX SOA records, all
        at the apex. Any count-based rule would fire on every
        conforming incremental transfer."""
        six = [xsoa("example.com.", 3), xsoa("example.com.", 1), xa(),
               xsoa("example.com.", 2), xa(), xsoa("example.com.", 2), xa(),
               xsoa("example.com.", 3), xa(), xsoa("example.com.", 3)]
        self.assertNotIn("DNSD-062", self._ex(six))

    def test_parent_zone_soa(self):
        self.assertIn("DNSD-062", self._ex([xsoa("example.com.", 3), xsoa("com.", 3),
                                            xsoa("example.com.", 3)]))

    def test_axfr_goes_to_063_not_062(self):
        got = self._ex([xsoa("example.com."), xsoa("sub.example.com."), xa()], qt="AXFR")
        self.assertNotIn("DNSD-062", got)
        self.assertIn("DNSD-063", got)


class TestAxfrStructureAndTransport(unittest.TestCase):

    CLI = IP(src="10.0.0.5", dst="10.0.0.1")
    SRV = IP(src="10.0.0.1", dst="10.0.0.5")

    def _stream(self, messages, qt="AXFR"):
        eng = Engine(Config())
        eng.handle_frame(xf(xq("example.com.", qt), self.CLI, 50000, 53), now=1.0)
        out = []
        for i, rrsets in enumerate(messages):
            out += eng.handle_frame(
                xf(xresp("example.com.", qt, rrsets, with_question=(i == 0)),
                   self.SRV, 53, 50000), now=1.01 + i * 0.01)
        return codes(out)

    def test_violations(self):
        self.assertIn("DNSD-063", self._stream([[xa(), xsoa("example.com.")]]))
        self.assertIn("DNSD-063", self._stream(
            [[xsoa("example.com."), xsoa("sub.example.com."), xa()]]))
        self.assertIn("DNSD-063", self._stream(
            [[xsoa("example.com."), xa()],
             [xa(), xsoa("example.com."), xa()],
             [xa(), xsoa("example.com.")]]))

    def test_conforming_axfr_is_silent(self):
        self.assertNotIn("DNSD-063", self._stream(
            [[xsoa("example.com."), xa(), xsoa("example.com.")]]))
        self.assertNotIn("DNSD-063", self._stream(
            [[xsoa("example.com."), xa()], [xa(), xa()],
             [xa(), xsoa("example.com.")]]))

    def test_conforming_multi_message_ixfr_is_silent(self):
        """RFC 1995 makes SOAs the delta markers, so 'an SOA in an
        intermediate message' describes every conforming IXFR."""
        self.assertNotIn("DNSD-063", self._stream(
            [[xsoa("example.com.", 3), xsoa("example.com.", 1), xa()],
             [xsoa("example.com.", 2), xa(), xsoa("example.com.", 2), xa()],
             [xsoa("example.com.", 3), xa(), xsoa("example.com.", 3)]], qt="IXFR"))

    def test_axfr_over_udp_but_not_ixfr(self):
        for label, l3 in (("IPv4", IP(src="203.0.113.9", dst="10.0.0.1")),
                          ("IPv6", IPv6(src="2001:db8::9", dst="fd00::1"))):
            eng = Engine(Config())
            self.assertIn("DNSD-064", codes(eng.handle_frame(
                xf(xq("example.com.", "AXFR"), l3, 50000, 53, tcp=False), now=1.0)), label)
            # RFC 1995 s2 PERMITS IXFR over UDP.
            eng = Engine(Config())
            self.assertNotIn("DNSD-064", codes(eng.handle_frame(
                xf(xq("example.com.", "IXFR"), l3, 50000, 53, tcp=False), now=1.0)), label)
            # AXFR over TCP is normal.
            eng = Engine(Config())
            self.assertNotIn("DNSD-064", codes(eng.handle_frame(
                xf(xq("example.com.", "AXFR"), l3, 50000, 53), now=1.0)), label)


class TestSpfParserTier(unittest.TestCase):
    """SPF parser tier (libspf2): DNSD-150..153.

    The thresholds here are the libspf2 source constants, not advisory
    prose. Four CVEs, three of which are reachable only through a
    specific shape of record:

      150  CVE-2021-33912  uppercase macro letter       (URL-encode)
      151  CVE-2021-33913  uppercase + 'r' transformer  (reverse+URL)
      152  CVE-2021-20314  budget-filling exp= literal  (<1.2.11)
      153  CVE-2023-42118  4-byte budget underflow      (>=1.2.11)
    """

    def _resp(self, owner, strings, l3=None):
        import struct
        from scapy.all import Ether, IP, UDP, raw
        rd = b"".join(bytes([len(s)]) + s for s in strings)
        rr = dn5(owner) + struct.pack("!HHIH", parse.T_TXT, 1, 300, len(rd)) + rd
        q = dn5(owner) + struct.pack("!HH", parse.T_TXT, 1)
        pay = struct.pack("!HHHHHH", 0x3131, 0x8180, 1, 1, 0, 0) + q + rr
        l3 = l3 if l3 is not None else IP(src="10.0.0.1", dst="10.0.0.9")
        return raw(Ether() / l3 / UDP(sport=53, dport=50000) / pay)

    @staticmethod
    def _split(blob):
        return [blob[i:i + 255] for i in range(0, len(blob), 255)]

    def _codes(self, frames, cfg=None, start=1.0):
        eng = Engine(cfg or Config())
        out = []
        for i, f in enumerate(frames):
            out += eng.handle_frame(f, now=start + i * 0.01)
        return [f["code"] for f in out], eng

    # -- the model, against the constants it was read from ------------
    def test_source_constants(self):
        self.assertEqual(spf_tier.SPF_MAX_MECH_LEN, 511)
        self.assertEqual(spf_tier.SPF_MAX_MOD_LEN, 511)
        self.assertEqual(spf_tier.SPF_DATA_T_SIZE, 4)
        # A TXT string is length-prefixed by one octet. That it cannot
        # reach the 511-byte compile budget is what makes the
        # multi-string split a NECESSARY condition for CVE-2021-20314
        # rather than a heuristic about how PoCs happen to be written.
        self.assertLess(spf_tier.TXT_STRING_MAX, spf_tier.SPF_MAX_MOD_LEN)

    def test_budget_window_boundaries(self):
        # Each macro variable costs align_sz(sizeof(SPF_data_t)) = 4.
        for n, rem in ((1, 507), (100, 111), (126, 7), (127, 3)):
            self.assertEqual(spf_tier.compile_budget(b"%{i}" * n)["remaining"], rem,
                             f"{n} macros")
        # The underflow arms when the remaining budget at a literal
        # initialisation drops below sizeof(SPF_data_t).
        self.assertFalse(spf_tier.compile_budget(b"%{i}" * 126)["underflow"])
        self.assertTrue(spf_tier.compile_budget(b"%{i}" * 127)["underflow"])

    def test_align_sz_is_not_the_identity(self):
        # spf_internal.h defines _align_sz under `#if 1`, so the
        # rounding version always compiles and the identity is dead
        # code. This module modelled the identity and called it
        # conservative; the library refused 126 variables plus a
        # one-byte literal as "SPF domainspec too long (509 chars,
        # 511 max)", which only adds up with the rounding.
        self.assertEqual([spf_tier.align_sz(n) for n in (0, 1, 4, 5, 8, 9)],
                         [0, 4, 4, 8, 8, 12])
        self.assertEqual(
            spf_tier.compile_budget(b"%{i}" * 126 + b"A")["stopped_at"], "too-long")

    def test_underflow_is_written_through_only_with_a_literal(self):
        # The write loop is `SPF_ENSURE_STRING_AVAIL(1); *dst++ = c;`
        # -- per byte, right after the guard that a wrapped ds_avail
        # can no longer fail. So literal text after the 127th
        # variable is written past the buffer, and nothing after it
        # means nothing is written.
        self.assertEqual(
            spf_tier.compile_budget(b"%{i}" * 127 + b".x")["bytes_past_buffer"], 2)
        self.assertEqual(
            spf_tier.compile_budget(b"%{i}" * 127)["bytes_past_buffer"], 0)

    def test_the_upper_bound_is_real(self):
        # This needed the VULNERABLE build to establish. At 128
        # variables SPF_ADD_LEN_TO refuses the next variable before
        # any write -- the vulnerable build says "SPF domainspec too
        # long (512 chars, 511 max)". HEAD returns its floor-check
        # error for 127 and for 1000 alike, because nothing after the
        # 127th variable runs, and reading that identical error as the
        # vulnerability briefly produced a model with no upper bound.
        for n in (128, 200, 1000):
            r = spf_tier.compile_budget(b"%{i}" * n + b".x")
            self.assertEqual(r["bytes_past_buffer"], 0, f"{n} macros")
            self.assertEqual(r["macro_count"], 127, f"{n} macros")

    # -- expansion: case is the whole discriminator -------------------
    def test_uppercase_macro_is_the_trigger(self):
        c, _ = self._codes([self._resp("e.com", [b"v=spf1 include:%{D}.x -all"])])
        self.assertIn("DNSD-150", c)
        self.assertNotIn("DNSD-151", c)

    def test_uppercase_plus_reverse_is_the_other_cve(self):
        c, _ = self._codes([self._resp("e.com", [b"v=spf1 include:%{Dr}.x -all"])])
        self.assertIn("DNSD-151", c)
        self.assertNotIn("DNSD-150", c)

    def test_lowercase_macro_is_silent(self):
        # The real-world case. libspf2 only enters the vulnerable
        # URL-encode block when d->dv.url_encode is set, which only an
        # uppercase letter does (RFC 7208 s7.1).
        for rec in (b"v=spf1 include:%{d}.x -all",
                    b"v=spf1 exists:%{ir}.%{l}.rbl.x ~all",
                    b"v=spf1 include:%{dr}.x -all"):
            c, _ = self._codes([self._resp("e.com", [rec])])
            self.assertEqual([x for x in c if x in ("DNSD-150", "DNSD-151")], [],
                             rec.decode())

    def test_ordinary_records_are_silent(self):
        for rec in (b"v=spf1 include:_spf.google.com ~all",
                    b"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all",
                    b"v=spf1 mx a -all", b"v=spf1 redirect=_spf.x.com"):
            c, _ = self._codes([self._resp("e.com", [rec])])
            self.assertEqual(c, [], rec.decode())

    # -- the underflow window ----------------------------------------
    def test_underflow_fires_at_and_above_the_arming_point(self):
        # The condition exists from 127 variables up; the evidence
        # says whether it is written through, which is the difference
        # between a probe and a hit.
        for n, want in ((100, False), (126, False), (127, True),
                        (128, True), (300, True)):
            c, _ = self._codes([self._resp(
                "e.com",
                self._split(b"v=spf1 include:" + b"%{i}" * n + b".x -all"))])
            self.assertEqual("DNSD-153" in c, want, f"{n} macros")

    def test_underflow_reports_the_window_it_found(self):
        eng = Engine(Config())
        out = eng.handle_frame(self._resp(
            "e.com", self._split(b"v=spf1 include:" + b"%{i}" * 127 + b".x -all")))
        f = [x for x in out if x["code"] == "DNSD-153"][0]
        self.assertTrue(0 <= f["evidence"]["min_remaining"] < 4)
        self.assertEqual(f["evidence"]["bytes_past_buffer"], 2)
        self.assertEqual(f["evidence"]["macro_count"], 127)
        self.assertEqual(f["evidence"]["budget"], 511)
        self.assertIn("1.2.11", f["evidence"]["affected"])

    # -- exp= correlation --------------------------------------------
    def test_exp_requires_the_correlation(self):
        # 508 bytes, the bottom of the four-byte window: a literal
        # that fits the pre-1.2.11 ds_avail (= _avail = 511) but not
        # the corrected one (= 507). 500 bytes fits both and
        # overflows nothing.
        big = self._split(b"A" * 508)
        # Target not named by any exp= -> silent. Without this the
        # detector would fire on every large TXT record on the network.
        c, _ = self._codes([self._resp("other.com", big)])
        self.assertNotIn("DNSD-152", c)
        # Named -> reported, on the explanation record.
        c, eng = self._codes([self._resp("e.com", [b"v=spf1 exp=x.e.com -all"]),
                              self._resp("x.e.com", big)])
        self.assertIn("DNSD-152", c)

    def test_exp_short_explanation_is_silent(self):
        c, _ = self._codes([self._resp("e.com", [b"v=spf1 exp=x.e.com -all"]),
                            self._resp("x.e.com", [b"Rejected: see e.com/spf"])])
        self.assertNotIn("DNSD-152", c)

    def test_exp_macro_target_is_not_remembered(self):
        # Its real name depends on the mail transaction. Storing the
        # unexpanded form would create a key no later record can match
        # -- coverage that cannot fire.
        _, eng = self._codes([self._resp("e.com",
                                         [b"v=spf1 exp=%{i}.x.e.com -all"])])
        self.assertEqual(len(eng.exp_targets), 0)

    def test_exp_table_is_bounded(self):
        _, eng = self._codes([self._resp(f"z{i}.com",
                                         [b"v=spf1 exp=e%d.com -all" % i])
                              for i in range(30)], cfg=Config(spf_max_exp_targets=4))
        self.assertEqual(len(eng.exp_targets), 4)
        self.assertEqual(eng.exp_targets.evictions, 26)

    # -- plumbing -----------------------------------------------------
    def test_suppression_is_per_owner_and_macro(self):
        f = self._resp("e.com", [b"v=spf1 include:%{Dr}.x -all"])
        c, _ = self._codes([f, f, f])
        self.assertEqual(c.count("DNSD-151"), 1)

    def test_kill_switch(self):
        c, _ = self._codes([self._resp("e.com", [b"v=spf1 include:%{Dr}.x -all"])],
                           cfg=Config(spf_enabled=False))
        self.assertEqual(c, [])

    def test_query_side_is_silent(self):
        # A TXT query carries no rdata. The first wiring of this tier
        # landed in the query branch and reported nothing at all.
        import dns.message
        from scapy.all import Ether, IP, UDP, raw
        q = dns.message.make_query("e.com.", "TXT").to_wire()
        fr = raw(Ether() / IP(src="10.0.0.9", dst="10.0.0.1")
                 / UDP(sport=50000, dport=53) / q)
        c, _ = self._codes([fr])
        self.assertEqual([x for x in c if x.startswith("DNSD-15")], [])

    def test_parser_is_total(self):
        for junk in (b"", b"%", b"%{", b"%{%{", bytes(range(256)), b"}" * 60,
                     b"v=spf1 " + b"%" * 500):
            spf_tier.parse_macros(junk)
            spf_tier.compile_budget(junk)
            spf_tier.spf_terms(junk)
            spf_tier.spf_record_text([junk])

    def test_dual_stack_parity(self):
        from scapy.all import IP, IPv6
        rec = [b"v=spf1 include:%{Dr}.x -all"]
        c4, _ = self._codes([self._resp("e.com", rec, IP(src="10.0.0.1", dst="10.0.0.9"))])
        c6, _ = self._codes([self._resp("e.com", rec, IPv6(src="fd00::1", dst="fd00::9"))])
        self.assertEqual(c4, c6)
        self.assertEqual(c4, ["DNSD-151"])
        # And for the record-shaped CVEs too.
        big = self._split(b"v=spf1 include:" + b"%{i}" * 127 + b" -all")
        for l3 in (IP(src="10.0.0.1", dst="10.0.0.9"), IPv6(src="fd00::1", dst="fd00::9")):
            c, _ = self._codes([self._resp("e.com", big, l3)])
            self.assertIn("DNSD-153", c)


class TestTcpReassembly(unittest.TestCase):
    """TCP stream reassembly (tcpreasm.py) and DNSD-160.

    Reassembly is the one part of this module that could invent a DNS
    message nobody sent, so most of these assert what it refuses to
    do rather than what it does.
    """

    K = ("v4", b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 53, 50000)

    @staticmethod
    def _fr(payload):
        return len(payload).to_bytes(2, "big") + payload

    @staticmethod
    def _dmsg(n=500, txid=0x1234, fill=b"Y"):
        """A PLAUSIBLE DNS message of n bytes.

        A stream with no SYN does not know where message boundaries
        are, so the reassembler requires the head of its buffer to
        look like a length prefix in front of a DNS header before it
        frames anything. These fixtures used b"Y" * 500 until that
        gate existed; something that could actually be framed is the
        right amount of realism rather than an inconvenience.
        """
        import struct
        n = max(n, 12)
        return struct.pack("!HHHHHH", txid, 0x8180, 0, 0, 0, 0) + fill * (n - 12)

    @staticmethod
    def _open(r, key, seq=1000, now=0.9):
        """Open a stream with a bare SYN, so offset `seq` is known to
        be the first byte of the first message. A SYN consumes its own
        sequence number, hence seq - 1."""
        r.add(key, (seq - 1) & 0xFFFFFFFF, b"", 0x02, now)

    @staticmethod
    def _r(cfg=None):
        from tcpreasm import Reassembler
        return Reassembler(cfg or Config())

    @staticmethod
    def _frame(seq, data, l3=None, flags="PA", sport=53, dport=50000):
        from scapy.all import Ether, IP, TCP, raw
        l3 = l3 if l3 is not None else IP(src="10.0.0.1", dst="10.0.0.9")
        return raw(Ether() / l3
                   / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / data)

    @staticmethod
    def _sigred():
        import struct
        hdr = struct.pack("!HHHHHH", 0x5151, 0x8180, 1, 1, 0, 0)
        question = b"\x00" + struct.pack("!HH", 1, 1)
        fixed = struct.pack("!HBBIIIH", 1, 8, 2, 3600, 1800000000, 1700000000, 0x003f)
        rdata = fixed + struct.pack("!H", 0xC000 | 46) + b"\x3f" * 65260
        rr = b"\xc0\x0c" + struct.pack("!HHIH", parse.T_RRSIG, 1, 3600,
                                       len(rdata)) + rdata
        return hdr + question + rr

    # -- sequence arithmetic -----------------------------------------
    def test_seq_delta_wraps(self):
        from tcpreasm import seq_delta
        self.assertEqual(seq_delta(100, 50), 50)
        self.assertEqual(seq_delta(50, 100), -50)
        # The case naive subtraction gets wrong, and the reason every
        # comparison in the module goes through this function.
        self.assertEqual(seq_delta(5, 0xFFFFFFFE), 7)
        self.assertEqual(seq_delta(0xFFFFFFFE, 5), -7)
        for a in (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
            for b in (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
                self.assertTrue(-(1 << 31) <= seq_delta(a, b) < (1 << 31))

    # -- framing ------------------------------------------------------
    def test_pipelined_messages(self):
        r = self._r()
        a, b, cc = self._dmsg(16, 1), self._dmsg(20, 2), self._dmsg(32, 3)
        m, _ = r.add(self.K, 1000,
                     self._fr(a) + self._fr(b) + self._fr(cc), 0x18, 1.0)
        self.assertEqual(m, [a, b, cc])

    def test_split_length_prefix(self):
        whole = self._fr(self._dmsg(600))
        for split in (1, 2, 3):
            r = self._r()
            out = []
            for off, end in ((0, split), (split, len(whole))):
                mm, _ = r.add(self.K, 1000 + off, whole[off:end], 0x18, 1.0)
                out += mm
            self.assertEqual([len(x) for x in out], [600], f"split at {split}")

    def test_zero_length_frame_abandons(self):
        r = self._r()
        # On a SYNCHRONISED stream offset zero really is a boundary,
        # so a zero length there is a framing error. On an
        # unsynchronised one it just means "not a boundary".
        self._open(r, self.K, 1000)
        m, _ = r.add(self.K, 1000, b"\x00\x00" + self._fr(self._dmsg(16)),
                     0x18, 1.0)
        self.assertEqual(m, [])
        self.assertEqual(r.stats.framing_errors, 1)
        r2 = self._r()
        m2, _ = r2.add(self.K, 1000, b"\x00\x00" + self._fr(self._dmsg(16)),
                       0x18, 1.0)
        self.assertEqual((m2, r2.stats.framing_errors), ([], 0))
        self.assertGreaterEqual(r2.stats.unsynced_waits, 1)

    # -- ordering -----------------------------------------------------
    def test_every_segment_order(self):
        whole = self._fr(self._dmsg(500))
        offs = [(0, 200), (200, 200), (400, 102)]
        import itertools
        for perm in itertools.permutations(offs):
            r = self._r()
            out = []
            for off, ln in perm:
                mm, _ = r.add(self.K, 1000 + off, whole[off:off + ln], 0x18, 1.0)
                out += mm
            self.assertEqual([len(x) for x in out], [500], f"order {perm}")

    def test_gap_is_never_filled(self):
        whole = self._fr(self._dmsg(500))
        r = self._r()
        m1, _ = r.add(self.K, 1000, whole[:100], 0x18, 1.0)
        m2, _ = r.add(self.K, 1300, whole[300:], 0x18, 1.1)
        self.assertEqual((m1, m2), ([], []))
        # Nothing is delivered until the hole closes.
        m3, _ = r.add(self.K, 1100, whole[100:300], 0x18, 1.2)
        self.assertEqual([len(x) for x in m3], [500])

    def test_stalled_stream_ages_out(self):
        whole = self._fr(self._dmsg(500))
        r = self._r()
        r.add(self.K, 1000, whole[:100], 0x18, 1.0)
        r.add(("v4", b"z", b"z", 53, 1), 1, b"", 0x02, 1000.0)
        self.assertEqual(r.stats.aged_streams, 1)
        self.assertGreaterEqual(r.stats.dropped_bytes, 100)

    # -- overlap, DNSD-160 -------------------------------------------
    def test_identical_retransmission_is_silent(self):
        r = self._r()
        seg = self._fr(self._dmsg(600, 7))[:300]
        r.add(self.K, 1000, seg, 0x18, 1.0)
        _, e = r.add(self.K, 1000, seg, 0x18, 1.1)
        self.assertEqual(e, [])
        self.assertEqual(r.stats.overlaps_identical, 1)

    def test_contradictory_overlap_is_reported_once(self):
        r = self._r()
        r.add(self.K, 1000, self._fr(self._dmsg(600, 8, b"A"))[:300], 0x18, 1.0)
        n = 0
        for i in range(5):
            _, e = r.add(self.K, 1100, b"EVIL" + b"A" * 96, 0x18, 1.1 + i * 0.01)
            n += len(e)
        self.assertEqual(n, 1)
        self.assertEqual(r.stats.overlaps_mismatch, 5)

    def test_first_wins(self):
        whole = self._fr(self._dmsg(600, 9, b"A"))
        r = self._r()
        r.add(self.K, 1000, whole[:300], 0x18, 1.0)
        r.add(self.K, 1100, b"EVIL" + b"A" * 96, 0x18, 1.1)
        m, _ = r.add(self.K, 1300, whole[300:], 0x18, 1.2)
        self.assertEqual(len(m), 1)
        self.assertNotIn(b"EVIL", m[0])

    def test_overlap_window_is_bounded_and_counted(self):
        # With no shadow a contradiction arriving after framing is
        # outside what can be checked, and says so rather than
        # pretending to have looked.
        r = self._r(Config(tcp_reasm_shadow_bytes=0))
        r.add(self.K, 1000, self._fr(self._dmsg(16, 11, b"A")), 0x18, 1.0)
        _, e = r.add(self.K, 1000, self._fr(self._dmsg(16, 11, b"Z")), 0x18, 1.1)
        self.assertEqual(e, [])
        self.assertEqual(r.stats.before_window, 1)
        # With one, it is caught.
        r = self._r(Config(tcp_reasm_shadow_bytes=2048))
        r.add(self.K, 1000, self._fr(self._dmsg(16, 12, b"A")), 0x18, 1.0)
        _, e = r.add(self.K, 1000, self._fr(self._dmsg(16, 12, b"Z")), 0x18, 1.1)
        self.assertEqual(len(e), 1)

    def test_dnsd160_end_to_end_dual_stack(self):
        from scapy.all import IP, IPv6
        whole = self._fr(self._dmsg(600, 13, b"\x00"))
        for l3 in (IP(src="10.0.0.1", dst="10.0.0.9"),
                   IPv6(src="fd00::1", dst="fd00::9")):
            eng = Engine(Config())
            eng.handle_frame(self._frame(1000, whole[:300], l3), now=1.0)
            out = eng.handle_frame(self._frame(1100, b"EVIL" + b"\x00" * 96, l3),
                                   now=1.01)
            self.assertIn("DNSD-160", [f["code"] for f in out])

    # -- teardown -----------------------------------------------------
    def test_rst_abandons(self):
        r = self._r()
        r.add(self.K, 1000, self._fr(self._dmsg(500))[:100], 0x18, 1.0)
        m, _ = r.add(self.K, 1000, b"", 0x04, 1.1)
        self.assertEqual((m, len(r), r.stats.reset_streams), ([], 0, 1))

    def test_tuple_reuse_does_not_splice(self):
        r = self._r()
        r.add(self.K, 1000, self._fr(self._dmsg(500))[:100], 0x18, 1.0)
        r.add(self.K, 5000, b"", 0x02, 1.1)
        new = self._dmsg(28, 21)
        m, _ = r.add(self.K, 5001, self._fr(new), 0x18, 1.2)
        self.assertEqual(m, [new])
        self.assertEqual(r.stats.reused_keys, 1)

    def test_midflight_stream_without_syn(self):
        r = self._r()
        mid = self._dmsg(40, 22)
        m, _ = r.add(self.K, 777777, self._fr(mid), 0x18, 1.0)
        self.assertEqual(m, [mid])

    def test_directions_are_separate_streams(self):
        r = self._r()
        r.add(("v4", b"\x01", b"\x02", 53, 50000), 1000,
              self._fr(self._dmsg(16, 30)), 0x18, 1.0)
        r.add(("v4", b"\x02", b"\x01", 50000, 53), 9000,
              self._fr(self._dmsg(16, 31)), 0x18, 1.0)
        self.assertEqual(len(r), 2)

    # -- bounds -------------------------------------------------------
    def test_bounds_hold(self):
        from tcpreasm import Reassembler
        r = Reassembler(Config(tcp_reasm_max_streams=4))
        for i in range(20):
            r.add(("v4", b"a", bytes([i]), 53, 50000), 1000,
                  b"\xff\xff" + b"A" * 50, 0x18, 1.0 + i * 0.001)
        self.assertEqual(len(r), 4)
        self.assertEqual(r.stats.evicted_streams, 16)

        r = Reassembler(Config(tcp_reasm_max_bytes=20000))
        for i in range(40):
            r.add(("v4", b"b", bytes([i]), 53, 50000), 1000,
                  b"\xff\xff" + b"A" * 1000, 0x18, 1.0 + i * 0.001)
        self.assertLessEqual(r.total_bytes, 20000)

    # -- what it unlocks ---------------------------------------------
    def test_sigred_across_realistic_segments(self):
        from scapy.all import IP, IPv6
        stream = self._fr(self._sigred())
        for l3 in (IP(src="10.0.0.1", dst="10.0.0.9"),
                   IPv6(src="fd00::1", dst="fd00::9")):
            eng = Engine(Config())
            got = []
            for off in range(0, len(stream), 1400):
                got += eng.handle_frame(
                    self._frame(1000 + off, stream[off:off + 1400], l3),
                    now=1.0 + off * 1e-6)
            self.assertIn("DNSD-044", [f["code"] for f in got])
            self.assertEqual(eng.reasm.stats.messages, 1)

    def test_sigred_is_invisible_without_reassembly(self):
        # The negative control, and the whole argument for this tier.
        from scapy.all import IP
        stream = self._fr(self._sigred())
        eng = Engine(Config(tcp_reasm_enabled=False))
        got = []
        for off in range(0, len(stream), 1400):
            got += eng.handle_frame(
                self._frame(1000 + off, stream[off:off + 1400],
                            IP(src="10.0.0.1", dst="10.0.0.9")),
                now=1.0 + off * 1e-6)
        codes = {f["code"] for f in got}
        self.assertNotIn("DNSD-044", codes)
        self.assertIn("DNSD-007", codes)

    def test_udp_never_enters_the_reassembler(self):
        from scapy.all import Ether, IP, UDP, raw
        import dns.message
        eng = Engine(Config())
        q = dns.message.make_query("u.example.", "A").to_wire()
        eng.handle_frame(raw(Ether() / IP(src="10.0.0.9", dst="10.0.0.1")
                             / UDP(sport=50000, dport=53) / q), now=1.0)
        self.assertEqual(len(eng.reasm), 0)
        self.assertEqual(eng.reasm.stats.segments, 0)

    def test_parser_is_total_on_segments(self):
        r = self._r()
        for junk in (b"", b"\x00", b"\xff", b"\xff\xff", bytes(range(256)),
                     b"\x00\x00\x00\x00", b"\xff\xff" + b"A" * 3):
            r.add(self.K, 1000, junk, 0x18, 1.0)
            r.add(self.K, 2000, junk, 0x18, 1.0)


class TestMaginotAccountingSplit(unittest.TestCase):
    """DNSD-006 / DNSD-170 glue-and-chain accounting split.

    Trigger/near-miss pairs from T1-T7. The split must downgrade the
    legitimate reverse-DNS shapes WITHOUT blunting the detector: every
    near-miss has to stay critical.
    """

    REV = "2.0.192.in-addr.arpa."
    NS1 = "ns1.customer.example."

    @staticmethod
    def _l3(fam):
        from scapy.all import IP, IPv6
        return (IP(src="198.51.100.9", dst="198.51.100.1") if fam == "v4"
                else IPv6(src="2001:db8::9", dst="2001:db8::1"))

    @staticmethod
    def _rs(name, rtype, *vals, ttl=3600):
        import dns.rrset
        return dns.rrset.from_text(name, ttl, "IN", rtype, *vals)

    def _resp(self, answer=(), authority=(), additional=(), qname=None):
        import dns.message
        qn = qname or self.REV
        m = dns.message.make_response(dns.message.make_query(qn, "PTR"))
        m.answer.extend(answer)
        m.authority.extend(authority)
        m.additional.extend(additional)
        return m.to_wire()

    def _codes(self, wire, fam="v4"):
        from scapy.all import Ether, UDP, raw
        eng = Engine(Config())
        fr = raw(Ether() / self._l3(fam) / UDP(sport=53, dport=50000) / wire)
        out = eng.handle_frame(fr, now=1.0)
        return [f["code"] for f in out], out

    # -- T1: the shape that caused the production false positive -----
    def test_T1_reverse_referral_glue_is_not_an_alarm(self):
        for fam in ("v4", "v6"):
            for gt, ga in (("A", "203.0.113.5"), ("AAAA", "2001:db8:c::5")):
                codes, out = self._codes(self._resp(
                    authority=[self._rs(self.REV, "NS", self.NS1)],
                    additional=[self._rs(self.NS1, gt, ga)]), fam)
                self.assertNotIn("DNSD-006", codes, f"{fam}/{gt}")
                self.assertIn("DNSD-170", codes, f"{fam}/{gt}")

    # -- T4 near-miss: the same glue with nothing referencing it -----
    def test_T4_unreferenced_glue_stays_critical(self):
        for fam in ("v4", "v6"):
            for gt, ga in (("A", "203.0.113.8"), ("AAAA", "2001:db8:c::8")):
                codes, _ = self._codes(self._resp(
                    additional=[self._rs(self.NS1, gt, ga)]), fam)
                self.assertIn("DNSD-006", codes, f"{fam}/{gt}")
                self.assertNotIn("DNSD-170", codes, f"{fam}/{gt}")

    # -- T2: a real out-of-bailiwick chain ---------------------------
    def test_T2_cname_chain_is_accounted(self):
        for fam in ("v4", "v6"):
            codes, out = self._codes(self._resp(
                answer=[self._rs(self.REV, "CNAME", "host.customer.example.")],
                authority=[self._rs("customer.example.", "NS", self.NS1)],
                additional=[self._rs(self.NS1, "A", "203.0.113.6")]), fam)
            self.assertNotIn("DNSD-006", codes, fam)
            reasons = sorted({f["evidence"]["reason"] for f in out
                              if f["code"] == "DNSD-170"})
            self.assertEqual(reasons, ["chain", "glue"], fam)

    # -- T5 near-miss: a foreign NS cannot launder its own glue ------
    def test_T5_foreign_ns_cannot_anchor_its_own_glue(self):
        for fam in ("v4", "v6"):
            for gt, ga in (("A", "203.0.113.9"), ("AAAA", "2001:db8:c::9")):
                codes, out = self._codes(self._resp(
                    authority=[self._rs("victim.example.", "NS",
                                        "ns.attacker.example.")],
                    additional=[self._rs("ns.attacker.example.", gt, ga)]), fam)
                self.assertIn("DNSD-006", codes, f"{fam}/{gt}")
                self.assertNotIn("DNSD-170", codes, f"{fam}/{gt}")
                six = [f for f in out if f["code"] == "DNSD-006"][0]
                self.assertEqual(six["evidence"]["count"], 2, f"{fam}/{gt}")

    # -- T3 near-miss: one stray among good glue ---------------------
    def test_T3_stray_record_is_isolated(self):
        for fam in ("v4", "v6"):
            codes, out = self._codes(self._resp(
                authority=[self._rs(self.REV, "NS", self.NS1)],
                additional=[self._rs(self.NS1, "A", "203.0.113.7"),
                            self._rs("www.victim.example.", "A", "203.0.113.7")]),
                fam)
            self.assertIn("DNSD-006", codes, fam)
            self.assertIn("DNSD-170", codes, fam)
            six = [f for f in out if f["code"] == "DNSD-006"][0]
            self.assertEqual(six["evidence"]["count"], 1, fam)
            self.assertEqual(six["evidence"]["names"], ["www.victim.example."], fam)

    # -- T6: canonicalisation ----------------------------------------
    def test_T6_case_insensitive_match(self):
        for fam in ("v4", "v6"):
            codes, _ = self._codes(self._resp(
                authority=[self._rs(self.REV, "NS", "NS1.Customer.Example.")],
                additional=[self._rs(self.NS1, "A", "203.0.113.10")]), fam)
            self.assertNotIn("DNSD-006", codes, fam)
            self.assertIn("DNSD-170", codes, fam)

    # -- T7: bounded -------------------------------------------------
    def test_T7_chain_is_bounded_and_grants_nothing_past_the_cap(self):
        import detect as _d
        self.assertEqual(_d.CHAIN_MAX_HOPS, 16)
        answer = [self._rs(self.REV, "CNAME", "h0.chain.example.")]
        for i in range(25):
            answer.append(self._rs(f"h{i}.chain.example.", "CNAME",
                                   f"h{i+1}.chain.example."))
        for fam in ("v4", "v6"):
            codes, out = self._codes(self._resp(
                answer=answer,
                additional=[self._rs("h24.chain.example.", "A", "203.0.113.24")]),
                fam)
            self.assertIn("DNSD-006", codes, fam)
            self.assertNotIn("DNSD-170", codes, fam)
            self.assertTrue([f for f in out if f["code"] == "DNSD-006"
                             ][0]["evidence"]["chain_truncated"], fam)

    def test_T7_loop_terminates(self):
        for fam in ("v4", "v6"):
            self._codes(self._resp(answer=[
                self._rs(self.REV, "CNAME", "a.loop.example."),
                self._rs("a.loop.example.", "CNAME", "b.loop.example."),
                self._rs("b.loop.example.", "CNAME", "a.loop.example.")]), fam)

    # -- the shared utility is untouched -----------------------------
    def test_shared_bailiwick_untouched(self):
        import bailiwick as _bw
        import detect as _d
        self.assertIs(_d.in_bailiwick, _bw.in_bailiwick)
        self.assertFalse(hasattr(_bw, "_chain_targets"))
        self.assertFalse(hasattr(_bw, "_anchored_ns_targets"))

    def test_dedupe_once_per_responder_zone_owner(self):
        from scapy.all import Ether, UDP, raw
        eng = Engine(Config())
        wire = self._resp(authority=[self._rs(self.REV, "NS", self.NS1)],
                          additional=[self._rs(self.NS1, "A", "203.0.113.5")])
        fr = raw(Ether() / self._l3("v4") / UDP(sport=53, dport=50000) / wire)
        n = [len([f for f in eng.handle_frame(fr, now=1.0 + i)
                  if f["code"] == "DNSD-170"]) for i in range(3)]
        self.assertEqual(n, [1, 0, 0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
