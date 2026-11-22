#!/usr/bin/env python3
"""Self-test for rdap_lookup: fixture RDAP/bootstrap server on loopback,
driven through the production Client/CLI code paths. No internet needed.
IPv6 transport is exercised only if the host can bind ::1."""
import contextlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socketserver

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rdap_lookup as R  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def vcard(fn, email=None, tel=None, kind="org", label=None):
    props = [["version", {}, "text", "4.0"], ["fn", {}, "text", fn], ["kind", {}, "text", kind]]
    if email:
        props.append(["email", {}, "text", email])
    if tel:
        props.append(["tel", {"type": "voice"}, "uri", f"tel:{tel}"])
    if label:
        props.append(["adr", {"label": label, "cc": "US"}, "text", ["", "", "", "", "", "", ""]])
    return ["vcard", props]


ROUTES = {}  # path -> (status, body_dict, headers)
HITS = []


def build_routes(base):
    reg_dom = {
        "objectClassName": "domain", "ldhName": "EXAMPLE.COM", "handle": "2336799_DOMAIN_COM-VRSN",
        "status": ["client transfer prohibited"],
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
                   {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:39Z"}],
        "nameservers": [{"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
                        {"objectClassName": "nameserver", "ldhName": "B.IANA-SERVERS.NET"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [{"objectClassName": "entity", "handle": "376", "roles": ["registrar"],
                      "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                      "vcardArray": vcard("RESERVED-Internet Assigned Numbers Authority"),
                      "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                                    "vcardArray": vcard("", email="abuse@iana.org", tel="+1.3108239358")}]}],
        "links": [{"rel": "self", "href": base + "/reg/domain/example.com", "type": "application/rdap+json"},
                  {"rel": "related", "href": base + "/registrar/domain/example.com",
                   "type": "application/rdap+json"}],
        "port43": "whois.verisign-grs.com",
    }
    registrar_dom = {
        "objectClassName": "domain", "ldhName": "example.com",
        "events": [{"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
        "entities": [{"roles": ["registrant"], "vcardArray": vcard("REDACTED FOR PRIVACY", kind="individual")},
                     {"roles": ["abuse"], "vcardArray": vcard("Abuse Desk", email="abuse@registrar.test")}],
    }
    idn_dom = dict(reg_dom, ldhName="xn--bcher-kva.example", unicodeName="bücher.example", links=[])
    couk = dict(reg_dom, ldhName="example.co.uk", links=[], port43="whois.nic.uk")
    ip4 = {"objectClassName": "ip network", "handle": "NET-192-0-2-0-1", "name": "TEST-NET-1",
           "type": "IANA Special Use", "ipVersion": "v4",
           "startAddress": "192.0.2.0", "endAddress": "192.0.2.255", "country": "US",
           "parentHandle": "NET-192-0-0-0-0",
           "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
           "events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}],
           "entities": [{"handle": "IANA", "roles": ["registrant"], "vcardArray": vcard("IANA", label="12025 Waterfront Dr\nLos Angeles")},
                        {"handle": "ABUSE-ARIN", "roles": ["abuse"], "vcardArray": vcard("Abuse", email="abuse@test.net")}]}
    ip4b = {"objectClassName": "ip network", "handle": "NET-198-51-100-0", "ipVersion": "v4",
            "startAddress": "198.51.100.0", "endAddress": "198.51.100.127", "entities": []}
    ip6 = {"objectClassName": "ip network", "handle": "2001:db8::/32", "name": "DOC-V6", "ipVersion": "v6",
           "startAddress": "2001:db8::", "endAddress": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
           "entities": [{"roles": ["technical"], "entities": [
               {"roles": ["abuse"], "vcardArray": vcard("v6 abuse", email="abuse6@test.net")}]}]}
    ip4.update({"arin_originas0_originautnums": [64500]})
    asn = {"objectClassName": "autnum", "handle": "AS64500", "name": "EXAMPLE-NET",
           "type": "DIRECT ALLOCATION", "startAutnum": 64500, "endAutnum": 64500, "country": "US",
           "status": ["active"],
           "events": [{"eventAction": "registration", "eventDate": "2001-05-01T00:00:00Z"}],
           "entities": [{"handle": "EXNET", "roles": ["registrant"], "vcardArray": vcard("Example Networks Inc")},
                        {"handle": "EXNOC", "roles": ["noc"], "vcardArray": vcard("NOC", email="noc@example.net")},
                        {"handle": "EXABU", "roles": ["abuse"], "vcardArray": vcard("Abuse", email="abuse@example.net")}]}
    asn_block = dict(asn, handle="AS4200000000", name="BLOCK", startAutnum=4200000000, endAutnum=4200000000,
                     entities=[])
    bs = lambda svcs: {"version": "1.0", "publication": "2026-11-01T00:00:00Z", "services": svcs}
    ROUTES.clear()
    ROUTES.update({
        "/bs/dns.json": (200, bs([[["com", "example"], [base + "/reg/"]],
                                  [["uk"], ["http://insecure.invalid/", base + "/uk"]],  # no https -> first
                                  [["co.uk"], [base + "/couk/"]]]), {}),
        "/bs/ipv4.json": (200, bs([[["192.0.0.0/8", "203.0.113.0/24"], [base + "/rir/"]],
                                   [["192.0.2.0/24"], [base + "/rir/"]],
                                   [["198.51.100.0/24"], [base + "/rir/"]]]), {}),
        "/bs/ipv6.json": (200, bs([[["2001:db8::/32"], [base + "/rir/"]]]), {}),
        "/bs/asn.json": (200, bs([[["1-1876", "64496-64511"], [base + "/rir/"]],
                                  [["64500"], [base + "/asrir/"]],       # narrower range wins
                                  [["4200000000-4294967294"], [base + "/rir/"]],
                                  [["65546-65551"], [base + "/rir/"]]]), {}),
        "/asrir/autnum/64500": (200, asn, {}),
        "/rir/autnum/4200000000": (200, asn_block, {}),
        "/rir/autnum/65546": (200, asn_block, {}),
        "/reg/domain/example.com": (200, reg_dom, {}),
        "/registrar/domain/example.com": (200, registrar_dom, {}),
        "/reg/domain/xn--bcher-kva.example": (200, idn_dom, {}),
        "/couk/domain/example.co.uk": (200, couk, {}),
        "/rir/ip/192.0.2.10": (200, ip4, {}),
        "/rir/ip/192.0.2.0/24": (200, ip4, {}),
        "/rir/ip/198.51.100.7": (301, {}, {"Location": base + "/rir2/ip/198.51.100.7"}),
        "/rir2/ip/198.51.100.7": (200, ip4b, {}),
        "/rir/ip/2001:db8::1": (200, ip6, {}),
        "/rir/ip/203.0.113.5": (429, {"title": "Too Many Requests"}, {"Retry-After": "30"}),
        "/rir/ip/192.0.2.99": (200, "NOTJSON", {}),
    })


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS.append((self.path, self.headers.get("Accept"), self.headers.get("User-Agent")))
        st, body, hdrs = ROUTES.get(self.path, (404, {"errorCode": 404, "title": "Not Found"}, {}))
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(st)
        self.send_header("Content-Type", "application/rdap+json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


WHOIS_SEEN = []


def whois_reply(q, host, alt):
    n = WHOIS_SEEN.count(q)
    WHOIS_SEEN.append(q)
    if q == "zz":
        return f"% IANA WHOIS server\ndomain:       ZZ\n\nrefer:        {host}\n\nwhois:        {host}\n"
    if q == "yy":
        return "% IANA WHOIS server\ndomain:       YY\nstatus:       ACTIVE\n"
    if q == "example.zz":
        return ("% ZZ registry\nDomain Name: EXAMPLE.ZZ\nRegistrar: ZZ Registrar Ltd\n"
                "Registrar IANA ID: 9999\nCreation Date: 2001-02-03T00:00:00Z\n"
                "Registry Expiry Date: 2030-02-03T00:00:00Z\nUpdated Date: 2026-01-01T00:00:00Z\n"
                "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n"
                "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n"
                "Name Server: NS1.EXAMPLE.ZZ.\nName Server: ns2.example.zz\nDNSSEC: signedDelegation\n"
                "Registrant Organization: Example Org\nRegistrant Country: ZZ\n"
                "Registrar Abuse Contact Email: abuse@zzreg.test\n>>> Last update of WHOIS database <<<\n")
    if q == "ccstyle.zz":  # ccTLD-style keys (RU/.se flavour)
        return ("domain:        CCSTYLE.ZZ\nnserver:       a.ns.zz.\nnserver:       b.ns.zz.\n"
                "state:         REGISTERED, DELEGATED\norg:           Cc Style LLC\n"
                "registrar:     CC-REG\ncreated:       2010-05-06T00:00:00Z\npaid-till:     2027-05-06T00:00:00Z\n")
    if q == "thin.zz":
        if n == 0:
            return (f"Domain Name: THIN.ZZ\nRegistrar WHOIS Server: {alt}\nRegistrar: Thin Reg\n"
                    "Registry Expiry Date: 2028-01-01T00:00:00Z\n")
        return ("Domain Name: thin.zz\nRegistrant Organization: Thin Holder\n"
                "Registrar Abuse Contact Email: abuse@thin.test\nRegistry Expiry Date: 1999-01-01T00:00:00Z\n")
    if q == "selfref.zz":
        return f"Domain Name: SELFREF.ZZ\nRegistrar: Self\nWhois Server: {host}\n"
    if q == "free.zz":
        return 'No match for "FREE.ZZ".\n'
    if q == "busy.zz":
        return "Query rate limit exceeded. Try again later.\n"
    if q == "latin.zz":
        return "Domain Name: LATIN.ZZ\nRegistrant: Soci\xe9t\xe9 G\xe9n\xe9rale\nRegistrar: R\n".encode("latin-1")
    return "% no data\n"


class WhoisH(socketserver.StreamRequestHandler):
    def handle(self):
        q = self.rfile.readline().decode().strip()
        r = whois_reply(q, self.server.reply_host, self.server.alt_host)
        self.wfile.write(r if isinstance(r, bytes) else r.encode())


class WhoisSrv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class WhoisSrv6(WhoisSrv):
    address_family = socket.AF_INET6


def start_whois(cls, addr):
    srv = cls((addr, 0), WhoisH)
    # same listener under two names: registry vs registrar host
    srv.reply_host, srv.alt_host = (("localhost", "127.0.0.1") if addr == "127.0.0.1"
                                    else ("::1", "0:0:0:0:0:0:0:1"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def whois_suite(base, wsrv, label):
    build_routes(base)
    cache = tempfile.mkdtemp(prefix="rdapc-")
    wh = "127.0.0.1" if wsrv.address_family == socket.AF_INET else "::1"
    common = ["--bootstrap-url", base + "/bs/", "--cache-dir", cache, "--delay", "0", "--timeout", "5",
              "--whois-iana", wh, "--whois-port", str(wsrv.server_address[1])]
    try:
        WHOIS_SEEN.clear()
        code, out = run_cli(common + ["--json", "https://www.example.zz/x"])
        rec = json.loads(out)
        r = rec.get("result", {})
        check(f"{label} whois ok", rec["ok"] and rec["protocol"] == "whois" and code == 0, out)
        check(f"{label} whois registrar", r["registrar"]["name"] == "ZZ Registrar Ltd"
              and r["registrar"]["iana_id"] == "9999", r)
        check(f"{label} whois events", r["events"] == {"registration": "2001-02-03T00:00:00Z",
              "expiration": "2030-02-03T00:00:00Z", "last changed": "2026-01-01T00:00:00Z"}, r)
        check(f"{label} whois status dedup", r["status"] == ["clientTransferProhibited"], r)
        check(f"{label} whois ns", r["nameservers"] == ["ns1.example.zz", "ns2.example.zz"], r)
        check(f"{label} whois dnssec", r["dnssec"] is True)
        check(f"{label} whois abuse", r["abuse"] == {"email": ["abuse@zzreg.test"]})
        check(f"{label} whois registrant", r["registrant"] == {"name": "Example Org", "country": "ZZ"}, r)
        check(f"{label} whois rdap note", any("RDAP" in n or "WHOIS only" in n for n in rec["notes"]), rec)
        check(f"{label} whois raw text", "Last update of WHOIS" in rec["whois_text"])
        check(f"{label} whois walk-down", WHOIS_SEEN == ["zz", "www.example.zz", "example.zz"]
              and rec["matched_name"] == "example.zz", WHOIS_SEEN)
        check(f"{label} iana cached", json.load(open(os.path.join(cache, "whois_servers.json")))["zz"]["server"]
              in ("localhost", "::1"))
        WHOIS_SEEN.clear()
        run_cli(common + ["--json", "example.zz"])
        check(f"{label} iana cache used", "zz" not in WHOIS_SEEN, WHOIS_SEEN)

        code, out = run_cli(common + ["--json", "ccstyle.zz"])
        r = json.loads(out)["result"]
        check(f"{label} whois cc keys", r["nameservers"] == ["a.ns.zz", "b.ns.zz"]
              and r["events"]["expiration"].startswith("2027") and r["registrant"]["name"] == "Cc Style LLC"
              and r["status"] == ["REGISTERED,"] and r["registrar"]["name"] == "CC-REG", r)

        WHOIS_SEEN.clear()
        code, out = run_cli(common + ["--json", "thin.zz"])
        rec = json.loads(out)
        r = rec["result"]
        check(f"{label} whois referral", len(rec["whois_hops"]) == 2
              and r["registrant"]["name"] == "Thin Holder" and r["abuse"]["email"] == ["abuse@thin.test"], out)
        check(f"{label} whois registry wins", r["events"]["expiration"].startswith("2028"), r)
        WHOIS_SEEN.clear()
        code, out = run_cli(common + ["--json", "--no-referral", "thin.zz"])
        check(f"{label} whois no-referral", len(json.loads(out)["whois_hops"]) == 1, out)
        code, out = run_cli(common + ["--json", "selfref.zz"])
        check(f"{label} whois no loop", json.loads(out)["whois_hops"] == [json.loads(out)["server"]], out)

        code, out = run_cli(common + ["--json", "free.zz"])
        rec = json.loads(out)
        check(f"{label} whois not found", rec["status"] == "not_found" and code == 1, out)
        code, out = run_cli(common + ["--json", "busy.zz"])
        rec = json.loads(out)
        check(f"{label} whois rate limit", rec["status"] == "error" and "rate-limited" in rec["error"]
              and rec["protocol"] == "whois" and code == 2, out)
        code, out = run_cli(common + ["--json", "latin.zz"])
        check(f"{label} whois latin-1", json.loads(out)["result"]["registrant"]["name"] == "Soci\xe9t\xe9 G\xe9n\xe9rale", out)
        code, out = run_cli(common + ["--json", "example.yy"])
        rec = json.loads(out)
        check(f"{label} no service", rec["status"] == "no_service" and code == 1, out)
        code, out = run_cli(common + ["--json", "--no-whois", "example.zz"])
        rec = json.loads(out)
        check(f"{label} --no-whois", rec["status"] == "no_rdap_service" and rec["protocol"] == "rdap", out)

        # RDAP-served TLDs never touch WHOIS
        WHOIS_SEEN.clear()
        run_cli(common + ["--json", "example.com", "192.0.2.10", "AS64500"])
        check(f"{label} rdap first", WHOIS_SEEN == [], WHOIS_SEEN)

        code, out = run_cli(common + ["--whois-text", "example.zz"])
        check(f"{label} whois text", "source" in out and "WHOIS" in out and "raw WHOIS" in out
              and "ZZ Registrar Ltd" in out, out)
        code, out = run_cli(common + ["--offline", "--json", "example.zz"])
        check(f"{label} whois offline cached", json.loads(out)["ok"], out)
        code, out = run_cli(common + ["--offline", "--json", "example.xq"])
        check(f"{label} whois offline uncached", "offline and no cached WHOIS" in json.loads(out)["error"], out)
    finally:
        shutil.rmtree(cache, ignore_errors=True)


class V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def start(server_cls, addr):
    srv = server_cls((addr, 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_cli(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = R.main(args)
    return code, buf.getvalue()


def suite(base, label):
    build_routes(base)
    cache = tempfile.mkdtemp(prefix="rdapc-")
    common = ["--bootstrap-url", base + "/bs/", "--cache-dir", cache, "--delay", "0", "--timeout", "5"]
    try:
        # --- domain, with registrar referral
        code, out = run_cli(common + ["--json", "example.com"])
        rec = json.loads(out)
        check(f"{label} dom ok", rec["ok"] and code == 0, out)
        r = rec["result"]
        check(f"{label} dom registrar", r["registrar"]["iana_id"] == "376")
        check(f"{label} dom nested abuse", r["abuse"]["email"] == ["abuse@iana.org"], r["abuse"])
        check(f"{label} dom tel strip", r["abuse"]["tel"] == ["+1.3108239358"])
        check(f"{label} dom expiry", r["events"]["expiration"].startswith("2027"))
        check(f"{label} dom dnssec", r["dnssec"] is True)
        check(f"{label} dom ns", r["nameservers"] == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"])
        check(f"{label} dom referral", rec["referral"]["ok"]
              and rec["referral"]["result"]["abuse"]["email"] == ["abuse@registrar.test"])
        check(f"{label} bootstrap cached", all(os.path.exists(os.path.join(cache, f))
                                               for f in ("dns.json",)))
        check(f"{label} accept hdr", any(h[1] and "rdap+json" in h[1] for h in HITS))
        check(f"{label} UA", any(h[2] and h[2].startswith("Ragnar-RDAP") for h in HITS))

        # --- no referral
        code, out = run_cli(common + ["--json", "--no-referral", "example.com"])
        check(f"{label} no-referral", "referral" not in json.loads(out))

        # --- URL with userinfo/port/path, subdomain walk-down
        HITS.clear()
        code, out = run_cli(common + ["--json", "https://user:pw@www.deep.example.com:8443/a?b=c"])
        rec = json.loads(out)
        check(f"{label} url walk", rec["ok"] and rec["matched_name"] == "example.com", out)
        walked = [h[0] for h in HITS if h[0].startswith("/reg/domain/")]
        check(f"{label} walk order", walked == ["/reg/domain/www.deep.example.com",
                                                "/reg/domain/deep.example.com",
                                                "/reg/domain/example.com"], walked)

        # --- deep subdomain still reaches registered name (MAX_WALK keeps shortest)
        code, out = run_cli(common + ["--json", "--no-referral", "a.b.c.d.e.f.example.com"])
        check(f"{label} deep walk", json.loads(out).get("matched_name") == "example.com", out)

        # --- longest suffix wins (co.uk over uk)
        code, out = run_cli(common + ["--json", "www.example.co.uk"])
        rec = json.loads(out)
        check(f"{label} suffix lpm", rec["ok"] and rec["bootstrap_match"] == "co.uk", out)

        # --- IDN
        code, out = run_cli(common + ["--json", "Bücher.example"])
        rec = json.loads(out)
        check(f"{label} idn", rec["ok"] and rec["normalized"] == "xn--bcher-kva.example", out)
        code, out = run_cli(common + ["Bücher.example"])
        check(f"{label} idn text", "bücher.example" in out, out)

        # --- not found / no service
        code, out = run_cli(common + ["--json", "nope.com"])
        rec = json.loads(out)
        check(f"{label} dom 404", rec["status"] == "not_found" and code == 1, out)
        code, out = run_cli(common + ["--json", "--no-whois", "example.zz"])
        rec = json.loads(out)
        check(f"{label} no service", rec["status"] == "no_rdap_service" and code == 1, out)

        # --- IPv4 with longest-prefix match and cidr0
        code, out = run_cli(common + ["--json", "192.0.2.10"])
        rec = json.loads(out)
        check(f"{label} ip4 ok", rec["ok"] and rec["family"] == "ipv4", out)
        check(f"{label} ip4 lpm", rec["bootstrap_match"] == "192.0.2.0/24", rec.get("bootstrap_match"))
        check(f"{label} ip4 cidr0", rec["result"]["cidrs"] == ["192.0.2.0/24"])
        check(f"{label} ip4 abuse", rec["result"]["abuse"]["email"] == ["abuse@test.net"])
        check(f"{label} ip4 adr label", "Waterfront" in json.dumps(rec["result"]["entities"]))

        check(f"{label} ip4 origin AS chained", rec["origin_as"][0]["ok"]
              and rec["origin_as"][0]["result"]["name"] == "EXAMPLE-NET", rec.get("origin_as"))
        code, out = run_cli(common + ["--json", "--no-asn-chain", "192.0.2.10"])
        check(f"{label} no-asn-chain", "origin_as" not in json.loads(out))

        # --- ASN lookups
        for t in ("AS64500", "as64500", "ASN 64500", "64500"):
            code, out = run_cli(common + ["--json", t])
            rec = json.loads(out)
            check(f"{label} asn {t}", rec["ok"] and rec["kind"] == "asn" and code == 0, out)
        r = rec["result"]
        check(f"{label} asn narrow match", rec["bootstrap_match"] == "64500-64500", rec.get("bootstrap_match"))
        check(f"{label} asn fields", r["name"] == "EXAMPLE-NET" and r["start"] == 64500
              and r["noc"]["email"] == ["noc@example.net"] and r["abuse"]["email"] == ["abuse@example.net"], r)
        code, out = run_cli(common + ["--json", "AS4200000000"])
        check(f"{label} asn 32-bit", json.loads(out)["ok"], out)
        code, out = run_cli(common + ["--json", "AS1.10"])
        rec = json.loads(out)
        check(f"{label} asdot", rec["ok"] and rec["normalized"] == "65546", out)
        code, out = run_cli(common + ["--json", "AS64512"])
        rec = json.loads(out)
        check(f"{label} asn private", rec["status"] == "no_rdap_service" and code == 1, out)
        code, out = run_cli(common + ["--json", "AS100"])
        check(f"{label} asn 404", json.loads(out)["status"] == "not_found", out)
        code, out = run_cli(common + ["AS64500", "192.0.2.10"])
        check(f"{label} asn text", "AS64500" in out and "noc@example.net" in out
              and "origin AS64500" in out, out)

        # --- CIDR query
        code, out = run_cli(common + ["--json", "192.0.2.0/24"])
        rec = json.loads(out)
        check(f"{label} cidr", rec["ok"] and rec["kind"] == "cidr" and rec["url"].endswith("/ip/192.0.2.0/24"), out)

        # --- RIR redirect, range-derived cidrs
        code, out = run_cli(common + ["--json", "http://198.51.100.7/x"])
        rec = json.loads(out)
        check(f"{label} redirect", rec["ok"] and rec["source_url"].endswith("/rir2/ip/198.51.100.7"), out)
        check(f"{label} range->cidr", rec["result"]["cidrs"] == ["198.51.100.0/25"], rec.get("result"))

        # --- IPv6 bare, bracketed URL, zone id
        for t in ("2001:db8::1", "[2001:DB8::1]", "https://[2001:db8::1]:443/", "2001:db8:0:0::1%eth0"):
            code, out = run_cli(common + ["--json", t])
            rec = json.loads(out)
            check(f"{label} ip6 {t}", rec["ok"] and rec["family"] == "ipv6"
                  and rec["normalized"] == "2001:db8::1", out)
        check(f"{label} ip6 deep abuse", rec["result"]["abuse"]["email"] == ["abuse6@test.net"])

        # --- 429 surfaces Retry-After, non-JSON is an error
        code, out = run_cli(common + ["--json", "203.0.113.5"])
        rec = json.loads(out)
        check(f"{label} 429", rec["http_status"] == 429 and rec["retry_after"] == "30" and code == 2, out)
        code, out = run_cli(common + ["--json", "192.0.2.99"])
        check(f"{label} not json", "not JSON" in json.loads(out)["error"])

        # --- invalid input
        code, out = run_cli(common + ["--json", "localhost"])
        check(f"{label} invalid", json.loads(out)["status"] == "invalid" and code == 2, out)

        # --- batch file, comments, worst exit code, JSON-lines
        bf = os.path.join(cache, "targets.txt")
        with open(bf, "w") as f:
            f.write("# list\nexample.com\n\n192.0.2.10\nnope.com\n")
        code, out = run_cli(common + ["--json", "-f", bf])
        lines = out.strip().splitlines()
        check(f"{label} batch", len(lines) == 3 and code == 1, out)

        # --- text renderer smoke
        code, out = run_cli(common + ["example.com", "192.0.2.10", "2001:db8::1"])
        check(f"{label} text", "registrar" in out and "TEST-NET-1" in out and "abuse6@test.net" in out, out)
    finally:
        shutil.rmtree(cache, ignore_errors=True)


def cache_suite(base):
    """Stale-cache fallback and offline mode."""
    build_routes(base)
    cache = tempfile.mkdtemp(prefix="rdapc-")
    try:
        common = ["--cache-dir", cache, "--delay", "0", "--timeout", "2", "--json"]
        run_cli(common + ["--bootstrap-url", base + "/bs/", "192.0.2.10"])
        p = os.path.join(cache, "ipv4.json")
        old = time.time() - 3 * 86400
        os.utime(p, (old, old))
        # bootstrap host dead -> stale cache + note, lookup still works
        code, out = run_cli(common + ["--bootstrap-url", "http://127.0.0.1:9/bs/", "192.0.2.10"])
        rec = json.loads(out)
        check("stale fallback", rec["ok"] and any("stale" in n for n in rec.get("notes", [])), out)
        code, out = run_cli(common + ["--bootstrap-url", "http://127.0.0.1:9/bs/", "--offline", "192.0.2.10"])
        rec = json.loads(out)
        check("offline", rec["ok"] and not rec.get("notes"), out)
        code, out = run_cli(common + ["--bootstrap-url", "http://127.0.0.1:9/bs/", "--offline", "2001:db8::1"])
        check("offline no cache", "offline and no cached" in json.loads(out)["error"], out)
        # empty cache, dead bootstrap -> clean error
        empty = tempfile.mkdtemp(prefix="rdapc-")
        code, out = run_cli(["--cache-dir", empty, "--json", "--timeout", "2",
                             "--bootstrap-url", "http://127.0.0.1:9/bs/", "example.com"])
        check("no bootstrap", "unavailable" in json.loads(out)["error"] and code == 2, out)
        shutil.rmtree(empty, ignore_errors=True)
        # --refresh
        code, out = run_cli(["--cache-dir", cache, "--bootstrap-url", base + "/bs/", "--refresh"])
        check("refresh", code == 0 and time.time() - os.path.getmtime(p) < 60, out)
    finally:
        shutil.rmtree(cache, ignore_errors=True)


def unit_suite():
    C = R.classify
    cases = {
        "8.8.8.8": ("ip", "8.8.8.8", 4),
        "2606:4700:4700::1111": ("ip", "2606:4700:4700::1111", 6),
        "::ffff:1.2.3.4": ("ip", "1.2.3.4", 4),
        "[::ffff:192.0.2.10]": ("ip", "192.0.2.10", 4),
        "10.0.0.5/8": ("cidr", "10.0.0.0/8", 4),
        "2001:db8::/48": ("cidr", "2001:db8::/48", 6),
        "Example.COM.": ("domain", "example.com", None),
        "ftp://files.example.org/pub": ("domain", "files.example.org", None),
        "example.org/path/x": ("domain", "example.org", None),
        "http://192.0.2.1:8080/": ("ip", "192.0.2.1", 4),
        "AS15169": ("asn", "15169", None),
        "asn15169": ("asn", "15169", None),
        "AS 15169": ("asn", "15169", None),
        "15169": ("asn", "15169", None),
        "AS1.10": ("asn", "65546", None),
        "AS4294967295": ("asn", "4294967295", None),
        "as-path.example.com": ("domain", "as-path.example.com", None),
    }
    for t, exp in cases.items():
        try:
            c = C(t)
            got = (c["kind"], c["value"], c["family"])
        except ValueError as e:
            got = ("ERR", str(e), None)
        check(f"classify {t}", got == exp, f"{got} != {exp}")
    for bad in ("", "   ", "localhost", "AS4294967296", "AS65536.1", "1.10", "http://", "a..b.com", "x" * 64 + ".com"):
        try:
            C(bad)
            check(f"classify reject {bad!r}", False)
        except ValueError:
            check(f"classify reject {bad!r}", True)
    check("vcard junk", R.parse_vcard(None) == {} and R.parse_vcard(["vcard"]) == {})
    check("vcard org list", R.parse_vcard(["vcard", [["org", {}, "text", ["A", "B"]]]])["org"] == "A B")


def main():
    unit_suite()
    srv4 = start(ThreadingHTTPServer, "127.0.0.1")
    base4 = f"http://127.0.0.1:{srv4.server_address[1]}"
    suite(base4, "v4")
    cache_suite(base4)
    whois_suite(base4, start_whois(WhoisSrv, "127.0.0.1"), "v4")
    try:
        srv6 = start(V6Server, "::1")
        suite(f"http://[::1]:{srv6.server_address[1]}", "v6")
        whois_suite(f"http://[::1]:{srv6.server_address[1]}", start_whois(WhoisSrv6, "::1"), "v6")
        v6 = "run"
    except OSError as e:
        v6 = f"SKIPPED (host has no IPv6: {e.strerror})"
    print(f"rdap_lookup self-test: {PASS} passed, {FAIL} failed; IPv6 transport tier: {v6}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
