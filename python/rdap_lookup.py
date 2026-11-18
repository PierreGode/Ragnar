#!/usr/bin/env python3
"""Ragnar RDAP Lookup - registration data for IPs, prefixes, ASNs, domains and URLs.

RDAP (RFC 9082/9083) first; server selection uses the IANA bootstrap
registries (RFC 9224) for DNS, IPv4, IPv6 and ASN. Domains whose TLD has no
RDAP service fall back to WHOIS (RFC 3912, TCP/43) via the IANA referral, so
this one tool replaces the WHOIS module. Stdlib only.

Active tool: every lookup queries a registry/RIR.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.2.0-dev"
MODULE = "rdap_lookup"
UA = f"Ragnar-RDAP/{VERSION}"
ACCEPT = "application/rdap+json, application/json;q=0.9"
IANA_BASE = "https://data.iana.org/rdap/"
BOOTSTRAP_FILES = {"dns": "dns.json", "ipv4": "ipv4.json", "ipv6": "ipv6.json", "asn": "asn.json"}
ASN_MAX = 2**32 - 1
WHOIS_IANA = "whois.iana.org"
WHOIS_PORT = 43
WHOIS_MAX = 1024 * 1024
WHOIS_SERVER_TTL = 7 * 24 * 3600
BOOTSTRAP_TTL = 24 * 3600
MAX_BODY = 4 * 1024 * 1024
MAX_WALK = 4  # domain walk-down attempts (www.a.example.co.uk -> ...)

EXIT_FOUND, EXIT_NOTFOUND, EXIT_ERROR = 0, 1, 2


class RdapError(Exception):
    def __init__(self, msg, status=None, retry_after=None):
        super().__init__(msg)
        self.status = status
        self.retry_after = retry_after


# --------------------------------------------------------------------------
# Input classification
# --------------------------------------------------------------------------
def _ip_result(ip) -> dict:
    # ::ffff:a.b.c.d is IPv4 space; the IPv6 bootstrap does not cover it.
    if ip.version == 6 and ip.ipv4_mapped:
        return {"kind": "ip", "value": ip.ipv4_mapped.compressed, "family": 4,
                "mapped_from": ip.compressed}
    return {"kind": "ip", "value": ip.compressed, "family": ip.version}


def parse_asn(t: str) -> int | None:
    """'AS15169', 'asn 15169', 'AS1.10' (asdot), or bare '15169' -> int; else None."""
    m = re.fullmatch(r"(?i)(?:asn?\s*)?(\d+)(?:\.(\d+))?", t.strip())
    if not m:
        return None
    has_prefix = t.strip()[:2].lower() == "as"
    if m.group(2) is not None:  # asdot needs the AS prefix (else it looks like a number/IP)
        if not has_prefix:
            return None
        hi, lo = int(m.group(1)), int(m.group(2))
        if hi > 65535 or lo > 65535:
            raise ValueError(f"invalid asdot ASN {t!r}")
        return hi * 65536 + lo
    n = int(m.group(1))
    if n > ASN_MAX:
        raise ValueError(f"ASN out of range: {t!r}")
    return n


def classify(target: str) -> dict:
    """Return {'kind': 'ip'|'cidr'|'asn'|'domain', 'value': str, 'family': 4|6|None}."""
    t = target.strip()
    if not t:
        raise ValueError("empty target")
    asn = parse_asn(t)
    if asn is not None:
        return {"kind": "asn", "value": str(asn), "family": None}

    # Bare IP / CIDR first (a bare IPv6 address would confuse urlsplit).
    bare = t[1:-1] if t.startswith("[") and t.endswith("]") else t
    try:
        return _ip_result(ipaddress.ip_address(bare.split("%")[0]))
    except ValueError:
        pass
    if "/" in t and "://" not in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            return {"kind": "cidr", "value": net.compressed, "family": net.version}
        except ValueError:
            pass

    # URL or hostname.
    s = t if "://" in t else "//" + t
    parts = urllib.parse.urlsplit(s)
    host = parts.hostname  # strips [], port, userinfo; lowercases
    if not host:
        raise ValueError(f"cannot extract a host from {target!r}")
    host = host.split("%")[0]
    try:
        return _ip_result(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.rstrip(".")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"invalid domain {host!r}: {e}") from None
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not l or len(l) > 63 for l in labels) or labels[-1].isdigit():
        raise ValueError(f"not a domain name: {host!r}")
    return {"kind": "domain", "value": ascii_host.lower(), "family": None}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def http_get_json(url: str, timeout: float) -> tuple[dict, str]:
    """GET url, return (json, final_url). Raises RdapError."""
    req = urllib.request.Request(url, headers={"Accept": ACCEPT, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_BODY + 1)
            final = resp.geturl()
    except urllib.error.HTTPError as e:
        ra = e.headers.get("Retry-After") if e.headers else None
        detail = ""
        try:
            j = json.loads(e.read(65536) or b"{}")
            detail = j.get("title") or " ".join(j.get("description") or [])
        except Exception:
            pass
        msg = f"HTTP {e.code}" + (f": {detail}" if detail else "")
        raise RdapError(msg, status=e.code, retry_after=ra) from None
    except urllib.error.URLError as e:
        raise RdapError(f"connection failed: {e.reason}") from None
    except TimeoutError:
        raise RdapError("timed out") from None
    if len(body) > MAX_BODY:
        raise RdapError("response exceeds size limit")
    try:
        return json.loads(body), final
    except ValueError:
        raise RdapError("response is not JSON") from None


# --------------------------------------------------------------------------
# Bootstrap (RFC 9224)
# --------------------------------------------------------------------------
def default_cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "ragnar", "rdap")


class Bootstrap:
    def __init__(self, base_url=IANA_BASE, cache_dir=None, ttl=BOOTSTRAP_TTL,
                 timeout=10.0, offline=False):
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.cache_dir = cache_dir or default_cache_dir()
        self.ttl = ttl
        self.timeout = timeout
        self.offline = offline
        self._mem: dict[str, dict] = {}
        self.notes: list[str] = []

    def _path(self, reg):
        return os.path.join(self.cache_dir, BOOTSTRAP_FILES[reg])

    def _write_cache(self, reg, data):
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.cache_dir, prefix=".bs-")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self._path(reg))
        except OSError as e:
            self.notes.append(f"bootstrap cache write failed: {e}")

    def load(self, reg) -> dict:
        if reg in self._mem:
            return self._mem[reg]
        path = self._path(reg)
        cached, age = None, None
        try:
            age = time.time() - os.path.getmtime(path)
            with open(path) as f:
                cached = json.load(f)
        except (OSError, ValueError):
            cached = None
        if cached is not None and (age < self.ttl or self.offline):
            self._mem[reg] = cached
            return cached
        if self.offline:
            raise RdapError(f"offline and no cached {BOOTSTRAP_FILES[reg]}")
        try:
            data, _ = http_get_json(self.base_url + BOOTSTRAP_FILES[reg], self.timeout)
            if not isinstance(data.get("services"), list):
                raise RdapError("bootstrap file has no services list")
            self._write_cache(reg, data)
        except RdapError as e:
            if cached is None:
                raise RdapError(f"bootstrap {BOOTSTRAP_FILES[reg]} unavailable: {e}") from None
            self.notes.append(f"using stale {BOOTSTRAP_FILES[reg]} ({int(age // 3600)}h old): {e}")
            data = cached
        self._mem[reg] = data
        return data

    @staticmethod
    def _pick(urls):
        https = [u for u in urls if u.lower().startswith("https://")]
        u = (https or urls)[0]
        return u if u.endswith("/") else u + "/"

    def server_for_domain(self, domain) -> tuple[str, str] | None:
        """Longest-label-suffix match. Returns (base_url, matched_suffix)."""
        best = None
        for entries, urls in (s[:2] for s in self.load("dns")["services"]):
            for e in entries:
                e = e.lower().strip(".")
                if domain == e or domain.endswith("." + e):
                    if best is None or e.count(".") > best[1].count("."):
                        best = (self._pick(urls), e)
        return best

    def server_for_asn(self, n: int) -> tuple[str, str] | None:
        """Ranges like '1-1876' or a single number. Narrowest range wins."""
        best = None
        for entries, urls in (s[:2] for s in self.load("asn")["services"]):
            for e in entries:
                lo, _, hi = str(e).partition("-")
                try:
                    lo, hi = int(lo), int(hi or lo)
                except ValueError:
                    continue
                if lo <= n <= hi and (best is None or hi - lo < best[2] - best[1]):
                    best = (self._pick(urls), lo, hi)
        return (best[0], f"{best[1]}-{best[2]}") if best else None

    def server_for_ip(self, net) -> tuple[str, str] | None:
        """Longest-prefix match. net is an ip_network. Returns (base_url, prefix)."""
        reg = "ipv4" if net.version == 4 else "ipv6"
        best = None
        for entries, urls in (s[:2] for s in self.load(reg)["services"]):
            for e in entries:
                try:
                    p = ipaddress.ip_network(e, strict=False)
                except ValueError:
                    continue
                if p.version == net.version and net.subnet_of(p):
                    if best is None or p.prefixlen > best[1].prefixlen:
                        best = (self._pick(urls), p)
        return (best[0], best[1].compressed) if best else None


# --------------------------------------------------------------------------
# Response normalisation (RFC 9083)
# --------------------------------------------------------------------------
def parse_vcard(vcard_array) -> dict:
    """jCard (RFC 7095) -> flat dict of the fields an operator acts on."""
    out: dict = {}
    if not (isinstance(vcard_array, list) and len(vcard_array) == 2
            and isinstance(vcard_array[1], list)):
        return out
    for prop in vcard_array[1]:
        if not (isinstance(prop, list) and len(prop) >= 4):
            continue
        name, params, _typ, val = prop[0], prop[1] or {}, prop[2], prop[3:]
        v = val[0] if len(val) == 1 else val
        if name == "fn" and v:
            out["name"] = str(v)
        elif name == "org" and v:
            out["org"] = v if isinstance(v, str) else " ".join(x for x in v if x)
        elif name == "kind":
            out["kind"] = v
        elif name == "email" and v:
            out.setdefault("email", []).append(str(v))
        elif name == "tel" and v:
            out.setdefault("tel", []).append(str(v).removeprefix("tel:"))
        elif name == "adr":
            label = params.get("label") if isinstance(params, dict) else None
            if label:
                out["address"] = " ".join(str(label).split())
            elif isinstance(v, list):
                flat = []
                for x in v:
                    flat.extend(x if isinstance(x, list) else [x])
                a = ", ".join(str(x) for x in flat if x)
                if a:
                    out["address"] = a
            if isinstance(params, dict) and params.get("cc"):
                out["country"] = params["cc"]
    return out


def parse_entities(entities, depth=0) -> list[dict]:
    out = []
    for ent in entities or []:
        if not isinstance(ent, dict):
            continue
        e = {"handle": ent.get("handle"), "roles": ent.get("roles") or []}
        e.update(parse_vcard(ent.get("vcardArray")))
        for pid in ent.get("publicIds") or []:
            if isinstance(pid, dict) and "IANA" in str(pid.get("type", "")):
                e["iana_id"] = pid.get("identifier")
        if depth < 3 and ent.get("entities"):
            e["entities"] = parse_entities(ent["entities"], depth + 1)
        out.append(e)
    return out


def events_map(events) -> dict:
    out = {}
    for ev in events or []:
        if isinstance(ev, dict) and ev.get("eventAction"):
            out.setdefault(ev["eventAction"], ev.get("eventDate"))
    return out


def find_role(entities, role) -> dict | None:
    for e in entities:
        if role in e["roles"]:
            return e
        hit = find_role(e.get("entities", []), role)
        if hit:
            return hit
    return None


def abuse_contact(entities) -> dict | None:
    e = find_role(entities, "abuse")
    if not e:
        return None
    return {k: e[k] for k in ("name", "email", "tel", "handle") if e.get(k)}


def related_rdap_links(obj, self_url) -> list[str]:
    out = []
    for ln in obj.get("links") or []:
        if not isinstance(ln, dict):
            continue
        href = ln.get("href")
        if (ln.get("rel") == "related" and href and href != self_url
                and "rdap" in str(ln.get("type", "application/rdap+json"))):
            out.append(href)
    return out


def norm_domain(obj) -> dict:
    ents = parse_entities(obj.get("entities"))
    reg = find_role(ents, "registrar")
    sdns = obj.get("secureDNS") or {}
    return {
        "object": "domain",
        "name": obj.get("ldhName"),
        "unicode_name": obj.get("unicodeName"),
        "handle": obj.get("handle"),
        "status": obj.get("status") or [],
        "events": events_map(obj.get("events")),
        "nameservers": [n.get("ldhName") for n in obj.get("nameservers") or []
                        if isinstance(n, dict) and n.get("ldhName")],
        "dnssec": sdns.get("delegationSigned"),
        "registrar": ({"name": reg.get("name") or reg.get("org"), "iana_id": reg.get("iana_id"),
                       "handle": reg.get("handle")} if reg else None),
        "registrant": _contact(find_role(ents, "registrant")),
        "abuse": abuse_contact(ents),
        "entities": ents,
    }


def norm_ip(obj) -> dict:
    ents = parse_entities(obj.get("entities"))
    cidrs = []
    for c in obj.get("cidr0_cidrs") or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx is not None and c.get("length") is not None:
            cidrs.append(f"{pfx}/{c['length']}")
    if not cidrs and obj.get("startAddress") and obj.get("endAddress"):
        try:
            s = ipaddress.ip_address(obj["startAddress"])
            e = ipaddress.ip_address(obj["endAddress"])
            cidrs = [n.compressed for n in ipaddress.summarize_address_range(s, e)]
        except (ValueError, TypeError):
            pass
    return {
        "object": "ip network",
        "handle": obj.get("handle"),
        "name": obj.get("name"),
        "type": obj.get("type"),
        "ip_version": obj.get("ipVersion"),
        "start": obj.get("startAddress"),
        "end": obj.get("endAddress"),
        "cidrs": cidrs,
        "country": obj.get("country"),
        "parent": obj.get("parentHandle"),
        "origin_asns": [int(a) for a in obj.get("arin_originas0_originautnums") or []
                        if str(a).isdigit()],
        "status": obj.get("status") or [],
        "events": events_map(obj.get("events")),
        "registrant": _contact(find_role(ents, "registrant")),
        "abuse": abuse_contact(ents),
        "entities": ents,
    }


def norm_asn(obj) -> dict:
    ents = parse_entities(obj.get("entities"))
    return {
        "object": "autnum",
        "handle": obj.get("handle"),
        "name": obj.get("name"),
        "type": obj.get("type"),
        "start": obj.get("startAutnum"),
        "end": obj.get("endAutnum"),
        "country": obj.get("country"),
        "status": obj.get("status") or [],
        "events": events_map(obj.get("events")),
        "registrant": _contact(find_role(ents, "registrant")),
        "abuse": abuse_contact(ents),
        "noc": _contact(find_role(ents, "noc")),
        "entities": ents,
    }


def _contact(e):
    if not e:
        return None
    return {k: e[k] for k in ("name", "org", "handle", "country", "email") if e.get(k)} or None



# --------------------------------------------------------------------------
# WHOIS fallback (RFC 3912) - only for domains whose TLD has no RDAP service
# --------------------------------------------------------------------------
WHOIS_NOT_FOUND = re.compile(
    r"(?im)^\s*(?:%+\s*)?(?:no match\b|not found\b|no entries found|no data found|"
    r"no object found|object does not exist|domain not found|nothing found|"
    r"status:\s*(?:free|available)\b|the queried object does not exist)")
WHOIS_RATE_LIMIT = re.compile(r"(?i)(limit exceeded|too many (?:requests|queries)|"
                              r"query rate|try again later)")
WHOIS_REFERRAL = re.compile(r"(?im)^\s*(?:registrar whois server|whois server|referralserver)\s*:"
                            r"\s*(?:whois://)?([a-z0-9.:\-]+)\s*$")
# canonical field <- lowercase WHOIS keys seen across registries
WHOIS_KEYS = {
    "name": ("domain name", "domain", "domainname", "domain_name"),
    "registrar": ("registrar", "registrar name", "sponsoring registrar", "registrar organization"),
    "iana_id": ("registrar iana id",),
    "registration": ("creation date", "created", "created on", "registered", "registered on",
                     "registration date", "domain registration date", "created date"),
    "expiration": ("registry expiry date", "expiry date", "expiration date", "expires",
                   "expires on", "paid-till", "registrar registration expiration date",
                   "renewal date", "domain expiration date", "expire date"),
    "last changed": ("updated date", "last updated", "last modified", "last-modified",
                     "changed", "modified", "last update", "updated"),
    "status": ("domain status", "status", "state"),
    "nameservers": ("name server", "nameserver", "nameservers", "nserver", "name servers",
                    "dns", "host name"),
    "dnssec": ("dnssec",),
    "registrant": ("registrant organization", "registrant", "registrant name", "org", "holder",
                   "registrant organisation"),
    "abuse": ("registrar abuse contact email", "abuse-mailbox", "abuse email", "abuse contact"),
    "country": ("registrant country", "country"),
}
_KEY2FIELD = {k: f for f, ks in WHOIS_KEYS.items() for k in ks}


def whois_query(host: str, query: str, timeout: float, port: int = WHOIS_PORT) -> str:
    """One RFC 3912 exchange. create_connection walks getaddrinfo, so v4 and v6 both work."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(query.encode("utf-8") + b"\r\n")
            chunks, total = [], 0
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
                total += len(b)
                if total > WHOIS_MAX:
                    raise RdapError(f"WHOIS reply from {host} exceeds size limit")
    except (OSError, socket.timeout) as e:
        raise RdapError(f"WHOIS {host}: {e.strerror or e}") from None
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse_whois(text: str) -> dict:
    """Key: value WHOIS text -> the same shape norm_domain() produces. Best effort by design;
    the raw text is always kept alongside."""
    f: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "%#>" or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower().strip("."), val.strip()
        field = _KEY2FIELD.get(key)
        if not field or not val:
            continue
        if field in ("status", "nameservers"):
            # 'clientTransferProhibited https://icann.org/epp#...' -> first token
            v = val.split()[0] if field == "status" else val.split()[0].rstrip(".").lower()
            lst = f.setdefault(field, [])
            if v not in lst:
                lst.append(v)
        else:
            f.setdefault(field, val)
    dnssec = f.get("dnssec", "").lower()
    events = {k: f[k] for k in ("registration", "expiration", "last changed") if k in f}
    abuse = f.get("abuse")
    return {
        "object": "domain",
        "name": (f.get("name") or "").lower() or None,
        "unicode_name": None,
        "handle": None,
        "status": f.get("status", []),
        "events": events,
        "nameservers": f.get("nameservers", []),
        "dnssec": (True if dnssec.startswith(("signed", "yes")) else
                   False if dnssec.startswith(("unsigned", "no")) else None),
        "registrar": ({"name": f["registrar"], "iana_id": f.get("iana_id"), "handle": None}
                      if f.get("registrar") else None),
        "registrant": ({"name": f["registrant"], "country": f.get("country")}
                       if f.get("registrant") else None),
        "abuse": {"email": [abuse]} if abuse and "@" in abuse else None,
        "entities": [],
    }


class WhoisServers:
    """TLD -> WHOIS server, learned from whois.iana.org and cached on disk."""

    def __init__(self, cache_dir, timeout, iana=WHOIS_IANA, port=WHOIS_PORT, offline=False):
        self.path = os.path.join(cache_dir, "whois_servers.json")
        self.timeout, self.iana, self.port, self.offline = timeout, iana, port, offline
        try:
            with open(self.path) as fh:
                self.map = json.load(fh)
        except (OSError, ValueError):
            self.map = {}

    def server_for(self, tld: str) -> str | None:
        ent = self.map.get(tld)
        if ent and (self.offline or time.time() - ent.get("t", 0) < WHOIS_SERVER_TTL):
            return ent.get("server")
        if self.offline:
            raise RdapError(f"offline and no cached WHOIS server for .{tld}")
        text = whois_query(self.iana, tld, self.timeout, self.port)
        m = re.search(r"(?im)^\s*(?:refer|whois)\s*:\s*([a-z0-9.:\-]+)\s*$", text)
        server = m.group(1).lower() if m else None
        self.map[tld] = {"server": server, "t": int(time.time())}
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".ws-")
            with os.fdopen(fd, "w") as fh:
                json.dump(self.map, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass
        return server

# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------
class Client:
    def __init__(self, bootstrap: Bootstrap, timeout=15.0, referral=True, raw=False,
                 asn_chain=True, whois: WhoisServers | None = None):
        self.bs = bootstrap
        self.whois = whois
        self.asn_chain = asn_chain
        self.timeout = timeout
        self.referral = referral
        self.raw = raw

    def lookup(self, target: str) -> dict:
        rec = {"module": MODULE, "version": VERSION, "query": target,
               "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        try:
            c = classify(target)
        except ValueError as e:
            return {**rec, "ok": False, "status": "invalid", "error": str(e)}
        rec.update(kind=c["kind"], normalized=c["value"])
        if c["family"]:
            rec["family"] = f"ipv{c['family']}"
        if c.get("mapped_from"):
            rec["mapped_from"] = c["mapped_from"]
        try:
            if c["kind"] == "domain":
                rec.update(self._domain(c["value"]))
                if rec.get("status") == "no_rdap_service" and self.whois:
                    rdap_err = rec.pop("error", None)
                    rec["protocol"] = "whois"
                    rec.setdefault("notes", []).append(rdap_err)
                    rec.update(self._whois_domain(c["value"]))
            elif c["kind"] == "asn":
                rec.update(self._asn(int(c["value"])))
            else:
                rec.update(self._ip(c["value"]))
        except RdapError as e:
            rec.update(ok=False, status="error", error=str(e))
            if e.status:
                rec["http_status"] = e.status
            if e.retry_after:
                rec["retry_after"] = e.retry_after
        rec.setdefault("protocol", "rdap")
        if self.bs.notes:
            rec["notes"] = list(dict.fromkeys(self.bs.notes + rec.get("notes", [])))
        return rec

    def _whois_domain(self, value):
        out = {"protocol": "whois"}
        tld = value.rsplit(".", 1)[-1]
        server = self.whois.server_for(tld)
        if not server:
            return {**out, "ok": False, "status": "no_service",
                    "error": f".{tld} has neither RDAP nor a WHOIS server listed at IANA"}
        labels = value.split(".")
        names = [".".join(labels[i:]) for i in range(len(labels) - 1)][-MAX_WALK:]
        text, result, tried = "", None, []
        for name in names:
            tried.append(name)
            t = whois_query(server, name, self.timeout, self.whois.port)
            if WHOIS_RATE_LIMIT.search(t) and len(t) < 2048:
                raise RdapError(f"WHOIS {server} rate-limited: {t.strip()[:200]}")
            p = parse_whois(t)
            if (p["registrar"] or p["name"]) and not (WHOIS_NOT_FOUND.search(t) and not p["registrar"]):
                text, result = t, p
                break
            text = t
        if result is None:
            return {**out, "ok": False, "status": "not_found", "server": server,
                    "tried": tried, "whois_text": text[:65536]}
        hops = [server]
        # One referral hop (thin registries point at the registrar's WHOIS).
        m = WHOIS_REFERRAL.search(text)
        if self.referral and m and m.group(1).lower() not in hops:
            ref = m.group(1).lower()
            try:
                rtext = whois_query(ref, value, self.timeout, self.whois.port)
                hops.append(ref)
                rres = parse_whois(rtext)
                for k, v in rres.items():  # registrar record fills gaps only
                    if v and not result.get(k):
                        result[k] = v
                result["events"] = {**rres["events"], **result["events"]}
                text = text + "\n\n# --- " + ref + " ---\n" + rtext
            except RdapError as e:
                out["referral_error"] = str(e)
        return {**out, "ok": True, "status": "found", "server": server, "whois_hops": hops,
                "matched_name": result["name"] or tried[-1], "result": result,
                "whois_text": text[:65536]}

    def _fetch(self, url):
        return http_get_json(url, self.timeout)

    def _ip(self, value):
        net = ipaddress.ip_network(value, strict=False)
        hit = self.bs.server_for_ip(net)
        if not hit:
            return {"ok": False, "status": "no_rdap_service",
                    "error": f"no RDAP service in IANA bootstrap for {value}"}
        base, matched = hit
        url = base + "ip/" + (value if "/" in value else net.network_address.compressed)
        try:
            obj, final = self._fetch(url)
        except RdapError as e:
            if e.status == 404:
                return {"ok": False, "status": "not_found", "server": base,
                        "bootstrap_match": matched, "url": url}
            raise
        out = {"ok": True, "status": "found", "server": base, "bootstrap_match": matched,
               "url": url, "source_url": final, "result": norm_ip(obj),
               "port43": obj.get("port43")}
        if self.raw:
            out["raw"] = obj
        if self.asn_chain and out["result"]["origin_asns"]:
            out["origin_as"] = []
            for n in out["result"]["origin_asns"][:4]:
                try:
                    a = self._asn(n)
                except RdapError as e:
                    a = {"ok": False, "status": "error", "error": str(e)}
                a.pop("raw", None)
                out["origin_as"].append({"asn": n, **a})
        return out

    def _asn(self, n: int):
        hit = self.bs.server_for_asn(n)
        if not hit:
            return {"ok": False, "status": "no_rdap_service",
                    "error": f"AS{n} is not in the IANA ASN bootstrap (private/reserved or unallocated)"}
        base, matched = hit
        url = f"{base}autnum/{n}"
        try:
            obj, final = self._fetch(url)
        except RdapError as e:
            if e.status == 404:
                return {"ok": False, "status": "not_found", "server": base,
                        "bootstrap_match": matched, "url": url}
            raise
        out = {"ok": True, "status": "found", "server": base, "bootstrap_match": matched,
               "url": url, "source_url": final, "result": norm_asn(obj),
               "port43": obj.get("port43")}
        if self.raw:
            out["raw"] = obj
        return out

    def _domain(self, value):
        hit = self.bs.server_for_domain(value)
        if not hit:
            tld = value.rsplit(".", 1)[-1]
            return {"ok": False, "status": "no_rdap_service",
                    "error": f".{tld} has no RDAP service in the IANA bootstrap"}
        base, suffix = hit
        labels = value.split(".")
        floor = suffix.count(".") + 2  # suffix plus one label
        # Longest first, but keep the shortest MAX_WALK so the registered
        # name (near the suffix) is always tried for deep subdomains.
        candidates = [".".join(labels[i:]) for i in range(len(labels) - floor + 1)][-MAX_WALK:]
        if not candidates:  # the query is the registry suffix itself
            candidates = [value]
        tried = []
        for name in candidates:
            url = base + "domain/" + name
            tried.append(name)
            try:
                obj, final = self._fetch(url)
            except RdapError as e:
                if e.status == 404:
                    continue
                raise
            out = {"ok": True, "status": "found", "server": base, "bootstrap_match": suffix,
                   "url": url, "source_url": final, "matched_name": name,
                   "result": norm_domain(obj), "port43": obj.get("port43")}
            if self.raw:
                out["raw"] = obj
            if self.referral:
                ref = self._referral(obj, final, url)
                if ref:
                    out["referral"] = ref
            return out
        return {"ok": False, "status": "not_found", "server": base,
                "bootstrap_match": suffix, "tried": tried}

    def _referral(self, obj, final, url):
        links = [l for l in related_rdap_links(obj, final) if l != url]
        if not links:
            return None
        href = links[0]
        try:
            robj, rfinal = self._fetch(href)
        except RdapError as e:
            return {"url": href, "ok": False, "error": str(e)}
        ref = {"url": href, "source_url": rfinal, "ok": True, "result": norm_domain(robj)}
        if self.raw:
            ref["raw"] = robj
        return ref


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def _fmt_contact(c):
    if not c:
        return None
    who = c.get("name") or c.get("org") or c.get("handle")
    bits = [who] if who else []
    if c.get("email"):
        bits.append(", ".join(c["email"]) if isinstance(c["email"], list) else c["email"])
    if c.get("tel"):
        bits.append(", ".join(c["tel"]))
    return " | ".join(bits) or None


def render_text(rec) -> str:
    L = [f"== {rec['query']}  [{rec.get('kind', '?')}"
         + (f" {rec['family']}" if rec.get("family") else "") + "]"]
    if not rec.get("ok"):
        L.append(f"  status: {rec.get('status')}")
        if rec.get("error"):
            L.append(f"  error:  {rec['error']}")
        if rec.get("tried"):
            L.append(f"  tried:  {', '.join(rec['tried'])} @ {rec.get('server')}")
        if rec.get("retry_after"):
            L.append(f"  retry-after: {rec['retry_after']}")
        for n in rec.get("notes", []):
            L.append(f"  note:   {n}")
        return "\n".join(L)
    r = rec["result"]

    def kv(k, v):
        if v not in (None, "", [], {}):
            L.append(f"  {k:<12} {v}")

    if rec.get("protocol") == "whois":
        kv("source", "WHOIS " + " -> ".join(rec.get("whois_hops", [rec.get("server")]))
           + " (no RDAP service for this TLD; parsed best-effort)")
    else:
        kv("server", rec.get("source_url"))
    if r["object"] == "domain":
        kv("domain", (r["name"] or rec.get("normalized")) + (f" ({r['unicode_name']})" if r.get("unicode_name")
                                  and r["unicode_name"] != r["name"] else ""))
        if rec.get("matched_name") and rec["matched_name"] != rec.get("normalized"):
            kv("note", f"{rec['normalized']} is not registered itself; showing {rec['matched_name']}")
        kv("handle", r["handle"])
        if r["registrar"]:
            kv("registrar", (r["registrar"]["name"] or "?")
               + (f" (IANA {r['registrar']['iana_id']})" if r["registrar"].get("iana_id") else ""))
        ev = r["events"]
        kv("registered", ev.get("registration"))
        kv("expires", ev.get("expiration"))
        kv("changed", ev.get("last changed"))
        kv("status", ", ".join(r["status"]))
        kv("nameservers", ", ".join(r["nameservers"]))
        kv("dnssec", {True: "signed", False: "unsigned"}.get(r["dnssec"]))
        kv("registrant", _fmt_contact(r["registrant"]))
        kv("abuse", _fmt_contact(r["abuse"]))
        ref = rec.get("referral")
        if ref:
            if ref.get("ok"):
                rr = ref["result"]
                L.append(f"  -- registrar record ({ref['source_url']})")
                kv("registrant", _fmt_contact(rr["registrant"]))
                kv("abuse", _fmt_contact(rr["abuse"]))
                kv("expires", rr["events"].get("expiration") or rr["events"].get(
                    "registrar expiration"))
            else:
                kv("referral", f"{ref['url']} failed: {ref.get('error')}")
    elif r["object"] == "autnum":
        rng = (f"AS{r['start']}" if r["start"] == r["end"]
               else f"AS{r['start']} - AS{r['end']}") if r["start"] is not None else None
        kv("asn", rng)
        kv("name", r["name"])
        kv("handle", r["handle"])
        kv("type", r["type"])
        kv("country", r["country"])
        kv("status", ", ".join(r["status"]))
        kv("registrant", _fmt_contact(r["registrant"]))
        kv("noc", _fmt_contact(r["noc"]))
        kv("abuse", _fmt_contact(r["abuse"]))
        kv("registered", r["events"].get("registration"))
        kv("changed", r["events"].get("last changed"))
    else:
        kv("network", ", ".join(r["cidrs"]) or f"{r['start']} - {r['end']}")
        kv("range", f"{r['start']} - {r['end']}" if r["start"] else None)
        kv("name", r["name"])
        kv("handle", r["handle"])
        kv("type", r["type"])
        kv("country", r["country"])
        kv("parent", r["parent"])
        kv("registrant", _fmt_contact(r["registrant"]))
        kv("abuse", _fmt_contact(r["abuse"]))
        ev = r["events"]
        kv("registered", ev.get("registration"))
        kv("changed", ev.get("last changed"))
        for oa in rec.get("origin_as", []):
            if oa.get("ok"):
                ar = oa["result"]
                L.append(f"  -- origin AS{oa['asn']} ({oa['source_url']})")
                kv("as name", ar["name"])
                kv("as org", _fmt_contact(ar["registrant"]))
                kv("as abuse", _fmt_contact(ar["abuse"]))
            else:
                kv("origin as", f"AS{oa['asn']}: {oa.get('error') or oa.get('status')}")
    for n in rec.get("notes", []):
        kv("note", n)
    return "\n".join(L)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="rdap_lookup",
        description="RDAP lookup for IPv4/IPv6 addresses, prefixes, ASNs, domains and URLs.")
    ap.add_argument("targets", nargs="*", help="IP, CIDR, ASN (AS15169 / 15169 / AS1.10), domain or URL")
    ap.add_argument("-f", "--file", help="read targets from file ('-' = stdin), one per line")
    ap.add_argument("--json", action="store_true", help="JSON-lines output (one record per target)")
    ap.add_argument("--raw", action="store_true", help="include raw RDAP response in JSON")
    ap.add_argument("--no-referral", action="store_true",
                    help="do not follow registry -> registrar referral for domains")
    ap.add_argument("--no-asn-chain", action="store_true",
                    help="do not look up the origin AS published in IP results (ARIN only)")
    ap.add_argument("--no-whois", action="store_true",
                    help="RDAP only: no WHOIS fallback for TLDs without RDAP")
    ap.add_argument("--whois-text", action="store_true",
                    help="print the raw WHOIS reply in text mode (always included in --json)")
    ap.add_argument("--whois-iana", default=WHOIS_IANA, help=argparse.SUPPRESS)
    ap.add_argument("--whois-port", type=int, default=WHOIS_PORT, help=argparse.SUPPRESS)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between targets in a batch (default 1.0)")
    ap.add_argument("--cache-dir", default=None, help=f"bootstrap cache (default {default_cache_dir()})")
    ap.add_argument("--bootstrap-url", default=IANA_BASE, help=argparse.SUPPRESS)
    ap.add_argument("--refresh", action="store_true", help="refetch IANA bootstrap files now")
    ap.add_argument("--offline", action="store_true", help="use cached bootstrap only, even if stale")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    a = ap.parse_args(argv)

    targets = list(a.targets)
    if a.file:
        fh = sys.stdin if a.file == "-" else open(a.file)
        with fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    if not targets and not a.refresh:
        ap.error("no targets")

    bs = Bootstrap(a.bootstrap_url, a.cache_dir, ttl=0 if a.refresh else BOOTSTRAP_TTL,
                   timeout=a.timeout, offline=a.offline)
    if a.refresh:
        for reg in BOOTSTRAP_FILES:
            try:
                bs.load(reg)
            except RdapError as e:
                print(f"refresh {reg}: {e}", file=sys.stderr)
                return EXIT_ERROR
        bs.ttl = BOOTSTRAP_TTL
        if not targets:
            print(f"bootstrap refreshed in {bs.cache_dir}")
            return EXIT_FOUND
    ws = None if a.no_whois else WhoisServers(bs.cache_dir, a.timeout, a.whois_iana,
                                              a.whois_port, a.offline)
    cli = Client(bs, timeout=a.timeout, referral=not a.no_referral, raw=a.raw,
                 asn_chain=not a.no_asn_chain, whois=ws)

    worst = EXIT_FOUND
    for i, t in enumerate(targets):
        if i and a.delay > 0:
            time.sleep(a.delay)
        rec = cli.lookup(t)
        if a.json:
            print(json.dumps(rec, ensure_ascii=False), flush=True)
        else:
            txt = render_text(rec)
            if a.whois_text and rec.get("whois_text"):
                txt += "\n  -- raw WHOIS --\n" + "\n".join(
                    "  " + ln for ln in rec["whois_text"].rstrip().splitlines())
            print(txt + ("\n" if i < len(targets) - 1 else ""), flush=True)
        code = (EXIT_FOUND if rec.get("ok")
                else EXIT_NOTFOUND if rec.get("status") in ("not_found", "no_rdap_service", "no_service")
                else EXIT_ERROR)
        worst = max(worst, code)
    return worst


if __name__ == "__main__":
    sys.exit(main())
