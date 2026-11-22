#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
certwatch - passive TLS certificate triage scanner  (Ragnar suite)

Watches TLS handshakes crossing a tap/SPAN/bridge and triages any X.509
certificate it can *observe* for expiry and validity problems. Detection
only: certwatch never opens a socket, never probes, never sends a byte.

HARD LIMIT (read this): the certificate is cleartext on the wire only for
TLS 1.0/1.1/1.2. In TLS 1.3 the Certificate message is encrypted under the
handshake keys, so it is NOT observable passively. For 1.3 flows certwatch
emits an inventory record (SNI + version + cipher) marked cert-not-observable
rather than a triage record. This is a property of TLS 1.3, not a bug.

Test floor: Raspberry Pi Zero 2W. See PLATFORM NOTES at the bottom.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import logging
import os
import signal
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# ---- crypto / x509 ---------------------------------------------------------
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

LOG = logging.getLogger("certwatch")

# Suite identity. Every emitted record carries these so a downstream
# aggregator (see ragnar_syslog.py) can tell modules apart.
MODULE = "certwatch"
VERSION = "1.0"

# ---------------------------------------------------------------------------
# Config / thresholds
# ---------------------------------------------------------------------------

# Common TLS-bearing TCP ports. Kept tight on purpose: on a Pi Zero 2W a broad
# 'tcp' capture on a busy SPAN port drops packets. Override with --ports.
DEFAULT_PORTS = (443, 8443, 993, 995, 465, 587, 990, 636, 989, 992,
                 5061, 6697, 8883, 9443, 4433, 10443)

WARN_DAYS_DEFAULT = 30          # "expiring soon" horizon
MAX_PUBLIC_VALIDITY_DAYS = 398  # CA/B Forum leaf ceiling; longer => flag
RSA_MIN_BITS = 2048
EC_MIN_BITS = 256

# Flow-table bounds (Pi Zero 2W has 512 MB; keep state small and bounded).
MAX_FLOWS = 512                 # concurrent half-open handshakes tracked
MAX_FLOW_BYTES = 64 * 1024      # per-direction handshake buffer cap
FLOW_TTL = 30.0                 # seconds of inactivity before eviction

# TLS constants
CT_HANDSHAKE = 0x16
CT_CHANGE_CIPHER = 0x14
CT_ALERT = 0x15
CT_APPDATA = 0x17
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0b
EXT_SNI = 0x0000
EXT_SUPPORTED_VERSIONS = 0x002b
TLS13 = 0x0304

SEV_CRIT = "CRITICAL"
SEV_WARN = "WARN"
SEV_INFO = "INFO"
SEV_OK = "OK"
_SEV_RANK = {SEV_OK: 0, SEV_INFO: 1, SEV_WARN: 2, SEV_CRIT: 3}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# X.509 triage engine
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Finding code registry
# ---------------------------------------------------------------------------
# Single source of truth for what this module can emit. The README verifier
# cross-checks this against both the code and the docs, which is more robust
# than scraping Finding(...) call sites -- a severity chosen at runtime (see
# ROCA_KEY) is invisible to a regex but explicit here.
# Value is the severity, or a tuple when it depends on the certificate.
FINDING_CODES = {
    "EXPIRED":            SEV_CRIT,
    "NOT_YET_VALID":      SEV_CRIT,
    "NAME_MISMATCH":      SEV_CRIT,
    "WEAK_SIG_MD5":       SEV_CRIT,
    "WEAK_SIG_SHA1":      SEV_CRIT,
    "EXPIRING_SOON":      SEV_WARN,
    "SELF_SIGNED":        SEV_WARN,
    "WEAK_KEY":           SEV_WARN,
    "MISSING_SAN":        SEV_WARN,
    "LONG_VALIDITY":      SEV_INFO,
    "WILDCARD":           SEV_INFO,
    "CA_CERT":            SEV_INFO,
    # CVE detectors
    "ROCA_KEY":           (SEV_CRIT, SEV_WARN),  # CRIT inside factorable sizes
    "CURVEBALL_SUSPECT":  SEV_CRIT,
    "EC_INVALID_FIELD":   SEV_CRIT,
    "EC_EXPLICIT_PARAMS": SEV_WARN,
    "DSA_IN_CHAIN":       SEV_WARN,
    "KEY_UNPARSEABLE":    SEV_WARN,
}


@dataclass
class Finding:
    code: str
    severity: str
    detail: str = ""


# ---------------------------------------------------------------------------
# CVE detectors (added Oct 31 2026 — see certwatch-cve-preflight.md)
#
# Every detector here reads the certificate's own bytes. None of them depends
# on the IP version, so IPv4/IPv6 parity is structural rather than per-rule.
# ---------------------------------------------------------------------------

# --- CVE-2017-15361 "ROCA": Infineon RSA key generation fingerprint ---------
# 17-prime discrete-log fingerprint (Nemec et al., CCS'17). A vulnerable
# modulus is, for every prime p below, congruent to a generator power whose
# exponent lies in a small set -- encoded here as a bitmask per prime.
# Genuine keys clear only about half the individual checks; all 17 must hit.
ROCA_PRIMES = (11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109,
               127, 151, 157)
ROCA_PRINTS = (1026, 5658, 107286, 199410, 67109890, 5310023542746834,
               1455791217086302986, 20052041432995567486,
               6041388139249378920330, 207530445072488465666,
               79228162521181866724264247298, 1760368345969468176824550810518,
               50079290986288516948354744811034,
               473022961816146413042658758988474,
               144390480366845522447407333004847678774,
               1800793591454480341970779146165214289059119882,
               126304807362733370595828809000324029340048915994)

# Key sizes the ROCA paper considers practically factorable.
ROCA_FACTORABLE_BITS = ((512, 704), (992, 1216), (1984, 2144))


def roca_fingerprint(n: int) -> bool:
    """True if an RSA modulus carries the Infineon (ROCA) fingerprint."""
    if n <= 0:
        return False
    for prime, mask in zip(ROCA_PRIMES, ROCA_PRINTS):
        if not ((1 << (n % prime)) & mask):
            return False
    return True


def roca_factorable(bits: int) -> bool:
    return any(lo <= bits <= hi for lo, hi in ROCA_FACTORABLE_BITS)


STD_CURVES = {
    "prime192v1": {
        "p": 0xfffffffffffffffffffffffffffffffeffffffffffffffff,
        "a": 0xfffffffffffffffffffffffffffffffefffffffffffffffc,
        "b": 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
        "G": bytes.fromhex("04188da80eb03090f67cbf20eb43a18800f4ff0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
        "n": 0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
    },
    "secp224r1": {
        "p": 0xffffffffffffffffffffffffffffffff000000000000000000000001,
        "a": 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe,
        "b": 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
        "G": bytes.fromhex("04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
        "n": 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
    },
    "prime256v1": {
        "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        "G": bytes.fromhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    },
    "secp384r1": {
        "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        "a": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        "b": 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        "G": bytes.fromhex("04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
        "n": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    },
    "secp521r1": {
        "p": 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        "a": 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
        "b": 0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        "G": bytes.fromhex("0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"),
        "n": 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
    },
    "secp256k1": {
        "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        "a": 0x0,
        "b": 0x7,
        "G": bytes.fromhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        "n": 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    },
}


# --- Minimal DER reader (explicit EC parameters) ---------------------------
# Hand-rolled rather than pulled from a library because the whole point is to
# read what the ORIGINAL certificate encodes. The cryptography library
# normalizes explicit parameters back to a named curve, which destroys the
# CVE-2020-0601 signal before a detector could ever see it.

EC_PUBKEY_OID = bytes.fromhex("06072A8648CE3D0201")   # 1.2.840.10045.2.1


def _der_read(buf: bytes, i: int):
    """Read one TLV. Returns (tag, value_bytes, next_index)."""
    if i + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(buf):
            raise ValueError("bad DER length")
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + n > len(buf):
        raise ValueError("DER length overruns buffer")
    return tag, buf[i:i + n], i + n


def ec_params_tag(der: bytes):
    """Tag of the EC AlgorithmIdentifier parameters in the original cert DER.

    0x06 = named curve OID (normal). 0x30 = explicit parameters, the shape
    CVE-2020-0601 relies on and the parse path CVE-2022-0778 loops in.
    Returns None when the certificate is not EC.
    """
    i = der.find(EC_PUBKEY_OID)
    if i < 0:
        return None
    j = i + len(EC_PUBKEY_OID)
    return der[j] if j < len(der) else None


def parse_explicit_ec_params(der: bytes):
    """Decode explicit ECParameters from a certificate DER.

    ECParameters ::= SEQUENCE {
        version INTEGER, fieldID SEQUENCE { OID, p INTEGER },
        curve SEQUENCE { a OCTET STRING, b OCTET STRING, seed BIT STRING OPT },
        base OCTET STRING, order INTEGER, cofactor INTEGER OPTIONAL }

    Returns a dict, or None if absent/unparseable. Never raises: a malformed
    certificate must not take the daemon down.
    """
    try:
        i = der.find(EC_PUBKEY_OID)
        if i < 0:
            return None
        j = i + len(EC_PUBKEY_OID)
        if j >= len(der) or der[j] != 0x30:
            return None
        _tag, seq, _ = _der_read(der, j)
        k = 0
        _t, _ver, k = _der_read(seq, k)
        _t, fid, k = _der_read(seq, k)
        _t, curve, k = _der_read(seq, k)
        _t, base, k = _der_read(seq, k)
        _t, order, k = _der_read(seq, k)
        m = 0
        _t, _foid, m = _der_read(fid, m)
        _t, p_b, m = _der_read(fid, m)
        q = 0
        _t, a_b, q = _der_read(curve, q)
        _t, b_b, q = _der_read(curve, q)
        return {
            "p": int.from_bytes(p_b, "big"),
            "a": int.from_bytes(a_b, "big"),
            "b": int.from_bytes(b_b, "big"),
            "G": bytes(base),
            "n": int.from_bytes(order, "big"),
        }
    except Exception:
        return None


def match_std_curve(params: dict):
    """Name of the standard curve whose field and coefficients these match."""
    for name, std in STD_CURVES.items():
        if (params["p"] == std["p"] and params["a"] == std["a"]
                and params["b"] == std["b"]):
            return name
    return None


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Deterministic-enough Miller-Rabin for CVE-2022-0778 field checking."""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small[:rounds]:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class CertTriage:
    """Pure function object: DER bytes in, findings out. No I/O, no network."""

    def __init__(self, warn_days: int = WARN_DAYS_DEFAULT):
        self.warn_days = warn_days

    def triage(self, der: bytes, server_name: Optional[str] = None) -> dict:
        cert = x509.load_der_x509_certificate(der)
        findings: list[Finding] = []
        now = _now()

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        # --- validity window ---
        if now > not_after:
            findings.append(Finding(
                "EXPIRED", SEV_CRIT,
                f"expired {(now - not_after).days}d ago ({not_after.date()})"))
        elif now < not_before:
            findings.append(Finding(
                "NOT_YET_VALID", SEV_CRIT,
                f"not valid until {not_before.date()}"))
        else:
            days_left = (not_after - now).days
            if days_left <= self.warn_days:
                findings.append(Finding(
                    "EXPIRING_SOON", SEV_WARN,
                    f"{days_left}d left ({not_after.date()})"))

        # --- validity period length ---
        validity_days = (not_after - not_before).days
        if validity_days > MAX_PUBLIC_VALIDITY_DAYS:
            findings.append(Finding(
                "LONG_VALIDITY", SEV_INFO,
                f"{validity_days}d window (>{MAX_PUBLIC_VALIDITY_DAYS}d); "
                "internal/non-public PKI"))

        # --- self-signed ---
        self_signed = cert.issuer == cert.subject
        if self_signed:
            findings.append(Finding("SELF_SIGNED", SEV_WARN,
                                    "issuer == subject"))

        # --- CA cert presented as leaf ---
        try:
            bc = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS).value
            if bc.ca:
                findings.append(Finding("CA_CERT", SEV_INFO,
                                        "BasicConstraints CA:TRUE"))
        except x509.ExtensionNotFound:
            pass

        # --- signature algorithm strength ---
        sig_hash = getattr(cert.signature_hash_algorithm, "name", "unknown")
        if sig_hash in ("md5", "md2"):
            findings.append(Finding("WEAK_SIG_MD5", SEV_CRIT,
                                    f"signature uses {sig_hash}"))
        elif sig_hash in ("sha1",):
            findings.append(Finding("WEAK_SIG_SHA1", SEV_CRIT,
                                    "signature uses sha1"))

        # --- public key strength ---
        # public_key() REFUSES explicit-parameter EC keys that do not map to
        # a supported named curve -- which is precisely what a CVE-2020-0601
        # certificate looks like, since its base point has been moved. If
        # this raised, the flow would be dropped on exactly the certificate
        # most worth reporting. So the key is optional from here on and the
        # DER-based detectors below run regardless.
        try:
            pk = cert.public_key()
        except Exception as e:
            pk = None
            key_desc = "unparseable"
            findings.append(Finding(
                "KEY_UNPARSEABLE", SEV_WARN,
                f"public key rejected by the X.509 parser ({e.__class__.__name__})"))
        if pk is not None:
            key_desc = self._key_desc(pk)
            weak = self._weak_key(pk)
            if weak:
                findings.append(Finding("WEAK_KEY", SEV_WARN, weak))

        # --- CVE detectors (cert-content; see certwatch-cve-preflight.md) ---
        findings.extend(self._cve_findings(der, pk))

        # --- SAN / naming ---
        sans = self._get_sans(cert)
        if not sans:
            findings.append(Finding("MISSING_SAN", SEV_WARN,
                                    "no subjectAltName (CN-only)"))
        if any(n.startswith("*.") for n in sans):
            findings.append(Finding("WILDCARD", SEV_INFO,
                                    "wildcard SAN present"))

        # --- SNI vs cert name match (only if we observed the SNI) ---
        name_match = None
        if server_name:
            name_match = self._name_matches(server_name, cert, sans)
            if not name_match:
                findings.append(Finding(
                    "NAME_MISMATCH", SEV_CRIT,
                    f"SNI '{server_name}' not in cert names"))

        severity = SEV_OK
        for f in findings:
            if _SEV_RANK[f.severity] > _SEV_RANK[severity]:
                severity = f.severity

        return {
            "subject": self._name_str(cert.subject),
            "issuer": self._name_str(cert.issuer),
            "serial": format(cert.serial_number, "x"),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            # Numeric and negative once expired, so a SIEM can alert on
            # "days_left < 7" without parsing the detail strings. Truncated
            # toward zero, not floored: timedelta.days floors, which would
            # report -41 for a cert the detail text calls "expired 40d ago".
            "days_left": int((not_after - now).total_seconds() // 86400)
            if not_after >= now else
            -int((now - not_after).total_seconds() // 86400),
            "validity_days": validity_days,
            "sig_hash": sig_hash,
            "key": key_desc,
            "sans": sans,
            "self_signed": self_signed,
            "sni": server_name,
            "sni_match": name_match,
            "status": severity,
            "findings": [f.__dict__ for f in findings],
        }

    # -- helpers --
    def _cve_findings(self, der: bytes, pk) -> list:
        """Cert-content CVE detectors.

        Wrapped defensively: a hostile certificate must cost one flow, never
        the daemon. Each detector is independent so one failure cannot
        suppress the others.
        """
        out = []

        # CVE-2017-15361 ROCA -- Infineon RSA key generation.
        try:
            if pk is not None and isinstance(pk, rsa.RSAPublicKey):
                n = pk.public_numbers().n
                if roca_fingerprint(n):
                    bits = pk.key_size
                    sev = SEV_CRIT if roca_factorable(bits) else SEV_WARN
                    out.append(Finding(
                        "ROCA_KEY", sev,
                        f"RSA-{bits} modulus carries the Infineon ROCA "
                        f"fingerprint (CVE-2017-15361)"
                        + ("; size is in the practically-factorable range"
                           if roca_factorable(bits) else
                           "; size outside the published factorable range")))
        except Exception:
            pass

        # CVE-2025-58188 -- a DSA key in the chain panics Go's x509 verifier.
        try:
            if pk is not None and isinstance(pk, dsa.DSAPublicKey):
                out.append(Finding(
                    "DSA_IN_CHAIN", SEV_WARN,
                    "DSA public key: panics Go crypto/x509 chain validation "
                    "(CVE-2025-58188, Go <1.24.8 / 1.25.0-1.25.2)"))
        except Exception:
            pass

        # CVE-2020-0601 CurveBall / CVE-2022-0778 -- explicit EC parameters.
        try:
            if ec_params_tag(der) == 0x30:
                params = parse_explicit_ec_params(der)
                if params is None:
                    out.append(Finding(
                        "EC_EXPLICIT_PARAMS", SEV_WARN,
                        "EC key uses explicit curve parameters that could "
                        "not be decoded"))
                else:
                    std = match_std_curve(params)
                    # CVE-2022-0778: non-prime field loops BN_mod_sqrt.
                    if not _is_probable_prime(params["p"]):
                        out.append(Finding(
                            "EC_INVALID_FIELD", SEV_CRIT,
                            "explicit EC parameters declare a non-prime "
                            "field: infinite loop in OpenSSL BN_mod_sqrt "
                            "on parse (CVE-2022-0778)"))
                    if std and params["G"] != STD_CURVES[std]["G"]:
                        # Field and coefficients match a standard curve but
                        # the generator does not: the CurveBall shape.
                        out.append(Finding(
                            "CURVEBALL_SUSPECT", SEV_CRIT,
                            f"explicit EC parameters match {std} except for "
                            f"the base point G -- forged-signature shape of "
                            f"CVE-2020-0601"))
                    else:
                        out.append(Finding(
                            "EC_EXPLICIT_PARAMS", SEV_WARN,
                            "EC key uses explicit curve parameters"
                            + (f" (matches {std})" if std
                               else " (non-standard curve)")
                            + "; rare in TLS server certs and the "
                              "precondition for CVE-2020-0601"))
        except Exception:
            pass

        return out

    @staticmethod
    def _key_desc(pk) -> str:
        if isinstance(pk, rsa.RSAPublicKey):
            return f"RSA-{pk.key_size}"
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return f"EC-{pk.curve.name}"
        if isinstance(pk, dsa.DSAPublicKey):
            return f"DSA-{pk.key_size}"
        return type(pk).__name__

    @staticmethod
    def _weak_key(pk) -> Optional[str]:
        if isinstance(pk, rsa.RSAPublicKey) and pk.key_size < RSA_MIN_BITS:
            return f"RSA-{pk.key_size} (<{RSA_MIN_BITS})"
        if isinstance(pk, dsa.DSAPublicKey):
            return f"DSA-{pk.key_size} (deprecated)"
        if isinstance(pk, ec.EllipticCurvePublicKey) and pk.key_size < EC_MIN_BITS:
            return f"EC-{pk.key_size} (<{EC_MIN_BITS})"
        return None

    @staticmethod
    def _get_sans(cert) -> list[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            return list(ext.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _name_str(name) -> str:
        try:
            cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn:
                return cn[0].value
        except Exception:
            pass
        return name.rfc4514_string()

    @classmethod
    def _name_matches(cls, host: str, cert, sans: list[str]) -> bool:
        names = list(sans)
        if not names:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn:
                names = [cn[0].value]
        host = host.lower().rstrip(".")
        for n in names:
            n = n.lower().rstrip(".")
            if n == host:
                return True
            if n.startswith("*.") and "." in host:
                if host.split(".", 1)[1] == n[2:]:
                    return True
        return False


# ---------------------------------------------------------------------------
# TLS wire parsers (raw bytes; never trust the input)
# ---------------------------------------------------------------------------

def parse_sni(client_hello_body: bytes) -> Optional[str]:
    """Extract SNI host from a ClientHello handshake body (post 4-byte hdr)."""
    try:
        b = client_hello_body
        i = 2 + 32                      # legacy_version + random
        sid_len = b[i]; i += 1 + sid_len
        cs_len = struct.unpack("!H", b[i:i+2])[0]; i += 2 + cs_len
        comp_len = b[i]; i += 1 + comp_len
        if i + 2 > len(b):
            return None
        ext_total = struct.unpack("!H", b[i:i+2])[0]; i += 2
        end = i + ext_total
        while i + 4 <= end:
            etype, elen = struct.unpack("!HH", b[i:i+4]); i += 4
            if etype == EXT_SNI:
                # server_name_list
                j = i + 2                # skip list length
                ntype = b[j]; j += 1
                nlen = struct.unpack("!H", b[j:j+2])[0]; j += 2
                if ntype == 0:
                    # SNI is carried as an ASCII A-label (IDNs are punycode)
                    return b[j:j+nlen].decode("ascii", "ignore")
            i += elen
    except Exception:
        return None
    return None


def parse_server_hello_version(sh_body: bytes) -> int:
    """Return negotiated TLS version. Honors supported_versions (real 1.3)."""
    legacy = struct.unpack("!H", sh_body[0:2])[0]
    try:
        b = sh_body
        i = 2 + 32
        sid_len = b[i]; i += 1 + sid_len
        i += 2            # cipher suite
        i += 1            # compression
        if i + 2 > len(b):
            return legacy
        ext_total = struct.unpack("!H", b[i:i+2])[0]; i += 2
        end = i + ext_total
        while i + 4 <= end:
            etype, elen = struct.unpack("!HH", b[i:i+4]); i += 4
            if etype == EXT_SUPPORTED_VERSIONS and elen >= 2:
                ver = struct.unpack("!H", b[i:i+2])[0]
                return ver
            i += elen
    except Exception:
        pass
    return legacy


def parse_certificate_msg(body: bytes) -> list[bytes]:
    """Parse a TLS<=1.2 Certificate handshake body into a list of DER blobs."""
    ders: list[bytes] = []
    if len(body) < 3:
        return ders
    total = int.from_bytes(body[0:3], "big")
    i = 3
    end = min(3 + total, len(body))
    while i + 3 <= end:
        clen = int.from_bytes(body[i:i+3], "big"); i += 3
        if clen <= 0 or i + clen > len(body):
            break
        ders.append(body[i:i+clen]); i += clen
    return ders


def hostport(addr: str, port: int) -> str:
    """Render address:port unambiguously.

    A bare IPv6 address joined to a port with a colon is not just ugly, it is
    ambiguous: "2001:db8::2:8443" is itself a valid IPv6 address
    (2001:db8:0:0:0:0:2:8443), so the result cannot be split back apart.
    RFC 3986 bracket form is the only correct rendering.
    """
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def ver_name(v: int) -> str:
    return {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
            0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(v, f"0x{v:04x}")


# ---------------------------------------------------------------------------
# Flow tracking / two-layer reassembly (TCP -> records -> handshake msgs)
# ---------------------------------------------------------------------------

@dataclass
class DirState:
    """One direction of one TCP connection."""
    tcp_buf: bytearray = field(default_factory=bytearray)   # raw payload
    hs_buf: bytearray = field(default_factory=bytearray)    # handshake stream
    done: bool = False           # stop parsing (appdata / cert seen / error)
    last: float = field(default_factory=time.time)


@dataclass
class ConnState:
    """Both directions keyed to a canonical connection id."""
    dirs: dict = field(default_factory=dict)   # 4-tuple -> DirState
    sni: Optional[str] = None
    version: Optional[int] = None
    reported: bool = False
    last: float = field(default_factory=time.time)


def conn_key(src, sport, dst, dport):
    """Canonical, direction-independent connection identifier."""
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


class FlowTracker:
    """Bounded, passive TLS handshake reassembler. Emits triage events."""

    def __init__(self, triage: CertTriage, emit, max_flows=MAX_FLOWS):
        self.triage = triage
        self.emit = emit                 # callback(dict)
        self.max_flows = max_flows
        self.conns: "collections.OrderedDict[tuple, ConnState]" = \
            collections.OrderedDict()
        self.stats = collections.Counter()

    # -- ingestion --
    def on_segment(self, src, sport, dst, dport, payload: bytes):
        if not payload:
            return
        ck = conn_key(src, sport, dst, dport)
        conn = self.conns.get(ck)
        if conn is None:
            if len(self.conns) >= self.max_flows:
                self.conns.popitem(last=False)     # LRU evict oldest
                self.stats["evicted_lru"] += 1
            conn = ConnState()
            self.conns[ck] = conn
        self.conns.move_to_end(ck)
        conn.last = time.time()

        dkey = (src, sport, dst, dport)
        d = conn.dirs.get(dkey)
        if d is None:
            d = DirState()
            conn.dirs[dkey] = d
        if d.done:
            return
        d.last = conn.last

        # bound the buffer (guards a hostile/garbage flow on 512 MB box)
        if len(d.tcp_buf) + len(payload) > MAX_FLOW_BYTES:
            payload = payload[:max(0, MAX_FLOW_BYTES - len(d.tcp_buf))]
            d.done = True
            self.stats["buf_capped"] += 1
        d.tcp_buf.extend(payload)

        try:
            self._drain_records(conn, ck, src, sport, dst, dport, d)
        except Exception as e:            # never crash on malformed input
            LOG.debug("parse error on %s: %s", dkey, e)
            d.done = True
            self.stats["parse_error"] += 1

    # -- record layer --
    def _drain_records(self, conn, ck, src, sport, dst, dport, d: DirState):
        buf = d.tcp_buf
        off = 0
        while len(buf) - off >= 5:
            ctype = buf[off]
            rlen = struct.unpack("!H", buf[off+3:off+5])[0]
            if len(buf) - off - 5 < rlen:
                break                     # incomplete record; wait for more
            body = bytes(buf[off+5:off+5+rlen])
            off += 5 + rlen
            if ctype == CT_HANDSHAKE:
                d.hs_buf.extend(body)
            elif ctype == CT_APPDATA:
                d.done = True             # handshake finished / encrypted now
                break
            elif ctype in (CT_ALERT, CT_CHANGE_CIPHER):
                continue
            else:
                d.done = True             # not TLS as we understand it
                break
        del buf[:off]
        self._drain_handshakes(conn, ck, src, sport, dst, dport, d)

    # -- handshake-message layer --
    def _drain_handshakes(self, conn, ck, src, sport, dst, dport, d: DirState):
        hb = d.hs_buf
        off = 0
        while len(hb) - off >= 4:
            htype = hb[off]
            hlen = int.from_bytes(hb[off+1:off+4], "big")
            if len(hb) - off - 4 < hlen:
                break                     # message spans more records; wait
            body = bytes(hb[off+4:off+4+hlen])
            off += 4 + hlen
            self._dispatch(conn, ck, src, sport, dst, dport, d, htype, body)
            if d.done:
                break
        del hb[:off]

    def _dispatch(self, conn, ck, src, sport, dst, dport, d, htype, body):
        if htype == HS_CLIENT_HELLO:
            sni = parse_sni(body)
            if sni:
                conn.sni = sni
                self.stats["client_hello"] += 1
        elif htype == HS_SERVER_HELLO:
            conn.version = parse_server_hello_version(body)
            self.stats["server_hello"] += 1
            if conn.version == TLS13:
                # cert is encrypted from here on; inventory-only, then evict
                self._report_tls13(conn, ck, src, sport, dst, dport)
                d.done = True
        elif htype == HS_CERTIFICATE:
            ders = parse_certificate_msg(body)
            self.stats["certificate_msg"] += 1
            self._report_cert(conn, ck, src, sport, dst, dport, ders)
            d.done = True                 # got what we came for; free the flow

    # -- reporting --
    def _report_cert(self, conn, ck, src, sport, dst, dport, ders):
        if not ders:
            return
        # server = the endpoint that sent the Certificate
        server, sport_ = src, sport
        try:
            res = self.triage.triage(ders[0], server_name=conn.sni)
        except Exception as e:
            LOG.debug("triage failed: %s", e)
            self.stats["triage_error"] += 1
            self._evict(ck)
            return
        res.update({
            "ts": _now().isoformat(),
            "module": MODULE,
            "server": hostport(server, sport_),
            "server_ip": server,
            "server_port": sport_,
            "tls_version": ver_name(conn.version) if conn.version else "<=1.2",
            "chain_len": len(ders),
            "type": "cert",
        })
        conn.reported = True
        self.emit(res)
        self.stats["reported_cert"] += 1
        self._evict(ck)

    def _report_tls13(self, conn, ck, src, sport, dst, dport):
        if conn.reported:
            return
        conn.reported = True
        self.emit({
            "ts": _now().isoformat(),
            "module": MODULE,
            "type": "inventory",
            "server": hostport(src, sport),
            "server_ip": src,
            "server_port": sport,
            "sni": conn.sni,
            "tls_version": "TLS1.3",
            "status": SEV_INFO,
            "note": "cert not observable (TLS 1.3 Certificate is encrypted)",
        })
        self.stats["reported_tls13"] += 1
        self._evict(ck)

    def _evict(self, ck):
        self.conns.pop(ck, None)

    # -- housekeeping --
    def sweep(self, now: Optional[float] = None):
        now = now or time.time()
        dead = [k for k, c in self.conns.items() if now - c.last > FLOW_TTL]
        for k in dead:
            self.conns.pop(k, None)
        if dead:
            self.stats["evicted_ttl"] += len(dead)


# ---------------------------------------------------------------------------
# Sniffer (scapy) — the only place we touch the wire, and only to read it
# ---------------------------------------------------------------------------

def build_bpf(ports, v6_eh: bool = True) -> str:
    """Build the capture filter.

    IPv6 extension headers are the trap here. libpcap cannot walk an IPv6
    next-header chain, so `tcp port 443` silently fails to match a TLS
    handshake carried behind a Hop-by-Hop, Destination Options or Fragment
    header -- and for HopByHop/DestOpt even a bare `tcp` fails, because the
    IPv6 next-header field reads 0/60, not 6. Measured, not assumed; see the
    README verifier's BPF tier.

    So IPv6 is captured wholesale (`ip6`) and the port decision is made in
    Python, where the header chain can actually be parsed. IPv4 keeps the
    cheap kernel-side port filter. --no-v6-eh reverts to the narrow filter
    for taps where IPv6 volume makes userspace filtering too expensive;
    that trades the blind spot back in, which is why it is not the default.
    """
    if ports == "any":
        return "tcp or ip6" if v6_eh else "tcp"
    v4 = " or ".join(f"tcp port {p}" for p in ports)
    if not v6_eh:
        return v4
    return f"(ip and ({v4})) or ip6"


class Sniffer:
    def __init__(self, tracker: FlowTracker, iface=None, ports=DEFAULT_PORTS,
                 v6_eh=True):
        self.tracker = tracker
        self.iface = iface
        self.ports = ports
        self.v6_eh = v6_eh
        self._stop = False
        self._last_sweep = time.time()

    def _handle(self, pkt):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        if TCP not in pkt:
            # Some readers hand back an undissected Raw frame; try once more.
            from scapy.layers.l2 import Ether
            try:
                pkt = Ether(bytes(pkt))
            except Exception:
                return
            if TCP not in pkt:
                return
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return
        # Port filter in userspace. IPv6 arrives unfiltered by design (see
        # build_bpf), so the port decision has to happen here or every v6
        # TCP flow on the tap would be tracked. ports is None in pcap mode,
        # where the operator chose the file and wants everything in it.
        if self.ports and self.ports != "any":
            if tcp.sport not in self.ports and tcp.dport not in self.ports:
                return
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        self.tracker.on_segment(src, tcp.sport, dst, tcp.dport, payload)
        now = time.time()
        if now - self._last_sweep > 5:
            self.tracker.sweep(now)
            self._last_sweep = now

    def run(self):
        from scapy.sendrecv import sniff
        bpf = build_bpf(self.ports, self.v6_eh)
        LOG.info("certwatch listening iface=%s filter=%r",
                 self.iface or "default", bpf)
        sniff(iface=self.iface, filter=bpf, prn=self._handle, store=False,
              stop_filter=lambda p: self._stop)

    def run_pcap(self, path):
        # Importing the layer modules registers DLT->class mappings
        # (conf.l2types); without this PcapReader falls back to Raw.
        from scapy.layers.l2 import Ether  # noqa: F401
        from scapy.layers.inet import IP, TCP  # noqa: F401
        from scapy.layers.inet6 import IPv6  # noqa: F401
        from scapy.utils import PcapReader
        # debug-level: batch mode reports its own progress to stderr and
        # would otherwise emit one INFO line per file across hundreds.
        LOG.debug("reading pcap %s", path)
        with PcapReader(path) as pr:
            for pkt in pr:
                self._handle(pkt)
        self.tracker.sweep(time.time() + FLOW_TTL + 1)

    def stop(self, *_):
        self._stop = True


# ---------------------------------------------------------------------------
# Batch mode: triage a directory of captures
# ---------------------------------------------------------------------------

import re

# Matches .pcap/.pcapng/.cap/.dmp, an optional .gz, AND an optional numeric
# rotation suffix -- tcpdump -C/-W writes capture.pcap0, capture.pcap1, ...
# with the number AFTER the extension, so a plain endswith('.pcap') silently
# skips every file in a rotation set. Longest alternative first so .pcapng
# isn't shadowed by .pcap.
CAPTURE_RE = re.compile(r"\.(pcapng|pcap|cap|dmp)(\d+)?(\.gz)?$", re.I)


def is_capture(fn: str) -> bool:
    return CAPTURE_RE.search(fn) is not None


def _natkey(s: str):
    """Natural sort key: file.pcap2 sorts before file.pcap10.

    tcpdump -C/-W rotation produces exactly that numbering, and plain
    lexicographic order would interleave a rotation set wrongly.
    """
    import re
    return [int(t) if t.isdigit() else t.lower()
            for t in re.split(r"(\d+)", s)]


def iter_capture_files(root: str, recursive: bool = False):
    """Return capture files under root, in natural (rotation) order."""
    hits = []
    if recursive:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if is_capture(fn):
                    hits.append(os.path.join(dirpath, fn))
    else:
        try:
            entries = os.listdir(root)
        except OSError as e:
            raise SystemExit(f"certwatch: cannot read {root}: {e}")
        for fn in entries:
            p = os.path.join(root, fn)
            if os.path.isfile(p) and is_capture(fn):
                hits.append(p)
    hits.sort(key=_natkey)
    return hits


class Dedupe:
    """Collapse repeat sightings of the same cert across many captures.

    Keyed on (server, serial): the same expired cert seen in 40 rotated
    captures is one problem, not 40. Sightings are counted and the source
    files recorded (capped), then flushed once at end of run.
    """

    MAX_FILES_TRACKED = 10

    def __init__(self, downstream):
        self.downstream = downstream
        self.seen: "collections.OrderedDict[tuple, dict]" = \
            collections.OrderedDict()
        self.passthrough = []          # records with no dedupe key

    def __call__(self, rec: dict):
        key = (rec.get("server"), rec.get("serial"))
        if key[1] is None:             # inventory/summary: nothing to dedupe
            self.passthrough.append(rec)
            return
        cur = self.seen.get(key)
        if cur is None:
            rec["seen_count"] = 1
            rec["seen_in"] = [rec["pcap"]] if rec.get("pcap") else []
            self.seen[key] = rec
            return
        cur["seen_count"] += 1
        f = rec.get("pcap")
        if f and f not in cur["seen_in"]:
            if len(cur["seen_in"]) < self.MAX_FILES_TRACKED:
                cur["seen_in"].append(f)
            else:
                cur["seen_truncated"] = True

    def flush(self):
        for rec in self.seen.values():
            self.downstream(rec)
        for rec in self.passthrough:
            self.downstream(rec)
        n = len(self.seen)
        self.seen.clear()
        self.passthrough.clear()
        return n


class BatchRunner:
    """Run certwatch across a directory of captures.

    State handling: by default each file gets a fresh FlowTracker. Carrying
    flow state across unrelated captures would let a 4-tuple in file A merge
    with a colliding 4-tuple in file B and fabricate a bogus record -- false
    data is worse than a false negative. --carry-state opts in for genuine
    rotation sets, where a handshake can legitimately straddle a boundary.
    """

    def __init__(self, args, triage, emit, quiet=False):
        self.args = args
        self.triage = triage
        self.emit = emit
        self.quiet = quiet
        self.stats = collections.Counter()
        self.by_status = collections.Counter()
        self.by_code = collections.Counter()

    def _wrap(self, path):
        """Inject provenance, then tally."""
        base = os.path.basename(path)

        def sink(rec):
            rec["pcap"] = base
            self.stats["records"] += 1
            self.by_status[rec.get("status", "?")] += 1
            for f in rec.get("findings", []):
                self.by_code[f["code"]] += 1
            self.emit(rec)
        return sink

    def run(self, root):
        files = iter_capture_files(root, self.args.recursive)
        if not files:
            print(f"certwatch: no captures found under {root}",
                  file=sys.stderr)
            return 1
        total = len(files)
        shared = None
        if self.args.carry_state:
            shared = FlowTracker(self.triage, emit=lambda r: None)

        t0 = time.time()
        for n, path in enumerate(files, 1):
            sink = self._wrap(path)
            if shared is not None:
                shared.emit = sink
                tracker = shared
            else:
                tracker = FlowTracker(self.triage, emit=sink)
            sniffer = Sniffer(tracker, ports=None)
            try:
                sniffer.run_pcap(path)
                self.stats["files_ok"] += 1
            except KeyboardInterrupt:
                raise
            except Exception as e:
                # One bad capture must not abort a 500-file run.
                self.stats["files_failed"] += 1
                print(f"certwatch: SKIP {os.path.basename(path)}: {e}",
                      file=sys.stderr)
                continue
            finally:
                if not self.quiet and (n % 25 == 0 or n == total):
                    print(f"certwatch: {n}/{total} captures, "
                          f"{self.stats['records']} records",
                          file=sys.stderr)
        self.stats["elapsed"] = round(time.time() - t0, 1)
        return 0

    def summary_record(self, unique=None) -> dict:
        return {
            "ts": _now().isoformat(),
            "module": MODULE,
            "type": "batch_summary",
            "status": SEV_INFO,
            "files_ok": self.stats["files_ok"],
            "files_failed": self.stats["files_failed"],
            "records": self.stats["records"],
            "unique_certs": unique,
            "by_status": dict(self.by_status),
            "by_code": dict(self.by_code.most_common()),
            "elapsed_sec": self.stats["elapsed"],
        }

    def print_summary(self, unique=None):
        s = self.stats
        print("-" * 60, file=sys.stderr)
        print(f"certwatch batch: {s['files_ok']} captures ok, "
              f"{s['files_failed']} failed, {s['records']} records"
              + (f", {unique} unique certs" if unique is not None else "")
              + f", {s['elapsed']}s", file=sys.stderr)
        if self.by_status:
            print("  status: " + "  ".join(
                f"{k}={v}" for k, v in sorted(
                    self.by_status.items(),
                    key=lambda kv: -_SEV_RANK.get(kv[0], 0))),
                file=sys.stderr)
        if self.by_code:
            print("  codes:  " + "  ".join(
                f"{k}={v}" for k, v in self.by_code.most_common(8)),
                file=sys.stderr)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def make_emitter(json_mode: bool, min_status: str = SEV_OK):
    floor = _SEV_RANK[min_status]

    def emit(rec: dict):
        if _SEV_RANK.get(rec.get("status", SEV_OK), 0) < floor:
            return
        if json_mode:
            print(json.dumps(rec, separators=(",", ":")), flush=True)
            return
        if rec.get("type") == "batch_summary":
            return                      # human summary goes to stderr

        if rec.get("type") == "inventory":
            print(f"[{rec['status']:>4}] {rec['server']:<22} "
                  f"{rec['tls_version']}  sni={rec.get('sni')}  "
                  f"({rec['note']})", flush=True)
            return
        codes = ",".join(f["code"] for f in rec.get("findings", [])) or "clean"
        prov = ""
        if rec.get("pcap"):
            prov = f" [{rec['pcap']}"
            if rec.get("seen_count", 1) > 1:
                prov += f" +{rec['seen_count'] - 1} more"
            prov += "]"
        print(f"[{rec['status']:>8}] {rec['server']:<22} "
              f"{rec['tls_version']:<7} {rec['subject']!r} "
              f"exp={rec['not_after'][:10]} sig={rec['sig_hash']} "
              f"key={rec['key']} -> {codes}{prov}", flush=True)
        for f in rec.get("findings", []):
            if f["severity"] in (SEV_CRIT, SEV_WARN):
                print(f"           - {f['severity']}: {f['code']}: "
                      f"{f['detail']}", flush=True)
    return emit


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Passive TLS certificate triage scanner (Ragnar).")
    src = p.add_mutually_exclusive_group()
    src.add_argument("-i", "--iface", help="capture interface (tap/SPAN/bridge)")
    src.add_argument("-r", "--pcap", help="read from a single pcap")
    src.add_argument("--pcap-dir", metavar="DIR",
                     help="batch-triage every capture in DIR "
                          "(.pcap/.pcapng/.cap, incl. .gz)")
    p.add_argument("--recursive", action="store_true",
                   help="with --pcap-dir: descend into subdirectories")
    p.add_argument("--dedupe", action="store_true",
                   help="with --pcap-dir: collapse repeat sightings of the "
                        "same cert (by server+serial) into one record")
    p.add_argument("--carry-state", action="store_true",
                   help="with --pcap-dir: keep flow state across files. Use "
                        "ONLY for a rotation set of one capture; on unrelated "
                        "captures colliding 4-tuples can fabricate records.")
    p.add_argument("--no-v6-eh", action="store_true",
                   help="narrow the BPF to a kernel-side port filter only. "
                        "Cheaper, but blind to IPv6 TLS behind extension "
                        "headers (libpcap cannot walk the chain).")
    p.add_argument("--ports", default=None,
                   help="comma list of TCP ports, or 'any' (default: common TLS)")
    p.add_argument("--warn-days", type=int, default=WARN_DAYS_DEFAULT,
                   help=f"expiring-soon horizon (default {WARN_DAYS_DEFAULT})")
    p.add_argument("--min-status", choices=[SEV_OK, SEV_INFO, SEV_WARN,
                                            SEV_CRIT], default=SEV_OK,
                   help="only report at or above this severity (default OK)")
    p.add_argument("--json", action="store_true", help="JSON lines output")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress batch progress on stderr")
    p.add_argument("--selftest", action="store_true",
                   help="run built-in self-test harness and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s certwatch %(levelname)s %(message)s")

    if args.selftest:
        import certwatch_selftest
        return certwatch_selftest.run()

    if args.ports in (None, ""):
        ports = DEFAULT_PORTS
    elif args.ports == "any":
        ports = "any"
    else:
        ports = tuple(int(x) for x in args.ports.split(","))

    triage = CertTriage(warn_days=args.warn_days)
    emit = make_emitter(args.json, args.min_status)

    # ---- batch: a directory of captures ----
    if args.pcap_dir:
        dedupe = Dedupe(emit) if args.dedupe else None
        runner = BatchRunner(args, triage, dedupe or emit, quiet=args.quiet)
        try:
            rc = runner.run(args.pcap_dir)
        except KeyboardInterrupt:
            print("certwatch: interrupted", file=sys.stderr)
            rc = 130
        unique = dedupe.flush() if dedupe else None
        if args.json:
            emit(runner.summary_record(unique))
        if not args.quiet:
            runner.print_summary(unique)
        return rc

    # ---- single capture / live wire ----
    tracker = FlowTracker(triage, emit=emit)
    sniffer = Sniffer(tracker, iface=args.iface, ports=ports,
                      v6_eh=not args.no_v6_eh)

    signal.signal(signal.SIGTERM, sniffer.stop)
    signal.signal(signal.SIGINT, sniffer.stop)

    try:
        if args.pcap:
            sniffer.run_pcap(args.pcap)
        else:
            sniffer.run()
    finally:
        LOG.info("stats: %s", dict(tracker.stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------
# PLATFORM NOTES (Pi Zero 2W test floor)
# ---------------------------------------------------------------------------
# * TLS 1.3: Certificate message is encrypted. Passive extraction is TLS<=1.2
#   only. 1.3 flows produce an inventory record (SNI/version), never a cert.
#   This is fundamental, not a limitation of the parser.
# * Capture drops: scapy's Python receive path is the bottleneck, not the
#   A53 cores. On a busy SPAN keep --ports tight (default is), or mirror only
#   the VLAN/subnet of interest. For line-rate taps move to a Pi 5 or add an
#   AF_PACKET/eBPF prefilter; certwatch's parser is happy either way.
# * Memory: flow state is bounded (MAX_FLOWS x MAX_FLOW_BYTES ~= 32 MB worst
#   case) with LRU + TTL eviction, safe on the 512 MB Zero 2W.
# * Direction: certwatch keys flows canonically and matches observed SNI
#   (client->server) to the observed Certificate (server->client) within one
#   connection, so NAME_MISMATCH works without knowing which side is "server"
#   a priori.
