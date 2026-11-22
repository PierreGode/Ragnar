"""
ike_detectors.py — the 9 ipsecwatch findings.

Core (stateless, per-message):
  D1 SWEET32               — 3DES / Blowfish offered (64-bit block cipher)
  D2 DHEater               — weak DH group offered (MODP-768 / MODP-1024)
  D3 Weak DH groups        — legacy/small groups below current guidance
  D4 IKEv1 Aggressive Mode — exchange type == 4 (identity + PSK-hash exposure)
  D5 Weak hash + PSK       — MD5/SHA1 hash (v1) or PRF (v2) with PSK auth
  D6 Legacy cipher         — DES / 3DES offered

Enhancements:
  E1 DHEater downgrade correlation (STATEFUL) — initiator offered strong DH,
     responder selected weak DH on the same SPI pair
  E2 Aggressive-mode PSK-hash extraction      — pull HASH payload from v1 msg 2
  E3 ML-KEM post-quantum downgrade (GATED)    — ML-KEM offered but no PQ
     transcript-auth signalling present

Every detector is address-family-agnostic: it reads only IKE protocol structure
from the parsed IKEMessage. src/dst/family are copied into the Finding for
reporting, never branched on. This is what makes v4/v6 parity structural, not
best-effort.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple
import json

from ike_constants import (
    IKEV1_EXCH_AGGRESSIVE, IKEV1_EXCH_NAMES, IKEV2_EXCH_NAMES,
    IKEV1_ENCR, IKEV1_ENCR_SWEET32, IKEV1_ENCR_LEGACY,
    IKEV1_HASH, IKEV1_HASH_WEAK, IKEV1_AUTH, IKEV1_AUTH_PSK_METHODS,
    IKEV2_ENCR, IKEV2_ENCR_SWEET32, IKEV2_ENCR_LEGACY,
    IKEV2_PRF, IKEV2_PRF_WEAK,
    IKEV2_TRANSFORM_TYPE_ENCR, IKEV2_TRANSFORM_TYPE_PRF, IKEV2_TRANSFORM_TYPE_DH,
    DH_GROUPS, DH_GROUPS_DHEATER, DH_GROUPS_WEAK, DH_GROUPS_STRONG, DH_GROUPS_ML_KEM,
    IKEV2_EXCH_IKE_SA_INIT,
)


@dataclass
class Finding:
    code: str
    severity: str                 # "high" | "medium" | "low"
    finding_type: str             # "detector" | "enhancement"
    ike_version: int              # 1 | 2
    exchange: str
    detail: str
    algorithm: str = ""
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    family: str = ""
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers to pull algorithm lists out of a parsed message, v1/v2 agnostic
# ─────────────────────────────────────────────────────────────────────────────
def _v2_ids(msg, ttype):
    out = []
    for prop in msg.proposals:
        for tf in prop.transforms:
            if tf.transform_type == ttype and tf.transform_id is not None:
                out.append(tf.transform_id)
    return out


def _v1_transforms(msg):
    for prop in msg.proposals:
        for tf in prop.transforms:
            yield tf


def _exch_name(msg):
    if msg.version == 1:
        return IKEV1_EXCH_NAMES.get(msg.exchange_type, f"v1-exch-{msg.exchange_type}")
    return IKEV2_EXCH_NAMES.get(msg.exchange_type, f"v2-exch-{msg.exchange_type}")


def _base(msg, **kw):
    """Fill the transport/context fields common to every finding."""
    return dict(
        ike_version=msg.version, exchange=_exch_name(msg),
        src=msg.src, dst=msg.dst, sport=msg.sport, dport=msg.dport,
        family=msg.family, **kw,
    )


# ─────────────────────────────────────────────────────────────────────────────
# D1 — SWEET32
# ─────────────────────────────────────────────────────────────────────────────
def detect_sweet32(msg) -> List[Finding]:
    out = []
    if msg.version == 1:
        for tf in _v1_transforms(msg):
            if tf.v1_encryption in IKEV1_ENCR_SWEET32:
                out.append(Finding(
                    code="SWEET32-VULNERABLE-CIPHER-PROPOSAL", severity="high",
                    finding_type="detector",
                    algorithm=IKEV1_ENCR.get(tf.v1_encryption, str(tf.v1_encryption)),
                    detail="64-bit block cipher offered in IKEv1 Phase-1 proposal",
                    **_base(msg)))
    else:
        for eid in _v2_ids(msg, IKEV2_TRANSFORM_TYPE_ENCR):
            if eid in IKEV2_ENCR_SWEET32:
                out.append(Finding(
                    code="SWEET32-VULNERABLE-CIPHER-PROPOSAL", severity="high",
                    finding_type="detector",
                    algorithm=IKEV2_ENCR.get(eid, str(eid)),
                    detail="64-bit block cipher offered in IKEv2 SA proposal",
                    **_base(msg)))
    return _dedup(out)


# ─────────────────────────────────────────────────────────────────────────────
# D2 — DHEater (weak DH group offered)
# ─────────────────────────────────────────────────────────────────────────────
def detect_dheater(msg) -> List[Finding]:
    out = []
    groups = _collect_dh_groups(msg)
    for g in groups:
        if g in DH_GROUPS_DHEATER:
            out.append(Finding(
                code="DHEATER-WEAK-DH-GROUP-OFFERED", severity="high",
                finding_type="detector",
                algorithm=DH_GROUPS.get(g, f"group-{g}"),
                detail="Small MODP group offered; susceptible to DoS/downgrade (DHEater)",
                extra={"dh_group_id": g}, **_base(msg)))
    return _dedup(out)


# ─────────────────────────────────────────────────────────────────────────────
# D3 — Weak DH groups (broader than DHEater's two)
# ─────────────────────────────────────────────────────────────────────────────
def detect_weak_dh(msg) -> List[Finding]:
    out = []
    for g in _collect_dh_groups(msg):
        if g in DH_GROUPS_WEAK:
            out.append(Finding(
                code="WEAK-DH-GROUP-OFFERED", severity="high",
                finding_type="detector",
                algorithm=DH_GROUPS.get(g, f"group-{g}"),
                detail="DH group below current strength guidance (recommend >=2048-bit MODP or ECP-256+)",
                extra={"dh_group_id": g}, **_base(msg)))
    return _dedup(out)


# ─────────────────────────────────────────────────────────────────────────────
# D4 — IKEv1 Aggressive Mode  (exchange type == 4, NOT a flag bit)
# ─────────────────────────────────────────────────────────────────────────────
def detect_aggressive_mode(msg) -> List[Finding]:
    if msg.version == 1 and msg.exchange_type == IKEV1_EXCH_AGGRESSIVE:
        return [Finding(
            code="IKEV1-AGGRESSIVE-MODE-DETECTED", severity="medium",
            finding_type="detector", algorithm="",
            detail="IKEv1 Aggressive Mode in use; identity and PSK hash exposed pre-auth",
            **_base(msg))]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# D5 — Weak hash / PRF with PSK authentication
# ─────────────────────────────────────────────────────────────────────────────
def detect_weak_hash_psk(msg) -> List[Finding]:
    out = []
    if msg.version == 1:
        for tf in _v1_transforms(msg):
            hash_weak = tf.v1_hash in IKEV1_HASH_WEAK
            is_psk = tf.v1_auth_method in IKEV1_AUTH_PSK_METHODS
            if hash_weak and is_psk:
                out.append(Finding(
                    code="WEAK-HASH-PSK-AUTHENTICATION", severity="medium",
                    finding_type="detector",
                    algorithm=IKEV1_HASH.get(tf.v1_hash, str(tf.v1_hash)),
                    detail="Weak hash with PSK auth; offline PSK cracking feasible",
                    extra={"auth_method": IKEV1_AUTH.get(tf.v1_auth_method, str(tf.v1_auth_method))},
                    **_base(msg)))
    else:
        # IKEv2 has no in-band auth-method transform; PRF weakness is the signal.
        for pid in _v2_ids(msg, IKEV2_TRANSFORM_TYPE_PRF):
            if pid in IKEV2_PRF_WEAK:
                out.append(Finding(
                    code="WEAK-PRF-IKEV2", severity="medium",
                    finding_type="detector",
                    algorithm=IKEV2_PRF.get(pid, str(pid)),
                    detail="Weak PRF offered in IKEv2 (MD5/SHA1)",
                    **_base(msg)))
    return _dedup(out)


# ─────────────────────────────────────────────────────────────────────────────
# D6 — Legacy cipher (DES / 3DES)
# ─────────────────────────────────────────────────────────────────────────────
def detect_legacy_cipher(msg) -> List[Finding]:
    out = []
    if msg.version == 1:
        for tf in _v1_transforms(msg):
            if tf.v1_encryption in IKEV1_ENCR_LEGACY:
                out.append(Finding(
                    code="LEGACY-CIPHER-PROPOSAL", severity="medium",
                    finding_type="detector",
                    algorithm=IKEV1_ENCR.get(tf.v1_encryption, str(tf.v1_encryption)),
                    detail="Deprecated cipher offered; migrate to AES-128+",
                    **_base(msg)))
    else:
        for eid in _v2_ids(msg, IKEV2_TRANSFORM_TYPE_ENCR):
            if eid in IKEV2_ENCR_LEGACY:
                out.append(Finding(
                    code="LEGACY-CIPHER-PROPOSAL", severity="medium",
                    finding_type="detector",
                    algorithm=IKEV2_ENCR.get(eid, str(eid)),
                    detail="Deprecated cipher offered; migrate to AES-128+",
                    **_base(msg)))
    return _dedup(out)


# ─────────────────────────────────────────────────────────────────────────────
# E2 — Aggressive-mode PSK hash extraction
# ─────────────────────────────────────────────────────────────────────────────
def extract_aggressive_psk_hash(msg) -> List[Finding]:
    """When an Aggressive-Mode message carries a HASH payload, surface it in a
    form an operator can hand to hashcat. Passive: the bytes are already in the
    clear on the wire; we only re-present them."""
    if msg.version == 1 and msg.exchange_type == IKEV1_EXCH_AGGRESSIVE and msg.v1_hash_payload:
        h = msg.v1_hash_payload
        return [Finding(
            code="IKEV1-AGGRESSIVE-MODE-PSK-HASH-EXTRACTED", severity="medium",
            finding_type="enhancement", algorithm="",
            detail="PSK hash recovered from Aggressive-Mode HASH payload (offline crack feasible)",
            extra={"hash_hex": h.hex(), "hash_len": len(h)},
            **_base(msg))]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# E3 — ML-KEM post-quantum downgrade (GATED behind TWO confirmed IANA registrations)
#
# This detector depends on two INDEPENDENT IANA assignments from two drafts:
#   (A) ML-KEM Key Exchange Method transform IDs — Transform Type 4 KE registry
#       (draft-ietf-ipsecme-ikev2-mlkem). Used to recognize a PQ offer.
#   (B) The downgrade-prevention Notify status type — IKEv2 Notify Message
#       Status Types registry (draft-ietf-ipsecme-ikev2-downgrade-prevention).
#       Its PRESENCE is what marks a PQ offer as protected.
# Neither is assigned as of this build, so E3 is gated off and fires only when
# the operator supplies real, confirmed numbers for BOTH.
#
# Scope limit (conscious, not silent): inspects IKE_SA_INIT only. RFC 9370's
# multi-KE framework also allows ML-KEM via IKE_FOLLOWUP_KE; that path is out of
# v0.1 scope.
# ─────────────────────────────────────────────────────────────────────────────
def detect_ml_kem_downgrade(msg, enabled=False, downgrade_prevention_notify=None) -> List[Finding]:
    """GATED. `enabled` must be explicitly True AND the module must have been
    given the real, confirmed numbers (see IPSecWatch below), or this never
    fires. This prevents false positives on the provisional sentinels.

    Signal: an IKE_SA_INIT that offers an ML-KEM KE method but carries no
    downgrade-prevention Notify => an on-path attacker can strip the PQ method
    and force classical (EC)DH.

    downgrade_prevention_notify is the code point from registry (B). If it is
    None we cannot tell protected from unprotected, so we do NOT fire (absence
    of a known protection signal is not evidence of vulnerability).
    """
    if not enabled or msg.version != 2:
        return []
    if msg.exchange_type != IKEV2_EXCH_IKE_SA_INIT:
        return []
    offered = set(_collect_dh_groups(msg))
    ml_kem_offered = offered & DH_GROUPS_ML_KEM
    if not ml_kem_offered:
        return []
    # (B) must be a known code point to make a protected/unprotected judgment.
    if downgrade_prevention_notify is None:
        return []
    if downgrade_prevention_notify in msg.v2_notify_types:
        return []  # protected — downgrade-prevention signalled
    return [Finding(
        code="ML-KEM-DOWNGRADE-VULNERABLE", severity="high",
        finding_type="enhancement",
        algorithm=",".join(_ke_name(g) for g in sorted(ml_kem_offered)),
        detail="ML-KEM KE offered without downgrade-prevention Notify; "
               "on-path strip to classical (EC)DH possible",
        extra={"ml_kem_ke_ids": sorted(ml_kem_offered)}, **_base(msg))]


def _ke_name(g):
    """Render a Key Exchange Method id: classical group name, else ML-KEM name."""
    from ike_constants import ML_KEM_KE_NAMES
    if g in DH_GROUPS:
        return DH_GROUPS[g]
    if g in ML_KEM_KE_NAMES:
        return ML_KEM_KE_NAMES[g]
    return f"ke-{g}"


# ─────────────────────────────────────────────────────────────────────────────
# E1 — Stateful DHEater downgrade correlation
# ─────────────────────────────────────────────────────────────────────────────
class DowngradeCorrelator:
    """Tracks DH groups offered by the initiator vs. selected by the responder,
    keyed by the SPI pair. Fires when a strong offer is answered by a weak pick.

    Passive and address-family-agnostic: keyed on IKE SPIs, not IP addresses,
    so it correlates identically over IPv4 and IPv6 (and survives NAT rewrites).
    """
    def __init__(self):
        # key: initiator_spi hex -> set of strong groups the initiator offered
        self._initiator_offered: Dict[str, set] = {}

    def observe(self, msg) -> List[Finding]:
        if msg.version != 2 or msg.exchange_type != IKEV2_EXCH_IKE_SA_INIT:
            return []
        key = msg.initiator_spi.hex()
        groups = set(_collect_dh_groups(msg))

        # Request from the initiator (response flag clear): record strong offers.
        if not msg.is_response:
            strong = groups & DH_GROUPS_STRONG
            if strong:
                self._initiator_offered[key] = strong
            return []

        # Response from the responder: did it pick a weak group after strong offer?
        offered_strong = self._initiator_offered.get(key)
        if not offered_strong:
            return []
        selected_weak = groups & DH_GROUPS_WEAK
        if selected_weak:
            # clear state; one finding per SPI pair
            self._initiator_offered.pop(key, None)
            return [Finding(
                code="DHEATER-DOWNGRADE-DETECTED", severity="high",
                finding_type="enhancement",
                algorithm=",".join(DH_GROUPS.get(g, str(g)) for g in sorted(selected_weak)),
                detail="Responder selected a weak DH group after initiator offered a strong one",
                extra={
                    "offered_strong": sorted(offered_strong),
                    "selected_weak": sorted(selected_weak),
                }, **_base(msg))]
        return []


# ─────────────────────────────────────────────────────────────────────────────
# shared helpers
# ─────────────────────────────────────────────────────────────────────────────
def _collect_dh_groups(msg):
    groups = []
    if msg.version == 1:
        for tf in _v1_transforms(msg):
            if tf.v1_dh_group is not None:
                groups.append(tf.v1_dh_group)
    else:
        groups.extend(_v2_ids(msg, IKEV2_TRANSFORM_TYPE_DH))
    return groups


def _dedup(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        k = (f.code, f.algorithm, f.extra.get("dh_group_id"))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────
CORE_DETECTORS = [
    detect_sweet32, detect_dheater, detect_weak_dh,
    detect_aggressive_mode, detect_weak_hash_psk, detect_legacy_cipher,
]


class IPSecWatch:
    def __init__(self, enable_dheater_correlation=True,
                 enable_aggressive_hash_extraction=True,
                 enable_ml_kem_detection=False,
                 ml_kem_downgrade_prevention_notify=None):
        self.enable_e1 = enable_dheater_correlation
        self.enable_e2 = enable_aggressive_hash_extraction
        # E3 requires BOTH registrations confirmed: the ML-KEM KE IDs
        # (ML_KEM_KE_IDS_CONFIRMED, registry A) AND a real downgrade-prevention
        # notify code point (registry B, passed in). Enabling the flag alone is
        # not enough — if either is unconfirmed, E3 stays inert regardless.
        from ike_constants import ML_KEM_KE_IDS_CONFIRMED
        self.dp_notify = ml_kem_downgrade_prevention_notify
        self.enable_e3 = bool(
            enable_ml_kem_detection
            and ML_KEM_KE_IDS_CONFIRMED
            and self.dp_notify is not None
        )
        self._e3_requested = enable_ml_kem_detection
        self._e3_blockers = []
        if enable_ml_kem_detection and not self.enable_e3:
            if not ML_KEM_KE_IDS_CONFIRMED:
                self._e3_blockers.append("ML-KEM KE transform IDs not yet IANA-assigned (registry A)")
            if self.dp_notify is None:
                self._e3_blockers.append("downgrade-prevention notify code point not supplied (registry B)")
        self.correlator = DowngradeCorrelator()

    def e3_status(self):
        """Human-readable E3 gate status, for CLI/diagnostics."""
        if self.enable_e3:
            return "E3 active"
        if not self._e3_requested:
            return "E3 off (not requested)"
        return "E3 requested but gated: " + "; ".join(self._e3_blockers)

    def analyze(self, msg) -> List[Finding]:
        findings: List[Finding] = []
        for det in CORE_DETECTORS:
            findings.extend(det(msg))
        if self.enable_e2:
            findings.extend(extract_aggressive_psk_hash(msg))
        if self.enable_e3:
            findings.extend(detect_ml_kem_downgrade(
                msg, enabled=True, downgrade_prevention_notify=self.dp_notify))
        if self.enable_e1:
            findings.extend(self.correlator.observe(msg))
        return findings
