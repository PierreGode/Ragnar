"""
ike_constants.py — RFC-verified IKE protocol registries.

Sources:
  - RFC 2408 (ISAKMP), RFC 2409 (IKEv1), RFC 7296 (IKEv2)
  - IANA "Internet Key Exchange Version 2 (IKEv2) Parameters"
  - IANA "Internet Security Association and Key Management Protocol (ISAKMP) IDs"

Wire-format truths that bite parsers (verified against RFCs, not memory):
  * IKEv1 Aggressive Mode is the EXCHANGE TYPE field (offset 18, value 4),
    NOT a flag bit. The Flags byte holds E/C/A bits only.
  * IKEv1 and IKEv2 share the first 16 bytes (two 8-byte cookies / SPIs) but
    diverge afterward; version byte (offset 17) high nibble = major version.
  * IKEv2 transforms chain via the "Last Substruc" byte: 0=last, 2=more(proposal),
    3=more(transform). Do not trust it blindly — always bound by declared length.
  * All multi-byte integers are network byte order (big-endian).
"""

# ─────────────────────────────────────────────────────────────────────────────
# IKE version (from the version byte, offset 17; high nibble is major version)
# ─────────────────────────────────────────────────────────────────────────────
IKE_VERSION_1 = 1
IKE_VERSION_2 = 2

# ─────────────────────────────────────────────────────────────────────────────
# IKEv1 / ISAKMP Exchange Types (RFC 2408 §3.1) — the byte at offset 18
# ─────────────────────────────────────────────────────────────────────────────
IKEV1_EXCH_NONE = 0
IKEV1_EXCH_BASE = 1
IKEV1_EXCH_IDENTITY_PROTECTION = 2      # a.k.a. Main Mode
IKEV1_EXCH_AUTHENTICATION_ONLY = 3
IKEV1_EXCH_AGGRESSIVE = 4              # <-- Aggressive Mode. THIS is the signal.
IKEV1_EXCH_INFORMATIONAL = 5
IKEV1_EXCH_QUICK_MODE = 32            # Phase 2 (RFC 2409 §5.5)
IKEV1_EXCH_NEW_GROUP_MODE = 33

IKEV1_EXCH_NAMES = {
    0: "NONE", 1: "Base", 2: "MainMode", 3: "AuthOnly",
    4: "AggressiveMode", 5: "Informational", 32: "QuickMode", 33: "NewGroup",
}

# IKEv1 Flags byte (RFC 2408 §3.1) — bit positions. NOTE: no "aggressive" bit here.
IKEV1_FLAG_ENCRYPTION = 0x01
IKEV1_FLAG_COMMIT = 0x02
IKEV1_FLAG_AUTH_ONLY = 0x04

# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 Exchange Types (RFC 7296 §3.1) — the byte at offset 18
# ─────────────────────────────────────────────────────────────────────────────
IKEV2_EXCH_IKE_SA_INIT = 34
IKEV2_EXCH_IKE_AUTH = 35
IKEV2_EXCH_CREATE_CHILD_SA = 36
IKEV2_EXCH_INFORMATIONAL = 37

IKEV2_EXCH_NAMES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH",
    36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}

# IKEv2 Flags byte (RFC 7296 §3.1)
IKEV2_FLAG_INITIATOR = 0x08
IKEV2_FLAG_VERSION = 0x10
IKEV2_FLAG_RESPONSE = 0x20

# ─────────────────────────────────────────────────────────────────────────────
# Generic / IKEv1 Payload Types (RFC 2408 §3.2, shared numbering w/ IKEv2 range)
# ─────────────────────────────────────────────────────────────────────────────
IKEV1_PAYLOAD_NONE = 0
IKEV1_PAYLOAD_SA = 1
IKEV1_PAYLOAD_PROPOSAL = 2
IKEV1_PAYLOAD_TRANSFORM = 3
IKEV1_PAYLOAD_KE = 4
IKEV1_PAYLOAD_ID = 5
IKEV1_PAYLOAD_CERT = 6
IKEV1_PAYLOAD_CERTREQ = 7
IKEV1_PAYLOAD_HASH = 8          # <-- Aggressive Mode PSK hash lives here (E2)
IKEV1_PAYLOAD_SIG = 9
IKEV1_PAYLOAD_NONCE = 10
IKEV1_PAYLOAD_NOTIFY = 11
IKEV1_PAYLOAD_DELETE = 12
IKEV1_PAYLOAD_VENDOR_ID = 13

# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 Payload Types (RFC 7296 §3.2) — start at 33
# ─────────────────────────────────────────────────────────────────────────────
IKEV2_PAYLOAD_NONE = 0
IKEV2_PAYLOAD_SA = 33
IKEV2_PAYLOAD_KE = 34
IKEV2_PAYLOAD_IDI = 35
IKEV2_PAYLOAD_IDR = 36
IKEV2_PAYLOAD_CERT = 37
IKEV2_PAYLOAD_CERTREQ = 38
IKEV2_PAYLOAD_AUTH = 39
IKEV2_PAYLOAD_NONCE = 40
IKEV2_PAYLOAD_NOTIFY = 41
IKEV2_PAYLOAD_DELETE = 42
IKEV2_PAYLOAD_VENDOR_ID = 43
IKEV2_PAYLOAD_SK = 46           # Encrypted & authenticated

# ─────────────────────────────────────────────────────────────────────────────
# IKEv1 Phase-1 Transform Attribute Types (RFC 2409 Appendix A)
# TV/TLV "Data Attributes" (RFC 2408 §3.3). High bit of type = AF (1 => TV).
# ─────────────────────────────────────────────────────────────────────────────
IKEV1_ATTR_ENCRYPTION_ALGORITHM = 1
IKEV1_ATTR_HASH_ALGORITHM = 2
IKEV1_ATTR_AUTHENTICATION_METHOD = 3
IKEV1_ATTR_GROUP_DESCRIPTION = 4      # DH group
IKEV1_ATTR_GROUP_TYPE = 5
IKEV1_ATTR_LIFE_TYPE = 11
IKEV1_ATTR_LIFE_DURATION = 12

# IKEv1 Encryption Algorithm values (RFC 2409 Appendix A)
IKEV1_ENCR = {
    1: "DES-CBC", 2: "IDEA-CBC", 3: "Blowfish-CBC", 4: "RC5-R16-B64-CBC",
    5: "3DES-CBC", 6: "CAST-CBC", 7: "AES-CBC",
}
# Weak-cipher classification for detectors
IKEV1_ENCR_SWEET32 = {3, 5}          # Blowfish, 3DES  (64-bit block => SWEET32)
IKEV1_ENCR_LEGACY = {1, 5}           # DES, 3DES       (deprecated / legacy)

# IKEv1 Hash Algorithm values (RFC 2409 Appendix A)
IKEV1_HASH = {1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
IKEV1_HASH_WEAK = {1, 2}             # MD5, SHA1

# IKEv1 Authentication Method values (RFC 2409 Appendix A)
IKEV1_AUTH = {
    1: "PSK", 2: "DSS-Sig", 3: "RSA-Sig", 4: "RSA-Enc", 5: "RSA-Enc-Revised",
    64221: "HybridInitRSA", 65001: "XAUTHInitPSK",
}
IKEV1_AUTH_PSK_METHODS = {1, 65001, 65003, 65005, 65007, 65009}  # PSK + XAUTH-PSK family

# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 Transform Types (RFC 7296 §3.3.2)
# ─────────────────────────────────────────────────────────────────────────────
IKEV2_TRANSFORM_TYPE_ENCR = 1
IKEV2_TRANSFORM_TYPE_PRF = 2
IKEV2_TRANSFORM_TYPE_INTEG = 3
IKEV2_TRANSFORM_TYPE_DH = 4
IKEV2_TRANSFORM_TYPE_ESN = 5

# IKEv2 Encryption Algorithm IDs (IANA IKEv2 registry, ENCR)
IKEV2_ENCR = {
    2: "DES-CBC", 3: "3DES-CBC", 4: "RC5", 5: "IDEA", 6: "CAST",
    7: "Blowfish-CBC", 8: "3IDEA", 11: "NULL",
    12: "AES-CBC", 13: "AES-CTR",
    14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16",
    18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
    23: "CAMELLIA-CBC", 28: "ChaCha20-Poly1305",
}
IKEV2_ENCR_SWEET32 = {3, 7}          # 3DES-CBC, Blowfish-CBC (64-bit block)
IKEV2_ENCR_LEGACY = {2, 3}           # DES-CBC, 3DES-CBC

# IKEv2 PRF IDs (IANA)
IKEV2_PRF = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256", 6: "PRF_HMAC_SHA2_384", 7: "PRF_HMAC_SHA2_512",
}
IKEV2_PRF_WEAK = {1, 2}              # HMAC-MD5, HMAC-SHA1

# IKEv2 Integrity IDs (IANA)
IKEV2_INTEG = {
    1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96", 5: "AUTH_HMAC_SHA2_256_128",
    12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192", 14: "AUTH_HMAC_SHA2_512_256",
}
IKEV2_INTEG_WEAK = {1, 2}

# ─────────────────────────────────────────────────────────────────────────────
# Transform Type 4 registry.
#
# RFC 9370 RENAMED Transform Type 4 from "Diffie-Hellman Group (D-H)" to
# "Key Exchange Method (KE)", and renamed the IANA registry from
# "Transform Type 4 - Diffie-Hellman Group Transform IDs" to
# "Transform Type 4 - Key Exchange Method Transform IDs". Same transform type,
# same numbers for the classical (EC)DH groups below; the rename just makes room
# for post-quantum KEMs to share the registry. Authoritative source:
#   https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-8
#
# Classical group IDs (RFC 3526 MODP, RFC 5114, RFC 5903 ECP) — stable, assigned.
# ─────────────────────────────────────────────────────────────────────────────
DH_GROUPS = {
    1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536",
    14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096",
    17: "MODP-6144", 18: "MODP-8192",
    19: "ECP-256", 20: "ECP-384", 21: "ECP-521",
    22: "MODP-1024-160", 23: "MODP-2048-224", 24: "MODP-2048-256",
    25: "ECP-192", 26: "ECP-224",
    27: "brainpoolP224r1", 28: "brainpoolP256r1",
    29: "brainpoolP384r1", 30: "brainpoolP512r1",
    31: "Curve25519", 32: "Curve448",
}

# DHEater (D2): the classic downgrade-prone small MODP groups.
DH_GROUPS_DHEATER = {1, 2}           # MODP-768, MODP-1024

# Weak DH (D3): legacy MODP + small-prime groups below current guidance.
# RFC 8247 / NIST SP 800-57: MODP < 2048 is deprecated; 22 (1024-bit subgroup)
# is also weak; 25/26 (ECP-192/224) below 128-bit strength.
DH_GROUPS_WEAK = {1, 2, 5, 22, 25, 26}

# "Strong" groups for the E1 downgrade correlation (>=128-bit security).
DH_GROUPS_STRONG = {14, 15, 16, 17, 18, 19, 20, 21, 24, 28, 29, 30, 31, 32}

# ─────────────────────────────────────────────────────────────────────────────
# E3 gate — post-quantum. TWO SEPARATE IANA REGISTRATIONS from TWO drafts.
# Do not conflate them; each is confirmed independently before E3 is enabled.
#
# (A) ML-KEM Key Exchange Method transform IDs.
#     Draft:  draft-ietf-ipsecme-ikev2-mlkem  (v09 as of 2026-07; NOT yet RFC)
#     Registry: Transform Type 4 - Key Exchange Method Transform IDs
#               (the ...#ikev2-parameters-8 table above)
#     The draft REQUESTS three names — "ml-kem-512", "ml-kem-768",
#     "ml-kem-1024" — but IANA has NOT assigned numbers yet. The values below
#     are NOT real KE IDs; they are unusable sentinels chosen high on purpose so
#     they never collide with an assigned classical group. When the registry
#     shows the real numbers, replace these AND remove this warning.
#
#     Also note the negotiation surface is wider than IKE_SA_INIT: RFC 9370's
#     multi-KE framework allows ML-KEM as an ADDITIONAL exchange via
#     IKE_FOLLOWUP_KE. E3 v0.1 inspects IKE_SA_INIT only — a conscious scope
#     limit, not a silent gap. Extend to IKE_FOLLOWUP_KE when that path matters.
#
# (B) Downgrade-prevention signal — a DIFFERENT draft, a DIFFERENT registry.
#     Draft:  draft-ietf-ipsecme-ikev2-downgrade-prevention (v08 as of 2026-07)
#     Registry: IKEv2 Notify Message Status Types (a DIFFERENT anchor on the
#               same IANA page, NOT the KE table). The Notify code point that
#               signals downgrade protection is what E3 checks for to decide a
#               PQ offer is protected. NOT yet assigned.
#
# Both are GATED to None/sentinel so E3 cannot fire on guesses. E3 is enabled
# only when the operator passes real, confirmed numbers (--enable-ml-kem plus
# the confirmed notify code), never on these placeholders.
# ─────────────────────────────────────────────────────────────────────────────
# (A) PROVISIONAL, NON-AUTHORITATIVE sentinels — not real IANA KE IDs.
ML_KEM_KE_IDS_CONFIRMED = False           # flip to True only when IANA assigns
DH_GROUPS_ML_KEM = {0xFD00, 0xFD01, 0xFD02}   # sentinels; replace on assignment
ML_KEM_KE_NAMES = {                        # names the draft requests (stable)
    0xFD00: "ml-kem-512(PROVISIONAL)",
    0xFD01: "ml-kem-768(PROVISIONAL)",
    0xFD02: "ml-kem-1024(PROVISIONAL)",
}

# (B) Downgrade-prevention Notify — separate registry, separate draft.
IKEV2_NOTIFY_INTERMEDIATE_EXCHANGE_SUPPORTED = 16438   # RFC 9242 (IKE_INTERMEDIATE), assigned
# The downgrade-prevention status-notify code point is NOT yet assigned. None
# means "unknown": E3 treats absence-of-protection as undetectable until a real
# code point is supplied, rather than guessing one.
IKEV2_NOTIFY_DOWNGRADE_PREVENTION = None

# Standard IKE ports
IKE_PORT = 500
IKE_NATT_PORT = 4500
