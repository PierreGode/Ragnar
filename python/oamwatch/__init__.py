"""oamwatch - passive IEEE 802.3ah Link OAM (EFM OAM) abuse detector.

Part of the Ragnar passive network security suite.

PRIME DIRECTIVES
  Passive-only. This package never transmits. There is no loopback arming, no
  variable polling, no active verification of any kind. The transmit guard in
  tests/conformance.py enforces this at the AST level.

  Dual-stack: not applicable. Link OAM is an L2 slow protocol with no IP
  header and no address-family split, the same as LACP. There is no IPv6
  variant to chase and nothing is omitted by its absence.

HONEST SCOPE
  802.3ah Link OAM has no CVE backbone at the CVSS 6.5 bar. Every finding is
  protocol abuse observable on a cleartext, unauthenticated plane. Link OAM is
  also point-to-point and config-gated, so a tap only sees it when the tap is
  on an OAM-enabled link.
"""

__version__ = "0.1.0-dev"

from .registry import REGISTRY, CODES  # noqa: F401
