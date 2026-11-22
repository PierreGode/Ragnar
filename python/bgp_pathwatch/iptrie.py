"""
iptrie.py -- longest-prefix-match trie over fixed-width integer keys.

Shared by two consumers:
  * bgp.Rib          -- "which prefix covers this target IP, and is it churning?"
  * asn resolution   -- ip -> origin AS via the BGP RIB or an offline pfx2as table

Generic on bit width (32 for IPv4, 128 for IPv6). Stores one value per prefix;
longest_match walks the key MSB-first and returns the deepest value seen. Pure
Python, no deps, fully testable.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional, Tuple


class _Node:
    __slots__ = ("child0", "child1", "value", "has_value")

    def __init__(self):
        self.child0: Optional[_Node] = None
        self.child1: Optional[_Node] = None
        self.value = None
        self.has_value = False


class IpTrie:
    def __init__(self, bits: int = 32):
        self.bits = bits
        self.root = _Node()
        self.count = 0

    def insert(self, key: int, plen: int, value) -> None:
        node = self.root
        for i in range(plen):
            bit = (key >> (self.bits - 1 - i)) & 1
            nxt = node.child1 if bit else node.child0
            if nxt is None:
                nxt = _Node()
                if bit:
                    node.child1 = nxt
                else:
                    node.child0 = nxt
            node = nxt
        if not node.has_value:
            self.count += 1
        node.value = value
        node.has_value = True

    def delete(self, key: int, plen: int) -> bool:
        node = self.root
        for i in range(plen):
            bit = (key >> (self.bits - 1 - i)) & 1
            node = node.child1 if bit else node.child0
            if node is None:
                return False
        if node.has_value:
            node.has_value = False
            node.value = None
            self.count -= 1
            return True
        return False

    def longest_match(self, key: int) -> Tuple[Optional[object], int]:
        """Return (value, matched_prefix_len) for the deepest covering prefix,
        or (None, -1) if nothing covers the key."""
        node = self.root
        best_val = None
        best_len = -1
        if node.has_value:                 # default route 0/0
            best_val, best_len = node.value, 0
        for i in range(self.bits):
            bit = (key >> (self.bits - 1 - i)) & 1
            node = node.child1 if bit else node.child0
            if node is None:
                break
            if node.has_value:
                best_val, best_len = node.value, i + 1
        return best_val, best_len


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def ip_to_int(ip: str) -> Tuple[int, int]:
    """Return (int_value, bits) for a v4 or v6 address string."""
    a = ipaddress.ip_address(ip)
    return int(a), (128 if a.version == 6 else 32)


def prefix_to_int(prefix: str) -> Tuple[int, int, int]:
    """'203.0.113.0/24' -> (int_network, prefixlen, bits)."""
    net = ipaddress.ip_network(prefix, strict=False)
    return int(net.network_address), net.prefixlen, net.max_prefixlen


def int_to_ip(value: int, bits: int) -> str:
    if bits == 32:
        return socket.inet_ntoa(value.to_bytes(4, "big"))
    return socket.inet_ntop(socket.AF_INET6, value.to_bytes(16, "big"))
