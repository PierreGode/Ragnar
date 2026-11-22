"""
modbuswatch — passive sensor driver.

Reads frames (live or from pcap), extracts the Modbus/TCP payload, builds a
FlowKey, decodes the ADU and feeds the engine. Receive-only: no socket is ever
opened for transmit.

Dual-stack handling is explicit. For IPv6 we walk the extension-header chain to
reach the TCP header rather than assuming a fixed offset — the same libpcap/BPF
blind spot that bit juniperwatch and the ntpwatch v6 work. TCP reassembly is
intentionally minimal: Modbus ADUs are tiny and almost always one-per-segment;
a segment too short to hold an MBAP header is skipped, not buffered.
"""

from __future__ import annotations

import socket
import time

from scapy.all import TCP, UDP, IP, IPv6, rdpcap
from scapy.layers.inet6 import (
    IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting,
    IPv6ExtHdrFragment,
)

try:  # Ragnar: relative inside the vendored package, bare for flat standalone.
    from .parser import parse, MODBUS_TCP_PORT, MODBUS_SECURITY_PORT
    from .state import FlowKey
    from .findings import Engine
    from .lora import parse_gwmp
except ImportError:
    from parser import parse, MODBUS_TCP_PORT, MODBUS_SECURITY_PORT
    from state import FlowKey
    from findings import Engine
    from lora import parse_gwmp

_V6_EXT = (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting,
           IPv6ExtHdrFragment)


def _l3(pkt):
    """Return (family, src, dst) or None if not v4/v6."""
    if IP in pkt:
        return socket.AF_INET, pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return socket.AF_INET6, pkt[IPv6].src, pkt[IPv6].dst
    return None


def _l4_from_v6(pkt, cls):
    """
    Walk the IPv6 extension-header chain to the requested L4 layer. scapy
    exposes pkt[TCP] / pkt[UDP] only if it parsed the chain; this guards the
    case where an extension header sits between IPv6 and L4, so we never miss a
    Modbus segment or a LoRaWAN backhaul datagram hidden behind one.
    """
    if cls in pkt:
        return pkt[cls]
    layer = pkt[IPv6]
    while isinstance(layer.payload, _V6_EXT):
        layer = layer.payload
    nxt = layer.payload
    return nxt if isinstance(nxt, cls) else None


def _tcp_from_v6(pkt):
    return _l4_from_v6(pkt, TCP)


def _udp_from_v6(pkt):
    return _l4_from_v6(pkt, UDP)


def process_packet(pkt, engine: Engine) -> None:
    l3 = _l3(pkt)
    if l3 is None:
        return
    family, src, dst = l3

    tcp = pkt[TCP] if (family == socket.AF_INET and TCP in pkt) else (
        _tcp_from_v6(pkt) if family == socket.AF_INET6 else None)
    if tcp is not None:
        return _process_tcp(pkt, engine, family, src, dst, tcp)

    udp = pkt[UDP] if (family == socket.AF_INET and UDP in pkt) else (
        _udp_from_v6(pkt) if family == socket.AF_INET6 else None)
    if udp is not None:
        return _process_udp(pkt, engine, family, src, dst, udp)


def _process_udp(pkt, engine: Engine, family, src, dst, udp) -> None:
    """LoRaWAN gateway backhaul: Semtech GWMP over UDP (default 1700)."""
    ports = getattr(engine, "lora", None)
    ports = ports.ports if ports is not None else ()
    if not ports:
        return
    sport, dport = int(udp.sport), int(udp.dport)
    if sport not in ports and dport not in ports:
        return
    payload = bytes(udp.payload)
    if not payload:
        return
    gwmp = parse_gwmp(payload)
    if gwmp is None:
        return      # strict: not well-formed GWMP, nothing is reported
    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
    # Direction is the signal on this tier, so the key is left as observed.
    engine.feed_lora(FlowKey(family, src, dst, 0), gwmp, now=ts,
                     dst_port=(dport if dport in ports else sport))


def _process_tcp(pkt, engine: Engine, family, src, dst, tcp) -> None:
    sport, dport = int(tcp.sport), int(tcp.dport)
    if MODBUS_TCP_PORT not in (sport, dport) and MODBUS_SECURITY_PORT not in (sport, dport):
        return

    payload = bytes(tcp.payload)
    if not payload:
        return

    # Record that a host speaks Modbus Security (802) so MBW-041 can fire later
    # when the same host is also reached in plaintext on 502.
    if MODBUS_SECURITY_PORT in (sport, dport):
        host = dst if dport == MODBUS_SECURITY_PORT else src
        engine.note_security_host(family, host)
        return  # TLS payload is opaque; nothing to decode

    is_response = sport == MODBUS_TCP_PORT  # slave speaks from 502
    adu = parse(payload, is_response=is_response)
    if adu is None:
        return

    # FlowKey is master->slave oriented. On a response, flip so the key always
    # names (master=src, slave=dst) for baseline consistency.
    if is_response:
        key = FlowKey(family, dst, src, adu.unit_id)
    else:
        key = FlowKey(family, src, dst, adu.unit_id)

    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
    engine.feed(key, adu, dst_port=(sport if is_response else dport), now=ts)


def run_pcap(path: str, engine: Engine | None = None) -> Engine:
    engine = engine or Engine()
    for pkt in rdpcap(path):
        process_packet(pkt, engine)
    return engine
