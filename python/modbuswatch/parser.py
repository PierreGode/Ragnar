"""
modbuswatch — MBAP + PDU decoder (hand-rolled, no libmodbus linkage).

Parsing our own bytes keeps the module clean of the very libmodbus CVEs it
detects. The MBAP length-vs-PDU cross-check in parse() IS finding MBW-030, so
this file is load-bearing, not just hygiene.

Modbus/TCP ADU:
    MBAP header (7 bytes):
        transaction id : u16
        protocol id     : u16   (0 for Modbus)
        length          : u16   (byte count of unit id + PDU that follows)
        unit id         : u8
    PDU:
        function code   : u8
        data            : ...

Address-family-agnostic: the ADU is identical over IPv4 and IPv6. Family is
carried alongside by the caller (see FlowKey), never inferred here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

MBAP_LEN = 7
MODBUS_TCP_PORT = 502
MODBUS_SECURITY_PORT = 802


class FC(IntEnum):
    READ_COILS = 1
    READ_DISCRETE_INPUTS = 2
    READ_HOLDING_REGISTERS = 3
    READ_INPUT_REGISTERS = 4
    WRITE_SINGLE_COIL = 5
    WRITE_SINGLE_REGISTER = 6
    READ_EXCEPTION_STATUS = 7
    DIAGNOSTICS = 8
    GET_COMM_EVENT_COUNTER = 11
    GET_COMM_EVENT_LOG = 12
    WRITE_MULTIPLE_COILS = 15
    WRITE_MULTIPLE_REGISTERS = 16
    REPORT_SERVER_ID = 17
    READ_FILE_RECORD = 20
    WRITE_FILE_RECORD = 21
    MASK_WRITE_REGISTER = 22
    READ_WRITE_MULTIPLE_REGISTERS = 23
    READ_FIFO_QUEUE = 24
    ENCAPSULATED_INTERFACE = 43  # MEI — incl. Read Device ID (type 14)
    UMAS = 90  # 0x5A — Schneider proprietary (UMAS / ModiPwn)


# Function codes that mutate slave state. MBW-001 keys off this set.
WRITE_FCS = frozenset({
    FC.WRITE_SINGLE_COIL,
    FC.WRITE_SINGLE_REGISTER,
    FC.WRITE_MULTIPLE_COILS,
    FC.WRITE_MULTIPLE_REGISTERS,
    FC.WRITE_FILE_RECORD,
    FC.MASK_WRITE_REGISTER,
    FC.READ_WRITE_MULTIPLE_REGISTERS,  # has a write leg
})

# FC8 diagnostic sub-functions of interest.
DIAG_RESTART_COMM = 0x0001
DIAG_FORCE_LISTEN_ONLY = 0x0004  # silently drops slave off the bus — MBW-002
DIAG_CLEAR_COUNTERS = 0x000A

# MEI (FC43) type for Read Device Identification — MBW-020.
MEI_READ_DEVICE_ID = 0x0E


@dataclass
class Adu:
    """One decoded Modbus/TCP ADU. malformed carries the reason if framing failed."""
    transaction_id: int
    protocol_id: int
    length: int           # MBAP length field as declared
    unit_id: int
    function_code: int
    is_response: bool      # from direction, set by caller; default request
    data: bytes = b""
    malformed: str | None = None   # non-None => MBW-030 trigger
    raw_len: int = 0               # actual bytes available for unit+PDU


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from(">H", b, off)[0]


def parse(payload: bytes, is_response: bool = False) -> Adu | None:
    """
    Decode a single Modbus/TCP ADU from a TCP payload.

    Returns None if the buffer is too short to even hold an MBAP header (not a
    Modbus packet / partial segment — caller decides whether to buffer).
    Returns an Adu with .malformed set when framing is internally inconsistent;
    that is the MBW-030 condition and the caller should emit, not discard.
    """
    if payload is None or len(payload) < MBAP_LEN + 1:
        return None

    txn = _u16(payload, 0)
    proto = _u16(payload, 2)
    length = _u16(payload, 4)
    unit = payload[6]
    fc = payload[7]

    # Bytes actually present after the MBAP length field position (unit id + PDU).
    available = len(payload) - 6
    adu = Adu(
        transaction_id=txn,
        protocol_id=proto,
        length=length,
        unit_id=unit,
        function_code=fc,
        is_response=is_response,
        data=payload[8:6 + length] if length >= 2 else payload[8:],
        raw_len=available,
    )

    # --- MBW-030 framing cross-checks (the load-bearing part) ---
    if proto != 0:
        adu.malformed = f"protocol_id={proto} (expected 0)"
        return adu
    if length < 2:
        adu.malformed = f"MBAP length={length} too small for unit+FC"
        return adu
    # Declared length must match bytes on the wire. A declared length longer than
    # what arrived is the libmodbus over-read / over-reply class
    # (CVE-2019-14462/14463, CVE-2024-10918).
    if length != available:
        adu.malformed = (
            f"MBAP length={length} != bytes present={available}"
        )
        return adu

    # --- PDU-internal consistency for the count-bearing writes ---
    # FC15/FC16 carry an explicit byte-count that must agree with quantity.
    # The 2019 libmodbus OOB reads live exactly here.
    if fc in (FC.WRITE_MULTIPLE_COILS, FC.WRITE_MULTIPLE_REGISTERS) and not is_response:
        reason = _check_multiple_write(fc, adu.data)
        if reason:
            adu.malformed = reason
            return adu

    return adu


def _check_multiple_write(fc: int, data: bytes) -> str | None:
    """
    FC15/16 request body: starting addr (u16), quantity (u16), byte count (u8),
    then <byte count> data bytes. Verify byte_count matches quantity and the
    trailing data length. Mismatch => OOB-read trigger (CVE-2019-14462/14463).
    """
    if len(data) < 5:
        return f"FC{fc} body too short ({len(data)} bytes)"
    quantity = struct.unpack_from(">H", data, 2)[0]
    byte_count = data[4]
    body = data[5:]

    if fc == FC.WRITE_MULTIPLE_COILS:
        expected_bytes = (quantity + 7) // 8
    else:  # WRITE_MULTIPLE_REGISTERS
        expected_bytes = quantity * 2

    if byte_count != expected_bytes:
        return (
            f"FC{fc} byte_count={byte_count} != expected {expected_bytes} "
            f"for quantity={quantity}"
        )
    if len(body) != byte_count:
        return (
            f"FC{fc} trailing data={len(body)} != byte_count={byte_count}"
        )
    return None


def diag_subfunction(adu: Adu) -> int | None:
    """FC8 sub-function code (u16) from the PDU data, or None."""
    if adu.function_code != FC.DIAGNOSTICS or len(adu.data) < 2:
        return None
    return struct.unpack_from(">H", adu.data, 0)[0]


def mei_type(adu: Adu) -> int | None:
    """FC43 MEI type (u8) from the PDU data, or None."""
    if adu.function_code != FC.ENCAPSULATED_INTERFACE or len(adu.data) < 1:
        return None
    return adu.data[0]


def umas_subcode(adu: Adu) -> int | None:
    """
    UMAS (FC90) session sub-function (u8). Schneider wraps its proprietary
    command in the first PDU byte after the FC. Used by the ModiPwn tracker.
    """
    if adu.function_code != FC.UMAS or len(adu.data) < 1:
        return None
    return adu.data[0]
